//! Overview, metrics, page titles, retention, journeys, live users, site data
//! checks and event counts, ported from server/src/api/analytics
//! (getOverview.ts, getOverviewBucketed.ts, lite/, getMetric.ts, getPageTitles.ts,
//! getRetention.ts, getJourneys.ts, getLiveUsercount.ts, events/getSiteEventCount.ts,
//! getOrgEventCount.ts), server/src/api/sites (getSiteHasData.ts,
//! getSiteIsPublic.ts) and server/src/services/siteMetrics.
//!
//! Every handler here runs after the preHandler chain from `analytics::chain`, then
//! does exactly what the Node handler does: the same SQL text (whitespace
//! included), the same bound parameters, the same response shaping and the same
//! error labels. Caddy moves these paths over one at a time, so a dashboard must
//! not be able to tell which backend answered.
//!
//! The handler bodies are generic over [`OverviewBackend`] so the whole request
//! path (validation, SQL, parameters, shaping) can be replayed against fixtures the
//! real Node handlers produced (see `parity/`), while production binds the
//! ClickHouse executor, Site Configuration and the site access cache.

use std::sync::OnceLock;

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
    routing::get,
};
use serde_json::{Map, Value, json};
use tracing::{debug, error};

use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, org_scoped, route_scope, site_scoped},
        js::{JsObject, JsValue},
        utils::{
            analytics_query::{AnalyticsClickHouse, AnalyticsQueryError, ClickHouseFailure, PaginatedRows, QuerySpec},
            get_filter_statement::{FilterStatementError, UnknownParameter},
            query_validation::FiltersError,
            time_window::{RangeError, TimeWindowParams},
        },
    },
    auth::guards::Authenticated,
    site_config::{DEFAULT_BOUNCE_THRESHOLD_SECONDS, SiteRef},
    state::AppState,
};

pub mod event_counts;
pub mod journeys;
pub mod lite;
pub mod live_users;
pub mod metric;
#[allow(clippy::module_inception)] // mirrors getOverview.ts inside the overview route group
pub mod overview;
pub mod page_titles;
pub mod retention;
pub mod site_data;
pub mod site_metrics;

#[cfg(test)]
mod parity;

/// One ClickHouse result row, keys in the order ClickHouse sent them.
pub type Row = Map<String, Value>;

/// `INNER JOIN FilteredSessions USING (session_id)`, shared by the session-qualified queries.
pub(crate) const SESSION_JOIN: &str = "INNER JOIN FilteredSessions USING (session_id)";

/// What a handler answers: a status and a JSON body, serialized the way Fastify's
/// `reply.send(object)` does (`JSON.stringify`).
#[derive(Clone, Debug, PartialEq)]
pub struct Reply {
    pub status: StatusCode,
    pub body: Value,
}

impl Reply {
    pub fn ok(body: Value) -> Self {
        Self { status: StatusCode::OK, body }
    }

    pub fn error(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, body: json!({ "error": message.into() }) }
    }

    /// The body as `JSON.stringify` writes it (JavaScript number spelling).
    pub fn body_text(&self) -> String {
        crate::js_json::stringify(&self.body)
    }

    pub fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body_text()));
        *response.status_mut() = self.status;
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        response
    }
}

/// An exception that escaped a Node handler, which Fastify's default error handler
/// answers with 500 `{ statusCode, error, message }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thrown {
    pub message: String,
}

impl Thrown {
    /// The `TypeError` Node's log sanitizer throws when a handler's catch logs a
    /// `ZodError`: `sanitizeError` copies `errors` onto an object whose prototype
    /// only has a getter for it. The catch block itself throws, so the labelled
    /// 500 is never sent.
    pub fn zod_error_logged() -> Self {
        Self { message: "Cannot set property errors of [object Object] which has only a getter".to_string() }
    }

    pub fn into_reply(self) -> Reply {
        Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: json!({ "statusCode": 500, "error": "Internal Server Error", "message": self.message }),
        }
    }
}

/// What a handler produced: a reply, or an exception for Fastify to answer.
pub type Outcome = Result<Reply, Thrown>;

/// Why building a query failed before it reached ClickHouse. In Node each of
/// these is an exception inside the route, which `analyticsRoute` turns into a
/// labelled 500.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// `toISOString` on an out-of-range time window bound
    #[error(transparent)]
    Range(#[from] RangeError),
    #[error(transparent)]
    Filters(#[from] FiltersError),
    #[error(transparent)]
    FilterStatement(#[from] FilterStatementError),
    /// `filterParamSchema.parse` inside `getSqlParam`
    #[error(transparent)]
    UnknownParameter(#[from] UnknownParameter),
    /// A JavaScript `TypeError` (a string method called on a non-string query value)
    #[error("TypeError: {0}")]
    TypeError(String),
    /// Node would have sent SQL ClickHouse cannot run (an unknown bucket renders
    /// as `undefined(...)`); Rust answers the same 500 without the round trip
    #[error("ClickHouse would reject the query: {0}")]
    Rejected(String),
}

impl BuildError {
    /// True when Node threw a `ZodError` here (a filters schema failure, or
    /// `filterParamSchema.parse` on an unknown metric parameter).
    pub fn is_zod_error(&self) -> bool {
        matches!(
            self,
            BuildError::Filters(FiltersError::Schema(_))
                | BuildError::FilterStatement(FilterStatementError::Filters(FiltersError::Schema(_)))
                | BuildError::UnknownParameter(_)
        )
    }
}

/// A handler failure: a build error or a failed ClickHouse call.
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error(transparent)]
    Build(#[from] BuildError),
    #[error(transparent)]
    Query(#[from] AnalyticsQueryError),
}

impl HandlerError {
    pub fn is_zod_error(&self) -> bool {
        matches!(self, HandlerError::Build(build) if build.is_zod_error())
    }
}

impl From<RangeError> for HandlerError {
    fn from(error: RangeError) -> Self {
        HandlerError::Build(error.into())
    }
}

impl From<FiltersError> for HandlerError {
    fn from(error: FiltersError) -> Self {
        HandlerError::Build(error.into())
    }
}

impl From<FilterStatementError> for HandlerError {
    fn from(error: FilterStatementError) -> Self {
        HandlerError::Build(error.into())
    }
}

/// `analyticsRoute`'s catch: log the label (and the failed SQL at debug), answer
/// 500 `{ error: "Failed to fetch <label>" }`. A `ZodError` makes Node's logging
/// call itself throw, so that failure escapes as [`Thrown`] instead.
pub fn route_failure(label: &str, failure: &HandlerError) -> Outcome {
    match failure {
        HandlerError::Query(query_error) => {
            error!(err = %query_error.original, label, "Analytics query failed");
            for query in &query_error.queries {
                debug!(query = %query, "Failed analytics query");
            }
        }
        HandlerError::Build(build_error) => error!(err = %build_error, label, "Analytics query failed"),
    }
    if failure.is_zod_error() {
        let thrown = Thrown::zod_error_logged();
        error!(label, message = %thrown.message, "Validation error escaped the analytics route (Node's log sanitizer throws on ZodError)");
        return Err(thrown);
    }
    Ok(Reply::error(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to fetch {label}")))
}

/// A nested handler's exception caught by an outer `analyticsRoute` (the lite
/// endpoints delegate to the standard handlers inside their own try block).
pub fn catch_nested(label: &str, outcome: Outcome) -> Reply {
    match outcome {
        Ok(reply) => reply,
        Err(thrown) => {
            error!(err = %thrown.message, label, "Analytics query failed");
            Reply::error(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to fetch {label}"))
        }
    }
}

/// Everything the handlers need from the outside world. Production binds
/// [`LiveBackend`]; the parity tests bind a recorder fed with Node's rows.
pub(crate) trait OverviewBackend {
    /// `runAnalyticsQuery(spec)`
    async fn run_analytics_query(&self, spec: &QuerySpec) -> Result<Vec<Row>, AnalyticsQueryError>;

    /// `runPaginatedQuery(dataSpec, countSpec)`
    async fn run_paginated_query(&self, data: &QuerySpec, count: &QuerySpec) -> Result<PaginatedRows, AnalyticsQueryError>;

    /// `clickhouse.query({ ..., clickhouse_settings: { max_threads: 1 } }).then(res => res.json())`
    async fn query_rows_single_thread(&self, spec: &QuerySpec) -> Result<Vec<Row>, ClickHouseFailure>;

    /// `siteConfig.getBounceThreshold(siteId)` for a numeric `siteId`
    async fn bounce_threshold(&self, site: f64) -> i32;

    /// `siteConfig.getConfig(siteId)?.public || false` for the route's `siteId` string
    async fn site_is_public(&self, site_id: &str) -> bool;

    /// `getSitesUserHasAccessTo(req)` filtered to one organization, as site ids
    async fn organization_site_ids(&self, organization_id: &str) -> Vec<i64>;

    /// `Date.now()`
    fn now_ms(&self) -> f64;
}

/// `Number(siteId)`.
pub fn js_number(text: &str) -> f64 {
    JsValue::from(text).to_number()
}

/// `Number(siteId)` where Node interpolates it into SQL (`site_id = ${siteId}`).
/// The chain only admits integral ids, so anything else is reported as a failure.
pub fn integral_site_id(site: f64) -> Result<i64, BuildError> {
    if site.is_finite() && site.fract() == 0.0 && site.abs() < 9_007_199_254_740_992.0 {
        Ok(site as i64)
    } else {
        Err(BuildError::Rejected(format!("site id {site} is not an integer")))
    }
}

/// The time params off a request query.
pub fn time_params(query: &JsObject) -> TimeWindowParams {
    TimeWindowParams::from_object(query)
}

/// Property lookup on `TimeBucketToFn` / `bucketIntervalMap` for a raw query value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketLookup {
    Valid(crate::analytics::types::TimeBucket),
    /// A key the maps do not hold (renders as `undefined`, or as an inherited
    /// `Object.prototype` member): the SQL built from it cannot run
    Invalid,
}

impl BucketLookup {
    /// `TimeBucketToFn[value]` with `value` already defaulted by the caller.
    pub fn of(value: &JsValue) -> Self {
        match crate::analytics::types::TimeBucket::parse(&value.to_js_string()) {
            Some(bucket) => BucketLookup::Valid(bucket),
            None => BucketLookup::Invalid,
        }
    }

    pub fn require(self, raw: &JsValue) -> Result<crate::analytics::types::TimeBucket, BuildError> {
        match self {
            BucketLookup::Valid(bucket) => Ok(bucket),
            BucketLookup::Invalid => Err(BuildError::Rejected(format!("unknown bucket {:?}", raw.to_js_string()))),
        }
    }
}

/// `Object.prototype` members a bracket lookup on a plain object finds.
pub fn is_object_prototype_key(key: &str) -> bool {
    matches!(
        key,
        "constructor"
            | "__defineGetter__"
            | "__defineSetter__"
            | "hasOwnProperty"
            | "__lookupGetter__"
            | "__lookupSetter__"
            | "isPrototypeOf"
            | "propertyIsEnumerable"
            | "toString"
            | "valueOf"
            | "__proto__"
            | "toLocaleString"
    )
}

/// The ClickHouse executor Node's `clickhouse` client corresponds to, built once
/// from the service configuration.
fn analytics_client(state: &AppState) -> Option<&'static AnalyticsClickHouse> {
    static CLIENT: OnceLock<Option<AnalyticsClickHouse>> = OnceLock::new();
    CLIENT
        .get_or_init(|| match AnalyticsClickHouse::new(&state.config.clickhouse) {
            Ok(client) => Some(client),
            Err(err) => {
                error!(error = %err, "Could not build the analytics ClickHouse client");
                None
            }
        })
        .as_ref()
}

/// The production backend: ClickHouse, Site Configuration and site access.
pub struct LiveBackend<'a> {
    state: &'a AppState,
    client: &'static AnalyticsClickHouse,
    auth: &'a Authenticated,
}

impl<'a> LiveBackend<'a> {
    pub fn new(state: &'a AppState, auth: &'a Authenticated) -> Option<Self> {
        analytics_client(state).map(|client| Self { state, client, auth })
    }
}

impl OverviewBackend for LiveBackend<'_> {
    async fn run_analytics_query(&self, spec: &QuerySpec) -> Result<Vec<Row>, AnalyticsQueryError> {
        self.client.run_analytics_query(spec).await
    }

    async fn run_paginated_query(&self, data: &QuerySpec, count: &QuerySpec) -> Result<PaginatedRows, AnalyticsQueryError> {
        self.client.run_paginated_query(data, count).await
    }

    async fn query_rows_single_thread(&self, spec: &QuerySpec) -> Result<Vec<Row>, ClickHouseFailure> {
        self.client.query_rows(spec, &[("max_threads", "1".to_string())]).await
    }

    async fn bounce_threshold(&self, site: f64) -> i32 {
        // getConfig: a falsy id reads nothing, a non-integer number matches no Site
        if site == 0.0 || site.is_nan() || site.fract() != 0.0 || !site.is_finite() {
            return DEFAULT_BOUNCE_THRESHOLD_SECONDS;
        }
        self.state
            .site_config
            .get_config(&SiteRef::Number(site as i64))
            .await
            .map_or(DEFAULT_BOUNCE_THRESHOLD_SECONDS, |config| config.bounce_threshold)
    }

    async fn site_is_public(&self, site_id: &str) -> bool {
        if site_id.is_empty() {
            return false;
        }
        self.state
            .site_config
            .get_config(&SiteRef::Text(site_id.to_string()))
            .await
            .is_some_and(|config| config.public)
    }

    async fn organization_site_ids(&self, organization_id: &str) -> Vec<i64> {
        let accessible = self.state.sites_access.sites_for(&self.state.pg, &self.auth.principal(), false).await;
        if accessible.is_empty() {
            return Vec::new();
        }
        // getSitesUserHasAccessTo returns whole Site rows and the handler filters
        // them by organizationId; the cache here holds ids, so read the owners
        match sqlx::query_scalar::<_, i32>(
            "SELECT site_id FROM sites WHERE site_id = ANY($1) AND organization_id = $2 ORDER BY site_id",
        )
        .bind(&accessible)
        .bind(organization_id)
        .fetch_all(&self.state.pg)
        .await
        {
            Ok(ids) => ids.into_iter().map(i64::from).collect(),
            Err(err) => {
                error!(error = %err, organization_id, "Could not read the organization of accessible sites");
                Vec::new()
            }
        }
    }

    fn now_ms(&self) -> f64 {
        crate::analytics::utils::time_window::now_ms()
    }
}

/// Fastify's `maxParamLength` (1500 in index.ts): find-my-way stops matching a
/// route whose raw (still percent-encoded) parameter is longer, so the request
/// falls through to the not-found handler. Every route here has its one parameter
/// in the fourth path segment.
const MAX_PARAM_LENGTH: usize = 1500;

async fn param_too_long(method: &Method, uri: &Uri) -> Option<Response> {
    let raw = uri.path().split('/').nth(3).unwrap_or_default();
    if raw.len() <= MAX_PARAM_LENGTH {
        return None;
    }
    debug!(length = raw.len(), "route parameter longer than maxParamLength");
    Some(crate::http::errors::not_found(method.clone(), uri.clone()).await)
}

fn client_unavailable() -> Response {
    Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
}

/// A handler outcome as the HTTP response Fastify would send.
fn outcome_response(outcome: Outcome) -> Response {
    match outcome {
        Ok(reply) => reply.into_response(),
        Err(thrown) => thrown.into_reply().into_response(),
    }
}

/// Declares an axum handler for a site route: the chain, then the generic handler.
macro_rules! site_route {
    ($name:ident, $resource:literal, $handler:path) => {
        async fn $name(
            State(state): State<AppState>,
            Path(site_id): Path<String>,
            method: Method,
            headers: HeaderMap,
            uri: Uri,
        ) -> Response {
            if let Some(response) = param_too_long(&method, &uri).await {
                return response;
            }
            let request = match site_scoped(
                &state,
                &headers,
                &uri,
                &site_id,
                SiteGuard::Public,
                route_scope($resource, "read"),
                ChainSteps::FULL,
            )
            .await
            {
                Ok(request) => request,
                Err(response) => return response,
            };
            let Some(backend) = LiveBackend::new(&state, &request.auth) else { return client_unavailable() };
            outcome_response($handler(&backend, &request.site_id, &request.query).await)
        }
    };
}

site_route!(live_user_count_route, "analytics", live_users::get_live_user_count);
site_route!(overview_route, "analytics", overview::get_overview);
site_route!(overview_time_series_route, "analytics", overview::get_overview_bucketed);
site_route!(overview_lite_route, "analytics", lite::get_overview_lite);
site_route!(overview_bucketed_lite_route, "analytics", lite::get_overview_bucketed_lite);
site_route!(metric_lite_route, "analytics", lite::get_metric_lite);
site_route!(metric_route, "analytics", metric::get_metric);
site_route!(page_titles_route, "analytics", page_titles::get_page_titles);
site_route!(retention_route, "analytics", retention::get_retention);
site_route!(journeys_route, "analytics", journeys::get_journeys);
site_route!(has_data_route, "sites", site_data::get_site_has_data);
site_route!(is_public_route, "sites", site_data::get_site_is_public);
site_route!(site_event_count_route, "events", event_counts::get_site_event_count);

/// GET /api/org-event-count/:organizationId (`orgAnalyticsRead`)
async fn org_event_count_route(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = param_too_long(&method, &uri).await {
        return response;
    }
    org_event_count(state, organization_id, headers, uri).await
}

/// GET /api/org-event-count/ : find-my-way matches an empty parameter, so the
/// guard answers (400 `Organization ID required`) instead of the not-found handler.
async fn org_event_count_empty_route(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    org_event_count(state, String::new(), headers, uri).await
}

async fn org_event_count(state: AppState, organization_id: String, headers: HeaderMap, uri: Uri) -> Response {
    let request =
        match org_scoped(&state, &headers, &uri, &organization_id, false, route_scope("analytics", "read")).await {
            Ok(request) => request,
            Err(response) => return response,
        };
    let Some(backend) = LiveBackend::new(&state, &request.auth) else { return client_unavailable() };
    outcome_response(event_counts::get_org_event_count(&backend, &organization_id, &request.query).await)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/sites/{siteId}/live-user-count", get(live_user_count_route))
        .route("/api/sites/{siteId}/overview", get(overview_route))
        .route("/api/sites/{siteId}/overview/time-series", get(overview_time_series_route))
        .route("/api/sites/{siteId}/overview-lite", get(overview_lite_route))
        .route("/api/sites/{siteId}/overview-bucketed-lite", get(overview_bucketed_lite_route))
        .route("/api/sites/{siteId}/metric-lite", get(metric_lite_route))
        .route("/api/sites/{siteId}/metric", get(metric_route))
        .route("/api/sites/{siteId}/page-titles", get(page_titles_route))
        .route("/api/sites/{siteId}/retention", get(retention_route))
        .route("/api/sites/{siteId}/journeys", get(journeys_route))
        .route("/api/sites/{siteId}/has-data", get(has_data_route))
        .route("/api/sites/{siteId}/is-public", get(is_public_route))
        .route("/api/sites/{siteId}/events/count", get(site_event_count_route))
        .route("/api/org-event-count/{organizationId}", get(org_event_count_route))
        .route("/api/org-event-count/", get(org_event_count_empty_route))
}
