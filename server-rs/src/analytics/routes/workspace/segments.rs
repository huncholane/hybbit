//! Saved segments, ported from server/src/api/analytics/segments (getSegments,
//! getSegment, createSegment, updateSegment, deleteSegment and segmentAccess).
//!
//! The rules: anyone with site access reads every segment; everyone else reads
//! public ones. Admins and owners (org admins, system admins, the organization's
//! own API key) edit anything; members edit what they created. A private segment
//! is a 404 to a viewer without site access, never a 403.
//!
//! The handler bodies are generic over the store and the caller so the vitest
//! suite (segmentAccess.test.ts), which mocks both, ports as unit tests.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use sqlx::{PgPool, Row, postgres::PgRow};
use tracing::{debug, error, info};

use super::{
    access::RequestAccess,
    request::{self, object, pg_int},
    schema::validation_error_body,
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::{JsValue, date, json, number::parse_int_10},
        segments::segment_schema::{Nullable, SegmentBody, SegmentScope, parse_create_segment_body, parse_update_segment_body},
        types::Filter,
        utils::time_window::now_ms,
    },
    state::AppState,
};

/// A failure inside a handler's `try`: answered with its 500.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("integer out of range for type integer")]
    OutOfRange,
}

fn bind_int(id: f64) -> Result<i32, StoreError> {
    pg_int(id).ok_or(StoreError::OutOfRange)
}

/// `SegmentRow` as drizzle returns it.
#[derive(Clone, Debug, PartialEq)]
pub struct SegmentRow {
    pub segment_id: i32,
    pub organization_id: String,
    pub site_id: Option<i32>,
    pub user_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub filters: JsValue,
    pub is_public: bool,
    pub kind: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// The values `createSegment` inserts.
#[derive(Clone, Debug, PartialEq)]
pub struct NewSegment {
    pub organization_id: String,
    pub site_id: Option<i32>,
    pub user_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub filters: Vec<Filter>,
    pub is_public: bool,
}

/// The `.set()` of `updateSegment`: `None` leaves a column alone.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SegmentChanges {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub filters: Option<Vec<Filter>>,
    pub is_public: Option<bool>,
    pub site_id: Option<Option<i32>>,
    /// `new Date().toISOString()`
    pub updated_at: String,
}

/// The Postgres side of the segment handlers.
pub trait SegmentStore {
    /// `getSiteOrganizationId`
    fn site_organization_id(&self, site_id: f64) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;
    /// `db.query.segments.findFirst({ where: segmentId })`
    fn find(&self, segment_id: f64) -> impl Future<Output = Result<Option<SegmentRow>, StoreError>> + Send;
    /// `findMany` over `segmentsForSiteCondition`, by name
    fn list(&self, site_id: f64, organization_id: &str) -> impl Future<Output = Result<Vec<SegmentRow>, StoreError>> + Send;
    fn insert(&self, segment: NewSegment) -> impl Future<Output = Result<Option<SegmentRow>, StoreError>> + Send;
    fn update(&self, segment_id: f64, changes: SegmentChanges) -> impl Future<Output = Result<Option<SegmentRow>, StoreError>> + Send;
    /// Whether a row was deleted
    fn delete(&self, segment_id: f64) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// What `resolveSegmentActor` reads off the request.
pub trait Caller {
    /// `request.user?.id`
    fn user_id(&self) -> Option<String>;
    /// `request.apiKeyOrganizationId`
    fn api_key_organization_id(&self) -> Option<String>;
    /// `getUserHasAccessToSite(request, siteId)`
    fn has_site_access(&self, site_id: f64) -> impl Future<Output = bool> + Send;
    /// `isOrgAdmin(await getOrgMembership(userId, organizationId))`
    fn is_org_admin(&self, user_id: &str, organization_id: &str) -> impl Future<Output = Result<bool, StoreError>> + Send;
    /// `getIsUserAdmin(request)`
    fn is_system_admin(&self) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// `SegmentActor`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentActor {
    pub user_id: Option<String>,
    pub has_site_access: bool,
    pub is_admin: bool,
}

const NO_ACCESS_ACTOR: SegmentActor = SegmentActor { user_id: None, has_site_access: false, is_admin: false };

/// `resolveSegmentActor`
pub async fn resolve_segment_actor<C: Caller>(caller: &C, site_id: f64, organization_id: &str) -> Result<SegmentActor, StoreError> {
    // `!request.user?.id && request.apiKeyOrganizationId`, by truthiness
    let user_id = caller.user_id().filter(|id| !id.is_empty());
    if user_id.is_none()
        && let Some(key_organization) = caller.api_key_organization_id().filter(|id| !id.is_empty())
    {
        let owns_site = key_organization == organization_id;
        return Ok(SegmentActor { user_id: None, has_site_access: owns_site, is_admin: owns_site });
    }
    let Some(user_id) = user_id else { return Ok(NO_ACCESS_ACTOR) };
    let has_site_access = caller.has_site_access(site_id).await;
    let org_admin = caller.is_org_admin(&user_id, organization_id).await?;
    let system_admin = caller.is_system_admin().await?;
    Ok(SegmentActor { user_id: Some(user_id), has_site_access, is_admin: system_admin || org_admin })
}

/// `canReadSegment`
pub fn can_read_segment(is_public: bool, actor: &SegmentActor) -> bool {
    actor.has_site_access || is_public
}

/// `canEditSegment`
pub fn can_edit_segment(segment_user_id: Option<&str>, actor: &SegmentActor) -> bool {
    if actor.is_admin {
        return true;
    }
    actor.has_site_access && actor.user_id.is_some() && segment_user_id == actor.user_id.as_deref()
}

/// `segmentBelongsToSite`
pub fn segment_belongs_to_site(segment_site: Option<i32>, segment_organization: &str, site_id: f64, organization_id: &str) -> bool {
    segment_organization == organization_id && segment_site.is_none_or(|id| f64::from(id) == site_id)
}

/// `serializeSegment`
pub fn serialize_segment(row: &SegmentRow, actor: &SegmentActor) -> JsValue {
    let text = |value: &Option<String>| value.clone().map_or(JsValue::Null, JsValue::String);
    object(vec![
        ("segmentId", JsValue::Number(f64::from(row.segment_id))),
        ("siteId", row.site_id.map_or(JsValue::Null, |id| JsValue::Number(f64::from(id)))),
        ("organizationId", JsValue::String(row.organization_id.clone())),
        ("userId", if actor.has_site_access { text(&row.user_id) } else { JsValue::Null }),
        ("name", JsValue::String(row.name.clone())),
        ("description", text(&row.description)),
        ("filters", row.filters.clone()),
        ("isPublic", JsValue::Bool(row.is_public)),
        ("type", JsValue::String(row.kind.clone())),
        ("createdAt", JsValue::String(row.created_at.clone().unwrap_or_default())),
        ("updatedAt", JsValue::String(row.updated_at.clone().unwrap_or_default())),
        ("canEdit", JsValue::Bool(can_edit_segment(row.user_id.as_deref(), actor))),
    ])
}

/// `parsePositiveId`
pub fn parse_positive_id(raw: &str) -> Option<f64> {
    let id = parse_int_10(raw);
    (!id.is_nan() && id > 0.0).then_some(id)
}

/// `loadSegmentForSite`
async fn load_segment_for_site<S: SegmentStore>(store: &S, site_id: f64, segment_id: f64) -> Result<Option<(SegmentRow, String)>, StoreError> {
    let Some(organization_id) = store.site_organization_id(site_id).await? else { return Ok(None) };
    let Some(segment) = store.find(segment_id).await? else { return Ok(None) };
    if !segment_belongs_to_site(segment.site_id, &segment.organization_id, site_id, &organization_id) {
        return Ok(None);
    }
    Ok(Some((segment, organization_id)))
}

/// A handler's answer before it becomes an HTTP response.
#[derive(Clone, Debug, PartialEq)]
pub struct Reply {
    pub status: StatusCode,
    pub body: JsValue,
}

impl Reply {
    fn ok(body: JsValue) -> Self {
        Self { status: StatusCode::OK, body }
    }

    fn error(status: StatusCode, message: &str) -> Self {
        Self { status, body: object(vec![("error", message.into())]) }
    }

    fn failed(err: &StoreError, message: &str) -> Self {
        error!(error = %err, "{message}");
        Self::error(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    fn into_response(self) -> Response {
        request::send(self.status, &self.body)
    }
}

/// `getSegments`
pub async fn get_segments<S: SegmentStore, C: Caller>(store: &S, caller: &C, site_param: &str) -> Reply {
    let Some(site_id) = parse_positive_id(site_param) else {
        return Reply::error(StatusCode::BAD_REQUEST, "Invalid site ID");
    };
    let result: Result<Reply, StoreError> = async {
        let Some(organization_id) = store.site_organization_id(site_id).await? else {
            return Ok(Reply::error(StatusCode::NOT_FOUND, "Site not found"));
        };
        let actor = resolve_segment_actor(caller, site_id, &organization_id).await;
        let rows = store.list(site_id, &organization_id).await;
        let (actor, rows) = (actor?, rows?);
        let visible: Vec<JsValue> =
            rows.iter().filter(|row| can_read_segment(row.is_public, &actor)).map(|row| serialize_segment(row, &actor)).collect();
        debug!(site_id, total = rows.len(), visible = visible.len(), "Fetched segments");
        Ok(Reply::ok(JsValue::Array(visible)))
    }
    .await;
    result.unwrap_or_else(|err| Reply::failed(&err, "Failed to fetch segments"))
}

fn ids(site_param: &str, segment_param: &str) -> Result<(f64, f64), Reply> {
    let site_id = parse_positive_id(site_param);
    let segment_id = parse_positive_id(segment_param);
    let Some(site_id) = site_id else {
        return Err(Reply::error(StatusCode::BAD_REQUEST, "Invalid site ID"));
    };
    let Some(segment_id) = segment_id else {
        return Err(Reply::error(StatusCode::BAD_REQUEST, "Invalid segment ID"));
    };
    Ok((site_id, segment_id))
}

/// `getSegment`
pub async fn get_segment<S: SegmentStore, C: Caller>(store: &S, caller: &C, site_param: &str, segment_param: &str) -> Reply {
    let (site_id, segment_id) = match ids(site_param, segment_param) {
        Ok(ids) => ids,
        Err(reply) => return reply,
    };
    let result: Result<Reply, StoreError> = async {
        let Some((segment, organization_id)) = load_segment_for_site(store, site_id, segment_id).await? else {
            return Ok(Reply::error(StatusCode::NOT_FOUND, "Segment not found"));
        };
        let actor = resolve_segment_actor(caller, site_id, &organization_id).await?;
        if !can_read_segment(segment.is_public, &actor) {
            return Ok(Reply::error(StatusCode::NOT_FOUND, "Segment not found"));
        }
        Ok(Reply::ok(serialize_segment(&segment, &actor)))
    }
    .await;
    result.unwrap_or_else(|err| Reply::failed(&err, "Failed to fetch segment"))
}

/// `createSegment`
pub async fn create_segment<S: SegmentStore, C: Caller>(store: &S, caller: &C, site_param: &str, body: &JsValue) -> Reply {
    let Some(site_id) = parse_positive_id(site_param) else {
        return Reply::error(StatusCode::BAD_REQUEST, "Invalid site ID");
    };
    let body: SegmentBody = match parse_create_segment_body(body) {
        Ok(body) => body,
        Err(issues) => return Reply { status: StatusCode::BAD_REQUEST, body: validation_error_body(&issues) },
    };
    let result: Result<Reply, StoreError> = async {
        let Some(organization_id) = store.site_organization_id(site_id).await? else {
            return Ok(Reply::error(StatusCode::NOT_FOUND, "Site not found"));
        };
        let actor = resolve_segment_actor(caller, site_id, &organization_id).await?;
        if !actor.has_site_access {
            return Ok(Reply::error(StatusCode::FORBIDDEN, "Forbidden"));
        }
        let org_wide = body.scope == Some(SegmentScope::Organization);
        if org_wide && !actor.is_admin {
            return Ok(Reply::error(StatusCode::FORBIDDEN, "Only organization admins can create organization-wide segments"));
        }
        let new_segment = NewSegment {
            organization_id,
            site_id: if org_wide { None } else { Some(bind_int(site_id)?) },
            user_id: actor.user_id.clone(),
            name: body.name.clone().unwrap_or_default(),
            description: match &body.description {
                Nullable::Value(text) => Some(text.clone()),
                _ => None,
            },
            filters: body.filters.clone().unwrap_or_default(),
            is_public: body.is_public.unwrap_or(false),
        };
        let Some(row) = store.insert(new_segment).await? else {
            return Ok(Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create segment"));
        };
        info!(site_id, segment_id = row.segment_id, org_wide, "Segment created");
        Ok(Reply { status: StatusCode::CREATED, body: serialize_segment(&row, &actor) })
    }
    .await;
    result.unwrap_or_else(|err| Reply::failed(&err, "Failed to create segment"))
}

/// `updateSegment`
pub async fn update_segment<S: SegmentStore, C: Caller>(
    store: &S,
    caller: &C,
    site_param: &str,
    segment_param: &str,
    body: &JsValue,
) -> Reply {
    let (site_id, segment_id) = match ids(site_param, segment_param) {
        Ok(ids) => ids,
        Err(reply) => return reply,
    };
    let body: SegmentBody = match parse_update_segment_body(body) {
        Ok(body) => body,
        Err(issues) => return Reply { status: StatusCode::BAD_REQUEST, body: validation_error_body(&issues) },
    };
    let result: Result<Reply, StoreError> = async {
        let Some((segment, organization_id)) = load_segment_for_site(store, site_id, segment_id).await? else {
            return Ok(Reply::error(StatusCode::NOT_FOUND, "Segment not found"));
        };
        let actor = resolve_segment_actor(caller, site_id, &organization_id).await?;
        if !can_read_segment(segment.is_public, &actor) {
            return Ok(Reply::error(StatusCode::NOT_FOUND, "Segment not found"));
        }
        if !can_edit_segment(segment.user_id.as_deref(), &actor) {
            return Ok(Reply::error(StatusCode::FORBIDDEN, "You can only edit segments you created"));
        }
        let becomes_org_wide = body.scope == Some(SegmentScope::Organization) && segment.site_id.is_some();
        if becomes_org_wide && !actor.is_admin {
            return Ok(Reply::error(StatusCode::FORBIDDEN, "Only organization admins can share a segment with every site"));
        }
        let changes = SegmentChanges {
            name: body.name.clone(),
            description: match &body.description {
                Nullable::Absent => None,
                Nullable::Null => Some(None),
                Nullable::Value(text) => Some(Some(text.clone())),
            },
            filters: body.filters.clone(),
            is_public: body.is_public,
            site_id: match body.scope {
                None => None,
                Some(SegmentScope::Organization) => Some(None),
                Some(SegmentScope::Site) => Some(Some(bind_int(site_id)?)),
            },
            updated_at: date::to_iso_string(now_ms()).unwrap_or_default(),
        };
        let Some(row) = store.update(segment_id, changes).await? else {
            return Ok(Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update segment"));
        };
        info!(site_id, segment_id = row.segment_id, "Segment updated");
        Ok(Reply::ok(serialize_segment(&row, &actor)))
    }
    .await;
    result.unwrap_or_else(|err| Reply::failed(&err, "Failed to update segment"))
}

/// `deleteSegment`
pub async fn delete_segment<S: SegmentStore, C: Caller>(store: &S, caller: &C, site_param: &str, segment_param: &str) -> Reply {
    let (site_id, segment_id) = match ids(site_param, segment_param) {
        Ok(ids) => ids,
        Err(reply) => return reply,
    };
    let result: Result<Reply, StoreError> = async {
        let Some((segment, organization_id)) = load_segment_for_site(store, site_id, segment_id).await? else {
            return Ok(Reply::error(StatusCode::NOT_FOUND, "Segment not found"));
        };
        let actor = resolve_segment_actor(caller, site_id, &organization_id).await?;
        if !can_read_segment(segment.is_public, &actor) {
            return Ok(Reply::error(StatusCode::NOT_FOUND, "Segment not found"));
        }
        if !can_edit_segment(segment.user_id.as_deref(), &actor) {
            return Ok(Reply::error(StatusCode::FORBIDDEN, "You can only delete segments you created"));
        }
        if !store.delete(segment_id).await? {
            return Ok(Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete segment"));
        }
        info!(site_id, segment_id, "Segment deleted");
        Ok(Reply::ok(object(vec![("success", true.into())])))
    }
    .await;
    result.unwrap_or_else(|err| Reply::failed(&err, "Failed to delete segment"))
}

/// The segments table in Postgres.
pub struct PgSegments<'a> {
    pub pg: &'a PgPool,
}

const SEGMENT_COLUMNS: &str = r#""segment_id", "organization_id", "site_id", "user_id", "name", "description",
    "filters"::text as "filters", "is_public", "type", "created_at"::text as "created_at",
    "updated_at"::text as "updated_at""#;

fn segment_row(row: &PgRow) -> Result<SegmentRow, sqlx::Error> {
    let filters_text: String = row.try_get("filters")?;
    Ok(SegmentRow {
        segment_id: row.try_get("segment_id")?,
        organization_id: row.try_get("organization_id")?,
        site_id: row.try_get("site_id")?,
        user_id: row.try_get("user_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        filters: json::parse(&filters_text).unwrap_or(JsValue::String(filters_text)),
        is_public: row.try_get("is_public")?,
        kind: row.try_get("type")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// `JSON.stringify(filters)`, as drizzle's jsonb column serialises it
fn filters_json(filters: &[Filter]) -> String {
    json::stringify(&JsValue::Array(filters.iter().map(Filter::to_js).collect())).unwrap_or_default()
}

impl SegmentStore for PgSegments<'_> {
    async fn site_organization_id(&self, site_id: f64) -> Result<Option<String>, StoreError> {
        let organization: Option<Option<String>> =
            sqlx::query_scalar(r#"select "organization_id" from "sites" where "sites"."site_id" = $1 limit 1"#)
                .bind(bind_int(site_id)?)
                .fetch_optional(self.pg)
                .await?;
        Ok(organization.flatten())
    }

    async fn find(&self, segment_id: f64) -> Result<Option<SegmentRow>, StoreError> {
        let row = sqlx::query(&format!(r#"select {SEGMENT_COLUMNS} from "segments" where "segments"."segment_id" = $1 limit 1"#))
            .bind(bind_int(segment_id)?)
            .fetch_optional(self.pg)
            .await?;
        Ok(row.as_ref().map(segment_row).transpose()?)
    }

    async fn list(&self, site_id: f64, organization_id: &str) -> Result<Vec<SegmentRow>, StoreError> {
        let rows = sqlx::query(&format!(
            r#"select {SEGMENT_COLUMNS} from "segments"
               where ("segments"."organization_id" = $1 and ("segments"."site_id" is null or "segments"."site_id" = $2))
               order by "segments"."name" asc"#
        ))
        .bind(organization_id)
        .bind(bind_int(site_id)?)
        .fetch_all(self.pg)
        .await?;
        Ok(rows.iter().map(segment_row).collect::<Result<Vec<_>, _>>()?)
    }

    async fn insert(&self, segment: NewSegment) -> Result<Option<SegmentRow>, StoreError> {
        let row = sqlx::query(&format!(
            r#"insert into "segments" ("organization_id", "site_id", "user_id", "name", "description", "filters", "is_public")
               values ($1, $2, $3, $4, $5, $6::jsonb, $7) returning {SEGMENT_COLUMNS}"#
        ))
        .bind(&segment.organization_id)
        .bind(segment.site_id)
        .bind(&segment.user_id)
        .bind(&segment.name)
        .bind(&segment.description)
        .bind(filters_json(&segment.filters))
        .bind(segment.is_public)
        .fetch_optional(self.pg)
        .await?;
        Ok(row.as_ref().map(segment_row).transpose()?)
    }

    async fn update(&self, segment_id: f64, changes: SegmentChanges) -> Result<Option<SegmentRow>, StoreError> {
        let mut assignments = Vec::new();
        let mut position = 1;
        let mut push = |column: &str, cast: &str| {
            assignments.push(format!(r#""{column}" = ${position}{cast}"#));
            position += 1;
        };
        if changes.name.is_some() {
            push("name", "");
        }
        if changes.description.is_some() {
            push("description", "");
        }
        if changes.filters.is_some() {
            push("filters", "::jsonb");
        }
        if changes.is_public.is_some() {
            push("is_public", "");
        }
        if changes.site_id.is_some() {
            push("site_id", "");
        }
        push("updated_at", "::timestamp");
        let sql = format!(
            r#"update "segments" set {} where "segments"."segment_id" = ${position} returning {SEGMENT_COLUMNS}"#,
            assignments.join(", ")
        );
        let mut statement = sqlx::query(&sql);
        if let Some(name) = changes.name {
            statement = statement.bind(name);
        }
        if let Some(description) = changes.description {
            statement = statement.bind(description);
        }
        if let Some(filters) = &changes.filters {
            statement = statement.bind(filters_json(filters));
        }
        if let Some(is_public) = changes.is_public {
            statement = statement.bind(is_public);
        }
        if let Some(site_id) = changes.site_id {
            statement = statement.bind(site_id);
        }
        let row = statement.bind(changes.updated_at).bind(bind_int(segment_id)?).fetch_optional(self.pg).await?;
        Ok(row.as_ref().map(segment_row).transpose()?)
    }

    async fn delete(&self, segment_id: f64) -> Result<bool, StoreError> {
        let deleted: Option<i32> =
            sqlx::query_scalar(r#"delete from "segments" where "segments"."segment_id" = $1 returning "segment_id""#)
                .bind(bind_int(segment_id)?)
                .fetch_optional(self.pg)
                .await?;
        Ok(deleted.is_some())
    }
}

impl Caller for RequestAccess<'_> {
    fn user_id(&self) -> Option<String> {
        RequestAccess::user_id(self).map(str::to_string)
    }

    fn api_key_organization_id(&self) -> Option<String> {
        RequestAccess::api_key_organization_id(self).map(str::to_string)
    }

    async fn has_site_access(&self, site_id: f64) -> bool {
        self.has_site(site_id, false).await
    }

    async fn is_org_admin(&self, user_id: &str, organization_id: &str) -> Result<bool, StoreError> {
        Ok(RequestAccess::is_org_admin(self, user_id, organization_id).await?)
    }

    async fn is_system_admin(&self) -> Result<bool, StoreError> {
        Ok(RequestAccess::is_system_admin(self).await?)
    }
}

async fn read_chain(state: &AppState, uri: &Uri, headers: &HeaderMap, site_param: &str) -> Result<crate::analytics::chain::SiteRequest, Response> {
    site_scoped(state, headers, uri, site_param, SiteGuard::Public, route_scope("segments", "read"), ChainSteps::FULL).await
}

async fn write_chain(state: &AppState, uri: &Uri, headers: &HeaderMap, site_param: &str) -> Result<crate::analytics::chain::SiteRequest, Response> {
    site_scoped(state, headers, uri, site_param, SiteGuard::Member, route_scope("segments", "write"), ChainSteps::FULL).await
}

/// GET /api/sites/:siteId/segments (`publicSegmentsRead`)
pub async fn list(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let site = match read_chain(&state, &uri, &headers, &params[0]).await {
        Ok(site) => site,
        Err(response) => return response,
    };
    let caller = RequestAccess::new(&state, &headers, &site.auth);
    get_segments(&PgSegments { pg: &state.pg }, &caller, &site.site_id).await.into_response()
}

/// GET /api/sites/:siteId/segments/:segmentId (`publicSegmentsRead`)
pub async fn get_one(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let site = match read_chain(&state, &uri, &headers, &params[0]).await {
        Ok(site) => site,
        Err(response) => return response,
    };
    let caller = RequestAccess::new(&state, &headers, &site.auth);
    get_segment(&PgSegments { pg: &state.pg }, &caller, &site.site_id, &params[1]).await.into_response()
}

/// POST /api/sites/:siteId/segments (`authSegmentsWrite`)
pub async fn create(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match write_chain(&state, &uri, &headers, &params[0]).await {
        Ok(site) => site,
        Err(response) => return response,
    };
    let caller = RequestAccess::new(&state, &headers, &site.auth);
    create_segment(&PgSegments { pg: &state.pg }, &caller, &site.site_id, &body).await.into_response()
}

/// PUT /api/sites/:siteId/segments/:segmentId (`authSegmentsWrite`)
pub async fn update(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match write_chain(&state, &uri, &headers, &params[0]).await {
        Ok(site) => site,
        Err(response) => return response,
    };
    let caller = RequestAccess::new(&state, &headers, &site.auth);
    update_segment(&PgSegments { pg: &state.pg }, &caller, &site.site_id, &params[1], &body).await.into_response()
}

/// DELETE /api/sites/:siteId/segments/:segmentId (`authSegmentsWrite`)
pub async fn delete(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    if let Err(response) = request::read_body(&headers, body).await {
        return response;
    }
    let site = match write_chain(&state, &uri, &headers, &params[0]).await {
        Ok(site) => site,
        Err(response) => return response,
    };
    let caller = RequestAccess::new(&state, &headers, &site.auth);
    delete_segment(&PgSegments { pg: &state.pg }, &caller, &site.site_id, &params[1]).await.into_response()
}

#[cfg(test)]
mod tests {
    //! Ported from segmentAccess.test.ts: the handlers run against an in-memory
    //! store and a scripted caller, as the vitest suite mocks Postgres and the
    //! access lookups.
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct State {
        site_organization: Option<String>,
        segments: Vec<SegmentRow>,
        site_access: bool,
        membership_role: Option<String>,
        system_admin: bool,
        writes: Vec<(String, Option<NewSegment>, Option<SegmentChanges>)>,
    }

    struct Fixture {
        state: Mutex<State>,
        user_id: Option<String>,
        api_key_organization_id: Option<String>,
    }

    impl SegmentStore for Fixture {
        async fn site_organization_id(&self, _: f64) -> Result<Option<String>, StoreError> {
            Ok(self.state.lock().unwrap().site_organization.clone())
        }
        async fn find(&self, _: f64) -> Result<Option<SegmentRow>, StoreError> {
            Ok(self.state.lock().unwrap().segments.first().cloned())
        }
        async fn list(&self, _: f64, _: &str) -> Result<Vec<SegmentRow>, StoreError> {
            Ok(self.state.lock().unwrap().segments.clone())
        }
        async fn insert(&self, segment: NewSegment) -> Result<Option<SegmentRow>, StoreError> {
            let mut state = self.state.lock().unwrap();
            state.writes.push(("insert".into(), Some(segment.clone()), None));
            Ok(Some(SegmentRow {
                segment_id: 99,
                organization_id: segment.organization_id,
                site_id: segment.site_id,
                user_id: segment.user_id,
                name: segment.name,
                description: segment.description,
                filters: JsValue::Array(segment.filters.iter().map(Filter::to_js).collect()),
                is_public: segment.is_public,
                kind: "segment".into(),
                created_at: None,
                updated_at: None,
            }))
        }
        async fn update(&self, _: f64, changes: SegmentChanges) -> Result<Option<SegmentRow>, StoreError> {
            let mut state = self.state.lock().unwrap();
            state.writes.push(("update".into(), None, Some(changes.clone())));
            let mut row = state.segments[0].clone();
            if let Some(name) = changes.name {
                row.name = name;
            }
            if let Some(is_public) = changes.is_public {
                row.is_public = is_public;
            }
            Ok(Some(row))
        }
        async fn delete(&self, _: f64) -> Result<bool, StoreError> {
            let mut state = self.state.lock().unwrap();
            state.writes.push(("delete".into(), None, None));
            Ok(!state.segments.is_empty())
        }
    }

    impl Caller for Fixture {
        fn user_id(&self) -> Option<String> {
            self.user_id.clone()
        }
        fn api_key_organization_id(&self) -> Option<String> {
            self.api_key_organization_id.clone()
        }
        async fn has_site_access(&self, _: f64) -> bool {
            self.state.lock().unwrap().site_access
        }
        async fn is_org_admin(&self, _: &str, _: &str) -> Result<bool, StoreError> {
            Ok(matches!(self.state.lock().unwrap().membership_role.as_deref(), Some("admin" | "owner")))
        }
        async fn is_system_admin(&self) -> Result<bool, StoreError> {
            Ok(self.state.lock().unwrap().system_admin)
        }
    }

    fn filters_body() -> &'static str {
        r#"[{"parameter":"device_type","type":"equals","value":["Mobile"]}]"#
    }

    fn segment_row(segment_id: i32, user_id: Option<&str>, site_id: Option<i32>, is_public: bool) -> SegmentRow {
        SegmentRow {
            segment_id,
            organization_id: "org_1".into(),
            site_id,
            user_id: user_id.map(str::to_string),
            name: "Mobile".into(),
            description: None,
            filters: json::parse(filters_body()).unwrap(),
            is_public,
            kind: "segment".into(),
            created_at: Some("2026-09-01T00:00:00Z".into()),
            updated_at: Some("2026-09-01T00:00:00Z".into()),
        }
    }

    fn fixture(user_id: Option<&str>, site_access: bool, role: Option<&str>, segments: Vec<SegmentRow>) -> Fixture {
        Fixture {
            state: Mutex::new(State {
                site_organization: Some("org_1".into()),
                segments,
                site_access,
                membership_role: role.map(str::to_string),
                ..Default::default()
            }),
            user_id: user_id.map(str::to_string),
            api_key_organization_id: None,
        }
    }

    fn member(segments: Vec<SegmentRow>) -> Fixture {
        fixture(Some("member_1"), true, Some("member"), segments)
    }

    fn admin(segments: Vec<SegmentRow>) -> Fixture {
        fixture(Some("admin_1"), true, Some("admin"), segments)
    }

    fn viewer(segments: Vec<SegmentRow>) -> Fixture {
        fixture(None, false, None, segments)
    }

    fn body(text: &str) -> JsValue {
        json::parse(text).unwrap()
    }

    fn field<'a>(value: &'a JsValue, name: &str) -> &'a JsValue {
        value.as_object().unwrap().get(name).unwrap()
    }

    #[tokio::test]
    async fn resolve_segment_actor_cases() {
        let mut own = viewer(vec![]);
        own.api_key_organization_id = Some("org_1".into());
        assert_eq!(
            resolve_segment_actor(&own, 1.0, "org_1").await.unwrap(),
            SegmentActor { user_id: None, has_site_access: true, is_admin: true }
        );
        let mut other = viewer(vec![]);
        other.api_key_organization_id = Some("org_2".into());
        assert_eq!(resolve_segment_actor(&other, 1.0, "org_1").await.unwrap(), NO_ACCESS_ACTOR);
        assert_eq!(resolve_segment_actor(&viewer(vec![]), 1.0, "org_1").await.unwrap(), NO_ACCESS_ACTOR);

        let owner = fixture(Some("u"), true, Some("owner"), vec![]);
        assert!(resolve_segment_actor(&owner, 1.0, "org_1").await.unwrap().is_admin);
        let plain = fixture(Some("u"), true, Some("member"), vec![]);
        assert!(!resolve_segment_actor(&plain, 1.0, "org_1").await.unwrap().is_admin);
        plain.state.lock().unwrap().system_admin = true;
        assert!(resolve_segment_actor(&plain, 1.0, "org_1").await.unwrap().is_admin);
    }

    #[test]
    fn rule_predicates() {
        let admin = SegmentActor { user_id: Some("a".into()), has_site_access: true, is_admin: true };
        let member = SegmentActor { user_id: Some("member_1".into()), has_site_access: true, is_admin: false };
        let viewer = NO_ACCESS_ACTOR;
        assert!(can_read_segment(false, &member));
        assert!(!can_read_segment(false, &viewer));
        assert!(can_read_segment(true, &viewer));
        assert!(can_edit_segment(Some("someone_else"), &admin));
        assert!(can_edit_segment(Some("member_1"), &member));
        assert!(!can_edit_segment(Some("someone_else"), &member));
        assert!(!can_edit_segment(None, &member));
        assert!(!can_edit_segment(None, &viewer));
        assert!(segment_belongs_to_site(Some(1), "org_1", 1.0, "org_1"));
        assert!(segment_belongs_to_site(None, "org_1", 2.0, "org_1"));
        assert!(!segment_belongs_to_site(Some(2), "org_1", 1.0, "org_1"));
        assert!(!segment_belongs_to_site(None, "org_2", 1.0, "org_1"));
    }

    #[tokio::test]
    async fn get_segments_cases() {
        let store = viewer(vec![segment_row(7, Some("member_1"), Some(1), true), segment_row(8, Some("member_1"), Some(1), false)]);
        let reply = get_segments(&store, &store, "1").await;
        assert_eq!(reply.status, StatusCode::OK);
        let JsValue::Array(items) = &reply.body else { panic!() };
        assert_eq!(items.len(), 1);
        assert_eq!(field(&items[0], "segmentId"), &JsValue::Number(7.0));
        assert_eq!(field(&items[0], "canEdit"), &JsValue::Bool(false));
        assert_eq!(field(&items[0], "userId"), &JsValue::Null);

        let store = member(vec![segment_row(7, Some("member_1"), Some(1), false), segment_row(8, Some("admin_1"), Some(1), false)]);
        let reply = get_segments(&store, &store, "1").await;
        let JsValue::Array(items) = &reply.body else { panic!() };
        let flags: Vec<(JsValue, JsValue)> =
            items.iter().map(|item| (field(item, "segmentId").clone(), field(item, "canEdit").clone())).collect();
        assert_eq!(flags, vec![(7.0.into(), true.into()), (8.0.into(), false.into())]);

        let store = member(vec![]);
        store.state.lock().unwrap().site_organization = None;
        assert_eq!(get_segments(&store, &store, "1").await.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_segment_cases() {
        let store = viewer(vec![segment_row(7, Some("member_1"), Some(1), false)]);
        assert_eq!(get_segment(&store, &store, "1", "7").await.status, StatusCode::NOT_FOUND);
        let store = admin(vec![segment_row(7, Some("member_1"), Some(2), false)]);
        assert_eq!(get_segment(&store, &store, "1", "7").await.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_segment_cases() {
        let store = member(vec![]);
        let reply = create_segment(&store, &store, "1", &body(&format!(r#"{{"name":"Mobile","filters":{}}}"#, filters_body()))).await;
        assert_eq!(reply.status, StatusCode::CREATED);
        let written = store.state.lock().unwrap().writes[0].1.clone().unwrap();
        assert_eq!((written.organization_id.as_str(), written.site_id, written.user_id.as_deref(), written.is_public), ("org_1", Some(1), Some("member_1"), false));
        assert_eq!(field(&reply.body, "canEdit"), &JsValue::Bool(true));

        let store = member(vec![]);
        let org_wide = body(&format!(r#"{{"name":"Paid","filters":{},"scope":"organization"}}"#, filters_body()));
        assert_eq!(create_segment(&store, &store, "1", &org_wide).await.status, StatusCode::FORBIDDEN);
        assert!(store.state.lock().unwrap().writes.is_empty());
        let store = admin(vec![]);
        assert_eq!(create_segment(&store, &store, "1", &org_wide).await.status, StatusCode::CREATED);
        assert_eq!(store.state.lock().unwrap().writes[0].1.as_ref().unwrap().site_id, None);

        let store = admin(vec![]);
        let reply =
            create_segment(&store, &store, "1", &body(r#"{"name":"Bad","filters":[{"parameter":"session_id","type":"equals","value":["x"]}]}"#))
                .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(field(&reply.body, "error"), &JsValue::String("Validation error".into()));
        assert!(store.state.lock().unwrap().writes.is_empty());

        let store = viewer(vec![]);
        let reply = create_segment(&store, &store, "1", &body(&format!(r#"{{"name":"Mobile","filters":{}}}"#, filters_body()))).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn update_segment_cases() {
        let store = member(vec![segment_row(7, Some("member_1"), Some(1), false)]);
        let reply = update_segment(&store, &store, "1", "7", &body(r#"{"name":"Renamed"}"#)).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(store.state.lock().unwrap().writes[0].2.as_ref().unwrap().name.as_deref(), Some("Renamed"));

        let store = member(vec![segment_row(7, Some("admin_1"), Some(1), false)]);
        assert_eq!(update_segment(&store, &store, "1", "7", &body(r#"{"name":"Renamed"}"#)).await.status, StatusCode::FORBIDDEN);
        assert!(store.state.lock().unwrap().writes.is_empty());

        let store = admin(vec![segment_row(7, Some("member_1"), Some(1), false)]);
        assert_eq!(update_segment(&store, &store, "1", "7", &body(r#"{"isPublic":true}"#)).await.status, StatusCode::OK);
        assert_eq!(store.state.lock().unwrap().writes[0].2.as_ref().unwrap().is_public, Some(true));

        let store = member(vec![segment_row(7, Some("member_1"), Some(1), false)]);
        assert_eq!(update_segment(&store, &store, "1", "7", &body(r#"{"scope":"organization"}"#)).await.status, StatusCode::FORBIDDEN);
        assert!(store.state.lock().unwrap().writes.is_empty());

        let store = admin(vec![segment_row(7, Some("member_1"), Some(1), false)]);
        let reply = update_segment(&store, &store, "1", "7", &body(r#"{"filters":[{"parameter":"browser","type":"equals","value":[]}]}"#)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_segment_cases() {
        let store = member(vec![segment_row(7, Some("member_1"), Some(1), false)]);
        assert_eq!(delete_segment(&store, &store, "1", "7").await.status, StatusCode::OK);
        assert_eq!(store.state.lock().unwrap().writes.len(), 1);

        let store = member(vec![segment_row(7, Some("admin_1"), Some(1), false)]);
        assert_eq!(delete_segment(&store, &store, "1", "7").await.status, StatusCode::FORBIDDEN);
        assert!(store.state.lock().unwrap().writes.is_empty());
        let store = admin(vec![segment_row(7, Some("admin_1"), Some(1), false)]);
        assert_eq!(delete_segment(&store, &store, "1", "7").await.status, StatusCode::OK);

        let store = viewer(vec![segment_row(7, Some("member_1"), Some(1), true)]);
        assert_eq!(delete_segment(&store, &store, "1", "7").await.status, StatusCode::FORBIDDEN);
        assert!(store.state.lock().unwrap().writes.is_empty());
    }
}
