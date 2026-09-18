//! The seven exclusion reads and the site view of the organization's IP
//! exclusions, ported from server/src/api/sites/getSiteExclusions.ts and
//! `getSiteOrganizationExcludedIPs` in
//! server/src/api/organizationExclusions/organizationExcludedIPs.ts. All eight sit
//! on the `authSitesRead` chain.
//!
//! Every one of them goes through `loadSiteConfigForSettings`, which validates
//! `:siteId` twice (as a non-empty string, then as a positive integer) and reads
//! the Site Configuration with `reload` rather than `getConfig`: a settings screen
//! reads back the write it just made, so another worker's pre-write cache entry
//! must not answer.

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::Value;
use tracing::error;

use super::request::{self, Issues, object};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        routes::people::common::path_params,
    },
    site_config::{SiteConfigData, SiteRef},
    state::AppState,
};

/// Which list an endpoint exposes. The response key is the field name, so it
/// cannot drift from the field being read.
#[derive(Clone, Copy, Debug)]
enum ExclusionField {
    Ips,
    Countries,
    Paths,
    Hostnames,
    UserAgents,
    Asns,
    QueryParams,
}

impl ExclusionField {
    /// The `SiteConfigData` key, which is also the response key.
    fn name(self) -> &'static str {
        match self {
            ExclusionField::Ips => "excludedIPs",
            ExclusionField::Countries => "excludedCountries",
            ExclusionField::Paths => "excludedPaths",
            ExclusionField::Hostnames => "excludedHostnames",
            ExclusionField::UserAgents => "excludedUserAgents",
            ExclusionField::Asns => "excludedASNs",
            ExclusionField::QueryParams => "excludedQueryParams",
        }
    }

    /// `FIELD_LABELS`, which the failure message reads as prose.
    fn label(self) -> &'static str {
        match self {
            ExclusionField::Ips => "excluded IPs",
            ExclusionField::Countries => "excluded countries",
            ExclusionField::Paths => "excluded paths",
            ExclusionField::Hostnames => "excluded hostnames",
            ExclusionField::UserAgents => "excluded user agents",
            ExclusionField::Asns => "excluded ASNs",
            ExclusionField::QueryParams => "excluded query params",
        }
    }

    fn values(self, config: &SiteConfigData) -> &Vec<String> {
        match self {
            ExclusionField::Ips => &config.excluded_ips,
            ExclusionField::Countries => &config.excluded_countries,
            ExclusionField::Paths => &config.excluded_paths,
            ExclusionField::Hostnames => &config.excluded_hostnames,
            ExclusionField::UserAgents => &config.excluded_user_agents,
            ExclusionField::Asns => &config.excluded_asns,
            ExclusionField::QueryParams => &config.excluded_query_params,
        }
    }
}

fn list(values: &[String]) -> Value {
    Value::Array(values.iter().map(|value| Value::String(value.clone())).collect())
}

/// What `loadSiteConfigForSettings` produces: the configuration, or the reply it
/// already sent (400/404), or the Postgres failure it let out.
enum Loaded {
    Config(Box<SiteConfigData>),
    Replied(Response),
    Failed,
}

/// `loadSiteConfigForSettings`
async fn load_site_config(state: &AppState, site_id: &str) -> Loaded {
    // `siteParamsSchema` = `z.object({ siteId: z.string().min(1) })`
    if request::string_length(site_id) < 1 {
        let mut issues = Issues::default();
        issues.field("siteId", request::string_too_small(1));
        return Loaded::Replied(request::send(
            StatusCode::BAD_REQUEST,
            &object(vec![
                ("success", Value::Bool(false)),
                ("error", Value::String("Invalid site ID".into())),
                ("details", issues.flatten()),
            ]),
        ));
    }

    let numeric = request::js_number(site_id);
    if !request::positive_integer(numeric) {
        return Loaded::Replied(request::failure(
            StatusCode::BAD_REQUEST,
            "Invalid site ID: must be a positive integer",
        ));
    }
    let Some(numeric) = request::pg_int(numeric) else {
        // Outside int4 Postgres refuses the bind and `reload` lets the throw out,
        // which the caller reports as its own 500
        error!(site_id, "Site id is not a Postgres integer; Node's reload throws here");
        return Loaded::Failed;
    };

    match state.site_config.reload(&SiteRef::Number(i64::from(numeric))).await {
        Ok(Some(config)) => Loaded::Config(Box::new(config)),
        Ok(None) => Loaded::Replied(request::failure(StatusCode::NOT_FOUND, "Site not found")),
        Err(err) => {
            error!(error = %err, site_id = numeric, "Error reading the site configuration");
            Loaded::Failed
        }
    }
}

/// The `authSitesRead` chain, then `loadSiteConfigForSettings`.
async fn settings_config(
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Box<SiteConfigData>, Result<Response, ()>> {
    let params = match path_params(method, uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return Err(Ok(response)),
    };
    let site = match site_scoped(
        state,
        headers,
        uri,
        &params[0],
        SiteGuard::Member,
        route_scope("sites", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return Err(Ok(response)),
    };
    match load_site_config(state, &site.site_id).await {
        Loaded::Config(config) => Ok(config),
        Loaded::Replied(response) => Err(Ok(response)),
        Loaded::Failed => Err(Err(())),
    }
}

/// `getExclusionField`
async fn exclusion_field(
    state: AppState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    field: ExclusionField,
) -> Response {
    match settings_config(&state, &method, &uri, &headers).await {
        Ok(config) => request::send(
            StatusCode::OK,
            &object(vec![("success", Value::Bool(true)), (field.name(), list(field.values(&config)))]),
        ),
        Err(Ok(response)) => response,
        Err(Err(())) => {
            request::failure(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to get {}", field.label()))
        }
    }
}

macro_rules! exclusion_route {
    ($name:ident, $field:expr) => {
        pub async fn $name(
            State(state): State<AppState>,
            method: Method,
            uri: Uri,
            headers: HeaderMap,
        ) -> Response {
            exclusion_field(state, method, uri, headers, $field).await
        }
    };
}

exclusion_route!(excluded_ips, ExclusionField::Ips);
exclusion_route!(excluded_countries, ExclusionField::Countries);
exclusion_route!(excluded_paths, ExclusionField::Paths);
exclusion_route!(excluded_hostnames, ExclusionField::Hostnames);
exclusion_route!(excluded_user_agents, ExclusionField::UserAgents);
exclusion_route!(excluded_asns, ExclusionField::Asns);
exclusion_route!(excluded_query_params, ExclusionField::QueryParams);

/// `getSiteOrganizationExcludedIPs`: the organization's list as one Site sees it,
/// plus whether that Site applies it.
pub async fn organization_excluded_ips(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    match settings_config(&state, &method, &uri, &headers).await {
        Ok(config) => request::send(
            StatusCode::OK,
            &object(vec![
                ("success", Value::Bool(true)),
                ("organizationId", config.organization_id.clone().map_or(Value::Null, Value::String)),
                ("useOrganizationExcludedIPs", Value::Bool(config.use_organization_excluded_ips)),
                ("excludedIPs", list(&config.organization_excluded_ips)),
            ]),
        ),
        Err(Ok(response)) => response,
        Err(Err(())) => {
            request::failure(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get organization excluded IPs")
        }
    }
}
