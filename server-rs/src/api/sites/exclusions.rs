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

/// What the two `:siteId` checks in `loadSiteConfigForSettings` decide, before
/// anything is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettingsSiteId {
    /// The id to `reload` with
    Numeric(i32),
    /// `siteParamsSchema` rejected it: 400 with the flattened issue
    SchemaError,
    /// Not a positive integer: 400 with the plain message
    NotPositive,
    /// A positive integer Postgres cannot bind, so `reload` throws and the caller
    /// answers with its own 500
    OutOfRange,
}

/// The pure half of `loadSiteConfigForSettings`, so the two checks are testable
/// without a store.
fn settings_site_id(site_id: &str) -> SettingsSiteId {
    // `siteParamsSchema` = `z.object({ siteId: z.string().min(1) })`
    if request::string_length(site_id) < 1 {
        return SettingsSiteId::SchemaError;
    }
    let numeric = request::js_number(site_id);
    if !request::positive_integer(numeric) {
        return SettingsSiteId::NotPositive;
    }
    match request::pg_int(numeric) {
        Some(numeric) => SettingsSiteId::Numeric(numeric),
        None => SettingsSiteId::OutOfRange,
    }
}

/// `loadSiteConfigForSettings`
async fn load_site_config(state: &AppState, site_id: &str) -> Loaded {
    let numeric = match settings_site_id(site_id) {
        SettingsSiteId::Numeric(numeric) => numeric,
        SettingsSiteId::SchemaError => {
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
        SettingsSiteId::NotPositive => {
            return Loaded::Replied(request::failure(
                StatusCode::BAD_REQUEST,
                "Invalid site ID: must be a positive integer",
            ));
        }
        SettingsSiteId::OutOfRange => {
            error!(site_id, "Site id is not a Postgres integer; Node's reload throws here");
            return Loaded::Failed;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// server/src/api/sites/getSiteExclusions.test.ts: each endpoint answers under
    /// its own field name, taken from the same `SiteConfigData` key it reads, and
    /// the failure message reads as prose.
    #[test]
    fn every_endpoint_answers_under_its_own_field_name() {
        let fields = [
            (ExclusionField::Ips, "excludedIPs", "excluded IPs"),
            (ExclusionField::Countries, "excludedCountries", "excluded countries"),
            (ExclusionField::Paths, "excludedPaths", "excluded paths"),
            (ExclusionField::Hostnames, "excludedHostnames", "excluded hostnames"),
            (ExclusionField::UserAgents, "excludedUserAgents", "excluded user agents"),
            (ExclusionField::Asns, "excludedASNs", "excluded ASNs"),
            (ExclusionField::QueryParams, "excludedQueryParams", "excluded query params"),
        ];
        let mut config = blank_config();
        config.excluded_ips = vec!["10.0.0.1".into()];
        config.excluded_countries = vec!["DE".into()];
        config.excluded_paths = vec!["/admin".into()];
        config.excluded_hostnames = vec!["staging.example.com".into()];
        config.excluded_user_agents = vec!["curl".into()];
        config.excluded_asns = vec!["AS13335".into()];
        config.excluded_query_params = vec!["fbclid".into()];
        let expected = [
            "10.0.0.1", "DE", "/admin", "staging.example.com", "curl", "AS13335", "fbclid",
        ];
        for ((field, name, label), value) in fields.into_iter().zip(expected) {
            assert_eq!(field.name(), name);
            assert_eq!(field.label(), label);
            assert_eq!(field.values(&config), &vec![value.to_string()]);
            assert_eq!(format!("Failed to get {}", field.label()), format!("Failed to get {label}"));
        }
    }

    /// The same suite: `getSiteExcludedCountries` used to skip the positive-integer
    /// guard and pass NaN into the query, so these ids must not reach the store.
    #[test]
    fn rejects_site_ids_that_are_not_positive_integers() {
        for site_id in ["abc", "0", "-1", "1.5"] {
            assert_eq!(settings_site_id(site_id), SettingsSiteId::NotPositive, "{site_id}");
        }
        assert_eq!(settings_site_id(""), SettingsSiteId::SchemaError);
        assert_eq!(settings_site_id("123"), SettingsSiteId::Numeric(123));
        // `Number(" 123 ")` is 123, as the handler reads it
        assert_eq!(settings_site_id(" 123 "), SettingsSiteId::Numeric(123));
        assert_eq!(settings_site_id("99999999999999999999"), SettingsSiteId::OutOfRange);
    }

    fn blank_config() -> SiteConfigData {
        SiteConfigData {
            id: None,
            site_id: 123,
            organization_id: None,
            site_type: crate::site_config::SiteType::Web,
            public: false,
            embed_enabled: false,
            salt_user_ids: false,
            domain: String::new(),
            block_bots: true,
            first_party_proxy: false,
            excluded_ips: Vec::new(),
            use_organization_excluded_ips: true,
            organization_excluded_ips: Vec::new(),
            excluded_countries: Vec::new(),
            excluded_paths: Vec::new(),
            excluded_hostnames: Vec::new(),
            excluded_user_agents: Vec::new(),
            excluded_asns: Vec::new(),
            excluded_query_params: Vec::new(),
            private_link_key: None,
            session_replay: false,
            web_vitals: false,
            track_errors: false,
            track_outbound: true,
            track_url_params: true,
            track_initial_page_view: true,
            track_spa_navigation: true,
            track_ip: false,
            track_button_clicks: false,
            track_copy: false,
            track_form_interactions: false,
            track_heartbeat: false,
            heartbeat_interval: 15,
            bounce_threshold: 10,
            tags: Vec::new(),
        }
    }
}
