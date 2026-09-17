//! The flag evaluation request core, ported from `evaluateFeatureFlagsForRuntime` in
//! server/src/api/featureFlags/index.ts. It serves both
//! `POST /api/site/:siteId/feature-flags/evaluate` (public, "client" runtime) and
//! `POST /api/sites/:siteId/feature-flags/evaluate` (authFlagsRead, "server" runtime).
//!
//! The route supplies what depends on the raw request (client IP resolution, GeoIP
//! and user agent parsing) through [`RequestFacts`]; everything else happens here.

use axum::http::StatusCode;
use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use sqlx::PgPool;

use super::{
    definitions::{self, DefinitionsError},
    evaluator::{self, FeatureFlagContext},
    js, query,
    schemas::{self, EvaluateFeatureFlagsBody},
};
use crate::{
    geo::Location,
    site_config::{SiteConfigData, SiteRef},
    state::AppState,
};

/// Which flags a request may see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    /// Browser SDK (`evaluateFeatureFlags`)
    Client,
    /// Server SDK with an API key (`evaluateServerFeatureFlags`)
    Server,
}

impl Runtime {
    pub fn as_str(self) -> &'static str {
        match self {
            Runtime::Client => "client",
            Runtime::Server => "server",
        }
    }
}

/// Request-dependent inputs, resolved by the route. Both are asked for only when the
/// Site has flags for the runtime, as in Node.
pub trait RequestFacts: Sync {
    /// `getLocation([resolveClientIp(request, { firstPartyProxy: site.firstPartyProxy })])[ip]`:
    /// None for unknown or private addresses and on lookup failure (Node's
    /// `.catch(() => ({}))`).
    fn location(&self, site: &SiteConfigData) -> Option<Location>;

    /// `getDeviceType(screenWidth, screenHeight, userAgentParser(getRequestUserAgent(request.headers)))`,
    /// given `body.screenWidth || 0` and `body.screenHeight || 0`.
    fn device_type(&self, screen_width: f64, screen_height: f64) -> String;
}

/// The data the core reads, so it can run against fakes in tests.
pub trait EvaluateStores: Sync {
    /// `siteConfig.getConfig(request.params.siteId)`
    fn site_config(&self, site_id_param: &str) -> impl Future<Output = Option<SiteConfigData>> + Send;
    /// `getFeatureFlagDefinitionsForRuntime(siteId, runtime)`
    fn definitions_for_runtime(
        &self,
        site_id: i32,
        runtime: Runtime,
    ) -> impl Future<Output = Result<Vec<Value>, DefinitionsError>> + Send;
    /// `db.query.userProfiles.findFirst(...)?.traits`: Ok(None) when there is no
    /// profile or its traits are null
    fn user_traits(&self, site_id: i32, user_id: &str) -> impl Future<Output = Result<Option<Value>, String>> + Send;
}

impl EvaluateStores for AppState {
    async fn site_config(&self, site_id_param: &str) -> Option<SiteConfigData> {
        self.site_config.get_config(&SiteRef::Text(site_id_param.to_string())).await
    }

    async fn definitions_for_runtime(&self, site_id: i32, runtime: Runtime) -> Result<Vec<Value>, DefinitionsError> {
        definitions::get_feature_flag_definitions_for_runtime(self, site_id, runtime.as_str()).await
    }

    async fn user_traits(&self, site_id: i32, user_id: &str) -> Result<Option<Value>, String> {
        load_user_traits(&self.pg, site_id, user_id).await
    }
}

/// `db.query.userProfiles.findFirst({ where: siteId and userId })?.traits`, the jsonb
/// as drizzle hands it to Node. None when there is no profile or the traits are null.
pub async fn load_user_traits(pg: &PgPool, site_id: i32, user_id: &str) -> Result<Option<Value>, String> {
    let traits: Option<Option<String>> =
        sqlx::query_scalar("SELECT traits::text FROM user_profiles WHERE site_id = $1 AND user_id = $2 LIMIT 1")
            .bind(site_id)
            .bind(user_id)
            .fetch_optional(pg)
            .await
            .map_err(|error| error.to_string())?;
    match traits.flatten() {
        None => Ok(None),
        Some(text) => {
            let traits = js::drizzle_jsonb(js::parse_json(&text).map_err(|error| error.to_string())?);
            Ok((!traits.is_null()).then_some(traits))
        }
    }
}

/// `evaluateFeatureFlagsForRuntime`: the status and JSON body for an evaluate request.
///
/// `site_id_param` is the decoded `:siteId` path segment; `body` the parsed JSON body,
/// None when the request had none (a text body can be passed as a JSON string, which
/// fails validation the same way). Serialise the body with
/// `crate::js_json::stringify` so numbers in payloads print as JavaScript prints them.
pub async fn evaluate_for_runtime(
    state: &AppState,
    site_id_param: &str,
    body: Option<&Value>,
    runtime: Runtime,
    facts: &dyn RequestFacts,
) -> (StatusCode, Value) {
    evaluate_with_stores(state, site_id_param, body, runtime, facts).await
}

/// [`evaluate_for_runtime`] over any stores.
pub async fn evaluate_with_stores<S: EvaluateStores>(
    stores: &S,
    site_id_param: &str,
    body: Option<&Value>,
    runtime: Runtime,
    facts: &dyn RequestFacts,
) -> (StatusCode, Value) {
    let body = match schemas::parse_evaluate_body(body) {
        Ok(body) => body,
        Err(issues) => {
            tracing::debug!(
                site_id = site_id_param,
                runtime = runtime.as_str(),
                "feature flag evaluation body failed validation"
            );
            return (StatusCode::BAD_REQUEST, json!({ "error": "Validation error", "details": issues.into_json() }));
        }
    };

    let Some(site) = stores.site_config(site_id_param).await else {
        tracing::debug!(
            site_id = site_id_param,
            runtime = runtime.as_str(),
            "feature flag evaluation for an unknown site"
        );
        return (StatusCode::NOT_FOUND, json!({ "error": "Site not found" }));
    };

    match evaluate_site(stores, &site, &body, runtime, facts).await {
        Ok(response) => (StatusCode::OK, response),
        Err(error) => {
            tracing::error!(site_id = site.site_id, runtime = runtime.as_str(), error = %error, "Failed to evaluate feature flags");
            (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "Failed to evaluate feature flags" }))
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum EvaluateError {
    #[error(transparent)]
    Definitions(#[from] DefinitionsError),
    #[error("loading user traits: {0}")]
    Traits(String),
    #[error(transparent)]
    Js(#[from] js::JsError),
}

async fn evaluate_site<S: EvaluateStores>(
    stores: &S,
    site: &SiteConfigData,
    body: &EvaluateFeatureFlagsBody,
    runtime: Runtime,
    facts: &dyn RequestFacts,
) -> Result<Value, EvaluateError> {
    let definitions = stores.definitions_for_runtime(site.site_id, runtime).await?;
    if definitions.is_empty() {
        tracing::debug!(site_id = site.site_id, runtime = runtime.as_str(), "no feature flags for runtime");
        return Ok(response(Map::new(), false));
    }

    let location = facts.location(site);
    let traits = match body.identified_user_id.as_deref().filter(|user_id| !user_id.is_empty()) {
        Some(user_id) => stores.user_traits(site.site_id, user_id).await.map_err(EvaluateError::Traits)?,
        None => None,
    };
    // `body.screenWidth || 0`: undefined, 0 and -0 all become 0
    let dimension = |value: Option<f64>| value.filter(|value| *value != 0.0).unwrap_or(0.0);
    let device_type = facts.device_type(dimension(body.screen_width), dimension(body.screen_height));

    let country = location.as_ref().and_then(|location| location.country_iso.clone());
    // `location?.region ? `${location.countryIso}-${location.region}` : undefined`
    let region = location.as_ref().and_then(|location| {
        let region = location.region.as_deref().filter(|region| !region.is_empty())?;
        Some(format!("{}-{region}", location.country_iso.as_deref().unwrap_or("undefined")))
    });
    let context = FeatureFlagContext {
        anonymous_id: body.anonymous_id.clone(),
        identified_user_id: body.identified_user_id.clone(),
        hostname: body.hostname.clone(),
        pathname: body.pathname.clone(),
        query: Some(match &body.query {
            Some(query) => query.clone(),
            None => query::parse_query(body.querystring.as_deref()),
        }),
        referrer: body.referrer.clone(),
        language: body.language.clone(),
        country,
        region,
        city: location.as_ref().and_then(|location| location.city.clone()),
        device_type: Some(device_type),
        traits: Some(traits.unwrap_or_else(|| Value::Object(Map::new()))),
    };

    let flags = evaluator::evaluate_feature_flag_definitions(&definitions, &context, Some(runtime.as_str()))?;
    tracing::debug!(site_id = site.site_id, runtime = runtime.as_str(), flags = flags.len(), "feature flags evaluated");
    Ok(response(flags, true))
}

fn response(flags: Map<String, Value>, enabled: bool) -> Value {
    json!({
        "flags": flags,
        "featureFlagsEnabled": enabled,
        "generatedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct FakeStores {
        site: Option<SiteConfigData>,
        definitions: Result<Vec<Value>, DefinitionsError>,
        traits: Mutex<Vec<(i32, String)>>,
    }

    impl EvaluateStores for FakeStores {
        async fn site_config(&self, _site_id_param: &str) -> Option<SiteConfigData> {
            self.site.clone()
        }

        async fn definitions_for_runtime(
            &self,
            _site_id: i32,
            runtime: Runtime,
        ) -> Result<Vec<Value>, DefinitionsError> {
            let definitions = self.definitions.clone()?;
            Ok(definitions::filter_for_runtime(&Value::Array(definitions), runtime.as_str())?)
        }

        async fn user_traits(&self, site_id: i32, user_id: &str) -> Result<Option<Value>, String> {
            self.traits.lock().unwrap().push((site_id, user_id.to_string()));
            Ok(Some(json!({ "plan": "pro" })))
        }
    }

    struct Facts;

    impl RequestFacts for Facts {
        fn location(&self, _site: &SiteConfigData) -> Option<Location> {
            Some(Location {
                country_iso: Some("US".into()),
                region: Some("CA".into()),
                city: Some("Oakland".into()),
                ..Default::default()
            })
        }

        fn device_type(&self, screen_width: f64, _screen_height: f64) -> String {
            if screen_width > 1024.0 { "Desktop" } else { "Mobile" }.to_string()
        }
    }

    fn site() -> SiteConfigData {
        SiteConfigData {
            id: Some("abc".into()),
            site_id: 42,
            organization_id: None,
            site_type: crate::site_config::SiteType::Web,
            public: false,
            embed_enabled: false,
            salt_user_ids: false,
            domain: "example.com".into(),
            block_bots: true,
            first_party_proxy: false,
            excluded_ips: vec![],
            use_organization_excluded_ips: true,
            organization_excluded_ips: vec![],
            excluded_countries: vec![],
            excluded_paths: vec![],
            excluded_hostnames: vec![],
            excluded_user_agents: vec![],
            excluded_asns: vec![],
            excluded_query_params: vec![],
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
            tags: vec![],
        }
    }

    fn flag(key: &str, runtime: &str, rules: Value) -> Value {
        json!({ "flagId": 1, "siteId": 42, "key": key, "enabled": true, "runtime": runtime, "flagType": "boolean",
                "payload": null, "variants": [], "rolloutPercentage": 100, "rules": rules, "conditionSets": [],
                "salt": "s", "version": 3 })
    }

    #[tokio::test]
    async fn validation_errors_answer_400_before_the_site_lookup() {
        let stores = FakeStores { site: None, definitions: Ok(vec![]), traits: Mutex::new(vec![]) };
        let (status, body) = evaluate_with_stores(&stores, "42", Some(&json!({})), Runtime::Client, &Facts).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "Validation error");
        assert_eq!(body["details"][0]["path"], json!(["anonymousId"]));
    }

    #[tokio::test]
    async fn unknown_sites_answer_404() {
        let stores = FakeStores { site: None, definitions: Ok(vec![]), traits: Mutex::new(vec![]) };
        let (status, body) =
            evaluate_with_stores(&stores, "42", Some(&json!({ "anonymousId": "a" })), Runtime::Client, &Facts).await;
        assert_eq!((status, body), (StatusCode::NOT_FOUND, json!({ "error": "Site not found" })));
    }

    #[tokio::test]
    async fn sites_without_flags_for_the_runtime_report_disabled() {
        let stores = FakeStores {
            site: Some(site()),
            definitions: Ok(vec![flag("srv", "server", json!([]))]),
            traits: Mutex::new(vec![]),
        };
        let (status, body) =
            evaluate_with_stores(&stores, "42", Some(&json!({ "anonymousId": "a" })), Runtime::Client, &Facts).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["flags"], json!({}));
        assert_eq!(body["featureFlagsEnabled"], json!(false));
        assert_eq!(body["generatedAt"].as_str().unwrap().len(), "2026-09-17T08:10:03.430Z".len());
    }

    #[tokio::test]
    async fn builds_the_context_from_body_location_traits_and_device() {
        let rules = json!([
            { "field": "region", "operator": "equals", "value": "US-CA" },
            { "field": "city", "operator": "equals", "value": "Oakland" },
            { "field": "device_type", "operator": "equals", "value": "Desktop" },
            { "field": "trait", "key": "plan", "operator": "equals", "value": "pro" },
            { "field": "query", "key": "utm", "operator": "equals", "value": "a b" },
        ]);
        let stores = FakeStores {
            site: Some(site()),
            definitions: Ok(vec![flag("f", "both", rules)]),
            traits: Mutex::new(vec![]),
        };
        let body = json!({ "anonymousId": "a", "identifiedUserId": " user-1 ", "querystring": "?utm=a+b", "screenWidth": 1920 });
        let (status, response) = evaluate_with_stores(&stores, "42", Some(&body), Runtime::Server, &Facts).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["featureFlagsEnabled"], json!(true));
        assert_eq!(response["flags"]["f"]["reason"], json!("rollout"), "{response}");
        assert_eq!(stores.traits.lock().unwrap().as_slice(), [(42, "user-1".to_string())]);
    }

    #[tokio::test]
    async fn evaluation_failures_answer_500() {
        let stores = FakeStores {
            site: Some(site()),
            definitions: Err(DefinitionsError::Database("connection refused".into())),
            traits: Mutex::new(vec![]),
        };
        let (status, body) =
            evaluate_with_stores(&stores, "42", Some(&json!({ "anonymousId": "a" })), Runtime::Client, &Facts).await;
        assert_eq!(
            (status, body),
            (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "Failed to evaluate feature flags" }))
        );
    }
}
