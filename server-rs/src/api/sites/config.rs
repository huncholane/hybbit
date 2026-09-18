//! `PUT /api/sites/:siteId/config`, ported from
//! server/src/api/sites/updateSiteConfig.ts on the `adminSitesWrite` chain,
//! together with its zod 3.25 schema.
//!
//! The schema's shape order is the order zod walks the keys, which is the order
//! `error.flatten()` lists `fieldErrors`, so the fields are declared here in the
//! same order as the TypeScript. Two zod behaviours the messages depend on:
//!
//! - `.trim()` is a check like any other, so it runs before the `min`/`max`/regex
//!   that follow it and the *trimmed* string is what gets stored;
//! - a failed check makes a value dirty rather than aborting it, so an array
//!   element can report several messages, and `.refine()` still runs after a
//!   failed `.regex()` (which is why an over-large ASN reports both).

use std::sync::LazyLock;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use regress::{Flags, Regex};
use serde_json::{Value, json};
use tracing::{error, warn};

use super::{
    lifecycle::{self, LifecycleFailure, UpdateInput},
    request::{self, Issues, object},
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::string::trim,
        routes::people::common::path_params,
    },
    site_config::SiteConfigData,
    state::AppState,
};

/// `/^[A-Z]{2}$/`
static COUNTRY_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Z]{2}$").expect("country pattern compiles"));
/// `/^(?:AS)?\d{1,10}$/i`
static ASN_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::with_flags(r"^(?:AS)?\d{1,10}$", Flags::from("i")).expect("ASN pattern compiles"));
/// `/^AS/i`, for the refinement's `String.prototype.replace`
static ASN_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::with_flags("^AS", Flags::from("i")).expect("ASN prefix compiles"));

const COUNTRY_MESSAGE: &str = "Country code must be a 2-letter ISO code (e.g., US, GB, CN)";
const ASN_MESSAGE: &str = "ASN must be a number, optionally prefixed with AS (e.g., AS13335 or 13335)";
const ASN_RANGE_MESSAGE: &str = "ASN must be at most 4294967295";
const QUERY_PARAM_MESSAGE: &str =
    "Query param rule must have a name before '=' (e.g., preview or utm_source=internal)";

/// `z.string()` with the checks the schema attaches, in declaration order.
/// Returns the value zod would keep (trimmed when `.trim()` is in the chain), or
/// `None` when the type check aborted.
struct StringChecks {
    trim: bool,
    min: Option<usize>,
    max: Option<usize>,
    length: Option<usize>,
}

impl StringChecks {
    const fn new() -> Self {
        Self { trim: false, min: None, max: None, length: None }
    }

    fn parse(&self, value: Option<&Value>, issues: &mut Issues, field: &str) -> Option<String> {
        let Some(Value::String(text)) = value else {
            issues.field(field, request::invalid_type("string", value));
            return None;
        };
        let mut text = text.clone();
        if self.trim {
            text = trim(&text).to_string();
        }
        let length = request::string_length(&text);
        if let Some(minimum) = self.min
            && length < minimum
        {
            issues.field(field, request::string_too_small(minimum));
        }
        if let Some(maximum) = self.max
            && length > maximum
        {
            issues.field(field, request::string_too_big(maximum));
        }
        // `.length(n)` reports too_big or too_small, both with `exact: true`, which
        // the default error map renders the same way
        if self.length.is_some_and(|exact| length != exact) {
            let exact = self.length.unwrap_or_default();
            issues.field(field, format!("String must contain exactly {exact} character(s)"));
        }
        Some(text)
    }
}

/// `z.array(element).max(limit)`: the array checks run first and every element is
/// still parsed, so one field can report the array issue and several element ones.
fn string_array(
    value: Option<&Value>,
    issues: &mut Issues,
    field: &str,
    limit: usize,
    checks: &StringChecks,
    mut element_extra: impl FnMut(&str, &mut Issues, &str),
) -> Option<Vec<String>> {
    let Some(Value::Array(items)) = value else {
        issues.field(field, request::invalid_type("array", value));
        return None;
    };
    if items.len() > limit {
        issues.field(field, request::array_too_big(limit));
    }
    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        // A `None` element aborted; zod keeps parsing the rest, and the array's own
        // value being INVALID only matters because the whole parse then fails
        if let Some(text) = checks.parse(Some(item), issues, field) {
            element_extra(&text, issues, field);
            parsed.push(text);
        }
    }
    Some(parsed)
}

/// `z.boolean().optional()`
fn boolean(value: Option<&Value>, issues: &mut Issues, field: &str) -> Option<bool> {
    match value {
        None => None,
        Some(Value::Bool(flag)) => Some(*flag),
        other => {
            issues.field(field, request::invalid_type("boolean", other));
            None
        }
    }
}

/// `z.number().int().min(low).max(high)`
fn bounded_int(value: Option<&Value>, issues: &mut Issues, field: &str, low: f64, high: f64) -> Option<f64> {
    let number = match value {
        None => return None,
        Some(Value::Number(number)) => number.as_f64().unwrap_or(f64::NAN),
        other => {
            issues.field(field, request::invalid_type("number", other));
            return None;
        }
    };
    if number.is_nan() {
        issues.field(field, "Expected number, received nan");
        return None;
    }
    if number.fract() != 0.0 || !number.is_finite() {
        issues.field(field, "Expected integer, received float");
    }
    if number < low {
        issues.field(field, format!("Number must be greater than or equal to {}", crate::js_json::number_to_string(low)));
    }
    if number > high {
        issues.field(field, format!("Number must be less than or equal to {}", crate::js_json::number_to_string(high)));
    }
    Some(number)
}

/// `z.enum(["web","mobile"]).nullable().optional()`
fn site_type(value: Option<&Value>, issues: &mut Issues) -> Option<Option<String>> {
    const OPTIONS: [&str; 2] = ["web", "mobile"];
    match value {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(text)) if OPTIONS.contains(&text.as_str()) => Some(Some(text.clone())),
        Some(Value::String(text)) => {
            issues.field("type", request::invalid_enum_value(&OPTIONS, text));
            None
        }
        other => {
            issues.field("type", request::enum_invalid_type(&OPTIONS, other));
            None
        }
    }
}

/// `updateSiteConfigSchema.safeParse(body)`: the input for the lifecycle service,
/// or `error.flatten()`.
pub fn parse_update_body(body: Option<&Value>) -> Result<UpdateInput, Value> {
    let mut issues = Issues::default();
    let Some(Value::Object(fields)) = body else {
        issues.form(request::invalid_type("object", body));
        return Err(issues.flatten());
    };
    let get = |name: &str| fields.get(name);
    let mut input = UpdateInput::default();

    const PLAIN: StringChecks = StringChecks::new();
    const TRIMMED: StringChecks = StringChecks { trim: true, ..StringChecks::new() };

    if let Some(value) = get("name") {
        input.name = StringChecks { min: Some(1), max: Some(255), ..PLAIN }.parse(Some(value), &mut issues, "name");
    }
    input.site_type = site_type(get("type"), &mut issues);
    input.public = boolean(get("public"), &mut issues, "public");
    input.embed_enabled = boolean(get("embedEnabled"), &mut issues, "embedEnabled");
    input.salt_user_ids = boolean(get("saltUserIds"), &mut issues, "saltUserIds");
    input.block_bots = boolean(get("blockBots"), &mut issues, "blockBots");
    input.first_party_proxy = boolean(get("firstPartyProxy"), &mut issues, "firstPartyProxy");
    if let Some(value) = get("domain") {
        input.domain = StringChecks { min: Some(1), max: Some(253), ..PLAIN }.parse(Some(value), &mut issues, "domain");
    }
    if let Some(value) = get("excludedIPs") {
        input.excluded_ips = string_array(
            Some(value),
            &mut issues,
            "excludedIPs",
            100,
            &StringChecks { min: Some(1), ..TRIMMED },
            |_, _, _| {},
        );
    }
    input.use_organization_excluded_ips =
        boolean(get("useOrganizationExcludedIPs"), &mut issues, "useOrganizationExcludedIPs");
    if let Some(value) = get("excludedCountries") {
        input.excluded_countries = string_array(
            Some(value),
            &mut issues,
            "excludedCountries",
            250,
            &StringChecks { length: Some(2), ..TRIMMED },
            |text, issues, field| {
                if COUNTRY_PATTERN.find(text).is_none() {
                    issues.field(field, COUNTRY_MESSAGE);
                }
            },
        );
    }
    if let Some(value) = get("excludedPaths") {
        input.excluded_paths = string_array(
            Some(value),
            &mut issues,
            "excludedPaths",
            100,
            &StringChecks { min: Some(1), max: Some(2048), ..TRIMMED },
            |_, _, _| {},
        );
    }
    if let Some(value) = get("excludedHostnames") {
        input.excluded_hostnames = string_array(
            Some(value),
            &mut issues,
            "excludedHostnames",
            100,
            &StringChecks { min: Some(1), max: Some(253), ..TRIMMED },
            |_, _, _| {},
        );
    }
    if let Some(value) = get("excludedUserAgents") {
        input.excluded_user_agents = string_array(
            Some(value),
            &mut issues,
            "excludedUserAgents",
            100,
            &StringChecks { min: Some(1), max: Some(512), ..TRIMMED },
            |_, _, _| {},
        );
    }
    if let Some(value) = get("excludedASNs") {
        input.excluded_asns = string_array(
            Some(value),
            &mut issues,
            "excludedASNs",
            100,
            &TRIMMED,
            |text, issues, field| {
                if ASN_PATTERN.find(text).is_none() {
                    issues.field(field, ASN_MESSAGE);
                }
                // The refinement runs even after a failed regex (dirty, not aborted)
                let without_prefix = match ASN_PREFIX.find(text) {
                    Some(found) => text[found.range().end..].to_string(),
                    None => text.to_string(),
                };
                // `Number(...) <= 4294967295` is false for NaN too, which is how a
                // value the regex already refused still reaches this message
                let number = request::js_number(&without_prefix);
                if !matches!(number.partial_cmp(&4_294_967_295.0), Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)) {
                    issues.field(field, ASN_RANGE_MESSAGE);
                }
            },
        );
    }
    if let Some(value) = get("excludedQueryParams") {
        input.excluded_query_params = string_array(
            Some(value),
            &mut issues,
            "excludedQueryParams",
            100,
            &StringChecks { min: Some(1), max: Some(512), ..TRIMMED },
            |text, issues, field| {
                if text.starts_with('=') {
                    issues.field(field, QUERY_PARAM_MESSAGE);
                }
            },
        );
    }
    if let Some(value) = get("tags") {
        input.tags = string_array(
            Some(value),
            &mut issues,
            "tags",
            20,
            &StringChecks { min: Some(1), max: Some(50), ..TRIMMED },
            |_, _, _| {},
        );
    }
    input.session_replay = boolean(get("sessionReplay"), &mut issues, "sessionReplay");
    input.web_vitals = boolean(get("webVitals"), &mut issues, "webVitals");
    input.track_errors = boolean(get("trackErrors"), &mut issues, "trackErrors");
    input.track_outbound = boolean(get("trackOutbound"), &mut issues, "trackOutbound");
    input.track_url_params = boolean(get("trackUrlParams"), &mut issues, "trackUrlParams");
    input.track_initial_page_view = boolean(get("trackInitialPageView"), &mut issues, "trackInitialPageView");
    input.track_spa_navigation = boolean(get("trackSpaNavigation"), &mut issues, "trackSpaNavigation");
    input.track_ip = boolean(get("trackIp"), &mut issues, "trackIp");
    input.track_button_clicks = boolean(get("trackButtonClicks"), &mut issues, "trackButtonClicks");
    input.track_copy = boolean(get("trackCopy"), &mut issues, "trackCopy");
    input.track_form_interactions = boolean(get("trackFormInteractions"), &mut issues, "trackFormInteractions");
    input.track_heartbeat = boolean(get("trackHeartbeat"), &mut issues, "trackHeartbeat");
    input.heartbeat_interval = bounded_int(get("heartbeatInterval"), &mut issues, "heartbeatInterval", 5.0, 300.0);
    input.bounce_threshold = bounded_int(get("bounceThreshold"), &mut issues, "bounceThreshold", 1.0, 600.0);

    if issues.is_empty() { Ok(input) } else { Err(issues.flatten()) }
}

/// The `SiteConfigData` object literal in server/src/lib/siteConfig.ts, which is
/// what `update` returns and the handler sends as `config`.
pub fn site_config_value(config: &SiteConfigData) -> Value {
    let list = |values: &Vec<String>| Value::Array(values.iter().map(|value| Value::String(value.clone())).collect());
    object(vec![
        ("id", config.id.clone().map_or(Value::Null, Value::String)),
        ("siteId", Value::from(config.site_id)),
        ("organizationId", config.organization_id.clone().map_or(Value::Null, Value::String)),
        ("type", Value::String(config.site_type.as_str().to_string())),
        ("public", Value::Bool(config.public)),
        ("embedEnabled", Value::Bool(config.embed_enabled)),
        ("saltUserIds", Value::Bool(config.salt_user_ids)),
        ("domain", Value::String(config.domain.clone())),
        ("blockBots", Value::Bool(config.block_bots)),
        ("firstPartyProxy", Value::Bool(config.first_party_proxy)),
        ("excludedIPs", list(&config.excluded_ips)),
        ("useOrganizationExcludedIPs", Value::Bool(config.use_organization_excluded_ips)),
        ("organizationExcludedIPs", list(&config.organization_excluded_ips)),
        ("excludedCountries", list(&config.excluded_countries)),
        ("excludedPaths", list(&config.excluded_paths)),
        ("excludedHostnames", list(&config.excluded_hostnames)),
        ("excludedUserAgents", list(&config.excluded_user_agents)),
        ("excludedASNs", list(&config.excluded_asns)),
        ("excludedQueryParams", list(&config.excluded_query_params)),
        ("privateLinkKey", config.private_link_key.clone().map_or(Value::Null, Value::String)),
        ("sessionReplay", Value::Bool(config.session_replay)),
        ("webVitals", Value::Bool(config.web_vitals)),
        ("trackErrors", Value::Bool(config.track_errors)),
        ("trackOutbound", Value::Bool(config.track_outbound)),
        ("trackUrlParams", Value::Bool(config.track_url_params)),
        ("trackInitialPageView", Value::Bool(config.track_initial_page_view)),
        ("trackSpaNavigation", Value::Bool(config.track_spa_navigation)),
        ("trackIp", Value::Bool(config.track_ip)),
        ("trackButtonClicks", Value::Bool(config.track_button_clicks)),
        ("trackCopy", Value::Bool(config.track_copy)),
        ("trackFormInteractions", Value::Bool(config.track_form_interactions)),
        ("trackHeartbeat", Value::Bool(config.track_heartbeat)),
        ("heartbeatInterval", Value::from(config.heartbeat_interval)),
        ("bounceThreshold", Value::from(config.bounce_threshold)),
        ("tags", list(&config.tags)),
    ])
}

/// The response for a `SiteLifecycleError`: `{ success: false, error }` plus
/// `details` only when the error carries any.
pub fn lifecycle_error_response(error: &lifecycle::SiteLifecycleError) -> Response {
    let mut fields = vec![("success", Value::Bool(false)), ("error", Value::String(error.message.clone()))];
    if let Some(details) = &error.details {
        fields.push(("details", details.clone()));
    }
    let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    request::send(status, &object(fields))
}

pub async fn update_site_config(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match path_params(&method, &uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Admin,
        route_scope("sites", "write"),
        ChainSteps::TIME_ONLY,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };

    let site_id = request::js_number(&site.site_id);
    if !request::positive_integer(site_id) {
        return request::failure(StatusCode::BAD_REQUEST, "Invalid site ID: must be a positive integer");
    }
    let input = match parse_update_body(body.as_ref()) {
        Ok(input) => input,
        Err(details) => {
            warn!(site_id, "Site configuration payload failed validation");
            return request::send(
                StatusCode::BAD_REQUEST,
                &json!({ "success": false, "error": "Invalid request data", "details": details }),
            );
        }
    };

    match lifecycle::update(&state, site_id, &input).await {
        Ok(config) => request::send(
            StatusCode::OK,
            &object(vec![
                ("success", Value::Bool(true)),
                ("message", Value::String("Site configuration updated successfully".into())),
                ("config", site_config_value(&config)),
            ]),
        ),
        Err(LifecycleFailure::Lifecycle(error)) => lifecycle_error_response(&error),
        Err(LifecycleFailure::Store(message)) => {
            error!(error = %message, site_id, "Error updating site configuration");
            request::failure(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update site configuration")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(body: Value) -> Value {
        parse_update_body(Some(&body)).map(|_| Value::Null).unwrap_err()
    }

    #[test]
    fn missing_body_is_required() {
        assert_eq!(
            parse_update_body(None).map(|_| Value::Null).unwrap_err(),
            json!({ "formErrors": ["Required"], "fieldErrors": {} })
        );
        assert_eq!(errors(json!([])), json!({ "formErrors": ["Expected object, received array"], "fieldErrors": {} }));
    }

    #[test]
    fn string_checks_run_after_trim() {
        assert_eq!(
            errors(json!({ "excludedPaths": ["   "] })),
            json!({ "formErrors": [], "fieldErrors": { "excludedPaths": ["String must contain at least 1 character(s)"] } })
        );
        let parsed = parse_update_body(Some(&json!({ "excludedPaths": ["  /a  "] }))).unwrap();
        assert_eq!(parsed.excluded_paths.unwrap(), vec!["/a".to_string()]);
    }

    #[test]
    fn asn_reports_the_regex_and_the_refinement() {
        assert_eq!(
            errors(json!({ "excludedASNs": ["AS99999999999"] })),
            json!({ "formErrors": [], "fieldErrors": { "excludedASNs": [
                "ASN must be a number, optionally prefixed with AS (e.g., AS13335 or 13335)",
                "ASN must be at most 4294967295"
            ] } })
        );
        assert!(parse_update_body(Some(&json!({ "excludedASNs": ["as4294967295", "13335"] }))).is_ok());
    }

    #[test]
    fn country_reports_length_and_pattern() {
        assert_eq!(
            errors(json!({ "excludedCountries": ["usa"] })),
            json!({ "formErrors": [], "fieldErrors": { "excludedCountries": [
                "String must contain exactly 2 character(s)",
                "Country code must be a 2-letter ISO code (e.g., US, GB, CN)"
            ] } })
        );
    }

    #[test]
    fn numbers_report_int_and_bounds() {
        assert_eq!(
            errors(json!({ "heartbeatInterval": 1.5 })),
            json!({ "formErrors": [], "fieldErrors": { "heartbeatInterval": [
                "Expected integer, received float",
                "Number must be greater than or equal to 5"
            ] } })
        );
        assert_eq!(
            errors(json!({ "bounceThreshold": 601 })),
            json!({ "formErrors": [], "fieldErrors": { "bounceThreshold": ["Number must be less than or equal to 600"] } })
        );
    }

    #[test]
    fn array_limits_and_element_issues_are_both_reported() {
        let long: Vec<Value> = (0..21).map(|index| Value::String(format!("t{index}"))).collect();
        assert_eq!(
            errors(json!({ "tags": long })),
            json!({ "formErrors": [], "fieldErrors": { "tags": ["Array must contain at most 20 element(s)"] } })
        );
        assert_eq!(
            errors(json!({ "tags": [1] })),
            json!({ "formErrors": [], "fieldErrors": { "tags": ["Expected string, received number"] } })
        );
    }

    #[test]
    fn site_type_is_nullable_and_enumerated() {
        assert_eq!(parse_update_body(Some(&json!({ "type": null }))).unwrap().site_type, Some(None));
        assert_eq!(
            parse_update_body(Some(&json!({ "type": "mobile" }))).unwrap().site_type,
            Some(Some("mobile".to_string()))
        );
        assert_eq!(
            errors(json!({ "type": "tablet" })),
            json!({ "formErrors": [], "fieldErrors": { "type": ["Invalid enum value. Expected 'web' | 'mobile', received 'tablet'"] } })
        );
        assert_eq!(
            errors(json!({ "type": 5 })),
            json!({ "formErrors": [], "fieldErrors": { "type": ["Expected 'web' | 'mobile', received number"] } })
        );
    }

    #[test]
    fn unknown_keys_are_stripped() {
        let parsed = parse_update_body(Some(&json!({ "unknown": 1 }))).unwrap();
        assert!(parsed.name.is_none() && parsed.site_type.is_none());
    }

    #[test]
    fn site_type_of_the_config_is_a_string() {
        assert_eq!(crate::site_config::SiteType::Mobile.as_str(), "mobile");
    }
}
