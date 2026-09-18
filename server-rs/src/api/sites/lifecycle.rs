//! The Site Configuration lifecycle service, ported from
//! server/src/services/sites/siteConfigurationLifecycle.ts: the `update`,
//! `updatePrivateLink` and `delete` halves the settings routes call (`create` is
//! `POST /organizations/:id/sites`, which is not in this group).
//!
//! Every plan lookup in the TypeScript sits behind `IS_CLOUD`, which this
//! deployment never sets, so the entitlement branches are not ported: no
//! subscription is consulted, `sessionReplay` is never refused and no site limit
//! applies. The rest is reproduced field for field, including the order the
//! checks run in, because each answers with a different status.

use std::sync::LazyLock;

use rand::Rng;
use regress::{Flags, Regex};
use serde_json::Value;
use sqlx::{PgPool, Row};
use tracing::{debug, info, warn};

use crate::{
    site_config::{SiteConfigData, SiteRef, SiteType},
    state::AppState,
    tracking::validate_ip_pattern,
};

/// `SiteLifecycleErrorCode`. Kept although only the status and message reach the
/// client: the code is what the TypeScript switches on, so naming it here keeps
/// the two readable side by side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteLifecycleErrorCode {
    InvalidSiteId,
    InvalidWebDomain,
    InvalidMobileIdentifier,
    MobileFeatureNotSupported,
    SiteNotFound,
    InvalidIpPatterns,
    EmptyUpdate,
    DomainConflict,
}

/// `SiteLifecycleError`
#[derive(Clone, Debug)]
pub struct SiteLifecycleError {
    /// Carried for the logs and to keep the two files readable side by side; the
    /// wire answer is the status and the message
    #[allow(dead_code)]
    pub code: SiteLifecycleErrorCode,
    pub status: u16,
    pub message: String,
    /// `error.details`, only ever the IP pattern list
    pub details: Option<Value>,
}

impl SiteLifecycleError {
    fn new(code: SiteLifecycleErrorCode, status: u16, message: &str) -> Self {
        Self { code, status, message: message.to_string(), details: None }
    }
}

/// Anything `update`, `updatePrivateLink` or `delete` can fail with: either the
/// service's own error (a status the handler sends) or a store failure the
/// handler turns into its 500.
#[derive(Debug)]
pub enum LifecycleFailure {
    Lifecycle(SiteLifecycleError),
    Store(String),
}

impl From<SiteLifecycleError> for LifecycleFailure {
    fn from(error: SiteLifecycleError) -> Self {
        LifecycleFailure::Lifecycle(error)
    }
}

impl From<sqlx::Error> for LifecycleFailure {
    fn from(error: sqlx::Error) -> Self {
        LifecycleFailure::Store(error.to_string())
    }
}

/// `DOMAIN_PATTERN`, compiled with the `u` flag as in the TypeScript.
static DOMAIN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::with_flags(
        r"^(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+\p{L}{2,}$",
        Flags::from("u"),
    )
    .expect("DOMAIN_PATTERN compiles")
});

/// `APP_IDENTIFIER_PATTERN`
static APP_IDENTIFIER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$").expect("APP_IDENTIFIER_PATTERN compiles"));

fn matches(pattern: &Regex, text: &str) -> bool {
    pattern.find(text).is_some()
}

/// `normalizeSiteType`
pub fn normalize_site_type(site_type: Option<Option<&str>>, current: SiteType) -> SiteType {
    match site_type {
        // `input.type === undefined ? site.type : input.type`
        None => current,
        Some(Some("mobile")) => SiteType::Mobile,
        Some(_) => SiteType::Web,
    }
}

/// `normalizeDomain`: one leading `http://` or `https://`, then every trailing slash.
pub fn normalize_domain(domain: &str) -> String {
    let without_scheme =
        domain.strip_prefix("https://").or_else(|| domain.strip_prefix("http://")).unwrap_or(domain);
    without_scheme.trim_end_matches('/').to_string()
}

/// `validateSiteIdentity`
pub fn validate_site_identity(site_type: SiteType, domain: &str) -> Result<(), SiteLifecycleError> {
    match site_type {
        SiteType::Web if !matches(&DOMAIN_PATTERN, domain) => Err(SiteLifecycleError::new(
            SiteLifecycleErrorCode::InvalidWebDomain,
            400,
            "Invalid domain format. Must be a valid domain like example.com or sub.example.com",
        )),
        SiteType::Mobile if !matches(&APP_IDENTIFIER_PATTERN, domain) => Err(SiteLifecycleError::new(
            SiteLifecycleErrorCode::InvalidMobileIdentifier,
            400,
            "Invalid app identifier. Use a bundle/package identifier like com.example.app",
        )),
        _ => Ok(()),
    }
}

/// `validateMobileFeatures`
pub fn validate_mobile_features(
    site_type: SiteType,
    session_replay: Option<bool>,
    web_vitals: Option<bool>,
) -> Result<(), SiteLifecycleError> {
    if site_type == SiteType::Mobile && (session_replay == Some(true) || web_vitals == Some(true)) {
        return Err(SiteLifecycleError::new(
            SiteLifecycleErrorCode::MobileFeatureNotSupported,
            400,
            "Session replay and Web Vitals are only available for web sites",
        ));
    }
    Ok(())
}

/// `validateSiteId`
fn validate_site_id(site_id: f64) -> Result<i32, SiteLifecycleError> {
    let invalid = || {
        SiteLifecycleError::new(
            SiteLifecycleErrorCode::InvalidSiteId,
            400,
            "Invalid site ID: must be a positive integer",
        )
    };
    if !site_id.is_finite() || site_id.fract() != 0.0 || site_id <= 0.0 {
        return Err(invalid());
    }
    // Past int4 the id is still a positive integer to JavaScript, but Postgres
    // refuses the bind and the throw escapes as the handler's 500
    super::request::pg_int(site_id).ok_or_else(|| {
        SiteLifecycleError::new(SiteLifecycleErrorCode::InvalidSiteId, 500, "site id out of Postgres integer range")
    })
}

/// The `sites` row `findSite` returns, reduced to what `update` and `delete` read.
pub struct SiteRow {
    pub site_id: i32,
    pub id: Option<String>,
    pub site_type: SiteType,
    pub domain: String,
    /// Read by the cloud entitlement branches, which are not ported
    #[allow(dead_code)]
    pub organization_id: Option<String>,
}

/// `findSite`
pub async fn find_site(pg: &PgPool, site_id: f64) -> Result<SiteRow, LifecycleFailure> {
    let numeric = match validate_site_id(site_id) {
        Ok(numeric) => numeric,
        // The out-of-range case is a store failure, not a client error
        Err(error) if error.status == 500 => return Err(LifecycleFailure::Store(error.message)),
        Err(error) => return Err(error.into()),
    };
    let row = sqlx::query(r#"SELECT site_id, id, type, domain, organization_id FROM sites WHERE site_id = $1 LIMIT 1"#)
        .bind(numeric)
        .fetch_optional(pg)
        .await?;
    let Some(row) = row else {
        debug!(site_id = numeric, "Site not found");
        return Err(SiteLifecycleError::new(SiteLifecycleErrorCode::SiteNotFound, 404, "Site not found").into());
    };
    let site_type: Option<String> = row.try_get("type")?;
    Ok(SiteRow {
        site_id: row.try_get("site_id")?,
        id: row.try_get("id")?,
        site_type: if site_type.as_deref() == Some("mobile") { SiteType::Mobile } else { SiteType::Web },
        domain: row.try_get::<Option<String>, _>("domain")?.unwrap_or_default(),
        organization_id: row.try_get("organization_id")?,
    })
}

/// One `updateData` entry: the column and the value bound to it.
pub enum ColumnValue {
    Text(String),
    /// `type` is the only column that can be set to NULL
    NullText,
    Bool(bool),
    Int(i32),
    /// A jsonb column; drizzle hands postgres-js `JSON.stringify(value)` and
    /// sqlx encodes the same array of strings
    Json(Value),
    /// An ISO string for a `timestamp without time zone` column. postgres-js sends
    /// it untyped and lets Postgres parse it; sqlx sends typed binary, so the
    /// placeholder carries an explicit `::timestamp` cast to get the same row.
    Timestamp(String),
}

/// `UpdateSiteConfigurationInput` after the route's zod schema, as the fields the
/// service copies into `updateData`. `Option::None` is the `undefined` the
/// TypeScript tests for.
#[derive(Default, Debug)]
pub struct UpdateInput {
    pub name: Option<String>,
    /// `Some(None)` is an explicit `null`
    pub site_type: Option<Option<String>>,
    pub public: Option<bool>,
    pub embed_enabled: Option<bool>,
    pub salt_user_ids: Option<bool>,
    pub block_bots: Option<bool>,
    pub first_party_proxy: Option<bool>,
    pub domain: Option<String>,
    pub excluded_ips: Option<Vec<String>>,
    pub use_organization_excluded_ips: Option<bool>,
    pub excluded_countries: Option<Vec<String>>,
    pub excluded_paths: Option<Vec<String>>,
    pub excluded_hostnames: Option<Vec<String>>,
    pub excluded_user_agents: Option<Vec<String>>,
    pub excluded_asns: Option<Vec<String>>,
    pub excluded_query_params: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub session_replay: Option<bool>,
    pub web_vitals: Option<bool>,
    pub track_errors: Option<bool>,
    pub track_outbound: Option<bool>,
    pub track_url_params: Option<bool>,
    pub track_initial_page_view: Option<bool>,
    pub track_spa_navigation: Option<bool>,
    pub track_ip: Option<bool>,
    pub track_button_clicks: Option<bool>,
    pub track_copy: Option<bool>,
    pub track_form_interactions: Option<bool>,
    pub track_heartbeat: Option<bool>,
    pub heartbeat_interval: Option<f64>,
    pub bounce_threshold: Option<f64>,
}

fn json_array(values: &[String]) -> Value {
    Value::Array(values.iter().map(|value| Value::String(value.clone())).collect())
}

/// `DIRECT_UPDATE_FIELDS`, in order, as `(column, value)` pairs for the fields the
/// input actually carries. The order only reaches the generated SQL, but keeping
/// it makes the two files line up.
fn direct_update_fields(input: &UpdateInput) -> Vec<(&'static str, ColumnValue)> {
    let mut fields: Vec<(&'static str, ColumnValue)> = Vec::new();
    fn text(fields: &mut Vec<(&'static str, ColumnValue)>, column: &'static str, value: &Option<String>) {
        if let Some(value) = value {
            fields.push((column, ColumnValue::Text(value.clone())));
        }
    }
    fn flag(fields: &mut Vec<(&'static str, ColumnValue)>, column: &'static str, value: Option<bool>) {
        if let Some(value) = value {
            fields.push((column, ColumnValue::Bool(value)));
        }
    }
    fn list(fields: &mut Vec<(&'static str, ColumnValue)>, column: &'static str, value: &Option<Vec<String>>) {
        if let Some(value) = value {
            fields.push((column, ColumnValue::Json(json_array(value))));
        }
    }
    fn integer(fields: &mut Vec<(&'static str, ColumnValue)>, column: &'static str, value: Option<f64>) {
        if let Some(value) = value {
            fields.push((column, ColumnValue::Int(value as i32)));
        }
    }

    text(&mut fields, "name", &input.name);
    flag(&mut fields, r#""public""#, input.public);
    flag(&mut fields, "embed_enabled", input.embed_enabled);
    flag(&mut fields, r#""saltUserIds""#, input.salt_user_ids);
    flag(&mut fields, r#""blockBots""#, input.block_bots);
    flag(&mut fields, "first_party_proxy", input.first_party_proxy);
    list(&mut fields, "excluded_ips", &input.excluded_ips);
    flag(&mut fields, "use_organization_excluded_ips", input.use_organization_excluded_ips);
    list(&mut fields, "excluded_countries", &input.excluded_countries);
    list(&mut fields, "excluded_paths", &input.excluded_paths);
    list(&mut fields, "excluded_hostnames", &input.excluded_hostnames);
    list(&mut fields, "excluded_user_agents", &input.excluded_user_agents);
    list(&mut fields, "excluded_asns", &input.excluded_asns);
    list(&mut fields, "excluded_query_params", &input.excluded_query_params);
    list(&mut fields, "tags", &input.tags);
    flag(&mut fields, r#""sessionReplay""#, input.session_replay);
    flag(&mut fields, r#""webVitals""#, input.web_vitals);
    flag(&mut fields, r#""trackErrors""#, input.track_errors);
    flag(&mut fields, r#""trackOutbound""#, input.track_outbound);
    flag(&mut fields, r#""trackUrlParams""#, input.track_url_params);
    flag(&mut fields, r#""trackInitialPageView""#, input.track_initial_page_view);
    flag(&mut fields, r#""trackSpaNavigation""#, input.track_spa_navigation);
    flag(&mut fields, r#""trackIp""#, input.track_ip);
    flag(&mut fields, r#""trackButtonClicks""#, input.track_button_clicks);
    flag(&mut fields, r#""trackCopy""#, input.track_copy);
    flag(&mut fields, r#""trackFormInteractions""#, input.track_form_interactions);
    flag(&mut fields, "track_heartbeat", input.track_heartbeat);
    integer(&mut fields, "heartbeat_interval", input.heartbeat_interval);
    integer(&mut fields, "bounce_threshold", input.bounce_threshold);
    fields
}

/// `new Date().toISOString()` for the `updated_at` column: Postgres reads the
/// trailing `Z` and drops it for a `timestamp without time zone`, which is what
/// drizzle sends.
pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// `randomBytes(6).toString("hex")`
fn random_hex_6() -> String {
    let mut bytes = [0u8; 6];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Postgres's unique-violation SQLSTATE, the one `isUniqueConstraintViolation`
/// turns into a 409. No unique index covers `sites.domain` in this deployment, so
/// the branch is unreachable here; it is kept so a future index behaves as Node does.
fn unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

/// `siteConfigurationLifecycle.update`
pub async fn update(
    state: &AppState,
    site_id: f64,
    input: &UpdateInput,
) -> Result<SiteConfigData, LifecycleFailure> {
    let site = find_site(&state.pg, site_id).await?;
    let next_type = normalize_site_type(input.site_type.as_ref().map(|value| value.as_deref()), site.site_type);
    let domain = normalize_domain(input.domain.as_deref().unwrap_or(&site.domain));

    if input.domain.is_some() || input.site_type.is_some() {
        validate_site_identity(next_type, &domain)?;
    }
    validate_mobile_features(next_type, input.session_replay, input.web_vitals)?;

    if let Some(ips) = &input.excluded_ips {
        let errors: Vec<Value> = ips
            .iter()
            .filter_map(|ip| {
                let validation = validate_ip_pattern(ip);
                validation.error.map(|message| Value::String(format!("{ip}: {message}")))
            })
            .collect();
        if !errors.is_empty() {
            let mut error =
                SiteLifecycleError::new(SiteLifecycleErrorCode::InvalidIpPatterns, 400, "Invalid IP patterns");
            error.details = Some(Value::Array(errors));
            return Err(error.into());
        }
    }

    let mut fields = direct_update_fields(input);
    if input.site_type.is_some() {
        fields.push(("type", if next_type == SiteType::Web { ColumnValue::NullText } else { ColumnValue::Text("mobile".into()) }));
    }
    if input.domain.is_some() {
        fields.push(("domain", ColumnValue::Text(domain.clone())));
    }
    if next_type == SiteType::Mobile {
        // `Object.assign` replaces an entry in place, so an explicit true earlier in
        // the object is overwritten and the key keeps its original position
        set_or_replace(&mut fields, r#""sessionReplay""#, ColumnValue::Bool(false));
        set_or_replace(&mut fields, r#""webVitals""#, ColumnValue::Bool(false));
    }

    if fields.is_empty() {
        return Err(SiteLifecycleError::new(SiteLifecycleErrorCode::EmptyUpdate, 400, "No fields to update").into());
    }
    fields.push(("updated_at", ColumnValue::Timestamp(now_iso())));

    let assignments: Vec<String> = fields
        .iter()
        .enumerate()
        .map(|(index, (column, value))| {
            let cast = if matches!(value, ColumnValue::Timestamp(_)) { "::timestamp" } else { "" };
            format!("{column} = ${}{cast}", index + 1)
        })
        .collect();
    let sql = format!("UPDATE sites SET {} WHERE site_id = ${}", assignments.join(", "), fields.len() + 1);
    let mut query = sqlx::query(&sql);
    for (_, value) in &fields {
        query = match value {
            ColumnValue::Text(text) => query.bind(text.clone()),
            ColumnValue::NullText => query.bind(Option::<String>::None),
            ColumnValue::Bool(flag) => query.bind(*flag),
            ColumnValue::Int(number) => query.bind(*number),
            ColumnValue::Json(json) => query.bind(json.clone()),
            ColumnValue::Timestamp(text) => query.bind(text.clone()),
        };
    }
    if let Err(error) = query.bind(site.site_id).execute(&state.pg).await {
        if unique_violation(&error) {
            warn!(site_id = site.site_id, "Domain already in use");
            return Err(SiteLifecycleError::new(SiteLifecycleErrorCode::DomainConflict, 409, "Domain already in use").into());
        }
        return Err(error.into());
    }

    state.site_config.invalidate(site.id.as_deref(), site.site_id);
    let config = state.site_config.get_config(&SiteRef::Number(i64::from(site.site_id))).await;
    match config {
        Some(config) => {
            info!(site_id = site.site_id, fields = fields.len() - 1, "Site configuration updated");
            Ok(config)
        }
        // `throw new Error(\`Updated Site ${siteId} could not be reloaded\`)`
        None => Err(LifecycleFailure::Store(format!("Updated Site {} could not be reloaded", site.site_id))),
    }
}

/// `Object.assign(updateData, { [field]: value })` semantics for the ordered list.
fn set_or_replace(fields: &mut Vec<(&'static str, ColumnValue)>, column: &'static str, value: ColumnValue) {
    match fields.iter_mut().find(|(name, _)| *name == column) {
        Some(entry) => entry.1 = value,
        None => fields.push((column, value)),
    }
}

/// `siteConfigurationLifecycle.updatePrivateLink`
pub async fn update_private_link(
    state: &AppState,
    site_id: f64,
    generate: bool,
) -> Result<Option<String>, LifecycleFailure> {
    let site = find_site(&state.pg, site_id).await?;
    let private_link_key = generate.then(random_hex_6);
    sqlx::query("UPDATE sites SET private_link_key = $1 WHERE site_id = $2")
        .bind(&private_link_key)
        .bind(site.site_id)
        .execute(&state.pg)
        .await?;
    state.site_config.invalidate(site.id.as_deref(), site.site_id);
    info!(site_id = site.site_id, generated = generate, "Private link key updated");
    Ok(private_link_key)
}

/// `siteConfigurationLifecycle.delete`: the two session-replay tables first (in
/// parallel, so either failure aborts before the row is removed), then the row.
pub async fn delete_site(state: &AppState, site_id: f64) -> Result<(), LifecycleFailure> {
    let site = find_site(&state.pg, site_id).await?;
    let id = i64::from(site.site_id).to_string();
    let events_params = [("id", id.clone())];
    let metadata_params = [("id", id)];
    let events =
        state.clickhouse.command("DELETE FROM session_replay_events WHERE site_id = {id:UInt32}", &events_params);
    let metadata = state
        .clickhouse
        .command("DELETE FROM session_replay_metadata_v2 WHERE site_id = {id:UInt32}", &metadata_params);
    let (events, metadata) = tokio::join!(events, metadata);
    events.map_err(|error| LifecycleFailure::Store(error.to_string()))?;
    metadata.map_err(|error| LifecycleFailure::Store(error.to_string()))?;

    sqlx::query("DELETE FROM sites WHERE site_id = $1").bind(site.site_id).execute(&state.pg).await?;
    state.site_config.invalidate(site.id.as_deref(), site.site_id);
    info!(site_id = site.site_id, "Site deleted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_pattern_matches_the_javascript_one() {
        for domain in ["example.com", "sub.example.com", "a-b.co", "xn--caf-dma.example", "café.example", "日本.みんな"] {
            assert!(matches(&DOMAIN_PATTERN, domain), "{domain}");
        }
        for domain in ["", "example", "-bad.com", "bad-.com", "example.c", "ex ample.com", "example.com/", "http://example.com"] {
            assert!(!matches(&DOMAIN_PATTERN, domain), "{domain}");
        }
    }

    #[test]
    fn app_identifier_pattern_matches_the_javascript_one() {
        assert!(matches(&APP_IDENTIFIER_PATTERN, "com.example.app"));
        assert!(matches(&APP_IDENTIFIER_PATTERN, "A"));
        assert!(!matches(&APP_IDENTIFIER_PATTERN, ".com.example"));
        assert!(!matches(&APP_IDENTIFIER_PATTERN, ""));
        assert!(!matches(&APP_IDENTIFIER_PATTERN, &format!("a{}", "b".repeat(253))));
        assert!(matches(&APP_IDENTIFIER_PATTERN, &format!("a{}", "b".repeat(252))));
    }

    #[test]
    fn normalize_domain_strips_one_scheme_and_every_trailing_slash() {
        assert_eq!(normalize_domain("https://example.com/"), "example.com");
        assert_eq!(normalize_domain("http://example.com///"), "example.com");
        assert_eq!(normalize_domain("example.com"), "example.com");
        assert_eq!(normalize_domain("https://http://example.com"), "http://example.com");
        assert_eq!(normalize_domain("HTTPS://example.com"), "HTTPS://example.com");
    }

    #[test]
    fn mobile_features_are_refused_only_when_asked_for() {
        assert!(validate_mobile_features(SiteType::Mobile, Some(true), None).is_err());
        assert!(validate_mobile_features(SiteType::Mobile, None, Some(true)).is_err());
        assert!(validate_mobile_features(SiteType::Mobile, Some(false), Some(false)).is_ok());
        assert!(validate_mobile_features(SiteType::Web, Some(true), Some(true)).is_ok());
    }

    // ----------------------------------------------------------------------
    // server/src/api/sites/updateSiteConfig.test.ts and
    // server/src/services/sites/siteConfigurationLifecycle.test.ts, for the paths
    // that survive without CLOUD.
    //
    // Every case in those suites that turns on a subscription (the session-replay
    // pro gate, the AppSumo and trial tiers, the site limit) has no self-hosted
    // equivalent: `IS_CLOUD` is false here, which is the branch the suites' own
    // "self-hosted bypass" case pins. What is left is which fields reach the
    // update, how the domain is cleaned and which requests are refused before any
    // write. The ordering the lifecycle suite asserts with mocks (persist once,
    // then invalidate, then reload; no invalidation when the write fails; replay
    // data before the row on delete) is checked end to end by the row snapshots in
    // parity/api-sites/writes.py.

    fn columns(input: &UpdateInput) -> Vec<&'static str> {
        direct_update_fields(input).into_iter().map(|(column, _)| column).collect()
    }

    fn value_of(fields: &[(&'static str, ColumnValue)], column: &str) -> String {
        let (_, value) = fields.iter().find(|(name, _)| *name == column).expect("column present");
        match value {
            ColumnValue::Text(text) => text.clone(),
            ColumnValue::NullText => "NULL".to_string(),
            ColumnValue::Bool(flag) => flag.to_string(),
            ColumnValue::Int(number) => number.to_string(),
            ColumnValue::Json(json) => json.to_string(),
            ColumnValue::Timestamp(text) => text.clone(),
        }
    }

    #[test]
    fn updates_settings_and_analytics_toggles() {
        let input = UpdateInput {
            name: Some("Renamed".into()),
            public: Some(true),
            block_bots: Some(false),
            web_vitals: Some(true),
            track_errors: Some(true),
            excluded_countries: Some(vec!["US".into(), "GB".into()]),
            tags: Some(vec!["prod".into()]),
            ..UpdateInput::default()
        };
        let fields = direct_update_fields(&input);
        assert_eq!(value_of(&fields, "name"), "Renamed");
        assert_eq!(value_of(&fields, r#""public""#), "true");
        assert_eq!(value_of(&fields, r#""blockBots""#), "false");
        assert_eq!(value_of(&fields, r#""webVitals""#), "true");
        assert_eq!(value_of(&fields, r#""trackErrors""#), "true");
        assert_eq!(value_of(&fields, "excluded_countries"), r#"["US","GB"]"#);
        assert_eq!(value_of(&fields, "tags"), r#"["prod"]"#);
        // nothing else is written
        assert_eq!(fields.len(), 7);
    }

    #[test]
    fn writes_nothing_for_an_empty_update() {
        assert!(columns(&UpdateInput::default()).is_empty());
    }

    #[test]
    fn cleans_the_domain_before_storing_it() {
        assert_eq!(normalize_domain("https://new.example.com/"), "new.example.com");
        assert!(validate_site_identity(SiteType::Web, "new.example.com").is_ok());
    }

    #[test]
    fn rejects_invalid_excluded_ip_patterns() {
        let validation = validate_ip_pattern("999.999.0.1");
        assert_eq!(validation.error, Some("Invalid IP address format"));
        assert!(validate_ip_pattern("10.0.0.1").error.is_none());
        // an empty or whitespace-only pattern passes, as the client allows
        assert!(validate_ip_pattern("   ").error.is_none());
    }

    #[test]
    fn refuses_session_replay_on_a_mobile_site_before_anything_else() {
        let error = validate_mobile_features(SiteType::Mobile, Some(true), None).unwrap_err();
        assert_eq!(error.status, 400);
        assert_eq!(error.message, "Session replay and Web Vitals are only available for web sites");
        assert_eq!(error.code, SiteLifecycleErrorCode::MobileFeatureNotSupported);
    }

    #[test]
    fn a_mobile_site_always_stores_replay_and_vitals_off() {
        // `updateData.sessionReplay = false` replaces the entry in place, so the
        // column keeps its position in the statement
        let input = UpdateInput { session_replay: Some(false), name: Some("x".into()), ..UpdateInput::default() };
        let mut fields = direct_update_fields(&input);
        set_or_replace(&mut fields, r#""sessionReplay""#, ColumnValue::Bool(false));
        set_or_replace(&mut fields, r#""webVitals""#, ColumnValue::Bool(false));
        assert_eq!(
            fields.iter().map(|(column, _)| *column).collect::<Vec<_>>(),
            vec!["name", r#""sessionReplay""#, r#""webVitals""#]
        );
        assert_eq!(value_of(&fields, r#""sessionReplay""#), "false");
        assert_eq!(value_of(&fields, r#""webVitals""#), "false");
    }

    #[test]
    fn refuses_a_site_id_that_is_not_a_positive_integer() {
        for site_id in [0.0, -1.0, 1.5, f64::NAN, f64::INFINITY] {
            let error = validate_site_id(site_id).unwrap_err();
            assert_eq!(error.status, 400, "{site_id}");
            assert_eq!(error.message, "Invalid site ID: must be a positive integer");
        }
        assert_eq!(validate_site_id(65200.0).unwrap(), 65200);
    }

    #[test]
    fn normalize_site_type_keeps_the_stored_type_when_none_is_sent() {
        assert_eq!(normalize_site_type(None, SiteType::Mobile), SiteType::Mobile);
        assert_eq!(normalize_site_type(Some(None), SiteType::Mobile), SiteType::Web);
        assert_eq!(normalize_site_type(Some(Some("mobile")), SiteType::Web), SiteType::Mobile);
        assert_eq!(normalize_site_type(Some(Some("web")), SiteType::Mobile), SiteType::Web);
    }

    #[test]
    fn the_private_link_key_is_six_random_bytes_in_hex() {
        let key = random_hex_6();
        assert_eq!(key.len(), 12);
        assert!(key.chars().all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
        assert_ne!(key, random_hex_6());
    }

    #[test]
    fn the_updated_at_value_is_an_iso_string_with_milliseconds() {
        let now = now_iso();
        assert_eq!(now.len(), 24, "{now}");
        assert!(now.ends_with('Z'));
        assert_eq!(now.as_bytes()[10], b'T');
        assert_eq!(now.as_bytes()[19], b'.');
    }
}
