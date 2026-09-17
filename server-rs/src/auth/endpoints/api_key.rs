//! `GET /api-key/list` and `POST /api-key/delete` from @better-auth/api-key with
//! auth.ts's two configurations: `default` (user keys) and `org` (organization keys,
//! managed through the organization roles' `apiKey` resource). Keys are created
//! through the Fastify routes, not here.

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use chrono::NaiveDateTime;
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row, postgres::PgRow};
use tracing::{debug, error, info, warn};

use crate::auth::bearer::ORG_API_KEY_CONFIG_ID;

use super::{
    better_json,
    context::{ApiError, Ctx, EndpointResult, Reply},
    db::{self, iso, iso_opt, opt_str},
    organization, require_session,
    validate::{self, Ty, optional, required},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    List,
    Delete,
}

pub async fn run(ctx: &mut Ctx<'_>, route: Route) -> EndpointResult {
    match route {
        Route::List => list(ctx).await,
        Route::Delete => delete(ctx).await,
    }
}

fn key_error(status: StatusCode, code: &str, message: &str) -> ApiError {
    ApiError::code(status, code, message)
}

/// `configIdMatches`: null, undefined and "default" are the same configuration
fn is_default_config(config_id: Option<&str>) -> bool {
    config_id.is_none_or(|id| id.is_empty() || id == "default")
}

/// `resolveConfiguration(ctx, configurations, configId)`: unknown ids fall back to default
fn references_organization(config_id: Option<&str>) -> bool {
    config_id == Some(ORG_API_KEY_CONFIG_ID)
}

static LAST_EXPIRED_SWEEP: LazyLock<Mutex<Option<Instant>>> = LazyLock::new(|| Mutex::new(None));

/// `deleteAllExpiredApiKeys`: at most once every 10 seconds per process, fire and forget
fn sweep_expired_keys(pg: &PgPool) {
    {
        let mut last = LAST_EXPIRED_SWEEP.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if last.is_some_and(|at| at.elapsed() < Duration::from_secs(10)) {
            return;
        }
        *last = Some(Instant::now());
    }
    let pg = pg.clone();
    tokio::spawn(async move {
        match sqlx::query(r#"DELETE FROM apikey WHERE "expiresAt" < $1 AND "expiresAt" IS NOT NULL"#).bind(db::now_ms()).execute(&pg).await {
            Ok(result) => debug!(deleted = result.rows_affected(), "Expired API keys swept"),
            Err(err) => error!(error = %err, "Failed to delete expired API keys"),
        }
    });
}

/// `checkOrgApiKeyPermission`: membership, then the role's `apiKey` action (owners always pass)
async fn check_org_permission(pg: &PgPool, user_id: &str, organization_id: &str, action: &str) -> Result<(), ApiError> {
    let role: Option<String> = sqlx::query_scalar(r#"SELECT role FROM member WHERE "userId" = $1 AND "organizationId" = $2"#)
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(pg)
        .await?;
    let Some(role) = role else {
        return Err(key_error(
            StatusCode::FORBIDDEN,
            "USER_NOT_MEMBER_OF_ORGANIZATION",
            "You are not a member of the organization that owns this API key.",
        ));
    };
    let mut permissions = Map::new();
    permissions.insert("apiKey".into(), json!([action]));
    if !organization::has_permission(&role, Some(&permissions), true) {
        return Err(key_error(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_API_KEY_PERMISSIONS",
            "You do not have permission to perform this action on organization API keys.",
        ));
    }
    Ok(())
}

struct ApiKeyRow {
    id: String,
    config_id: Option<String>,
    name: Option<String>,
    start: Option<String>,
    reference_id: String,
    prefix: Option<String>,
    refill_interval: Option<i32>,
    refill_amount: Option<i32>,
    last_refill_at: Option<NaiveDateTime>,
    enabled: bool,
    rate_limit_enabled: bool,
    rate_limit_time_window: Option<i32>,
    rate_limit_max: Option<i32>,
    request_count: i32,
    remaining: Option<i32>,
    last_request: Option<NaiveDateTime>,
    expires_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
    permissions: Option<String>,
    metadata: Option<Value>,
}

const KEY_COLUMNS: &str = r#"id, "configId", name, start, "referenceId", prefix, "refillInterval", "refillAmount", "lastRefillAt", enabled, "rateLimitEnabled", "rateLimitTimeWindow", "rateLimitMax", "requestCount", remaining, "lastRequest", "expiresAt", "createdAt", "updatedAt", permissions, metadata"#;

impl ApiKeyRow {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            config_id: row.try_get("configId")?,
            name: row.try_get("name")?,
            start: row.try_get("start")?,
            reference_id: row.try_get("referenceId")?,
            prefix: row.try_get("prefix")?,
            refill_interval: row.try_get("refillInterval")?,
            refill_amount: row.try_get("refillAmount")?,
            last_refill_at: row.try_get("lastRefillAt")?,
            enabled: row.try_get("enabled")?,
            rate_limit_enabled: row.try_get("rateLimitEnabled")?,
            rate_limit_time_window: row.try_get("rateLimitTimeWindow")?,
            rate_limit_max: row.try_get("rateLimitMax")?,
            request_count: row.try_get("requestCount")?,
            remaining: row.try_get("remaining")?,
            last_request: row.try_get("lastRequest")?,
            expires_at: row.try_get("expiresAt")?,
            created_at: row.try_get("createdAt")?,
            updated_at: row.try_get("updatedAt")?,
            permissions: row.try_get("permissions")?,
            metadata: row.try_get("metadata")?,
        })
    }

    /// The listed shape: the row minus `key`, metadata as `parseDoubleStringifiedMetadata`
    /// returns it and permissions through `safeJSONParse` (null when absent or unparseable).
    fn to_json(&self, metadata: Value) -> Value {
        let mut map = Map::new();
        let int = |value: Option<i32>| value.map_or(Value::Null, Value::from);
        map.insert("configId".into(), opt_str(self.config_id.clone()));
        map.insert("name".into(), opt_str(self.name.clone()));
        map.insert("start".into(), opt_str(self.start.clone()));
        map.insert("referenceId".into(), Value::from(self.reference_id.clone()));
        map.insert("prefix".into(), opt_str(self.prefix.clone()));
        map.insert("refillInterval".into(), int(self.refill_interval));
        map.insert("refillAmount".into(), int(self.refill_amount));
        map.insert("lastRefillAt".into(), iso_opt(self.last_refill_at));
        map.insert("enabled".into(), Value::from(self.enabled));
        map.insert("rateLimitEnabled".into(), Value::from(self.rate_limit_enabled));
        map.insert("rateLimitTimeWindow".into(), int(self.rate_limit_time_window));
        map.insert("rateLimitMax".into(), int(self.rate_limit_max));
        map.insert("requestCount".into(), Value::from(self.request_count));
        map.insert("remaining".into(), int(self.remaining));
        map.insert("lastRequest".into(), iso_opt(self.last_request));
        map.insert("expiresAt".into(), iso_opt(self.expires_at));
        map.insert("createdAt".into(), Value::from(iso(self.created_at)));
        map.insert("updatedAt".into(), Value::from(iso(self.updated_at)));
        let permissions = self
            .permissions
            .as_deref()
            .filter(|text| !text.is_empty())
            .map(better_json::safe_json_parse)
            .unwrap_or(Value::Null);
        map.insert("permissions".into(), permissions);
        map.insert("metadata".into(), metadata);
        map.insert("id".into(), Value::from(self.id.clone()));
        Value::Object(map)
    }

    /// `metadata` as the adapter hands it to the plugin; see [`adapter_metadata`].
    fn adapter_metadata(&self) -> Result<AdapterMetadata, ApiError> {
        adapter_metadata(self.metadata.as_ref()).map_err(|err| {
            error!(key_id = %self.id, error = ?err, "API key metadata failed the schema's parseJSON output transform");
            ApiError::internal()
        })
    }
}

/// Node's read path for `apikey.metadata`: drizzle receives the jsonb text and
/// `JSON.parse`s it once (so the plugin starts from the jsonb value itself, with JS
/// key order), then the plugin schema's `transform.output` maps falsy values to null
/// and runs better-json's strict `parseJSON` on strings, which throws (failing the
/// whole query) for text that is not JSON. Probed against Node with 15 stored shapes
/// (scratchpad probe_metadata.py); a jsonb string holding an ISO date throws too.
fn adapter_metadata(raw: Option<&Value>) -> Result<AdapterMetadata, better_json::StrictParseError> {
    let from_drizzle = match raw {
        None => return Ok(AdapterMetadata::Other(Value::Null)),
        Some(value) => better_json::js_object_order(value.clone()),
    };
    if !better_json::is_truthy(&from_drizzle) {
        return Ok(AdapterMetadata::Other(Value::Null));
    }
    let Value::String(text) = from_drizzle else { return Ok(AdapterMetadata::Other(from_drizzle)) };
    match better_json::parse_json_strict(&text)? {
        // a top-level ISO string comes back as a Date object, which is not migrated
        Some(Value::String(parsed)) if !better_json::parses_to_date(&text) => Ok(AdapterMetadata::String(parsed)),
        Some(value) => Ok(AdapterMetadata::Other(value)),
        None => Ok(AdapterMetadata::Other(Value::Null)),
    }
}

/// What the plugin receives for `metadata`: JS strings are the legacy shape.
#[derive(Debug, PartialEq)]
enum AdapterMetadata {
    String(String),
    Other(Value),
}

/// `parseDoubleStringifiedMetadata` on the adapter output, plus whether
/// `batchMigrateLegacyMetadata` rewrites the row (only when it is still a string).
fn listed_metadata(adapter_value: AdapterMetadata) -> (Value, bool) {
    match adapter_value {
        AdapterMetadata::String(text) => (better_json::safe_json_parse(&text), true),
        AdapterMetadata::Other(value) => (value, false),
    }
}

/// `GET /api-key/list[?organizationId=]`
async fn list(ctx: &mut Ctx<'_>) -> EndpointResult {
    let query = Value::Object(ctx.query.clone());
    validate::object(
        Some(&query),
        &[optional("configId", Ty::String), optional("organizationId", Ty::String), optional("sortBy", Ty::String)],
        "query",
        false,
    )?;
    let limit = coerce_index(ctx.query.get("limit"), "limit")?;
    let offset = coerce_index(ctx.query.get("offset"), "offset")?;
    if let Some(direction) = ctx.query.get("sortDirection")
        && !matches!(direction.as_str(), Some("asc" | "desc"))
    {
        return Err(ApiError::code(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "[query.sortDirection] Invalid option: expected one of \"asc\"|\"desc\"",
        ));
    }
    let session = require_session(ctx).await?;
    let pg = &ctx.state.pg;
    let organization_id = ctx.query_str("organizationId").filter(|id| !id.is_empty()).map(str::to_string);
    if let Some(organization_id) = &organization_id {
        check_org_permission(pg, &session.user.id, organization_id, "read").await?;
    }
    let reference_id = organization_id.clone().unwrap_or_else(|| session.user.id.clone());
    let config_filter = ctx.query_str("configId").filter(|id| !id.is_empty()).map(str::to_string);
    let sort = match ctx.query_str("sortBy").filter(|s| !s.is_empty()) {
        Some(field) => {
            let Some(column) = sort_column(field) else {
                error!(field, "API key list sorted by an unknown field");
                return Err(ApiError::internal());
            };
            let direction = if ctx.query_str("sortDirection") == Some("desc") { "DESC" } else { "ASC" };
            format!(" ORDER BY {column} {direction}")
        }
        None => String::new(),
    };
    let rows = sqlx::query(&format!(r#"SELECT {KEY_COLUMNS} FROM apikey WHERE "referenceId" = $1{sort} LIMIT 100"#))
        .bind(&reference_id)
        .fetch_all(pg)
        .await?;
    let keys: Vec<ApiKeyRow> = rows.iter().map(ApiKeyRow::from_row).collect::<Result<_, _>>()?;
    // findMany runs the output transform on every fetched row before any filtering
    let metadata: Vec<AdapterMetadata> = keys.iter().map(ApiKeyRow::adapter_metadata).collect::<Result<_, _>>()?;
    let wants_organization = organization_id.is_some();
    let mut filtered: Vec<(&ApiKeyRow, AdapterMetadata)> = keys
        .iter()
        .zip(metadata)
        .filter(|(key, _)| references_organization(key.config_id.as_deref()) == wants_organization && key.reference_id == reference_id)
        .collect();
    if let Some(config) = &config_filter {
        filtered.retain(|(key, _)| {
            (is_default_config(key.config_id.as_deref()) && is_default_config(Some(config))) || key.config_id.as_deref() == Some(config)
        });
    }
    let total = filtered.len();
    let page: Vec<(&ApiKeyRow, AdapterMetadata)> =
        filtered.into_iter().skip(offset.unwrap_or(0) as usize).take(limit.map_or(usize::MAX, |limit| limit as usize)).collect();
    sweep_expired_keys(pg);
    let mut listed = Vec::with_capacity(page.len());
    for (key, adapter_value) in page {
        let (metadata, migrate) = listed_metadata(adapter_value);
        if migrate {
            // batchMigrateLegacyMetadata: the write is transform.input's
            // JSON.stringify, which Postgres reads back as the jsonb value (an object
            // for parsed objects, a jsonb string when the parse still gave a string)
            let stored = crate::js_json::stringify(&metadata);
            match sqlx::query(r#"UPDATE apikey SET metadata = $1::jsonb WHERE id = $2"#).bind(stored).bind(&key.id).execute(pg).await {
                Ok(_) => info!(key_id = %key.id, "Migrated double-stringified API key metadata"),
                Err(err) => warn!(error = %err, key_id = %key.id, "Failed to migrate double-stringified metadata"),
            }
        }
        listed.push(key.to_json(metadata));
    }
    let mut body = Map::new();
    body.insert("apiKeys".into(), Value::Array(listed));
    body.insert("total".into(), Value::from(total));
    if let Some(limit) = limit {
        body.insert("limit".into(), Value::from(limit));
    }
    if let Some(offset) = offset {
        body.insert("offset".into(), Value::from(offset));
    }
    debug!(total, organization = wants_organization, "API keys listed");
    Ok(Reply::Json(Value::Object(body)))
}

/// `z.coerce.number().int().nonnegative().optional()`
fn coerce_index(value: Option<&Value>, name: &str) -> Result<Option<i64>, ApiError> {
    let Some(value) = value else { return Ok(None) };
    let text = value.as_str().unwrap_or_default();
    let number = if text.trim().is_empty() { 0.0 } else { text.trim().parse::<f64>().unwrap_or(f64::NAN) };
    let invalid = |message: String| ApiError::code(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", &message);
    if number.is_nan() {
        return Err(invalid(format!("[query.{name}] Invalid input: expected number, received NaN")));
    }
    if number.fract() != 0.0 {
        return Err(invalid(format!("[query.{name}] Invalid input: expected int, received number")));
    }
    if number < 0.0 {
        return Err(invalid(format!("[query.{name}] Too small: expected number to be >=0")));
    }
    Ok(Some(number as i64))
}

fn sort_column(field: &str) -> Option<&'static str> {
    Some(match field {
        "id" => "id",
        "configId" => r#""configId""#,
        "name" => "name",
        "start" => "start",
        "referenceId" => r#""referenceId""#,
        "prefix" => "prefix",
        "key" => "key",
        "enabled" => "enabled",
        "expiresAt" => r#""expiresAt""#,
        "createdAt" => r#""createdAt""#,
        "updatedAt" => r#""updatedAt""#,
        "lastRequest" => r#""lastRequest""#,
        "remaining" => "remaining",
        "requestCount" => r#""requestCount""#,
        _ => return None,
    })
}

/// `POST /api-key/delete {keyId, configId?}`
async fn delete(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[optional("configId", Ty::String), required("keyId", Ty::String)], "body", false)?;
    let session = require_session(ctx).await?;
    if session.user.banned == Some(true) {
        return Err(key_error(StatusCode::UNAUTHORIZED, "USER_BANNED", "User is banned"));
    }
    let pg = &ctx.state.pg;
    let key_id = ctx.body_str("keyId").unwrap_or_default().to_string();
    let requested_config = ctx.body_str("configId").filter(|id| !id.is_empty()).map(str::to_string);
    // resolveConfiguration: an unknown configId falls back to the default one
    let lookup_config = match requested_config.as_deref() {
        Some(ORG_API_KEY_CONFIG_ID) => Some(ORG_API_KEY_CONFIG_ID),
        _ => None,
    };
    let not_found = || key_error(StatusCode::NOT_FOUND, "KEY_NOT_FOUND", "API Key not found");
    let row = sqlx::query(&format!("SELECT {KEY_COLUMNS} FROM apikey WHERE id = $1")).bind(&key_id).fetch_optional(pg).await?;
    let Some(key) = row.as_ref().map(ApiKeyRow::from_row).transpose()? else { return Err(not_found()) };
    // findOne runs the schema's output transform, which throws on unparseable metadata
    key.adapter_metadata()?;
    let matches = (is_default_config(key.config_id.as_deref()) && is_default_config(lookup_config))
        || key.config_id.as_deref() == lookup_config;
    if !matches {
        return Err(not_found());
    }
    if references_organization(key.config_id.as_deref()) {
        check_org_permission(pg, &session.user.id, &key.reference_id, "delete").await?;
    } else if key.reference_id != session.user.id {
        return Err(not_found());
    }
    sqlx::query("DELETE FROM apikey WHERE id = $1")
        .bind(&key.id)
        .execute(pg)
        .await
        .map_err(|err| ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()))?;
    sweep_expired_keys(pg);
    info!(key_id = %key.id, user_id = %session.user.id, "API key deleted");
    Ok(Reply::Json(json!({"success": true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_read_path() {
        // Expectations from probing Node (jsonb value in, listed metadata and migration out)
        let listed = |raw: Option<Value>| adapter_metadata(raw.as_ref()).map(listed_metadata);
        let text = |value: Value| Value::String(value.to_string());
        let j = json!({"b": 1, "1": 2, "at": "2024-01-01T00:00:00Z"});
        let revived = json!({"1": 2, "b": 1, "at": "2024-01-01T00:00:00.000Z"});
        assert_eq!(listed(None), Ok((Value::Null, false)));
        assert_eq!(listed(Some(json!(null))), Ok((Value::Null, false)));
        // a jsonb object is passed through untouched (no date revival)
        assert_eq!(listed(Some(json!({"a": 1, "at": "2024-01-01T00:00:00Z"}))), Ok((json!({"a": 1, "at": "2024-01-01T00:00:00Z"}), false)));
        // what Node writes: a jsonb string holding the JSON text, parsed with revival
        let listed_j = listed(Some(text(j.clone()))).unwrap();
        assert_eq!(crate::js_json::stringify(&listed_j.0), crate::js_json::stringify(&revived));
        assert!(!listed_j.1);
        // one level deeper is migrated
        assert_eq!(listed(Some(text(text(j.clone())))).map(|(_, migrate)| migrate), Ok(true));
        assert_eq!(listed(Some(json!("\"not json\""))), Ok((Value::Null, true)));
        assert_eq!(listed(Some(text(json!("\"not json\"")))), Ok((json!("not json"), true)));
        assert_eq!(listed(Some(json!(5))), Ok((json!(5), false)));
        assert_eq!(listed(Some(json!("5"))), Ok((json!(5), false)));
        assert_eq!(listed(Some(json!(""))), Ok((Value::Null, false)));
        assert_eq!(listed(Some(json!(false))), Ok((Value::Null, false)));
        assert_eq!(listed(Some(json!("true"))), Ok((json!(true), false)));
        assert_eq!(listed(Some(json!("\"2024-01-01T00:00:00Z\""))), Ok((json!("2024-01-01T00:00:00.000Z"), false)));
        assert!(listed(Some(json!("not json"))).is_err());
        assert!(listed(Some(json!("2024-01-01T00:00:00Z"))).is_err());
    }

    #[test]
    fn index_coercion() {
        assert_eq!(coerce_index(None, "limit").unwrap(), None);
        assert_eq!(coerce_index(Some(&json!("5")), "limit").unwrap(), Some(5));
        assert!(coerce_index(Some(&json!("-1")), "limit").is_err());
        assert!(coerce_index(Some(&json!("x")), "limit").is_err());
    }
}
