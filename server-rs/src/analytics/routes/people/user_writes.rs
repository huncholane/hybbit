//! Dashboard writes to a user, ported from server/src/api/analytics/users:
//! `POST /users/identify` (identifyUser.ts) and `PUT /users/:userId/traits`
//! (updateUserTraits.ts) on the `authUsersWrite` chain, and
//! `DELETE /users/:userId` (deleteUser.ts, GDPR erasure) on `adminUsersWrite`.
//!
//! Fastify parses the body before any preHandler, so a malformed body is
//! rejected ahead of the access checks, exactly as in Node.

use std::time::Duration;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use sqlx::{
    Postgres, Type,
    encode::{Encode, IsNull},
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo, types::Oid},
};
use tracing::{error, info, warn};

use super::common::{HandlerError, path_params, pg_integer, read_body, send_json};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, SiteRequest, route_scope, site_scoped},
        js::JsValue,
        utils::analytics_query::{QueryParam, format_query, format_query_param, parse_clickhouse_error},
    },
    identity::{backfill_identified_user_id, identify::js_json_stringify_object},
    state::AppState,
};

/// `MAX_TRAITS_SIZE`: 2 KB, matching the tracker identify endpoint.
const MAX_TRAITS_SIZE: usize = 2048;

fn traits_too_large_message() -> String {
    format!("Traits must be less than {MAX_TRAITS_SIZE} bytes (2KB)")
}

// ---------------------------------------------------------------------------
// zod 3.25 validation with `error.flatten()`

#[derive(Default)]
struct Issues {
    form_errors: Vec<String>,
    field_errors: IndexMap<&'static str, Vec<String>>,
}

impl Issues {
    fn field(&mut self, name: &'static str, message: String) {
        self.field_errors.entry(name).or_default().push(message);
    }

    fn is_empty(&self) -> bool {
        self.form_errors.is_empty() && self.field_errors.is_empty()
    }

    /// `error.flatten()`
    fn flatten(self) -> Value {
        let field_errors: Map<String, Value> =
            self.field_errors.into_iter().map(|(name, messages)| (name.to_string(), json!(messages))).collect();
        json!({ "formErrors": self.form_errors, "fieldErrors": field_errors })
    }
}

/// zod's `ZodParsedType` name for a JSON value.
fn parsed_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// zod's default `invalid_type` message (`undefined` reads "Required").
fn invalid_type(expected: &str, received: Option<&Value>) -> String {
    match received {
        None => "Required".to_string(),
        Some(value) => format!("Expected {expected}, received {}", parsed_type(value)),
    }
}

/// `z.string().min(1).max(255)`
fn bounded_string(issues: &mut Issues, name: &'static str, value: Option<&Value>) -> Option<String> {
    let Some(Value::String(text)) = value else {
        issues.field(name, invalid_type("string", value));
        return None;
    };
    let length = text.encode_utf16().count();
    if length < 1 {
        issues.field(name, "String must contain at least 1 character(s)".to_string());
    }
    if length > 255 {
        issues.field(name, "String must contain at most 255 character(s)".to_string());
    }
    Some(text.clone())
}

/// `z.record(z.unknown()).refine(size <= MAX_TRAITS_SIZE)`: the record, or None
/// when the type check aborted.
fn traits_record(issues: &mut Issues, value: Option<&Value>) -> Option<Map<String, Value>> {
    let Some(Value::Object(record)) = value else {
        issues.field("traits", invalid_type("object", value));
        return None;
    };
    // ZodRecord rebuilds the object without `__proto__`
    let record: Map<String, Value> =
        record.iter().filter(|(key, _)| key.as_str() != "__proto__").map(|(key, item)| (key.clone(), item.clone())).collect();
    if js_json_stringify_object(&record).len() > MAX_TRAITS_SIZE {
        issues.field("traits", traits_too_large_message());
    }
    Some(record)
}

/// The validated `identifyUserBodySchema` body.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentifyUserBody {
    pub anonymous_id: String,
    pub user_id: String,
    pub traits: Option<Map<String, Value>>,
}

/// `identifyUserBodySchema.safeParse(body)`: the payload or `error.flatten()`.
pub fn validate_identify_user_body(body: Option<&Value>) -> Result<IdentifyUserBody, Value> {
    let mut issues = Issues::default();
    let Some(Value::Object(object)) = body else {
        issues.form_errors.push(invalid_type("object", body));
        return Err(issues.flatten());
    };
    let anonymous_id = bounded_string(&mut issues, "anonymous_id", object.get("anonymous_id"));
    let user_id = bounded_string(&mut issues, "user_id", object.get("user_id"));
    let traits = match object.get("traits") {
        None => None,
        present => traits_record(&mut issues, present),
    };
    if !issues.is_empty() {
        return Err(issues.flatten());
    }
    Ok(IdentifyUserBody {
        anonymous_id: anonymous_id.unwrap_or_default(),
        user_id: user_id.unwrap_or_default(),
        traits,
    })
}

/// `updateUserTraitsBodySchema.safeParse(body)`: the traits record or `error.flatten()`.
pub fn validate_update_traits_body(body: Option<&Value>) -> Result<Map<String, Value>, Value> {
    let mut issues = Issues::default();
    let Some(Value::Object(object)) = body else {
        issues.form_errors.push(invalid_type("object", body));
        return Err(issues.flatten());
    };
    let traits = traits_record(&mut issues, object.get("traits"));
    match traits {
        Some(traits) if issues.is_empty() => Ok(traits),
        _ => Err(issues.flatten()),
    }
}

// ---------------------------------------------------------------------------
// Postgres

/// A jsonb parameter holding JSON text, as drizzle's jsonb column encoder hands
/// `JSON.stringify(value)` to postgres.js.
struct JsonbText<'a>(&'a str);

impl Type<Postgres> for JsonbText<'_> {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_oid(Oid(3802))
    }
}

impl Encode<'_, Postgres> for JsonbText<'_> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        // jsonb binary format: version 1, then the text
        buf.push(1);
        buf.extend_from_slice(self.0.as_bytes());
        Ok(IsNull::No)
    }
}

/// `Object.fromEntries(Object.entries(traits).filter(([, v]) => v !== null))`
fn without_nulls(traits: &Map<String, Value>) -> Map<String, Value> {
    traits.iter().filter(|(_, value)| !value.is_null()).map(|(key, value)| (key.clone(), value.clone())).collect()
}

fn invalid_payload(details: Value) -> Response {
    send_json(StatusCode::BAD_REQUEST, &json!({ "error": "Invalid payload", "details": details }))
}

/// `authUsersWrite`: resolveSiteId, `requireSiteAccess` with `users:write`,
/// validateTimeParams, expandSegmentParam.
async fn users_write_chain(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    site_id_param: &str,
) -> Result<SiteRequest, Response> {
    site_scoped(state, headers, uri, site_id_param, SiteGuard::Member, route_scope("users", "write"), ChainSteps::FULL).await
}

/// The identify writes: profile (merged traits or a shell), alias, backfill.
async fn identify_writes(state: &AppState, site: f64, body: &IdentifyUserBody) -> Result<(), IdentifyFailure> {
    let site_id = pg_integer(site)?;
    let filtered = body.traits.as_ref().map(without_nulls).unwrap_or_default();

    if !filtered.is_empty() {
        let text = js_json_stringify_object(&filtered);
        sqlx::query(
            r#"insert into "user_profiles" ("site_id", "user_id", "traits", "created_at", "updated_at") values ($1, $2, $3, default, default) on conflict ("site_id","user_id") do update set "traits" = "user_profiles"."traits" || $4::jsonb, "updated_at" = now()"#,
        )
        .bind(site_id)
        .bind(&body.user_id)
        .bind(JsonbText(&text))
        .bind(&text)
        .execute(&state.pg)
        .await?;
    } else {
        // Profile shell so the user shows up in search and the inventory
        sqlx::query(
            r#"insert into "user_profiles" ("site_id", "user_id", "traits", "created_at", "updated_at") values ($1, $2, default, default, default) on conflict do nothing"#,
        )
        .bind(site_id)
        .bind(&body.user_id)
        .execute(&state.pg)
        .await?;
    }

    sqlx::query(
        r#"insert into "user_aliases" ("id", "site_id", "anonymous_id", "user_id", "created_at") values (default, $1, $2, $3, default) on conflict ("site_id","anonymous_id") do update set "user_id" = $4"#,
    )
    .bind(site_id)
    .bind(&body.anonymous_id)
    .bind(&body.user_id)
    .bind(&body.user_id)
    .execute(&state.pg)
    .await?;

    // Queued with no window: the operator asserts the device's whole history
    backfill_identified_user_id(&state.ingest.backfill, site_id, &body.anonymous_id, &body.user_id, None);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum IdentifyFailure {
    #[error(transparent)]
    Handler(#[from] HandlerError),
    #[error(transparent)]
    Postgres(#[from] sqlx::Error),
}

/// `POST /api/sites/:siteId/users/identify`
pub async fn identify_user(
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
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request = match users_write_chain(&state, &uri, &headers, &params[0]).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let payload = match validate_identify_user_body(body.as_ref()) {
        Ok(payload) => payload,
        Err(details) => {
            warn!(site_id = %request.site_id, "Dashboard identify payload rejected");
            return invalid_payload(details);
        }
    };
    if payload.anonymous_id == payload.user_id {
        return send_json(StatusCode::BAD_REQUEST, &json!({ "error": "User ID must be different from the anonymous ID" }));
    }

    let site = JsValue::from(request.site_id.as_str()).to_number();
    match identify_writes(&state, site, &payload).await {
        Ok(()) => {
            info!(site_id = %request.site_id, "Dashboard identified a user");
            send_json(StatusCode::OK, &json!({ "success": true }))
        }
        Err(failure) => {
            error!(err = %failure, site_id = %request.site_id, "Error identifying user");
            send_json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": "Failed to identify user" }))
        }
    }
}

/// `PUT /api/sites/:siteId/users/:userId/traits`
pub async fn update_user_traits(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match path_params(&method, &uri, &[3, 5]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request = match users_write_chain(&state, &uri, &headers, &params[0]).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let traits = match validate_update_traits_body(body.as_ref()) {
        Ok(traits) => traits,
        Err(details) => {
            warn!(site_id = %request.site_id, "Trait update payload rejected");
            return invalid_payload(details);
        }
    };
    // `v !== null && v !== undefined`; JSON has no undefined
    let traits = without_nulls(&traits);
    let user_id = params[1].as_str();
    let site = JsValue::from(request.site_id.as_str()).to_number();

    let result: Result<(), IdentifyFailure> = async {
        let site_id = pg_integer(site)?;
        let text = js_json_stringify_object(&traits);
        sqlx::query(
            r#"insert into "user_profiles" ("site_id", "user_id", "traits", "created_at", "updated_at") values ($1, $2, $3, default, default) on conflict ("site_id","user_id") do update set "traits" = $4, "updated_at" = now()"#,
        )
        .bind(site_id)
        .bind(user_id)
        .bind(JsonbText(&text))
        .bind(JsonbText(&text))
        .execute(&state.pg)
        .await?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            info!(site_id = %request.site_id, keys = traits.len(), "Replaced user traits");
            send_json(StatusCode::OK, &json!({ "success": true }))
        }
        Err(failure) => {
            error!(err = %failure, site_id = %request.site_id, "Error updating user traits");
            send_json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": "Failed to update user traits" }))
        }
    }
}

// ---------------------------------------------------------------------------
// DELETE /users/:userId

/// `clickhouse.command({ query, query_params })`: the statement goes in the body
/// (trimmed, trailing semicolons removed, no FORMAT clause), parameters in the URL.
async fn clickhouse_command(state: &AppState, query: &str, params: &[(&str, QueryParam)]) -> Result<(), HandlerError> {
    static HTTP: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let http = HTTP.get_or_init(|| {
        reqwest::Client::builder().timeout(Duration::from_millis(300_000)).build().expect("building the HTTP client")
    });
    let config = &state.config.clickhouse;

    let mut search: Vec<(String, String)> = vec![("query_id".to_string(), random_query_id())];
    for (name, value) in params {
        search.push((format!("param_{name}"), format_query_param(value, false, false)));
    }
    if config.database != "default" {
        search.push(("database".to_string(), config.database.clone()));
    }
    // `format_query` appends a FORMAT clause the command path never sends
    let formatted = format_query(query, "X");
    let statement = formatted.strip_suffix(" \nFORMAT X").unwrap_or(&formatted).to_string();

    let response = http
        .post(format!("{}/", config.url.trim_end_matches('/')))
        .query(&search)
        .header("X-ClickHouse-User", &config.user)
        .header("X-ClickHouse-Key", &config.password)
        .body(statement)
        .send()
        .await
        .map_err(|err| HandlerError::new(err.to_string()))?;
    let status = response.status();
    let text = response.text().await.map_err(|err| HandlerError::new(err.to_string()))?;
    if status.is_success() {
        Ok(())
    } else {
        Err(HandlerError::new(parse_clickhouse_error(&text).message))
    }
}

fn random_query_id() -> String {
    let bits: u128 = rand::random();
    let bits = (bits & !(0xF << 76) & !(0x3 << 62)) | (0x4 << 76) | (0x2 << 62);
    let hex = format!("{bits:032x}");
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// The events a user owns: identified as them, or unattributed on one of their devices.
const USER_CONDITION: &str = "site_id = {siteId:UInt16}
      AND (
        identified_user_id = {userId:String}
        OR (user_id IN ({deviceIds:Array(String)}) AND identified_user_id = '')
      )";

async fn delete_user_data(state: &AppState, site: f64, user_id: &str) -> Result<usize, IdentifyFailure> {
    let site_id = pg_integer(site)?;
    let aliases: Vec<String> =
        sqlx::query_scalar(r#"select "anonymous_id" from "user_aliases" where ("user_aliases"."site_id" = $1 and "user_aliases"."user_id" = $2)"#)
            .bind(site_id)
            .bind(user_id)
            .fetch_all(&state.pg)
            .await?;
    let mut device_ids = vec![QueryParam::String(user_id.to_string())];
    device_ids.extend(aliases.iter().map(|id| QueryParam::String(id.clone())));
    let params = [
        ("siteId", QueryParam::Number(site)),
        ("userId", QueryParam::String(user_id.to_string())),
        ("deviceIds", QueryParam::Array(device_ids)),
    ];

    // R2 replay payloads only exist on cloud deployments (IS_CLOUD), never here
    let statements: Vec<String> = ["events", "session_replay_events", "session_replay_metadata_v2"]
        .iter()
        .map(|table| format!("DELETE FROM {table} WHERE {USER_CONDITION}"))
        .collect();
    let (events, replay_events, replay_metadata) = tokio::join!(
        clickhouse_command(state, &statements[0], &params),
        clickhouse_command(state, &statements[1], &params),
        clickhouse_command(state, &statements[2], &params),
    );
    events?;
    replay_events?;
    replay_metadata?;

    let (profiles, aliases_deleted) = tokio::join!(
        sqlx::query(r#"delete from "user_profiles" where ("user_profiles"."site_id" = $1 and "user_profiles"."user_id" = $2)"#)
            .bind(site_id)
            .bind(user_id)
            .execute(&state.pg),
        sqlx::query(
            r#"delete from "user_aliases" where ("user_aliases"."site_id" = $1 and ("user_aliases"."user_id" = $2 or "user_aliases"."anonymous_id" = $3))"#,
        )
        .bind(site_id)
        .bind(user_id)
        .bind(user_id)
        .execute(&state.pg),
    );
    profiles?;
    aliases_deleted?;
    Ok(aliases.len())
}

/// `DELETE /api/sites/:siteId/users/:userId`
pub async fn delete_user(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match path_params(&method, &uri, &[3, 5]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    if let Err(response) = read_body(&headers, body).await {
        return response;
    }
    let request = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Admin,
        route_scope("users", "write"),
        ChainSteps::TIME_ONLY,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };
    let user_id = params[1].as_str();
    let site = JsValue::from(request.site_id.as_str()).to_number();

    match delete_user_data(&state, site, user_id).await {
        Ok(devices) => {
            info!(site_id = %request.site_id, linked_devices = devices, "Deleted user data");
            send_json(StatusCode::OK, &json!({ "success": true }))
        }
        Err(failure) => {
            error!(err = %failure, site_id = %request.site_id, "Error deleting user");
            send_json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": "Failed to delete user" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identify(body: Value) -> Result<IdentifyUserBody, Value> {
        validate_identify_user_body(Some(&body))
    }

    #[test]
    fn identify_body_validation_matches_zod() {
        assert_eq!(
            validate_identify_user_body(None).unwrap_err(),
            json!({ "formErrors": ["Required"], "fieldErrors": {} })
        );
        assert_eq!(identify(json!([])).unwrap_err(), json!({ "formErrors": ["Expected object, received array"], "fieldErrors": {} }));
        assert_eq!(
            identify(json!({ "anonymous_id": "", "user_id": 5, "traits": null })).unwrap_err(),
            json!({
                "formErrors": [],
                "fieldErrors": {
                    "anonymous_id": ["String must contain at least 1 character(s)"],
                    "user_id": ["Expected string, received number"],
                    "traits": ["Expected object, received null"],
                }
            })
        );
        let big = "x".repeat(2100);
        assert_eq!(
            identify(json!({ "anonymous_id": "a", "user_id": "b", "traits": { "k": big } })).unwrap_err(),
            json!({ "formErrors": [], "fieldErrors": { "traits": ["Traits must be less than 2048 bytes (2KB)"] } })
        );
        let ok = identify(json!({ "anonymous_id": "a", "user_id": "b", "traits": { "plan": "pro", "gone": null } })).unwrap();
        assert_eq!(without_nulls(ok.traits.as_ref().unwrap()), json!({ "plan": "pro" }).as_object().unwrap().clone());
        assert_eq!(identify(json!({ "anonymous_id": "a", "user_id": "b" })).unwrap().traits, None);
    }

    #[test]
    fn traits_body_validation_matches_zod() {
        assert_eq!(
            validate_update_traits_body(Some(&json!({}))).unwrap_err(),
            json!({ "formErrors": [], "fieldErrors": { "traits": ["Required"] } })
        );
        assert_eq!(
            validate_update_traits_body(Some(&json!("text"))).unwrap_err(),
            json!({ "formErrors": ["Expected object, received string"], "fieldErrors": {} })
        );
        assert!(validate_update_traits_body(Some(&json!({ "traits": {} }))).is_ok());
    }

    #[test]
    fn delete_condition_covers_linked_devices() {
        assert!(USER_CONDITION.contains("user_id IN ({deviceIds:Array(String)}) AND identified_user_id = ''"));
        assert_eq!(format_query_param(&QueryParam::Array(vec!["a'b".into(), "c".into()]), false, false), "['a\\'b','c']");
    }
}
