//! What the admin panel, feature flag and experiment handlers share: Fastify's
//! reply and body handling as Node's handlers experience it, find-my-way's
//! parameter decoding and route completion, the `clickhouse` client from
//! server/src/db/clickhouse/client.ts, and how postgres.js binds JavaScript
//! numbers to integer columns.
//!
//! The report and workspace groups carry their own copies of these; keeping one
//! here rather than widening theirs leaves each ported group free to move.

use std::{collections::HashMap, sync::OnceLock};

use axum::{
    Router,
    body::Body,
    extract::RawPathParams,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
    routing::{MethodFilter, MethodRouter},
};
use serde_json::{Value, json};
use tracing::{debug, error, warn};

use crate::{
    analytics::{
        js::{JsObject, JsValue, json as js_json, string::utf16_len},
        utils::analytics_query::{AnalyticsClickHouse, ClickHouseFailure, QuerySpec},
    },
    http,
    state::AppState,
    tracking::{
        body::{BodyHeaders, BodyRejection, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_body_with_depth, reject_before_reading},
        json::JsValue as BodyValue,
    },
};

/// `maxParamLength` in server/src/index.ts: a longer path parameter matches no route.
const MAX_PARAM_LENGTH: usize = 1500;

/// How deep a request body is materialised. The deepest thing any schema here
/// looks at is a flag payload nested inside a condition set variant; past this a
/// value's type is all that can matter, and zod never prints a deeper value.
const BODY_KEEP_DEPTH: usize = 64;

// ---------------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------------

/// `reply.send(object)`: `JSON.stringify` with Fastify's JSON content type.
pub fn send_js(status: StatusCode, body: &JsValue) -> Response {
    let text = js_json::stringify(body).unwrap_or_default();
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

/// [`send_js`] for a serde value, spelled the way `JSON.stringify` spells numbers.
pub fn send_json(status: StatusCode, body: &Value) -> Response {
    http::js_json(status, body)
}

/// `reply.status(status).send({ error })`.
pub fn send_error(status: StatusCode, message: &str) -> Response {
    send_json(status, &json!({ "error": message }))
}

/// `reply.status(status).send({ error, details })`.
pub fn send_error_details(status: StatusCode, message: &str, details: Value) -> Response {
    send_json(status, &json!({ "error": message, "details": details }))
}

/// Fastify's default error handler for an exception that escaped a handler:
/// `{statusCode, code, error, message}`, with `code` present only when the thrown
/// value carries one. The `/api` error rewrite then appends `resolution`.
pub fn uncaught_exception(route: &str, code: Option<&str>, message: &str) -> Response {
    error!(route, code = code.unwrap_or(""), message, "Unhandled exception in an admin route handler");
    let mut body = serde_json::Map::new();
    body.insert("statusCode".into(), json!(500));
    if let Some(code) = code {
        body.insert("code".into(), Value::String(code.to_string()));
    }
    body.insert("error".into(), Value::String("Internal Server Error".into()));
    body.insert("message".into(), Value::String(message.to_string()));
    send_json(StatusCode::INTERNAL_SERVER_ERROR, &Value::Object(body))
}

/// A ClickHouse failure that escaped a handler with no catch block, as Fastify
/// answers it: `@clickhouse/client` throws a `ClickHouseError` whose `code` is the
/// server's numeric code as text and whose `message` is the parsed exception.
pub fn clickhouse_exception(route: &str, err: &ClickHouseFailure) -> Response {
    let code = match err {
        ClickHouseFailure::Server { info, .. } => info.code.clone(),
        _ => None,
    };
    uncaught_exception(route, code.as_deref(), &err.message())
}

/// A JavaScript object literal from ordered fields.
pub fn object(fields: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(fields.into_iter().map(|(name, value)| (name.to_string(), value)).collect())
}

/// `value ?? null` for an optional string column.
pub fn nullable_text(value: Option<String>) -> JsValue {
    value.map_or(JsValue::Null, JsValue::String)
}

/// A JavaScript exception thrown while building a query from stored data. Only
/// the message is observable, and only where Fastify's default error handler
/// answers.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct JsError(pub String);

impl JsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// `value[key]` for a plain data value: own properties of objects, nothing on the
/// primitives and arrays, and V8's TypeError for `null` and `undefined`.
pub fn property(value: &JsValue, key: &str) -> Result<JsValue, JsError> {
    match value {
        JsValue::Undefined | JsValue::Null => Err(JsError::new(format!(
            "Cannot read properties of {} (reading '{key}')",
            if value.is_undefined() { "undefined" } else { "null" }
        ))),
        JsValue::Object(object) => Ok(object.get_or_undefined(key).clone()),
        _ => Ok(JsValue::Undefined),
    }
}

// ---------------------------------------------------------------------------------
// ClickHouse
// ---------------------------------------------------------------------------------

static ADMIN_CLICKHOUSE: OnceLock<AnalyticsClickHouse> = OnceLock::new();

/// The `clickhouse` client (server/src/db/clickhouse/client.ts) the admin handlers
/// use directly, built once so every request shares one connection pool. Unlike
/// `runAnalyticsQuery` these calls send no `max_execution_time`, so the requests
/// stay byte-identical to Node's and land in `system.query_log` the same way.
pub fn admin_clickhouse(state: &AppState) -> Result<&'static AnalyticsClickHouse, reqwest::Error> {
    if let Some(client) = ADMIN_CLICKHOUSE.get() {
        return Ok(client);
    }
    let client = AnalyticsClickHouse::new(&state.config.clickhouse)?;
    Ok(ADMIN_CLICKHOUSE.get_or_init(|| client))
}

/// `(await clickhouse.query({ query, format: "JSONEachRow" })).json()`.
pub async fn clickhouse_rows(state: &AppState, query: &str) -> Result<Vec<JsValue>, ClickHouseFailure> {
    let client = admin_clickhouse(state).map_err(ClickHouseFailure::from)?;
    let (query_id, rows) = client.query_json_each_row(&QuerySpec::new(query)).await?;
    debug!(query_id, rows = rows.len(), "admin ClickHouse query finished");
    Ok(rows)
}

/// `Number(row[column])` for a JSONEachRow member Node converts by hand.
pub fn row_number(row: &JsValue, column: &str) -> f64 {
    match row {
        JsValue::Object(object) => object.get_or_undefined(column).to_number(),
        _ => f64::NAN,
    }
}

/// `row[column]` kept as it arrived (Node passes several of these straight through).
pub fn row_value(row: &JsValue, column: &str) -> JsValue {
    match row {
        JsValue::Object(object) => object.get_or_undefined(column).clone(),
        _ => JsValue::Undefined,
    }
}

// ---------------------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------------------

/// A body value from the Fastify-compatible parser as a JavaScript value.
fn body_value(value: BodyValue) -> JsValue {
    match value {
        BodyValue::Null => JsValue::Null,
        BodyValue::Bool(flag) => JsValue::Bool(flag),
        BodyValue::Number(number) => JsValue::Number(number),
        BodyValue::String(text) => JsValue::String(text),
        BodyValue::Array(items) => JsValue::Array(items.into_iter().map(body_value).collect()),
        BodyValue::Object(entries) => {
            let mut object = JsObject::new();
            for (key, item) in entries {
                object.insert(key, body_value(item));
            }
            JsValue::Object(object)
        }
        BodyValue::UnreadArray => JsValue::Array(Vec::new()),
        BodyValue::UnreadObject => JsValue::Object(JsObject::new()),
    }
}

fn rejection_response(rejection: BodyRejection) -> Response {
    let mut response = http::json(rejection.status, &rejection.body);
    if rejection.close_connection {
        response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// `request.body` for a route under `/api`: Fastify's default `application/json`
/// and `text/plain` parsers with the 10 MB `bodyLimit`, run before any preHandler.
/// `Undefined` when the request carried no body.
pub async fn read_body(headers: &HeaderMap, body: Body) -> Result<JsValue, Response> {
    let body_headers = BodyHeaders::from_headers(headers);
    if let Some(rejection) = reject_before_reading(&body_headers) {
        return Err(rejection_response(rejection));
    }
    let raw = match axum::body::to_bytes(body, TRACK_BODY_LIMIT_BYTES + 1).await {
        Ok(raw) => raw,
        Err(err) => {
            warn!(error = %err, "Request body could not be read within the limit");
            return Err(rejection_response(body_too_large()));
        }
    };
    match parse_body_with_depth(&body_headers, &raw, BODY_KEEP_DEPTH) {
        Ok(Some(value)) => Ok(body_value(value)),
        Ok(None) => Ok(JsValue::Undefined),
        Err(rejection) => Err(rejection_response(rejection)),
    }
}

/// Every `%` starts a two-digit hex escape (`decodeURI` throws otherwise).
fn valid_percent_escapes(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if !(bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

/// The request's path parameters as find-my-way hands them to Fastify: percent
/// decoded, with a parameter longer than `maxParamLength` matching no route and a
/// malformed escape answered by the not-found handler.
pub async fn path_params(raw: &RawPathParams, method: &Method, uri: &Uri) -> Result<HashMap<String, String>, Response> {
    let mut params = HashMap::new();
    for (name, value) in raw.iter() {
        if !valid_percent_escapes(value) {
            warn!(param = name, "Path parameter has a malformed percent escape");
            return Err(http::errors::not_found(method.clone(), uri.clone()).await);
        }
        let decoded = match percent_encoding::percent_decode_str(value).decode_utf8() {
            Ok(text) => text.into_owned(),
            Err(_) => {
                warn!(param = name, "Path parameter is not valid percent-encoded UTF-8");
                return Err(http::errors::not_found(method.clone(), uri.clone()).await);
            }
        };
        if utf16_len(&decoded) > MAX_PARAM_LENGTH {
            debug!(param = name, "Path parameter longer than maxParamLength");
            return Err(http::errors::not_found(method.clone(), uri.clone()).await);
        }
        params.insert(name.to_string(), decoded);
    }
    Ok(params)
}

/// The named parameter, or "" when the route pattern left it out.
pub fn param(params: &HashMap<String, String>, name: &str) -> String {
    params.get(name).cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------------
// Postgres binding
// ---------------------------------------------------------------------------------

/// How postgres.js sends a JavaScript number bound to an `integer` column
/// (`String(value)`), and whether Postgres accepts that text: `None` means the
/// statement fails and the handler's error path answers.
pub fn pg_int4(value: f64) -> Option<i32> {
    crate::analytics::js::number::number_to_string(value).parse::<i32>().ok()
}

// ---------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------

/// The same handlers under every combination of empty and non-empty parameters,
/// because find-my-way lets a parameter match an empty segment and axum does not.
pub fn with_empty_params(
    mut router: Router<AppState>,
    pattern: &str,
    handlers: MethodRouter<AppState>,
) -> Router<AppState> {
    let segments: Vec<&str> = pattern.split('/').collect();
    let params: Vec<usize> =
        segments.iter().enumerate().filter(|(_, segment)| segment.starts_with('{')).map(|(index, _)| index).collect();
    for mask in 0..(1usize << params.len()) {
        let path: Vec<&str> = segments
            .iter()
            .enumerate()
            .map(|(index, segment)| match params.iter().position(|param| *param == index) {
                Some(bit) if mask & (1 << bit) != 0 => "",
                _ => segment,
            })
            .collect();
        router = router.route(&path.join("/"), handlers.clone());
    }
    router
}

/// Route every method the path does not register to the 404 handler, because
/// axum's method-not-allowed fallback would add an `Allow` header Node never sends.
pub fn complete(handlers: MethodRouter<AppState>, registered: &[&str]) -> MethodRouter<AppState> {
    let all = [
        ("GET", MethodFilter::GET),
        ("HEAD", MethodFilter::HEAD),
        ("POST", MethodFilter::POST),
        ("PUT", MethodFilter::PUT),
        ("DELETE", MethodFilter::DELETE),
        ("PATCH", MethodFilter::PATCH),
        ("OPTIONS", MethodFilter::OPTIONS),
        ("TRACE", MethodFilter::TRACE),
        ("CONNECT", MethodFilter::CONNECT),
    ];
    // HEAD is answered by the GET handler wherever one is registered
    let answered = |name: &str| registered.contains(&name) || (name == "HEAD" && registered.contains(&"GET"));
    all.into_iter()
        .filter(|(name, _)| !answered(name))
        .fold(handlers, |handlers, (_, filter)| handlers.on(filter, http::errors::not_found))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_integer_text() {
        assert_eq!(pg_int4(12.0), Some(12));
        assert_eq!(pg_int4(1.5), None);
        assert_eq!(pg_int4(f64::NAN), None);
        assert_eq!(pg_int4(2_147_483_648.0), None);
    }

    #[test]
    fn percent_escapes() {
        assert!(valid_percent_escapes("a%20b"));
        assert!(!valid_percent_escapes("a%2"));
        assert!(!valid_percent_escapes("%zz"));
    }
}
