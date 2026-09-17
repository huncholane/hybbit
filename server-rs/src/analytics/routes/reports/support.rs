//! What the report handlers share: Fastify's reply and body handling as Node's
//! handlers experience it, the JavaScript semantics of reading untyped request
//! values, and how postgres.js (drizzle's driver here) binds JavaScript values.

use std::{collections::HashMap, sync::OnceLock};

use axum::{
    body::Body,
    extract::RawPathParams,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use serde_json::{Value, json};
use tracing::{debug, error, warn};

use crate::{
    analytics::{
        js::{JsObject, JsValue, json as js_json, number::number_to_string, string::utf16_len},
        utils::analytics_query::AnalyticsClickHouse,
    },
    http,
    state::AppState,
    tracking::{
        body::{BodyHeaders, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_body_with_depth, reject_before_reading},
        json::JsValue as BodyValue,
    },
};

/// Fastify's `maxParamLength` in server/src/index.ts: a longer path parameter
/// matches no route.
const MAX_PARAM_LENGTH: usize = 1500;

/// How deep request bodies are materialised; funnel steps and goal configs are a
/// few levels deep, so anything past this is far outside what the UI sends.
const BODY_KEEP_DEPTH: usize = 1100;

static ANALYTICS_CLICKHOUSE: OnceLock<AnalyticsClickHouse> = OnceLock::new();

/// The analytics ClickHouse client (`clickhouse` in db/clickhouse/client.ts), built
/// once from the configuration so every report query shares one connection pool.
pub fn analytics_clickhouse(state: &AppState) -> Result<&'static AnalyticsClickHouse, reqwest::Error> {
    if let Some(client) = ANALYTICS_CLICKHOUSE.get() {
        return Ok(client);
    }
    let client = AnalyticsClickHouse::new(&state.config.clickhouse)?;
    Ok(ANALYTICS_CLICKHOUSE.get_or_init(|| client))
}

/// A JavaScript exception thrown while building a query or reading a body. Only
/// the message is observable, and only where Fastify's default error handler
/// answers (the handlers' own catch blocks replace it with a fixed body).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct JsError(pub String);

impl JsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// `reply.send(object)`: `JSON.stringify` with Fastify's JSON content type.
pub fn send_json(status: StatusCode, body: &Value) -> Response {
    let text = crate::js_json::stringify(body);
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

/// [`send_json`] for a JavaScript value (undefined members vanish as in `JSON.stringify`).
pub fn send_js(status: StatusCode, body: &JsValue) -> Response {
    let text = js_json::stringify(body).unwrap_or_default();
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

/// `reply.status(status).send({ error })`.
pub fn send_error(status: StatusCode, message: &str) -> Response {
    send_json(status, &json!({ "error": message }))
}

/// Fastify's default error handler for an exception that escaped a handler:
/// `{statusCode, error, message}` (a `TypeError` has no `code`). The `/api`
/// error rewrite then adds `code` and `resolution`.
pub fn uncaught_exception(route: &str, exception: &JsError) -> Response {
    error!(route, err = %exception, "Unhandled exception in route handler");
    send_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({ "statusCode": 500, "error": "Internal Server Error", "message": exception.0 }),
    )
}

/// What Node's logger throws when a handler logs a `ZodError`: `sanitizeError`
/// (lib/logger/logger.ts) copies the non-enumerable `errors` onto an object with
/// `ZodError.prototype`, where `errors` is a getter, and the assignment throws in
/// strict mode. The exception escapes the handler's catch block, so Fastify's
/// default error handler answers instead of the handler's own error body.
pub const ZOD_ERROR_LOG_EXCEPTION: &str = "Cannot set property errors of [object Object] which has only a getter";

/// Whether a failure is a `ZodError` in Node: the filters schema, or
/// `filterParamSchema.parse` inside `getSqlParam`.
pub fn is_zod_error(err: &(dyn std::error::Error + 'static)) -> bool {
    use crate::analytics::utils::{
        get_filter_statement::{FilterStatementError, UnknownParameter},
        query_validation::FiltersError,
    };
    matches!(err.downcast_ref::<FilterStatementError>(), Some(FilterStatementError::Filters(FiltersError::Schema(_))))
        || matches!(err.downcast_ref::<FiltersError>(), Some(FiltersError::Schema(_)))
        || err.downcast_ref::<UnknownParameter>().is_some()
}

/// A handler's catch block that logs the error first (`analyticsRoute`,
/// getFunnel, createGoal, updateGoal): a `ZodError` turns into the logger's
/// exception, anything else into `fallback`.
pub fn caught(route: &str, err: &(dyn std::error::Error + 'static), fallback: impl FnOnce() -> Response) -> Response {
    if is_zod_error(err) {
        warn!(route, err = %err, "Logging a ZodError throws in Node; answering with its exception");
        return uncaught_exception(route, &JsError::new(ZOD_ERROR_LOG_EXCEPTION));
    }
    fallback()
}

/// `analyticsRoute`'s catch block.
pub fn analytics_failure(label: &str, err: &(dyn std::error::Error + 'static)) -> Response {
    caught(label, err, || crate::analytics::utils::analytics_query::analytics_route_failure(label, err))
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

/// Every `%` starts a two-digit hex escape (`decodeURI` throws otherwise).
fn valid_percent_escapes(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if !(bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit) && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)) {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

/// A body value from the Fastify-compatible parser, as the analytics layer's
/// JavaScript value. Containers deeper than the kept depth were validated but not
/// materialised; they read as empty containers.
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

/// `request.body` for a route registered under `/api`: Fastify's default
/// `application/json` and `text/plain` parsers with the 10 MB `bodyLimit`, run
/// before any preHandler. `Undefined` when the request carried no body.
pub async fn read_body(headers: &HeaderMap, body: Body) -> Result<JsValue, Response> {
    let body_headers = BodyHeaders::from_headers(headers);
    let rejection_response = |rejection: crate::tracking::body::BodyRejection| {
        let mut response = http::json(rejection.status, &rejection.body);
        if rejection.close_connection {
            response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        response
    };
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

/// `value[key]` for a plain data value: own properties of objects, nothing on the
/// primitives and arrays (none of the keys handlers read live on their
/// prototypes), and V8's TypeError for `null` and `undefined`.
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

/// `value.length` (TypeError for null and undefined).
pub fn length(value: &JsValue) -> Result<JsValue, JsError> {
    match value {
        JsValue::Array(items) => Ok(JsValue::Number(items.len() as f64)),
        JsValue::String(text) => Ok(JsValue::Number(utf16_len(text) as f64)),
        other => property(other, "length"),
    }
}

/// The abstract relational comparison `left < right` for the operand kinds the
/// handlers compare (`steps.length < 2`, `stepNumber > steps.length`).
pub fn less_than(left: &JsValue, right: &JsValue) -> bool {
    if let (JsValue::String(a), JsValue::String(b)) = (left, right) {
        let a: Vec<u16> = a.encode_utf16().collect();
        let b: Vec<u16> = b.encode_utf16().collect();
        return a < b;
    }
    let (a, b) = (to_primitive_number(left), to_primitive_number(right));
    !a.is_nan() && !b.is_nan() && a < b
}

/// `ToNumber(ToPrimitive(value))` for data values.
fn to_primitive_number(value: &JsValue) -> f64 {
    match value {
        JsValue::Object(_) => f64::NAN,
        other => other.to_number(),
    }
}

/// The text postgres.js sends for a request value bound without a column type:
/// `inferType` types booleans (and arrays whose first element, followed down
/// nested arrays, is a boolean) as `bool`, which no integer comparison accepts
/// (`None`); everything else goes as `String(value)` for Postgres to parse.
pub fn postgres_js_text(value: &JsValue) -> Option<String> {
    let mut first = value;
    while let JsValue::Array(items) = first {
        match items.first() {
            Some(item) => first = item,
            None => break,
        }
    }
    (!matches!(first, JsValue::Bool(_))).then(|| value.to_js_string())
}

/// How postgres.js sends a JavaScript number bound to an `integer` column
/// (`String(value)`), and whether Postgres accepts that text: `None` means the
/// statement fails (`NaN`, fractions, exponents, out of range) and the handler's
/// error path answers.
pub fn pg_int4(value: f64) -> Option<i32> {
    let text = number_to_string(value);
    text.parse::<i32>().ok()
}

/// [`pg_int4`] for a `bigint` parameter (`LIMIT`/`OFFSET`).
pub fn pg_int8(value: f64) -> Option<i64> {
    number_to_string(value).parse::<i64>().ok()
}

/// A value read off `Object.prototype` by a lookup table keyed with request input
/// (`TimeBucketToFn[bucket]`, `BOT_LAYER_COLUMNS[layer]`), as a template literal
/// prints it. Such a lookup is truthy, so Node goes on to build SQL around it.
pub fn object_prototype_text(key: &str) -> Option<&'static str> {
    Some(match key {
        "constructor" => "function Object() { [native code] }",
        "__defineGetter__" => "function __defineGetter__() { [native code] }",
        "__defineSetter__" => "function __defineSetter__() { [native code] }",
        "hasOwnProperty" => "function hasOwnProperty() { [native code] }",
        "__lookupGetter__" => "function __lookupGetter__() { [native code] }",
        "__lookupSetter__" => "function __lookupSetter__() { [native code] }",
        "isPrototypeOf" => "function isPrototypeOf() { [native code] }",
        "propertyIsEnumerable" => "function propertyIsEnumerable() { [native code] }",
        "toString" => "function toString() { [native code] }",
        "valueOf" => "function valueOf() { [native code] }",
        "__proto__" => "[object Object]",
        "toLocaleString" => "function toLocaleString() { [native code] }",
        _ => return None,
    })
}

/// Fills `${name}` slots in one pass, as a template literal interpolates:
/// substituted text is never scanned again, so request values that happen to
/// contain `${...}` stay literal.
pub fn template(text: &str, slots: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(text.len() + slots.iter().map(|(_, value)| value.len()).sum::<usize>());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match slots.iter().find(|(slot, _)| *slot == name) {
                    Some((_, value)) => out.push_str(value),
                    None => {
                        debug_assert!(false, "template slot {name} has no value");
                        out.push_str(&rest[start..start + 2 + end + 1]);
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_slots_are_filled_once() {
        assert_eq!(template("a ${x} b ${y}", &[("x", "${y}"), ("y", "2")]), "a ${y} b 2");
        assert_eq!(template("no slots", &[]), "no slots");
    }

    #[test]
    fn postgres_integer_text() {
        assert_eq!(pg_int4(12.0), Some(12));
        assert_eq!(pg_int4(-0.0), Some(0));
        assert_eq!(pg_int4(1.5), None);
        assert_eq!(pg_int4(f64::NAN), None);
        assert_eq!(pg_int4(2_147_483_648.0), None);
        assert_eq!(pg_int4(1e21), None);
        assert_eq!(pg_int8(1e20), None);
        assert_eq!(pg_int8(9e15), Some(9_000_000_000_000_000));
    }

    #[test]
    fn postgres_js_parameter_text() {
        use crate::analytics::js::json::parse;
        let text = |json: &str| postgres_js_text(&parse(json).unwrap());
        assert_eq!(text("[3]").as_deref(), Some("3"));
        assert_eq!(text("[[3]]").as_deref(), Some("3"));
        assert_eq!(text("[3,4]").as_deref(), Some("3,4"));
        assert_eq!(text("[null]").as_deref(), Some(""));
        assert_eq!(text(r#"" 7""#).as_deref(), Some(" 7"));
        assert_eq!(text(r#"{"a":1}"#).as_deref(), Some("[object Object]"));
        assert_eq!(text("true"), None);
        assert_eq!(text("[[true], 1]"), None);
    }

    #[test]
    fn property_reads_follow_javascript() {
        let object = JsValue::Object([("type".to_string(), JsValue::from("page"))].into_iter().collect());
        assert_eq!(property(&object, "type").unwrap(), JsValue::from("page"));
        assert_eq!(property(&object, "value").unwrap(), JsValue::Undefined);
        assert_eq!(property(&JsValue::from("abc"), "type").unwrap(), JsValue::Undefined);
        assert_eq!(property(&JsValue::Null, "type").unwrap_err().0, "Cannot read properties of null (reading 'type')");
        assert_eq!(length(&JsValue::from("ab\u{1F600}")).unwrap(), JsValue::Number(4.0));
        assert_eq!(length(&JsValue::Number(5.0)).unwrap(), JsValue::Undefined);
        assert!(less_than(&JsValue::Number(1.0), &JsValue::Number(2.0)));
        assert!(!less_than(&JsValue::Undefined, &JsValue::Number(2.0)));
    }

    #[test]
    fn percent_escapes() {
        assert!(valid_percent_escapes("a%20b"));
        assert!(!valid_percent_escapes("a%2"));
        assert!(!valid_percent_escapes("%zz"));
    }
}
