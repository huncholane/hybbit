//! Plumbing shared by the people routes: path parameters the way find-my-way
//! hands them to Fastify, JSON bodies written with `JSON.stringify`, the
//! analytics ClickHouse client, JavaScript coercions the handlers lean on, and
//! Fastify's body parsing for the three write routes.

use std::sync::OnceLock;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use serde_json::{Map, Value, json};
use tracing::{error, warn};

use crate::{
    analytics::{
        js::{
            JsValue,
            number::{number_to_string, parse_int_10},
            string::{is_js_space_char, utf16_len},
        },
        utils::{
            analytics_query::{AnalyticsClickHouse, AnalyticsQueryError, analytics_route_failure},
            get_filter_statement::FilterStatementError,
            query_validation::FiltersError,
            time_window::RangeError,
        },
    },
    http,
    state::AppState,
    tracking::body::{
        BodyHeaders, BodyRejection, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_body_with_depth, reject_before_reading,
    },
};

/// `maxParamLength` in server/src/index.ts: find-my-way refuses to match a longer
/// parameter, so the request falls through to the 404 handler.
pub const MAX_PARAM_LENGTH: usize = 1500;

/// JSON bodies read by the write routes keep every level (traits are stored whole).
const WRITE_BODY_KEEP_DEPTH: usize = 1100;

static ANALYTICS_CLICKHOUSE: OnceLock<AnalyticsClickHouse> = OnceLock::new();

/// The analytics ClickHouse client (`clickhouse` in server/src/db/clickhouse/client.ts),
/// built once from the service configuration.
pub fn clickhouse(state: &AppState) -> &'static AnalyticsClickHouse {
    ANALYTICS_CLICKHOUSE.get_or_init(|| {
        AnalyticsClickHouse::new(&state.config.clickhouse).expect("building the analytics ClickHouse client")
    })
}

/// `reply.send(object)`: `JSON.stringify` of the payload with Fastify's JSON
/// content type. Numbers print as JavaScript prints them.
pub fn send_json(status: StatusCode, body: &Value) -> Response {
    let mut response = Response::new(Body::from(crate::js_json::stringify(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

/// `res.send({ ... })` with a 200.
pub fn ok(body: Value) -> Response {
    send_json(StatusCode::OK, &body)
}

/// `res.status(400).send({ error })`.
pub fn bad_request(message: &str) -> Response {
    http::json(StatusCode::BAD_REQUEST, &json!({ "error": message }))
}

/// Why a query could not be built: a thrown filter or time error.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error(transparent)]
    Filters(#[from] FilterStatementError),
    #[error(transparent)]
    Time(#[from] RangeError),
}

impl BuildError {
    /// A `ZodError` from `validateFilters` (as opposed to "Invalid JSON format",
    /// a bad regex or a non-numeric comparison, which are plain Errors).
    pub fn is_zod_error(&self) -> bool {
        matches!(self, BuildError::Filters(FilterStatementError::Filters(FiltersError::Schema(_))))
    }
}

/// Anything a people handler's try block can fail with.
#[derive(Debug, thiserror::Error)]
pub enum RouteFailure {
    #[error(transparent)]
    Build(#[from] BuildError),
    #[error(transparent)]
    Query(#[from] AnalyticsQueryError),
    #[error(transparent)]
    Handler(#[from] HandlerError),
    #[error(transparent)]
    Postgres(#[from] sqlx::Error),
}

impl RouteFailure {
    pub fn is_zod_error(&self) -> bool {
        matches!(self, RouteFailure::Build(build) if build.is_zod_error())
    }
}

/// What Node's logger throws when a catch block logs a `ZodError` at error level:
/// `sanitizeError` copies the error onto `Object.create(ZodError.prototype)` and
/// assigning `errors` hits the prototype's getter-only accessor. The throw escapes
/// the catch block, so Fastify answers with it instead of the handler's own 500.
pub const ZOD_LOG_TYPE_ERROR: &str = "Cannot set property errors of [object Object] which has only a getter";

/// `analyticsRoute`'s catch: 500 `{ error: "Failed to fetch <label>" }`, except for
/// a `ZodError`, whose logging throws (see [`ZOD_LOG_TYPE_ERROR`]).
pub fn route_failure(label: &str, failure: impl Into<RouteFailure>) -> Response {
    let failure = failure.into();
    if failure.is_zod_error() {
        warn!(label, error = %failure, "Filters failed schema validation; Node's error log throws here");
        return uncaught_error(ZOD_LOG_TYPE_ERROR);
    }
    match &failure {
        RouteFailure::Query(query_error) => analytics_route_failure(label, query_error),
        other => analytics_route_failure(label, other),
    }
}

/// A handler step that failed with something other than a ClickHouse error
/// (a filter that does not validate, a Postgres error, a JavaScript TypeError),
/// carrying the message Node would log and, for uncaught throws, send.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct HandlerError(pub String);

impl HandlerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Fastify's default error handler for an error thrown outside any try/catch:
/// 500 with the error's message (the /api rewrite adds `code` and `resolution`).
pub fn uncaught_error(message: &str) -> Response {
    error!(error = message, "Unhandled route error");
    http::json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({ "statusCode": 500, "error": "Internal Server Error", "message": message }),
    )
}

/// The value `req.query[name]` holds, `undefined` when absent.
pub fn query_value<'a>(query: &'a crate::analytics::js::JsObject, name: &str) -> &'a JsValue {
    query.get_or_undefined(name)
}

/// `const { name = fallback } = req.query`: the default only replaces `undefined`.
pub fn with_default(value: &JsValue, fallback: JsValue) -> JsValue {
    if value.is_undefined() { fallback } else { value.clone() }
}

/// `parseInt(value, 10)` on any value (`String(value)` first).
pub fn parse_int_radix_10(value: &JsValue) -> f64 {
    parse_int_10(&value.to_js_string())
}

/// `parseInt(value)` without a radix: a `0x` prefix after the sign switches to
/// hexadecimal, anything else parses as decimal.
pub fn parse_int_auto(value: &JsValue) -> f64 {
    let text = value.to_js_string();
    let trimmed = text.trim_start_matches(is_js_space_char);
    let (negative, unsigned) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let Some(hex) = unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")) else {
        return parse_int_10(&text);
    };
    let digits: Vec<u32> = hex.chars().map_while(|c| c.to_digit(16)).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    // Exact up to 2^53, correctly rounded beyond through the u128 accumulator for
    // the lengths a query string can plausibly carry
    let value = if digits.len() <= 32 {
        digits.iter().fold(0u128, |acc, digit| acc * 16 + u128::from(*digit)) as f64
    } else {
        digits.iter().fold(0f64, |acc, digit| acc * 16.0 + f64::from(*digit))
    };
    if negative { -value } else { value }
}

/// `JSON.stringify` of a JavaScript number as a JSON value (NaN and the
/// infinities become null).
pub fn number_value(number: f64) -> Value {
    crate::analytics::js::value::number_to_serde(number)
}

/// `Number(siteId)` for a site id that passed the guard, as the integer Postgres
/// receives. postgres.js sends `String(number)` and Postgres parses an integer
/// out of it, so anything that is not a whole number in range fails there.
pub fn pg_integer(number: f64) -> Result<i32, HandlerError> {
    if number.fract() == 0.0 && number >= f64::from(i32::MIN) && number <= f64::from(i32::MAX) {
        Ok(number as i32)
    } else {
        Err(HandlerError::new(format!("invalid input syntax for type integer: \"{}\"", number_to_string(number))))
    }
}

/// A `LIMIT`/`OFFSET` value postgres.js sends as `String(number)`: Postgres takes
/// a non-negative bigint and rejects anything else.
pub fn pg_row_count(number: f64, clause: &str) -> Result<i64, HandlerError> {
    let text = number_to_string(number);
    match text.parse::<i64>() {
        Ok(count) if count >= 0 => Ok(count),
        Ok(_) => Err(HandlerError::new(format!("{clause} must not be negative"))),
        Err(_) => Err(HandlerError::new(format!("invalid input syntax for type bigint: \"{text}\""))),
    }
}

/// The names `Object.prototype` answers for, which a plain lookup table keyed by
/// request input (`TimeBucketToFn[bucket]`) treats as present.
pub fn is_object_prototype_key(key: &str) -> bool {
    matches!(
        key,
        "constructor"
            | "__defineGetter__"
            | "__defineSetter__"
            | "hasOwnProperty"
            | "__lookupGetter__"
            | "__lookupSetter__"
            | "isPrototypeOf"
            | "propertyIsEnumerable"
            | "toString"
            | "valueOf"
            | "__proto__"
            | "toLocaleString"
    )
}

/// Fills a copy of a Node template literal: every `${name}` is replaced by its
/// value in one pass (inserted text is never rescanned), so the SQL stays
/// byte-identical to the TypeScript source it was pasted from.
pub fn render(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').expect("unterminated template placeholder");
        let name = &after[..end];
        let value = values
            .iter()
            .find(|(key, _)| *key == name)
            .unwrap_or_else(|| panic!("template placeholder {name} has no value"))
            .1;
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// A JSON object from `(key, value)` pairs, in order.
pub fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(entries.into_iter().map(|(key, value)| (key.to_string(), value)).collect::<Map<String, Value>>())
}

// ---------------------------------------------------------------------------
// Path parameters

/// `decodeComponentChar`: the characters `decodeURI` leaves encoded.
fn decode_component_char(high: u8, low: u8) -> Option<char> {
    match (high, low) {
        (b'2', b'5') => Some('%'),
        (b'2', b'3') => Some('#'),
        (b'2', b'4') => Some('$'),
        (b'2', b'6') => Some('&'),
        (b'2', b'B' | b'b') => Some('+'),
        (b'2', b'C' | b'c') => Some(','),
        (b'2', b'F' | b'f') => Some('/'),
        (b'3', b'A' | b'a') => Some(':'),
        (b'3', b'B' | b'b') => Some(';'),
        (b'3', b'D' | b'd') => Some('='),
        (b'3', b'F' | b'f') => Some('?'),
        (b'4', b'0') => Some('@'),
        _ => None,
    }
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
    let digit = |b: u8| (b as char).to_digit(16);
    Some((digit(high)? * 16 + digit(low)?) as u8)
}

/// JavaScript `decodeURI`: every escape decodes except those of `;/?:@&=+$,#`;
/// a malformed escape or invalid UTF-8 throws.
fn decode_uri(input: &str) -> Option<String> {
    const RESERVED: &[u8] = b";/?:@&=+$,#";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            let next = input[index..].find('%').map_or(bytes.len(), |offset| index + offset);
            out.push_str(&input[index..next]);
            index = next;
            continue;
        }
        let first = hex_byte(*bytes.get(index + 1)?, *bytes.get(index + 2)?)?;
        if first < 0x80 {
            if RESERVED.contains(&first) {
                out.push_str(&input[index..index + 3]);
            } else {
                out.push(first as char);
            }
            index += 3;
            continue;
        }
        let length = match first {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => return None,
        };
        let mut sequence = vec![first];
        index += 3;
        for _ in 1..length {
            if bytes.get(index) != Some(&b'%') {
                return None;
            }
            let byte = hex_byte(*bytes.get(index + 1)?, *bytes.get(index + 2)?)?;
            if byte & 0xC0 != 0x80 {
                return None;
            }
            sequence.push(byte);
            index += 3;
        }
        out.push_str(std::str::from_utf8(&sequence).ok()?);
    }
    Some(out)
}

/// find-my-way's `safeDecodeURI`: whether the path needs `decodeURI`, and whether
/// parameters need their reserved escapes decoded. `%25` is re-escaped first so
/// it survives `decodeURI` as `%25`.
/// `None` when `decodeURI` throws (Fastify's `onBadUrl` then answers).
fn safe_decode_uri(path: &str) -> Option<(String, bool)> {
    let bytes = path.as_bytes();
    let mut should_decode = false;
    let mut should_decode_param = false;
    let mut rebuilt = String::with_capacity(path.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' && index > 0 {
            let high = bytes.get(index + 1).copied().unwrap_or(0);
            let low = bytes.get(index + 2).copied().unwrap_or(0);
            if decode_component_char(high, low).is_none() {
                should_decode = true;
            } else {
                should_decode_param = true;
                if high == b'2' && low == b'5' {
                    should_decode = true;
                    rebuilt.push_str("%2525");
                } else {
                    rebuilt.push_str(&path[index..index + 3]);
                }
                index += 3;
                continue;
            }
        }
        let next = path[index + 1..].find('%').map_or(bytes.len(), |offset| index + 1 + offset);
        rebuilt.push_str(&path[index..next]);
        index = next;
    }
    let decoded = if should_decode { decode_uri(&rebuilt)? } else { rebuilt };
    Some((decoded, should_decode_param))
}

/// `safeDecodeURIComponent` over the reserved escapes `decodeURI` kept.
fn safe_decode_uri_component(component: &str) -> String {
    let Some(start) = component.find('%') else {
        return component.to_string();
    };
    let bytes = component.as_bytes();
    let mut decoded = String::new();
    let mut last = start;
    let mut index = start;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes.get(index + 1).copied().unwrap_or(0);
            let low = bytes.get(index + 2).copied().unwrap_or(0);
            decoded.push_str(&component[last..index]);
            match decode_component_char(high, low) {
                Some(character) => decoded.push(character),
                // `'' + null`
                None => decoded.push_str("null"),
            }
            last = (index + 3).min(bytes.len());
            index += 3;
            continue;
        }
        index += 1;
    }
    format!("{}{}{}", &component[..start], decoded, &component[last..])
}

/// Fastify's `onBadUrl` response, written straight to the socket in Node (no
/// hooks run, so no CORS headers and no error-body rewrite). The message quotes
/// the request URL, query string included.
fn bad_url(url: &str) -> Response {
    let body = format!(
        "{{\"error\":\"Bad Request\",\"code\":\"FST_ERR_BAD_URL\",\"message\":{},\"statusCode\":400}}",
        crate::js_json::stringify(&Value::String(format!("'{url}' is not a valid url component")))
    );
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response.extensions_mut().insert(http::RawFrameworkResponse);
    response
}

/// The route's path parameters at the given segment positions, decoded the way
/// find-my-way decodes them (`/api/sites/:siteId/...` has `siteId` at 3).
pub async fn path_params(method: &Method, uri: &Uri, positions: &[usize]) -> Result<Vec<String>, Response> {
    let raw_path = uri.path();
    let Some((decoded, decode_params)) = safe_decode_uri(raw_path) else {
        warn!(path = raw_path, "Request path is not a valid URL component");
        let url = uri.path_and_query().map_or(raw_path, |value| value.as_str());
        return Err(bad_url(url));
    };
    let segments: Vec<&str> = decoded.split('/').collect();
    let mut params = Vec::with_capacity(positions.len());
    for &position in positions {
        let raw = segments.get(position).copied().unwrap_or_default();
        let param = if decode_params { safe_decode_uri_component(raw) } else { raw.to_string() };
        if utf16_len(&param) > MAX_PARAM_LENGTH {
            warn!(position, length = utf16_len(&param), "Path parameter exceeds maxParamLength");
            return Err(http::errors::not_found(method.clone(), uri.clone()).await);
        }
        params.push(param);
    }
    Ok(params)
}

// ---------------------------------------------------------------------------
// Request bodies

fn rejection_response(rejection: BodyRejection) -> Response {
    let mut response = http::json(rejection.status, &rejection.body);
    if rejection.close_connection {
        response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Fastify's content-type parsing before the preHandlers run: `Ok(None)` is an
/// `undefined` body, otherwise the parsed JSON (or text/plain string) as serde
/// JSON in JavaScript property order.
pub async fn read_body(headers: &HeaderMap, body: Body) -> Result<Option<Value>, Response> {
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
    parse_body_with_depth(&body_headers, &raw, WRITE_BODY_KEEP_DEPTH)
        .map(|parsed| parsed.map(|value| value.to_serde()))
        .map_err(rejection_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_paths_like_find_my_way() {
        let (path, params) = safe_decode_uri("/api/sites/1/users/a%2Fb").unwrap();
        assert_eq!(path, "/api/sites/1/users/a%2Fb");
        assert!(params);
        assert_eq!(safe_decode_uri_component("a%2Fb"), "a/b");

        let (path, params) = safe_decode_uri("/api/sites/1/users/caf%C3%A9").unwrap();
        assert_eq!(path, "/api/sites/1/users/café");
        assert!(!params);

        let (path, params) = safe_decode_uri("/api/sites/1/users/100%25").unwrap();
        assert_eq!(path, "/api/sites/1/users/100%25");
        assert!(params);
        assert_eq!(safe_decode_uri_component("100%25"), "100%");

        assert!(safe_decode_uri("/api/sites/1/users/%zz").is_none());
        assert!(safe_decode_uri("/api/sites/1/users/%E0%A4").is_none());
        assert!(safe_decode_uri("/api/sites/1/users/%").is_none());
        let (path, _) = safe_decode_uri("/api/sites/1/users/%20x").unwrap();
        assert_eq!(path, "/api/sites/1/users/ x");
    }

    #[test]
    fn parse_int_without_radix() {
        assert_eq!(parse_int_auto(&"0x10".into()), 16.0);
        assert_eq!(parse_int_auto(&" -0X1f".into()), -31.0);
        assert!(parse_int_auto(&"0x".into()).is_nan());
        assert_eq!(parse_int_auto(&"12abc".into()), 12.0);
        assert_eq!(parse_int_auto(&"1e3".into()), 1.0);
        assert!(parse_int_auto(&"abc".into()).is_nan());
        assert_eq!(parse_int_auto(&JsValue::Array(vec!["5".into(), "6".into()])), 5.0);
    }

    #[test]
    fn postgres_counts() {
        assert_eq!(pg_row_count(10.0, "LIMIT").unwrap(), 10);
        assert!(pg_row_count(-1.0, "LIMIT").is_err());
        assert!(pg_row_count(f64::NAN, "LIMIT").is_err());
        assert!(pg_row_count(1e21, "LIMIT").is_err());
        assert_eq!(pg_row_count(-0.0, "OFFSET").unwrap(), 0);
    }
}
