//! Request plumbing the site-settings routes share.
//!
//! Path decoding, `reply.send` of a plain object and Fastify's default body
//! parsing come from `analytics::routes::people::common`, which already ports
//! find-my-way 9.3's parameter decoding, `maxParamLength: 1500` and the two
//! default content-type parsers; only what those do not cover lives here: the
//! 50 MB body limit `POST …/imports/:importId/events` is registered with, the
//! zod 3.25 pieces `updateSiteConfig` and the private-link body need, and the
//! `Number`/`z.coerce.number` coercions the handlers apply to `:siteId`.

use axum::{body::Body, http::HeaderMap, http::HeaderValue, http::StatusCode, http::header, response::Response};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use tracing::warn;

use crate::{
    analytics::{
        js::{number::number_to_string, string::utf16_len},
        routes::people::common::send_json,
    },
    http,
    tracking::body::{BodyHeaders, BodyRejection, body_too_large, parse_body_with_limit, reject_before_reading_with_limit},
};

/// Fastify's server-wide `bodyLimit` (server/src/index.ts).
pub const DEFAULT_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// `bodyLimit: 50 * 1024 * 1024` on `/sites/:siteId/imports/:importId/events`.
pub const IMPORT_BODY_LIMIT: usize = 50 * 1024 * 1024;

/// How deep a parsed body is kept. The deepest thing any schema here reads is an
/// import event's string field (body → events → event → value), and
/// `updateSiteConfig` only looks one level into its arrays; 8 leaves headroom and
/// keeps a hostile 50 MB body from recursing without bound.
const BODY_KEEP_DEPTH: usize = 8;

/// `reply.status(status).send(value)`: `JSON.stringify` with Fastify's JSON content
/// type, numbers spelled as JavaScript spells them.
pub fn send(status: StatusCode, value: &Value) -> Response {
    send_json(status, value)
}

/// `reply.status(status).send({ error })`
pub fn error(status: StatusCode, message: &str) -> Response {
    send(status, &json!({ "error": message }))
}

/// `reply.status(status).send({ success: false, error })`
pub fn failure(status: StatusCode, message: &str) -> Response {
    send(status, &json!({ "success": false, "error": message }))
}

/// `reply.send()` with no payload: Fastify writes an empty body and no content
/// type (`getSiteImport`'s success answers and `deleteSiteImport` do this).
pub fn empty_ok() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}

/// A JavaScript object literal from ordered fields.
pub fn object(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(fields.into_iter().map(|(name, value)| (name.to_string(), value)).collect::<Map<String, Value>>())
}

fn rejection_response(rejection: BodyRejection) -> Response {
    let mut response = http::json(rejection.status, &rejection.body);
    if rejection.close_connection {
        response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// `request.body` with the route's own `bodyLimit`: `Ok(None)` is `undefined`
/// (no body and no content type), otherwise the parsed JSON or text/plain string.
pub async fn read_body_limited(headers: &HeaderMap, body: Body, limit: usize) -> Result<Option<Value>, Response> {
    let body_headers = BodyHeaders::from_headers(headers);
    if let Some(rejection) = reject_before_reading_with_limit(&body_headers, limit) {
        return Err(rejection_response(rejection));
    }
    let raw = match axum::body::to_bytes(body, limit + 1).await {
        Ok(raw) => raw,
        Err(err) => {
            warn!(error = %err, limit, "Request body could not be read within the limit");
            return Err(rejection_response(body_too_large()));
        }
    };
    parse_body_with_limit(&body_headers, &raw, BODY_KEEP_DEPTH, limit)
        .map(|parsed| parsed.map(|value| value.to_serde()))
        .map_err(rejection_response)
}

/// `request.body` at the server-wide limit.
pub async fn read_body(headers: &HeaderMap, body: Body) -> Result<Option<Value>, Response> {
    read_body_limited(headers, body, DEFAULT_BODY_LIMIT).await
}

// ---------------------------------------------------------------------------
// JavaScript coercions on the :siteId parameter

/// `Number(siteId)` for a route parameter: the double JavaScript produces, NaN
/// for anything it cannot read as a number.
pub fn js_number(text: &str) -> f64 {
    let trimmed = crate::analytics::js::string::trim(text);
    if trimmed.is_empty() {
        return 0.0;
    }
    let radix = |prefix: &str, radix: u32| -> Option<f64> {
        let digits = trimmed.strip_prefix(prefix)?;
        if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
            return Some(f64::NAN);
        }
        // Exact below 2^53 and correctly rounded above through the f64 accumulator
        Some(digits.chars().fold(0f64, |acc, digit| acc * f64::from(radix) + f64::from(digit.to_digit(radix).unwrap())))
    };
    for (prefix, base) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(value) = radix(prefix, base) {
            return value;
        }
    }
    match trimmed {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    // JavaScript rejects the "inf"/"nan"/"1_0" spellings Rust's parser accepts
    if trimmed.bytes().any(|b| b == b'_') || trimmed.chars().any(|c| c.is_ascii_alphabetic() && c != 'e' && c != 'E') {
        return f64::NAN;
    }
    trimmed.parse::<f64>().unwrap_or(f64::NAN)
}

/// `Number.isInteger(siteId) && siteId > 0`, the check `updateSiteConfig`,
/// `deleteSite` and `updateSitePrivateLinkConfig` apply to `Number(siteId)`.
pub fn positive_integer(value: f64) -> bool {
    value.is_finite() && value.fract() == 0.0 && value > 0.0
}

/// `z.coerce.number().int().positive()` over a route parameter: `Number(value)`,
/// then integer and positive. Used by usage, imports and the batch endpoint.
pub fn coerce_positive_int(text: &str) -> Option<f64> {
    let value = js_number(text);
    positive_integer(value).then_some(value)
}

/// The integer Postgres receives for a site id that passed those checks. Values
/// past int4 make Postgres throw inside Node's `try`, which surfaces as the
/// handler's own 500; `None` stands for that.
pub fn pg_int(value: f64) -> Option<i32> {
    (value.fract() == 0.0 && value >= f64::from(i32::MIN) && value <= f64::from(i32::MAX)).then_some(value as i32)
}

// ---------------------------------------------------------------------------
// zod 3.25 `safeParse` with `error.flatten()`

/// Issues collected in the order zod reports them, flattened the way
/// `ZodError.flatten()` flattens them: issues with an empty path go to
/// `formErrors`, the rest under the first path segment.
#[derive(Default, Debug)]
pub struct Issues {
    form_errors: Vec<String>,
    field_errors: IndexMap<String, Vec<String>>,
}

impl Issues {
    pub fn form(&mut self, message: impl Into<String>) {
        self.form_errors.push(message.into());
    }

    pub fn field(&mut self, name: &str, message: impl Into<String>) {
        self.field_errors.entry(name.to_string()).or_default().push(message.into());
    }

    pub fn is_empty(&self) -> bool {
        self.form_errors.is_empty() && self.field_errors.is_empty()
    }

    /// `error.flatten()`
    pub fn flatten(&self) -> Value {
        let field_errors: Map<String, Value> =
            self.field_errors.iter().map(|(name, messages)| (name.clone(), json!(messages))).collect();
        json!({ "formErrors": self.form_errors, "fieldErrors": field_errors })
    }
}

/// zod's `ZodParsedType` for a JSON value (`undefined` is a missing key).
pub fn parsed_type(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

/// zod's default `invalid_type` message; a missing value reads "Required".
pub fn invalid_type(expected: &str, received: Option<&Value>) -> String {
    match received {
        None => "Required".to_string(),
        Some(_) => format!("Expected {expected}, received {}", parsed_type(received)),
    }
}

/// `z.string().min(n)` / `.max(n)` messages, counted in UTF-16 code units like
/// JavaScript's `String.length`.
pub fn string_too_small(minimum: usize) -> String {
    format!("String must contain at least {} character(s)", number_to_string(minimum as f64))
}

pub fn string_too_big(maximum: usize) -> String {
    format!("String must contain at most {} character(s)", number_to_string(maximum as f64))
}

pub fn array_too_big(maximum: usize) -> String {
    format!("Array must contain at most {} element(s)", number_to_string(maximum as f64))
}

pub fn string_length(text: &str) -> usize {
    utf16_len(text)
}

/// `z.enum(options)`'s `invalid_enum_value` message.
pub fn invalid_enum_value(options: &[&str], received: &str) -> String {
    let joined = options.iter().map(|option| format!("'{option}'")).collect::<Vec<_>>().join(" | ");
    format!("Invalid enum value. Expected {joined}, received '{received}'")
}

/// `z.enum(options)`'s `invalid_type` message, whose "expected" is the joined
/// option list rather than a type name.
pub fn enum_invalid_type(options: &[&str], received: Option<&Value>) -> String {
    let joined = options.iter().map(|option| format!("'{option}'")).collect::<Vec<_>>().join(" | ");
    invalid_type(&joined, received)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_coercion_follows_javascript() {
        assert_eq!(js_number("65200"), 65200.0);
        assert_eq!(js_number(" 12 "), 12.0);
        assert_eq!(js_number(""), 0.0);
        assert_eq!(js_number("0x1A"), 26.0);
        assert_eq!(js_number("1e3"), 1000.0);
        assert!(js_number("abc").is_nan());
        assert!(js_number("inf").is_nan());
        assert!(js_number("1_0").is_nan());
        assert_eq!(js_number("Infinity"), f64::INFINITY);
        assert_eq!(js_number("1.5"), 1.5);
        assert!(js_number("0x").is_nan());
    }

    #[test]
    fn positive_integer_matches_number_is_integer() {
        assert!(positive_integer(1.0));
        assert!(!positive_integer(0.0));
        assert!(!positive_integer(-1.0));
        assert!(!positive_integer(1.5));
        assert!(!positive_integer(f64::NAN));
        assert!(!positive_integer(f64::INFINITY));
    }

    #[test]
    fn flatten_matches_zod() {
        let mut issues = Issues::default();
        issues.field("name", string_too_small(1));
        issues.field("name", string_too_big(255));
        issues.form(invalid_type("object", None));
        assert_eq!(
            issues.flatten(),
            json!({
                "formErrors": ["Required"],
                "fieldErrors": { "name": ["String must contain at least 1 character(s)", "String must contain at most 255 character(s)"] }
            })
        );
    }
}
