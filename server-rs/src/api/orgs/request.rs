//! Request plumbing shared by the organization, team, member, account and API key
//! routes, ported from the Fastify 5.8.5 machinery around Node's handlers:
//! find-my-way 9.3 parameter decoding with `maxParamLength: 1500`, the default body
//! parsers, and `reply.send` of a plain object.
//!
//! It is a sibling of `analytics::routes::workspace::request` and
//! `analytics::routes::people::common`, which do the same for their groups; each
//! group keeps its own copy so the ports stay independent.

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use serde_json::json;
use tracing::{debug, warn};

use crate::{
    analytics::js::{JsObject, JsValue, json as js, string::utf16_len},
    http,
    tracking::{
        body::{
            BodyHeaders, BodyRejection, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_body_with_depth,
            reject_before_reading,
        },
        json::JsValue as ParsedJson,
    },
};

/// `maxParamLength` in server/src/index.ts
pub const MAX_PARAM_LENGTH: usize = 1500;

/// How deep a parsed body is kept. The deepest shape any handler here looks at is
/// `permissions.<resource>[i]` on API key creation (three levels); below the kept
/// depth only a value's type can matter, which the placeholder containers preserve.
const BODY_KEEP_DEPTH: usize = 16;

/// `reply.send(object)`: `JSON.stringify` with Fastify's JSON content type.
pub fn send(status: StatusCode, value: &JsValue) -> Response {
    let body = js::stringify(value).unwrap_or_default();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

/// `reply.status(status).send(text)`: a string payload is `text/plain`.
pub fn send_text(status: StatusCode, text: &str) -> Response {
    let mut response = Response::new(Body::from(text.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

/// `reply.status(status).type("text/html").send(html)`
pub fn send_html(status: StatusCode, html: &str) -> Response {
    let mut response = Response::new(Body::from(html.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    response
}

/// `reply.status(status).send()` with no payload.
pub fn send_empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

/// `reply.status(status).send({ error })`
pub fn error(status: StatusCode, message: &str) -> Response {
    send(status, &object(vec![("error", message.into())]))
}

/// A JavaScript object literal from ordered fields.
pub fn object(fields: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(fields.into_iter().map(|(name, value)| (name.to_string(), value)).collect())
}

/// `value ?? null` for an optional text column.
pub fn text(value: Option<String>) -> JsValue {
    value.map_or(JsValue::Null, JsValue::String)
}

/// `value ?? null` for an optional boolean column.
pub fn boolean(value: Option<bool>) -> JsValue {
    value.map_or(JsValue::Null, JsValue::Bool)
}

/// `value ?? null` for an optional integer column.
pub fn integer(value: Option<i32>) -> JsValue {
    value.map_or(JsValue::Null, |number| JsValue::Number(f64::from(number)))
}

/// Characters `decodeURI` leaves encoded (find-my-way's `decodeComponentChar` set
/// minus `%`, which it handles by re-encoding).
fn is_reserved(byte: u8) -> bool {
    b"#$&+,/:;=?@".contains(&byte)
}

fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

/// find-my-way's `decodeComponentChar`: the character an escape of a reserved
/// character (or `%25`) stands for.
fn decode_component_char(high: Option<u8>, low: Option<u8>) -> Option<char> {
    let (high, low) = (high?, low?);
    let character = match (high, low.to_ascii_uppercase()) {
        (b'2', b'5') => '%',
        (b'2', b'3') => '#',
        (b'2', b'4') => '$',
        (b'2', b'6') => '&',
        (b'2', b'B') => '+',
        (b'2', b'C') => ',',
        (b'2', b'F') => '/',
        (b'3', b'A') => ':',
        (b'3', b'B') => ';',
        (b'3', b'D') => '=',
        (b'3', b'F') => '?',
        (b'4', b'0') => '@',
        _ => return None,
    };
    Some(character)
}

/// `decodeURI`: every escape decoded except those of reserved characters; a
/// malformed escape or byte sequence is a `URIError` (None).
fn decode_uri(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            let next = text[index..].find('%').map_or(bytes.len(), |offset| index + offset);
            out.push_str(&text[index..next]);
            index = next;
            continue;
        }
        let escape = |at: usize| -> Option<u8> {
            if bytes.get(at) != Some(&b'%') {
                return None;
            }
            Some(hex_value(*bytes.get(at + 1)?)? * 16 + hex_value(*bytes.get(at + 2)?)?)
        };
        let first = escape(index)?;
        if first < 0x80 {
            if is_reserved(first) {
                out.push_str(&text[index..index + 3]);
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
        for position in 1..length {
            let continuation = escape(index + position * 3)?;
            if continuation & 0xC0 != 0x80 {
                return None;
            }
            sequence.push(continuation);
        }
        // from_utf8 rejects overlong forms, surrogates and code points past U+10FFFF, as V8 does
        out.push_str(std::str::from_utf8(&sequence).ok()?);
        index += length * 3;
    }
    Some(out)
}

/// find-my-way's `safeDecodeURI` flag for a raw path, None when `decodeURI` would
/// throw (Fastify answers FST_ERR_BAD_URL).
fn sanitize_path(path: &str) -> Option<bool> {
    // `%25` is re-encoded so decodeURI yields a literal `%25` for the param step
    decode_uri(&path.replace("%25", "%2525"))?;
    let bytes = path.as_bytes();
    let should_decode_param = bytes.iter().enumerate().any(|(index, &byte)| {
        byte == b'%' && decode_component_char(bytes.get(index + 1).copied(), bytes.get(index + 2).copied()).is_some()
    });
    Some(should_decode_param)
}

/// find-my-way's `safeDecodeURIComponent`: decode the reserved-character escapes
/// `decodeURI` left behind.
fn safe_decode_uri_component(component: &str) -> String {
    let Some(start) = component.find('%') else { return component.to_string() };
    let bytes = component.as_bytes();
    let mut decoded = String::new();
    let mut last = start;
    let mut index = start;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let character = decode_component_char(bytes.get(index + 1).copied(), bytes.get(index + 2).copied());
            decoded.push_str(&component[last..index]);
            match character {
                Some(character) => decoded.push(character),
                None => decoded.push_str("null"),
            }
            last = (index + 3).min(bytes.len());
        }
        index += 1;
    }
    format!("{}{}{}", &component[..start], decoded, &component[last..])
}

/// Why a route's parameters could not be read.
pub enum ParamFailure {
    /// A parameter longer than `maxParamLength`: find-my-way finds no route
    NotFound,
    /// `decodeURI` threw on the path
    BadUrl,
}

/// The decoded values of the path segments at `indices` (0 is the empty segment
/// before the leading slash), as find-my-way hands them to `request.params`.
pub fn route_params(uri: &Uri, indices: &[usize]) -> Result<Vec<String>, ParamFailure> {
    let path = uri.path();
    let Some(should_decode_param) = sanitize_path(path) else {
        debug!(path, "Path is not a valid URL component");
        return Err(ParamFailure::BadUrl);
    };
    let segments: Vec<&str> = path.split('/').collect();
    let mut values = Vec::with_capacity(indices.len());
    for &index in indices {
        let raw = segments.get(index).copied().unwrap_or_default();
        let mut value = decode_uri(&raw.replace("%25", "%2525")).ok_or(ParamFailure::BadUrl)?;
        if should_decode_param {
            value = safe_decode_uri_component(&value);
        }
        if utf16_len(&value) > MAX_PARAM_LENGTH {
            debug!(path, "Route parameter exceeds maxParamLength");
            return Err(ParamFailure::NotFound);
        }
        values.push(value);
    }
    Ok(values)
}

/// The response for a [`ParamFailure`].
pub async fn param_failure(failure: ParamFailure, method: Method, uri: Uri) -> Response {
    match failure {
        ParamFailure::NotFound => http::errors::not_found(method, uri).await,
        // Normally answered earlier by http::bad_url at the edge; kept for a direct call
        ParamFailure::BadUrl => {
            let url = uri.path_and_query().map_or_else(|| uri.path().to_string(), |value| value.as_str().to_string());
            warn!(url = %url, "Request URL is not a valid url component");
            let body = json!({
                "error": "Bad Request",
                "code": "FST_ERR_BAD_URL",
                "message": format!("'{url}' is not a valid url component"),
                "statusCode": 400,
            });
            let mut response = Response::new(Body::from(crate::js_json::stringify(&body)));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response.extensions_mut().insert(http::RawFrameworkResponse);
            response
        }
    }
}

fn rejection_response(rejection: BodyRejection) -> Response {
    let mut response = http::json(rejection.status, &rejection.body);
    if rejection.close_connection {
        response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Convert the ingest parser's value into the analytics one. Containers below the
/// kept depth become empty containers of the same type (see [`BODY_KEEP_DEPTH`]).
fn to_js(value: &ParsedJson) -> JsValue {
    match value {
        ParsedJson::Null => JsValue::Null,
        ParsedJson::Bool(flag) => JsValue::Bool(*flag),
        ParsedJson::Number(number) => JsValue::Number(*number),
        ParsedJson::String(text) => JsValue::String(text.clone()),
        ParsedJson::Array(items) => JsValue::Array(items.iter().map(to_js).collect()),
        ParsedJson::Object(entries) => {
            JsValue::Object(entries.iter().map(|(key, entry)| (key.clone(), to_js(entry))).collect())
        }
        ParsedJson::UnreadArray => JsValue::Array(Vec::new()),
        ParsedJson::UnreadObject => JsValue::Object(JsObject::new()),
    }
}

/// `request.body` for a POST, PUT or DELETE route: Fastify's two default parsers
/// (JSON through secure-json-parse, text/plain as a string) with the 10 MB limit.
/// `Undefined` when the request has neither a body nor a content type.
pub async fn read_body(headers: &HeaderMap, body: Body) -> Result<JsValue, Response> {
    read_body_checked(headers, body).await.map(|(value, _)| value)
}

/// Whether JSON text holds a `\uD800`-`\uDFFF` escape that is not half of a pair.
/// `JSON.parse` keeps such a lone surrogate in the string; the Rust parsers turn it
/// into U+FFFD. The difference only shows where Node re-serialises the value into a
/// jsonb column: `JSON.stringify` writes the escape back and Postgres rejects it.
pub fn has_lone_surrogate_escape(raw: &[u8]) -> bool {
    let mut in_string = false;
    let mut pending_high = false;
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        if !in_string {
            in_string = byte == b'"';
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                if pending_high {
                    return true;
                }
                in_string = false;
                index += 1;
            }
            b'\\' if raw.get(index + 1) == Some(&b'u') => {
                let unit = raw
                    .get(index + 2..index + 6)
                    .and_then(|hex| std::str::from_utf8(hex).ok())
                    .and_then(|hex| u16::from_str_radix(hex, 16).ok())
                    .unwrap_or(0);
                match unit {
                    0xD800..=0xDBFF if pending_high => return true,
                    0xD800..=0xDBFF => pending_high = true,
                    0xDC00..=0xDFFF if pending_high => pending_high = false,
                    0xDC00..=0xDFFF => return true,
                    _ if pending_high => return true,
                    _ => {}
                }
                index += 6;
            }
            _ => {
                if pending_high {
                    return true;
                }
                index += if byte == b'\\' { 2 } else { 1 };
            }
        }
    }
    pending_high
}

/// [`read_body`] plus whether the raw JSON held a lone surrogate escape.
pub async fn read_body_checked(headers: &HeaderMap, body: Body) -> Result<(JsValue, bool), Response> {
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
        Ok(None) => Ok((JsValue::Undefined, false)),
        Ok(Some(value @ ParsedJson::String(_))) => Ok((to_js(&value), false)),
        Ok(Some(value)) => Ok((to_js(&value), has_lone_surrogate_escape(&raw))),
        Err(rejection) => Err(rejection_response(rejection)),
    }
}

/// Postgres's refusal of a lone surrogate escape in jsonb input, for the value Node
/// would have sent: only possible when the body carried one and the stored JSON holds
/// the replacement character it became.
pub fn jsonb_rejects(lone_surrogate: bool, stored_json: &str) -> bool {
    lone_surrogate && stored_json.contains('\u{FFFD}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(path: &str, indices: &[usize]) -> Result<Vec<String>, &'static str> {
        route_params(&path.parse::<Uri>().unwrap(), indices).map_err(|failure| match failure {
            ParamFailure::NotFound => "not found",
            ParamFailure::BadUrl => "bad url",
        })
    }

    #[test]
    fn params_decode_like_find_my_way() {
        assert_eq!(params("/api/organizations/o%2501/teams", &[3]).unwrap(), ["o%01"]);
        assert_eq!(params("/api/organizations/%20o/teams/%2F%41", &[3, 5]).unwrap(), [" o", "/A"]);
        assert_eq!(params("/api/organizations/%E2%9C%93/teams", &[3]).unwrap(), ["\u{2713}"]);
        assert_eq!(params("/api/organizations/o%zz/teams", &[3]), Err("bad url"));
        assert_eq!(params("/api/organizations/o/teams/", &[3, 5]).unwrap(), ["o", ""]);
        assert_eq!(params(&format!("/api/organizations/{}/teams", "o".repeat(1500)), &[3]).unwrap()[0].len(), 1500);
        assert_eq!(params(&format!("/api/organizations/{}/teams", "o".repeat(1501)), &[3]), Err("not found"));
    }
}
