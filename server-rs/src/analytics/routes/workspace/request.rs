//! Request plumbing the workspace routes share, ported from the Fastify 5.8.5
//! machinery around Node's handlers: find-my-way 9.3 parameter decoding and
//! `maxParamLength: 1500`, the default body parsers, `request.ip` under
//! `trustProxy: true`, and `reply.send` of a plain object.

use std::net::IpAddr;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use serde_json::json;
use tracing::{debug, warn};

use crate::{
    analytics::js::{JsObject, JsValue, json, string::utf16_len},
    http,
    tracking::{
        body::{BodyHeaders, BodyRejection, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_body_with_depth, reject_before_reading},
        json::JsValue as ParsedJson,
    },
};

/// `maxParamLength` in server/src/index.ts
pub const MAX_PARAM_LENGTH: usize = 1500;

/// How deep a parsed body is kept. No workspace schema looks further than six
/// levels in (a dashboard card's `mapping.yColumns` entries); below that only a
/// value's type can matter, and zod never reports a deeper value's contents.
const BODY_KEEP_DEPTH: usize = 16;

/// `reply.send(object)`: `JSON.stringify` with Fastify's JSON content type.
pub fn send(status: StatusCode, value: &JsValue) -> Response {
    let body = json::stringify(value).unwrap_or_default();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

/// `reply.status(status).send({ error })`
pub fn error(status: StatusCode, message: &str) -> Response {
    let mut body = JsObject::new();
    body.insert("error", message.into());
    send(status, &JsValue::Object(body))
}

/// A JavaScript object literal from ordered fields.
pub fn object(fields: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(fields.into_iter().map(|(name, value)| (name.to_string(), value)).collect())
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

/// find-my-way's `safeDecodeURI` flags for a raw path, None when `decodeURI`
/// would throw (Fastify answers FST_ERR_BAD_URL).
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
        ParamFailure::BadUrl => {
            // find-my-way reports the URL as requested, query string included, and
            // Fastify writes the reply itself: plain JSON content type, no hooks
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

/// Convert the ingest parser's value into the analytics one. Containers below
/// the kept depth become empty containers of the same type (see
/// [`BODY_KEEP_DEPTH`]); recursion is bounded by that depth.
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
        Ok(None) => Ok(JsValue::Undefined),
        Ok(Some(value)) => Ok(to_js(&value)),
        Err(rejection) => Err(rejection_response(rejection)),
    }
}

/// proxy-addr's `parse` of X-Forwarded-For: addresses from right to left, split
/// on commas with spaces trimmed.
fn forwarded_addresses(header: &str) -> Vec<&str> {
    let bytes = header.as_bytes();
    let mut list = Vec::new();
    let (mut start, mut end) = (bytes.len(), bytes.len());
    for index in (0..bytes.len()).rev() {
        match bytes[index] {
            b' ' => {
                if start == end {
                    start = index;
                    end = index;
                }
            }
            b',' => {
                if start != end {
                    list.push(&header[start..end]);
                }
                start = index;
                end = index;
            }
            _ => start = index,
        }
    }
    if start != end {
        list.push(&header[start..end]);
    }
    list
}

/// `request.ip` with `trustProxy: true`: every hop is trusted, so the address is
/// the leftmost X-Forwarded-For entry, or the socket's when there is none. Node
/// joins repeated headers with ", ".
pub fn request_ip(headers: &HeaderMap, peer: IpAddr) -> String {
    let values: Vec<String> = headers
        .get_all("x-forwarded-for")
        .iter()
        .map(|value| crate::tracking::js::latin1(value.as_bytes()))
        .collect();
    if !values.is_empty() {
        let joined = values.join(", ");
        if let Some(leftmost) = forwarded_addresses(&joined).last() {
            return (*leftmost).to_string();
        }
    }
    match peer {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => format!("::ffff:{v4}"),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// `Number(id)` bound as a Postgres integer: values past the int4 range (which
/// `parseInt` can produce) make Postgres throw inside Node's `try`, so they
/// surface as the handler's 500.
pub fn pg_int(id: f64) -> Option<i32> {
    (id.fract() == 0.0 && id >= f64::from(i32::MIN) && id <= f64::from(i32::MAX)).then_some(id as i32)
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
        assert_eq!(params("/api/sites/1%2501/segments", &[3]).unwrap(), ["1%01"]);
        assert_eq!(params("/api/sites/%201/segments/%2F%41", &[3, 5]).unwrap(), [" 1", "/A"]);
        assert_eq!(params("/api/sites/%E2%9C%93/segments", &[3]).unwrap(), ["\u{2713}"]);
        assert_eq!(params("/api/sites/a%2541/x", &[3]).unwrap(), ["a%41"]);
        assert_eq!(params("/api/sites/1%zz/segments", &[3]), Err("bad url"));
        assert_eq!(params("/api/sites/1/segments/%C3", &[3]), Err("bad url"));
        assert_eq!(params("/api/sites/1/segments/", &[3, 5]).unwrap(), ["1", ""]);
        assert_eq!(params(&format!("/api/sites/1/dashboards/{}", "1".repeat(1500)), &[5]).unwrap()[0].len(), 1500);
        assert_eq!(params(&format!("/api/sites/1/dashboards/{}", "1".repeat(1501)), &[5]), Err("not found"));
    }

    #[test]
    fn request_ip_takes_the_leftmost_forwarded_address() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(request_ip(&headers, peer), "127.0.0.1");
        headers.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9, 1.1.1.1"));
        assert_eq!(request_ip(&headers, peer), "9.9.9.9");
        headers.insert("x-forwarded-for", HeaderValue::from_static(" ,  2.2.2.2 ,3.3.3.3"));
        assert_eq!(request_ip(&headers, peer), "2.2.2.2");
        headers.insert("x-forwarded-for", HeaderValue::from_static(""));
        assert_eq!(request_ip(&headers, peer), "127.0.0.1");
        headers.append("x-forwarded-for", HeaderValue::from_static("4.4.4.4"));
        assert_eq!(request_ip(&headers, peer), "4.4.4.4");
    }

    #[test]
    fn int_binding_matches_postgres_range() {
        assert_eq!(pg_int(2_147_483_647.0), Some(i32::MAX));
        assert_eq!(pg_int(2_147_483_648.0), None);
        assert_eq!(pg_int(f64::INFINITY), None);
    }
}
