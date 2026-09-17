//! Fastify's answer to a URL whose path cannot be percent-decoded, ported from
//! find-my-way 9.3 (`safeDecodeURI` in lib/url-sanitizer.js) and Fastify 5.8
//! (`onBadUrl` in fastify.js).
//!
//! find-my-way decodes the path before matching any route. When `decodeURI`
//! throws (a `%` not followed by two hex digits, or escapes that are not valid
//! UTF-8), Fastify writes a raw 400 straight to the socket: no hooks run, so there
//! are no CORS headers, no `/api` error rewrite and no `charset` on the content
//! type. This middleware sits outside every other layer for the same reason.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::Response,
};
use serde_json::json;
use tracing::warn;

/// `decodeComponentChar(high, low)`: the escapes that `decodeURI` leaves encoded
/// but `decodeURIComponent` would decode (`%25` and the reserved characters).
fn is_component_escape(high: Option<u8>, low: Option<u8>) -> bool {
    match (high, low) {
        (Some(b'2'), Some(low)) => matches!(low, b'5' | b'3' | b'4' | b'6' | b'B' | b'b' | b'C' | b'c' | b'F' | b'f'),
        (Some(b'3'), Some(low)) => matches!(low, b'A' | b'a' | b'B' | b'b' | b'D' | b'd' | b'F' | b'f'),
        (Some(b'4'), Some(b'0')) => true,
        _ => false,
    }
}

fn hex_byte(bytes: &[u8], percent: usize) -> Option<u8> {
    let digits = bytes.get(percent + 1..percent + 3)?;
    let text = std::str::from_utf8(digits).ok()?;
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u8::from_str_radix(text, 16).ok()
}

/// Whether ECMAScript `decodeURI(text)` throws a `URIError`.
fn decode_uri_throws(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(first) = hex_byte(bytes, index) else { return true };
        index += 3;
        if first < 0x80 {
            continue;
        }
        let length = if first & 0xE0 == 0xC0 {
            2
        } else if first & 0xF0 == 0xE0 {
            3
        } else if first & 0xF8 == 0xF0 {
            4
        } else {
            return true;
        };
        let mut sequence = vec![first];
        for _ in 1..length {
            if bytes.get(index) != Some(&b'%') {
                return true;
            }
            let Some(next) = hex_byte(bytes, index) else { return true };
            if next & 0xC0 != 0x80 {
                return true;
            }
            sequence.push(next);
            index += 3;
        }
        // Overlong forms, surrogates and code points past U+10FFFF throw too
        if std::str::from_utf8(&sequence).is_err() {
            return true;
        }
    }
    false
}

/// `safeDecodeURI(path)` throws: scan from the second character, cut at `?` or
/// `#`, double `%25` so it survives decoding, and run `decodeURI` only when some
/// escape is not a component-only one.
pub fn is_bad_url(url: &str) -> bool {
    let mut path = url.as_bytes().to_vec();
    let mut should_decode = false;
    let mut index = 1;
    while index < path.len() {
        match path[index] {
            b'%' => {
                let (high, low) = (path.get(index + 1).copied(), path.get(index + 2).copied());
                if !is_component_escape(high, low) {
                    should_decode = true;
                } else {
                    if (high, low) == (Some(b'2'), Some(b'5')) {
                        should_decode = true;
                        path.splice(index + 1..index + 1, *b"25");
                        index += 2;
                    }
                    index += 2;
                }
            }
            b'?' | b'#' => {
                path.truncate(index);
                break;
            }
            _ => {}
        }
        index += 1;
    }
    should_decode && decode_uri_throws(&path)
}

/// The raw 400 for a URL find-my-way cannot decode; everything else passes through.
pub async fn reject_bad_url(req: Request, next: Next) -> Response {
    let url = req.uri().path_and_query().map_or_else(|| req.uri().path().to_string(), |value| value.as_str().to_string());
    if !is_bad_url(&url) {
        return next.run(req).await;
    }
    warn!(method = %req.method(), "URL is not a valid url component");
    let body = crate::js_json::stringify(&json!({
        "error": "Bad Request",
        "code": "FST_ERR_BAD_URL",
        "message": format!("'{url}' is not a valid url component"),
        "statusCode": 400,
    }));
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_escapes_are_bad_urls() {
        assert!(is_bad_url("/api/sites/%zz/funnels"));
        assert!(is_bad_url("/api/sites/4/goals/%"));
        assert!(is_bad_url("/api/x%2"));
        assert!(is_bad_url("/api/%C3"));
        assert!(is_bad_url("/api/%C0%80"));
        assert!(is_bad_url("/api/%ED%A0%80"));
        assert!(is_bad_url("/api/%80"));
        assert!(is_bad_url("/%zz?x=1"));
    }

    #[test]
    fn decodable_urls_pass() {
        assert!(!is_bad_url("/api/sites/4/funnels"));
        assert!(!is_bad_url("/api/sites/a%20b"));
        assert!(!is_bad_url("/api/%C3%A9"));
        assert!(!is_bad_url("/api/%F0%9F%98%80"));
        assert!(!is_bad_url("/api/x?filters=%zz"));
        assert!(!is_bad_url("/api/%2F%3f%40"));
        assert!(!is_bad_url("/api/%25zz"));
        // only escapes decodeURI would decode trigger it, and the first character is never scanned
        assert!(!is_bad_url("/api/%2F%3A"));
        assert!(is_bad_url("/api/%2F%"));
        assert!(!is_bad_url("%zz"));
    }
}
