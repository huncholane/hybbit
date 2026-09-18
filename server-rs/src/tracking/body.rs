//! Request body parsing for `POST /api/track`, ported from Fastify 5.8.5 as Node
//! configures it (server/src/index.ts): the route sits on the root instance, so only
//! Fastify's two default parsers apply (`application/json` through secure-json-parse,
//! `text/plain` as a string); the `application/json` override in index.ts belongs to
//! the Better Auth plugin's encapsulated context and never sees this route.
//!
//! The pieces reproduced: `handleRequest`'s missing-Content-Type rule,
//! `lib/content-type.js` media type validation, `rawBody`'s limit and Content-Length
//! checks (which compare against the UTF-8 length of the *decoded* text, so invalid
//! UTF-8 under a Content-Length is a 400), and the default JSON parser's empty-body and
//! invalid-JSON errors. Rejections carry the body Fastify's default error handler
//! sends; the `/api` error rewrite (`http::errors`) then adds `resolution` and keeps
//! the rest.

use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};

use super::{
    js::{js_to_lower, js_trim, js_trim_end, js_trim_start, latin1},
    json::{JsValue, parse_json},
};

/// `bodyLimit` in server/src/index.ts
pub const TRACK_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;

/// The schema reads the payload object and one level inside it (`feature_flags`)
const TRACK_BODY_KEEP_DEPTH: usize = 2;

/// A body Fastify refused before the handler ran.
#[derive(Debug, Clone, PartialEq)]
pub struct BodyRejection {
    pub status: StatusCode,
    /// `{statusCode, code, error, message}` as Fastify serialises the error
    pub body: Value,
    /// Fastify sets `Connection: close` when a content-type parser fails, since the
    /// client may still be sending
    pub close_connection: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FastifyBodyError {
    InvalidMediaType,
    BodyTooLarge,
    InvalidContentLength,
    EmptyJsonBody,
    InvalidJsonBody,
}

impl FastifyBodyError {
    fn rejection(self, close_connection: bool) -> BodyRejection {
        let (status, code, message) = match self {
            FastifyBodyError::InvalidMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "FST_ERR_CTP_INVALID_MEDIA_TYPE", "Unsupported Media Type")
            }
            FastifyBodyError::BodyTooLarge => {
                (StatusCode::PAYLOAD_TOO_LARGE, "FST_ERR_CTP_BODY_TOO_LARGE", "Request body is too large")
            }
            FastifyBodyError::InvalidContentLength => (
                StatusCode::BAD_REQUEST,
                "FST_ERR_CTP_INVALID_CONTENT_LENGTH",
                "Request body size did not match Content-Length",
            ),
            FastifyBodyError::EmptyJsonBody => (
                StatusCode::BAD_REQUEST,
                "FST_ERR_CTP_EMPTY_JSON_BODY",
                "Body cannot be empty when content-type is set to 'application/json'",
            ),
            FastifyBodyError::InvalidJsonBody => (
                StatusCode::BAD_REQUEST,
                "FST_ERR_CTP_INVALID_JSON_BODY",
                "Body is not valid JSON but content-type is set to 'application/json'",
            ),
        };
        let reason = status.canonical_reason().unwrap_or_default();
        tracing::debug!(status = status.as_u16(), code, message, "Tracking request body rejected");
        BodyRejection {
            status,
            body: json!({ "statusCode": status.as_u16(), "code": code, "error": reason, "message": message }),
            close_connection,
        }
    }
}

/// The headers Fastify's body handling consults, as Node exposes them.
#[derive(Debug, Clone, Default)]
pub struct BodyHeaders {
    pub content_type: Option<String>,
    pub content_length: Option<String>,
    pub transfer_encoding: bool,
}

impl BodyHeaders {
    /// Node keeps the first Content-Type and Content-Length of duplicates.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            content_type: headers.get(header::CONTENT_TYPE).map(|value| latin1(value.as_bytes())),
            content_length: headers.get(header::CONTENT_LENGTH).map(|value| latin1(value.as_bytes())),
            transfer_encoding: headers.contains_key(header::TRANSFER_ENCODING),
        }
    }

    /// `Number(request.headers['content-length'])`, None standing for NaN
    fn declared_length(&self) -> Option<f64> {
        let text = js_trim(self.content_length.as_deref()?);
        if text.is_empty() {
            return Some(0.0);
        }
        if text.bytes().all(|b| b.is_ascii_digit()) {
            return text.parse::<f64>().ok();
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyParser {
    Json,
    PlainText,
}

/// Everything Fastify decides from the headers alone, before reading the body:
/// `Ok(None)` means there is no body to read (`request.body` stays `undefined`).
/// `limit` is the route's `bodyLimit` (the server default unless the route sets
/// its own, as `/imports/:importId/events` does).
fn choose_parser(headers: &BodyHeaders, limit: usize) -> Result<Option<BodyParser>, BodyRejection> {
    let Some(content_type) = headers.content_type.as_deref() else {
        let empty = !headers.transfer_encoding && headers.content_length.as_deref().is_none_or(|length| length == "0");
        if empty {
            return Ok(None);
        }
        // `contentTypeParser.run('')` finds no parser for an unnamed type
        return Err(FastifyBodyError::InvalidMediaType.rejection(false));
    };

    let parser = match media_type(content_type).as_deref() {
        Some("application/json") => BodyParser::Json,
        Some("text/plain") => BodyParser::PlainText,
        _ => return Err(FastifyBodyError::InvalidMediaType.rejection(false)),
    };

    if headers.declared_length().is_some_and(|length| length > limit as f64) {
        return Err(FastifyBodyError::BodyTooLarge.rejection(true));
    }
    Ok(Some(parser))
}

/// The rejection Node sends without reading the body, if any: an unsupported or
/// missing media type, or a declared Content-Length over the limit. Handlers call
/// this first, then read at most `TRACK_BODY_LIMIT_BYTES + 1` bytes (answering
/// [`body_too_large`] past that) and hand them to [`parse_track_body`].
pub fn reject_before_reading(headers: &BodyHeaders) -> Option<BodyRejection> {
    choose_parser(headers, TRACK_BODY_LIMIT_BYTES).err()
}

/// [`reject_before_reading`] for a route registered with its own `bodyLimit`
/// (`/api/sites/:siteId/imports/:importId/events` raises it to 50 MB).
pub fn reject_before_reading_with_limit(headers: &BodyHeaders, limit: usize) -> Option<BodyRejection> {
    choose_parser(headers, limit).err()
}

/// The rejection for a body that grew past the limit while being read.
pub fn body_too_large() -> BodyRejection {
    FastifyBodyError::BodyTooLarge.rejection(true)
}

/// Turns the raw request into `request.body`: `Ok(None)` is `undefined` (no body and
/// no Content-Type), otherwise the parsed JSON value or the text/plain string.
pub fn parse_track_body(headers: &BodyHeaders, raw: &[u8]) -> Result<Option<JsValue>, BodyRejection> {
    parse_body_with_depth(headers, raw, TRACK_BODY_KEEP_DEPTH)
}

/// [`parse_track_body`] for routes that read deeper into the body (identify keeps
/// whole trait objects). The same Fastify defaults apply to every route.
pub fn parse_body_with_depth(
    headers: &BodyHeaders,
    raw: &[u8],
    keep_depth: usize,
) -> Result<Option<JsValue>, BodyRejection> {
    parse_body_with_limit(headers, raw, keep_depth, TRACK_BODY_LIMIT_BYTES)
}

/// [`parse_body_with_depth`] for a route registered with its own `bodyLimit`
/// (`/api/sites/:siteId/imports/:importId/events` raises it to 50 MB).
pub fn parse_body_with_limit(
    headers: &BodyHeaders,
    raw: &[u8],
    keep_depth: usize,
    limit: usize,
) -> Result<Option<JsValue>, BodyRejection> {
    let Some(parser) = choose_parser(headers, limit)? else {
        return Ok(None);
    };

    if raw.len() > limit {
        return Err(body_too_large());
    }

    // `payload.setEncoding('utf8')`: invalid sequences become U+FFFD, and the length
    // checks below count the re-encoded text, not the bytes received
    let text = String::from_utf8_lossy(raw);
    if text.len() > limit {
        return Err(body_too_large());
    }
    if let Some(declared) = headers.declared_length()
        && declared != text.len() as f64
    {
        return Err(FastifyBodyError::InvalidContentLength.rejection(true));
    }

    match parser {
        BodyParser::PlainText => Ok(Some(JsValue::String(text.into_owned()))),
        BodyParser::Json => {
            if text.is_empty() {
                return Err(FastifyBodyError::EmptyJsonBody.rejection(true));
            }
            // secure-json-parse drops one leading byte order mark
            let json_text = text.strip_prefix('\u{FEFF}').unwrap_or(&text);
            match parse_json(json_text, keep_depth) {
                Ok(parsed) if !parsed.prototype_poisoned => Ok(Some(parsed.value)),
                Ok(_) => {
                    tracing::warn!("Tracking body contains forbidden prototype property");
                    Err(FastifyBodyError::InvalidJsonBody.rejection(true))
                }
                Err(error) => {
                    tracing::debug!(position = error.position, "Tracking body is not valid JSON");
                    Err(FastifyBodyError::InvalidJsonBody.rejection(true))
                }
            }
        }
    }
}

/// `new ContentType(header).mediaType` from fastify/lib/content-type.js, or None when
/// the header is not a valid `type/subtype[; params]`.
fn media_type(header: &str) -> Option<String> {
    if header.is_empty() || header == "undefined" {
        return None;
    }

    let (kind, subtype) = match header.find(';') {
        None => {
            let slash = header.find('/')?;
            (js_to_lower(js_trim_start(&header[..slash])), js_to_lower(js_trim_end(&header[slash + 1..])))
        }
        Some(semicolon) => {
            let media = js_to_lower(&header[..semicolon]);
            let slash = media.find('/')?;
            (js_trim_start(&media[..slash]).to_string(), js_trim_end(&media[slash + 1..]).to_string())
        }
    };

    (is_token(&kind) && is_token(&subtype)).then(|| format!("{kind}/{subtype}"))
}

/// RFC 9110 token: `^[\w!#$%&'*+.^`|~-]+$`
fn is_token(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"_!#$%&'*+.^`|~-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(content_type: Option<&str>, content_length: Option<&str>, chunked: bool) -> BodyHeaders {
        BodyHeaders {
            content_type: content_type.map(str::to_string),
            content_length: content_length.map(str::to_string),
            transfer_encoding: chunked,
        }
    }

    fn code(result: Result<Option<JsValue>, BodyRejection>) -> String {
        match result {
            Ok(_) => "ok".into(),
            Err(rejection) => rejection.body["code"].as_str().unwrap().to_string(),
        }
    }

    #[test]
    fn parses_media_types_like_fastify() {
        assert_eq!(media_type("Application/JSON; charset=utf-8").as_deref(), Some("application/json"));
        assert_eq!(media_type(" text/plain").as_deref(), Some("text/plain"));
        assert_eq!(media_type("application /json"), None);
        assert_eq!(media_type("application/json/x"), None);
        assert_eq!(media_type("json"), None);
        assert_eq!(media_type("undefined"), None);
    }

    #[test]
    fn missing_content_type_is_undefined_only_without_a_body() {
        assert_eq!(parse_track_body(&headers(None, None, false), b""), Ok(None));
        assert_eq!(parse_track_body(&headers(None, Some("0"), false), b""), Ok(None));
        assert_eq!(code(parse_track_body(&headers(None, Some("2"), false), b"{}")), "FST_ERR_CTP_INVALID_MEDIA_TYPE");
        assert_eq!(code(parse_track_body(&headers(None, None, true), b"")), "FST_ERR_CTP_INVALID_MEDIA_TYPE");
    }

    #[test]
    fn json_and_text_bodies() {
        let json = headers(Some("application/json"), None, false);
        assert_eq!(code(parse_track_body(&json, b"")), "FST_ERR_CTP_EMPTY_JSON_BODY");
        assert_eq!(code(parse_track_body(&json, b"{")), "FST_ERR_CTP_INVALID_JSON_BODY");
        assert_eq!(code(parse_track_body(&json, br#"{"__proto__":1}"#)), "FST_ERR_CTP_INVALID_JSON_BODY");
        assert_eq!(parse_track_body(&json, "\u{FEFF}null".as_bytes()), Ok(Some(JsValue::Null)));
        let text = headers(Some("text/plain"), None, false);
        assert_eq!(parse_track_body(&text, b"{}"), Ok(Some(JsValue::String("{}".into()))));
        assert_eq!(
            code(parse_track_body(&headers(Some("application/xml"), None, false), b"")),
            "FST_ERR_CTP_INVALID_MEDIA_TYPE"
        );
    }

    #[test]
    fn length_checks_use_the_decoded_text() {
        // 0xFF becomes U+FFFD, three bytes where one was declared
        let declared = headers(Some("text/plain"), Some("1"), false);
        assert_eq!(code(parse_track_body(&declared, b"\xFF")), "FST_ERR_CTP_INVALID_CONTENT_LENGTH");
        // a truncated four-byte sequence is three bytes and one replacement character
        let same_length = headers(Some("text/plain"), Some("3"), false);
        assert_eq!(parse_track_body(&same_length, b"\xF0\x9F\x98"), Ok(Some(JsValue::String("\u{FFFD}".into()))));
        let too_large = headers(Some("application/json"), Some("10485761"), false);
        assert_eq!(code(parse_track_body(&too_large, b"")), "FST_ERR_CTP_BODY_TOO_LARGE");
    }
}
