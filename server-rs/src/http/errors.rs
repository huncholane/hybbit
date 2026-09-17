//! Error bodies, ported from server/src/lib/api-errors.ts.

use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, Method, StatusCode, Uri, header},
    middleware::Next,
    response::Response,
};
use serde_json::{Map, Value, json};

/// Error bodies are small; anything past this is replaced by the defaults.
const MAX_ERROR_BODY_BYTES: usize = 10 * 1024 * 1024;

struct Defaults {
    code: &'static str,
    message: &'static str,
    resolution: &'static str,
}

fn defaults_for(status: u16) -> Defaults {
    let (code, message, resolution) = match status {
        401 => (
            "AUTHENTICATION_REQUIRED",
            "Authentication is required.",
            "Send a valid API key in the Authorization header as a Bearer token.",
        ),
        403 => (
            "FORBIDDEN",
            "The credential does not have permission for this operation.",
            "Use a credential with the required scope and Site or Organization access.",
        ),
        404 => (
            "NOT_FOUND",
            "The requested API resource was not found.",
            "Check identifiers and paths against https://hygo.ai/openapi.json.",
        ),
        405 => (
            "METHOD_NOT_ALLOWED",
            "The HTTP method is not supported for this path.",
            "Choose a method listed for this path in https://hygo.ai/openapi.json.",
        ),
        409 => (
            "CONFLICT",
            "The request conflicts with the current resource state.",
            "Refresh the resource, resolve the conflicting state, and retry.",
        ),
        413 => (
            "PAYLOAD_TOO_LARGE",
            "The request body is too large.",
            "Reduce the payload size or split it into smaller requests.",
        ),
        415 => (
            "UNSUPPORTED_MEDIA_TYPE",
            "The request media type is not supported.",
            "Send JSON with Content-Type: application/json unless the operation documents another type.",
        ),
        429 => (
            "RATE_LIMITED",
            "Rate limit exceeded.",
            "Wait for the advertised retry period, then retry the request.",
        ),
        status if status >= 500 => (
            "INTERNAL_ERROR",
            "The server could not complete the request.",
            "Retry with exponential backoff. Contact support if the error persists.",
        ),
        _ => (
            "INVALID_REQUEST",
            "The request is invalid.",
            "Check the request parameters and body against https://hygo.ai/openapi.json.",
        ),
    };
    Defaults { code, message, resolution }
}

/// `normalizeApiError`: keep the handler's fields and fill in `error`, `code`,
/// `message` and `resolution`, in that order after the existing keys.
pub fn normalize_api_error(status: u16, payload: Value) -> Map<String, Value> {
    let mut existing = match payload {
        Value::Object(map) => map,
        Value::String(text) => Map::from_iter([("error".to_string(), Value::String(text))]),
        Value::Array(items) => Map::from_iter([("details".to_string(), Value::Array(items))]),
        _ => Map::new(),
    };
    let defaults = defaults_for(status);

    let string_field = |map: &Map<String, Value>, key: &str| map.get(key).and_then(Value::as_str).map(str::to_string);
    let message = string_field(&existing, "message")
        .or_else(|| string_field(&existing, "error"))
        .unwrap_or_else(|| defaults.message.to_string());
    let error = string_field(&existing, "error").unwrap_or_else(|| message.clone());
    let code = string_field(&existing, "code").unwrap_or_else(|| defaults.code.to_string());
    let resolution = string_field(&existing, "resolution").unwrap_or_else(|| defaults.resolution.to_string());

    existing.insert("error".into(), Value::String(error));
    existing.insert("code".into(), Value::String(code));
    existing.insert("message".into(), Value::String(message));
    existing.insert("resolution".into(), Value::String(resolution));
    existing
}

/// Marks a response produced by Fastify-level code (hooks) on a path whose handler
/// responses skip the rewrite, so it is rewritten anyway.
#[derive(Clone, Copy, Debug)]
pub struct RewriteApiError;

pub fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

fn is_excluded_from_rewrite(path: &str) -> bool {
    // MCP answers in JSON-RPC, and Better Auth writes its responses directly
    path == "/api/mcp" || path.starts_with("/api/mcp/") || path.starts_with("/api/auth/")
}

/// Rewrites every `/api` response with status >= 400 into the structured error
/// shape, like Node's `onSend` hook.
pub async fn api_error_responses(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let response = next.run(req).await;

    let forced = response.extensions().get::<RewriteApiError>().is_some();
    if response.status().as_u16() < 400 || !is_api_path(&path) || (is_excluded_from_rewrite(&path) && !forced) {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let bytes = to_bytes(body, MAX_ERROR_BODY_BYTES).await.unwrap_or_default();
    // An empty body is Fastify's `undefined` payload, which carries no fields
    let payload = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };

    let normalized = Value::Object(normalize_api_error(parts.status.as_u16(), payload));
    parts
        .headers
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    parts.headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    parts
        .headers
        .insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    parts.headers.remove(header::CONTENT_LENGTH);

    Response::from_parts(parts, Body::from(serde_json::to_vec(&normalized).unwrap_or_default()))
}

/// Fastify's not-found handler. Also used for a known path with an unsupported
/// method, which Fastify answers with 404 rather than 405.
pub async fn not_found(method: Method, uri: Uri) -> Response {
    let path = uri.path();
    let body = if is_api_path(path) {
        let message = format!("No API route matches {method} {path}.");
        json!({
            "error": message,
            "code": "API_ROUTE_NOT_FOUND",
            "message": message,
            "resolution": "Read https://hygo.ai/openapi.json and choose a documented operation.",
            "details": { "method": method.as_str(), "path": path },
        })
    } else {
        json!({
            "error": "Resource not found.",
            "code": "NOT_FOUND",
            "message": "Resource not found.",
            "resolution": "Check the requested path and try again.",
        })
    };
    super::json(StatusCode::NOT_FOUND, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_handler_fields_and_appends_the_standard_ones_in_order() {
        let normalized = normalize_api_error(403, json!({ "error": "Insufficient scope", "required": "sites:write" }));
        assert_eq!(
            serde_json::to_string(&normalized).unwrap(),
            r#"{"error":"Insufficient scope","required":"sites:write","code":"FORBIDDEN","message":"Insufficient scope","resolution":"Use a credential with the required scope and Site or Organization access."}"#
        );
    }

    #[test]
    fn prefers_an_explicit_message_and_code() {
        let normalized = normalize_api_error(400, json!({ "error": "bad", "message": "Nope", "code": "CUSTOM" }));
        assert_eq!(normalized["error"], "bad");
        assert_eq!(normalized["message"], "Nope");
        assert_eq!(normalized["code"], "CUSTOM");
    }

    #[test]
    fn wraps_text_arrays_and_empty_bodies() {
        assert_eq!(normalize_api_error(401, json!("Unauthorized"))["message"], "Unauthorized");
        assert_eq!(normalize_api_error(400, json!([1, 2]))["details"], json!([1, 2]));
        let empty = normalize_api_error(418, Value::Null);
        assert_eq!(empty["code"], "INVALID_REQUEST");
        assert_eq!(empty["error"], "The request is invalid.");
        assert_eq!(normalize_api_error(503, Value::Null)["code"], "INTERNAL_ERROR");
    }
}
