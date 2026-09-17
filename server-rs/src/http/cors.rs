//! CORS, ported from server/src/lib/cors.ts plus the @fastify/cors 11.2.0 behaviour
//! it configures (delegator mode, strict preflight, 204 preflight replies).

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use url::Url;

const ALLOWED_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS, PATCH";
const ALLOWED_HEADERS: &str = "Content-Type, Authorization, X-Requested-With, x-captcha-response, x-private-key, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID";
const DEV_TRUSTED_ORIGINS: [&str; 2] = ["http://localhost:3002", "http://127.0.0.1:3002"];

pub struct CorsPolicy {
    trusted_origins: Vec<String>,
}

impl CorsPolicy {
    /// Trusted origins: the origin of BASE_URL, plus the local dashboard outside production.
    pub fn new(base_url: Option<&str>, production: bool) -> Self {
        let mut trusted_origins = Vec::new();
        if let Some(origin) = base_url.and_then(normalize_origin) {
            trusted_origins.push(origin);
        }
        if !production {
            for origin in DEV_TRUSTED_ORIGINS {
                if !trusted_origins.iter().any(|existing| existing == origin) {
                    trusted_origins.push(origin.to_string());
                }
            }
        }
        Self { trusted_origins }
    }

    fn is_trusted(&self, origin: &str) -> bool {
        self.trusted_origins.iter().any(|trusted| trusted == origin)
    }
}

/// `normalizeCorsOrigin`: trim, drop one surrounding quote on each side, and keep the
/// origin of an http(s) URL.
pub fn normalize_origin(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let unquoted = trimmed.strip_prefix(['\'', '"']).unwrap_or(trimmed);
    let unquoted = unquoted.strip_suffix(['\'', '"']).unwrap_or(unquoted);

    let url = Url::parse(unquoted).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

/// Paths any origin may call (the tracking script, embeds, OAuth discovery).
pub fn is_public_cors_path(path: &str) -> bool {
    path == "/api/track"
        || path == "/api/identify"
        || path == "/api/version"
        || path.starts_with("/.well-known/oauth-")
        || path.starts_with("/.well-known/openid-configuration")
        || path.starts_with("/api/session-replay/record/")
        || path.starts_with("/api/site/tracking-config/")
        || single_segment_between(path, "/api/sites/", "/sessions")
        || single_segment_between(path, "/api/sites/", "/embed-stats")
        || single_segment_between(path, "/api/site/", "/feature-flags/evaluate")
}

fn single_segment_between(path: &str, prefix: &str, suffix: &str) -> bool {
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .is_some_and(|segment| !segment.is_empty() && !segment.contains('/'))
}

fn is_unsafe_method(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE)
}

pub async fn cors(State(policy): State<Arc<CorsPolicy>>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let raw_origin = req.headers().get(header::ORIGIN).cloned();
    let normalized_origin = raw_origin
        .as_ref()
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_origin);
    let public = is_public_cors_path(&path);

    // Node refuses cross-origin writes from untrusted origins in an onRequest hook.
    // CORS has already run by then, but for an untrusted origin it adds only Vary.
    if is_unsafe_method(&method) && raw_origin.is_some() && !public {
        let trusted = normalized_origin.as_deref().is_some_and(|origin| policy.is_trusted(origin));
        if !trusted {
            let mut response = super::json(StatusCode::FORBIDDEN, &json!({ "error": "Origin not allowed" }));
            add_vary_origin(response.headers_mut());
            // Fastify sends this from a hook, so the error rewrite applies even under
            // /api/auth, whose own responses bypass it
            response.extensions_mut().insert(super::errors::RewriteApiError);
            return response;
        }
    }

    // None: CORS disabled for this request. Some(credentials): reflect the origin.
    let allow = match &normalized_origin {
        None => None,
        Some(origin) if public => Some(policy.is_trusted(origin)),
        Some(origin) => policy.is_trusted(origin).then_some(true),
    };

    let Some(credentials) = allow else {
        // A disabled preflight falls through to routing and ends in the 404 handler
        let mut response = next.run(req).await;
        if response.extensions().get::<super::RawFrameworkResponse>().is_none() {
            add_vary_origin(response.headers_mut());
        }
        return response;
    };
    let origin = raw_origin.unwrap_or_else(|| HeaderValue::from_static(""));

    if method == Method::OPTIONS {
        let mut response = if !req.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) {
            (StatusCode::BAD_REQUEST, [(header::CONTENT_TYPE, "text/plain")], "Invalid Preflight Request").into_response()
        } else {
            let mut response = StatusCode::NO_CONTENT.into_response();
            let headers = response.headers_mut();
            headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(ALLOWED_METHODS));
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static(ALLOWED_HEADERS));
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
            response
        };
        add_cors_headers(response.headers_mut(), origin, credentials);
        add_vary_origin(response.headers_mut());
        return response;
    }

    let mut response = next.run(req).await;
    if response.extensions().get::<super::RawFrameworkResponse>().is_some() {
        return response;
    }
    // Better Auth sets its own Access-Control-Allow-Origin on some responses (`*` on
    // MCP client registration); in Node it writes after @fastify/cors, so its value wins
    if !response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
        add_cors_headers(response.headers_mut(), origin, credentials);
    } else if credentials {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
    }
    add_vary_origin(response.headers_mut());
    response
}

fn add_cors_headers(headers: &mut HeaderMap, origin: HeaderValue, credentials: bool) {
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    if credentials {
        headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
    }
}

/// @fastify/cors sets `Vary: Origin` on every response when origins are resolved per request.
fn add_vary_origin(headers: &mut HeaderMap) {
    let existing = headers
        .get(header::VARY)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    match existing {
        None => {
            headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        }
        Some(vary) => {
            let already = vary
                .split(',')
                .map(str::trim)
                .any(|token| token == "*" || token.eq_ignore_ascii_case("origin"));
            if !already && let Ok(value) = HeaderValue::from_str(&format!("{vary}, Origin")) {
                headers.insert(header::VARY, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_origins_like_the_url_constructor() {
        assert_eq!(normalize_origin(" https://a.hygo.ai/dashboard?x=1 ").as_deref(), Some("https://a.hygo.ai"));
        assert_eq!(normalize_origin("\"https://A.hygo.ai:443\"").as_deref(), Some("https://a.hygo.ai"));
        assert_eq!(normalize_origin("http://localhost:3002").as_deref(), Some("http://localhost:3002"));
        assert_eq!(normalize_origin("ftp://example.com"), None);
        assert_eq!(normalize_origin("null"), None);
        assert_eq!(normalize_origin(""), None);
    }

    #[test]
    fn recognizes_public_paths() {
        for path in [
            "/api/track",
            "/api/identify",
            "/api/version",
            "/.well-known/oauth-protected-resource",
            "/.well-known/openid-configuration/api/mcp",
            "/api/session-replay/record/3",
            "/api/site/tracking-config/3",
            "/api/sites/3/sessions",
            "/api/sites/abc/embed-stats",
            "/api/site/3/feature-flags/evaluate",
        ] {
            assert!(is_public_cors_path(path), "{path} should be public");
        }
        for path in ["/api/sites/3/sessions/abc", "/api/sites//sessions", "/api/config", "/api/sites/3/overview"] {
            assert!(!is_public_cors_path(path), "{path} should not be public");
        }
    }

    #[test]
    fn trusts_localhost_only_outside_production() {
        let production = CorsPolicy::new(Some("https://a.hygo.ai"), true);
        assert!(production.is_trusted("https://a.hygo.ai"));
        assert!(!production.is_trusted("http://localhost:3002"));
        assert!(CorsPolicy::new(Some("https://a.hygo.ai"), false).is_trusted("http://localhost:3002"));
    }
}
