//! CSRF and redirect-target checks, ported from better-auth/dist/api/middlewares/
//! origin-check.mjs (`originCheckMiddleware`, `formCsrfMiddleware`, `originCheck`)
//! and auth/trusted-origins.mjs (`matchesOriginPattern`).

use std::sync::LazyLock;

use axum::http::{Method, StatusCode};
use regex::Regex;
use serde_json::Value;
use tracing::{error, warn};
use url::Url;

use crate::config::Config;

use super::context::{ApiError, Ctx};

/// `trustedOrigins`: the base URL's origin, then the app's CORS origins
/// (`getTrustedCorsOrigins`: BASE_URL's origin, plus the local dashboard outside
/// production), then BETTER_AUTH_TRUSTED_ORIGINS. Duplicates are kept, as in Node.
pub fn trusted_origins(config: &Config) -> Vec<String> {
    let mut origins = Vec::new();
    if let Some(base) = super::base_url(config).and_then(|base| Url::parse(&base).ok()) {
        origins.push(base.origin().ascii_serialization());
    }
    // getTrustedCorsOrigins builds its own de-duplicated list
    let mut cors: Vec<String> = Vec::new();
    if let Some(origin) = config.base_url.as_deref().and_then(crate::http::cors::normalize_origin) {
        cors.push(origin);
    }
    if !config.production {
        for origin in ["http://localhost:3002", "http://127.0.0.1:3002"] {
            if !cors.iter().any(|existing| existing == origin) {
                cors.push(origin.to_string());
            }
        }
    }
    origins.extend(cors);
    if let Some(extra) = &config.auth.trusted_origins_env {
        origins.extend(extra.split(',').filter(|origin| !origin.is_empty()).map(str::to_string));
    }
    origins
}

static RELATIVE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/[A-Za-z0-9_\-.+/@]*(?:\?[A-Za-z0-9_\-.+/=&%@]*)?$").expect("valid regex"));

/// The WHATWG origin of a URL, None for opaque ("null") origins or unparseable text
pub fn url_origin(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

fn url_protocol(url: &str) -> Option<String> {
    Url::parse(url).ok().map(|parsed| format!("{}:", parsed.scheme()))
}

/// `matchesOriginPattern(url, pattern, { allowRelativePaths })`
pub fn matches_origin_pattern(url: &str, pattern: &str, allow_relative_paths: bool) -> bool {
    if let Some(rest) = url.strip_prefix('/') {
        if !allow_relative_paths {
            return false;
        }
        // `^\/(?!\/|\\|%2f|%5c)[\w\-.\+/@]*(?:\?[\w\-.\+/=&%@]*)?$`
        let lower = rest.to_ascii_lowercase();
        if rest.starts_with('/') || rest.starts_with('\\') || lower.starts_with("%2f") || lower.starts_with("%5c") {
            return false;
        }
        return RELATIVE_PATH.is_match(url);
    }
    if pattern.contains('*') || pattern.contains('?') {
        warn!(pattern, "Wildcard trusted origin patterns are not supported; treating as no match");
        return false;
    }
    match url_protocol(url).as_deref() {
        Some("http:" | "https:") | None => url_origin(url).as_deref() == Some(pattern),
        Some(_) => url.starts_with(pattern),
    }
}

pub fn is_trusted_origin(ctx: &Ctx<'_>, url: &str, allow_relative_paths: bool) -> bool {
    trusted_origins(&ctx.state.config).iter().any(|pattern| matches_origin_pattern(url, pattern, allow_relative_paths))
}

fn skip_checks(ctx: &Ctx<'_>) -> bool {
    // `skipOriginCheck` defaults to true only under test
    ctx.state.config.auth.test
}

/// `validateOrigin(ctx, forceValidate)`: with cookies (or when forced) the Origin,
/// else Referer, must match a trusted origin.
pub fn validate_origin(ctx: &Ctx<'_>, force: bool) -> Result<(), ApiError> {
    if skip_checks(ctx) {
        return Ok(());
    }
    let uses_cookies = ctx.headers.contains_key("cookie");
    if !(force || uses_cookies) {
        return Ok(());
    }
    let origin = ctx
        .header("origin")
        .filter(|value| !value.is_empty())
        .or_else(|| ctx.header("referer").filter(|value| !value.is_empty()))
        .unwrap_or_default();
    if origin.is_empty() || origin == "null" {
        return Err(ApiError::code(StatusCode::FORBIDDEN, "MISSING_OR_NULL_ORIGIN", "Missing or null Origin"));
    }
    if !is_trusted_origin(ctx, origin, false) {
        error!(origin, "Invalid origin");
        return Err(ApiError::code(StatusCode::FORBIDDEN, "INVALID_ORIGIN", "Invalid origin"));
    }
    Ok(())
}

fn validate_url(ctx: &Ctx<'_>, value: Option<&Value>, label: &str) -> Result<(), ApiError> {
    let Some(value) = value.filter(|value| super::context::truthy(Some(value))) else { return Ok(()) };
    let Some(url) = value.as_str() else {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, &format!("Invalid {label}: expected a string")));
    };
    if is_trusted_origin(ctx, url, true) {
        return Ok(());
    }
    error!(label, "Untrusted redirect target refused");
    let (code, message) = match label {
        "callbackURL" => ("INVALID_CALLBACK_URL", "Invalid callbackURL"),
        "redirectURL" => ("INVALID_REDIRECT_URL", "Invalid redirectURL"),
        "errorCallbackURL" => ("INVALID_ERROR_CALLBACK_URL", "Invalid errorCallbackURL"),
        _ => ("INVALID_NEW_USER_CALLBACK_URL", "Invalid newUserCallbackURL"),
    };
    Err(ApiError::code(StatusCode::FORBIDDEN, code, message))
}

/// `originCheckMiddleware`, the router middleware on every path: skipped for GET,
/// OPTIONS and HEAD; validates the Origin, then `callbackURL` (body or query),
/// `redirectTo`, `errorCallbackURL` and `newUserCallbackURL` from the raw body.
pub fn origin_check_middleware(ctx: &Ctx<'_>) -> Result<(), ApiError> {
    if matches!(ctx.method, Method::GET | Method::OPTIONS | Method::HEAD) {
        return Ok(());
    }
    validate_origin(ctx, false)?;
    if skip_checks(ctx) {
        return Ok(());
    }
    let body = ctx.body_object();
    let field = |name: &str| body.and_then(|body| body.get(name));
    let callback = field("callbackURL").filter(|v| super::context::truthy(Some(v))).or_else(|| ctx.query.get("callbackURL"));
    validate_url(ctx, callback, "callbackURL")?;
    validate_url(ctx, field("redirectTo"), "redirectURL")?;
    validate_url(ctx, field("errorCallbackURL"), "errorCallbackURL")?;
    validate_url(ctx, field("newUserCallbackURL"), "newUserCallbackURL")?;
    Ok(())
}

/// `originCheck((ctx) => ctx.query.callbackURL)` on verify-email
pub fn origin_check_value(ctx: &Ctx<'_>, url: Option<&str>) -> Result<(), ApiError> {
    if skip_checks(ctx) {
        return Ok(());
    }
    let Some(url) = url.filter(|url| !url.is_empty()) else { return Ok(()) };
    if is_trusted_origin(ctx, url, true) {
        return Ok(());
    }
    Err(ApiError::code(StatusCode::FORBIDDEN, "INVALID_CALLBACK_URL", "Invalid callbackURL"))
}

/// `formCsrfMiddleware`: cookies mean a normal origin check; Fetch Metadata headers
/// block cross-site navigations and otherwise force the check; a bare Origin or
/// Referer forces it too.
pub fn form_csrf_middleware(ctx: &Ctx<'_>) -> Result<(), ApiError> {
    if skip_checks(ctx) {
        return Ok(());
    }
    if ctx.headers.contains_key("cookie") {
        return validate_origin(ctx, false);
    }
    let site = ctx.header("sec-fetch-site");
    let mode = ctx.header("sec-fetch-mode");
    let dest = ctx.header("sec-fetch-dest");
    let present = |value: Option<&str>| value.is_some_and(|v| !v.trim().is_empty());
    if present(site) || present(mode) || present(dest) {
        if site == Some("cross-site") && mode == Some("navigate") {
            error!("Blocked cross-site navigation login attempt (CSRF protection)");
            return Err(ApiError::code(
                StatusCode::FORBIDDEN,
                "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
                "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
            ));
        }
        return validate_origin(ctx, true);
    }
    if ctx.header("origin").is_some_and(|v| !v.is_empty()) || ctx.header("referer").is_some_and(|v| !v.is_empty()) {
        return validate_origin(ctx, true);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_patterns_follow_better_auth() {
        let trusted = "https://a.hygo.ai";
        assert!(matches_origin_pattern("https://a.hygo.ai/settings?x=1", trusted, false));
        assert!(!matches_origin_pattern("https://evil.example", trusted, false));
        assert!(matches_origin_pattern("/dashboard", trusted, true));
        assert!(matches_origin_pattern("/login?next=/a&b=%20", trusted, true));
        assert!(!matches_origin_pattern("/dashboard", trusted, false));
        assert!(!matches_origin_pattern("//evil.example", trusted, true));
        assert!(!matches_origin_pattern("/%2Fevil", trusted, true));
        assert!(!matches_origin_pattern("/a b", trusted, true));
        assert!(!matches_origin_pattern("javascript:alert(1)", trusted, true));
        assert!(matches_origin_pattern("myapp://x", "myapp://", true));
    }
}
