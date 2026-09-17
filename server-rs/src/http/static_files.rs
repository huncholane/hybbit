//! Tracking scripts and other files in `public/`, served like @fastify/static and
//! the `/api/*.js` aliases in server/src/index.ts.

use std::{path::Path, time::UNIX_EPOCH};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};

use super::errors;
use crate::state::AppState;

const ONE_HOUR: u32 = 3_600;
const ONE_DAY: u32 = 86_400;

pub async fn script_js(State(state): State<AppState>, headers: HeaderMap) -> Response {
    serve_or_not_found(&state.config.public_dir.join("script.js"), ONE_HOUR, &headers, "/api/script.js").await
}

pub async fn replay_js(State(state): State<AppState>, headers: HeaderMap) -> Response {
    serve_or_not_found(&state.config.public_dir.join("rrweb.min.js"), ONE_DAY, &headers, "/api/replay.js").await
}

pub async fn metrics_js(State(state): State<AppState>, headers: HeaderMap) -> Response {
    serve_or_not_found(&state.config.public_dir.join("web-vitals.iife.js"), ONE_DAY, &headers, "/api/metrics.js").await
}

/// Everything no route matched: files from `public/` at the root for GET and HEAD,
/// the not-found handler for the rest.
pub async fn fallback(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if (method == Method::GET || method == Method::HEAD)
        && !errors::is_api_path(uri.path())
        && let Some(name) = public_file_name(uri.path())
        && let Some(response) = file_response(&state.config.public_dir.join(name), 0, &headers).await
    {
        return response;
    }
    errors::not_found(method, uri).await
}

/// A plain top-level file of `public/` for a GET or HEAD at the root, as
/// @fastify/static serves it (`max-age=0`, ETag, Last-Modified).
pub async fn public_file(public_dir: &Path, path: &str, headers: &HeaderMap) -> Option<Response> {
    let name = public_file_name(path)?;
    file_response(&public_dir.join(name), 0, headers).await
}

/// Only plain top-level file names: `public/` has no subdirectories, and dotfiles and
/// traversal never resolve.
fn public_file_name(path: &str) -> Option<&str> {
    let name = path.strip_prefix('/')?;
    let plain = !name.is_empty() && !name.starts_with('.') && !name.contains(['/', '\\', '%']);
    plain.then_some(name)
}

async fn serve_or_not_found(path: &Path, max_age: u32, headers: &HeaderMap, route: &str) -> Response {
    match file_response(path, max_age, headers).await {
        Some(response) => response,
        None => {
            tracing::error!(file = %path.display(), route, "static file missing");
            errors::not_found(Method::GET, Uri::from_static("/")).await
        }
    }
}

async fn file_response(path: &Path, max_age: u32, request_headers: &HeaderMap) -> Option<Response> {
    let metadata = tokio::fs::metadata(path).await.ok().filter(|metadata| metadata.is_file())?;
    let modified = metadata.modified().ok();
    let etag = stat_etag(metadata.len(), modified);
    let last_modified = modified.map(httpdate::fmt_http_date);

    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&format!("public, max-age={max_age}")) {
        headers.insert(header::CACHE_CONTROL, value);
    }
    if let Some(value) = last_modified.as_deref().and_then(|date| HeaderValue::from_str(date).ok()) {
        headers.insert(header::LAST_MODIFIED, value);
    }
    if let Ok(value) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, value);
    }
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type(path)));

    if is_fresh(request_headers, &etag, modified) {
        return Some((StatusCode::NOT_MODIFIED, headers).into_response());
    }

    let bytes = tokio::fs::read(path).await.ok()?;
    Some((StatusCode::OK, headers, Body::from(bytes)).into_response())
}

/// The `etag` package's stat form, which @fastify/send uses: size and modification
/// time in hex. Node's fs.Stats rounds the modification time to the nearest millisecond.
pub fn stat_etag(len: u64, modified: Option<std::time::SystemTime>) -> String {
    let mtime_ms = modified
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| (duration.as_nanos() + 500_000) / 1_000_000);
    format!("W/\"{len:x}-{mtime_ms:x}\"")
}

/// If-None-Match wins when present (weak comparison); otherwise If-Modified-Since.
pub fn is_fresh(request_headers: &HeaderMap, etag: &str, modified: Option<std::time::SystemTime>) -> bool {
    if let Some(if_none_match) = request_headers.get(header::IF_NONE_MATCH).and_then(|value| value.to_str().ok()) {
        let bare = etag.trim_start_matches("W/");
        return if_none_match
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == bare);
    }

    let since = request_headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok());
    match (since, modified) {
        (Some(since), Some(modified)) => {
            let seconds = |time: std::time::SystemTime| time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            seconds(modified) <= seconds(since)
        }
        _ => false,
    }
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("js") => "application/javascript; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_only_plain_top_level_names() {
        assert_eq!(public_file_name("/script.js"), Some("script.js"));
        assert_eq!(public_file_name("/"), None);
        assert_eq!(public_file_name("/.env"), None);
        assert_eq!(public_file_name("/../server/.env"), None);
        assert_eq!(public_file_name("/%2e%2e%2fsecret"), None);
        assert_eq!(public_file_name("/nested/file.js"), None);
    }

    #[test]
    fn compares_etags_weakly() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"8a90-1\", W/\"10-2\""));
        assert!(is_fresh(&headers, "W/\"10-2\"", None));
        assert!(!is_fresh(&headers, "W/\"10-3\"", None));
    }
}
