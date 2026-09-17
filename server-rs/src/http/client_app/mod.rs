//! The dashboard: the static export of `client/` (`output: "export"`), served for
//! every path that is not `/api`. This replaces the Next.js server that used to run
//! in its own container; the redirects that server and client/src/proxy.ts made
//! are reproduced in [`redirects`], and URLs of dynamic routes are mapped onto the
//! page exported for them in [`routes`].
//!
//! Caching: `/_next/static` files are content-hashed and cached for a year; pages,
//! their flight data (`.txt`) and public files revalidate with an ETag on every use,
//! so a deploy takes effect on the next navigation.

use std::{
    io,
    path::{Path, PathBuf},
};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use percent_encoding::percent_decode_str;
use tokio_util::io::ReaderStream;

use super::{errors, static_files};
use crate::state::AppState;

pub mod redirects;
pub mod routes;

use redirects::Redirect;
use routes::RouteTree;

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// Pages and flight data: always revalidate, so a deploy is picked up at once
const REVALIDATE: &str = "no-cache";
/// Files from client/public, as Next served them
const PUBLIC_FILE: &str = "public, max-age=0";
/// What Next sent with its not-found page
const NOT_FOUND_PAGE: &str = "private, no-cache, no-store, max-age=0, must-revalidate";

pub struct ClientApp {
    dir: PathBuf,
    routes: RouteTree,
}

/// The router's fallback. API paths keep Node's JSON 404; everything else is the
/// dashboard, or, without an export, the backend's public files and a JSON 404.
pub async fn fallback(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if errors::is_api_path(uri.path()) {
        return errors::not_found(method, uri).await;
    }
    // Caddy sent these prefixes to the backend before the dashboard moved here, so
    // a discovery document this service lacks keeps answering like the backend did
    if is_backend_well_known(uri.path()) {
        return static_files::fallback(State(state), method, uri, headers).await;
    }
    match &state.client_app {
        Some(app) => app.respond(&method, &uri, &headers, &state.config.public_dir).await,
        None => static_files::fallback(State(state), method, uri, headers).await,
    }
}

fn is_backend_well_known(path: &str) -> bool {
    path.starts_with("/.well-known/oauth-") || path.starts_with("/.well-known/openid-configuration")
}

/// Paths Caddy sent to the backend before the dashboard moved into this service;
/// everything else used to be answered by the Next server.
pub fn is_backend_path(path: &str) -> bool {
    errors::is_api_path(path) || is_backend_well_known(path)
}

/// What a request resolved to, for the log line.
#[derive(Clone, Copy)]
enum Kind {
    Asset,
    Public,
    Flight,
    Page,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Asset => "asset",
            Kind::Public => "public file",
            Kind::Flight => "flight data",
            Kind::Page => "page",
        }
    }

    fn cache_control(self) -> &'static str {
        match self {
            Kind::Asset => IMMUTABLE,
            Kind::Public => PUBLIC_FILE,
            Kind::Flight | Kind::Page => REVALIDATE,
        }
    }
}

impl ClientApp {
    /// Reads the export's routes. `None` (logged) when the directory is missing or
    /// unreadable, in which case non-API paths keep answering like the Node backend.
    pub fn load(dir: &Path) -> Option<Self> {
        if !dir.join("index.html").is_file() {
            tracing::warn!(
                dir = %dir.display(),
                "client export not found (no index.html); the dashboard is not served, non-API paths answer 404"
            );
            return None;
        }
        match RouteTree::scan(dir) {
            Ok(routes) => {
                if !dir.join("404.html").is_file() {
                    tracing::warn!(dir = %dir.display(), "client export has no 404.html; unknown paths get an empty 404");
                }
                tracing::info!(dir = %dir.display(), pages = routes.page_count(), "client export loaded");
                Some(Self { dir: dir.to_path_buf(), routes })
            }
            Err(error) => {
                tracing::error!(dir = %dir.display(), error = %error, "could not read the client export");
                None
            }
        }
    }

    /// Answers a non-API request. `public_dir` is the backend's own public/ directory
    /// (tracking scripts), which is served at the root after the export's files.
    pub async fn respond(&self, method: &Method, uri: &Uri, request_headers: &HeaderMap, public_dir: &Path) -> Response {
        let path = uri.path();
        let query = uri.query();

        // Next normalised URLs before anything else, for every method
        if let Some(redirect) = redirects::repeated_slashes(path, query).or_else(|| redirects::trailing_slash(path, query))
        {
            return redirect_response(path, redirect);
        }
        if let Some(redirect) = redirects::proxy(path, query) {
            return redirect_response(path, redirect);
        }

        let head = method == Method::HEAD;
        if method == Method::GET || head {
            if path.starts_with("/_next/static/") {
                return match self.exported_file(path) {
                    Some(file) => match serve_file(&file, Kind::Asset, request_headers, head).await {
                        Ok(response) => response,
                        Err(error) => io_failure(&file, &error),
                    },
                    None => asset_not_found(path),
                };
            }

            if let Some(file) = self.exported_file(path) {
                let kind = if path.ends_with(".txt") { Kind::Flight } else { Kind::Public };
                match serve_file(&file, kind, request_headers, head).await {
                    Ok(response) => return response,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return io_failure(&file, &error),
                }
            }

            if let Some(response) = static_files::public_file(public_dir, path, request_headers).await {
                tracing::debug!(path, "served backend public file");
                return response;
            }

            if let Some(response) = self.flight_data(path, query, request_headers, head).await {
                return response;
            }
        }

        if let Some(page) = self.routes.find(path) {
            let file = self.dir.join(page).with_extension("html");
            return match serve_file(&file, Kind::Page, request_headers, head).await {
                Ok(response) => response,
                Err(error) => io_failure(&file, &error),
            };
        }

        self.not_found(method, path, head).await
    }

    /// Flight data the client router fetches for a page it navigates to:
    /// `/12/main.txt` for the page, `/12/main/__next.<segment>.txt` for one segment
    /// of it. Pages of dynamic routes are exported once, so the file comes from the
    /// placeholder page the URL matches.
    async fn flight_data(&self, path: &str, query: Option<&str>, request_headers: &HeaderMap, head: bool) -> Option<Response> {
        let (route, segment_file) = match path.rsplit_once('/') {
            Some((route, last)) if last.starts_with("__next.") && last.ends_with(".txt") => {
                (if route.is_empty() { "/" } else { route }, Some(decode_segment(last)?))
            }
            _ => (path.strip_suffix(".txt")?, None),
        };

        // A navigation to /12 fetches /12.txt; Next's middleware redirected the RSC
        // request like the page, and the router follows the redirect
        if segment_file.is_none()
            && let Some(Redirect::Temporary { location, reason }) = redirects::proxy(route, query)
            && reason != "oauth callback"
        {
            let location = match location.split_once('?') {
                Some((target, search)) => format!("{target}.txt?{search}"),
                None => format!("{location}.txt"),
            };
            return Some(redirect_response(path, Redirect::Temporary { location, reason }));
        }

        let page = self.routes.find(route)?;
        let file = match segment_file {
            Some(name) => self.dir.join(page).join(name),
            None => self.dir.join(page).with_extension("txt"),
        };
        match serve_file(&file, Kind::Flight, request_headers, head).await {
            Ok(response) => Some(response),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                tracing::debug!(path, file = %file.display(), "no flight data for this page");
                None
            }
            Err(error) => Some(io_failure(&file, &error)),
        }
    }

    /// A file of the export named by the URL path, other than a page's HTML (pages
    /// are only reachable through their route, as they were under Next).
    fn exported_file(&self, path: &str) -> Option<PathBuf> {
        let mut file = self.dir.clone();
        for segment in path.strip_prefix('/')?.split('/') {
            file.push(decode_segment(segment)?);
        }
        let is_page = file.extension().is_some_and(|extension| extension == "html");
        (!is_page && file.is_file()).then_some(file)
    }

    async fn not_found(&self, method: &Method, path: &str, head: bool) -> Response {
        tracing::debug!(method = %method, path, "no page matches; serving the not-found page");
        let file = self.dir.join("404.html");
        let body = match tokio::fs::read(&file).await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(file = %file.display(), error = %error, "could not read the not-found page");
                Vec::new()
            }
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(NOT_FOUND_PAGE));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        let body = if head { Body::empty() } else { Body::from(body) };
        (StatusCode::NOT_FOUND, headers, body).into_response()
    }
}

/// One path segment, percent-decoded. `None` for anything that could leave the
/// export directory or name a hidden file.
fn decode_segment(segment: &str) -> Option<String> {
    let decoded = percent_decode_str(segment).decode_utf8().ok()?;
    let safe = !decoded.is_empty()
        && !decoded.starts_with('.')
        && !decoded.contains(['/', '\\', '\0']);
    safe.then(|| decoded.into_owned())
}

fn redirect_response(from: &str, redirect: Redirect) -> Response {
    let (status, location, reason) = match redirect {
        Redirect::Permanent { location, reason } => (StatusCode::PERMANENT_REDIRECT, location, reason),
        Redirect::Temporary { location, reason } => (StatusCode::TEMPORARY_REDIRECT, location, reason),
    };
    tracing::info!(from, to = %location, status = status.as_u16(), reason, "client redirect");

    let Ok(location_value) = HeaderValue::from_str(&location) else {
        tracing::error!(from, to = %location, "redirect target is not a valid header value");
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut headers = HeaderMap::new();
    if status == StatusCode::PERMANENT_REDIRECT {
        headers.insert(header::LOCATION, location_value);
        if let Ok(refresh) = HeaderValue::from_str(&format!("0;url={location}")) {
            headers.insert(header::REFRESH, refresh);
        }
    } else {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store, max-age=0"));
        headers.insert(header::LOCATION, location_value);
    }
    // Next wrote the target as the body too, without a content type, and streamed it
    // (a body of unknown length also keeps Caddy from sniffing a content type)
    let body = Body::from_stream(ReaderStream::new(io::Cursor::new(location.into_bytes())));
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// A missing build asset: Next's plain-text 404.
fn asset_not_found(path: &str) -> Response {
    tracing::debug!(path, "no such build asset");
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(NOT_FOUND_PAGE));
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    (StatusCode::NOT_FOUND, headers, "Not Found").into_response()
}

fn io_failure(file: &Path, error: &io::Error) -> Response {
    tracing::error!(file = %file.display(), error = %error, "could not read a client export file");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
}

async fn serve_file(file: &Path, kind: Kind, request_headers: &HeaderMap, head: bool) -> io::Result<Response> {
    let metadata = tokio::fs::metadata(file).await?;
    if !metadata.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "not a file"));
    }
    let modified = metadata.modified().ok();
    let etag = static_files::stat_etag(metadata.len(), modified);

    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(kind.cache_control()));
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type(file)));
    if let Some(value) = modified.map(httpdate::fmt_http_date).and_then(|date| HeaderValue::from_str(&date).ok()) {
        headers.insert(header::LAST_MODIFIED, value);
    }
    if let Ok(value) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, value);
    }

    if static_files::is_fresh(request_headers, &etag, modified) {
        tracing::debug!(file = %file.display(), kind = kind.as_str(), "not modified");
        return Ok((StatusCode::NOT_MODIFIED, headers).into_response());
    }

    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(metadata.len()));
    tracing::debug!(file = %file.display(), kind = kind.as_str(), bytes = metadata.len(), head, "serving");
    if head {
        return Ok((StatusCode::OK, headers).into_response());
    }
    let stream = ReaderStream::with_capacity(tokio::fs::File::open(file).await?, 64 * 1024);
    Ok((StatusCode::OK, headers, Body::from_stream(stream)).into_response())
}

fn content_type(file: &Path) -> &'static str {
    match file.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        // Flight data: the client router accepts text/plain from a static host
        Some("txt") => "text/plain; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=UTF-8",
        Some("css") => "text/css; charset=UTF-8",
        Some("json" | "map") => "application/json; charset=UTF-8",
        Some("geojson") => "application/geo+json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("avif") => "image/avif",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("wasm") => "application/wasm",
        Some("webmanifest") => "application/manifest+json",
        Some("xml") => "application/xml",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests;
