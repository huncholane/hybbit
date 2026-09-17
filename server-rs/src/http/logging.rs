//! Request logs, ported from server/src/lib/logger/requestLogging.ts.

use std::time::Instant;

use axum::{extract::MatchedPath, extract::Request, middleware::Next, response::Response};

/// Routes Node registers with `logLevel: "silent"`.
fn is_silent(route: &str) -> bool {
    route == "/api/health" || route == "/api/sites/{siteId}/live-user-count"
}

/// Successful responses on these are logged at debug: they fire on every tracked page.
fn is_high_volume(route: &str) -> bool {
    matches!(route, "/api/identify" | "/api/metrics.js" | "/api/replay.js" | "/api/script.js" | "/api/track")
        || route.ends_with("/session-replay/record/{siteId}")
}

pub async fn request_log(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let url = req.uri().path().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| url.clone());
    let started = Instant::now();

    let response = next.run(req).await;

    if is_silent(&route) {
        return response;
    }

    let status = response.status().as_u16();
    let response_time_ms = (started.elapsed().as_secs_f64() * 100_000.0).round() / 100.0;
    let method = method.as_str();

    if status >= 500 {
        tracing::error!(method, url, route, status_code = status, response_time_ms, "Request completed with server error");
    } else if status >= 400 {
        tracing::warn!(method, url, route, status_code = status, response_time_ms, "Request completed with client error");
    } else if is_high_volume(&route) {
        tracing::debug!(method, url, route, status_code = status, response_time_ms, "Request completed");
    } else {
        tracing::info!(method, url, route, status_code = status, response_time_ms, "Request completed");
    }

    response
}
