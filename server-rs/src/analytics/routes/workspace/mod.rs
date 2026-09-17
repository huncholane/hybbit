//! Annotations, dashboards, segments and custom SQL: the routes server/src/index.ts
//! registers with `authAnnotationsWrite`/`publicAnnotationsRead`,
//! `authDashboardsRead`/`authDashboardsWrite`, `publicSegmentsRead`/
//! `authSegmentsWrite` and `orgSqlRead` (with their rate limits).
//!
//! Routing mirrors find-my-way where axum's matcher differs:
//! - a parameter may be empty (`/api/sites/1/segments/` reaches the `:segmentId`
//!   handlers with `""`, and `/api/sites//segments` the site handlers), so those
//!   shapes are registered explicitly;
//! - `/dashboards/run-card` is only a POST route; GET, PUT and DELETE on that path
//!   reach the `:dashboardId` handlers with `run-card` as the id;
//! - a method a path does not register gets Fastify's plain 404. It is registered
//!   explicitly, because axum's method-not-allowed fallback adds an `Allow` header.
//!
//! Handlers read their parameters from the raw path with find-my-way's decoding
//! and 404 past `maxParamLength` (see `request`).

use axum::{
    Router,
    routing::{MethodFilter, MethodRouter, get, post, put},
};

use crate::{http::errors, state::AppState};

mod access;
mod annotation_schema;
mod annotations;
mod custom_query;
mod dashboard_schema;
mod dashboards;
mod generate;
mod luxon;
mod openrouter;
mod rate_limit;
mod request;
mod schema;
mod segments;

/// The same handlers under every combination of empty and non-empty parameters.
fn with_empty_params(mut router: Router<AppState>, pattern: &str, handlers: MethodRouter<AppState>) -> Router<AppState> {
    let segments: Vec<&str> = pattern.split('/').collect();
    let params: Vec<usize> =
        segments.iter().enumerate().filter(|(_, segment)| segment.starts_with('{')).map(|(index, _)| index).collect();
    for mask in 0..(1usize << params.len()) {
        let path: Vec<&str> = segments
            .iter()
            .enumerate()
            .map(|(index, segment)| match params.iter().position(|param| *param == index) {
                Some(bit) if mask & (1 << bit) != 0 => "",
                _ => segment,
            })
            .collect();
        router = router.route(&path.join("/"), handlers.clone());
    }
    router
}

/// Route every method the path does not register to the 404 handler.
fn complete(handlers: MethodRouter<AppState>, registered: &[&str]) -> MethodRouter<AppState> {
    let all = [
        ("GET", MethodFilter::GET),
        ("HEAD", MethodFilter::HEAD),
        ("POST", MethodFilter::POST),
        ("PUT", MethodFilter::PUT),
        ("DELETE", MethodFilter::DELETE),
        ("PATCH", MethodFilter::PATCH),
        ("OPTIONS", MethodFilter::OPTIONS),
        ("TRACE", MethodFilter::TRACE),
        ("CONNECT", MethodFilter::CONNECT),
    ];
    let has_get = registered.contains(&"GET");
    all.into_iter()
        .filter(|(name, _)| !registered.contains(name) && !(*name == "HEAD" && has_get))
        .fold(handlers, |handlers, (_, filter)| handlers.on(filter, errors::not_found))
}

pub fn router() -> Router<AppState> {
    let routes: Vec<(&str, MethodRouter<AppState>, &[&str])> = vec![
        ("/api/sites/{siteId}/annotations", get(annotations::list).post(annotations::create), &["GET", "POST"]),
        ("/api/sites/{siteId}/annotations/{annotationId}", put(annotations::update).delete(annotations::delete), &["PUT", "DELETE"]),
        ("/api/sites/{siteId}/dashboards", get(dashboards::list).post(dashboards::create), &["GET", "POST"]),
        (
            "/api/sites/{siteId}/dashboards/run-card",
            post(custom_query::run_card).get(dashboards::get_one).put(dashboards::update).delete(dashboards::delete),
            &["POST", "GET", "PUT", "DELETE"],
        ),
        (
            "/api/sites/{siteId}/dashboards/{dashboardId}",
            get(dashboards::get_one).put(dashboards::update).delete(dashboards::delete),
            &["GET", "PUT", "DELETE"],
        ),
        ("/api/sites/{siteId}/segments", get(segments::list).post(segments::create), &["GET", "POST"]),
        (
            "/api/sites/{siteId}/segments/{segmentId}",
            get(segments::get_one).put(segments::update).delete(segments::delete),
            &["GET", "PUT", "DELETE"],
        ),
        ("/api/organizations/{organizationId}/analytics/query", post(custom_query::run_custom_query), &["POST"]),
        ("/api/organizations/{organizationId}/analytics/query/generate", post(generate::generate), &["POST"]),
    ];
    routes.into_iter().fold(Router::new(), |router, (pattern, handlers, registered)| {
        with_empty_params(router, pattern, complete(handlers, registered))
    })
}
