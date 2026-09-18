//! Site settings, exclusions, private links, usage, embed stats, imports and
//! check-install, ported from `sitesRoutes` in server/src/index.ts and the
//! handlers under server/src/api/sites (plus the site half of
//! server/src/api/organizationExclusions/organizationExcludedIPs.ts).
//!
//! Routing mirrors find-my-way where axum's matcher differs:
//! - a parameter may be empty (`/api/sites/` reaches getSite with `""`, and
//!   `/api/sites/1/imports/` the `:importId` handlers), so every route is also
//!   registered with each combination of its parameters left empty;
//! - find-my-way keeps one tree per method, so a method a path does not register
//!   gets Fastify's plain 404. That is registered explicitly, because axum's
//!   method-not-allowed fallback would add an `Allow` header.
//!
//! Guard chains, from `sitesRoutes`:
//! - `publicSitesRead` = resolveSiteId, allowPublicSiteAccess(sites:read), validateTimeParams, expandSegmentParam
//! - `authSitesRead`   = resolveSiteId, requireSiteAccess(sites:read), validateTimeParams, expandSegmentParam
//! - `adminSitesRead`  = resolveSiteId, requireSiteAdminAccess(sites:read), validateTimeParams
//! - `adminSitesWrite` = resolveSiteId, requireSiteAdminAccess(sites:write), validateTimeParams
//! - embed-stats runs `resolveSiteId` alone, and check-install no preHandler at all.
// Early replies travel as `Err(Response)`, the shape `analytics::chain` hands back
#![allow(clippy::result_large_err)]

use axum::{
    Router,
    routing::{MethodFilter, MethodRouter, delete, get, post, put},
};

use crate::{http::errors, state::AppState};

mod check_install;
mod config;
mod delete_site;
mod embed_stats;
mod exclusions;
mod import_mappers;
mod imports;
mod lifecycle;
mod move_site;
mod private_link;
mod request;
mod site;
mod usage;

/// Every spelling of `pattern` with any subset of its `{param}` segments empty,
/// so a request find-my-way matches with an empty parameter reaches the handler
/// rather than the router's fallback.
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

/// Route every method the path does not register to the 404 handler, which is
/// what find-my-way's per-method trees produce.
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
    // HEAD is answered by the GET handler wherever one is registered
    let answered = |name: &str| registered.contains(&name) || (name == "HEAD" && registered.contains(&"GET"));
    all.into_iter()
        .filter(|(name, _)| !answered(name))
        .fold(handlers, |handlers, (_, filter)| handlers.on(filter, errors::not_found))
}

pub fn router() -> Router<AppState> {
    let routes: Vec<(&str, MethodRouter<AppState>, &[&str])> = vec![
        ("/api/sites/{siteId}", get(site::get_site).delete(delete_site::delete_site), &["GET", "DELETE"]),
        ("/api/sites/{siteId}/config", put(config::update_site_config), &["PUT"]),
        ("/api/sites/{siteId}/move", put(move_site::move_site), &["PUT"]),
        (
            "/api/sites/{siteId}/private-link-config",
            get(private_link::get_private_link_config).post(private_link::update_private_link_config),
            &["GET", "POST"],
        ),
        ("/api/sites/{siteId}/excluded-ips", get(exclusions::excluded_ips), &["GET"]),
        ("/api/sites/{siteId}/excluded-countries", get(exclusions::excluded_countries), &["GET"]),
        ("/api/sites/{siteId}/excluded-paths", get(exclusions::excluded_paths), &["GET"]),
        ("/api/sites/{siteId}/excluded-hostnames", get(exclusions::excluded_hostnames), &["GET"]),
        ("/api/sites/{siteId}/excluded-user-agents", get(exclusions::excluded_user_agents), &["GET"]),
        ("/api/sites/{siteId}/excluded-asns", get(exclusions::excluded_asns), &["GET"]),
        ("/api/sites/{siteId}/excluded-query-params", get(exclusions::excluded_query_params), &["GET"]),
        (
            "/api/sites/{siteId}/organization-excluded-ips",
            get(exclusions::organization_excluded_ips),
            &["GET"],
        ),
        ("/api/sites/{siteId}/usage", get(usage::get_site_usage), &["GET"]),
        ("/api/sites/{siteId}/embed-stats", get(embed_stats::get_embed_stats), &["GET"]),
        ("/api/sites/{siteId}/imports", get(imports::list).post(imports::create), &["GET", "POST"]),
        ("/api/sites/{siteId}/imports/{importId}", delete(imports::delete_import), &["DELETE"]),
        ("/api/sites/{siteId}/imports/{importId}/events", post(imports::batch_events), &["POST"]),
        ("/api/site/check-install", get(check_install::check_install), &["GET"]),
    ];
    routes.into_iter().fold(Router::new(), |router, (pattern, handlers, registered)| {
        with_empty_params(router, pattern, complete(handlers, registered))
    })
}
