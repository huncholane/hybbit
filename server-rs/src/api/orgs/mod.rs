//! Organizations, teams, members, account settings and API keys, ported from
//! server/src/api/user, server/src/api/teams, server/src/api/memberAccess and
//! server/src/api/organizationExclusions.
//!
//! Registration follows `organizationsRoutes`, `teamsRoutes` and `userRoutes` in
//! server/src/index.ts, adjusted for two ways find-my-way matches where axum does
//! not:
//!
//! - find-my-way keeps a separate tree per method, so a path registered for one
//!   method is a plain 404 for every other. axum shares one tree, so each path
//!   routes the methods it does not register to the 404 handler explicitly (its
//!   method-not-allowed fallback would add an `Allow` header Node never sends).
//! - find-my-way matches an empty parameter (`/api/organizations//teams` reaches
//!   `listTeams` with the organization ""), axum does not, so every route is also
//!   registered with each combination of its parameters left empty.

// Early replies travel as `Err(Response)`, the shape `analytics::chain` hands back
#![allow(clippy::result_large_err)]

use axum::{
    Router,
    routing::{MethodFilter, MethodRouter, get, post, put},
};

use crate::{http::errors, state::AppState};

mod access;
mod account;
mod api_keys;
mod chain;
mod exclusions;
mod js;
mod members;
mod org_sites;
mod organizations;
mod request;
mod signed_token;
mod teams;
mod zod;

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
    // HEAD is answered by the GET handler wherever one is registered
    let answered = |name: &str| registered.contains(&name) || (name == "HEAD" && registered.contains(&"GET"));
    all.into_iter()
        .filter(|(name, _)| !answered(name))
        .fold(handlers, |handlers, (_, filter)| handlers.on(filter, errors::not_found))
}

pub fn router() -> Router<AppState> {
    let routes: Vec<(&str, MethodRouter<AppState>, &[&str])> = vec![
        ("/api/organizations", get(organizations::get_my_organizations), &["GET"]),
        ("/api/user/organizations", get(organizations::get_user_organizations), &["GET"]),
        ("/api/organizations/{organizationId}/sites", get(org_sites::list).post(org_sites::create), &["GET", "POST"]),
        ("/api/organizations/{organizationId}/members", get(members::list).post(members::add_user), &["GET", "POST"]),
        ("/api/organizations/{organizationId}/users", post(members::create_user), &["POST"]),
        (
            "/api/organizations/{organizationId}/members/{memberId}/sites",
            put(members::update_site_access),
            &["PUT"],
        ),
        (
            "/api/organizations/{organizationId}/excluded-ips",
            get(exclusions::get).put(exclusions::update),
            &["GET", "PUT"],
        ),
        ("/api/organizations/{organizationId}/teams", get(teams::list).post(teams::create), &["GET", "POST"]),
        (
            "/api/organizations/{organizationId}/teams/{teamId}",
            put(teams::update).delete(teams::delete),
            &["PUT", "DELETE"],
        ),
        ("/api/organizations/{organizationId}/api-keys", post(api_keys::create_org_key), &["POST"]),
        ("/api/organizations/{organizationId}/api-usage", get(api_keys::org_api_usage), &["GET"]),
        ("/api/user/account-settings", post(account::update_settings), &["POST"]),
        ("/api/user/unsubscribe-marketing", post(account::unsubscribe), &["POST"]),
        (
            "/api/user/unsubscribe-marketing-oneclick",
            get(account::one_click_unsubscribe).post(account::one_click_unsubscribe),
            &["GET", "POST"],
        ),
        ("/api/user/api-keys", post(api_keys::create_user_key), &["POST"]),
    ];
    routes.into_iter().fold(Router::new(), |router, (pattern, handlers, registered)| {
        with_empty_params(router, pattern, complete(handlers, registered))
    })
}
