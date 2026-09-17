//! Sessions, events, users, user traits and error tracking.
//!
//! Registrations follow `analyticsRoutes` in server/src/index.ts, adjusted for two
//! ways find-my-way matches where axum does not:
//!
//! - find-my-way keeps a separate tree per method, so a static segment registered
//!   for one method never hides a parameter route of another: `GET
//!   /users/identify` is getUserInfo for the user "identify" and `DELETE
//!   /users/session-count` deletes the user "session-count". axum shares one tree
//!   across methods, so those static paths carry the parameter route's handlers
//!   for the other methods.
//! - find-my-way matches an empty parameter (`/sessions/` is getSession for the
//!   session ""), axum does not, so every route is also registered with each
//!   combination of its parameters left empty.

use axum::{
    Router,
    routing::{MethodRouter, get, post, put},
};

use crate::state::AppState;

mod common;
pub mod errors;
pub mod events;
pub mod sessions;
pub mod user_traits;
pub mod user_writes;
pub mod users;

/// Every spelling of `path` with any subset of its `{param}` segments empty.
fn empty_param_variants(path: &str) -> Vec<String> {
    let segments: Vec<&str> = path.split('/').collect();
    let params: Vec<usize> =
        segments.iter().enumerate().filter(|(_, segment)| segment.starts_with('{')).map(|(index, _)| index).collect();
    (0..1usize << params.len())
        .map(|mask| {
            segments
                .iter()
                .enumerate()
                .map(|(index, segment)| match params.iter().position(|param| *param == index) {
                    Some(bit) if mask & (1 << bit) != 0 => "",
                    _ => segment,
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect()
}

/// `router.route(path, handler)` for `path` and its empty-parameter spellings.
fn route(router: Router<AppState>, path: &str, handler: MethodRouter<AppState>) -> Router<AppState> {
    empty_param_variants(path).into_iter().fold(router, |router, variant| router.route(&variant, handler.clone()))
}

pub fn router() -> Router<AppState> {
    let routes: Vec<(&str, MethodRouter<AppState>)> = vec![
        // Sessions (publicSessionsRead)
        ("/api/sites/{siteId}/sessions", get(sessions::get_sessions)),
        ("/api/sites/{siteId}/sessions/locations", get(sessions::get_session_locations)),
        ("/api/sites/{siteId}/sessions/{sessionId}", get(sessions::get_session)),
        // Events (publicEventsRead)
        ("/api/sites/{siteId}/events", get(events::get_events)),
        ("/api/sites/{siteId}/events/time-series", get(events::get_event_bucketed)),
        ("/api/sites/{siteId}/events/names", get(events::get_event_names)),
        ("/api/sites/{siteId}/events/properties", get(events::get_event_properties)),
        ("/api/sites/{siteId}/events/autocapture", get(events::get_autocapture_events)),
        ("/api/sites/{siteId}/events/autocapture-values", get(events::get_autocapture_values)),
        ("/api/sites/{siteId}/events/outbound", get(events::get_outbound_links)),
        // Errors (publicAnalyticsRead)
        ("/api/sites/{siteId}/errors/names", get(errors::get_error_names)),
        ("/api/sites/{siteId}/errors/events", get(errors::get_error_events)),
        ("/api/sites/{siteId}/errors/time-series", get(errors::get_error_bucketed)),
        // Users (publicUsersRead, authUsersWrite, adminUsersWrite)
        ("/api/sites/{siteId}/users", get(users::get_users)),
        (
            "/api/sites/{siteId}/users/session-count",
            get(users::get_user_session_count).delete(user_writes::delete_user),
        ),
        (
            "/api/sites/{siteId}/users/identify",
            post(user_writes::identify_user).get(users::get_user_info).delete(user_writes::delete_user),
        ),
        ("/api/sites/{siteId}/users/{userId}", get(users::get_user_info).delete(user_writes::delete_user)),
        ("/api/sites/{siteId}/users/{userId}/traits", put(user_writes::update_user_traits)),
        // User traits (publicUsersRead)
        ("/api/sites/{siteId}/user-traits/keys", get(user_traits::get_user_trait_keys)),
        ("/api/sites/{siteId}/user-traits/values", get(user_traits::get_user_trait_values)),
        ("/api/sites/{siteId}/user-traits/users", get(user_traits::get_user_trait_value_users)),
    ];
    routes.into_iter().fold(Router::new(), |router, (path, handler)| route(router, path, handler))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_parameter_spellings() {
        assert_eq!(empty_param_variants("/api/sites/{siteId}/events"), ["/api/sites/{siteId}/events", "/api/sites//events"]);
        assert_eq!(
            empty_param_variants("/api/sites/{siteId}/users/{userId}/traits"),
            [
                "/api/sites/{siteId}/users/{userId}/traits",
                "/api/sites//users/{userId}/traits",
                "/api/sites/{siteId}/users//traits",
                "/api/sites//users//traits",
            ]
        );
    }
}
