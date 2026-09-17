//! Dashboard analytics routes, ported from server/src/api/analytics. Each group is
//! its own module so the ports land independently; `router` mounts them all.

use axum::Router;

use crate::state::AppState;

pub mod overview;
pub mod people;
pub mod reports;
pub mod workspace;

/// Every analytics route.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(overview::router())
        .merge(people::router())
        .merge(reports::router())
        .merge(workspace::router())
}
