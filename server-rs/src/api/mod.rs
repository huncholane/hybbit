//! The settings-side API: everything the dashboard's management screens call.
//! Each group is its own module so the ports land independently.

use axum::Router;

use crate::state::AppState;

pub mod sites;
pub mod orgs;
pub mod admin;

/// Every settings-side route.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(sites::router())
        .merge(orgs::router())
        .merge(admin::router())
}
