//! The admin panel API plus feature flag and experiment management, ported from server/src/api/admin, server/src/api/featureFlags and server/src/api/experiments.

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
