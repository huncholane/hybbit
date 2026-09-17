use axum::{Router, routing::get};

use crate::state::AppState;

mod health;

/// Every route this service answers. Paths match the Node backend exactly, because
/// Caddy switches them over to this service one area at a time.
pub fn router(state: AppState) -> Router {
    Router::new().route("/api/health", get(health::health)).with_state(state)
}
