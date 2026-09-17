//! Funnels, goals, performance (web vitals) and bot analytics.

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
