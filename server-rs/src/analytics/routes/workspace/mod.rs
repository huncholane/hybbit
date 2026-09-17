//! Annotations, dashboards, segments and custom SQL.

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
