//! Overview, metrics, page titles, retention, journeys, live users, site data checks and event counts.

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
