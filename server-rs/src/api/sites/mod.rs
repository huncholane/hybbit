//! Site settings, exclusions, private links, usage, embed stats, imports and check-install, ported from server/src/api/sites.

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
