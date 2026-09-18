//! Organizations, teams, members, account settings and API keys, ported from server/src/api/user, server/src/api/teams, server/src/api/memberAccess and server/src/api/organizationExclusions.

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
