//! Caller resolution the handlers do for themselves, ported from
//! server/src/lib/auth-utils.ts (`getUserIdFromRequest`, `wasRateLimited`) and the
//! site-access cache invalidation every write in this group performs.

use axum::http::HeaderMap;
use tracing::debug;

use crate::{
    analytics::js::JsObject,
    auth::{
        bearer::{BearerIdentityStatus, resolve_bearer_identity},
        bearer_token,
        guards::AuthContext,
        session::AuthSession,
    },
    state::AppState,
};

/// `getUserIdFromRequest`: the session user, then a bearer credential's user.
///
/// Unlike the guards this does **not** go through `checkApiKey`, so it needs no
/// organization or site target: a user-owned API key resolves to its user
/// wherever it is sent. Organization-owned keys carry no user and resolve to
/// `None`, as in Node.
pub async fn user_id_from_request(
    state: &AppState,
    headers: &HeaderMap,
    query: &JsObject,
    context: &AuthContext<'_>,
) -> Result<Option<String>, axum::response::Response> {
    if let Some(session) = context.session().await? {
        return Ok(Some(session.user_id));
    }
    let authorization = headers.get(axum::http::header::AUTHORIZATION).and_then(|value| value.to_str().ok());
    let query_api_key = query.get("api_key").and_then(crate::analytics::js::JsValue::as_str);
    let Some(token) = bearer_token(authorization, query_api_key) else { return Ok(None) };
    let identity = resolve_bearer_identity(&state.pg, token).await;
    if identity.status == BearerIdentityStatus::Valid
        && let Some(user_id) = identity.user_id
    {
        return Ok(Some(user_id));
    }
    debug!(status = ?identity.status, "Bearer credential resolved to no user");
    Ok(None)
}

/// `getSessionFromReq(request)` for handlers that need the session itself.
pub async fn session(context: &AuthContext<'_>) -> Result<Option<AuthSession>, axum::response::Response> {
    context.session().await
}

/// `invalidateSitesAccessCache(userId)`
pub fn invalidate_sites_access(state: &AppState, user_id: &str) {
    state.sites_access.invalidate_user(user_id);
    debug!(user_id, "Invalidated the site access cache");
}
