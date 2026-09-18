//! The preHandler chains `organizationsRoutes`, `teamsRoutes` and `userRoutes`
//! register with in server/src/index.ts.
//!
//! `orgMemberScoped`/`orgAdminScoped`/`authOnlyScoped` are
//! `analytics::chain::{org_scoped, account_scoped}` and are reused as they are. The
//! two chains only these routes use are here, because they have no
//! `validateTimeParams` step:
//!
//! - `authOnlyNoScopedKeys` = `[requireAuth("deny-scoped")]`
//! - `orgAdminNoScopedKeys` = `[requireOrgAdminFromParams("deny-scoped")]`
//!
//! `GET /api/organizations` and the one-click unsubscribe routes have no chain at
//! all; their handlers resolve the caller themselves.

use axum::{
    http::{HeaderMap, Uri},
    response::Response,
};

use crate::{
    analytics::{
        chain::fastify_query,
        js::{JsObject, JsValue},
    },
    auth::guards::{AuthContext, Authenticated, RouteScope},
    state::AppState,
};

/// What a chain hands a handler: the principal and Fastify's parsed query string.
pub struct Request {
    pub auth: Authenticated,
    pub query: JsObject,
}

/// `?api_key=` as `checkApiKey` reads it (a repeated parameter is an array and is
/// ignored, matching `typeof request.query.api_key === "string"`).
fn query_api_key(query: &JsObject) -> Option<String> {
    query.get("api_key").and_then(JsValue::as_str).map(str::to_string)
}

/// `authOnlyNoScopedKeys`: `requireAuth("deny-scoped")` and nothing else.
pub async fn auth_only_no_scoped_keys(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<Request, Response> {
    let query = fastify_query(uri);
    let context = AuthContext::new(state, headers, query_api_key(&query));
    let auth = context.require_auth(Some(RouteScope::DenyScoped), None, None).await?;
    Ok(Request { auth, query })
}

/// `orgAdminNoScopedKeys`: `requireOrgAdminFromParams("deny-scoped")` and nothing else.
pub async fn org_admin_no_scoped_keys(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    organization_id: &str,
) -> Result<Request, Response> {
    let query = fastify_query(uri);
    let context = AuthContext::new(state, headers, query_api_key(&query));
    let auth = context.require_org_admin(Some(organization_id), Some(RouteScope::DenyScoped)).await?;
    Ok(Request { auth, query })
}

/// An unguarded route: only Fastify's query parsing runs before the handler.
pub fn unguarded(uri: &Uri) -> JsObject {
    fastify_query(uri)
}

/// The `AuthContext` an unguarded handler builds to resolve the caller itself
/// (`getUserIdFromRequest`, `getSessionFromReq`).
pub fn context<'a>(state: &'a AppState, headers: &'a HeaderMap, query: &JsObject) -> AuthContext<'a> {
    AuthContext::new(state, headers, query_api_key(query))
}
