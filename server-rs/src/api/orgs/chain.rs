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
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use serde_json::json;

use crate::{
    analytics::{
        chain::fastify_query,
        js::{JsObject, JsValue},
        utils::query_validation::validate_http_time_params,
    },
    auth::guards::{AuthContext, Authenticated, RouteScope},
    http,
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

/// `authOnlyScoped(resource, action)` on a path that carries an `:organizationId`.
///
/// `requireAuth` reads the organization from `request.params` and hands it to
/// `checkApiKey`, so a bearer credential is verified against that organization: an
/// organization key for it is admitted (subject to the scope), a user key needs a
/// membership there, and a key for another organization is rejected. That is the
/// difference from `analytics::chain::account_scoped`, which has no parameters to
/// read.
pub async fn auth_only_scoped(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    organization_id: &str,
    route_scope: Option<RouteScope>,
) -> Result<Request, Response> {
    let query = fastify_query(uri);
    let context = AuthContext::new(state, headers, query_api_key(&query));
    let auth = context.require_auth(route_scope, Some(organization_id), None).await?;
    // `validateTimeParams`
    if let Some(message) = validate_http_time_params(&JsValue::Object(query.clone())) {
        return Err(http::json(StatusCode::BAD_REQUEST, &json!({ "error": message })));
    }
    Ok(Request { auth, query })
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
