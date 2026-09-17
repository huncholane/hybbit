//! Route guards, ported from server/src/lib/auth-middleware.ts.
//!
//! Handlers call one guard first and get either the authenticated principal or the
//! exact response Node's preHandler would have sent (the error body rewrite in
//! `http::errors` then fills in `code`, `message` and `resolution` as it does for
//! every error). Scopes constrain bearer credentials only; cookie sessions bypass
//! them.
//!
//! Per-request memoisation: Node resolves the cookie session up to three times per
//! guard and verifies a bearer credential once per guard. Rust resolves each once
//! per request; the database effects are the same idempotent writes.

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use tokio::sync::OnceCell;
use tracing::error;

use super::{
    AccessTarget, BearerAuthResult,
    access::{AccessPrincipal, get_org_membership, is_system_admin},
    bearer_token, check_api_key,
    scopes::{ScopeRequirement, has_scope},
    session::{AuthSession, get_session},
};
use crate::{site_config::SiteRef, state::AppState};

/// `RouteScope`: what a bearer credential must be granted on this route.
#[derive(Clone, Copy, Debug)]
pub enum RouteScope {
    Require(ScopeRequirement),
    /// Scoped (and organization-owned) credentials are rejected outright
    DenyScoped,
}

pub const fn scope(resource: &'static str, action: &'static str) -> Option<RouteScope> {
    Some(RouteScope::Require(ScopeRequirement { resource, action }))
}

/// The principal a guard admitted.
#[derive(Clone, Debug, Default)]
pub struct Authenticated {
    /// `request.user.id`: the session user or a user-owned bearer credential
    pub user_id: Option<String>,
    /// `request.apiKeyOrganizationId`: set for organization-owned API keys
    pub api_key_organization_id: Option<String>,
    /// `request.bearerAuth`
    pub bearer: bool,
    /// `request.bearerStatements` (None = unrestricted)
    pub statements: Option<super::scopes::ScopeStatements>,
    /// The cookie session, when that is how the request authenticated
    pub session: Option<AuthSession>,
}

impl Authenticated {
    pub fn principal(&self) -> AccessPrincipal {
        AccessPrincipal { user_id: self.user_id.clone(), api_key_organization_id: self.api_key_organization_id.clone() }
    }
}

/// One request's view of its credentials.
pub struct AuthContext<'a> {
    pub state: &'a AppState,
    pub headers: &'a HeaderMap,
    /// `?api_key=` when it appeared exactly once
    pub query_api_key: Option<String>,
    session: OnceCell<Option<AuthSession>>,
}

type GuardResult = Result<Authenticated, Response>;

fn reply(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn internal_error(err: impl std::fmt::Display) -> Response {
    error!(error = %err, "Auth guard failed");
    reply(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"statusCode": 500, "error": "Internal Server Error", "message": "Internal Server Error"}),
    )
}

fn forbidden() -> Response {
    reply(StatusCode::FORBIDDEN, json!({"error": "Forbidden"}))
}

/// `sendInsufficientScope`
fn insufficient_scope(scope: RouteScope) -> Response {
    match scope {
        RouteScope::DenyScoped => reply(StatusCode::FORBIDDEN, json!({"error": "Insufficient scope"})),
        RouteScope::Require(requirement) => reply(
            StatusCode::FORBIDDEN,
            json!({"error": "Insufficient scope", "required": format!("{}:{}", requirement.resource, requirement.action)}),
        ),
    }
}

/// `sendRateLimited` without the budget headers, which only exist with CLOUD=true
fn rate_limited() -> Response {
    reply(StatusCode::TOO_MANY_REQUESTS, json!({"error": "Rate limit exceeded"}))
}

/// `bearerScopeOk`
fn bearer_scope_ok(result: &BearerAuthResult, scope: Option<RouteScope>) -> bool {
    match scope {
        None => true,
        Some(RouteScope::DenyScoped) => result.statements.is_none() && result.organization_id.is_none(),
        Some(RouteScope::Require(requirement)) => has_scope(result.statements.as_ref(), requirement),
    }
}

/// `attachApiKeyUser`
fn bearer_principal(result: BearerAuthResult) -> Authenticated {
    Authenticated {
        user_id: result.user_id.clone(),
        api_key_organization_id: if result.user_id.is_some() { None } else { result.organization_id },
        bearer: true,
        statements: result.statements,
        session: None,
    }
}

fn session_principal(session: Option<AuthSession>) -> Authenticated {
    Authenticated { user_id: session.as_ref().map(|s| s.user_id.clone()), session, ..Default::default() }
}

/// JavaScript `Number(text)` for route parameters, kept only when it is an
/// integer (`site.siteId === Number(siteId)` can only hold for those).
pub fn js_number_param(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    let value = if trimmed.is_empty() {
        0.0
    } else if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()? as f64
    } else if let Some(octal) = trimmed.strip_prefix("0o").or_else(|| trimmed.strip_prefix("0O")) {
        i64::from_str_radix(octal, 8).ok()? as f64
    } else if let Some(binary) = trimmed.strip_prefix("0b").or_else(|| trimmed.strip_prefix("0B")) {
        i64::from_str_radix(binary, 2).ok()? as f64
    } else {
        // Rust accepts "inf"/"nan" spellings JS does not, and JS rejects neither
        // leading "+" nor exponents; integers are all that matter here
        if trimmed.chars().any(|c| c.is_ascii_alphabetic() && c != 'e' && c != 'E') {
            return None;
        }
        trimmed.parse::<f64>().ok()?
    };
    (value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0).then_some(value as i64)
}

impl<'a> AuthContext<'a> {
    pub fn new(state: &'a AppState, headers: &'a HeaderMap, query_api_key: Option<String>) -> Self {
        Self { state, headers, query_api_key, session: OnceCell::new() }
    }

    fn token(&self) -> Option<&str> {
        let authorization = self.headers.get(axum::http::header::AUTHORIZATION).and_then(|value| value.to_str().ok());
        bearer_token(authorization, self.query_api_key.as_deref())
    }

    /// `getSessionFromReq`, once per request
    pub async fn session(&self) -> Result<Option<AuthSession>, Response> {
        self.session
            .get_or_try_init(|| async {
                get_session(
                    &self.state.pg,
                    self.state.config.better_auth_secret.as_deref(),
                    self.state.config.production,
                    self.headers,
                )
                .await
            })
            .await
            .cloned()
            .map_err(internal_error)
    }

    async fn check_api_key(&self, target: AccessTarget<'_>) -> Result<BearerAuthResult, Response> {
        check_api_key(&self.state.pg, self.token(), target).await.map_err(|err| {
            // Node's message is known for this one failure; see SiteIdQueryFailed
            if let sqlx::Error::Encode(inner) = &err
                && let Some(failed) = inner.downcast_ref::<super::SiteIdQueryFailed>()
            {
                error!(error = %failed, "Auth guard failed");
                return reply(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"statusCode": 500, "error": "Internal Server Error", "message": failed.to_string()}),
                );
            }
            internal_error(err)
        })
    }

    async fn session_user_id(&self) -> Result<Option<String>, Response> {
        Ok(self.session().await?.map(|session| session.user_id))
    }

    /// `getUserHasAccessToSite` / `getUserHasAdminAccessToSite` for the session user
    async fn session_has_site(&self, site_id: &str, admin_only: bool) -> Result<bool, Response> {
        let principal = AccessPrincipal { user_id: self.session_user_id().await?, api_key_organization_id: None };
        let Some(wanted) = js_number_param(site_id) else { return Ok(false) };
        let sites = self.state.sites_access.sites_for(&self.state.pg, &principal, admin_only).await;
        Ok(sites.iter().any(|id| i64::from(*id) == wanted))
    }

    /// `requireAuth`
    pub async fn require_auth(
        &self,
        scope: Option<RouteScope>,
        organization_id: Option<&str>,
        site_id: Option<&str>,
    ) -> GuardResult {
        if let Some(session) = self.session().await? {
            return Ok(session_principal(Some(session)));
        }

        let target = AccessTarget { organization_id, site_id: site_id.and_then(js_number_param), site_param: site_id };
        let result = self.check_api_key(target).await?;
        if result.valid {
            return if bearer_scope_ok(&result, scope) { Ok(bearer_principal(result)) } else { Err(insufficient_scope(scope.unwrap())) };
        }
        if result.rate_limited {
            return Err(rate_limited());
        }
        Err(reply(StatusCode::UNAUTHORIZED, json!({"error": "Unauthorized"})))
    }

    /// `requireAdmin`: session only
    pub async fn require_admin(&self) -> GuardResult {
        let user_id = self.session_user_id().await?;
        if !is_system_admin(&self.state.pg, user_id.as_deref()).await.map_err(internal_error)? {
            return Err(reply(StatusCode::UNAUTHORIZED, json!({"error": "Unauthorized"})));
        }
        Ok(session_principal(self.session().await?))
    }

    /// `requireSiteAccess`
    pub async fn require_site_access(&self, site_id: Option<&str>, scope: Option<RouteScope>) -> GuardResult {
        let Some(site_id) = site_id.filter(|id| !id.is_empty()) else {
            return Err(reply(StatusCode::BAD_REQUEST, json!({"error": "Site ID required"})));
        };

        let result = self.check_api_key(AccessTarget { site_id: js_number_param(site_id), site_param: Some(site_id), ..Default::default() }).await?;
        let mut scope_denied = false;
        if result.valid {
            if bearer_scope_ok(&result, scope) {
                return Ok(bearer_principal(result));
            }
            scope_denied = true;
        }

        if self.session_has_site(site_id, false).await? {
            return Ok(session_principal(self.session().await?));
        }
        if result.rate_limited {
            return Err(rate_limited());
        }
        if scope_denied {
            return Err(insufficient_scope(scope.unwrap()));
        }
        Err(forbidden())
    }

    /// `requireSiteAdminAccess`
    pub async fn require_site_admin_access(&self, site_id: Option<&str>, scope: Option<RouteScope>) -> GuardResult {
        let Some(site_id) = site_id.filter(|id| !id.is_empty()) else {
            return Err(reply(StatusCode::BAD_REQUEST, json!({"error": "Site ID required"})));
        };

        let result = self.check_api_key(AccessTarget { site_id: js_number_param(site_id), site_param: Some(site_id), ..Default::default() }).await?;
        let mut scope_denied = false;
        if result.valid && matches!(result.role.as_deref(), Some("admin" | "owner")) {
            if bearer_scope_ok(&result, scope) {
                return Ok(bearer_principal(result));
            }
            scope_denied = true;
        }

        // System admins have account-wide authority
        let user_id = self.session_user_id().await?;
        if is_system_admin(&self.state.pg, user_id.as_deref()).await.map_err(internal_error)? {
            return Ok(session_principal(self.session().await?));
        }
        if self.session_has_site(site_id, true).await? {
            return Ok(session_principal(self.session().await?));
        }
        if result.rate_limited {
            return Err(rate_limited());
        }
        if scope_denied {
            return Err(insufficient_scope(scope.unwrap()));
        }
        Err(forbidden())
    }

    /// `allowPublicSiteAccess`: public Sites, private link keys, sessions and bearers.
    pub async fn allow_public_site_access(&self, site_id: Option<&str>, scope: Option<RouteScope>) -> GuardResult {
        let Some(site_id) = site_id.filter(|id| !id.is_empty()) else {
            return Err(reply(StatusCode::BAD_REQUEST, json!({"error": "Site ID required"})));
        };

        let result = self.check_api_key(AccessTarget { site_id: js_number_param(site_id), site_param: Some(site_id), ..Default::default() }).await?;
        let mut scope_denied = false;
        if result.valid {
            if bearer_scope_ok(&result, scope) {
                return Ok(bearer_principal(result));
            }
            scope_denied = true;
        }

        if self.has_public_site_access(site_id, scope, &result).await? {
            return Ok(session_principal(self.session().await?));
        }
        if result.rate_limited {
            return Err(rate_limited());
        }
        if scope_denied {
            return Err(insufficient_scope(scope.unwrap()));
        }
        Err(forbidden())
    }

    /// `getUserHasAccessToSitePublic`. Node verifies the bearer a second time here;
    /// the first verification's result is reused (same answer, one fewer write).
    async fn has_public_site_access(
        &self,
        site_id: &str,
        scope: Option<RouteScope>,
        bearer: &BearerAuthResult,
    ) -> Result<bool, Response> {
        if self.session_has_site(site_id, false).await? {
            return Ok(true);
        }

        let config = self.state.site_config.get_config(&SiteRef::Text(site_id.to_string())).await;
        if config.as_ref().is_some_and(|config| config.public) {
            return Ok(true);
        }

        if let Some(private_key) = self.headers.get("x-private-key").and_then(|value| value.to_str().ok())
            && !private_key.is_empty()
            && config.as_ref().and_then(|config| config.private_link_key.as_deref()) == Some(private_key)
        {
            return Ok(true);
        }

        let requirement = match scope {
            Some(RouteScope::Require(requirement)) => Some(requirement),
            _ => None,
        };
        Ok(bearer.valid && requirement.is_none_or(|requirement| has_scope(bearer.statements.as_ref(), requirement)))
    }

    /// `requireOrgMember`
    pub async fn require_org_member(&self, organization_id: Option<&str>, scope: Option<RouteScope>) -> GuardResult {
        let Some(organization_id) = organization_id.filter(|id| !id.is_empty()) else {
            return Err(reply(StatusCode::BAD_REQUEST, json!({"error": "Organization ID required"})));
        };

        let result = self
            .check_api_key(AccessTarget { organization_id: Some(organization_id), ..Default::default() })
            .await?;
        let mut scope_denied = false;
        if result.valid {
            if bearer_scope_ok(&result, scope) {
                return Ok(bearer_principal(result));
            }
            scope_denied = true;
        }

        let user_id = self.session_user_id().await?;
        let membership = get_org_membership(&self.state.pg, user_id.as_deref(), Some(organization_id))
            .await
            .map_err(internal_error)?;
        if membership.is_some() {
            return Ok(session_principal(self.session().await?));
        }
        if result.rate_limited {
            return Err(rate_limited());
        }
        if scope_denied {
            return Err(insufficient_scope(scope.unwrap()));
        }
        Err(forbidden())
    }

    /// `requireOrgAdminFromParams`
    pub async fn require_org_admin(&self, organization_id: Option<&str>, scope: Option<RouteScope>) -> GuardResult {
        let Some(organization_id) = organization_id.filter(|id| !id.is_empty()) else {
            return Err(reply(StatusCode::BAD_REQUEST, json!({"error": "Organization ID required in path"})));
        };

        let result = self
            .check_api_key(AccessTarget { organization_id: Some(organization_id), ..Default::default() })
            .await?;
        let mut scope_denied = false;
        if result.valid && matches!(result.role.as_deref(), Some("admin" | "owner")) {
            if bearer_scope_ok(&result, scope) {
                return Ok(bearer_principal(result));
            }
            scope_denied = true;
        }

        let Some(session) = self.session().await? else {
            if result.rate_limited {
                return Err(rate_limited());
            }
            if scope_denied {
                return Err(insufficient_scope(scope.unwrap()));
            }
            return Err(reply(StatusCode::UNAUTHORIZED, json!({"error": "Unauthorized"})));
        };

        let membership = get_org_membership(&self.state.pg, Some(&session.user_id), Some(organization_id))
            .await
            .map_err(internal_error)?;
        match membership {
            None => Err(reply(StatusCode::FORBIDDEN, json!({"error": "You are not a member of this organization"}))),
            Some(membership) if !membership.is_admin() => {
                Err(reply(StatusCode::FORBIDDEN, json!({"error": "You must be an admin or owner"})))
            }
            Some(_) => Ok(session_principal(Some(session))),
        }
    }
}

/// `resolveSiteId`: a Site's text id (longer than four characters) becomes its
/// numeric id; an unknown non-numeric identifier is a 404.
pub async fn resolve_site_id(state: &AppState, site_id: &str) -> Result<String, Response> {
    if site_id.is_empty() || site_id.chars().count() <= 4 {
        return Ok(site_id.to_string());
    }
    if let Some(numeric) = state.site_config.resolve_site_id(&SiteRef::Text(site_id.to_string())).await {
        return Ok(numeric.to_string());
    }
    if !site_id.chars().all(|c| c.is_ascii_digit()) {
        return Err(reply(StatusCode::NOT_FOUND, json!({"error": "Site not found"})));
    }
    Ok(site_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_params_follow_javascript() {
        assert_eq!(js_number_param("12"), Some(12));
        assert_eq!(js_number_param(" 12 "), Some(12));
        assert_eq!(js_number_param("0x1A"), Some(26));
        assert_eq!(js_number_param("1e1"), Some(10));
        assert_eq!(js_number_param(""), Some(0));
        assert_eq!(js_number_param("1.5"), None);
        assert_eq!(js_number_param("abc"), None);
        assert_eq!(js_number_param("inf"), None);
    }
}
