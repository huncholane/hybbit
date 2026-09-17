//! The request-scoped access questions the workspace handlers ask after their
//! guard has run, ported from server/src/lib/auth-utils.ts as those handlers call
//! them: `getSitesUserHasAccessTo`, `getUserHasAccessToSite`,
//! `getUserHasAdminAccessToSite`, `getIsUserAdmin` and `getSessionFromReq`.
//!
//! One quirk carries over on purpose: `getIsUserAdmin` reads only the cookie
//! session, never `request.user`, so a request authenticated by a user API key
//! is a system admin exactly when it also carries a system admin's session.

use axum::http::HeaderMap;
use sqlx::PgPool;
use tracing::{debug, error};

use crate::{
    auth::{
        access::{get_org_membership, is_system_admin},
        guards::Authenticated,
        session::get_session,
    },
    state::AppState,
};

pub struct RequestAccess<'a> {
    pub state: &'a AppState,
    pub headers: &'a HeaderMap,
    pub auth: &'a Authenticated,
}

impl<'a> RequestAccess<'a> {
    pub fn new(state: &'a AppState, headers: &'a HeaderMap, auth: &'a Authenticated) -> Self {
        Self { state, headers, auth }
    }

    pub fn pg(&self) -> &PgPool {
        &self.state.pg
    }

    /// `request.user?.id`
    pub fn user_id(&self) -> Option<&str> {
        self.auth.user_id.as_deref()
    }

    /// `request.apiKeyOrganizationId`
    pub fn api_key_organization_id(&self) -> Option<&str> {
        if self.auth.user_id.is_none() { self.auth.api_key_organization_id.as_deref() } else { None }
    }

    /// `getSitesUserHasAccessTo(request, adminOnly)` as site ids. Lookup failures
    /// answer no sites, as in Node.
    pub async fn site_ids(&self, admin_only: bool) -> Vec<i32> {
        let principal = self.auth.principal();
        if !(self.auth.bearer && principal.user_id.is_some()) {
            return self.state.sites_access.sites_for(&self.state.pg, &principal, admin_only).await;
        }
        // A user credential: system-admin authority comes from the cookie session, if any
        let session_user = match self.session_user_id().await {
            Ok(user) => user,
            Err(err) => {
                error!(error = %err, "Error getting sites user has access to");
                return Vec::new();
            }
        };
        self.state.sites_access.sites_for_request(&self.state.pg, &principal, session_user.as_deref(), admin_only).await
    }

    /// `getUserHasAccessToSite` / `getUserHasAdminAccessToSite`:
    /// `sites.some(site => site.siteId === Number(siteId))`
    pub async fn has_site(&self, site_id: f64, admin_only: bool) -> bool {
        let sites = self.site_ids(admin_only).await;
        let found = sites.iter().any(|id| f64::from(*id) == site_id);
        debug!(site_id, admin_only, found, "Checked site access");
        found
    }

    /// `getSessionFromReq(request)?.user.id`. The guard already resolved the session
    /// unless a bearer credential let the request in.
    pub async fn session_user_id(&self) -> Result<Option<String>, sqlx::Error> {
        if !self.auth.bearer {
            return Ok(self.auth.session.as_ref().map(|session| session.user_id.clone()));
        }
        let session = get_session(
            &self.state.pg,
            self.state.config.better_auth_secret.as_deref(),
            self.state.config.production,
            self.headers,
        )
        .await?;
        Ok(session.map(|session| session.user_id))
    }

    /// `getIsUserAdmin(request)`: the session user's role is exactly "admin".
    pub async fn is_system_admin(&self) -> Result<bool, sqlx::Error> {
        let user_id = self.session_user_id().await?;
        is_system_admin(&self.state.pg, user_id.as_deref()).await
    }

    /// `isOrgAdmin(await getOrgMembership(userId, organizationId))`
    pub async fn is_org_admin(&self, user_id: &str, organization_id: &str) -> Result<bool, sqlx::Error> {
        Ok(get_org_membership(&self.state.pg, Some(user_id), Some(organization_id))
            .await?
            .is_some_and(|membership| membership.is_admin()))
    }
}
