//! The preHandler chains analytics routes are registered with in server/src/index.ts
//! (`publicSiteScoped`, `authSiteScoped`, `adminSiteScoped`, the annotations chain,
//! `orgMemberScoped`, `orgAdminScoped`, `authOnlyScoped`, `adminOnly`), plus
//! Fastify's query-string parsing, so every ported route starts from the same
//! request state Node's handlers see.
//!
//! Order per chain, as in Node: resolveSiteId, the access guard, validateTimeParams,
//! expandSegmentParam. The first step that answers ends the request.

use axum::{
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use serde_json::json;
use sqlx::Row;
use tracing::{debug, error};

use crate::{
    analytics::{
        js::{JsObject, JsValue},
        segments::expand_segment_param::{
            LoadedSegment, SegmentRejection, apply_loaded_segment, segment_param_lookup,
        },
        utils::query_validation::validate_http_time_params,
    },
    auth::{
        access::AccessPrincipal,
        guards::{AuthContext, Authenticated, RouteScope, js_number_param, resolve_site_id, scope},
        scopes::{ScopeRequirement, has_scope},
    },
    http,
    state::AppState,
};

const SEGMENTS_READ: ScopeRequirement = ScopeRequirement { resource: "segments", action: "read" };

/// Which guard a site-scoped chain runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteGuard {
    /// `allowPublicSiteAccess`: public sites, private links, members, bearers
    Public,
    /// `requireSiteAccess`
    Member,
    /// `requireSiteAdminAccess`
    Admin,
}

/// Which optional steps follow the guard.
#[derive(Clone, Copy, Debug)]
pub struct ChainSteps {
    pub validate_time: bool,
    pub expand_segment: bool,
}

impl ChainSteps {
    /// `publicSiteScoped` / `authSiteScoped`
    pub const FULL: Self = Self { validate_time: true, expand_segment: true };
    /// `adminSiteScoped`, `orgMemberScoped`, `orgAdminScoped`, `authOnlyScoped`, `adminOnly`
    pub const TIME_ONLY: Self = Self { validate_time: true, expand_segment: false };
    /// `publicAnnotationsRead`, and routes registered with a bare guard
    pub const GUARD_ONLY: Self = Self { validate_time: false, expand_segment: false };
}

/// What a site-scoped handler receives.
pub struct SiteRequest {
    pub auth: Authenticated,
    /// `request.params.siteId` after resolveSiteId (a numeric id when the Site exists)
    pub site_id: String,
    /// `request.query`, with `filters` rewritten when a segment was expanded
    pub query: JsObject,
}

/// What an org-scoped or account-scoped handler receives.
pub struct ScopedRequest {
    pub auth: Authenticated,
    pub query: JsObject,
}

/// fast-decode-uri-component: the decoded text, or None when any escape is
/// malformed or a run of escapes is not valid UTF-8.
fn fast_decode(input: &str) -> Option<String> {
    if !input.contains('%') {
        return Some(input.to_string());
    }
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            let next = input[index..].find('%').map_or(bytes.len(), |offset| index + offset);
            out.push_str(&input[index..next]);
            index = next;
            continue;
        }
        let mut run = Vec::new();
        while index < bytes.len() && bytes[index] == b'%' {
            let hex = input.get(index + 1..index + 3)?;
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            run.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        }
        out.push_str(std::str::from_utf8(&run).ok()?);
    }
    Some(out)
}

/// Fastify's default query parser (find-my-way 9 over fast-querystring 1.1):
/// repeated keys become arrays, `+` is a space, and a part that fails to decode is
/// kept verbatim.
pub fn fastify_query(uri: &Uri) -> JsObject {
    let mut result = JsObject::new();
    let Some(query) = uri.query().filter(|query| !query.is_empty()) else {
        return result;
    };
    for part in query.split('&') {
        let (raw_key, raw_value) = match part.find('=') {
            Some(eq) => (&part[..eq], Some(&part[eq + 1..])),
            None => (part, None),
        };
        if raw_value.is_none() && raw_key.is_empty() {
            continue;
        }
        let decode = |raw: &str| {
            let spaced = raw.replace('+', " ");
            fast_decode(&spaced).unwrap_or(spaced)
        };
        let key = decode(raw_key);
        let value = raw_value.map(decode).unwrap_or_default();
        // `insert` keeps an existing key's position, as property assignment does
        match result.get(&key).cloned() {
            None => result.insert(key, JsValue::String(value)),
            Some(JsValue::Array(mut values)) => {
                values.push(JsValue::String(value));
                result.insert(key, JsValue::Array(values));
            }
            Some(existing) => result.insert(key, JsValue::Array(vec![existing, JsValue::String(value)])),
        }
    }
    result
}

fn segment_rejection(rejection: SegmentRejection) -> Response {
    let status = StatusCode::from_u16(rejection.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    http::json(status, &rejection.body.to_serde())
}

fn internal_error(err: impl std::fmt::Display) -> Response {
    error!(error = %err, "Analytics preHandler failed");
    http::json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({ "statusCode": 500, "error": "Internal Server Error", "message": "Internal Server Error" }),
    )
}

/// `validateTimeParams`
fn validate_time(query: &JsObject) -> Result<(), Response> {
    match validate_http_time_params(&JsValue::Object(query.clone())) {
        Some(message) => Err(http::json(StatusCode::BAD_REQUEST, &json!({ "error": message }))),
        None => Ok(()),
    }
}

/// `expandSegmentParam`
async fn expand_segment(
    state: &AppState,
    auth: &Authenticated,
    site_id: &str,
    query: &mut JsObject,
) -> Result<(), Response> {
    let bearer_can_read_segments = auth.bearer.then(|| has_scope(auth.statements.as_ref(), SEGMENTS_READ));
    let Some(lookup) = segment_param_lookup(query, Some(site_id), bearer_can_read_segments).map_err(segment_rejection)?
    else {
        return Ok(());
    };
    // Ids past the integer column's range fail inside Postgres in Node (a 500)
    if lookup.segment_id > f64::from(i32::MAX) || lookup.site_id > f64::from(i32::MAX) {
        return Err(internal_error("segment or site id out of integer range"));
    }
    let (segment_id, numeric_site_id) = (lookup.segment_id as i32, lookup.site_id as i32);

    // loadSegmentForSite
    let organization_id: Option<Option<String>> =
        sqlx::query_scalar("SELECT organization_id FROM sites WHERE site_id = $1 LIMIT 1")
            .bind(numeric_site_id)
            .fetch_optional(&state.pg)
            .await
            .map_err(internal_error)?;
    let loaded = match organization_id.flatten().filter(|id| !id.is_empty()) {
        None => None,
        Some(organization_id) => {
            let row = sqlx::query(
                "SELECT organization_id, site_id, filters, is_public FROM segments WHERE segment_id = $1 LIMIT 1",
            )
            .bind(segment_id)
            .fetch_optional(&state.pg)
            .await
            .map_err(internal_error)?;
            match row {
                Some(row) => {
                    let row_organization: String = row.try_get("organization_id").map_err(internal_error)?;
                    let row_site: Option<i32> = row.try_get("site_id").map_err(internal_error)?;
                    let belongs = row_organization == organization_id
                        && row_site.is_none_or(|site| site == numeric_site_id);
                    if belongs {
                        let filters: serde_json::Value = row.try_get("filters").map_err(internal_error)?;
                        let is_public: bool = row.try_get("is_public").map_err(internal_error)?;
                        Some((LoadedSegment { filters: JsValue::from_serde(&filters), is_public }, organization_id))
                    } else {
                        None
                    }
                }
                None => None,
            }
        }
    };

    // resolveSegmentActor(...).hasSiteAccess, only needed once a segment was found
    let has_site_access = match &loaded {
        None => false,
        Some((_, organization_id)) => {
            if auth.user_id.is_none() && auth.api_key_organization_id.is_some() {
                auth.api_key_organization_id.as_deref() == Some(organization_id.as_str())
            } else if let Some(user_id) = &auth.user_id {
                let principal = AccessPrincipal { user_id: Some(user_id.clone()), api_key_organization_id: None };
                let sites = state.sites_access.sites_for(&state.pg, &principal, false).await;
                sites.contains(&numeric_site_id)
            } else {
                false
            }
        }
    };

    debug!(segment_id, site_id = numeric_site_id, found = loaded.is_some(), "Expanding segment_id");
    apply_loaded_segment(query, loaded.as_ref().map(|(segment, _)| segment), has_site_access)
        .map_err(segment_rejection)
}

/// A site-scoped chain: resolveSiteId, the guard with `scope(resource, action)`,
/// then the optional steps.
pub async fn site_scoped(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    site_id_param: &str,
    guard: SiteGuard,
    route_scope: Option<RouteScope>,
    steps: ChainSteps,
) -> Result<SiteRequest, Response> {
    let mut query = fastify_query(uri);
    let site_id = resolve_site_id(state, site_id_param).await?;

    let query_api_key = query.get("api_key").and_then(JsValue::as_str).map(str::to_string);
    let context = AuthContext::new(state, headers, query_api_key);
    let auth = match guard {
        SiteGuard::Public => context.allow_public_site_access(Some(&site_id), route_scope).await?,
        SiteGuard::Member => context.require_site_access(Some(&site_id), route_scope).await?,
        SiteGuard::Admin => context.require_site_admin_access(Some(&site_id), route_scope).await?,
    };

    if steps.validate_time {
        validate_time(&query)?;
    }
    if steps.expand_segment {
        expand_segment(state, &auth, &site_id, &mut query).await?;
    }
    Ok(SiteRequest { auth, site_id, query })
}

/// `orgMemberScoped` (member) or `orgAdminScoped` (admin): the guard, then
/// validateTimeParams.
pub async fn org_scoped(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    organization_id: &str,
    admin: bool,
    route_scope: Option<RouteScope>,
) -> Result<ScopedRequest, Response> {
    let query = fastify_query(uri);
    let query_api_key = query.get("api_key").and_then(JsValue::as_str).map(str::to_string);
    let context = AuthContext::new(state, headers, query_api_key);
    let auth = if admin {
        context.require_org_admin(Some(organization_id), route_scope).await?
    } else {
        context.require_org_member(Some(organization_id), route_scope).await?
    };
    validate_time(&query)?;
    Ok(ScopedRequest { auth, query })
}

/// `authOnlyScoped` (`requireAuth`, then validateTimeParams) or `adminOnly`
/// (`requireAdmin`, then validateTimeParams).
pub async fn account_scoped(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    system_admin: bool,
    route_scope: Option<RouteScope>,
) -> Result<ScopedRequest, Response> {
    let query = fastify_query(uri);
    let query_api_key = query.get("api_key").and_then(JsValue::as_str).map(str::to_string);
    let context = AuthContext::new(state, headers, query_api_key);
    let auth = if system_admin {
        context.require_admin().await?
    } else {
        context.require_auth(route_scope, None, None).await?
    };
    validate_time(&query)?;
    Ok(ScopedRequest { auth, query })
}

/// `scope(resource, action)` re-exported for route modules.
pub const fn route_scope(resource: &'static str, action: &'static str) -> Option<RouteScope> {
    scope(resource, action)
}

/// `Number(siteId)` as handlers use it after the chain.
pub fn numeric_site_id(site_id: &str) -> Option<i64> {
    js_number_param(site_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(text: &str) -> JsObject {
        fastify_query(&format!("/x?{text}").parse::<Uri>().unwrap())
    }

    #[test]
    fn parses_like_fast_querystring() {
        let parsed = query("a=1&b=two+words&a=2&c&=x&d=%E2%9C%93&e=%zz&f=%C3&g=a=b&&h=");
        let pairs: Vec<(String, JsValue)> = parsed.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        assert_eq!(
            pairs,
            vec![
                ("a".into(), JsValue::Array(vec![JsValue::String("1".into()), JsValue::String("2".into())])),
                ("b".into(), JsValue::String("two words".into())),
                ("c".into(), JsValue::String(String::new())),
                ("".into(), JsValue::String("x".into())),
                ("d".into(), JsValue::String("\u{2713}".into())),
                ("e".into(), JsValue::String("%zz".into())),
                ("f".into(), JsValue::String("%C3".into())),
                ("g".into(), JsValue::String("a=b".into())),
                ("h".into(), JsValue::String(String::new())),
            ]
        );
    }
}
