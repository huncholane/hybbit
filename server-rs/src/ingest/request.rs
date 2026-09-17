//! `resolveTrackingRequest` (server/src/services/tracker/trackingRequest.ts): the
//! facts about one tracking request, resolved once at the edge and passed by
//! value through every stage.

use std::net::IpAddr;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};

use crate::{
    auth::{AccessTarget, bearer_token, check_api_key, scopes::ScopeRequirement, scopes::has_scope},
    geo::AsnLookup,
    site_config::{SiteConfigData, SiteRef},
    state::AppState,
    tracking::{
        client_ip::{collect_candidate_client_ips, get_request_user_agent, resolve_client_ip},
        payload::ValidatedTrackingPayload,
    },
};

const INGEST_WRITE: ScopeRequirement = ScopeRequirement { resource: "ingest", action: "write" };

/// `TrackingRequest`
pub struct TrackingRequest<'a> {
    pub payload: ValidatedTrackingPayload,
    /// Site Configuration for `payload.site_id`, fetched once for the request
    pub site: SiteConfigData,
    /// The authoritative client IP: identity, geolocation and bot detection all use it
    pub ip_address: String,
    /// The authoritative user agent, under the same rule
    pub user_agent: String,
    /// Every plausible client IP, for exclusion matching only
    pub candidate_ips: Vec<String>,
    /// A bearer with `ingest:write` for this Site let the payload set IP and user agent
    pub trusted_server_side_ingestion: bool,
    pub headers: &'a HeaderMap,
    /// Request-scoped ASN resolver: each IP is looked up at most once per event
    pub asn_lookup: AsnLookup<'a>,
    /// The event's timestamp and the instant that picks its salt day
    pub received_at: DateTime<Utc>,
}

/// JavaScript `a || b` for optional strings.
fn or_else(preferred: Option<&str>, fallback: &str) -> String {
    preferred.filter(|value| !value.is_empty()).unwrap_or(fallback).to_string()
}

/// `resolveTrackingRequest`: None when the Site is unknown (the caller's 404).
/// Errors are the database failures Node lets reach the handler's 500.
pub async fn resolve_tracking_request<'a>(
    state: &'a AppState,
    headers: &'a HeaderMap,
    peer: IpAddr,
    query_api_key: Option<&str>,
    payload: ValidatedTrackingPayload,
) -> Result<Option<TrackingRequest<'a>>, sqlx::Error> {
    // Stamped before the first await, so a cold config read or a slow key check
    // cannot push the event into the next bucket or salt day
    let received_at = Utc::now();

    let Some(site) = state.site_config.get_config(&SiteRef::Text(payload.site_id.clone())).await else {
        return Ok(None);
    };

    let asn_lookup = state.geo.asn_lookup();
    let trusted_server_side_ingestion = is_trusted_server_side_ingestion(state, headers, query_api_key, site.site_id).await?;

    let request_ip = resolve_client_ip(headers, peer, site.first_party_proxy, &asn_lookup);
    let request_user_agent = get_request_user_agent(headers);

    // Only a trusted bearer may speak for someone else
    let (ip_address, user_agent) = if trusted_server_side_ingestion {
        (or_else(payload.ip_address.as_deref(), &request_ip), or_else(payload.user_agent.as_deref(), &request_user_agent))
    } else {
        (request_ip.clone(), request_user_agent)
    };

    let candidate_ips = collect_candidate_client_ips(headers, peer, &[ip_address.as_str(), request_ip.as_str()]);

    Ok(Some(TrackingRequest {
        payload,
        site,
        ip_address,
        user_agent,
        candidate_ips,
        trusted_server_side_ingestion,
        headers,
        asn_lookup,
        received_at,
    }))
}

/// `isTrustedServerSideIngestion`: an under-scoped or invalid bearer degrades to
/// ordinary client-side traffic, never a 4xx.
async fn is_trusted_server_side_ingestion(
    state: &AppState,
    headers: &HeaderMap,
    query_api_key: Option<&str>,
    site_id: i32,
) -> Result<bool, sqlx::Error> {
    let authorization = headers.get(axum::http::header::AUTHORIZATION).and_then(|value| value.to_str().ok());
    if !authorization.is_some_and(|value| value.starts_with("Bearer ")) {
        return Ok(false);
    }

    let token = bearer_token(authorization, query_api_key);
    let result =
        check_api_key(&state.pg, token, AccessTarget { site_id: Some(i64::from(site_id)), ..Default::default() }).await?;
    Ok(result.valid && has_scope(result.statements.as_ref(), INGEST_WRITE))
}
