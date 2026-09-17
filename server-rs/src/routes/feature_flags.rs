//! POST /api/site/:siteId/feature-flags/evaluate (public, browser SDK) and
//! POST /api/sites/:siteId/feature-flags/evaluate (authFlagsRead, server SDK), from
//! server/src/api/featureFlags/index.ts.

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Uri},
    response::Response,
};

use crate::{
    analytics::chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
    feature_flags::evaluate::{RequestFacts, Runtime, evaluate_for_runtime},
    geo::Location,
    http,
    site_config::SiteConfigData,
    state::AppState,
    tracking::{
        body::{BodyHeaders, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_body_with_depth, reject_before_reading},
        client_ip::{get_request_user_agent, resolve_client_ip},
    },
    ua::{get_device_type, parse},
};

/// The request's IP and user agent, resolved only when the Site has flags.
struct HttpFacts<'a> {
    state: &'a AppState,
    headers: &'a HeaderMap,
    peer: SocketAddr,
}

impl RequestFacts for HttpFacts<'_> {
    fn location(&self, site: &SiteConfigData) -> Option<Location> {
        let asn_lookup = self.state.geo.asn_lookup();
        let ip = resolve_client_ip(self.headers, self.peer.ip(), site.first_party_proxy, &asn_lookup);
        self.state.geo.location(&ip)
    }

    fn device_type(&self, screen_width: f64, screen_height: f64) -> String {
        // `userAgentParser(...)` without the tracking cache, as Node calls it here
        let ua = parse(&get_request_user_agent(self.headers));
        get_device_type(screen_width, screen_height, &ua).to_string()
    }
}

/// Fastify's body handling, then the body as serde JSON (None when absent).
async fn read_body(headers: &HeaderMap, body: Body) -> Result<Option<serde_json::Value>, Response> {
    let body_headers = BodyHeaders::from_headers(headers);
    let reject = |rejection: crate::tracking::body::BodyRejection| {
        let mut response = http::json(rejection.status, &rejection.body);
        if rejection.close_connection {
            response
                .headers_mut()
                .insert(axum::http::header::CONNECTION, axum::http::HeaderValue::from_static("close"));
        }
        response
    };
    if let Some(rejection) = reject_before_reading(&body_headers) {
        return Err(reject(rejection));
    }
    let raw = axum::body::to_bytes(body, TRACK_BODY_LIMIT_BYTES + 1).await.map_err(|_| reject(body_too_large()))?;
    let parsed = parse_body_with_depth(&body_headers, &raw, 64).map_err(reject)?;
    Ok(parsed.map(|value| value.to_serde()))
}

/// `evaluateFeatureFlags`
pub async fn evaluate_client(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let facts = HttpFacts { state: &state, headers: &headers, peer };
    let (status, value) = evaluate_for_runtime(&state, &site_id, body.as_ref(), Runtime::Client, &facts).await;
    http::js_json(status, &value)
}

/// `evaluateServerFeatureFlags` behind `authFlagsRead`
pub async fn evaluate_server(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(site_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Fastify parses the body before preHandlers run, so its rejections come first
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request = match site_scoped(
        &state,
        &headers,
        &uri,
        &site_id,
        SiteGuard::Member,
        route_scope("flags", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };
    let facts = HttpFacts { state: &state, headers: &headers, peer };
    let (status, value) =
        evaluate_for_runtime(&state, &request.site_id, body.as_ref(), Runtime::Server, &facts).await;
    http::js_json(status, &value)
}
