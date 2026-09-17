//! POST /api/track (server/src/services/tracker/trackEvent.ts) and POST /api/identify
//! (server/src/services/tracker/identifyService.ts). Public: the tracking script and
//! server-side SDKs call them.
//!
//! The bodies go through Fastify's default content-type parsers in Node; the
//! `tracking::body` port reproduces those before the handler logic runs.

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::Response,
};
use serde_json::{Value, json};
use tracing::{error, warn};

use crate::{
    http,
    identity::{IdentifyDeps, IdentifyRequest, handle_identify},
    ingest::{
        pipeline::{IngestOutcome, ingest_event},
        request::resolve_tracking_request,
    },
    state::AppState,
    tracking::{
        body::{
            BodyHeaders, BodyRejection, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_body_with_depth, parse_track_body,
            reject_before_reading,
        },
        client_ip::resolve_client_ip,
        json::JsValue,
        payload::validate_tracking_payload,
        url_params::url_search_params,
    },
};

/// Identify reads whole trait objects; see `JsValue::to_serde` for what is deeper.
const IDENTIFY_BODY_KEEP_DEPTH: usize = 1100;

fn rejection_response(rejection: BodyRejection) -> Response {
    let mut response = http::json(rejection.status, &rejection.body);
    if rejection.close_connection {
        response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Read the body the way Fastify does before a route handler: reject by headers,
/// cap the size, then parse JSON or text.
async fn read_body(headers: &HeaderMap, body: Body, keep_depth: usize) -> Result<Option<JsValue>, Response> {
    let body_headers = BodyHeaders::from_headers(headers);
    if let Some(rejection) = reject_before_reading(&body_headers) {
        return Err(rejection_response(rejection));
    }
    let raw = match axum::body::to_bytes(body, TRACK_BODY_LIMIT_BYTES + 1).await {
        Ok(raw) => raw,
        Err(err) => {
            warn!(error = %err, "Tracking body could not be read within the limit");
            return Err(rejection_response(body_too_large()));
        }
    };
    let parsed = if keep_depth == 2 {
        parse_track_body(&body_headers, &raw)
    } else {
        parse_body_with_depth(&body_headers, &raw, keep_depth)
    };
    parsed.map_err(rejection_response)
}

/// `request.query.api_key` when it is a single string
fn single_query_value(uri: &Uri, name: &str) -> Option<String> {
    let pairs = url_search_params(uri.query().unwrap_or(""));
    let mut matches = pairs.into_iter().filter(|(key, _)| key == name);
    match (matches.next(), matches.next()) {
        (Some((_, value)), None) => Some(value),
        _ => None,
    }
}

/// `trackEvent`: parse, resolve, ingest, answer.
pub async fn track(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match read_body(&headers, body, 2).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let payload = match validate_tracking_payload(body.as_ref()) {
        Ok(payload) => payload,
        Err(errors) => return http::json(StatusCode::BAD_REQUEST, &errors.response_body()),
    };

    let failed = || http::json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "success": false, "error": "Failed to track event" }));
    let site_id = payload.site_id.clone();
    let query_api_key = single_query_value(&uri, "api_key");

    let request = match resolve_tracking_request(&state, &headers, peer.ip(), query_api_key.as_deref(), payload).await {
        Ok(Some(request)) => request,
        Ok(None) => {
            warn!(site_id = %site_id, "Site not found");
            return http::json(StatusCode::NOT_FOUND, &json!({ "success": false, "error": "Site not found" }));
        }
        Err(err) => {
            error!(error = %err, site_id = %site_id, "Error tracking event");
            return failed();
        }
    };

    match ingest_event(&state, &request).await {
        Ok(IngestOutcome::Excluded(decision)) => http::json(
            StatusCode::OK,
            &json!({ "success": true, "message": decision.tracked_message().unwrap_or_default() }),
        ),
        Ok(IngestOutcome::Bot | IngestOutcome::NoSession | IngestOutcome::Tracked { .. }) => {
            http::json(StatusCode::OK, &json!({ "success": true }))
        }
        Err(err) => {
            error!(error = %err, site_id = %site_id, "Error tracking event");
            failed()
        }
    }
}

/// `handleIdentify`
pub async fn identify(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match read_body(&headers, body, IDENTIFY_BODY_KEEP_DEPTH).await {
        Ok(body) => body.map(|value| value.to_serde()),
        Err(response) => return response,
    };

    let asn_lookup = state.geo.asn_lookup();
    let resolve_ip = |site: &crate::site_config::SiteConfigData| {
        resolve_client_ip(&headers, peer.ip(), site.first_party_proxy, &asn_lookup)
    };
    let user_agent = headers.get(header::USER_AGENT).map(|value| crate::tracking::js::latin1(value.as_bytes()));

    let deps = IdentifyDeps {
        pg: &state.pg,
        redis: &state.redis,
        site_config: &state.site_config,
        asn_lookup: &asn_lookup,
        secret: state.config.better_auth_secret.as_deref(),
        user_ids: &state.ingest.user_ids,
        backfill: &state.ingest.backfill,
    };
    let (status, body): (StatusCode, Value) = handle_identify(
        &deps,
        IdentifyRequest { body: body.as_ref(), user_agent_header: user_agent.as_deref(), resolve_client_ip: &resolve_ip },
    )
    .await;
    http::json(status, &body)
}
