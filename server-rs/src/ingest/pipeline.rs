//! `ingestEvent` (server/src/services/tracker/ingestEvent.ts): one resolved
//! tracking request through the stages, in Node's order.
//!
//!   1. Site Exclusion Decision: first, so disowned traffic leaves no trace.
//!   2. Over-limit: never, this deployment has no billing (see PORT_PLAN.md).
//!   3. Heartbeats only extend a live session and skip bot detection.
//!   4. Bot detection runs for every Site; `blockBots` decides where it goes.
//!   5. Identity and session, then the rows.

use tracing::{debug, info};

use super::{
    request::TrackingRequest,
    rows::{BasePayload, bot_event_row, event_row, is_filtered_event},
};
use crate::{
    bot::{BotBlockingInput, BotBlockingPayload},
    identity::{UserIdDeps, UserIdError, UserIdOptions},
    state::AppState,
    tracking::{
        exclusions::{SiteExclusionDecision, SiteExclusionRequest, SiteExclusionRules, decide_site_exclusion},
        payload::TrackingEventType,
    },
    ua::parse_user_agent,
};

/// `IngestOutcome`
#[derive(Debug)]
pub enum IngestOutcome {
    Excluded(SiteExclusionDecision),
    Bot,
    /// A heartbeat with no live session to extend
    NoSession,
    Tracked { session_id: String },
}

/// `ingestEvent`. Errors are the failures Node's handler turns into a 500.
pub async fn ingest_event(state: &AppState, request: &TrackingRequest<'_>) -> Result<IngestOutcome, UserIdError> {
    let payload = &request.payload;
    let site = &request.site;
    let ingest = &state.ingest;

    let exclusion = decide_site_exclusion(
        &SiteExclusionRules::from(site),
        &SiteExclusionRequest {
            ip_address: &request.ip_address,
            candidate_ips: &request.candidate_ips,
            pathname: payload.pathname.as_deref(),
            querystring: payload.querystring.as_deref(),
            hostname: payload.hostname.as_deref(),
            user_agent: Some(&request.user_agent),
        },
        state.geo.as_ref(),
        &request.asn_lookup,
    );
    if exclusion.is_excluded() {
        info!(site_id = %payload.site_id, decision = ?exclusion, "Site exclusion matched");
        return Ok(IngestOutcome::Excluded(exclusion));
    }

    if payload.event_type == TrackingEventType::Heartbeat {
        let event = create_base_payload(state, request).await?;
        let session = ingest
            .sessions
            .refresh_session(&state.redis, &event.user_id, &event.identified_user_id, site.site_id)
            .await;
        let Some(session_id) = session else {
            debug!(site_id = %payload.site_id, "Dropping heartbeat - no live session to extend");
            return Ok(IngestOutcome::NoSession);
        };
        queue_event(state, request, &event, &session_id);
        return Ok(IngestOutcome::Tracked { session_id });
    }

    let detection = ingest
        .bot
        .check_bot_blocking(BotBlockingInput {
            headers: request.headers,
            block_bots: site.block_bots,
            trusted_server_side_ingestion: request.trusted_server_side_ingestion,
            is_mobile_site: site.site_type == crate::site_config::SiteType::Mobile,
            payload: BotBlockingPayload {
                site_id: site.site_id,
                user_agent: Some(&request.user_agent),
                client_bot_score: payload.bot_score.map(i64::from),
                client_bot_signal_mask: payload.bot_signal_mask.map(i64::from),
                screen_width: payload.screen_width,
                screen_height: payload.screen_height,
                language: payload.language.as_deref(),
                hostname: payload.hostname.as_deref(),
                pathname: payload.pathname.as_deref(),
                event_type: Some(payload.event_type.as_str()),
                referrer: payload.referrer.as_deref(),
                ip_address: &request.ip_address,
            },
            asn_lookup: &request.asn_lookup,
        })
        .await;

    let event = create_base_payload(state, request).await?;

    if let Some(detection) = detection.as_ref().filter(|detection| detection.enforced) {
        let session_id = format!("bot:{}", event.user_id);
        ingest.bot_events.add(bot_event_row(&event, &session_id, &state.geo, &detection.event_properties));
        return Ok(IngestOutcome::Bot);
    }

    let session_id = ingest
        .sessions
        .update_session(&state.redis, &event.user_id, &event.identified_user_id, site.site_id)
        .await;
    queue_event(state, request, &event, &session_id);

    // Blocking is off for this Site, so the hit is tracked, but the detection is
    // kept so the owner can see what enabling blocking would remove
    if let Some(detection) = detection {
        ingest.bot_observations.add(bot_event_row(&event, &session_id, &state.geo, &detection.event_properties));
    }

    Ok(IngestOutcome::Tracked { session_id })
}

fn queue_event(state: &AppState, request: &TrackingRequest<'_>, event: &BasePayload, session_id: &str) {
    if is_filtered_event(event) {
        return;
    }
    let asn = request.asn_lookup.lookup(&event.ip_address);
    state.ingest.events.add(event_row(event, session_id, &state.geo, asn));
}

/// `createBasePayload`: the device fingerprint and the event as queued.
async fn create_base_payload(state: &AppState, request: &TrackingRequest<'_>) -> Result<BasePayload, UserIdError> {
    let payload = &request.payload;
    let site = &request.site;
    let secret = state.config.better_auth_secret.as_deref();
    let options = UserIdOptions { salt_user_ids: Some(site.salt_user_ids), received_at: Some(request.received_at) };

    let user_id = match payload.anonymous_id.as_deref().filter(|id| !id.is_empty()) {
        Some(anonymous_id) => {
            state
                .ingest
                .user_ids
                .generate_user_id_from_client_id(state.site_config.as_ref(), secret, anonymous_id, site.site_id, options)
                .await?
        }
        None => {
            let deps = UserIdDeps { redis: &state.redis, salt_source: state.site_config.as_ref(), secret };
            state
                .ingest
                .user_ids
                .generate_user_id(
                    &deps,
                    &request.asn_lookup,
                    &request.ip_address,
                    &request.user_agent,
                    site.site_id,
                    options,
                )
                .await?
        }
    };

    Ok(BasePayload::new(
        payload,
        site.site_id,
        &request.ip_address,
        request.received_at,
        parse_user_agent(&request.user_agent),
        user_id,
        site.track_ip,
    ))
}
