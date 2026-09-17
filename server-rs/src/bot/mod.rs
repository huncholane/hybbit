//! Bot detection for public tracking ingestion, ported from
//! server/src/services/tracker/botBlocking (read its README.md first).
//!
//! `check_bot_blocking` (Node's `checkBotBlocking` in index.ts) is the single
//! decision point. Detection runs for every site; the site's `blockBots` decides
//! what happens to a detection, not whether one is looked for:
//!
//! | detection | blockBots | event lands in        | audit row          |
//! |-----------|-----------|-----------------------|--------------------|
//! | yes       | on        | nowhere (not `events`)| `bot_events`       |
//! | yes       | off       | `events`, as normal   | `bot_observations` |
//! | no        | either    | `events`, as normal   | none               |
//!
//! Layers, all evaluated before deciding so a request matching several is
//! counted against each: `ua_pattern` (isbot patterns plus curated names, and the
//! stale browser version sub-rule), `header_heuristics`, `client_signals` (the
//! tracker's `_bs`/`_bsm` plus server-derived geometry), `bot_asn` (curated bot
//! providers convict; hosting ASNs only corroborate) and `rate_anomaly` (Redis
//! counters shared with Node).
//!
//! Porting notes: every regex runs with JavaScript semantics (`js::JsRegex`),
//! headers are read the way Node's `IncomingHttpHeaders` presents them
//! (`header_heuristics::node_header`), and everything shared through Redis (keys,
//! members, TTLs, the `anomalyObserve` script, the `bot:stats` and `bot:sb`
//! hashes, the `bot:enum:q:*` markers) is byte-compatible with Node.
//!
//! Wiring (for the ingestion port): build one [`BotBlocking`] per process and
//! keep it in the app state, call [`BotBlocking::check_bot_blocking`] from the
//! track handler, and spawn [`site_baseline::spawn_site_baseline_refresh`] and
//! [`detection_stats::spawn_bot_detection_stats_flush`] at startup.
#![allow(dead_code)] // wired into ingestion when /api/track is ported

pub mod anomaly_observe;
pub mod anomaly_scorer;
pub mod bot_provider_asns;
pub mod config;
pub mod detection_stats;
pub mod enumeration_observer;
pub mod header_heuristics;
pub mod js;
pub mod signal_contract;
pub mod site_baseline;
pub mod stale_browser_version;
pub mod ua_bots;

#[cfg(test)]
mod differential;

use std::sync::Arc;

use axum::http::HeaderMap;
use redis::aio::ConnectionManager;
use serde::Serialize;

use self::{
    anomaly_scorer::{AnomalyCounters, AnomalyInput, AnomalyReason, AnomalyScorer},
    bot_provider_asns::{BotAsnSource, classify_bot_asn},
    config::CLIENT_BOT_SCORE_THRESHOLD,
    detection_stats::{BotDetectionMethod, BotDetectionStats},
    header_heuristics::{detect_bot, node_header},
    signal_contract::{
        ClientBotSignal, MAX_CLIENT_BOT_SCORE, STRONG_CLIENT_BOT_SIGNAL_BITS, get_client_bot_signal_names,
        get_screen_dimension_signals, score_from_mask, to_int32,
    },
    site_baseline::SiteBaselines,
    stale_browser_version::classify_stale_browser_version,
    ua_bots::classify_ua,
};
use crate::geo::{AsnInfo, AsnLookup};

/// Node's `AsnLookup` function type: resolves an IP to its ASN. Implemented for
/// the per-request [`AsnLookup`] and for plain closures (tests, fixed answers).
pub trait AsnResolver {
    fn lookup_asn(&self, ip: &str) -> Option<AsnInfo>;
}

impl AsnResolver for AsnLookup<'_> {
    fn lookup_asn(&self, ip: &str) -> Option<AsnInfo> {
        self.lookup(ip)
    }
}

impl<F: Fn(&str) -> Option<AsnInfo>> AsnResolver for F {
    fn lookup_asn(&self, ip: &str) -> Option<AsnInfo> {
        self(ip)
    }
}

/// `BotBlockingPayload`: the validated tracking payload fields bot detection
/// reads. Numbers are the payload's (validated as integers in Node), screen
/// dimensions as doubles because they are printed into the cohort key the
/// JavaScript way.
#[derive(Clone, Copy, Debug, Default)]
pub struct BotBlockingPayload<'a> {
    /// Numeric site id, the one ingestion uses everywhere else.
    pub site_id: i32,
    /// The user agent ingestion resolved (payload override for trusted ingestion).
    pub user_agent: Option<&'a str>,
    /// `_bs`
    pub client_bot_score: Option<i64>,
    /// `_bsm`
    pub client_bot_signal_mask: Option<i64>,
    pub screen_width: Option<f64>,
    pub screen_height: Option<f64>,
    pub language: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub pathname: Option<&'a str>,
    pub event_type: Option<&'a str>,
    /// As it arrived, before self-referrers are cleared for storage.
    pub referrer: Option<&'a str>,
    /// The resolved client IP.
    pub ip_address: &'a str,
}

/// `BotBlockingInput`.
#[derive(Clone, Copy)]
pub struct BotBlockingInput<'a> {
    /// The request's headers; header heuristics are the only thing this needs
    /// from the HTTP request.
    pub headers: &'a HeaderMap,
    pub block_bots: bool,
    /// Verified bearer ingestion: only the UA layer applies.
    pub trusted_server_side_ingestion: bool,
    /// App/mobile site: the browser-shaped UA and header layers are skipped.
    pub is_mobile_site: bool,
    pub payload: BotBlockingPayload<'a>,
    /// The request-scoped ASN resolver shared with the rest of ingestion.
    pub asn_lookup: &'a (dyn AsnResolver + Sync),
}

/// `BotBlockingDetection`: one layer's finding, with compact layer-specific
/// details for the consolidated log line.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BotBlockingDetection {
    pub layer: BotDetectionMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_category: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_name: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_operator: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_purpose: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_bot_score: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_bot_signal_mask: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_signals: Option<Vec<ClientBotSignal>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_provider: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_category: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_note: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_reasons: Option<Vec<AnomalyReason>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_counters: Option<AnomalyCounters>,
}

impl BotBlockingDetection {
    fn new(layer: BotDetectionMethod) -> Self {
        Self {
            layer,
            bot_category: None,
            matched_pattern: None,
            bot_name: None,
            bot_operator: None,
            bot_purpose: None,
            reason: None,
            score: None,
            client_bot_score: None,
            client_bot_signal_mask: None,
            client_signals: None,
            ip: None,
            asn: None,
            asn_org: None,
            asn_provider: None,
            asn_category: None,
            asn_note: None,
            anomaly_reasons: None,
            anomaly_counters: None,
        }
    }
}

/// `BotEventProperties`: what a detection adds to the audit row. The bot event
/// queue writes these as `bot_events` / `bot_observations` columns:
///
/// | field                      | column                        | when absent |
/// |----------------------------|-------------------------------|-------------|
/// | `bot_asn`                  | `asn`                         | NULL        |
/// | `bot_asn_org`              | `asn_org`                     |             |
/// | `detected_*` (five layers) | `detected_*`                  |             |
/// | `matched_ua_pattern`       | `matched_ua_pattern`          |             |
/// | `bot_category`             | `bot_category`                |             |
/// | `bot_name` / `_operator` / `_purpose` | `bot_name` / `bot_operator` / `bot_purpose` | |
/// | `asn_provider`             | `asn_provider`                |             |
/// | `client_bot_score`         | `client_bot_score`            | NULL        |
/// | `client_signal_mask`       | `client_signal_mask`          | 0           |
/// | `anomaly_reasons`          | `anomaly_reasons`             |             |
/// | `anomaly_score`            | `anomaly_score`               |             |
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BotEventProperties {
    pub is_bot: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_asn: Option<u32>,
    pub bot_asn_org: String,
    pub detected_ua_pattern: bool,
    pub detected_header_heuristics: bool,
    pub detected_client_signals: bool,
    pub detected_bot_asn: bool,
    pub detected_rate_anomaly: bool,
    pub matched_ua_pattern: String,
    pub bot_category: String,
    /// Published identity of the bot when a curated pattern matched; empty for a
    /// generic upstream match.
    pub bot_name: String,
    pub bot_operator: String,
    pub bot_purpose: String,
    /// Curated provider behind the request's ASN, the independent half of an
    /// attribution claim.
    pub asn_provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_bot_score: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_signal_mask: Option<i64>,
    /// Which anomaly rules fired, comma-separated, and their summed score.
    pub anomaly_reasons: String,
    pub anomaly_score: i64,
}

/// `BotDetectionResult`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BotDetectionResult {
    /// Whether this detection is acted on (the site blocks bots). An unenforced
    /// detection goes to `bot_observations` and the event is tracked as normal.
    pub enforced: bool,
    /// The first detecting layer's message.
    pub message: &'static str,
    pub detections: Vec<BotBlockingDetection>,
    pub event_properties: BotEventProperties,
}

const MESSAGE_UA_PATTERN: &str = "Bot detected using ua-pattern";
const MESSAGE_HEADER_HEURISTICS: &str = "Bot detected using header heuristics";
const MESSAGE_CLIENT_SIGNALS: &str = "Bot detected using client signals";
const MESSAGE_BOT_ASN: &str = "Bot detected using bot asn";
const MESSAGE_RATE_ANOMALY: &str = "Bot detected using rate anomaly";

/// `getClientSignalResult`'s value.
#[derive(Clone, Debug, PartialEq)]
struct ClientSignalResult {
    score: i64,
    strong_score: i64,
    mask: i64,
    signal_names: Vec<ClientBotSignal>,
    score_for_stats: Option<i64>,
    mask_for_stats: Option<i64>,
    has_client_mask: bool,
    has_client_score: bool,
}

/// `getClientSignalResult`: the client's score and mask, supplemented by the
/// geometry rules re-derived from the reported dimensions (so every tracker
/// version gets them), and by `missingScreenDimensions` when a screen was
/// expected and none was reported.
fn get_client_signal_result(
    payload: &BotBlockingPayload<'_>,
    user_agent: &str,
    has_reportable_screen: bool,
) -> ClientSignalResult {
    let has_client_score = payload.client_bot_score.is_some();
    let has_client_mask = payload.client_bot_signal_mask.is_some();
    let raw_mask = payload.client_bot_signal_mask.unwrap_or(0);
    let mut mask = raw_mask;
    let mut inferred_score = 0;

    let mut add_inferred_signal = |signal: ClientBotSignal| {
        let bit = signal.mask();
        if to_int32(mask) & bit == 0 {
            mask = i64::from(to_int32(mask) | bit);
        }
        if !has_client_score || to_int32(raw_mask) & bit == 0 {
            inferred_score += signal.weight();
        }
    };

    if payload.screen_width.is_some() || payload.screen_height.is_some() {
        for signal in get_screen_dimension_signals(
            payload.screen_width.unwrap_or(f64::NAN),
            payload.screen_height.unwrap_or(f64::NAN),
            user_agent,
        ) {
            add_inferred_signal(signal);
        }
    } else if has_reportable_screen {
        add_inferred_signal(ClientBotSignal::MissingScreenDimensions);
    }

    let score = (payload.client_bot_score.unwrap_or(0) + inferred_score).min(MAX_CLIENT_BOT_SCORE);
    // Derived from the mask, not the opaque score: a score sent without a mask
    // cannot be decomposed, so it can only corroborate.
    let strong_score = score_from_mask(to_int32(mask) & STRONG_CLIENT_BOT_SIGNAL_BITS);

    ClientSignalResult {
        score,
        strong_score,
        mask,
        signal_names: get_client_bot_signal_names(to_int32(mask)),
        score_for_stats: (has_client_score || inferred_score > 0).then_some(score),
        mask_for_stats: (has_client_mask || mask != 0).then_some(mask),
        has_client_mask,
        has_client_score,
    }
}

/// `buildBotEventProperties`.
fn build_bot_event_properties(
    detections: &[BotBlockingDetection],
    asn_info: Option<&AsnInfo>,
    client_signals: &ClientSignalResult,
) -> BotEventProperties {
    let has_layer = |layer| detections.iter().any(|detection| detection.layer == layer);
    let find_layer = |layer| detections.iter().find(|detection| detection.layer == layer);
    let ua = find_layer(BotDetectionMethod::UaPattern);
    let anomaly = find_layer(BotDetectionMethod::RateAnomaly);
    let asn = find_layer(BotDetectionMethod::BotAsn);

    BotEventProperties {
        is_bot: true,
        bot_asn: asn_info.map(|info| info.asn),
        bot_asn_org: asn_info.map(|info| info.organization.clone()).unwrap_or_default(),
        detected_ua_pattern: has_layer(BotDetectionMethod::UaPattern),
        detected_header_heuristics: has_layer(BotDetectionMethod::HeaderHeuristics),
        detected_client_signals: has_layer(BotDetectionMethod::ClientSignals),
        detected_bot_asn: has_layer(BotDetectionMethod::BotAsn),
        detected_rate_anomaly: has_layer(BotDetectionMethod::RateAnomaly),
        matched_ua_pattern: ua.and_then(|detection| detection.matched_pattern.clone()).unwrap_or_default(),
        bot_category: ua.and_then(|detection| detection.bot_category).unwrap_or_default().to_string(),
        bot_name: ua.and_then(|detection| detection.bot_name).unwrap_or_default().to_string(),
        bot_operator: ua.and_then(|detection| detection.bot_operator).unwrap_or_default().to_string(),
        bot_purpose: ua.and_then(|detection| detection.bot_purpose).unwrap_or_default().to_string(),
        asn_provider: asn.and_then(|detection| detection.asn_provider).unwrap_or_default().to_string(),
        client_bot_score: client_signals.score_for_stats,
        client_signal_mask: client_signals.mask_for_stats,
        anomaly_reasons: anomaly
            .and_then(|detection| detection.anomaly_reasons.as_ref())
            .map(|reasons| reasons.iter().map(|reason| reason.rule).collect::<Vec<_>>().join(","))
            .unwrap_or_default(),
        anomaly_score: anomaly.and_then(|detection| detection.score).unwrap_or(0),
    }
}

fn ua_detection(user_agent: &str) -> Option<BotBlockingDetection> {
    let classification = classify_ua(user_agent);
    classification.is_bot.then(|| BotBlockingDetection {
        bot_category: classification.category.map(|category| category.as_str()),
        matched_pattern: classification.matched_pattern.map(str::to_string),
        bot_name: classification.name,
        bot_operator: classification.operator,
        bot_purpose: classification.purpose.map(|purpose| purpose.as_str()),
        ..BotBlockingDetection::new(BotDetectionMethod::UaPattern)
    })
}

/// Bot detection state for one process: the anomaly scorer (with its Redis
/// handle and in-process fallback), the shared site baselines and the detection
/// totals. Node keeps these as module singletons.
pub struct BotBlocking {
    pub anomaly: AnomalyScorer,
    pub stats: Arc<BotDetectionStats>,
}

impl BotBlocking {
    /// `redis` is the handle anomaly counters and streak markers go through;
    /// None runs on the in-process fallbacks only.
    pub fn new(redis: Option<ConnectionManager>) -> Self {
        let baselines = Arc::new(SiteBaselines::new());
        Self { anomaly: AnomalyScorer::new(redis, baselines), stats: Arc::new(BotDetectionStats::new()) }
    }

    /// The baseline map to hand to `spawn_site_baseline_refresh`.
    pub fn baselines(&self) -> Arc<SiteBaselines> {
        self.anomaly.baselines().clone()
    }

    /// `classifyTrustedIngestion`: the UA layer alone, for authenticated
    /// server-side ingestion reporting someone else's user agent. The stale
    /// version rule is left out (meaningless for a relayed user agent) and no ASN
    /// is attributed (the address is the reporting server's).
    fn classify_trusted_ingestion(
        &self,
        user_agent: &str,
        block_bots: bool,
        client_signals: &ClientSignalResult,
    ) -> Option<BotDetectionResult> {
        let detection = ua_detection(user_agent)?;
        let detections = vec![detection];
        self.stats.record_bot_detections(&[BotDetectionMethod::UaPattern], block_bots);
        let event_properties = build_bot_event_properties(&detections, None, client_signals);
        Some(BotDetectionResult { enforced: block_bots, message: MESSAGE_UA_PATTERN, detections, event_properties })
    }

    /// `checkBotBlocking`: run every layer and return the detection, or None for
    /// a clean request.
    pub async fn check_bot_blocking(&self, input: BotBlockingInput<'_>) -> Option<BotDetectionResult> {
        let payload = &input.payload;
        let user_agent = payload
            .user_agent
            .filter(|user_agent| !user_agent.is_empty())
            .map(str::to_string)
            .or_else(|| node_header(input.headers, "user-agent").filter(|user_agent| !user_agent.is_empty()))
            .unwrap_or_default();

        let client_signals = get_client_signal_result(
            payload,
            &user_agent,
            !input.is_mobile_site && !input.trusted_server_side_ingestion,
        );
        self.stats.record_bot_blocking_request(
            client_signals.score_for_stats,
            client_signals.mask_for_stats,
            client_signals.has_client_mask,
            client_signals.has_client_score,
        );

        // Trusted server-side ingestion reports its own IP and someone else's user
        // agent; only the UA layer means anything against it, and it is the only
        // way to see a crawler that never runs JavaScript.
        if input.trusted_server_side_ingestion {
            return self.classify_trusted_ingestion(&user_agent, input.block_bots, &client_signals);
        }

        let mut detections: Vec<BotBlockingDetection> = Vec::new();
        let mut block_message: Option<&'static str> = None;
        let mut add_detection = |message: &'static str, detection: BotBlockingDetection, detections: &mut Vec<_>| {
            block_message.get_or_insert(message);
            detections.push(detection);
        };

        // Layers 1 and 2 are browser-shaped and flag native SDK traffic, so mobile
        // sites skip them.
        if !input.is_mobile_site {
            // Layer 1: user-agent classification.
            if let Some(detection) = ua_detection(&user_agent) {
                add_detection(MESSAGE_UA_PATTERN, detection, &mut detections);
            } else {
                // Layer 1b: a browser release too old to have run the tracker.
                let stale = classify_stale_browser_version(&user_agent);
                if stale.is_stale {
                    add_detection(
                        MESSAGE_UA_PATTERN,
                        BotBlockingDetection {
                            bot_category: Some("stale_version"),
                            matched_pattern: stale.matched_version,
                            ..BotBlockingDetection::new(BotDetectionMethod::UaPattern)
                        },
                        &mut detections,
                    );
                }
            }

            // Layer 2: header heuristics.
            let header_detection = detect_bot(input.headers, &user_agent);
            if header_detection.is_bot {
                add_detection(
                    MESSAGE_HEADER_HEURISTICS,
                    BotBlockingDetection {
                        reason: header_detection.reason,
                        score: Some(header_detection.score),
                        ..BotBlockingDetection::new(BotDetectionMethod::HeaderHeuristics)
                    },
                    &mut detections,
                );
            }
        }

        // Layer 3: client signals. Only strong signals convict; weak ones reaching
        // the threshold corroborate.
        let mut supporting_client_signal_detection = None;
        if client_signals.score.max(client_signals.strong_score) >= CLIENT_BOT_SCORE_THRESHOLD {
            let detection = BotBlockingDetection {
                client_bot_score: Some(client_signals.score),
                client_bot_signal_mask: Some(client_signals.mask),
                client_signals: Some(client_signals.signal_names.clone()),
                ..BotBlockingDetection::new(BotDetectionMethod::ClientSignals)
            };
            if client_signals.strong_score >= CLIENT_BOT_SCORE_THRESHOLD {
                add_detection(MESSAGE_CLIENT_SIGNALS, detection, &mut detections);
            } else {
                supporting_client_signal_detection = Some(detection);
            }
        }

        // Layer 4: ASN. Curated bot providers convict; hosting only corroborates.
        let ip_for_asn = payload.ip_address;
        let mut asn_info: Option<AsnInfo> = None;
        let mut supporting_hosting_asn_detection = None;
        let mut is_hosting_asn = false;
        if !ip_for_asn.is_empty() {
            asn_info = input.asn_lookup.lookup_asn(ip_for_asn);
            let bot_asn_match = classify_bot_asn(asn_info.as_ref().map(|info| info.asn));
            is_hosting_asn = asn_info.is_some() && bot_asn_match.is_bot_infrastructure;
            if let Some(info) = asn_info.as_ref().filter(|_| bot_asn_match.is_bot_infrastructure) {
                let detection = BotBlockingDetection {
                    ip: Some(ip_for_asn.to_string()),
                    asn: Some(info.asn),
                    asn_org: Some(info.organization.clone()),
                    asn_provider: bot_asn_match.provider,
                    asn_category: bot_asn_match.category.map(|category| category.as_str()),
                    asn_note: bot_asn_match.note,
                    ..BotBlockingDetection::new(BotDetectionMethod::BotAsn)
                };
                if bot_asn_match.source == Some(BotAsnSource::CuratedBotProvider) {
                    add_detection(MESSAGE_BOT_ASN, detection, &mut detections);
                } else {
                    supporting_hosting_asn_detection = Some(detection);
                }
            }
        }

        // Layer 5: request-rate and crawl-shape anomalies.
        let anomaly = self
            .anomaly
            .observe_tracking_anomaly(&AnomalyInput {
                site_id: payload.site_id,
                ip_address: payload.ip_address,
                user_agent: &user_agent,
                hostname: payload.hostname,
                pathname: payload.pathname,
                event_type: payload.event_type,
                referrer: payload.referrer,
                has_client_bot_score: payload.client_bot_score.is_some(),
                screen_width: payload.screen_width,
                screen_height: payload.screen_height,
                language: payload.language,
                is_hosting_asn,
                asn: asn_info.as_ref().map(|info| info.asn),
                ..AnomalyInput::default()
            })
            .await;
        if anomaly.is_anomalous {
            add_detection(
                MESSAGE_RATE_ANOMALY,
                BotBlockingDetection {
                    score: Some(anomaly.score),
                    anomaly_reasons: Some(anomaly.reasons),
                    anomaly_counters: Some(anomaly.counters),
                    ..BotBlockingDetection::new(BotDetectionMethod::RateAnomaly)
                },
                &mut detections,
            );
        }

        // Supporting evidence attaches only when a convicting layer fired; two
        // supporting signals must not convict each other.
        if !detections.is_empty() {
            if let Some(detection) = supporting_client_signal_detection {
                add_detection(MESSAGE_CLIENT_SIGNALS, detection, &mut detections);
            }
            if let Some(detection) = supporting_hosting_asn_detection {
                add_detection(MESSAGE_BOT_ASN, detection, &mut detections);
            }
        }

        if detections.is_empty() {
            return None;
        }

        let layers: Vec<BotDetectionMethod> = detections.iter().map(|detection| detection.layer).collect();
        // Node keeps this line behind a constant that is off (it is verbose at
        // traffic volume); here it is a debug event, which costs nothing unless
        // debug logging is on.
        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::debug!(
                site_id = payload.site_id,
                detection_count = detections.len(),
                detection_layers = ?layers.iter().map(|layer| layer.as_str()).collect::<Vec<_>>(),
                detections = %serde_json::to_string(&detections).unwrap_or_default(),
                enforced = input.block_bots,
                "Bot request detected"
            );
        }

        self.stats.record_bot_detections(&layers, input.block_bots);

        let event_properties = build_bot_event_properties(&detections, asn_info.as_ref(), &client_signals);
        Some(BotDetectionResult {
            enforced: input.block_bots,
            message: block_message.unwrap_or("Bot detected"),
            detections,
            event_properties,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/tracker/botBlocking/index.test.ts. Anomaly
    //! scoring runs on the in-process counters so detection is deterministic.
    use super::*;
    use crate::bot::header_heuristics::header_map;

    const BASE_IP: &str = "203.0.113.10";

    fn no_asn(_: &str) -> Option<AsnInfo> {
        None
    }

    fn amazon(_: &str) -> Option<AsnInfo> {
        Some(AsnInfo { asn: 16509, organization: "Amazon.com, Inc.".into() })
    }

    fn openai(_: &str) -> Option<AsnInfo> {
        Some(AsnInfo { asn: 401518, organization: "OpenAI, L.L.C.".into() })
    }

    fn detector() -> BotBlocking {
        let detector = BotBlocking::new(None);
        detector.anomaly.set_redis_enabled(false);
        detector
    }

    fn base_payload() -> BotBlockingPayload<'static> {
        BotBlockingPayload { site_id: 123, ip_address: BASE_IP, ..BotBlockingPayload::default() }
    }

    fn browser_headers() -> HeaderMap {
        header_map(&[
            ("accept", b"*/*"),
            ("accept-encoding", b"gzip, br"),
            ("accept-language", b"en-US,en;q=0.9"),
            ("sec-fetch-site", b"cross-site"),
            ("user-agent", b"Mozilla/5.0 Chrome/120 Safari/537.36"),
        ])
    }

    fn with_user_agent(headers: &HeaderMap, user_agent: &str) -> HeaderMap {
        let mut headers = headers.clone();
        headers.insert("user-agent", user_agent.parse().unwrap());
        headers
    }

    fn input<'a>(headers: &'a HeaderMap, block_bots: bool, payload: BotBlockingPayload<'a>) -> BotBlockingInput<'a> {
        BotBlockingInput {
            headers,
            block_bots,
            trusted_server_side_ingestion: false,
            is_mobile_site: false,
            payload,
            asn_lookup: &no_asn,
        }
    }

    fn layers(result: &Option<BotDetectionResult>) -> Vec<BotDetectionMethod> {
        result
            .as_ref()
            .map(|result| result.detections.iter().map(|detection| detection.layer).collect())
            .unwrap_or_default()
    }

    const CLEAN_PAYLOAD_FIELDS: (Option<f64>, Option<f64>, Option<i64>, Option<i64>) =
        (Some(1512.0), Some(982.0), Some(0), Some(0));

    fn clean_payload() -> BotBlockingPayload<'static> {
        let (screen_width, screen_height, client_bot_score, client_bot_signal_mask) = CLEAN_PAYLOAD_FIELDS;
        BotBlockingPayload { screen_width, screen_height, client_bot_score, client_bot_signal_mask, ..base_payload() }
    }

    #[tokio::test]
    async fn still_detects_when_bot_blocking_is_disabled_but_does_not_enforce() {
        let detector = detector();
        let headers = HeaderMap::new();
        let result = detector.check_bot_blocking(input(&headers, false, base_payload())).await.unwrap();
        assert!(!result.enforced);
    }

    #[tokio::test]
    async fn marks_the_same_detection_as_enforced_when_blocking_is_enabled() {
        let detector = detector();
        let headers = HeaderMap::new();
        let result = detector.check_bot_blocking(input(&headers, true, base_payload())).await.unwrap();
        assert!(result.enforced);
    }

    #[tokio::test]
    async fn returns_none_for_a_clean_request_whether_or_not_blocking_is_enabled() {
        let detector = detector();
        let headers = browser_headers();
        for block_bots in [true, false] {
            assert_eq!(detector.check_bot_blocking(input(&headers, block_bots, clean_payload())).await, None);
        }
    }

    #[tokio::test]
    async fn skips_browser_shaped_layers_for_trusted_server_side_ingestion() {
        let detector = detector();
        let headers = HeaderMap::new();
        let result = detector
            .check_bot_blocking(BotBlockingInput {
                trusted_server_side_ingestion: true,
                ..input(&headers, true, base_payload())
            })
            .await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn does_not_convict_trusted_ingestion_reporting_a_browser_user_agent() {
        let detector = detector();
        let headers = HeaderMap::new();
        let payload = BotBlockingPayload { user_agent: Some("Mozilla/5.0 Chrome/120 Safari/537.36"), ..base_payload() };
        let result = detector
            .check_bot_blocking(BotBlockingInput {
                trusted_server_side_ingestion: true,
                ..input(&headers, true, payload)
            })
            .await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn classifies_a_crawler_user_agent_reported_through_trusted_ingestion() {
        let detector = detector();
        let headers = HeaderMap::new();
        let payload = BotBlockingPayload {
            user_agent: Some(
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot",
            ),
            ..base_payload()
        };
        let result = detector
            .check_bot_blocking(BotBlockingInput {
                trusted_server_side_ingestion: true,
                asn_lookup: &openai,
                ..input(&headers, true, payload)
            })
            .await
            .unwrap();
        assert!(result.enforced);
        assert_eq!(layers(&Some(result.clone())), vec![BotDetectionMethod::UaPattern]);
        let properties = result.event_properties;
        assert!(properties.detected_ua_pattern);
        assert!(
            !properties.detected_header_heuristics && !properties.detected_bot_asn && !properties.detected_rate_anomaly
        );
        assert_eq!(
            (properties.bot_name.as_str(), properties.bot_operator.as_str(), properties.bot_purpose.as_str()),
            ("GPTBot", "OpenAI", "ai_training")
        );
        assert_eq!(properties.asn_provider, "");
        assert_eq!(properties.bot_asn, None);
    }

    #[tokio::test]
    async fn leaves_enforcement_to_block_bots_for_trusted_ingestion() {
        let detector = detector();
        let headers = HeaderMap::new();
        let payload = BotBlockingPayload { user_agent: Some("ClaudeBot/1.0"), ..base_payload() };
        let result = detector
            .check_bot_blocking(BotBlockingInput {
                trusted_server_side_ingestion: true,
                ..input(&headers, false, payload)
            })
            .await
            .unwrap();
        assert!(!result.enforced);
    }

    #[tokio::test]
    async fn does_not_bypass_bot_blocking_for_an_unverified_bearer_header() {
        let detector = detector();
        let headers = header_map(&[("authorization", b"Bearer token")]);
        let result = detector.check_bot_blocking(input(&headers, true, base_payload())).await.unwrap();
        assert_eq!(result.message, "Bot detected using header heuristics");
    }

    #[tokio::test]
    async fn counts_requests_before_the_trusted_ingestion_bypass() {
        let detector = detector();
        let headers = HeaderMap::new();
        detector
            .check_bot_blocking(BotBlockingInput {
                trusted_server_side_ingestion: true,
                ..input(&headers, true, clean_payload())
            })
            .await;
        let stats = detector.stats.snapshot();
        assert_eq!((stats.total_requests, stats.total_bot_requests, stats.total_enforced_bot_requests), (1, 0, 0));
        assert_eq!(stats.bot_request_percentage, 0.0);
        assert_eq!(stats.client_bot_score_histogram["score0"], 1);
    }

    #[tokio::test]
    async fn separates_what_was_detected_from_what_was_enforced() {
        let detector = detector();
        let headers = HeaderMap::new();
        detector.check_bot_blocking(input(&headers, true, base_payload())).await;
        detector.check_bot_blocking(input(&headers, false, base_payload())).await;
        let stats = detector.stats.snapshot();
        assert_eq!((stats.total_requests, stats.total_bot_requests, stats.total_enforced_bot_requests), (2, 2, 1));
    }

    #[tokio::test]
    async fn records_missing_screen_dimensions_without_ever_convicting_on_them() {
        let detector = detector();
        let headers = browser_headers();
        let payload =
            BotBlockingPayload { client_bot_score: Some(0), client_bot_signal_mask: Some(0), ..base_payload() };
        assert_eq!(detector.check_bot_blocking(input(&headers, true, payload)).await, None);
        assert_eq!(detector.stats.snapshot().client_bot_signal_totals["missingScreenDimensions"], 1);
    }

    #[tokio::test]
    async fn does_not_raise_missing_screen_dimensions_for_mobile_sites() {
        let detector = detector();
        let headers = HeaderMap::new();
        let payload =
            BotBlockingPayload { client_bot_score: Some(0), client_bot_signal_mask: Some(0), ..base_payload() };
        detector.check_bot_blocking(BotBlockingInput { is_mobile_site: true, ..input(&headers, true, payload) }).await;
        assert_eq!(detector.stats.snapshot().client_bot_signal_totals["missingScreenDimensions"], 0);
    }

    #[tokio::test]
    async fn returns_bot_event_properties_for_detected_bots() {
        let detector = detector();
        let headers = HeaderMap::new();
        let result = detector.check_bot_blocking(input(&headers, true, base_payload())).await;
        let detected = result.clone().unwrap();
        assert_eq!(detected.message, "Bot detected using header heuristics");
        assert!(detected.event_properties.is_bot && detected.event_properties.detected_header_heuristics);
        assert_eq!(layers(&result), vec![BotDetectionMethod::HeaderHeuristics]);

        let stats = detector.stats.snapshot();
        assert_eq!((stats.total_requests, stats.total_bot_requests), (1, 1));
        assert_eq!(stats.bot_request_percentage, 100.0);
        assert_eq!(stats.totals["header_heuristics"], 1);
        assert_eq!(stats.client_bot_score_histogram["missing"], 1);
        assert_eq!(stats.client_bot_signal_totals["missingMask"], 1);
    }

    #[tokio::test]
    async fn skips_browser_shaped_layers_for_mobile_sites() {
        let detector = detector();
        let headers = header_map(&[("user-agent", b"okhttp/4.12.0")]);
        let payload = BotBlockingPayload {
            user_agent: Some("okhttp/4.12.0"),
            client_bot_score: Some(0),
            client_bot_signal_mask: Some(0),
            ..base_payload()
        };
        assert!(detector.check_bot_blocking(input(&headers, true, payload)).await.is_some());
        let as_mobile = detector
            .check_bot_blocking(BotBlockingInput { is_mobile_site: true, ..input(&headers, true, payload) })
            .await;
        assert_eq!(as_mobile, None);
    }

    #[tokio::test]
    async fn still_flags_mobile_traffic_through_client_signals() {
        let detector = detector();
        let headers = header_map(&[("user-agent", b"okhttp/4.12.0")]);
        let payload = BotBlockingPayload {
            user_agent: Some("okhttp/4.12.0"),
            client_bot_score: Some(3),
            client_bot_signal_mask: Some(i64::from(ClientBotSignal::AutomationApi.mask())),
            ..base_payload()
        };
        let result = detector
            .check_bot_blocking(BotBlockingInput { is_mobile_site: true, ..input(&headers, true, payload) })
            .await;
        assert_eq!(result.as_ref().unwrap().message, "Bot detected using client signals");
        assert_eq!(layers(&result), vec![BotDetectionMethod::ClientSignals]);
    }

    #[tokio::test]
    async fn records_client_bot_score_and_signal_aggregates() {
        let detector = detector();
        let headers = browser_headers();
        let web = BotBlockingPayload { screen_width: Some(1512.0), screen_height: Some(982.0), ..base_payload() };
        let mask = |signal: ClientBotSignal| Some(i64::from(signal.mask()));
        for (score, signal_mask) in [
            (None, None),
            (Some(0), Some(0)),
            (Some(1), mask(ClientBotSignal::SwiftShader)),
            (Some(2), mask(ClientBotSignal::ZeroOuterDimensions)),
            (Some(3), mask(ClientBotSignal::AutomationApi)),
        ] {
            let payload = BotBlockingPayload { client_bot_score: score, client_bot_signal_mask: signal_mask, ..web };
            detector.check_bot_blocking(input(&headers, true, payload)).await;
        }

        let stats = detector.stats.snapshot();
        assert_eq!((stats.total_requests, stats.total_bot_requests), (5, 1));
        assert_eq!(stats.bot_request_percentage, 20.0);
        assert_eq!(stats.client_bot_score_histogram.values().copied().collect::<Vec<_>>(), vec![1, 1, 1, 1, 1]);
        let totals = &stats.client_bot_signal_totals;
        for (name, expected) in [
            ("missingMask", 1),
            ("automationApi", 1),
            ("zeroOuterDimensions", 1),
            ("missingChrome", 0),
            ("swiftShader", 1),
            ("emptyPlugins", 0),
            ("defaultViewport800x600", 0),
            ("defaultViewport1024x768", 0),
            ("impossibleDimensions", 0),
            ("outerDimensionsWeird", 0),
            ("pluginApiAbsence", 0),
            ("unknownMaskBits", 0),
        ] {
            assert_eq!(totals[name], expected, "{name}");
        }
    }

    const HEADLESS_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36";

    #[tokio::test]
    async fn collects_every_matching_bot_signal_before_returning() {
        let detector = detector();
        let headers = header_map(&[("user-agent", HEADLESS_UA.as_bytes())]);
        let payload = BotBlockingPayload {
            client_bot_score: Some(3),
            screen_width: Some(800.0),
            screen_height: Some(600.0),
            ..base_payload()
        };
        let result = detector.check_bot_blocking(input(&headers, true, payload)).await;
        let detected = result.clone().unwrap();
        assert_eq!(detected.message, "Bot detected using ua-pattern");
        let properties = &detected.event_properties;
        assert!(
            properties.detected_ua_pattern
                && properties.detected_header_heuristics
                && properties.detected_client_signals
        );
        assert_eq!(
            (properties.matched_ua_pattern.as_str(), properties.bot_category.as_str()),
            ("headlesschrome", "headless")
        );
        assert_eq!(
            layers(&result),
            vec![
                BotDetectionMethod::UaPattern,
                BotDetectionMethod::HeaderHeuristics,
                BotDetectionMethod::ClientSignals
            ]
        );
    }

    async fn client_signals_for(user_agent: &str, width: f64, height: f64) -> Option<BotDetectionResult> {
        let detector = detector();
        let headers = with_user_agent(&browser_headers(), user_agent);
        let payload = BotBlockingPayload {
            client_bot_score: Some(0),
            client_bot_signal_mask: Some(0),
            screen_width: Some(width),
            screen_height: Some(height),
            ..base_payload()
        };
        detector.check_bot_blocking(input(&headers, true, payload)).await
    }

    #[tokio::test]
    async fn moves_default_viewport_fingerprints_into_client_signals() {
        let result =
            client_signals_for("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36", 1024.0, 768.0)
                .await;
        assert_eq!(result.as_ref().unwrap().message, "Bot detected using client signals");
        assert!(result.as_ref().unwrap().event_properties.detected_client_signals);
        assert_eq!(layers(&result), vec![BotDetectionMethod::ClientSignals]);
        assert_eq!(result.unwrap().detections[0].client_signals, Some(vec![ClientBotSignal::DefaultViewport1024x768]));
    }

    #[tokio::test]
    async fn convicts_the_1280x1200_headless_geometry_on_a_desktop_ua() {
        let result =
            client_signals_for("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/116 Safari/537.36", 1280.0, 1200.0)
                .await;
        assert_eq!(layers(&result), vec![BotDetectionMethod::ClientSignals]);
        assert_eq!(result.unwrap().detections[0].client_signals, Some(vec![ClientBotSignal::DefaultViewport1280x1200]));
    }

    #[tokio::test]
    async fn leaves_1280x1200_alone_on_a_mobile_ua() {
        let result = client_signals_for(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
            1280.0,
            1200.0,
        )
        .await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn does_not_convict_on_weak_client_signals_alone() {
        let detector = detector();
        let headers = browser_headers();
        let payload = BotBlockingPayload {
            client_bot_score: Some(3),
            client_bot_signal_mask: Some(i64::from(
                ClientBotSignal::ZeroOuterDimensions.mask() | ClientBotSignal::SwiftShader.mask(),
            )),
            ..base_payload()
        };
        assert_eq!(detector.check_bot_blocking(input(&headers, true, payload)).await, None);
    }

    #[tokio::test]
    async fn does_not_convict_on_a_client_score_sent_without_a_mask() {
        let detector = detector();
        let headers = browser_headers();
        let payload = BotBlockingPayload { client_bot_score: Some(5), ..base_payload() };
        assert_eq!(detector.check_bot_blocking(input(&headers, true, payload)).await, None);
    }

    #[tokio::test]
    async fn uses_weak_client_signals_as_supporting_evidence() {
        let detector = detector();
        let headers = with_user_agent(&browser_headers(), HEADLESS_UA);
        let weak_mask = i64::from(ClientBotSignal::ZeroOuterDimensions.mask() | ClientBotSignal::SwiftShader.mask());
        let payload = BotBlockingPayload {
            screen_width: Some(1512.0),
            screen_height: Some(982.0),
            client_bot_score: Some(3),
            client_bot_signal_mask: Some(weak_mask),
            ..base_payload()
        };
        let result = detector.check_bot_blocking(input(&headers, true, payload)).await;
        let detected = result.clone().unwrap();
        assert_eq!(detected.message, "Bot detected using ua-pattern");
        assert!(detected.event_properties.detected_ua_pattern && detected.event_properties.detected_client_signals);
        assert_eq!(detected.event_properties.client_bot_score, Some(3));
        assert_eq!(detected.event_properties.client_signal_mask, Some(weak_mask));
        assert!(layers(&result).contains(&BotDetectionMethod::ClientSignals));
    }

    #[tokio::test]
    async fn does_not_let_two_supporting_signals_convict_each_other() {
        let detector = detector();
        let headers = browser_headers();
        let payload = BotBlockingPayload {
            ip_address: "18.0.0.1",
            client_bot_score: Some(3),
            client_bot_signal_mask: Some(i64::from(
                ClientBotSignal::ZeroOuterDimensions.mask() | ClientBotSignal::SwiftShader.mask(),
            )),
            ..base_payload()
        };
        let result = detector
            .check_bot_blocking(BotBlockingInput { asn_lookup: &amazon, ..input(&headers, true, payload) })
            .await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn does_not_block_a_generic_hosting_asn_by_itself() {
        let detector = detector();
        let headers = browser_headers();
        let payload = BotBlockingPayload {
            ip_address: "18.0.0.1",
            client_bot_score: Some(0),
            client_bot_signal_mask: Some(0),
            ..base_payload()
        };
        let result = detector
            .check_bot_blocking(BotBlockingInput { asn_lookup: &amazon, ..input(&headers, true, payload) })
            .await;
        assert_eq!(result, None);
        let stats = detector.stats.snapshot();
        assert_eq!((stats.total_requests, stats.total_bot_requests, stats.totals["bot_asn"]), (1, 0, 0));
    }

    #[tokio::test]
    async fn uses_a_generic_hosting_asn_as_supporting_evidence() {
        let detector = detector();
        let headers = browser_headers();
        let payload = BotBlockingPayload {
            ip_address: "18.0.0.1",
            client_bot_score: Some(3),
            client_bot_signal_mask: Some(i64::from(ClientBotSignal::AutomationApi.mask())),
            ..base_payload()
        };
        let result = detector
            .check_bot_blocking(BotBlockingInput { asn_lookup: &amazon, ..input(&headers, true, payload) })
            .await;
        let detected = result.clone().unwrap();
        assert_eq!(detected.message, "Bot detected using client signals");
        assert!(detected.event_properties.detected_client_signals && detected.event_properties.detected_bot_asn);
        assert_eq!(detected.event_properties.bot_asn, Some(16509));
        assert_eq!(layers(&result), vec![BotDetectionMethod::ClientSignals, BotDetectionMethod::BotAsn]);
    }

    #[tokio::test]
    async fn still_blocks_curated_bot_provider_asns_alone() {
        let detector = detector();
        let headers = browser_headers();
        let payload = BotBlockingPayload {
            ip_address: "57.154.0.1",
            client_bot_score: Some(0),
            client_bot_signal_mask: Some(0),
            ..base_payload()
        };
        let result = detector
            .check_bot_blocking(BotBlockingInput { asn_lookup: &openai, ..input(&headers, true, payload) })
            .await;
        let detected = result.clone().unwrap();
        assert_eq!(detected.message, "Bot detected using bot asn");
        assert!(detected.event_properties.detected_bot_asn);
        assert_eq!(detected.event_properties.bot_asn, Some(401518));
        assert_eq!(detected.event_properties.asn_provider, "OpenAI");
        assert_eq!(layers(&result), vec![BotDetectionMethod::BotAsn]);
    }

    #[tokio::test]
    async fn adds_a_rate_anomaly_layer_after_a_request_burst() {
        let detector = detector();
        let headers = browser_headers();
        let payload = BotBlockingPayload {
            client_bot_score: Some(0),
            hostname: Some("example.com"),
            pathname: Some("/"),
            ..base_payload()
        };
        let mut result = None;
        for _ in 0..31 {
            result = detector.check_bot_blocking(input(&headers, true, payload)).await;
        }
        let detected = result.clone().unwrap();
        assert_eq!(detected.message, "Bot detected using rate anomaly");
        assert_eq!(layers(&result), vec![BotDetectionMethod::RateAnomaly]);
        let rules: Vec<&str> =
            detected.detections[0].anomaly_reasons.as_ref().unwrap().iter().map(|reason| reason.rule).collect();
        assert!(rules.contains(&"tuple_events_10s"));
        assert!(detected.event_properties.anomaly_reasons.contains("tuple_events_10s"));
        assert!(detected.event_properties.anomaly_score > 0);
    }

    #[tokio::test]
    async fn leaves_the_anomaly_audit_fields_empty_when_another_layer_convicted() {
        let detector = detector();
        let user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        let headers = with_user_agent(&browser_headers(), user_agent);
        let payload = BotBlockingPayload { user_agent: Some(user_agent), ..base_payload() };
        let result = detector.check_bot_blocking(input(&headers, true, payload)).await.unwrap();
        assert_eq!((result.event_properties.anomaly_reasons.as_str(), result.event_properties.anomaly_score), ("", 0));
    }

    const STALE_ANDROID: &str = "Mozilla/5.0 (Linux; Android 8.0; SM-G930F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.0.0 Mobile Safari/537.36";

    #[tokio::test]
    async fn convicts_a_browser_release_too_old_to_have_run_the_tracker() {
        let detector = detector();
        let headers = with_user_agent(&browser_headers(), STALE_ANDROID);
        let payload = BotBlockingPayload {
            user_agent: Some(STALE_ANDROID),
            client_bot_score: Some(0),
            client_bot_signal_mask: Some(0),
            screen_width: Some(375.0),
            screen_height: Some(812.0),
            ..base_payload()
        };
        let result = detector.check_bot_blocking(input(&headers, true, payload)).await;
        let detected = result.clone().unwrap();
        assert_eq!(detected.message, "Bot detected using ua-pattern");
        assert!(detected.event_properties.detected_ua_pattern);
        assert_eq!(
            (detected.event_properties.bot_category.as_str(), detected.event_properties.matched_ua_pattern.as_str()),
            ("stale_version", "Chrome/40")
        );
        assert_eq!(layers(&result), vec![BotDetectionMethod::UaPattern]);
    }

    #[tokio::test]
    async fn keeps_a_stale_version_from_overriding_a_more_specific_match() {
        let detector = detector();
        let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/40.0.0.0 Safari/537.36";
        let headers = with_user_agent(&browser_headers(), user_agent);
        let payload = BotBlockingPayload {
            user_agent: Some(user_agent),
            client_bot_score: Some(0),
            client_bot_signal_mask: Some(0),
            ..base_payload()
        };
        let result = detector.check_bot_blocking(input(&headers, true, payload)).await.unwrap();
        assert_eq!(
            (result.event_properties.bot_category.as_str(), result.event_properties.matched_ua_pattern.as_str()),
            ("headless", "headlesschrome")
        );
    }

    #[tokio::test]
    async fn skips_the_stale_version_rule_for_mobile_sites() {
        let detector = detector();
        let headers = with_user_agent(&browser_headers(), STALE_ANDROID);
        let payload = BotBlockingPayload {
            user_agent: Some(STALE_ANDROID),
            client_bot_score: Some(0),
            client_bot_signal_mask: Some(0),
            ..base_payload()
        };
        let result = detector
            .check_bot_blocking(BotBlockingInput { is_mobile_site: true, ..input(&headers, true, payload) })
            .await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn convicts_a_square_screen() {
        let detector = detector();
        let headers = browser_headers();
        let payload = BotBlockingPayload {
            client_bot_score: Some(0),
            client_bot_signal_mask: Some(0),
            screen_width: Some(2000.0),
            screen_height: Some(2000.0),
            ..base_payload()
        };
        let result = detector.check_bot_blocking(input(&headers, true, payload)).await.unwrap();
        assert_eq!(result.message, "Bot detected using client signals");
        assert!(result.event_properties.detected_client_signals);
        assert_eq!(result.detections[0].client_signals, Some(vec![ClientBotSignal::SquareScreen]));
    }

    #[tokio::test]
    async fn convicts_a_square_screen_on_a_mobile_ua_too() {
        let result = client_signals_for(
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36",
            2000.0,
            2000.0,
        )
        .await;
        assert_eq!(result.unwrap().detections[0].client_signals, Some(vec![ClientBotSignal::SquareScreen]));
    }

    #[tokio::test]
    async fn convicts_screen_dimensions_outside_the_real_range() {
        for (width, height) in [(1.0, 1.0), (16384.0, 16384.0), (1920.0, 10000.0)] {
            let detector = detector();
            let headers = browser_headers();
            let payload = BotBlockingPayload {
                client_bot_score: Some(0),
                client_bot_signal_mask: Some(0),
                screen_width: Some(width),
                screen_height: Some(height),
                ..base_payload()
            };
            let result = detector.check_bot_blocking(input(&headers, true, payload)).await.unwrap();
            assert_eq!(
                result.detections[0].client_signals,
                Some(vec![ClientBotSignal::ImpossibleDimensions]),
                "{width}x{height}"
            );
        }
    }

    #[tokio::test]
    async fn leaves_real_displays_at_the_edges_of_the_plausible_range_alone() {
        let detector = detector();
        let headers = browser_headers();
        for (width, height) in [(320.0, 480.0), (7680.0, 4320.0), (1920.0, 1080.0)] {
            let payload = BotBlockingPayload {
                client_bot_score: Some(0),
                client_bot_signal_mask: Some(0),
                screen_width: Some(width),
                screen_height: Some(height),
                ..base_payload()
            };
            assert_eq!(detector.check_bot_blocking(input(&headers, true, payload)).await, None, "{width}x{height}");
        }
    }

    #[test]
    fn check_bot_blocking_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        let detector = detector();
        let headers = HeaderMap::new();
        assert_send(detector.check_bot_blocking(input(&headers, true, base_payload())));
    }
}
