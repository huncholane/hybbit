//! The rate and crawl-shape anomaly layer, ported from
//! server/src/services/tracker/botBlocking/anomalyScorer.ts.
//!
//! Counters live in Redis so every worker, replica and both backends share one
//! view: an in-process map only sees 1/N of the traffic behind a load balancer.
//! Every key, member, window and cap below is the one Node writes, through the
//! byte-identical `anomalyObserve` script, so Node and Rust increment the same
//! counters during the cutover. When Redis fails the in-process counters take
//! over for that request (accuracy degrades under clustering, detection keeps
//! working), and `DISABLE_REDIS_ANOMALY=true` pins scoring to them.
//!
//! Reasons come back in two lists. Convicting rules are keyed on a single actor
//! or on a distribution no organic population produces, and can open a
//! conviction. Supporting rules are keyed on dimensions real visitors share (an
//! IP, a popular browser) plus long-window volume, and only ever add to a score
//! convicting evidence has already opened. See the botBlocking README for the
//! reasoning behind each rule; the constants' comments below keep the numbers'
//! provenance.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::LazyLock,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use indexmap::IndexMap;
use redis::aio::ConnectionManager;
use serde::Serialize;

use super::{
    anomaly_observe::{AnomalyCounterKind, AnomalyCounterSpec, AnomalyDistribution, anomaly_observe},
    enumeration_observer::{ENUMERATION_BUCKET_MS, EnumerationObservation, EnumerationObserver, EnumerationReading},
    js::{JsRegex, JsText, PROCESS_ID, js_number_to_string, normalize_dimension, now_ms},
    site_baseline::{SiteBaseline, SiteBaselines},
};

const SECOND: i64 = 1000;
const MINUTE: i64 = 60 * SECOND;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * 60 * MINUTE;
const TEN_MINUTES: i64 = 10 * MINUTE;

const ANOMALY_SCORE_THRESHOLD: i64 = 4;
const CLEANUP_INTERVAL_MS: i64 = 60 * SECOND;
const MAX_COUNTER_BUCKET_SIZE: usize = 512;
const MAX_DISTINCT_BUCKET_SIZE: usize = 512;
const MAX_DISTRIBUTION_FIELDS: usize = 128;
/// Bounds only the in-process fallback's distinct sets; Redis uses HyperLogLog.
const MAX_LOCAL_DISTINCT_VALUES: usize = 4096;
/// Bounds how many keys the in-process fallback's plain counters hold at once.
const MAX_LOCAL_COUNTER_KEYS: usize = 100_000;

/// Cohort uniformity: a cohort (screen, language, browser family on one site)
/// spread evenly across many browser versions inside a one-hour bucket. Organic
/// cohorts peak on the current version (>= 0.74 modal share at this volume); the
/// fleet that motivated the rule sat at 0.09-0.15 across 16 versions. It is the
/// only rule that catches a paced distributed crawler, and the hour bucket is
/// what made it fire at all (a minute bucket never did in 14 days).
const COHORT_MIN_EVENTS_1H: i64 = 100;
const COHORT_MIN_DISTINCT_VERSIONS: i64 = 8;
const COHORT_MAX_MODAL_SHARE: f64 = 0.25;

/// Long-window per-actor volume, supporting only and permanently so: the actor
/// is the exact request IP, and an office or carrier NAT is one address shared
/// by hundreds of people. Dropped for actors showing many user agents.
const ACTOR_EVENTS_1D_THRESHOLD: i64 = 1000;
const ACTOR_EVENTS_1D_SCORE: i64 = 1;
const PROXY_MERGE_MAX_USER_AGENTS: i64 = 3;

/// Site flood: the site's 10-minute volume against twenty times its padded weekly
/// median (at least 100 events). The gate alone never convicts; inside a flood a
/// cohort convicts when it is a quarter of the site, 60% distinct actors and 95%
/// direct, and an actor convicts at 200 events a day from a hosting address only
/// (a residential version convicted two real power users on its first day).
const FLOOD_MULTIPLE: f64 = 20.0;
const FLOOD_MIN_EVENTS_10M: f64 = 100.0;
const FLOOD_COHORT_MIN_EVENTS_10M: i64 = 50;
const FLOOD_COHORT_MIN_ACTOR_RATIO: f64 = 0.6;
const FLOOD_COHORT_MIN_DIRECT_SHARE: f64 = 0.95;
const FLOOD_COHORT_MIN_SITE_SHARE: f64 = 0.25;
const FLOOD_ACTOR_EVENTS_1D_HOSTING: i64 = 200;

/// A hosting address convicts on 1,000 events a day on its own. SASE egress
/// (Cato, Zscaler, Netskope) routes whole companies through cloud addresses and
/// is exempt.
const HOSTING_ACTOR_EVENTS_1D_THRESHOLD: i64 = 1000;
const SASE_EGRESS_ASNS: [u32; 3] = [
    13150, // Cato Networks
    22616, // Zscaler
    55256, // Netskope
];

/// Auto-captured interaction events fire in legitimate bursts (a human on a
/// configurator), so they skip the tuple event counters and get their own
/// beyond-human burst rule.
const INTERACTION_EVENT_TYPES: [&str; 3] = ["button_click", "input_change", "copy"];

/// `AnomalyReason`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyReason {
    pub rule: &'static str,
    pub score: i64,
    pub value: i64,
    pub threshold: i64,
    pub window_seconds: i64,
}

/// `AnomalyCounters`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyCounters {
    pub tuple_events_10s: i64,
    pub tuple_events_60s: i64,
    pub tuple_interaction_events_10s: i64,
    pub tuple_distinct_paths_60s: i64,
    pub ip_events_60s: i64,
    pub ip_distinct_user_agents_5m: i64,
    pub ip_distinct_hosts_60s: i64,
    pub site_user_agent_events_60s: i64,
    pub missing_client_score_60s: i64,
    pub cohort_events_1h: i64,
    pub cohort_top_version_events_1h: i64,
    pub cohort_distinct_versions_1h: i64,
    pub actor_events_1d: i64,
    pub site_events_10m: i64,
    pub site_distinct_actors_10m: i64,
    pub cohort_events_10m: i64,
    pub cohort_distinct_actors_10m: i64,
    pub cohort_direct_events_10m: i64,
    pub enumeration_events_15m: i64,
    pub enumeration_distinct_paths_15m: i64,
    pub enumeration_distinct_actors_15m: i64,
    pub enumeration_direct_events_15m: i64,
}

/// `keyof AnomalyCounters` for the counters a plan observes directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterName {
    TupleEvents10s,
    TupleEvents60s,
    TupleInteractionEvents10s,
    TupleDistinctPaths60s,
    IpEvents60s,
    IpDistinctUserAgents5m,
    IpDistinctHosts60s,
    SiteUserAgentEvents60s,
    MissingClientScore60s,
    CohortEvents1h,
    ActorEvents1d,
    SiteEvents10m,
    SiteDistinctActors10m,
    CohortEvents10m,
    CohortDistinctActors10m,
    CohortDirectEvents10m,
    EnumerationEvents15m,
    EnumerationDistinctPaths15m,
    EnumerationDistinctActors15m,
    EnumerationDirectEvents15m,
}

impl AnomalyCounters {
    fn set(&mut self, name: CounterName, value: i64) {
        let slot = match name {
            CounterName::TupleEvents10s => &mut self.tuple_events_10s,
            CounterName::TupleEvents60s => &mut self.tuple_events_60s,
            CounterName::TupleInteractionEvents10s => &mut self.tuple_interaction_events_10s,
            CounterName::TupleDistinctPaths60s => &mut self.tuple_distinct_paths_60s,
            CounterName::IpEvents60s => &mut self.ip_events_60s,
            CounterName::IpDistinctUserAgents5m => &mut self.ip_distinct_user_agents_5m,
            CounterName::IpDistinctHosts60s => &mut self.ip_distinct_hosts_60s,
            CounterName::SiteUserAgentEvents60s => &mut self.site_user_agent_events_60s,
            CounterName::MissingClientScore60s => &mut self.missing_client_score_60s,
            CounterName::CohortEvents1h => &mut self.cohort_events_1h,
            CounterName::ActorEvents1d => &mut self.actor_events_1d,
            CounterName::SiteEvents10m => &mut self.site_events_10m,
            CounterName::SiteDistinctActors10m => &mut self.site_distinct_actors_10m,
            CounterName::CohortEvents10m => &mut self.cohort_events_10m,
            CounterName::CohortDistinctActors10m => &mut self.cohort_distinct_actors_10m,
            CounterName::CohortDirectEvents10m => &mut self.cohort_direct_events_10m,
            CounterName::EnumerationEvents15m => &mut self.enumeration_events_15m,
            CounterName::EnumerationDistinctPaths15m => &mut self.enumeration_distinct_paths_15m,
            CounterName::EnumerationDistinctActors15m => &mut self.enumeration_distinct_actors_15m,
            CounterName::EnumerationDirectEvents15m => &mut self.enumeration_direct_events_15m,
        };
        *slot = value;
    }
}

/// How the scorer should find the site's baseline (`AnomalyInput.siteBaseline`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum BaselineSource {
    /// Read the shared baseline map (`undefined` in Node).
    #[default]
    Lookup,
    /// Treat the site as having no baseline (`null`, tests only).
    Absent,
    /// Use this baseline (tests only).
    Given(SiteBaseline),
}

/// `AnomalyInput`.
#[derive(Clone, Debug, Default)]
pub struct AnomalyInput<'a> {
    /// Numeric site id; counters are namespaced by it.
    pub site_id: i32,
    pub ip_address: &'a str,
    pub user_agent: &'a str,
    pub hostname: Option<&'a str>,
    pub pathname: Option<&'a str>,
    pub event_type: Option<&'a str>,
    /// The referrer as it arrived, not the stored value.
    pub referrer: Option<&'a str>,
    pub has_client_bot_score: bool,
    /// Cohort dimensions; the cohort rules are skipped unless all resolve.
    pub screen_width: Option<f64>,
    pub screen_height: Option<f64>,
    pub language: Option<&'a str>,
    /// Whether the request address resolved to hosting or bot-provider space.
    pub is_hosting_asn: bool,
    pub asn: Option<u32>,
    pub site_baseline: BaselineSource,
    /// Overrides the clock; tests only.
    pub now_ms: Option<i64>,
}

/// `AnomalyResult`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyResult {
    pub is_anomalous: bool,
    pub score: i64,
    /// Rules describing a single actor; only these can open a conviction.
    pub convicting_reasons: Vec<AnomalyReason>,
    /// Rules keyed on shared dimensions; they only raise an opened score.
    pub supporting_reasons: Vec<AnomalyReason>,
    /// Both lists, convicting first, for the audit record.
    pub reasons: Vec<AnomalyReason>,
    pub counters: AnomalyCounters,
    /// Shadow-mode enumeration reading; recorded, never scored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enumeration: Option<EnumerationObservation>,
}

// ---------------------------------------------------------------------------
// In-process fallback counters, each mirroring its Redis counterpart.
// ---------------------------------------------------------------------------

/// `pruneTimestamps`: drop the leading timestamps older than the window, then
/// cap the bucket.
fn prune_timestamps(bucket: &mut VecDeque<i64>, now_ms: i64, window_ms: i64) -> usize {
    let oldest_allowed = now_ms - window_ms;
    while bucket.front().is_some_and(|timestamp| *timestamp < oldest_allowed) {
        bucket.pop_front();
    }
    while bucket.len() > MAX_COUNTER_BUCKET_SIZE {
        bucket.pop_front();
    }
    bucket.len()
}

/// `pruneDistinct`: drop values last seen before the window, then evict in
/// first-insertion order (a JavaScript Map keeps a key's position on update).
fn prune_distinct(bucket: &mut IndexMap<String, i64>, now_ms: i64, window_ms: i64) -> usize {
    let oldest_allowed = now_ms - window_ms;
    bucket.retain(|_, last_seen| *last_seen >= oldest_allowed);
    while bucket.len() > MAX_DISTINCT_BUCKET_SIZE {
        bucket.shift_remove_index(0);
    }
    bucket.len()
}

/// `RollingCounter`: event timestamps per key over a sliding window.
#[derive(Default)]
struct RollingCounter {
    buckets: HashMap<String, VecDeque<i64>>,
}

impl RollingCounter {
    fn observe(&mut self, key: &str, now_ms: i64, window_ms: i64) -> i64 {
        let bucket = self.buckets.entry(key.to_string()).or_default();
        bucket.push_back(now_ms);
        prune_timestamps(bucket, now_ms, window_ms) as i64
    }

    fn cleanup(&mut self, now_ms: i64, max_window_ms: i64) {
        self.buckets.retain(|_, bucket| prune_timestamps(bucket, now_ms, max_window_ms) > 0);
    }
}

/// `RollingDistinctCounter`: value to last-seen time per key over a sliding window.
#[derive(Default)]
struct RollingDistinctCounter {
    buckets: HashMap<String, IndexMap<String, i64>>,
}

impl RollingDistinctCounter {
    fn observe(&mut self, key: &str, value: &str, now_ms: i64, window_ms: i64) -> i64 {
        let bucket = self.buckets.entry(key.to_string()).or_default();
        bucket.insert(value.to_string(), now_ms);
        prune_distinct(bucket, now_ms, window_ms) as i64
    }

    fn cleanup(&mut self, now_ms: i64, max_window_ms: i64) {
        self.buckets.retain(|_, bucket| prune_distinct(bucket, now_ms, max_window_ms) > 0);
    }
}

/// `BucketedDistributionCounter`: value to count inside a tumbling bucket.
#[derive(Default)]
struct BucketedDistributionCounter {
    buckets: HashMap<String, (i64, HashMap<String, i64>)>,
}

impl BucketedDistributionCounter {
    fn observe(
        &mut self,
        key: &str,
        value: &str,
        now_ms: i64,
        window_ms: i64,
        max_fields: usize,
    ) -> AnomalyDistribution {
        let bucket_start_ms = now_ms.div_euclid(window_ms) * window_ms;
        let bucket = self.buckets.entry(key.to_string()).or_insert_with(|| (bucket_start_ms, HashMap::new()));
        if bucket.0 != bucket_start_ms {
            *bucket = (bucket_start_ms, HashMap::new());
        }

        let counts = &mut bucket.1;
        if let Some(count) = counts.get_mut(value) {
            *count += 1;
        } else if counts.len() < max_fields {
            counts.insert(value.to_string(), 1);
        }

        let total = counts.values().sum();
        let top = counts.values().copied().max().unwrap_or(0).max(0);
        AnomalyDistribution { total, top, distinct: counts.len() as i64 }
    }

    fn cleanup(&mut self, now_ms: i64, window_ms: i64) {
        self.buckets.retain(|_, (start_ms, _)| *start_ms + window_ms >= now_ms);
    }
}

/// `BucketedCounter`: a plain count inside a tumbling bucket, bounded by key
/// count. Past the cap a new key counts as zero rather than evicting anyone:
/// eviction would let a heavy actor clear its own count by cycling keys, and
/// zero keeps the fallback failing towards saying nothing.
#[derive(Default)]
pub struct BucketedCounter {
    buckets: HashMap<String, (i64, i64)>,
}

impl BucketedCounter {
    pub fn observe(&mut self, key: &str, now_ms: i64, window_ms: i64, max_keys: usize) -> i64 {
        let bucket_start_ms = now_ms.div_euclid(window_ms) * window_ms;
        match self.buckets.get_mut(key) {
            Some(bucket) => {
                // A key already present is rolled over, not added, so it is let
                // through at capacity.
                if bucket.0 != bucket_start_ms {
                    *bucket = (bucket_start_ms, 0);
                }
                bucket.1 += 1;
                bucket.1
            }
            None => {
                if self.buckets.len() >= max_keys {
                    return 0;
                }
                self.buckets.insert(key.to_string(), (bucket_start_ms, 1));
                1
            }
        }
    }

    pub fn cleanup(&mut self, now_ms: i64, window_ms: i64) {
        self.buckets.retain(|_, (start_ms, _)| *start_ms + window_ms >= now_ms);
    }
}

/// `BucketedDistinctCounter`: distinct values inside a tumbling bucket, capped,
/// so above the cap it undercounts (towards saying nothing).
#[derive(Default)]
struct BucketedDistinctCounter {
    buckets: HashMap<String, (i64, HashSet<String>)>,
}

impl BucketedDistinctCounter {
    fn observe(&mut self, key: &str, value: &str, now_ms: i64, window_ms: i64, max_values: usize) -> i64 {
        let bucket_start_ms = now_ms.div_euclid(window_ms) * window_ms;
        let bucket = self.buckets.entry(key.to_string()).or_insert_with(|| (bucket_start_ms, HashSet::new()));
        if bucket.0 != bucket_start_ms {
            *bucket = (bucket_start_ms, HashSet::new());
        }
        if bucket.1.len() < max_values {
            bucket.1.insert(value.to_string());
        }
        bucket.1.len() as i64
    }

    fn cleanup(&mut self, now_ms: i64, window_ms: i64) {
        self.buckets.retain(|_, (start_ms, _)| *start_ms + window_ms >= now_ms);
    }
}

/// Node's module-level counters, one set per scorer.
#[derive(Default)]
struct LocalCounters {
    tuple_events_10s: RollingCounter,
    tuple_events_60s: RollingCounter,
    tuple_interaction_events_10s: RollingCounter,
    ip_events_60s: RollingCounter,
    site_user_agent_events_60s: RollingCounter,
    missing_client_score_60s: RollingCounter,
    tuple_distinct_paths_60s: RollingDistinctCounter,
    ip_distinct_user_agents_5m: RollingDistinctCounter,
    ip_distinct_hosts_60s: RollingDistinctCounter,
    cohort_browser_versions_1h: BucketedDistributionCounter,
    actor_events_1d: BucketedCounter,
    site_events_10m: BucketedCounter,
    cohort_events_10m: BucketedCounter,
    cohort_direct_events_10m: BucketedCounter,
    site_distinct_actors_10m: BucketedDistinctCounter,
    cohort_distinct_actors_10m: BucketedDistinctCounter,
    enumeration_events_15m: BucketedCounter,
    enumeration_direct_events_15m: BucketedCounter,
    enumeration_distinct_paths_15m: BucketedDistinctCounter,
    enumeration_distinct_actors_15m: BucketedDistinctCounter,
    last_cleanup_ms: i64,
}

impl LocalCounters {
    /// `maybeCleanup`
    fn maybe_cleanup(&mut self, now_ms: i64) {
        if now_ms - self.last_cleanup_ms < CLEANUP_INTERVAL_MS {
            return;
        }
        self.last_cleanup_ms = now_ms;

        self.tuple_events_10s.cleanup(now_ms, 10 * SECOND);
        self.tuple_events_60s.cleanup(now_ms, MINUTE);
        self.tuple_interaction_events_10s.cleanup(now_ms, 10 * SECOND);
        self.ip_events_60s.cleanup(now_ms, MINUTE);
        self.site_user_agent_events_60s.cleanup(now_ms, MINUTE);
        self.missing_client_score_60s.cleanup(now_ms, MINUTE);
        self.tuple_distinct_paths_60s.cleanup(now_ms, MINUTE);
        self.ip_distinct_user_agents_5m.cleanup(now_ms, 5 * MINUTE);
        self.ip_distinct_hosts_60s.cleanup(now_ms, MINUTE);
        self.cohort_browser_versions_1h.cleanup(now_ms, HOUR);
        self.actor_events_1d.cleanup(now_ms, DAY);
        self.site_events_10m.cleanup(now_ms, TEN_MINUTES);
        self.cohort_events_10m.cleanup(now_ms, TEN_MINUTES);
        self.cohort_direct_events_10m.cleanup(now_ms, TEN_MINUTES);
        self.site_distinct_actors_10m.cleanup(now_ms, TEN_MINUTES);
        self.cohort_distinct_actors_10m.cleanup(now_ms, TEN_MINUTES);
        self.enumeration_events_15m.cleanup(now_ms, ENUMERATION_BUCKET_MS);
        self.enumeration_direct_events_15m.cleanup(now_ms, ENUMERATION_BUCKET_MS);
        self.enumeration_distinct_paths_15m.cleanup(now_ms, ENUMERATION_BUCKET_MS);
        self.enumeration_distinct_actors_15m.cleanup(now_ms, ENUMERATION_BUCKET_MS);
    }
}

// ---------------------------------------------------------------------------
// The counter plan: every counter described once for both backends.
// ---------------------------------------------------------------------------

/// `CounterPlan`: a counter's Redis key and member plus the equivalent
/// in-process observation (`local_key`, the member as value, `local_window_ms`).
/// `enabled` is false for conditional counters, which read as zero.
#[derive(Clone, Debug, PartialEq)]
pub struct CounterPlan {
    pub name: CounterName,
    pub enabled: bool,
    pub kind: AnomalyCounterKind,
    pub redis_key: String,
    pub member: String,
    pub window_ms: i64,
    pub max_size: i64,
    local_key: String,
    local_window_ms: i64,
}

/// `EnumerationPlan`: the cohort bucket the enumeration observer reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumerationPlan {
    pub cohort_key: String,
    pub bucket: i64,
    /// Arrived with no referrer at all, judged on the raw value.
    pub is_direct: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AnomalyPlan {
    pub counters: Vec<CounterPlan>,
    pub enumeration: Option<EnumerationPlan>,
}

static BRANDED_BROWSER_PATTERN: LazyLock<JsRegex> =
    LazyLock::new(|| JsRegex::new(r"(Edg|EdgA|EdgiOS|OPR|SamsungBrowser|Firefox|FxiOS|CriOS|Chrome)\/(\d{1,4})"));
static GENERIC_VERSION_PATTERN: LazyLock<JsRegex> = LazyLock::new(|| JsRegex::new(r"Version\/(\d{1,4})"));

/// `getBrowserIdentity`: the browser family and major version, the cohort key's
/// grouping and the distribution's dimension. Chromium derivatives whose token
/// follows `Chrome/` (Edge, Opera) resolve to chrome because the leftmost match
/// wins; Samsung Internet and the iOS browsers keep their own family.
pub fn get_browser_identity(user_agent: &str) -> (String, String) {
    let text = JsText::new(user_agent);
    if let Some(found) = BRANDED_BROWSER_PATTERN.exec(&text) {
        return (text.group(&found, 1).unwrap_or_default().to_lowercase(), text.group(&found, 2).unwrap_or_default());
    }
    if let Some(found) = GENERIC_VERSION_PATTERN.exec(&text) {
        return ("safari".to_string(), text.group(&found, 1).unwrap_or_default());
    }
    (String::new(), String::new())
}

/// `hashValue`: 32-bit FNV-1a over UTF-16 code units, printed in base 36.
pub fn hash_value(value: &str) -> String {
    let mut hash: u32 = 0x811c_9dc5;
    for unit in value.encode_utf16() {
        hash ^= u32::from(unit);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    to_base36(hash)
}

fn to_base36(mut value: u32) -> String {
    if value == 0 {
        return "0".to_string();
    }
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(char::from_digit(value % 36, 36).unwrap_or('0'));
        value /= 36;
    }
    digits.iter().rev().collect()
}

/// `addReason`: record a rule only when its value exceeds the threshold.
fn add_reason(
    reasons: &mut Vec<AnomalyReason>,
    rule: &'static str,
    score: i64,
    value: i64,
    threshold: i64,
    window_seconds: i64,
) {
    if value <= threshold {
        return;
    }
    reasons.push(AnomalyReason { rule, score, value, threshold, window_seconds });
}

/// `isSiteInFlood`: the site's 10-minute volume against its own baseline. No
/// baseline, or one too young, is never a flood.
fn is_site_in_flood(counters: &AnomalyCounters, baseline: Option<SiteBaseline>) -> bool {
    let Some(baseline) = baseline.filter(|baseline| baseline.eligible) else {
        return false;
    };
    let gate = (FLOOD_MULTIPLE * baseline.events10m).max(FLOOD_MIN_EVENTS_10M);
    counters.site_events_10m as f64 >= gate
}

/// `computeAnomalyResult`.
pub fn compute_anomaly_result(
    counters: AnomalyCounters,
    site_baseline: Option<SiteBaseline>,
    is_hosting_asn: bool,
    asn: Option<u32>,
) -> AnomalyResult {
    // Convicting rules describe a single actor. The interaction-burst threshold is
    // beyond human clicking speed (10/s sustained).
    let mut convicting = Vec::new();
    add_reason(&mut convicting, "tuple_events_10s", 4, counters.tuple_events_10s, 30, 10);
    add_reason(&mut convicting, "tuple_events_60s", 4, counters.tuple_events_60s, 120, 60);
    add_reason(&mut convicting, "tuple_interaction_events_10s", 4, counters.tuple_interaction_events_10s, 100, 10);
    add_reason(&mut convicting, "tuple_distinct_paths_60s", 4, counters.tuple_distinct_paths_60s, 25, 60);
    add_reason(&mut convicting, "missing_client_score_60s", 1, counters.missing_client_score_60s, 20, 60);

    // Cohort uniformity: a distribution no organic population produces.
    if counters.cohort_events_1h >= COHORT_MIN_EVENTS_1H
        && counters.cohort_distinct_versions_1h >= COHORT_MIN_DISTINCT_VERSIONS
        && (counters.cohort_top_version_events_1h as f64) < counters.cohort_events_1h as f64 * COHORT_MAX_MODAL_SHARE
    {
        convicting.push(AnomalyReason {
            rule: "cohort_version_uniformity_1h",
            score: 4,
            value: ((counters.cohort_top_version_events_1h as f64 / counters.cohort_events_1h as f64) * 100.0).round()
                as i64,
            threshold: (COHORT_MAX_MODAL_SHARE * 100.0) as i64,
            window_seconds: 3600,
        });
    }

    let shared_egress_guard = counters.ip_distinct_user_agents_5m <= PROXY_MERGE_MAX_USER_AGENTS;
    let sase_exempt = asn.is_some_and(|asn| SASE_EGRESS_ASNS.contains(&asn));

    if is_site_in_flood(&counters, site_baseline) {
        let cohort_events = counters.cohort_events_10m;
        let cohort = cohort_events as f64;
        if cohort_events >= FLOOD_COHORT_MIN_EVENTS_10M
            && counters.cohort_distinct_actors_10m as f64 >= cohort * FLOOD_COHORT_MIN_ACTOR_RATIO
            && counters.cohort_direct_events_10m as f64 >= cohort * FLOOD_COHORT_MIN_DIRECT_SHARE
            && cohort >= counters.site_events_10m as f64 * FLOOD_COHORT_MIN_SITE_SHARE
        {
            convicting.push(AnomalyReason {
                rule: "site_flood_oneshot_cohort_10m",
                score: 4,
                value: ((counters.cohort_distinct_actors_10m as f64 / cohort) * 100.0).round() as i64,
                // 0.6 * 100 is exactly 60 in doubles, as it is in JavaScript.
                threshold: (FLOOD_COHORT_MIN_ACTOR_RATIO * 100.0) as i64,
                window_seconds: 600,
            });
        }

        if is_hosting_asn && shared_egress_guard && !sase_exempt {
            add_reason(
                &mut convicting,
                "site_flood_actor_1d",
                4,
                counters.actor_events_1d,
                FLOOD_ACTOR_EVENTS_1D_HOSTING,
                86400,
            );
        }
    }

    if is_hosting_asn && shared_egress_guard && !sase_exempt {
        add_reason(
            &mut convicting,
            "hosting_actor_events_1d",
            4,
            counters.actor_events_1d,
            HOSTING_ACTOR_EVENTS_1D_THRESHOLD,
            86400,
        );
    }

    // Supporting rules: shared dimensions many real visitors legitimately share.
    let mut supporting = Vec::new();
    add_reason(&mut supporting, "ip_events_60s", 3, counters.ip_events_60s, 200, 60);
    add_reason(&mut supporting, "ip_distinct_user_agents_5m", 3, counters.ip_distinct_user_agents_5m, 10, 300);
    add_reason(&mut supporting, "ip_distinct_hosts_60s", 2, counters.ip_distinct_hosts_60s, 6, 60);
    add_reason(&mut supporting, "site_user_agent_events_60s", 1, counters.site_user_agent_events_60s, 300, 60);
    if shared_egress_guard {
        add_reason(
            &mut supporting,
            "actor_events_1d",
            ACTOR_EVENTS_1D_SCORE,
            counters.actor_events_1d,
            ACTOR_EVENTS_1D_THRESHOLD,
            86400,
        );
    }

    // The invariant: supporting evidence only adds to a score convicting evidence
    // has already opened.
    let convicting_score: i64 = convicting.iter().map(|reason| reason.score).sum();
    let supporting_score: i64 = supporting.iter().map(|reason| reason.score).sum();
    let score = if convicting.is_empty() { 0 } else { convicting_score + supporting_score };

    let reasons = convicting.iter().chain(supporting.iter()).cloned().collect();
    AnomalyResult {
        is_anomalous: score >= ANOMALY_SCORE_THRESHOLD,
        score,
        convicting_reasons: convicting,
        supporting_reasons: supporting,
        reasons,
        counters,
        enumeration: None,
    }
}

/// Test double for the Redis script: receives `(nowMs, specs)`.
#[cfg(test)]
pub(crate) type MockObserve =
    Arc<dyn Fn(i64, &[AnomalyCounterSpec]) -> Result<Vec<AnomalyDistribution>, String> + Send + Sync>;

/// The anomaly layer's state: Redis handle, in-process fallback counters, the
/// enumeration observer and the shared site baselines.
pub struct AnomalyScorer {
    redis: Option<ConnectionManager>,
    redis_enabled: AtomicBool,
    local: Mutex<LocalCounters>,
    enumeration: EnumerationObserver,
    baselines: Arc<SiteBaselines>,
    event_seq: AtomicU64,
    #[cfg(test)]
    mock: Mutex<Option<MockObserve>>,
}

impl AnomalyScorer {
    /// Scoring runs against Redis unless `DISABLE_REDIS_ANOMALY=true` (read once,
    /// as Node reads it at module load) or no Redis handle is given.
    pub fn new(redis: Option<ConnectionManager>, baselines: Arc<SiteBaselines>) -> Self {
        let disabled = std::env::var("DISABLE_REDIS_ANOMALY").is_ok_and(|value| value == "true");
        let enabled = !disabled && redis.is_some();
        tracing::info!(
            service = "anomaly-scorer",
            redis_counters = enabled,
            disable_redis_anomaly = disabled,
            "Anomaly scorer initialised"
        );
        Self {
            redis: redis.clone(),
            redis_enabled: AtomicBool::new(enabled),
            local: Mutex::default(),
            enumeration: EnumerationObserver::new(redis),
            baselines,
            // Node's token is `<nowMs>-<pid>-<seq>` with seq starting at 1. Two
            // containers can both run as PID 1, so this process starts its
            // sequence at a random point; the member format is unchanged.
            event_seq: AtomicU64::new(u64::from(rand::random::<u32>())),
            #[cfg(test)]
            mock: Mutex::new(None),
        }
    }

    pub fn baselines(&self) -> &Arc<SiteBaselines> {
        &self.baselines
    }

    /// `setRedisAnomalyEnabledForTests`
    pub fn set_redis_enabled(&self, enabled: bool) {
        self.redis_enabled.store(enabled, Ordering::SeqCst);
    }

    /// `resetAnomalyScorerForTests`
    pub fn reset(&self) {
        *self.local.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = LocalCounters::default();
        self.enumeration.reset();
        self.event_seq.store(0, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn set_mock(&self, mock: Option<MockObserve>) {
        *self.mock.lock().unwrap() = mock;
    }

    /// `nextEventToken`: a unique sorted-set member per observation.
    fn next_event_token(&self, now_ms: i64) -> String {
        const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
        let seq = self
            .event_seq
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |seq| Some((seq + 1) % MAX_SAFE_INTEGER))
            .map(|previous| (previous + 1) % MAX_SAFE_INTEGER)
            .unwrap_or(0);
        format!("{now_ms}-{}-{seq}", *PROCESS_ID)
    }

    /// `buildCounterPlan`
    pub fn build_counter_plan(&self, input: &AnomalyInput<'_>, now_ms: i64) -> AnomalyPlan {
        let site_id = input.site_id;
        let ip_address = normalize_dimension(Some(input.ip_address));
        let user_agent_hash = hash_value(input.user_agent);
        let hostname = normalize_dimension(input.hostname);
        let pathname = normalize_dimension(input.pathname);

        let tuple_key = format!("{site_id}:{ip_address}:{user_agent_hash}");
        let ip_key = format!("{site_id}:{ip_address}");
        let site_user_agent_key = format!("{site_id}:{user_agent_hash}");
        let event_token = self.next_event_token(now_ms);
        let is_interaction = INTERACTION_EVENT_TYPES.contains(&input.event_type.unwrap_or(""));

        // The cohort's bucket lives in the key so the Redis hash expires on its
        // own. The browser family and language are part of the key: without them
        // one cohort pooled unrelated populations into a flat-looking distribution.
        let language = normalize_dimension(input.language);
        let (browser_family, browser_major_version) = get_browser_identity(input.user_agent);
        let has_cohort = !browser_family.is_empty()
            && !browser_major_version.is_empty()
            && !language.is_empty()
            && input.screen_width.is_some_and(|width| width > 0.0)
            && input.screen_height.is_some_and(|height| height > 0.0);
        let cohort_key = if has_cohort {
            format!(
                "{site_id}:{}x{}:{language}:{browser_family}",
                js_number_to_string(input.screen_width.unwrap_or_default()),
                js_number_to_string(input.screen_height.unwrap_or_default())
            )
        } else {
            String::new()
        };
        let cohort_bucket = now_ms.div_euclid(HOUR);
        let flood_bucket = now_ms.div_euclid(TEN_MINUTES);
        let site_key = site_id.to_string();

        // Enumeration shape is measured over the same cohort on a 15-minute bucket
        // and needs a path, since path novelty is the whole measurement.
        let has_enumeration_cohort = has_cohort && !pathname.is_empty();
        let enumeration_bucket = now_ms.div_euclid(ENUMERATION_BUCKET_MS);
        let is_direct = normalize_dimension(input.referrer).is_empty();
        let day_bucket = now_ms.div_euclid(DAY);

        #[allow(clippy::too_many_arguments)]
        fn plan(
            name: CounterName,
            enabled: bool,
            kind: AnomalyCounterKind,
            redis_key: String,
            member: &str,
            window_ms: i64,
            max_size: i64,
            local_key: &str,
            local_window_ms: i64,
        ) -> CounterPlan {
            CounterPlan {
                name,
                enabled,
                kind,
                redis_key,
                member: member.to_string(),
                window_ms,
                max_size,
                local_key: local_key.to_string(),
                local_window_ms,
            }
        }

        use AnomalyCounterKind::{Cardinality, Counter, Distribution, Rolling};
        use CounterName::*;
        let counter_size = MAX_COUNTER_BUCKET_SIZE as i64;
        let distinct_size = MAX_DISTINCT_BUCKET_SIZE as i64;

        let counters = vec![
            plan(
                TupleEvents10s,
                !is_interaction,
                Rolling,
                format!("bot:a:te10:{tuple_key}"),
                &event_token,
                10 * SECOND,
                counter_size,
                &tuple_key,
                10 * SECOND,
            ),
            plan(
                TupleEvents60s,
                !is_interaction,
                Rolling,
                format!("bot:a:te60:{tuple_key}"),
                &event_token,
                MINUTE,
                counter_size,
                &tuple_key,
                MINUTE,
            ),
            plan(
                TupleInteractionEvents10s,
                is_interaction,
                Rolling,
                format!("bot:a:ti10:{tuple_key}"),
                &event_token,
                10 * SECOND,
                counter_size,
                &tuple_key,
                10 * SECOND,
            ),
            plan(
                TupleDistinctPaths60s,
                !pathname.is_empty(),
                Rolling,
                format!("bot:a:tdp:{tuple_key}"),
                &pathname,
                MINUTE,
                distinct_size,
                &tuple_key,
                MINUTE,
            ),
            plan(
                IpEvents60s,
                true,
                Rolling,
                format!("bot:a:ie60:{ip_key}"),
                &event_token,
                MINUTE,
                counter_size,
                &ip_key,
                MINUTE,
            ),
            plan(
                IpDistinctUserAgents5m,
                true,
                Rolling,
                format!("bot:a:idua:{ip_key}"),
                &user_agent_hash,
                5 * MINUTE,
                distinct_size,
                &ip_key,
                5 * MINUTE,
            ),
            plan(
                IpDistinctHosts60s,
                !hostname.is_empty(),
                Rolling,
                format!("bot:a:idh:{ip_key}"),
                &hostname,
                MINUTE,
                distinct_size,
                &ip_key,
                MINUTE,
            ),
            plan(
                SiteUserAgentEvents60s,
                true,
                Rolling,
                format!("bot:a:sue:{site_user_agent_key}"),
                &event_token,
                MINUTE,
                counter_size,
                &site_user_agent_key,
                MINUTE,
            ),
            plan(
                MissingClientScore60s,
                !input.has_client_bot_score,
                Rolling,
                format!("bot:a:mcs:{tuple_key}"),
                &event_token,
                MINUTE,
                counter_size,
                &tuple_key,
                MINUTE,
            ),
            plan(
                CohortEvents1h,
                has_cohort,
                Distribution,
                format!("bot:a:cbv:{cohort_key}:{cohort_bucket}"),
                &browser_major_version,
                2 * HOUR,
                MAX_DISTRIBUTION_FIELDS as i64,
                &cohort_key,
                HOUR,
            ),
            plan(ActorEvents1d, true, Counter, format!("bot:a:av:{ip_key}:{day_bucket}"), "", DAY, 0, &ip_key, DAY),
            // Site-flood counters on one fixed 10-minute bucket. The actor here is
            // the visitor tuple, the identity a fleet mints per hit.
            plan(
                SiteEvents10m,
                true,
                Counter,
                format!("bot:f:se:{site_key}:{flood_bucket}"),
                "",
                2 * TEN_MINUTES,
                0,
                &site_key,
                TEN_MINUTES,
            ),
            plan(
                SiteDistinctActors10m,
                true,
                Cardinality,
                format!("bot:f:sa:{site_key}:{flood_bucket}"),
                &tuple_key,
                2 * TEN_MINUTES,
                0,
                &site_key,
                TEN_MINUTES,
            ),
            plan(
                CohortEvents10m,
                has_cohort,
                Counter,
                format!("bot:f:ce:{cohort_key}:{flood_bucket}"),
                "",
                2 * TEN_MINUTES,
                0,
                &cohort_key,
                TEN_MINUTES,
            ),
            plan(
                CohortDistinctActors10m,
                has_cohort,
                Cardinality,
                format!("bot:f:ca:{cohort_key}:{flood_bucket}"),
                &tuple_key,
                2 * TEN_MINUTES,
                0,
                &cohort_key,
                TEN_MINUTES,
            ),
            plan(
                CohortDirectEvents10m,
                has_cohort && is_direct,
                Counter,
                format!("bot:f:cd:{cohort_key}:{flood_bucket}"),
                "",
                2 * TEN_MINUTES,
                0,
                &cohort_key,
                TEN_MINUTES,
            ),
            plan(
                EnumerationEvents15m,
                has_enumeration_cohort,
                Counter,
                format!("bot:e:ev:{cohort_key}:{enumeration_bucket}"),
                "",
                ENUMERATION_BUCKET_MS,
                0,
                &cohort_key,
                ENUMERATION_BUCKET_MS,
            ),
            // A cohort can reach tens of thousands of distinct paths in a bucket,
            // which is what HyperLogLog is for.
            plan(
                EnumerationDistinctPaths15m,
                has_enumeration_cohort,
                Cardinality,
                format!("bot:e:pa:{cohort_key}:{enumeration_bucket}"),
                &pathname,
                ENUMERATION_BUCKET_MS,
                0,
                &cohort_key,
                ENUMERATION_BUCKET_MS,
            ),
            plan(
                EnumerationDistinctActors15m,
                has_enumeration_cohort,
                Cardinality,
                format!("bot:e:ac:{cohort_key}:{enumeration_bucket}"),
                &ip_address,
                ENUMERATION_BUCKET_MS,
                0,
                &cohort_key,
                ENUMERATION_BUCKET_MS,
            ),
            plan(
                EnumerationDirectEvents15m,
                has_enumeration_cohort && is_direct,
                Counter,
                format!("bot:e:di:{cohort_key}:{enumeration_bucket}"),
                "",
                ENUMERATION_BUCKET_MS,
                0,
                &cohort_key,
                ENUMERATION_BUCKET_MS,
            ),
        ];

        AnomalyPlan {
            counters,
            enumeration: has_enumeration_cohort.then_some(EnumerationPlan {
                cohort_key,
                bucket: enumeration_bucket,
                is_direct,
            }),
        }
    }

    /// `observeViaRedis`
    async fn observe_via_redis(&self, plan: &[CounterPlan], now_ms: i64) -> Result<AnomalyCounters, String> {
        let enabled: Vec<&CounterPlan> = plan.iter().filter(|entry| entry.enabled).collect();
        let specs: Vec<AnomalyCounterSpec> = enabled
            .iter()
            .map(|entry| AnomalyCounterSpec {
                key: entry.redis_key.clone(),
                kind: entry.kind,
                member: entry.member.clone(),
                window_ms: entry.window_ms,
                max_size: entry.max_size,
            })
            .collect();

        #[cfg(test)]
        let mock = self.mock.lock().unwrap().clone();
        #[cfg(test)]
        let readings = match mock {
            Some(mock) => mock(now_ms, &specs)?,
            None => self.call_redis(now_ms, &specs).await?,
        };
        #[cfg(not(test))]
        let readings = self.call_redis(now_ms, &specs).await?;

        Ok(counters_from_readings(&enabled, &readings))
    }

    async fn call_redis(&self, now_ms: i64, specs: &[AnomalyCounterSpec]) -> Result<Vec<AnomalyDistribution>, String> {
        let redis = self.redis.as_ref().ok_or_else(|| "Redis is not configured".to_string())?;
        anomaly_observe(redis, now_ms, specs).await.map_err(|error| error.to_string())
    }

    /// `observeViaLocal`
    fn observe_via_local(&self, plan: &[CounterPlan], now_ms: i64) -> AnomalyCounters {
        let mut local = self.local.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        local.maybe_cleanup(now_ms);
        let mut counters = AnomalyCounters::default();
        for entry in plan.iter().filter(|entry| entry.enabled) {
            let key = entry.local_key.as_str();
            let value = entry.member.as_str();
            let window = entry.local_window_ms;
            let reading = match entry.name {
                CounterName::TupleEvents10s => local.tuple_events_10s.observe(key, now_ms, window),
                CounterName::TupleEvents60s => local.tuple_events_60s.observe(key, now_ms, window),
                CounterName::TupleInteractionEvents10s => {
                    local.tuple_interaction_events_10s.observe(key, now_ms, window)
                }
                CounterName::TupleDistinctPaths60s => {
                    local.tuple_distinct_paths_60s.observe(key, value, now_ms, window)
                }
                CounterName::IpEvents60s => local.ip_events_60s.observe(key, now_ms, window),
                CounterName::IpDistinctUserAgents5m => {
                    local.ip_distinct_user_agents_5m.observe(key, value, now_ms, window)
                }
                CounterName::IpDistinctHosts60s => local.ip_distinct_hosts_60s.observe(key, value, now_ms, window),
                CounterName::SiteUserAgentEvents60s => local.site_user_agent_events_60s.observe(key, now_ms, window),
                CounterName::MissingClientScore60s => local.missing_client_score_60s.observe(key, now_ms, window),
                CounterName::CohortEvents1h => {
                    let distribution =
                        local.cohort_browser_versions_1h.observe(key, value, now_ms, window, MAX_DISTRIBUTION_FIELDS);
                    counters.cohort_top_version_events_1h = distribution.top;
                    counters.cohort_distinct_versions_1h = distribution.distinct;
                    distribution.total
                }
                CounterName::ActorEvents1d => {
                    local.actor_events_1d.observe(key, now_ms, window, MAX_LOCAL_COUNTER_KEYS)
                }
                CounterName::SiteEvents10m => {
                    local.site_events_10m.observe(key, now_ms, window, MAX_LOCAL_COUNTER_KEYS)
                }
                CounterName::SiteDistinctActors10m => {
                    local.site_distinct_actors_10m.observe(key, value, now_ms, window, MAX_LOCAL_DISTINCT_VALUES)
                }
                CounterName::CohortEvents10m => {
                    local.cohort_events_10m.observe(key, now_ms, window, MAX_LOCAL_COUNTER_KEYS)
                }
                CounterName::CohortDistinctActors10m => {
                    local.cohort_distinct_actors_10m.observe(key, value, now_ms, window, MAX_LOCAL_DISTINCT_VALUES)
                }
                CounterName::CohortDirectEvents10m => {
                    local.cohort_direct_events_10m.observe(key, now_ms, window, MAX_LOCAL_COUNTER_KEYS)
                }
                CounterName::EnumerationEvents15m => {
                    local.enumeration_events_15m.observe(key, now_ms, window, MAX_LOCAL_COUNTER_KEYS)
                }
                CounterName::EnumerationDistinctPaths15m => {
                    local.enumeration_distinct_paths_15m.observe(key, value, now_ms, window, MAX_LOCAL_DISTINCT_VALUES)
                }
                CounterName::EnumerationDistinctActors15m => {
                    local.enumeration_distinct_actors_15m.observe(key, value, now_ms, window, MAX_LOCAL_DISTINCT_VALUES)
                }
                CounterName::EnumerationDirectEvents15m => {
                    local.enumeration_direct_events_15m.observe(key, now_ms, window, MAX_LOCAL_COUNTER_KEYS)
                }
            };
            counters.set(entry.name, reading);
        }
        counters
    }

    /// `observeTrackingAnomaly`: observe one event and score it.
    pub async fn observe_tracking_anomaly(&self, input: &AnomalyInput<'_>) -> AnomalyResult {
        let now_ms = input.now_ms.unwrap_or_else(now_ms);
        let plan = self.build_counter_plan(input, now_ms);

        let redis_enabled = self.redis_enabled.load(Ordering::SeqCst);
        let mut used_local_counters = !redis_enabled;
        let counters = if redis_enabled {
            match self.observe_via_redis(&plan.counters, now_ms).await {
                Ok(counters) => counters,
                Err(error) => {
                    // A Redis blip must never break ingestion.
                    used_local_counters = true;
                    tracing::error!(
                        service = "anomaly-scorer",
                        error = %error,
                        site_id = input.site_id,
                        "Redis anomaly counters failed; using in-process fallback"
                    );
                    self.observe_via_local(&plan.counters, now_ms)
                }
            }
        } else {
            self.observe_via_local(&plan.counters, now_ms)
        };

        let site_baseline = match input.site_baseline {
            BaselineSource::Lookup => self.baselines.get(input.site_id),
            BaselineSource::Absent => None,
            BaselineSource::Given(baseline) => Some(baseline),
        };
        let mut result = compute_anomaly_result(counters, site_baseline, input.is_hosting_asn, input.asn);

        // Only a direct hit incremented the direct counter, so only a direct hit
        // reads a meaningful share. Evidence gathered, not a verdict.
        if let Some(enumeration) = plan.enumeration.as_ref().filter(|enumeration| enumeration.is_direct) {
            result.enumeration = Some(
                self.enumeration
                    .observe_enumeration(
                        &enumeration.cohort_key,
                        enumeration.bucket,
                        EnumerationReading {
                            events: counters.enumeration_events_15m,
                            distinct_paths: counters.enumeration_distinct_paths_15m,
                            distinct_actors: counters.enumeration_distinct_actors_15m,
                            direct_events: counters.enumeration_direct_events_15m,
                        },
                        used_local_counters,
                    )
                    .await,
            );
        }

        if result.is_anomalous {
            tracing::debug!(
                service = "anomaly-scorer",
                site_id = input.site_id,
                score = result.score,
                rules = ?result.reasons.iter().map(|reason| reason.rule).collect::<Vec<_>>(),
                used_local_counters,
                "Request anomaly detected"
            );
        }
        result
    }
}

/// Map readings back onto counters by plan position.
fn counters_from_readings(enabled: &[&CounterPlan], readings: &[AnomalyDistribution]) -> AnomalyCounters {
    let mut counters = AnomalyCounters::default();
    for (index, entry) in enabled.iter().enumerate() {
        let reading = readings.get(index).copied().unwrap_or_default();
        counters.set(entry.name, reading.total);
        if entry.name == CounterName::CohortEvents1h {
            counters.cohort_top_version_events_1h = reading.top;
            counters.cohort_distinct_versions_1h = reading.distinct;
        }
    }
    counters
}

#[cfg(test)]
pub(crate) mod tests {
    //! Ported from server/src/services/tracker/botBlocking/anomalyScorer.test.ts.
    use super::*;

    const BASE_NOW: i64 = 1_000_000;

    fn base_input() -> AnomalyInput<'static> {
        AnomalyInput {
            site_id: 123,
            ip_address: "203.0.113.10",
            user_agent: "Mozilla/5.0 Chrome/120 Safari/537.36",
            hostname: Some("example.com"),
            pathname: Some("/"),
            event_type: Some("pageview"),
            has_client_bot_score: true,
            now_ms: Some(BASE_NOW),
            ..AnomalyInput::default()
        }
    }

    pub(crate) fn local_scorer() -> AnomalyScorer {
        let scorer = AnomalyScorer::new(None, Arc::new(SiteBaselines::new()));
        scorer.set_redis_enabled(false);
        scorer
    }

    fn rules(reasons: &[AnomalyReason]) -> Vec<&'static str> {
        reasons.iter().map(|reason| reason.rule).collect()
    }

    fn rolling_readings(totals: &[i64]) -> Vec<AnomalyDistribution> {
        totals.iter().map(|total| AnomalyDistribution { total: *total, top: 0, distinct: 0 }).collect()
    }

    type RecordedCalls = Arc<Mutex<Vec<(i64, Vec<AnomalyCounterSpec>)>>>;

    /// A scorer whose Redis script is replaced by fixed readings, recording the
    /// specs of every call.
    fn mocked_scorer(readings: Result<Vec<AnomalyDistribution>, String>) -> (AnomalyScorer, RecordedCalls) {
        let scorer = AnomalyScorer::new(None, Arc::new(SiteBaselines::new()));
        scorer.set_redis_enabled(true);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        scorer.set_mock(Some(Arc::new(move |now, specs: &[AnomalyCounterSpec]| {
            recorded.lock().unwrap().push((now, specs.to_vec()));
            readings.clone()
        })));
        (scorer, calls)
    }

    #[test]
    fn hashes_like_node() {
        // FNV-1a over UTF-16 code units, base 36 (values printed by Node).
        assert_eq!(hash_value(""), "ztntfp");
        assert_eq!(hash_value("Mozilla/5.0 Chrome/120 Safari/537.36"), "oyqi2y");
        assert_eq!(hash_value("\u{1F600}x"), "187o2m8");
    }

    // --- observeTrackingAnomaly (in-process fallback) ---------------------------

    #[tokio::test]
    async fn does_not_flag_normal_traffic() {
        let scorer = local_scorer();
        let result = scorer.observe_tracking_anomaly(&base_input()).await;
        assert!(!result.is_anomalous);
        assert_eq!(result.score, 0);
        assert!(result.reasons.is_empty());
    }

    #[tokio::test]
    async fn flags_high_request_bursts_for_a_single_visitor_tuple() {
        let scorer = local_scorer();
        let mut result = scorer.observe_tracking_anomaly(&base_input()).await;
        for i in 1..30 {
            result =
                scorer.observe_tracking_anomaly(&AnomalyInput { now_ms: Some(BASE_NOW + i), ..base_input() }).await;
        }
        assert!(!result.is_anomalous);

        let result =
            scorer.observe_tracking_anomaly(&AnomalyInput { now_ms: Some(BASE_NOW + 30), ..base_input() }).await;
        assert!(result.is_anomalous);
        assert!(rules(&result.reasons).contains(&"tuple_events_10s"));
    }

    #[tokio::test]
    async fn flags_fast_path_crawling() {
        let scorer = local_scorer();
        let mut result = scorer.observe_tracking_anomaly(&base_input()).await;
        for i in 1..=25 {
            let path = format!("/docs/{i}");
            result = scorer
                .observe_tracking_anomaly(&AnomalyInput {
                    pathname: Some(&path),
                    now_ms: Some(BASE_NOW + i),
                    ..base_input()
                })
                .await;
        }
        assert!(result.is_anomalous);
        assert!(rules(&result.reasons).contains(&"tuple_distinct_paths_60s"));
    }

    #[tokio::test]
    async fn treats_missing_client_score_as_weak_context() {
        let scorer = local_scorer();
        let mut result =
            scorer.observe_tracking_anomaly(&AnomalyInput { has_client_bot_score: false, ..base_input() }).await;
        for i in 1..=20 {
            result = scorer
                .observe_tracking_anomaly(&AnomalyInput {
                    has_client_bot_score: false,
                    now_ms: Some(BASE_NOW + i * 2_000),
                    ..base_input()
                })
                .await;
        }
        assert!(!result.is_anomalous);
        assert_eq!(
            result.reasons,
            vec![AnomalyReason {
                rule: "missing_client_score_60s",
                score: 1,
                value: 21,
                threshold: 20,
                window_seconds: 60
            }]
        );
    }

    #[tokio::test]
    async fn does_not_flag_rapid_interaction_bursts_from_a_real_widget_user() {
        let scorer = local_scorer();
        let mut result =
            scorer.observe_tracking_anomaly(&AnomalyInput { event_type: Some("button_click"), ..base_input() }).await;
        for i in 1..90 {
            result = scorer
                .observe_tracking_anomaly(&AnomalyInput {
                    event_type: Some("button_click"),
                    now_ms: Some(BASE_NOW + i * 100),
                    ..base_input()
                })
                .await;
        }
        assert!(!result.is_anomalous);
        assert_eq!(result.counters.tuple_events_10s, 0);
    }

    #[tokio::test]
    async fn flags_beyond_human_interaction_bursts() {
        let scorer = local_scorer();
        let mut result =
            scorer.observe_tracking_anomaly(&AnomalyInput { event_type: Some("button_click"), ..base_input() }).await;
        for i in 1..=101 {
            result = scorer
                .observe_tracking_anomaly(&AnomalyInput {
                    event_type: Some("button_click"),
                    now_ms: Some(BASE_NOW + i),
                    ..base_input()
                })
                .await;
        }
        assert!(result.is_anomalous);
        assert!(rules(&result.reasons).contains(&"tuple_interaction_events_10s"));
    }

    #[tokio::test]
    async fn expires_old_observations_outside_the_window() {
        let scorer = local_scorer();
        for i in 0..35 {
            scorer.observe_tracking_anomaly(&AnomalyInput { now_ms: Some(BASE_NOW + i), ..base_input() }).await;
        }
        let result =
            scorer.observe_tracking_anomaly(&AnomalyInput { now_ms: Some(BASE_NOW + 70_000), ..base_input() }).await;
        assert!(!result.is_anomalous);
        assert_eq!(result.counters.tuple_events_10s, 1);
    }

    // --- BucketedCounter key bound ----------------------------------------------

    const WINDOW: i64 = 60_000;

    #[test]
    fn stops_admitting_new_keys_at_the_cap_and_reports_them_as_zero() {
        let mut counter = BucketedCounter::default();
        assert_eq!(counter.observe("a", 0, WINDOW, 2), 1);
        assert_eq!(counter.observe("b", 0, WINDOW, 2), 1);
        assert_eq!(counter.observe("c", 0, WINDOW, 2), 0);
        assert_eq!(counter.observe("c", 0, WINDOW, 2), 0);
    }

    #[test]
    fn keeps_counting_the_keys_it_already_holds() {
        let mut counter = BucketedCounter::default();
        counter.observe("a", 0, WINDOW, 1);
        counter.observe("b", 0, WINDOW, 1);
        assert_eq!(counter.observe("a", 0, WINDOW, 1), 2);
    }

    #[test]
    fn rolls_an_existing_key_into_a_new_window_even_at_capacity() {
        let mut counter = BucketedCounter::default();
        counter.observe("a", 0, WINDOW, 1);
        assert_eq!(counter.observe("a", WINDOW, WINDOW, 1), 1);
    }

    #[test]
    fn readmits_keys_once_cleanup_has_freed_the_window() {
        let mut counter = BucketedCounter::default();
        counter.observe("a", 0, WINDOW, 1);
        assert_eq!(counter.observe("b", 0, WINDOW, 1), 0);
        counter.cleanup(WINDOW * 3, WINDOW);
        assert_eq!(counter.observe("b", WINDOW * 3, WINDOW, 1), 1);
    }

    // --- cohort version uniformity (in-process fallback) -------------------------

    fn cohort_input() -> AnomalyInput<'static> {
        AnomalyInput {
            screen_width: Some(1280.0),
            screen_height: Some(1200.0),
            language: Some("en-US"),
            ..base_input()
        }
    }

    fn desktop_chrome(version: i64) -> String {
        format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
        )
    }

    async fn drive_cohort(scorer: &AnomalyScorer, versions: &[i64]) -> AnomalyResult {
        let first = desktop_chrome(versions[0]);
        let mut result = scorer.observe_tracking_anomaly(&AnomalyInput { user_agent: &first, ..cohort_input() }).await;
        for (index, version) in versions.iter().enumerate() {
            let ip = format!("198.51.100.{}", index % 254);
            let ua = desktop_chrome(*version);
            let path = format!("/summoners/{index}");
            result = scorer
                .observe_tracking_anomaly(&AnomalyInput {
                    ip_address: &ip,
                    user_agent: &ua,
                    pathname: Some(&path),
                    now_ms: Some(BASE_NOW + index as i64),
                    ..cohort_input()
                })
                .await;
        }
        result
    }

    #[tokio::test]
    async fn convicts_a_busy_cohort_spread_evenly_across_many_versions() {
        let scorer = local_scorer();
        let versions: Vec<i64> = (0..480).map(|index| 103 + (index % 16)).collect();
        let result = drive_cohort(&scorer, &versions).await;
        assert!(result.is_anomalous);
        assert!(rules(&result.reasons).contains(&"cohort_version_uniformity_1h"));
        assert_eq!(result.counters.cohort_distinct_versions_1h, 16);
    }

    #[tokio::test]
    async fn leaves_an_equally_busy_organic_cohort_alone() {
        let scorer = local_scorer();
        let versions: Vec<i64> =
            (0..480).map(|index| if index % 100 < 87 { 150 } else { 140 + (index % 10) }).collect();
        let result = drive_cohort(&scorer, &versions).await;
        assert!(!result.is_anomalous);
        assert!(!rules(&result.reasons).contains(&"cohort_version_uniformity_1h"));
    }

    #[tokio::test]
    async fn ignores_a_flat_cohort_too_small_to_be_a_fleet() {
        let scorer = local_scorer();
        let versions: Vec<i64> = (0..60).map(|index| 103 + (index % 16)).collect();
        let result = drive_cohort(&scorer, &versions).await;
        assert!(!result.is_anomalous);
        assert!(result.counters.cohort_events_1h < 100);
    }

    #[tokio::test]
    async fn skips_the_cohort_counter_when_the_fingerprint_is_incomplete() {
        let scorer = local_scorer();
        let result = scorer.observe_tracking_anomaly(&AnomalyInput { screen_width: None, ..base_input() }).await;
        assert_eq!(result.counters.cohort_events_1h, 0);
        assert_eq!(result.counters.cohort_distinct_versions_1h, 0);
    }

    #[tokio::test]
    async fn skips_the_cohort_counter_when_the_language_is_unset() {
        let scorer = local_scorer();
        let result = scorer.observe_tracking_anomaly(&AnomalyInput { language: None, ..cohort_input() }).await;
        assert_eq!(result.counters.cohort_events_1h, 0);
    }

    #[tokio::test]
    async fn does_not_convict_a_mixed_browser_population_sharing_one_screen_and_language() {
        let scorer = local_scorer();
        let families: [fn(i64) -> String; 4] = [
            desktop_chrome,
            |version| {
                format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}.0) Gecko/20100101 Firefox/{version}.0")
            },
            |version| {
                format!(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version}.0 Safari/605.1.15"
                )
            },
            |version| {
                format!(
                    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/{version}.0 Chrome/115.0.0.0 Mobile Safari/537.36"
                )
            },
        ];
        let dominant_versions = [150, 130, 18, 23];

        let mut result = None;
        let mut index = 0;
        for (family_index, build) in families.iter().enumerate() {
            let dominant = dominant_versions[family_index];
            for event in 0..320 {
                let version = if event % 100 < 85 { dominant } else { dominant - 1 - (event % 3) };
                let ip = format!("198.51.100.{}", index % 254);
                let ua = build(version);
                let path = format!("/article/{index}");
                result = Some(
                    scorer
                        .observe_tracking_anomaly(&AnomalyInput {
                            ip_address: &ip,
                            user_agent: &ua,
                            pathname: Some(&path),
                            now_ms: Some(BASE_NOW + index),
                            ..cohort_input()
                        })
                        .await,
                );
                index += 1;
            }
        }
        let result = result.unwrap();
        assert!(!rules(&result.reasons).contains(&"cohort_version_uniformity_1h"));
        assert!(!result.is_anomalous);
        assert_eq!(result.counters.cohort_events_1h, 320);
    }

    const CHROME_120: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    async fn cohort_sizes_per_agent(scorer: &AnomalyScorer, user_agents: &[String]) -> Vec<i64> {
        let mut sizes = Vec::new();
        let mut index = 0;
        for user_agent in user_agents {
            let mut result = None;
            for _ in 0..10 {
                let ip = format!("198.51.100.{}", index % 254);
                let path = format!("/article/{index}");
                result = Some(
                    scorer
                        .observe_tracking_anomaly(&AnomalyInput {
                            ip_address: &ip,
                            user_agent,
                            pathname: Some(&path),
                            now_ms: Some(BASE_NOW + index),
                            ..cohort_input()
                        })
                        .await,
                );
                index += 1;
            }
            sizes.push(result.unwrap().counters.cohort_events_1h);
        }
        sizes
    }

    fn derivative_agents() -> (String, String, String) {
        (CHROME_120.to_string(), format!("{CHROME_120} Edg/120.0.2210.144"), format!("{CHROME_120} OPR/106.0.4998.70"))
    }

    #[tokio::test]
    async fn pools_chromium_derivatives_that_report_their_chromium_version() {
        let scorer = local_scorer();
        let (chrome, edge, opera) = derivative_agents();
        assert_eq!(cohort_sizes_per_agent(&scorer, &[chrome, edge, opera]).await, vec![10, 20, 30]);
    }

    #[tokio::test]
    async fn keeps_one_version_distribution_for_a_pooled_derivative() {
        let scorer = local_scorer();
        let (chrome, edge, opera) = derivative_agents();
        cohort_sizes_per_agent(&scorer, &[chrome, edge.clone(), opera]).await;
        let result = scorer.observe_tracking_anomaly(&AnomalyInput { user_agent: &edge, ..cohort_input() }).await;
        assert_eq!(result.counters.cohort_distinct_versions_1h, 1);
    }

    #[tokio::test]
    async fn separates_families_whose_version_numbers_move_independently() {
        let scorer = local_scorer();
        let agents = [
            CHROME_120.to_string(),
            "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36".to_string(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.101 Mobile/15E148 Safari/604.1".to_string(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/121.0 Mobile/15E148 Safari/605.1.15".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15".to_string(),
        ];
        assert_eq!(cohort_sizes_per_agent(&scorer, &agents).await, vec![10, 10, 10, 10, 10]);
    }

    #[tokio::test]
    async fn still_convicts_a_fleet_rotating_versions_within_one_family() {
        let scorer = local_scorer();
        let versions: Vec<i64> = (0..480).map(|index| 103 + (index % 16)).collect();
        let result = drive_cohort(&scorer, &versions).await;
        assert!(rules(&result.reasons).contains(&"cohort_version_uniformity_1h"));
    }

    // --- enumeration observer (shadow mode) ----------------------------------------

    fn enumeration_input() -> AnomalyInput<'static> {
        AnomalyInput {
            screen_width: Some(1920.0),
            screen_height: Some(1080.0),
            language: Some("en-US"),
            referrer: Some(""),
            ..base_input()
        }
    }

    async fn drive_enumeration_bucket(scorer: &AnomalyScorer, bucket_start_ms: i64) -> AnomalyResult {
        let mut result = None;
        for index in 0..320 {
            let ip = format!("198.51.{}.{}", index / 254, index % 254);
            let path = format!("/status/online/gender/f/hair/white/page/{bucket_start_ms}-{index}");
            result = Some(
                scorer
                    .observe_tracking_anomaly(&AnomalyInput {
                        ip_address: &ip,
                        pathname: Some(&path),
                        now_ms: Some(bucket_start_ms + index),
                        ..enumeration_input()
                    })
                    .await,
            );
        }
        result.unwrap()
    }

    #[tokio::test]
    async fn observes_an_enumerating_cohort_without_scoring_it() {
        let scorer = local_scorer();
        let result = drive_enumeration_bucket(&scorer, 1_000_000).await;
        let enumeration = result.enumeration.unwrap();
        assert!(enumeration.qualifies);
        assert!(!enumeration.sustained);
        assert_eq!(result.score, 0);
        assert!(!result.is_anomalous);
        assert!(result.convicting_reasons.is_empty());
    }

    #[tokio::test]
    async fn marks_the_cohort_once_the_shape_holds_across_two_consecutive_buckets() {
        let scorer = local_scorer();
        drive_enumeration_bucket(&scorer, 1_000_000).await;
        let result = drive_enumeration_bucket(&scorer, 1_000_000 + 15 * 60 * 1000).await;
        let enumeration = result.enumeration.unwrap();
        assert!(enumeration.qualifies && enumeration.sustained);
        assert!(!result.is_anomalous);
    }

    #[tokio::test]
    async fn does_not_carry_a_streak_across_a_gap_in_the_buckets() {
        let scorer = local_scorer();
        drive_enumeration_bucket(&scorer, 1_000_000).await;
        let result = drive_enumeration_bucket(&scorer, 1_000_000 + 3 * 15 * 60 * 1000).await;
        let enumeration = result.enumeration.unwrap();
        assert!(enumeration.qualifies && !enumeration.sustained);
    }

    #[tokio::test]
    async fn does_not_observe_when_the_hit_arrived_with_a_referrer() {
        let scorer = local_scorer();
        let result = scorer
            .observe_tracking_anomaly(&AnomalyInput {
                referrer: Some("https://news.example.com/"),
                ..enumeration_input()
            })
            .await;
        assert!(result.enumeration.is_none());
    }

    // --- site flood (in-process fallback) ------------------------------------------

    const BUCKET_START: i64 = 1_200_000;
    const QUIET_SITE: SiteBaseline = SiteBaseline { events10m: 0.0, eligible: true };

    async fn drive_one_shot_fleet(scorer: &AnomalyScorer, count: i64, baseline: BaselineSource) -> AnomalyResult {
        let mut result = None;
        for index in 0..count {
            let ip = format!("203.0.{}.{}", index / 250, index % 250);
            let ua = desktop_chrome(118 + (index % 4));
            let path = format!("/showcase/{}", index % 70);
            result = Some(
                scorer
                    .observe_tracking_anomaly(&AnomalyInput {
                        site_baseline: baseline,
                        ip_address: &ip,
                        user_agent: &ua,
                        screen_width: Some(1920.0),
                        screen_height: Some(1080.0),
                        language: Some("en-US"),
                        pathname: Some(&path),
                        referrer: None,
                        now_ms: Some(BUCKET_START + index * 1_000),
                        ..base_input()
                    })
                    .await,
            );
        }
        result.unwrap()
    }

    #[tokio::test]
    async fn convicts_a_one_shot_fleet_flooding_a_quiet_site() {
        let scorer = local_scorer();
        let result = drive_one_shot_fleet(&scorer, 120, BaselineSource::Given(QUIET_SITE)).await;
        assert!(result.is_anomalous);
        assert!(rules(&result.convicting_reasons).contains(&"site_flood_oneshot_cohort_10m"));
        assert_eq!(result.counters.site_events_10m, 120);
        assert_eq!(result.counters.cohort_distinct_actors_10m, 120);
    }

    #[tokio::test]
    async fn stays_quiet_below_the_flood_gate() {
        let scorer = local_scorer();
        assert!(!drive_one_shot_fleet(&scorer, 90, BaselineSource::Given(QUIET_SITE)).await.is_anomalous);
    }

    #[tokio::test]
    async fn never_fires_for_a_site_with_no_baseline() {
        let scorer = local_scorer();
        assert!(!drive_one_shot_fleet(&scorer, 200, BaselineSource::Absent).await.is_anomalous);
    }

    #[tokio::test]
    async fn never_fires_for_a_site_too_young_to_have_a_baseline() {
        let scorer = local_scorer();
        let young = SiteBaseline { events10m: 0.0, eligible: false };
        assert!(!drive_one_shot_fleet(&scorer, 200, BaselineSource::Given(young)).await.is_anomalous);
    }

    #[tokio::test]
    async fn scales_the_gate_with_the_sites_own_baseline() {
        let scorer = local_scorer();
        let busy = SiteBaseline { events10m: 30.0, eligible: true };
        assert!(!drive_one_shot_fleet(&scorer, 300, BaselineSource::Given(busy)).await.is_anomalous);
    }

    const SCREENS: [(f64, f64); 8] = [
        (390.0, 844.0),
        (393.0, 852.0),
        (430.0, 932.0),
        (1920.0, 1080.0),
        (1536.0, 864.0),
        (1366.0, 768.0),
        (412.0, 915.0),
        (1440.0, 900.0),
    ];

    #[tokio::test]
    async fn leaves_a_launch_shaped_surge_alone() {
        let scorer = local_scorer();
        let ua = desktop_chrome(150);
        let mut result = None;
        for index in 0..300 {
            let visitor = index / 3;
            let (width, height) = SCREENS[(visitor % 8) as usize];
            let ip = format!("198.51.{}.{}", visitor / 250, visitor % 250);
            let path = format!("/launch/{}", index % 5);
            result = Some(
                scorer
                    .observe_tracking_anomaly(&AnomalyInput {
                        site_baseline: BaselineSource::Given(QUIET_SITE),
                        ip_address: &ip,
                        user_agent: &ua,
                        screen_width: Some(width),
                        screen_height: Some(height),
                        language: Some("en-US"),
                        pathname: Some(&path),
                        referrer: Some("https://news.ycombinator.com/"),
                        now_ms: Some(BUCKET_START + index * 1_000),
                        ..base_input()
                    })
                    .await,
            );
        }
        let result = result.unwrap();
        assert_eq!(result.counters.site_events_10m, 300);
        assert!(!result.is_anomalous);
    }

    #[tokio::test]
    async fn leaves_a_one_shot_campaign_alone_when_devices_are_diverse() {
        let scorer = local_scorer();
        let ua = desktop_chrome(150);
        let mut result = None;
        for index in 0..300 {
            let (width, height) = SCREENS[(index % 8) as usize];
            let ip = format!("198.51.{}.{}", index / 250, index % 250);
            result = Some(
                scorer
                    .observe_tracking_anomaly(&AnomalyInput {
                        site_baseline: BaselineSource::Given(QUIET_SITE),
                        ip_address: &ip,
                        user_agent: &ua,
                        screen_width: Some(width),
                        screen_height: Some(height),
                        language: Some("en-US"),
                        pathname: Some("/promo"),
                        referrer: None,
                        now_ms: Some(BUCKET_START + index * 1_000),
                        ..base_input()
                    })
                    .await,
            );
        }
        assert!(!result.unwrap().is_anomalous);
    }

    #[tokio::test]
    async fn convicts_a_hosting_address_carrying_a_flood_on_its_own() {
        let scorer = local_scorer();
        let mut result = None;
        for index in 0..250 {
            result = Some(
                scorer
                    .observe_tracking_anomaly(&AnomalyInput {
                        site_baseline: BaselineSource::Given(QUIET_SITE),
                        ip_address: "20.0.0.5",
                        is_hosting_asn: true,
                        asn: Some(8075),
                        screen_width: Some(1920.0),
                        screen_height: Some(1080.0),
                        language: Some("en-US"),
                        pathname: Some("/"),
                        now_ms: Some(BUCKET_START + index * 2_000),
                        ..base_input()
                    })
                    .await,
            );
        }
        let result = result.unwrap();
        assert!(result.is_anomalous);
        assert!(rules(&result.convicting_reasons).contains(&"site_flood_actor_1d"));
    }

    #[tokio::test]
    async fn never_convicts_a_residential_address_on_volume_inside_a_flood() {
        let scorer = local_scorer();
        let mut result = None;
        for index in 0..1200 {
            result = Some(
                scorer
                    .observe_tracking_anomaly(&AnomalyInput {
                        site_baseline: BaselineSource::Given(QUIET_SITE),
                        ip_address: "203.0.113.77",
                        is_hosting_asn: false,
                        pathname: Some("/"),
                        now_ms: Some(BUCKET_START + index * 2_000),
                        ..base_input()
                    })
                    .await,
            );
        }
        let result = result.unwrap();
        assert!(!rules(&result.reasons).contains(&"site_flood_actor_1d"));
        assert!(!result.is_anomalous);
    }

    // --- hosting actor volume (Redis-backed, mocked script) --------------------------

    // Spec order for base_input: te10, te60, tdp, ie60, idua, idh, sue, av, se, sa.
    #[tokio::test]
    async fn convicts_a_hosting_address_on_long_window_volume_alone() {
        let (scorer, _) = mocked_scorer(Ok(rolling_readings(&[1, 2, 1, 10, 1, 1, 5, 1500, 20, 20])));
        let result = scorer
            .observe_tracking_anomaly(&AnomalyInput { is_hosting_asn: true, asn: Some(8075), ..base_input() })
            .await;
        assert!(result.is_anomalous);
        assert_eq!(rules(&result.convicting_reasons), vec!["hosting_actor_events_1d"]);
    }

    #[tokio::test]
    async fn exempts_sase_egress_from_the_hosting_rule() {
        let (scorer, _) = mocked_scorer(Ok(rolling_readings(&[1, 2, 1, 10, 1, 1, 5, 1500, 20, 20])));
        let result = scorer
            .observe_tracking_anomaly(&AnomalyInput { is_hosting_asn: true, asn: Some(13150), ..base_input() })
            .await;
        assert!(!result.is_anomalous);
        assert!(!rules(&result.reasons).contains(&"hosting_actor_events_1d"));
    }

    #[tokio::test]
    async fn drops_the_hosting_rule_for_an_address_showing_many_user_agents() {
        let (scorer, _) = mocked_scorer(Ok(rolling_readings(&[1, 2, 1, 10, 12, 1, 5, 1500, 20, 20])));
        let result = scorer
            .observe_tracking_anomaly(&AnomalyInput { is_hosting_asn: true, asn: Some(8075), ..base_input() })
            .await;
        assert!(!result.is_anomalous);
    }

    // --- observeTrackingAnomaly (Redis-backed, mocked script) -------------------------

    #[tokio::test]
    async fn sends_one_spec_per_enabled_counter_and_maps_results_back_by_name() {
        let (scorer, calls) = mocked_scorer(Ok(rolling_readings(&[31, 5, 2, 9, 3, 1, 4, 7, 12, 1, 1])));
        let result =
            scorer.observe_tracking_anomaly(&AnomalyInput { has_client_bot_score: false, ..base_input() }).await;

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (now, specs) = &calls[0];
        assert_eq!(*now, BASE_NOW);
        assert_eq!(specs.len(), 11);
        let prefixes = [
            "bot:a:te10:",
            "bot:a:te60:",
            "bot:a:tdp:",
            "bot:a:ie60:",
            "bot:a:idua:",
            "bot:a:idh:",
            "bot:a:sue:",
            "bot:a:mcs:",
            "bot:a:av:",
            "bot:f:se:",
            "bot:f:sa:",
        ];
        for (spec, prefix) in specs.iter().zip(prefixes) {
            assert!(spec.key.starts_with(prefix), "{} starts with {prefix}", spec.key);
        }

        assert_eq!(result.counters.tuple_events_10s, 31);
        assert_eq!(result.counters.missing_client_score_60s, 7);
        assert!(result.is_anomalous);
        assert!(rules(&result.reasons).contains(&"tuple_events_10s"));
    }

    #[tokio::test]
    async fn never_convicts_on_long_window_volume_alone() {
        let (scorer, _) = mocked_scorer(Ok(rolling_readings(&[1, 2, 1, 10, 1, 1, 5, 1500])));
        let result = scorer.observe_tracking_anomaly(&base_input()).await;
        assert!(!result.is_anomalous);
        assert_eq!(result.score, 0);
        assert!(rules(&result.supporting_reasons).contains(&"actor_events_1d"));
        assert!(result.convicting_reasons.is_empty());
    }

    #[tokio::test]
    async fn drops_long_window_volume_for_an_actor_showing_many_user_agents() {
        let (scorer, _) = mocked_scorer(Ok(rolling_readings(&[1, 2, 1, 10, 12, 1, 5, 1500])));
        let result = scorer.observe_tracking_anomaly(&base_input()).await;
        assert!(!rules(&result.reasons).contains(&"actor_events_1d"));
        assert!(rules(&result.reasons).contains(&"ip_distinct_user_agents_5m"));
    }

    #[tokio::test]
    async fn adds_long_window_volume_to_a_score_convicting_evidence_opened() {
        let (scorer, _) = mocked_scorer(Ok(rolling_readings(&[31, 2, 1, 10, 1, 1, 5, 1500])));
        let result = scorer.observe_tracking_anomaly(&base_input()).await;
        assert_eq!(rules(&result.convicting_reasons), vec!["tuple_events_10s"]);
        assert_eq!(result.score, 5);
        assert!(result.is_anomalous);
    }

    #[tokio::test]
    async fn omits_conditional_counters_that_do_not_apply() {
        let (scorer, calls) = mocked_scorer(Ok(rolling_readings(&[1, 1, 1, 1, 1, 1, 1, 1])));
        let result = scorer
            .observe_tracking_anomaly(&AnomalyInput {
                pathname: None,
                hostname: None,
                has_client_bot_score: true,
                ..base_input()
            })
            .await;
        assert_eq!(calls.lock().unwrap()[0].1.len(), 8);
        assert_eq!(result.counters.tuple_distinct_paths_60s, 0);
        assert_eq!(result.counters.ip_distinct_hosts_60s, 0);
        assert_eq!(result.counters.missing_client_score_60s, 0);
    }

    #[tokio::test]
    async fn never_convicts_on_crowd_rules_alone() {
        let (scorer, _) = mocked_scorer(Ok(rolling_readings(&[1, 2, 1, 500, 40, 12, 5000])));
        let result = scorer.observe_tracking_anomaly(&base_input()).await;
        assert!(!result.is_anomalous);
        assert_eq!(result.score, 0);
        assert_eq!(
            rules(&result.reasons),
            vec!["ip_events_60s", "ip_distinct_user_agents_5m", "ip_distinct_hosts_60s", "site_user_agent_events_60s"]
        );
    }

    #[tokio::test]
    async fn counts_crowd_rules_once_individual_evidence_exists() {
        let (scorer, _) = mocked_scorer(Ok(rolling_readings(&[31, 31, 1, 500, 40, 12, 5000])));
        let result = scorer.observe_tracking_anomaly(&base_input()).await;
        assert!(result.is_anomalous);
        assert_eq!(result.score, 4 + 3 + 3 + 2 + 1);
    }

    #[tokio::test]
    async fn falls_back_to_in_process_counting_when_redis_fails() {
        let (scorer, _) = mocked_scorer(Err("redis down".to_string()));
        let first = scorer.observe_tracking_anomaly(&base_input()).await;
        assert_eq!(first.counters.tuple_events_10s, 1);
        let second =
            scorer.observe_tracking_anomaly(&AnomalyInput { now_ms: Some(BASE_NOW + 1), ..base_input() }).await;
        assert_eq!(second.counters.tuple_events_10s, 2);
    }

    #[tokio::test]
    async fn falls_back_when_no_redis_handle_exists_but_scoring_is_enabled() {
        let scorer = AnomalyScorer::new(None, Arc::new(SiteBaselines::new()));
        scorer.set_redis_enabled(true);
        let result = scorer.observe_tracking_anomaly(&base_input()).await;
        assert_eq!(result.counters.tuple_events_10s, 1);
    }

    #[test]
    fn builds_node_shaped_keys_and_members() {
        let scorer = local_scorer();
        let input = AnomalyInput {
            ip_address: " 203.0.113.10 ",
            user_agent: CHROME_120,
            hostname: Some("Example.COM"),
            pathname: Some("/Docs"),
            screen_width: Some(1920.0),
            screen_height: Some(1080.0),
            language: Some("en-US"),
            referrer: Some(""),
            ..base_input()
        };
        let plan = scorer.build_counter_plan(&input, 3_600_000 * 500 + 7);
        let hash = hash_value(CHROME_120);
        let keys: Vec<&str> = plan.counters.iter().map(|entry| entry.redis_key.as_str()).collect();
        assert_eq!(keys[0], format!("bot:a:te10:123:203.0.113.10:{hash}"));
        assert_eq!(keys[9], "bot:a:cbv:123:1920x1080:en-us:chrome:500");
        assert_eq!(keys[10], format!("bot:a:av:123:203.0.113.10:{}", (3_600_000 * 500 + 7) / DAY));
        assert_eq!(plan.counters[3].member, "/docs");
        assert_eq!(plan.counters[6].member, "example.com");
        assert_eq!(plan.counters[9].member, "120");
        assert!(plan.counters[0].member.starts_with(&format!("{}-{}-", 3_600_000 * 500 + 7, *PROCESS_ID)));
        assert_eq!(
            plan.enumeration,
            Some(EnumerationPlan {
                cohort_key: "123:1920x1080:en-us:chrome".to_string(),
                bucket: (3_600_000 * 500 + 7) / ENUMERATION_BUCKET_MS,
                is_direct: true
            })
        );
    }
}
