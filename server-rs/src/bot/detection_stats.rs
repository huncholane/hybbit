//! Bot detection totals, ported from
//! server/src/services/tracker/botBlocking/botDetectionStats.ts.
//!
//! Counters are incremented in-process on the hot path (no per-event Redis) and
//! flushed once a minute as deltas into the Redis hash `bot:stats`, which Node
//! processes flush into too, so the logged totals are cluster-wide and span both
//! backends. The field names (`totalRequests`, `m:<method>`, `cs:<bucket>`,
//! `sig:<signal>`) are Node's. Whichever process wins the `bot:stats:loglock`
//! lock for the interval logs the aggregate, so the cluster emits one line.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use indexmap::IndexMap;
use redis::aio::ConnectionManager;
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::task::JoinHandle;

use super::{
    anomaly_observe::REDIS_COMMAND_TIMEOUT,
    js::{js_round_to_fixed, js_string_to_number},
    signal_contract::{ALL_CLIENT_BOT_SIGNAL_BITS, ClientBotSignal, to_int32},
};

/// `BotDetectionMethod`: the detection layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BotDetectionMethod {
    UaPattern,
    HeaderHeuristics,
    ClientSignals,
    BotAsn,
    RateAnomaly,
}

impl BotDetectionMethod {
    /// `BOT_DETECTION_METHODS`
    pub const ALL: [BotDetectionMethod; 5] = [
        BotDetectionMethod::UaPattern,
        BotDetectionMethod::HeaderHeuristics,
        BotDetectionMethod::ClientSignals,
        BotDetectionMethod::BotAsn,
        BotDetectionMethod::RateAnomaly,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            BotDetectionMethod::UaPattern => "ua_pattern",
            BotDetectionMethod::HeaderHeuristics => "header_heuristics",
            BotDetectionMethod::ClientSignals => "client_signals",
            BotDetectionMethod::BotAsn => "bot_asn",
            BotDetectionMethod::RateAnomaly => "rate_anomaly",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// `BOT_DETECTION_STATS_INTERVAL_MS`
pub const BOT_DETECTION_STATS_INTERVAL: Duration = Duration::from_millis(60_000);
const STATS_HASH_KEY: &str = "bot:stats";
const STATS_LOG_LOCK_KEY: &str = "bot:stats:loglock";
const STATS_LOG_LOCK_TTL_MS: i64 = 60_000 - 5_000;

/// Histogram bucket names in Node's key order.
const HISTOGRAM_KEYS: [&str; 5] = ["missing", "score0", "score1", "score2", "score3Plus"];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counters {
    total_requests: i64,
    total_bot_requests: i64,
    total_enforced_bot_requests: i64,
    totals: [i64; 5],
    /// missing, score0, score1, score2, score3Plus
    histogram: [i64; 5],
    missing_mask: i64,
    unknown_mask_bits: i64,
    /// Per `ClientBotSignal::ALL` index.
    signals: [i64; 13],
}

/// `getBotDetectionStats()`'s shape.
#[derive(Clone, Debug, PartialEq)]
pub struct BotDetectionStatsSnapshot {
    pub total_requests: i64,
    pub total_bot_requests: i64,
    pub total_enforced_bot_requests: i64,
    pub bot_request_percentage: f64,
    pub totals: IndexMap<&'static str, i64>,
    pub client_bot_score_histogram: IndexMap<&'static str, i64>,
    pub client_bot_signal_totals: IndexMap<&'static str, i64>,
}

/// `getBotRequestPercentage`: two decimals, the JavaScript way.
fn bot_request_percentage(requests: i64, bot_requests: i64) -> f64 {
    if requests == 0 {
        return 0.0;
    }
    js_round_to_fixed((bot_requests as f64 / requests as f64) * 100.0, 2)
}

/// Redis key names, overridable so tests never touch the shared keys.
#[derive(Clone, Debug)]
struct StatsKeys {
    hash: String,
    lock: String,
}

/// In-process detection totals plus the flush bookkeeping.
pub struct BotDetectionStats {
    counters: Mutex<Counters>,
    last_flushed: Mutex<HashMap<String, i64>>,
    flushing: AtomicBool,
    keys: StatsKeys,
}

impl Default for BotDetectionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl BotDetectionStats {
    pub fn new() -> Self {
        Self::with_keys(STATS_HASH_KEY, STATS_LOG_LOCK_KEY)
    }

    fn with_keys(hash: &str, lock: &str) -> Self {
        Self {
            counters: Mutex::default(),
            last_flushed: Mutex::default(),
            flushing: AtomicBool::new(false),
            keys: StatsKeys { hash: hash.to_string(), lock: lock.to_string() },
        }
    }

    fn counters(&self) -> std::sync::MutexGuard<'_, Counters> {
        self.counters.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `recordBotBlockingRequest`. `has_client_score` and `has_client_mask` are
    /// whether the client reported them, which measures tracker adoption; the
    /// score and mask are what the request ended up with, server-inferred
    /// signals included.
    pub fn record_bot_blocking_request(
        &self,
        client_bot_score: Option<i64>,
        client_bot_signal_mask: Option<i64>,
        has_client_mask: bool,
        has_client_score: bool,
    ) {
        let mut counters = self.counters();
        counters.total_requests += 1;

        let bucket = match client_bot_score.filter(|_| has_client_score) {
            None => 0,
            Some(0) => 1,
            Some(1) => 2,
            Some(2) => 3,
            Some(_) => 4,
        };
        counters.histogram[bucket] += 1;

        if !has_client_mask {
            counters.missing_mask += 1;
        }

        if let Some(mask) = client_bot_signal_mask {
            let mask = to_int32(mask);
            for (index, signal) in ClientBotSignal::ALL.iter().enumerate() {
                if mask & signal.mask() != 0 {
                    counters.signals[index] += 1;
                }
            }
            if mask & !ALL_CLIENT_BOT_SIGNAL_BITS != 0 {
                counters.unknown_mask_bits += 1;
            }
        }
    }

    /// `recordBotDetections`: `enforced` is whether the detection was acted on,
    /// so the gap between detected and enforced is what sites with blocking
    /// disabled are absorbing.
    pub fn record_bot_detections(&self, methods: &[BotDetectionMethod], enforced: bool) {
        let mut counters = self.counters();
        counters.total_bot_requests += 1;
        if enforced {
            counters.total_enforced_bot_requests += 1;
        }
        for method in methods {
            counters.totals[method.index()] += 1;
        }
    }

    /// `getBotDetectionStats`
    pub fn snapshot(&self) -> BotDetectionStatsSnapshot {
        let counters = *self.counters();
        snapshot_from(&counters)
    }

    /// `resetBotDetectionStatsForTests`
    pub fn reset(&self) {
        *self.counters() = Counters::default();
        self.last_flushed.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    }

    /// `flattenLocalCounters`: the Redis hash field names, in Node's order.
    fn flatten(counters: &Counters) -> Vec<(String, i64)> {
        let mut flat = vec![
            ("totalRequests".to_string(), counters.total_requests),
            ("totalBotRequests".to_string(), counters.total_bot_requests),
            ("totalEnforcedBotRequests".to_string(), counters.total_enforced_bot_requests),
        ];
        for method in BotDetectionMethod::ALL {
            flat.push((format!("m:{}", method.as_str()), counters.totals[method.index()]));
        }
        for (index, key) in HISTOGRAM_KEYS.iter().enumerate() {
            flat.push((format!("cs:{key}"), counters.histogram[index]));
        }
        flat.push(("sig:missingMask".to_string(), counters.missing_mask));
        flat.push(("sig:unknownMaskBits".to_string(), counters.unknown_mask_bits));
        for (index, signal) in ClientBotSignal::ALL.iter().enumerate() {
            flat.push((format!("sig:{}", signal.name()), counters.signals[index]));
        }
        flat
    }

    /// `flushBotDetectionStats`: push the deltas since the last flush into the
    /// shared hash and, if this process wins the interval lock, log the
    /// cluster-wide aggregate. Re-entrant calls are ignored and nothing throws:
    /// without Redis the local totals are logged instead.
    pub async fn flush(&self, redis: &ConnectionManager) {
        if self.flushing.swap(true, Ordering::SeqCst) {
            return;
        }

        let result: anyhow::Result<()> = async {
            let current = Self::flatten(&self.counters());
            let mut connection = redis.clone();

            let deltas: Vec<(String, i64)> = {
                let last = self.last_flushed.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                current
                    .iter()
                    .map(|(field, value)| (field.clone(), value - last.get(field).copied().unwrap_or(0)))
                    .filter(|(_, delta)| *delta != 0)
                    .collect()
            };
            if !deltas.is_empty() {
                let mut pipeline = redis::pipe();
                for (field, delta) in &deltas {
                    pipeline.cmd("HINCRBY").arg(&self.keys.hash).arg(field).arg(*delta).ignore();
                }
                with_timeout(pipeline.query_async::<()>(&mut connection)).await?;
            }
            *self.last_flushed.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = current.into_iter().collect();

            let mut lock = redis::cmd("SET");
            lock.arg(&self.keys.lock).arg("1").arg("PX").arg(STATS_LOG_LOCK_TTL_MS).arg("NX");
            let acquired = with_timeout(lock.query_async::<Option<String>>(&mut connection)).await?;
            if acquired.is_some() {
                let mut read = redis::cmd("HGETALL");
                read.arg(&self.keys.hash);
                let hash = with_timeout(read.query_async::<HashMap<String, String>>(&mut connection)).await?;
                let aggregate = structure_aggregate(&hash);
                tracing::info!(
                    total_requests = aggregate.total_requests,
                    total_bot_requests = aggregate.total_bot_requests,
                    total_enforced_bot_requests = aggregate.total_enforced_bot_requests,
                    bot_request_percentage = aggregate.bot_request_percentage,
                    bot_detection_totals = %json_map(&aggregate.totals),
                    client_bot_score_histogram = %json_map(&aggregate.client_bot_score_histogram),
                    client_bot_signal_totals = %json_map(&aggregate.client_bot_signal_totals),
                    deltas_flushed = deltas.len(),
                    "Bot detection totals (cluster, cumulative)"
                );
            } else {
                tracing::debug!(
                    deltas_flushed = deltas.len(),
                    "Bot detection totals flushed; another process logs this interval"
                );
            }
            Ok(())
        }
        .await;

        if let Err(error) = result {
            let local = self.snapshot();
            tracing::warn!(
                error = %error,
                total_requests = local.total_requests,
                total_bot_requests = local.total_bot_requests,
                total_enforced_bot_requests = local.total_enforced_bot_requests,
                bot_request_percentage = local.bot_request_percentage,
                totals = %json_map(&local.totals),
                client_bot_score_histogram = %json_map(&local.client_bot_score_histogram),
                client_bot_signal_totals = %json_map(&local.client_bot_signal_totals),
                "Bot detection totals (local; Redis aggregation unavailable)"
            );
        }
        self.flushing.store(false, Ordering::SeqCst);
    }
}

async fn with_timeout<T>(future: impl Future<Output = redis::RedisResult<T>>) -> anyhow::Result<T> {
    Ok(tokio::time::timeout(REDIS_COMMAND_TIMEOUT, future)
        .await
        .map_err(|_| anyhow::anyhow!("Redis command timed out after {REDIS_COMMAND_TIMEOUT:?}"))??)
}

fn json_map(map: &IndexMap<&'static str, i64>) -> String {
    let object: Map<String, Value> = map.iter().map(|(key, value)| (key.to_string(), Value::from(*value))).collect();
    Value::Object(object).to_string()
}

fn snapshot_from(counters: &Counters) -> BotDetectionStatsSnapshot {
    let mut signal_totals = IndexMap::new();
    signal_totals.insert("missingMask", counters.missing_mask);
    signal_totals.insert("unknownMaskBits", counters.unknown_mask_bits);
    for (index, signal) in ClientBotSignal::ALL.iter().enumerate() {
        signal_totals.insert(signal.name(), counters.signals[index]);
    }
    BotDetectionStatsSnapshot {
        total_requests: counters.total_requests,
        total_bot_requests: counters.total_bot_requests,
        total_enforced_bot_requests: counters.total_enforced_bot_requests,
        bot_request_percentage: bot_request_percentage(counters.total_requests, counters.total_bot_requests),
        totals: BotDetectionMethod::ALL
            .iter()
            .map(|method| (method.as_str(), counters.totals[method.index()]))
            .collect(),
        client_bot_score_histogram: HISTOGRAM_KEYS
            .iter()
            .enumerate()
            .map(|(index, key)| (*key, counters.histogram[index]))
            .collect(),
        client_bot_signal_totals: signal_totals,
    }
}

/// `structureAggregate`: the shared hash read back into the logged shape.
/// `Number(hash[field] ?? 0) || 0`, so junk reads as zero.
fn structure_aggregate(hash: &HashMap<String, String>) -> BotDetectionStatsSnapshot {
    let num = |field: &str| -> i64 {
        let value = hash.get(field).map(|text| js_string_to_number(text)).unwrap_or(0.0);
        if value.is_nan() { 0 } else { value as i64 }
    };
    let mut counters = Counters {
        total_requests: num("totalRequests"),
        total_bot_requests: num("totalBotRequests"),
        total_enforced_bot_requests: num("totalEnforcedBotRequests"),
        missing_mask: num("sig:missingMask"),
        unknown_mask_bits: num("sig:unknownMaskBits"),
        ..Counters::default()
    };
    for method in BotDetectionMethod::ALL {
        counters.totals[method.index()] = num(&format!("m:{}", method.as_str()));
    }
    for (index, key) in HISTOGRAM_KEYS.iter().enumerate() {
        counters.histogram[index] = num(&format!("cs:{key}"));
    }
    for (index, signal) in ClientBotSignal::ALL.iter().enumerate() {
        counters.signals[index] = num(&format!("sig:{}", signal.name()));
    }
    snapshot_from(&counters)
}

/// The module-level `setInterval` in Node: flush every 60 seconds. The first
/// flush happens one interval after start. Abort the handle to stop it.
pub fn spawn_bot_detection_stats_flush(stats: Arc<BotDetectionStats>, redis: ConnectionManager) -> JoinHandle<()> {
    tracing::info!(interval_ms = BOT_DETECTION_STATS_INTERVAL.as_millis() as u64, "Starting bot detection stats flush");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + BOT_DETECTION_STATS_INTERVAL,
            BOT_DETECTION_STATS_INTERVAL,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            stats.flush(&redis).await;
        }
    })
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/tracker/botBlocking/botDetectionStats.test.ts,
    //! against the parity Redis with test-only key names instead of a mock.
    use super::*;
    use crate::bot::anomaly_observe::tests::{delete_matching, parity_redis};

    async fn hash(redis: &ConnectionManager, key: &str) -> HashMap<String, String> {
        let mut connection = redis.clone();
        redis::cmd("HGETALL").arg(key).query_async(&mut connection).await.unwrap()
    }

    #[tokio::test]
    async fn flushes_only_the_delta_since_the_previous_flush() {
        let Some(redis) = parity_redis().await else { return };
        let (hash_key, lock_key) = ("bot:test:65020:stats", "bot:test:65020:stats:loglock");
        delete_matching(&redis, "bot:test:65020:*").await;
        // Hold the lock so this test is only about the deltas.
        let mut connection = redis.clone();
        let _: () = redis::cmd("SET")
            .arg(lock_key)
            .arg("held")
            .arg("PX")
            .arg(60_000)
            .query_async(&mut connection)
            .await
            .unwrap();

        let stats = BotDetectionStats::with_keys(hash_key, lock_key);
        stats.record_bot_blocking_request(None, None, false, false);
        stats.record_bot_detections(&[BotDetectionMethod::UaPattern], true);
        stats.flush(&redis).await;

        let first = hash(&redis, hash_key).await;
        assert_eq!(first.get("totalRequests").map(String::as_str), Some("1"));
        assert_eq!(first.get("totalBotRequests").map(String::as_str), Some("1"));
        assert_eq!(first.get("m:ua_pattern").map(String::as_str), Some("1"));
        assert_eq!(first.get("cs:missing").map(String::as_str), Some("1"));
        assert_eq!(first.get("sig:missingMask").map(String::as_str), Some("1"));
        assert!(!first.contains_key("m:bot_asn"), "unchanged fields are not sent");

        // Pretend another process added to the shared totals in between.
        let _: () = redis::cmd("HINCRBY")
            .arg(hash_key)
            .arg("totalRequests")
            .arg(10)
            .query_async(&mut connection)
            .await
            .unwrap();
        stats.record_bot_blocking_request(Some(0), Some(0), true, true);
        stats.flush(&redis).await;

        let second = hash(&redis, hash_key).await;
        assert_eq!(second.get("totalRequests").map(String::as_str), Some("12"), "a delta of 1, not the running total");
        assert_eq!(second.get("cs:score0").map(String::as_str), Some("1"));
        assert_eq!(second.get("m:ua_pattern").map(String::as_str), Some("1"));

        delete_matching(&redis, "bot:test:65020:*").await;
    }

    #[tokio::test]
    async fn does_nothing_to_the_hash_when_there_is_nothing_new() {
        let Some(redis) = parity_redis().await else { return };
        let (hash_key, lock_key) = ("bot:test:65021:stats", "bot:test:65021:stats:loglock");
        delete_matching(&redis, "bot:test:65021:*").await;
        let stats = BotDetectionStats::with_keys(hash_key, lock_key);
        stats.flush(&redis).await;
        assert!(hash(&redis, hash_key).await.is_empty());
        delete_matching(&redis, "bot:test:65021:*").await;
    }

    #[tokio::test]
    async fn takes_the_log_lock_with_nx_and_a_ttl() {
        let Some(redis) = parity_redis().await else { return };
        let (hash_key, lock_key) = ("bot:test:65022:stats", "bot:test:65022:stats:loglock");
        delete_matching(&redis, "bot:test:65022:*").await;
        let stats = BotDetectionStats::with_keys(hash_key, lock_key);
        stats.record_bot_blocking_request(None, None, false, false);
        stats.flush(&redis).await;

        let mut connection = redis.clone();
        let value: Option<String> = redis::cmd("GET").arg(lock_key).query_async(&mut connection).await.unwrap();
        assert_eq!(value.as_deref(), Some("1"));
        let ttl: i64 = redis::cmd("PTTL").arg(lock_key).query_async(&mut connection).await.unwrap();
        assert!(ttl > 0 && ttl <= STATS_LOG_LOCK_TTL_MS);

        // A second flush inside the interval does not overwrite the held lock.
        let _: () = redis::cmd("SET")
            .arg(lock_key)
            .arg("other")
            .arg("PX")
            .arg(60_000)
            .query_async(&mut connection)
            .await
            .unwrap();
        stats.record_bot_blocking_request(None, None, false, false);
        stats.flush(&redis).await;
        let value: Option<String> = redis::cmd("GET").arg(lock_key).query_async(&mut connection).await.unwrap();
        assert_eq!(value.as_deref(), Some("other"));
        delete_matching(&redis, "bot:test:65022:*").await;
    }

    #[tokio::test]
    async fn survives_a_failed_flush_and_resends_the_delta_later() {
        let Some(redis) = parity_redis().await else { return };
        let (hash_key, lock_key) = ("bot:test:65023:stats", "bot:test:65023:stats:loglock");
        delete_matching(&redis, "bot:test:65023:*").await;
        // A string where the hash should be makes every HINCRBY fail, which takes
        // the same path as Redis being unreachable.
        let mut connection = redis.clone();
        let _: () = redis::cmd("SET").arg(hash_key).arg("not a hash").query_async(&mut connection).await.unwrap();

        let stats = BotDetectionStats::with_keys(hash_key, lock_key);
        stats.record_bot_detections(&[BotDetectionMethod::RateAnomaly], true);
        stats.flush(&redis).await;
        assert!(!stats.flushing.load(Ordering::SeqCst), "the re-entrancy guard is released");

        let _: () = redis::cmd("DEL").arg(hash_key).query_async(&mut connection).await.unwrap();
        stats.flush(&redis).await;
        let flushed = hash(&redis, hash_key).await;
        assert_eq!(flushed.get("m:rate_anomaly").map(String::as_str), Some("1"), "nothing was lost");
        delete_matching(&redis, "bot:test:65023:*").await;
    }

    #[test]
    fn records_the_histogram_and_signal_totals_like_node() {
        let stats = BotDetectionStats::new();
        stats.record_bot_blocking_request(None, None, false, false);
        stats.record_bot_blocking_request(Some(0), Some(0), true, true);
        stats.record_bot_blocking_request(Some(1), Some(ClientBotSignal::SwiftShader.mask() as i64), true, true);
        stats.record_bot_blocking_request(
            Some(2),
            Some(ClientBotSignal::ZeroOuterDimensions.mask() as i64),
            true,
            true,
        );
        stats.record_bot_blocking_request(
            Some(3),
            Some(ClientBotSignal::AutomationApi.mask() as i64 | (1 << 20)),
            true,
            true,
        );
        // A score the client did not report counts as missing even when inferred.
        stats.record_bot_blocking_request(
            Some(1),
            Some(ClientBotSignal::MissingScreenDimensions.mask() as i64),
            false,
            false,
        );
        stats.record_bot_detections(&[BotDetectionMethod::ClientSignals, BotDetectionMethod::BotAsn], false);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_requests, 6);
        assert_eq!(snapshot.total_bot_requests, 1);
        assert_eq!(snapshot.total_enforced_bot_requests, 0);
        assert_eq!(snapshot.bot_request_percentage, 16.67);
        assert_eq!(snapshot.totals["client_signals"], 1);
        assert_eq!(snapshot.totals["bot_asn"], 1);
        assert_eq!(snapshot.client_bot_score_histogram.values().copied().collect::<Vec<_>>(), vec![2, 1, 1, 1, 1]);
        assert_eq!(snapshot.client_bot_signal_totals["missingMask"], 2);
        assert_eq!(snapshot.client_bot_signal_totals["unknownMaskBits"], 1);
        assert_eq!(snapshot.client_bot_signal_totals["automationApi"], 1);
        assert_eq!(snapshot.client_bot_signal_totals["missingScreenDimensions"], 1);
        let keys: Vec<&str> = snapshot.client_bot_signal_totals.keys().copied().collect();
        assert_eq!(&keys[..3], &["missingMask", "unknownMaskBits", "automationApi"]);

        let flat = BotDetectionStats::flatten(&stats.counters());
        let roundtrip: HashMap<String, String> =
            flat.iter().map(|(key, value)| (key.clone(), value.to_string())).collect();
        assert_eq!(structure_aggregate(&roundtrip), snapshot);
    }
}
