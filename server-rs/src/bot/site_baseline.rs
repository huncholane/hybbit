//! Per-site traffic baselines for the site-flood rules, ported from
//! server/src/services/tracker/botBlocking/siteBaseline.ts.
//!
//! Every other rate rule uses an absolute threshold, so a site that normally sees
//! four events an hour can be hit at a thousand times that by individually
//! well-behaved traffic and trip nothing. The flood rules compare the site's
//! current 10-minute volume with its own normal: the median of its 10-minute
//! event counts over the trailing week, empty buckets counted as zero (1,008
//! buckets). A site whose first event in the window is under six and a half days
//! old is not yet eligible, and a site with no row has no baseline; both keep the
//! flood rules off, so every failure fails towards not accusing.
//!
//! One ClickHouse aggregate every 15 minutes, elected through a Redis lock and
//! written to the Redis hash `bot:sb` that Node and Rust share (`<events10m>:<0|1>`
//! per site id), mirrored into the in-process map the hot path reads every five
//! minutes. The hot path never touches Redis or ClickHouse for this.

use std::{
    collections::HashMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use redis::aio::ConnectionManager;
use serde_json::{Map, Value};
use tokio::task::JoinHandle;

use super::{
    anomaly_observe::REDIS_COMMAND_TIMEOUT,
    js::{PROCESS_ID, js_number_to_string, js_string_to_number},
};
use crate::clickhouse::ClickHouse;

const TEN_MINUTES_PER_WEEK: u32 = 7 * 24 * 6;
const MIN_SITE_AGE_HOURS: u32 = 6 * 24 + 12;
/// `SITE_BASELINE_REFRESH_MS`
pub const SITE_BASELINE_REFRESH: Duration = Duration::from_millis(15 * 60 * 1000);
/// `SITE_BASELINE_MIRROR_MS`
pub const SITE_BASELINE_MIRROR: Duration = Duration::from_millis(5 * 60 * 1000);
const REDIS_HASH_KEY: &str = "bot:sb";
const REDIS_HASH_TTL_MS: i64 = 2 * 60 * 60 * 1000;
/// Refresh election: only the process that wins this lock queries ClickHouse.
const REFRESH_LOCK_KEY: &str = "bot:sb:lock";
const REFRESH_LOCK_TTL_MS: i64 = 15 * 60 * 1000 - 30_000;

/// The query, verbatim from siteBaseline.ts.
const BASELINE_QUERY: &str = "
      SELECT
        site_id,
        arraySort(arrayResize(groupArray(c), {buckets:UInt32}, 0))[{median:UInt32}] AS baseline_10m,
        min(b) <= now() - INTERVAL {minAgeHours:UInt32} HOUR AS eligible
      FROM (
        SELECT site_id, toStartOfInterval(timestamp, INTERVAL 10 MINUTE) AS b, count() AS c
        FROM events
        WHERE timestamp >= now() - INTERVAL 7 DAY
        GROUP BY site_id, b
      )
      GROUP BY site_id
    ";

/// `SiteBaseline`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SiteBaseline {
    /// Median events per 10-minute bucket over the trailing week, zero-padded.
    pub events10m: f64,
    /// Whether the site has enough history for a baseline to mean anything.
    pub eligible: bool,
}

/// The process-local baseline map (`baselines` in Node), shared by the scorer
/// and the refresh tasks.
#[derive(Default)]
pub struct SiteBaselines {
    baselines: RwLock<HashMap<i32, SiteBaseline>>,
    started: AtomicBool,
    keys: BaselineKeys,
}

/// Redis key names, overridable so tests against a shared Redis never touch the
/// production-named keys.
#[derive(Clone, Debug)]
struct BaselineKeys {
    hash: String,
    lock: String,
}

impl Default for BaselineKeys {
    fn default() -> Self {
        Self { hash: REDIS_HASH_KEY.to_string(), lock: REFRESH_LOCK_KEY.to_string() }
    }
}

impl SiteBaselines {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_keys(hash: &str, lock: &str) -> Self {
        Self { keys: BaselineKeys { hash: hash.to_string(), lock: lock.to_string() }, ..Self::default() }
    }

    /// `getSiteBaseline`.
    pub fn get(&self, site_id: i32) -> Option<SiteBaseline> {
        self.baselines.read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&site_id).copied()
    }

    /// `setSiteBaselineForTests`.
    pub fn set(&self, site_id: i32, baseline: Option<SiteBaseline>) {
        let mut baselines = self.baselines.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        match baseline {
            Some(baseline) => baselines.insert(site_id, baseline),
            None => baselines.remove(&site_id),
        };
    }

    /// `resetSiteBaselinesForTests`.
    pub fn reset(&self) {
        self.baselines.write().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    }

    pub fn len(&self) -> usize {
        self.baselines.read().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    /// `replaceBaselines`.
    fn replace(&self, next: HashMap<i32, SiteBaseline>) {
        *self.baselines.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
    }
}

/// `encode`: `<events10m>:<1|0>`, the number printed the JavaScript way.
pub fn encode(baseline: SiteBaseline) -> String {
    format!("{}:{}", js_number_to_string(baseline.events10m), if baseline.eligible { 1 } else { 0 })
}

/// `decode`: None when the events count is not a finite number.
pub fn decode(value: &str) -> Option<SiteBaseline> {
    let mut parts = value.split(':');
    let events10m = js_string_to_number(parts.next().unwrap_or_default());
    if !events10m.is_finite() {
        return None;
    }
    Some(SiteBaseline { events10m, eligible: parts.next() == Some("1") })
}

/// `Number(value)` for a JSON value as ClickHouse returned it, after Node's
/// `processResults` (which only ever turns an exact numeric string into the same
/// number `Number` would).
fn json_number(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(number)) => number.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(text)) => js_string_to_number(text),
        Some(Value::Bool(flag)) => f64::from(u8::from(*flag)),
        Some(Value::Null) => 0.0,
        _ => f64::NAN,
    }
}

/// A site id key, when `Number(key)` names an integral site id.
fn site_id_from_number(number: f64) -> Option<i32> {
    (number.fract() == 0.0 && number >= f64::from(i32::MIN) && number <= f64::from(i32::MAX)).then_some(number as i32)
}

/// `computeSiteBaselines`.
pub async fn compute_site_baselines(clickhouse: &ClickHouse) -> anyhow::Result<HashMap<i32, SiteBaseline>> {
    let rows: Vec<Map<String, Value>> = clickhouse
        .query(
            BASELINE_QUERY,
            &[
                ("buckets", TEN_MINUTES_PER_WEEK.to_string()),
                ("median", (TEN_MINUTES_PER_WEEK / 2).to_string()),
                ("minAgeHours", MIN_SITE_AGE_HOURS.to_string()),
            ],
        )
        .await?;

    let mut next = HashMap::with_capacity(rows.len());
    for row in rows {
        let Some(site_id) = site_id_from_number(json_number(row.get("site_id"))) else {
            tracing::warn!(service = "site-baseline", row = ?row, "Site baseline row without a usable site id");
            continue;
        };
        let eligible =
            matches!(row.get("eligible"), Some(Value::Bool(true))) || json_number(row.get("eligible")) == 1.0;
        next.insert(site_id, SiteBaseline { events10m: json_number(row.get("baseline_10m")), eligible });
    }
    Ok(next)
}

async fn with_timeout<T>(future: impl Future<Output = redis::RedisResult<T>>) -> anyhow::Result<T> {
    Ok(tokio::time::timeout(REDIS_COMMAND_TIMEOUT, future)
        .await
        .map_err(|_| anyhow::anyhow!("Redis command timed out after {REDIS_COMMAND_TIMEOUT:?}"))??)
}

/// `refreshFromClickhouse`: run the query if this process wins the refresh lock
/// (or Redis is down, in which case there is no sharing anyway), replace the
/// local map and publish the result to the shared hash.
pub async fn refresh_from_clickhouse(baselines: &SiteBaselines, redis: &ConnectionManager, clickhouse: &ClickHouse) {
    let mut connection = redis.clone();
    let mut lock = redis::cmd("SET");
    lock.arg(&baselines.keys.lock).arg(PROCESS_ID.to_string()).arg("PX").arg(REFRESH_LOCK_TTL_MS).arg("NX");
    match with_timeout(lock.query_async::<Option<String>>(&mut connection)).await {
        Ok(Some(reply)) if reply == "OK" => {}
        Ok(_) => {
            tracing::debug!(service = "site-baseline", "Site baseline refresh lock held elsewhere; mirroring instead");
            return;
        }
        Err(error) => {
            tracing::warn!(service = "site-baseline", error = %error, "Site baseline refresh lock unavailable; refreshing locally");
        }
    }

    let result: anyhow::Result<usize> = async {
        let next = compute_site_baselines(clickhouse).await?;
        let sites = next.len();
        let flat: Vec<String> =
            next.iter().flat_map(|(site_id, baseline)| [site_id.to_string(), encode(*baseline)]).collect();
        baselines.replace(next);

        if sites > 0 {
            let mut pipeline = redis::pipe();
            pipeline
                .atomic()
                .cmd("DEL")
                .arg(&baselines.keys.hash)
                .ignore()
                .cmd("HSET")
                .arg(&baselines.keys.hash)
                .arg(&flat)
                .ignore()
                .cmd("PEXPIRE")
                .arg(&baselines.keys.hash)
                .arg(REDIS_HASH_TTL_MS)
                .ignore();
            with_timeout(pipeline.query_async::<()>(&mut connection)).await?;
        }
        Ok(sites)
    }
    .await;

    match result {
        Ok(sites) => tracing::info!(service = "site-baseline", sites, "Site baselines refreshed"),
        Err(error) => tracing::error!(service = "site-baseline", error = %error, "Site baseline refresh failed"),
    }
}

/// `mirrorFromRedis`: adopt the shared hash. An empty or missing hash keeps
/// what this process already has.
pub async fn mirror_from_redis(baselines: &SiteBaselines, redis: &ConnectionManager) {
    let mut connection = redis.clone();
    let mut entries = redis::cmd("HGETALL");
    entries.arg(&baselines.keys.hash);
    match with_timeout(entries.query_async::<HashMap<String, String>>(&mut connection)).await {
        Ok(entries) if entries.is_empty() => {
            tracing::debug!(service = "site-baseline", "No shared site baselines to mirror yet");
        }
        Ok(entries) => {
            let next: HashMap<i32, SiteBaseline> = entries
                .iter()
                .filter_map(|(key, value)| Some((site_id_from_number(js_string_to_number(key))?, decode(value)?)))
                .collect();
            tracing::debug!(service = "site-baseline", sites = next.len(), "Site baselines mirrored from Redis");
            baselines.replace(next);
        }
        Err(error) => {
            tracing::warn!(service = "site-baseline", error = %error, "Site baseline mirror from Redis failed");
        }
    }
}

/// The running refresh loop (`startSiteBaselineRefresh`'s timers).
pub struct SiteBaselineRefresh {
    handles: Vec<JoinHandle<()>>,
}

impl SiteBaselineRefresh {
    /// `stopSiteBaselineRefresh`.
    pub fn stop(self) {
        for handle in self.handles {
            handle.abort();
        }
    }
}

/// `startSiteBaselineRefresh`: spawn the refresh loop. Safe to run in every
/// process of either backend: the ClickHouse query is elected through Redis and
/// the rest pick up its result on the mirror interval. The first mirror runs
/// immediately so a restarted process is not blind until the next refresh.
/// Returns None if this `SiteBaselines` already has a loop running.
pub fn spawn_site_baseline_refresh(
    baselines: Arc<SiteBaselines>,
    redis: ConnectionManager,
    clickhouse: ClickHouse,
) -> Option<SiteBaselineRefresh> {
    if baselines.started.swap(true, Ordering::SeqCst) {
        return None;
    }
    tracing::info!(service = "site-baseline", "Starting site baseline refresh");

    let initial = {
        let (baselines, redis, clickhouse) = (baselines.clone(), redis.clone(), clickhouse.clone());
        tokio::spawn(async move {
            mirror_from_redis(&baselines, &redis).await;
            refresh_from_clickhouse(&baselines, &redis, &clickhouse).await;
        })
    };

    // setInterval fires first after one period, not immediately.
    let refresh = {
        let (baselines, redis, clickhouse) = (baselines.clone(), redis.clone(), clickhouse);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + SITE_BASELINE_REFRESH, SITE_BASELINE_REFRESH);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                refresh_from_clickhouse(&baselines, &redis, &clickhouse).await;
            }
        })
    };

    let mirror = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + SITE_BASELINE_MIRROR, SITE_BASELINE_MIRROR);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            mirror_from_redis(&baselines, &redis).await;
        }
    });

    Some(SiteBaselineRefresh { handles: vec![initial, refresh, mirror] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bot::anomaly_observe::tests::{delete_matching, parity_redis};

    #[test]
    fn encodes_and_decodes_the_shared_hash_format() {
        assert_eq!(encode(SiteBaseline { events10m: 12.0, eligible: true }), "12:1");
        assert_eq!(encode(SiteBaseline { events10m: 1.5, eligible: false }), "1.5:0");
        assert_eq!(decode("12:1"), Some(SiteBaseline { events10m: 12.0, eligible: true }));
        assert_eq!(decode("0:0"), Some(SiteBaseline { events10m: 0.0, eligible: false }));
        assert_eq!(decode("7"), Some(SiteBaseline { events10m: 7.0, eligible: false }));
        assert_eq!(decode(":1"), Some(SiteBaseline { events10m: 0.0, eligible: true }));
        assert_eq!(decode("abc:1"), None);
        assert_eq!(decode("Infinity:1"), None);
    }

    #[test]
    fn reads_clickhouse_values_like_number() {
        assert_eq!(json_number(Some(&Value::String("12".into()))), 12.0);
        assert_eq!(json_number(Some(&serde_json::json!(3))), 3.0);
        assert_eq!(json_number(Some(&Value::Bool(true))), 1.0);
        assert_eq!(site_id_from_number(js_string_to_number(" 42 ")), Some(42));
        assert_eq!(site_id_from_number(js_string_to_number("4.5")), None);
        assert_eq!(site_id_from_number(js_string_to_number("x")), None);
    }

    #[tokio::test]
    async fn mirrors_the_shared_hash_and_keeps_state_when_it_is_empty() {
        let Some(redis) = parity_redis().await else { return };
        let hash = "bot:test:65002:sb";
        let baselines = SiteBaselines::with_keys(hash, "bot:test:65002:sb:lock");
        delete_matching(&redis, hash).await;

        baselines.set(65002, Some(SiteBaseline { events10m: 3.0, eligible: true }));
        mirror_from_redis(&baselines, &redis).await;
        assert_eq!(baselines.get(65002), Some(SiteBaseline { events10m: 3.0, eligible: true }));

        let mut connection = redis.clone();
        let _: () = redis::cmd("HSET")
            .arg(hash)
            .arg(&["65003", "9:1", "65004", "0:0", "junk", "1:1", "65005", "x:1"])
            .query_async(&mut connection)
            .await
            .unwrap();
        mirror_from_redis(&baselines, &redis).await;
        assert_eq!(baselines.get(65002), None);
        assert_eq!(baselines.get(65003), Some(SiteBaseline { events10m: 9.0, eligible: true }));
        assert_eq!(baselines.get(65004), Some(SiteBaseline { events10m: 0.0, eligible: false }));
        assert_eq!(baselines.len(), 2);

        delete_matching(&redis, hash).await;
    }

    #[tokio::test]
    async fn refreshes_through_the_lock_and_another_process_mirrors_the_result() {
        let Some(redis) = parity_redis().await else { return };
        let clickhouse = ClickHouse::new("http://127.0.0.1:58123", "analytics", "default", "hygo").unwrap();
        if clickhouse.ping().await.is_err() {
            eprintln!("parity ClickHouse unreachable; skipping");
            return;
        }
        let (hash, lock) = ("bot:test:65030:sb", "bot:test:65030:sb:lock");
        delete_matching(&redis, "bot:test:65030:*").await;

        let expected = compute_site_baselines(&clickhouse).await.unwrap();

        // A lock held elsewhere means this process leaves the query to its holder.
        let mut connection = redis.clone();
        let _: () =
            redis::cmd("SET").arg(lock).arg("other").arg("PX").arg(60_000).query_async(&mut connection).await.unwrap();
        let loser = SiteBaselines::with_keys(hash, lock);
        refresh_from_clickhouse(&loser, &redis, &clickhouse).await;
        assert_eq!(loser.len(), 0);
        let _: () = redis::cmd("DEL").arg(lock).query_async(&mut connection).await.unwrap();

        let winner = SiteBaselines::with_keys(hash, lock);
        refresh_from_clickhouse(&winner, &redis, &clickhouse).await;
        assert_eq!(winner.len(), expected.len());
        let holder: Option<String> = redis::cmd("GET").arg(lock).query_async(&mut connection).await.unwrap();
        assert_eq!(holder, Some(PROCESS_ID.to_string()));

        if !expected.is_empty() {
            let ttl: i64 = redis::cmd("PTTL").arg(hash).query_async(&mut connection).await.unwrap();
            assert!(ttl > 0 && ttl <= REDIS_HASH_TTL_MS);
            let mirror = SiteBaselines::with_keys(hash, lock);
            mirror_from_redis(&mirror, &redis).await;
            for (site_id, baseline) in &expected {
                assert_eq!(mirror.get(*site_id), Some(*baseline), "site {site_id}");
            }
        }

        delete_matching(&redis, "bot:test:65030:*").await;
    }
}
