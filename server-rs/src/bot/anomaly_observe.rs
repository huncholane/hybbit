//! The `anomalyObserve` Redis script and its wrapper, ported from
//! server/src/db/redis/redis.ts.
//!
//! Every counter a request touches rides one Lua call, so anomaly scoring costs
//! a single round-trip, and the state lives in Redis so every worker and both
//! backends share one view. The script source in `anomaly_observe.lua` is the
//! byte-identical body of Node's `defineCommand` template literal, extracted by
//! `parity/bot/generate_sources.mts` (the test pins its SHA-1, which matches the
//! one ioredis loads), so both processes load the same script and the keys, members,
//! windows and caps they pass are laid out identically: KEYS are the counter
//! keys, ARGV is `[nowMs, then (kind, member, windowMs, maxSize) per key]`, and
//! every key yields three integers.
//!
//! Counter kinds:
//! - rolling (`z`): sorted set over a sliding window, exact cardinality;
//! - distribution (`h`): hash of value to count, reports total, top and distinct;
//! - counter (`c`): plain INCR inside a caller-encoded bucket;
//! - cardinality (`p`): HyperLogLog distinct count inside a caller-encoded bucket.

use std::{sync::LazyLock, time::Duration};

use redis::aio::ConnectionManager;

/// The script body, verbatim from redis.ts.
pub const ANOMALY_OBSERVE_LUA: &str = include_str!("anomaly_observe.lua");

/// SHA-1 of the script as ioredis loads it; EVALSHA hits the same cached script
/// whichever backend loaded it first.
pub const ANOMALY_OBSERVE_SHA1: &str = "5bfe5c89ec9bff09f742c4dd01e585175459faa5";

static SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| redis::Script::new(ANOMALY_OBSERVE_LUA));

/// ioredis `commandTimeout` on Node's clients: fail fast so callers fall back
/// instead of hanging through an outage.
pub const REDIS_COMMAND_TIMEOUT: Duration = Duration::from_millis(1000);

/// `AnomalyCounterSpec["kind"]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnomalyCounterKind {
    Rolling,
    Distribution,
    Counter,
    Cardinality,
}

impl AnomalyCounterKind {
    /// `ANOMALY_KIND_CODES`: the wire codes the script dispatches on.
    pub const fn code(self) -> &'static str {
        match self {
            AnomalyCounterKind::Rolling => "z",
            AnomalyCounterKind::Distribution => "h",
            AnomalyCounterKind::Counter => "c",
            AnomalyCounterKind::Cardinality => "p",
        }
    }
}

/// `AnomalyCounterSpec`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnomalyCounterSpec {
    /// Fully namespaced Redis key.
    pub key: String,
    pub kind: AnomalyCounterKind,
    /// Unique per-event token (rate counters) or the observed value.
    pub member: String,
    /// Rolling window for `Rolling`; key TTL for the fixed-bucket kinds.
    pub window_ms: i64,
    /// Cap on stored members or fields; 0 disables trimming.
    pub max_size: i64,
}

/// `AnomalyDistribution`: total, the largest single value's count and the
/// distinct value count. Non-distribution kinds fill only `total`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnomalyDistribution {
    pub total: i64,
    pub top: i64,
    pub distinct: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum AnomalyObserveError {
    #[error("Redis anomaly script failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Redis anomaly script timed out after {0:?}")]
    Timeout(Duration),
}

/// `anomalyObserve`: observe one event against a batch of counters and return
/// each counter's reading in `specs` order.
pub async fn anomaly_observe(
    redis: &ConnectionManager,
    now_ms: i64,
    specs: &[AnomalyCounterSpec],
) -> Result<Vec<AnomalyDistribution>, AnomalyObserveError> {
    let mut invocation = SCRIPT.prepare_invoke();
    for spec in specs {
        invocation.key(&spec.key);
    }
    invocation.arg(now_ms);
    for spec in specs {
        invocation.arg(spec.kind.code()).arg(&spec.member).arg(spec.window_ms).arg(spec.max_size);
    }

    let mut connection = redis.clone();
    let flat: Vec<i64> = tokio::time::timeout(REDIS_COMMAND_TIMEOUT, invocation.invoke_async(&mut connection))
        .await
        .map_err(|_| AnomalyObserveError::Timeout(REDIS_COMMAND_TIMEOUT))??;

    Ok((0..specs.len())
        .map(|index| AnomalyDistribution {
            total: flat.get(index * 3).copied().unwrap_or(0),
            top: flat.get(index * 3 + 1).copied().unwrap_or(0),
            distinct: flat.get(index * 3 + 2).copied().unwrap_or(0),
        })
        .collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A connection to the parity Redis, or None (and the test skips) when it is
    /// not running.
    pub(crate) async fn parity_redis() -> Option<ConnectionManager> {
        let url = std::env::var("BOT_TEST_REDIS_URL").unwrap_or_else(|_| "redis://:hygo@127.0.0.1:56379/".to_string());
        let client = redis::Client::open(url).ok()?;
        match tokio::time::timeout(Duration::from_secs(2), ConnectionManager::new(client)).await {
            Ok(Ok(manager)) => Some(manager),
            _ => {
                eprintln!("parity Redis unreachable; skipping");
                None
            }
        }
    }

    pub(crate) async fn delete_matching(redis: &ConnectionManager, pattern: &str) {
        let mut connection = redis.clone();
        let keys: Vec<String> = redis::cmd("KEYS").arg(pattern).query_async(&mut connection).await.unwrap_or_default();
        if !keys.is_empty() {
            let _: Result<(), _> = redis::cmd("DEL").arg(&keys).query_async(&mut connection).await;
        }
    }

    #[test]
    fn script_is_byte_identical_to_node() {
        assert_eq!(SCRIPT.get_hash(), ANOMALY_OBSERVE_SHA1);
        assert!(ANOMALY_OBSERVE_LUA.starts_with("\n    local now = tonumber(ARGV[1])"));
    }

    #[tokio::test]
    async fn observes_every_counter_kind_in_one_call() {
        let Some(redis) = parity_redis().await else { return };
        let prefix = "bot:test:65001:observe";
        delete_matching(&redis, &format!("{prefix}:*")).await;

        let specs = |token: &str, version: &str| {
            vec![
                AnomalyCounterSpec {
                    key: format!("{prefix}:z"),
                    kind: AnomalyCounterKind::Rolling,
                    member: token.to_string(),
                    window_ms: 10_000,
                    max_size: 512,
                },
                AnomalyCounterSpec {
                    key: format!("{prefix}:h"),
                    kind: AnomalyCounterKind::Distribution,
                    member: version.to_string(),
                    window_ms: 60_000,
                    max_size: 2,
                },
                AnomalyCounterSpec {
                    key: format!("{prefix}:c"),
                    kind: AnomalyCounterKind::Counter,
                    member: String::new(),
                    window_ms: 60_000,
                    max_size: 0,
                },
                AnomalyCounterSpec {
                    key: format!("{prefix}:p"),
                    kind: AnomalyCounterKind::Cardinality,
                    member: version.to_string(),
                    window_ms: 60_000,
                    max_size: 0,
                },
            ]
        };

        let now = 1_000_000;
        anomaly_observe(&redis, now, &specs("a", "120")).await.unwrap();
        anomaly_observe(&redis, now + 1, &specs("b", "120")).await.unwrap();
        anomaly_observe(&redis, now + 2, &specs("c", "121")).await.unwrap();
        // A third distinct version is refused by the field cap but still counted
        // in nothing: the hash admits no new field at capacity.
        let last = anomaly_observe(&redis, now + 20_000, &specs("d", "122")).await.unwrap();

        // The rolling window dropped a, b, c (older than now + 10s).
        assert_eq!(last[0], AnomalyDistribution { total: 1, top: 0, distinct: 0 });
        assert_eq!(last[1], AnomalyDistribution { total: 3, top: 2, distinct: 2 });
        assert_eq!(last[2], AnomalyDistribution { total: 4, top: 0, distinct: 0 });
        assert_eq!(last[3], AnomalyDistribution { total: 3, top: 0, distinct: 0 });

        delete_matching(&redis, &format!("{prefix}:*")).await;
    }
}
