//! The enumeration observer, in shadow mode. Ported from
//! server/src/services/tracker/botBlocking/enumerationObserver.ts.
//!
//! A distributed crawler walking a site's URL space leaves no per-visitor
//! evidence: it paces itself under every rate threshold and burns a fresh
//! identity per hit. What it cannot hide is the shape of what a cohort requests,
//! measured per (cohort, 15-minute bucket):
//!
//! ```text
//! path novelty      distinct paths / events    enumeration, not reading
//! events per actor  events / distinct actors   an identity per request
//! direct share      events with no referrer    arrived at, not navigated to
//! ```
//!
//! It is an aggregate statement about a cohort, so it is recorded and never
//! convicts, and a cohort must qualify in two consecutive buckets before it is
//! marked. The direct share is measured on the raw referrer, before self
//! referrers are cleared for storage. Known weaknesses (evaluation against the
//! running bucket rather than a closed one, and no way to tell a crawler from a
//! direct one-hit-per-recipient campaign) are why this is not a rule yet.
//!
//! The streak markers are the Redis keys `bot:enum:q:<cohortKey>:<bucket>`,
//! shared with Node.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use redis::aio::ConnectionManager;
use serde::Serialize;

use super::{anomaly_observe::REDIS_COMMAND_TIMEOUT, js::js_round_to_fixed};

/// `ENUMERATION_BUCKET_MS`
pub const ENUMERATION_BUCKET_MS: i64 = 15 * 60 * 1000;

/// Gates, set well outside anything organic: the crawler behind them ran at 0.96
/// novelty and 1.17 events per actor; a busy content site sits near 0.02 novelty.
const MIN_EVENTS: i64 = 300;
const MIN_PATH_NOVELTY: f64 = 0.9;
const MAX_EVENTS_PER_ACTOR: f64 = 1.25;
const MIN_DIRECT_SHARE: f64 = 0.98;

/// Bounds on the in-process fallbacks.
const MAX_LOCAL_STREAK_ENTRIES: usize = 1024;
const MAX_RESOLVED_BUCKETS: usize = 1024;

/// `EnumerationReading`: raw counter readings for one cohort's current bucket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnumerationReading {
    pub events: i64,
    pub distinct_paths: i64,
    pub distinct_actors: i64,
    pub direct_events: i64,
}

/// `evaluateEnumerationReading`'s result.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EnumerationEvaluation {
    pub qualifies: bool,
    pub path_novelty: f64,
    pub events_per_actor: f64,
    pub direct_share: f64,
    pub events: i64,
}

/// `EnumerationObservation`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnumerationObservation {
    /// This bucket meets every gate.
    pub qualifies: bool,
    /// This bucket and the one before it both qualified.
    pub sustained: bool,
    pub path_novelty: f64,
    pub events_per_actor: f64,
    pub direct_share: f64,
    pub events: i64,
}

fn ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator > 0 { numerator as f64 / denominator as f64 } else { 0.0 }
}

/// `evaluateEnumerationReading`.
pub fn evaluate_enumeration_reading(reading: EnumerationReading) -> EnumerationEvaluation {
    let path_novelty = ratio(reading.distinct_paths, reading.events);
    let events_per_actor = ratio(reading.events, reading.distinct_actors);
    let direct_share = ratio(reading.direct_events, reading.events);

    let qualifies = reading.events >= MIN_EVENTS
        && path_novelty >= MIN_PATH_NOVELTY
        // HyperLogLog is approximate, so actors can exceed events by a hair.
        && events_per_actor > 0.0
        && events_per_actor <= MAX_EVENTS_PER_ACTOR
        && direct_share >= MIN_DIRECT_SHARE;

    EnumerationEvaluation { qualifies, path_novelty, events_per_actor, direct_share, events: reading.events }
}

/// The observer's in-process state: the local streak markers (one per cohort
/// bucket, exactly as Redis holds one key per bucket) and the verdict already
/// resolved for each bucket, so a crawler's thousands of events in one bucket
/// cost one round-trip and one log line rather than thousands.
pub struct EnumerationObserver {
    redis: Option<ConnectionManager>,
    local_qualified_buckets: Mutex<HashSet<String>>,
    resolved_buckets: Mutex<HashMap<String, bool>>,
}

impl EnumerationObserver {
    pub fn new(redis: Option<ConnectionManager>) -> Self {
        Self { redis, local_qualified_buckets: Mutex::default(), resolved_buckets: Mutex::default() }
    }

    /// `resetEnumerationObserverForTests`.
    pub fn reset(&self) {
        self.local_qualified_buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
        self.resolved_buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    }

    /// `markLocally`: record this bucket and report whether the previous one was.
    fn mark_locally(&self, cohort_key: &str, bucket: i64) -> bool {
        let mut local = self.local_qualified_buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_qualified = local.contains(&format!("{cohort_key}:{}", bucket - 1));
        if local.len() >= MAX_LOCAL_STREAK_ENTRIES {
            local.clear();
        }
        local.insert(format!("{cohort_key}:{bucket}"));
        previous_qualified
    }

    /// `resolveStreak`: mark this bucket and report whether the previous one
    /// qualified, at most once per (cohort, bucket) per process. `use_local_state`
    /// follows the backend the counters used, so an outage never pays a Redis
    /// timeout per qualifying bucket.
    async fn resolve_streak(&self, cohort_key: &str, bucket: i64, use_local_state: bool) -> bool {
        let bucket_key = format!("{cohort_key}:{bucket}");
        if let Some(resolved) =
            self.resolved_buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&bucket_key)
        {
            return *resolved;
        }

        let sustained = if use_local_state {
            self.mark_locally(cohort_key, bucket)
        } else {
            match self.streak_via_redis(cohort_key, bucket).await {
                Ok(sustained) => sustained,
                Err(error) => {
                    // A streak spanning an outage is lost; shadow mode under-reports
                    // rather than inventing a finding.
                    tracing::error!(
                        service = "enumeration-observer",
                        error = %error,
                        "Enumeration streak check failed; using in-process fallback"
                    );
                    self.mark_locally(cohort_key, bucket)
                }
            }
        };

        let mut resolved = self.resolved_buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if resolved.len() >= MAX_RESOLVED_BUCKETS {
            resolved.clear();
        }
        resolved.insert(bucket_key, sustained);
        sustained
    }

    /// `MULTI; SET bot:enum:q:<cohort>:<bucket> 1 PX 45min; EXISTS <previous>; EXEC`.
    async fn streak_via_redis(&self, cohort_key: &str, bucket: i64) -> anyhow::Result<bool> {
        let redis = self.redis.as_ref().ok_or_else(|| anyhow::anyhow!("Redis is not configured"))?;
        let mut connection = redis.clone();
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .cmd("SET")
            .arg(format!("bot:enum:q:{cohort_key}:{bucket}"))
            .arg("1")
            .arg("PX")
            .arg(ENUMERATION_BUCKET_MS * 3)
            .ignore()
            .cmd("EXISTS")
            .arg(format!("bot:enum:q:{cohort_key}:{}", bucket - 1));
        let (exists,): (i64,) = tokio::time::timeout(REDIS_COMMAND_TIMEOUT, pipeline.query_async(&mut connection))
            .await
            .map_err(|_| anyhow::anyhow!("Redis command timed out after {REDIS_COMMAND_TIMEOUT:?}"))??;
        Ok(exists == 1)
    }

    /// `observeEnumeration`: evaluate one cohort bucket, consulting the streak
    /// only when the bucket qualifies. The only output of shadow mode is a log
    /// line the first time a sustained cohort is resolved.
    pub async fn observe_enumeration(
        &self,
        cohort_key: &str,
        bucket: i64,
        reading: EnumerationReading,
        use_local_state: bool,
    ) -> EnumerationObservation {
        let evaluated = evaluate_enumeration_reading(reading);
        let observation = |sustained| EnumerationObservation {
            qualifies: evaluated.qualifies,
            sustained,
            path_novelty: evaluated.path_novelty,
            events_per_actor: evaluated.events_per_actor,
            direct_share: evaluated.direct_share,
            events: evaluated.events,
        };
        if !evaluated.qualifies {
            return observation(false);
        }

        let already_resolved = self
            .resolved_buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&format!("{cohort_key}:{bucket}"));
        let sustained = self.resolve_streak(cohort_key, bucket, use_local_state).await;

        if sustained && !already_resolved {
            tracing::warn!(
                service = "enumeration-observer",
                cohort_key,
                bucket,
                events = evaluated.events,
                path_novelty = js_round_to_fixed(evaluated.path_novelty, 3),
                events_per_actor = js_round_to_fixed(evaluated.events_per_actor, 3),
                direct_share = js_round_to_fixed(evaluated.direct_share, 3),
                "Enumeration cohort sustained across two buckets (shadow mode, not enforced)"
            );
        }

        observation(sustained)
    }
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/tracker/botBlocking/enumerationObserver.test.ts.
    //! The Redis-backed cases run against the parity Redis instead of a mock.
    use super::*;
    use crate::bot::anomaly_observe::tests::{delete_matching, parity_redis};

    /// The measured shape of the crawler this rule was built from.
    const CRAWLER_READING: EnumerationReading =
        EnumerationReading { events: 400, distinct_paths: 384, distinct_actors: 342, direct_events: 400 };

    #[test]
    fn recognises_an_enumerating_cohort() {
        let result = evaluate_enumeration_reading(CRAWLER_READING);
        assert!(result.qualifies);
        assert!(result.path_novelty > 0.9);
        assert!(result.events_per_actor < 1.25);
    }

    #[test]
    fn leaves_ordinary_reading_traffic_alone() {
        let result = evaluate_enumeration_reading(EnumerationReading {
            events: 4000,
            distinct_paths: 90,
            distinct_actors: 850,
            direct_events: 3960,
        });
        assert!(!result.qualifies);
    }

    #[test]
    fn leaves_a_small_cohort_alone_even_when_its_shape_matches() {
        let result = evaluate_enumeration_reading(EnumerationReading {
            events: 12,
            distinct_paths: 12,
            distinct_actors: 12,
            direct_events: 12,
        });
        assert!(!result.qualifies);
        assert_eq!(result.path_novelty, 1.0);
    }

    #[test]
    fn leaves_a_campaign_landing_burst_alone_because_it_arrives_referred() {
        let result = evaluate_enumeration_reading(EnumerationReading {
            events: 900,
            distinct_paths: 880,
            distinct_actors: 870,
            direct_events: 40,
        });
        assert!(!result.qualifies);
        assert!(result.path_novelty > 0.9);
    }

    #[test]
    fn reports_zeros_rather_than_dividing_by_zero() {
        let result = evaluate_enumeration_reading(EnumerationReading::default());
        assert_eq!(
            (result.qualifies, result.path_novelty, result.events_per_actor, result.direct_share),
            (false, 0.0, 0.0, 0.0)
        );
    }

    #[tokio::test]
    async fn does_not_mark_a_cohort_on_its_first_qualifying_bucket() {
        let Some(redis) = parity_redis().await else { return };
        let cohort = "65010:1920x1080:en-us:chrome";
        delete_matching(&redis, &format!("bot:enum:q:{cohort}:*")).await;

        let observer = EnumerationObserver::new(Some(redis.clone()));
        let result = observer.observe_enumeration(cohort, 42, CRAWLER_READING, false).await;
        assert!(result.qualifies);
        assert!(!result.sustained);

        let mut connection = redis.clone();
        let ttl: i64 =
            redis::cmd("PTTL").arg(format!("bot:enum:q:{cohort}:42")).query_async(&mut connection).await.unwrap();
        assert!(ttl > 0 && ttl <= ENUMERATION_BUCKET_MS * 3, "marker written with a 45 minute TTL, got {ttl}");
        delete_matching(&redis, &format!("bot:enum:q:{cohort}:*")).await;
    }

    #[tokio::test]
    async fn marks_a_cohort_once_the_previous_bucket_qualified_too() {
        let Some(redis) = parity_redis().await else { return };
        let cohort = "65011:1920x1080:en-us:chrome";
        delete_matching(&redis, &format!("bot:enum:q:{cohort}:*")).await;
        let mut connection = redis.clone();
        let _: () = redis::cmd("SET")
            .arg(format!("bot:enum:q:{cohort}:42"))
            .arg("1")
            .query_async(&mut connection)
            .await
            .unwrap();

        let observer = EnumerationObserver::new(Some(redis.clone()));
        let result = observer.observe_enumeration(cohort, 43, CRAWLER_READING, false).await;
        assert!(result.qualifies);
        assert!(result.sustained);
        delete_matching(&redis, &format!("bot:enum:q:{cohort}:*")).await;
    }

    #[tokio::test]
    async fn does_not_consult_the_streak_for_a_cohort_that_did_not_qualify() {
        let Some(redis) = parity_redis().await else { return };
        let cohort = "65012:1920x1080:en-us:chrome";
        delete_matching(&redis, &format!("bot:enum:q:{cohort}:*")).await;

        let observer = EnumerationObserver::new(Some(redis.clone()));
        let result = observer
            .observe_enumeration(
                cohort,
                42,
                EnumerationReading { events: 4000, distinct_paths: 90, distinct_actors: 850, direct_events: 3960 },
                false,
            )
            .await;
        assert!(!result.qualifies);
        assert!(!result.sustained);

        let mut connection = redis.clone();
        let exists: i64 =
            redis::cmd("EXISTS").arg(format!("bot:enum:q:{cohort}:42")).query_async(&mut connection).await.unwrap();
        assert_eq!(exists, 0, "no marker written");
    }

    #[tokio::test]
    async fn falls_back_to_local_streaks_without_redis() {
        let observer = EnumerationObserver::new(None);
        let first = observer.observe_enumeration("cohort", 1, CRAWLER_READING, false).await;
        let second = observer.observe_enumeration("cohort", 2, CRAWLER_READING, false).await;
        assert!(!first.sustained);
        assert!(second.sustained);
        // Resolved once per bucket: a later event in bucket 2 reads the verdict back.
        assert!(observer.observe_enumeration("cohort", 2, CRAWLER_READING, true).await.sustained);
    }
}
