//! Feature flag definitions, ported from server/src/services/featureFlags/definitions.ts.
//!
//! A Site's flags are cached in Redis under `feature-flags:definitions:<siteId>` for
//! five minutes, shared with the Node backend. The value is `JSON.stringify` of the
//! drizzle rows, so this module writes the exact bytes Node writes: camelCase keys in
//! schema order, jsonb columns as postgres-js and drizzle hand them to Node (parsed,
//! and a JSON string holding JSON parsed a second time), timestamps as Postgres
//! prints them, numbers and object keys in JavaScript's spelling and order. Reading
//! accepts anything `JSON.parse` accepts and keeps JavaScript's key order.
//!
//! As in Node, concurrent loads for one Site share a single Postgres query, and a
//! load that started before an invalidation does not write its (stale) rows back.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use redis::{AsyncCommands, aio::ConnectionManager};
use serde_json::{Map, Value};
use sqlx::{PgPool, Row};
use tokio::sync::OnceCell;

use super::js::{self, JsError};
use crate::{js_json, state::AppState};

pub const CACHE_PREFIX: &str = "feature-flags:definitions";
pub const CACHE_TTL_SECONDS: u64 = 300;
/// ioredis `commandTimeout` in Node's client: Redis is an optimisation, so a slow
/// server falls back to Postgres instead of stalling the request.
const REDIS_COMMAND_TIMEOUT: Duration = Duration::from_millis(1000);

pub fn cache_key(site_id: i32) -> String {
    format!("{CACHE_PREFIX}:{site_id}")
}

/// A failed load. Cloneable because concurrent callers share one load's outcome.
#[derive(Clone, Debug, thiserror::Error)]
pub enum DefinitionsError {
    #[error("loading feature flag definitions from Postgres: {0}")]
    Database(String),
    /// A JavaScript TypeError Node would throw on the loaded value
    #[error("{0}")]
    Js(#[from] JsError),
}

/// Where definitions come from: the shared Redis cache and Postgres. A trait so the
/// cache logic can be tested with an in-memory store.
pub trait DefinitionsStore: Sync {
    fn cache_get(&self, key: &str) -> impl Future<Output = Result<Option<String>, String>> + Send;
    fn cache_set(&self, key: &str, value: &str, ttl_seconds: u64) -> impl Future<Output = Result<(), String>> + Send;
    fn cache_del(&self, key: &str) -> impl Future<Output = Result<(), String>> + Send;
    /// The Site's rows as drizzle returns them, ordered by key.
    fn load_rows(&self, site_id: i32) -> impl Future<Output = Result<Vec<Value>, String>> + Send;
}

/// `db.query.featureFlags.findMany({ where: siteId, orderBy: asc(key) })`, with jsonb
/// and timestamps read as text so their JavaScript form can be rebuilt exactly.
const SELECT_DEFINITIONS: &str = r#"SELECT flag_id, site_id, key, description, enabled, runtime, flag_type,
    payload::text AS payload, variants::text AS variants, rollout_percentage, rules::text AS rules,
    condition_sets::text AS condition_sets, salt, version, created_at::text AS created_at,
    updated_at::text AS updated_at
    FROM feature_flags WHERE site_id = $1 ORDER BY key ASC"#;

/// The real stores: a Redis connection and the Postgres pool.
pub struct Stores<'a> {
    pub pg: &'a PgPool,
    pub redis: &'a ConnectionManager,
}

impl DefinitionsStore for Stores<'_> {
    async fn cache_get(&self, key: &str) -> Result<Option<String>, String> {
        let mut redis = self.redis.clone();
        match tokio::time::timeout(REDIS_COMMAND_TIMEOUT, redis.get::<_, Option<String>>(key)).await {
            Ok(result) => result.map_err(|error| error.to_string()),
            Err(_) => Err("Redis command timed out".to_string()),
        }
    }

    async fn cache_set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), String> {
        let mut redis = self.redis.clone();
        match tokio::time::timeout(REDIS_COMMAND_TIMEOUT, redis.set_ex::<_, _, ()>(key, value, ttl_seconds)).await {
            Ok(result) => result.map_err(|error| error.to_string()),
            Err(_) => Err("Redis command timed out".to_string()),
        }
    }

    async fn cache_del(&self, key: &str) -> Result<(), String> {
        let mut redis = self.redis.clone();
        match tokio::time::timeout(REDIS_COMMAND_TIMEOUT, redis.del::<_, ()>(key)).await {
            Ok(result) => result.map_err(|error| error.to_string()),
            Err(_) => Err("Redis command timed out".to_string()),
        }
    }

    async fn load_rows(&self, site_id: i32) -> Result<Vec<Value>, String> {
        let rows = sqlx::query(SELECT_DEFINITIONS)
            .bind(site_id)
            .fetch_all(self.pg)
            .await
            .map_err(|error| error.to_string())?;
        rows.iter().map(row_json).collect()
    }
}

fn stores(state: &AppState) -> Stores<'_> {
    Stores { pg: &state.pg, redis: &state.redis }
}

/// One drizzle row as the JavaScript object Node caches.
fn row_json(row: &sqlx::postgres::PgRow) -> Result<Value, String> {
    let column = |name: &str| -> Result<Value, String> {
        let text: Option<String> = row.try_get(name).map_err(|error| error.to_string())?;
        match text {
            None => Ok(Value::Null),
            Some(text) => js::parse_json(&text).map(js::drizzle_jsonb).map_err(|error| {
                format!("feature_flags.{name} is jsonb JavaScript can read but serde_json cannot: {error}")
            }),
        }
    };
    let text = |name: &str| -> Result<Value, String> {
        let value: Option<String> = row.try_get(name).map_err(|error| error.to_string())?;
        Ok(value.map_or(Value::Null, Value::String))
    };
    let integer = |name: &str| -> Result<Value, String> {
        let value: i32 = row.try_get(name).map_err(|error| error.to_string())?;
        Ok(Value::from(value))
    };
    let enabled: bool = row.try_get("enabled").map_err(|error| error.to_string())?;

    let mut map = Map::new();
    map.insert("flagId".into(), integer("flag_id")?);
    map.insert("siteId".into(), integer("site_id")?);
    map.insert("key".into(), text("key")?);
    map.insert("description".into(), text("description")?);
    map.insert("enabled".into(), Value::Bool(enabled));
    map.insert("runtime".into(), text("runtime")?);
    map.insert("flagType".into(), text("flag_type")?);
    map.insert("payload".into(), column("payload")?);
    map.insert("variants".into(), column("variants")?);
    map.insert("rolloutPercentage".into(), integer("rollout_percentage")?);
    map.insert("rules".into(), column("rules")?);
    map.insert("conditionSets".into(), column("condition_sets")?);
    map.insert("salt".into(), text("salt")?);
    map.insert("version".into(), integer("version")?);
    map.insert("createdAt".into(), text("created_at")?);
    map.insert("updatedAt".into(), text("updated_at")?);
    Ok(Value::Object(map))
}

type LoadResult = Result<Arc<Value>, DefinitionsError>;

/// `inFlightLoads` and `cacheGenerations`, Node's module-level state.
#[derive(Default)]
pub struct DefinitionsCache {
    in_flight: Mutex<HashMap<i32, Arc<OnceCell<LoadResult>>>>,
    generations: Mutex<HashMap<i32, u64>>,
}

impl DefinitionsCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn generation(&self, site_id: i32) -> u64 {
        let generations = self.generations.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        generations.get(&site_id).copied().unwrap_or(0)
    }

    /// `getFeatureFlagDefinitions`: the Site's definitions as the JavaScript value
    /// Node would hold (an array unless someone wrote something else to the cache).
    pub async fn get<S: DefinitionsStore>(&self, store: &S, site_id: i32) -> LoadResult {
        let cell = {
            let mut in_flight = self.in_flight.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            in_flight.entry(site_id).or_insert_with(|| Arc::new(OnceCell::new())).clone()
        };
        let result = cell.get_or_init(|| self.load(store, site_id)).await.clone();

        // `.finally`: forget the load unless an invalidation already replaced it
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if in_flight.get(&site_id).is_some_and(|current| Arc::ptr_eq(current, &cell)) {
            in_flight.remove(&site_id);
        }
        result
    }

    /// `getFeatureFlagDefinitionsForRuntime`: the flags that run in `runtime` ("client"
    /// or "server"), including those marked "both".
    pub async fn get_for_runtime<S: DefinitionsStore>(
        &self,
        store: &S,
        site_id: i32,
        runtime: &str,
    ) -> Result<Vec<Value>, DefinitionsError> {
        let definitions = self.get(store, site_id).await?;
        Ok(filter_for_runtime(&definitions, runtime)?)
    }

    /// `loadFeatureFlagDefinitions`.
    async fn load<S: DefinitionsStore>(&self, store: &S, site_id: i32) -> LoadResult {
        let key = cache_key(site_id);

        match store.cache_get(&key).await {
            Ok(Some(cached)) => match js::parse_json(&cached) {
                Ok(definitions) => {
                    tracing::debug!(site_id, bytes = cached.len(), "feature flag definitions served from Redis");
                    return Ok(Arc::new(definitions));
                }
                // JSON.parse throwing inside Node's try falls through to Postgres too
                Err(error) => {
                    tracing::warn!(site_id, error = %error, "unreadable feature flag definitions cache entry; loading from Postgres");
                }
            },
            Ok(None) => tracing::debug!(site_id, "feature flag definitions not cached"),
            Err(error) => {
                tracing::warn!(site_id, error = %error, "Redis unavailable for feature flag definitions; loading from Postgres");
            }
        }

        let generation = self.generation(site_id);
        let rows = store.load_rows(site_id).await.map_err(|error| {
            tracing::error!(site_id, error = %error, "loading feature flag definitions from Postgres failed");
            DefinitionsError::Database(error)
        })?;
        let definitions = Value::Array(rows);

        if self.generation(site_id) == generation {
            let serialized = js_json::stringify(&definitions);
            match store.cache_set(&key, &serialized, CACHE_TTL_SECONDS).await {
                Ok(()) => tracing::debug!(site_id, bytes = serialized.len(), "feature flag definitions cached"),
                Err(error) => {
                    tracing::warn!(site_id, error = %error, "caching feature flag definitions failed; serving the Postgres rows");
                }
            }
        } else {
            tracing::debug!(site_id, "feature flag definitions changed while loading; not caching the stale rows");
        }
        Ok(Arc::new(definitions))
    }

    /// `invalidateFeatureFlagDefinitions`.
    pub async fn invalidate<S: DefinitionsStore>(&self, store: &S, site_id: i32) {
        {
            let mut generations = self.generations.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *generations.entry(site_id).or_insert(0) += 1;
        }
        self.in_flight.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&site_id);

        if let Err(error) = store.cache_del(&cache_key(site_id)).await {
            // Postgres stays the source of truth and the entry expires on its own
            tracing::warn!(site_id, error = %error, "deleting the feature flag definitions cache entry failed");
        } else {
            tracing::info!(site_id, "feature flag definitions cache invalidated");
        }
    }
}

/// The process-wide instance, like Node's module state.
static DEFINITIONS: LazyLock<DefinitionsCache> = LazyLock::new(DefinitionsCache::new);

/// `definitions.filter(definition => definition.runtime === "both" || definition.runtime === runtime)`.
pub fn filter_for_runtime(definitions: &Value, runtime: &str) -> Result<Vec<Value>, JsError> {
    let Value::Array(definitions) = definitions else {
        return Err(JsError("TypeError: (intermediate value).filter is not a function".to_string()));
    };
    let mut matching = Vec::new();
    for definition in definitions {
        let flag_runtime = js::get(Some(definition), "runtime")?.and_then(Value::as_str);
        if flag_runtime == Some("both") || flag_runtime == Some(runtime) {
            matching.push(definition.clone());
        }
    }
    Ok(matching)
}

/// `getFeatureFlagDefinitions` on the shared state.
pub async fn get_feature_flag_definitions(state: &AppState, site_id: i32) -> Result<Arc<Value>, DefinitionsError> {
    DEFINITIONS.get(&stores(state), site_id).await
}

/// `getFeatureFlagDefinitionsForRuntime` on the shared state.
pub async fn get_feature_flag_definitions_for_runtime(
    state: &AppState,
    site_id: i32,
    runtime: &str,
) -> Result<Vec<Value>, DefinitionsError> {
    DEFINITIONS.get_for_runtime(&stores(state), site_id, runtime).await
}

/// `hasFeatureFlagsForRuntime`: whether any flag of the Site runs in `runtime`.
pub async fn has_feature_flags_for_runtime(state: &AppState, site_id: i32, runtime: &str) -> anyhow::Result<bool> {
    Ok(!get_feature_flag_definitions_for_runtime(state, site_id, runtime).await?.is_empty())
}

/// `invalidateFeatureFlagDefinitions`: call after creating, updating or deleting a flag.
pub async fn invalidate_feature_flag_definitions(state: &AppState, site_id: i32) {
    DEFINITIONS.invalidate(&stores(state), site_id).await;
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/featureFlags/definitions.test.ts, with an
    //! in-memory store in place of the mocked Redis and drizzle clients.

    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct MockStore {
        cached: Mutex<Option<Result<Option<String>, String>>>,
        set_fails: bool,
        rows: Mutex<Vec<Value>>,
        find_many_calls: AtomicUsize,
        sets: Mutex<Vec<(String, String, u64)>>,
        dels: Mutex<Vec<String>>,
        load_delay: Option<Duration>,
    }

    impl DefinitionsStore for MockStore {
        async fn cache_get(&self, _key: &str) -> Result<Option<String>, String> {
            self.cached.lock().unwrap().clone().unwrap_or(Ok(None))
        }

        async fn cache_set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), String> {
            self.sets.lock().unwrap().push((key.to_string(), value.to_string(), ttl_seconds));
            if self.set_fails { Err("redis unavailable".to_string()) } else { Ok(()) }
        }

        async fn cache_del(&self, key: &str) -> Result<(), String> {
            self.dels.lock().unwrap().push(key.to_string());
            Ok(())
        }

        async fn load_rows(&self, _site_id: i32) -> Result<Vec<Value>, String> {
            self.find_many_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(delay) = self.load_delay {
                tokio::time::sleep(delay).await;
            }
            Ok(self.rows.lock().unwrap().clone())
        }
    }

    #[tokio::test]
    async fn caches_empty_results_so_flagless_sites_do_not_repeatedly_query_postgres() {
        let store = MockStore::default();
        let cache = DefinitionsCache::new();
        assert_eq!(*cache.get(&store, 123).await.unwrap(), json!([]));
        assert_eq!(store.find_many_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            store.sets.lock().unwrap().as_slice(),
            [("feature-flags:definitions:123".to_string(), "[]".to_string(), 300)]
        );
    }

    #[tokio::test]
    async fn returns_definitions_from_the_shared_cache_without_querying_postgres() {
        let definitions = json!([{ "flagId": 1, "siteId": 123, "key": "checkout" }]);
        let store = MockStore { cached: Mutex::new(Some(Ok(Some(definitions.to_string())))), ..Default::default() };
        let cache = DefinitionsCache::new();
        assert_eq!(*cache.get(&store, 123).await.unwrap(), definitions);
        assert_eq!(store.find_many_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn does_not_enable_browser_evaluation_for_server_only_flags() {
        let store = MockStore {
            cached: Mutex::new(Some(Ok(Some(
                json!([
                    { "flagId": 1, "siteId": 123, "key": "server_key", "runtime": "server" },
                    { "flagId": 2, "siteId": 123, "key": "shared_key", "runtime": "both" },
                ])
                .to_string(),
            )))),
            ..Default::default()
        };
        let cache = DefinitionsCache::new();
        let definitions = cache.get(&store, 123).await.unwrap();
        assert_eq!(
            filter_for_runtime(&definitions, "client").unwrap(),
            vec![json!({ "flagId": 2, "siteId": 123, "key": "shared_key", "runtime": "both" })]
        );
    }

    #[tokio::test]
    async fn falls_back_to_postgres_when_redis_is_unavailable() {
        let definitions = vec![json!({ "flagId": 1, "siteId": 456, "key": "checkout" })];
        let store = MockStore {
            cached: Mutex::new(Some(Err("redis unavailable".to_string()))),
            set_fails: true,
            rows: Mutex::new(definitions.clone()),
            ..Default::default()
        };
        let cache = DefinitionsCache::new();
        assert_eq!(*cache.get(&store, 456).await.unwrap(), Value::Array(definitions));
    }

    #[tokio::test]
    async fn invalidates_the_shared_cache_after_a_mutation() {
        let store = MockStore::default();
        let cache = DefinitionsCache::new();
        cache.invalidate(&store, 123).await;
        assert_eq!(store.dels.lock().unwrap().as_slice(), ["feature-flags:definitions:123".to_string()]);
    }

    #[tokio::test]
    async fn concurrent_loads_share_one_query() {
        let store = MockStore { load_delay: Some(Duration::from_millis(50)), ..Default::default() };
        let cache = DefinitionsCache::new();
        let (first, second) = tokio::join!(cache.get(&store, 7), cache.get(&store, 7));
        assert!(first.is_ok() && second.is_ok());
        assert_eq!(store.find_many_calls.load(Ordering::SeqCst), 1);
        // The finished load is forgotten, so the next call reads again
        cache.get(&store, 7).await.unwrap();
        assert_eq!(store.find_many_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_load_overtaken_by_an_invalidation_does_not_cache_stale_rows() {
        let store = MockStore { load_delay: Some(Duration::from_millis(50)), ..Default::default() };
        let cache = DefinitionsCache::new();
        let (loaded, ()) = tokio::join!(cache.get(&store, 9), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cache.invalidate(&store, 9).await;
        });
        assert!(loaded.is_ok());
        assert!(store.sets.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unparseable_cache_entries_fall_back_to_postgres() {
        let store = MockStore { cached: Mutex::new(Some(Ok(Some("{not json".to_string())))), ..Default::default() };
        let cache = DefinitionsCache::new();
        assert_eq!(*cache.get(&store, 11).await.unwrap(), json!([]));
        assert_eq!(store.find_many_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn filtering_non_arrays_and_null_rows_throws_like_node() {
        assert!(filter_for_runtime(&json!({}), "client").is_err());
        assert_eq!(
            filter_for_runtime(&json!([null]), "client").unwrap_err().0,
            "TypeError: Cannot read properties of null (reading 'runtime')"
        );
        assert!(filter_for_runtime(&json!([1, "x"]), "client").unwrap().is_empty());
    }
}
