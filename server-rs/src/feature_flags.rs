//! Feature flag definitions, ported in part from
//! server/src/services/featureFlags/definitions.ts.

use anyhow::Result;
use redis::AsyncCommands;
use serde::Deserialize;

use crate::state::AppState;

const CACHE_PREFIX: &str = "feature-flags:definitions";
const CACHE_TTL_SECONDS: u64 = 300;

#[derive(Deserialize)]
struct CachedDefinition {
    runtime: Option<String>,
}

fn cache_key(site_id: i32) -> String {
    format!("{CACHE_PREFIX}:{site_id}")
}

fn applies_to(runtime: Option<&str>, wanted: &str) -> bool {
    matches!(runtime, Some("both")) || runtime == Some(wanted)
}

/// `hasFeatureFlagsForRuntime`: whether any flag of the Site runs in `runtime`
/// ("client" or "server"). Reads the definitions cache Node shares in Redis and falls
/// back to Postgres. Only an empty result is written back: `[]` is the one value
/// whose JSON is identical to what Node stores, so Node keeps reading a valid cache.
pub async fn has_feature_flags_for_runtime(state: &AppState, site_id: i32, runtime: &str) -> Result<bool> {
    let mut redis = state.redis.clone();
    let key = cache_key(site_id);

    // Redis is an optimisation; any failure falls through to Postgres
    if let Ok(Some(cached)) = redis.get::<_, Option<String>>(&key).await
        && let Ok(definitions) = serde_json::from_str::<Vec<CachedDefinition>>(&cached)
    {
        return Ok(definitions
            .iter()
            .any(|definition| applies_to(definition.runtime.as_deref(), runtime)));
    }

    let runtimes: Vec<Option<String>> = sqlx::query_scalar("SELECT runtime FROM feature_flags WHERE site_id = $1")
        .bind(site_id)
        .fetch_all(&state.pg)
        .await?;

    if runtimes.is_empty() {
        let _: Result<(), _> = redis.set_ex(&key, "[]", CACHE_TTL_SECONDS).await;
    }

    Ok(runtimes.iter().any(|value| applies_to(value.as_deref(), runtime)))
}
