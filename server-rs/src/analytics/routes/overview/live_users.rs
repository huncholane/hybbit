//! GET /api/sites/:siteId/live-user-count (server/src/api/analytics/getLiveUsercount.ts).
//! Registered with `logLevel: "silent"` in Node because the dashboard polls it;
//! `http::logging` skips its request log for the same reason.

use serde_json::{Map, Value};
use tracing::trace;

use crate::analytics::{
    js::{JsObject, JsValue},
    utils::{analytics_query::QuerySpec, effective_user_id::effective_user_id},
};

use super::{Outcome, BuildError, HandlerError, OverviewBackend, Reply, js_number, route_failure};

/// `buildLiveUsercountQuery()`: people, not sessions, so a visitor whose session
/// restarts inside the window counts once.
pub fn build_live_usercount_query() -> String {
    format!(
        "SELECT COUNT(DISTINCT {}) AS count FROM events WHERE timestamp > now() - interval {{minutes:Int32}} minute AND site_id = {{siteId:Int32}}",
        effective_user_id("")
    )
}

/// `Number(minutes || 5)`.
pub fn live_minutes(query: &JsObject) -> f64 {
    let minutes = query.get_or_undefined("minutes");
    if minutes.is_truthy() { minutes.to_number() } else { 5.0 }
}

/// `getLiveUsercount`: `{ count: result[0].count }`.
pub(crate) async fn get_live_user_count<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    const LABEL: &str = "live user count";
    let site = js_number(site_id);
    let minutes = live_minutes(query);
    let result: Result<Reply, HandlerError> = async {
        let spec = QuerySpec::new(build_live_usercount_query()).param("siteId", site).param("minutes", minutes);
        let rows = backend.run_analytics_query(&spec).await?;
        // `result[0].count` throws a TypeError on an empty result
        let Some(first) = rows.first() else {
            return Err(BuildError::TypeError("Cannot read properties of undefined (reading 'count')".into()).into());
        };
        let mut body = Map::new();
        if let Some(count) = first.get("count") {
            body.insert("count".to_string(), count.clone());
        }
        let count_text = first.get("count").map_or(JsValue::Undefined, JsValue::from_serde).to_js_string();
        trace!(site_id = site, minutes, count = %count_text, "live user count");
        Ok(Reply::ok(Value::Object(body)))
    }
    .await;
    result.or_else(|failure| route_failure(LABEL, &failure))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_people_in_the_window() {
        assert_eq!(
            build_live_usercount_query(),
            "SELECT COUNT(DISTINCT COALESCE(NULLIF(identified_user_id, ''), user_id)) AS count FROM events WHERE timestamp > now() - interval {minutes:Int32} minute AND site_id = {siteId:Int32}"
        );
    }

    #[test]
    fn minutes_default_to_five() {
        let query = |value: Option<&str>| -> JsObject {
            value.into_iter().map(|value| ("minutes".to_string(), JsValue::from(value))).collect()
        };
        assert_eq!(live_minutes(&query(None)), 5.0);
        assert_eq!(live_minutes(&query(Some(""))), 5.0);
        assert_eq!(live_minutes(&query(Some("30"))), 30.0);
        assert!(live_minutes(&query(Some("abc"))).is_nan());
    }
}
