//! GET /api/sites/:siteId/overview (server/src/api/analytics/getOverview.ts) and
//! GET /api/sites/:siteId/overview/time-series (getOverviewBucketed.ts).

use serde_json::{Map, Value};
use tracing::debug;

use crate::analytics::{
    js::{JsObject, JsValue},
    types::TimeBucket,
    utils::{
        analytics_query::QuerySpec,
        effective_user_id::effective_user_id,
        session_filters::build_filtered_sessions_cte,
        time_window::resolve_time_window_with_clock,
    },
};

use super::{Outcome, 
    BucketLookup, BuildError, HandlerError, OverviewBackend, Reply, SESSION_JOIN, integral_site_id, js_number,
    route_failure,
    site_metrics::{build_metrics_spec, build_overview_query as build_overview_metrics_query},
    time_params,
};

/// `buildOverviewQuery(params, siteId)`: the Site Metrics definition, so the PDF
/// report and weekly email report the same numbers as this dashboard.
pub fn build_overview_query(query: &JsObject, site_id: i64, now: &dyn Fn() -> f64) -> Result<String, BuildError> {
    let spec = build_metrics_spec(&time_params(query), query.get_or_undefined("filters"), site_id, now)?;
    Ok(build_overview_metrics_query(&spec))
}

/// `getOverview`: one row of headline metrics, `{ data: row }`.
pub(crate) async fn get_overview<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    const LABEL: &str = "overview";
    let site = js_number(site_id);
    let result: Result<Reply, HandlerError> = async {
        let sql = build_overview_query(query, integral_site_id(site)?, &|| backend.now_ms())?;
        let bounce_threshold = backend.bounce_threshold(site).await;
        let spec = QuerySpec::new(sql).param("siteId", site).param("bounceThreshold", bounce_threshold);
        let rows = backend.run_analytics_query(&spec).await?;
        debug!(site_id = site, rows = rows.len(), bounce_threshold, "overview fetched");
        Ok(Reply::ok(data_first_row(rows)))
    }
    .await;
    result.or_else(|failure| route_failure(LABEL, &failure))
}

/// `{ data: data[0] }`: an absent row is `undefined`, which `JSON.stringify` drops.
pub fn data_first_row(rows: Vec<super::Row>) -> Value {
    let mut body = Map::new();
    if let Some(row) = rows.into_iter().next() {
        body.insert("data".to_string(), Value::Object(row));
    }
    Value::Object(body)
}

/// `const { bucket = "hour" } = params` then the `TimeBucketToFn` lookup.
pub fn overview_bucket(query: &JsObject) -> (BucketLookup, JsValue) {
    match query.get_or_undefined("bucket") {
        JsValue::Undefined => (BucketLookup::Valid(TimeBucket::Hour), JsValue::from("hour")),
        raw => (BucketLookup::of(raw), raw.clone()),
    }
}

/// `buildOverviewBucketedQuery(params, siteId)`.
pub fn build_overview_bucketed_query(
    query: &JsObject,
    site_id: i64,
    now: &dyn Fn() -> f64,
) -> Result<String, BuildError> {
    let (bucket, raw_bucket) = overview_bucket(query);
    let window = resolve_time_window_with_clock(&time_params(query), now)?;
    let time_statement = window.where_timestamp();
    let filtered_sessions_cte =
        build_filtered_sessions_cte(query.get_or_undefined("filters"), site_id, &time_statement, "FilteredSessions")?;
    // An unknown bucket renders `undefined(...)` into both SELECTs in Node
    let bucket = bucket.require(&raw_bucket)?;
    let session_join = if filtered_sessions_cte.is_some() { SESSION_JOIN } else { "" };
    let fill_clause = window.fill(bucket);
    let cte = filtered_sessions_cte.map(|cte| format!("{cte},")).unwrap_or_default();
    let start_bucket = window.bucketed("start_time", bucket);
    let timestamp_bucket = window.bucketed("timestamp", bucket);
    let users = effective_user_id("");
    Ok(format!(
        "
WITH
{cte}
SessionsWithStats AS (
    SELECT
        session_id,
        MIN(timestamp) AS start_time,
        MAX(timestamp) AS end_time,
        countIf(type = 'pageview') AS total_pageviews_in_session
    FROM events
    {session_join}
    WHERE
        site_id = {{siteId:Int32}}
        {time_statement}
    GROUP BY session_id
)
SELECT
    session_stats.time AS time,
    session_stats.sessions,
    session_stats.pages_per_session,
    session_stats.bounce_rate * 100 AS bounce_rate,
    session_stats.session_duration,
    page_stats.pageviews,
    page_stats.users
FROM
(
    SELECT
         {start_bucket} AS time,
        COUNT() AS sessions,
        AVG(total_pageviews_in_session) AS pages_per_session,
        -- Shorter than the Site's threshold (first to last event, heartbeats included)
        sumIf(1, dateDiff('second', start_time, end_time) < {{bounceThreshold:UInt32}}) / COUNT() AS bounce_rate,
        AVG(end_time - start_time) AS session_duration
    FROM SessionsWithStats
    GROUP BY time ORDER BY time {fill_clause}
) AS session_stats
FULL JOIN
(
    SELECT
        {timestamp_bucket} AS time,
        countIf(type = 'pageview') AS pageviews,
        COUNT(DISTINCT {users}) AS users
    FROM events
    {session_join}
    WHERE
        site_id = {{siteId:Int32}}
        {time_statement}
    GROUP BY time ORDER BY time {fill_clause}
) AS page_stats
USING time
ORDER BY time"
    ))
}

/// `getOverviewBucketed`: the overview metrics per bucket, `{ data: rows }`.
pub(crate) async fn get_overview_bucketed<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    const LABEL: &str = "pageviews";
    let site = js_number(site_id);
    let result: Result<Reply, HandlerError> = async {
        let built = build_overview_bucketed_query(query, integral_site_id(site)?, &|| backend.now_ms());
        if let Err(BuildError::Rejected(reason)) = &built {
            // Node builds unrunnable SQL without throwing, so it still reads the
            // bounce threshold before ClickHouse rejects the query
            debug!(site_id = site, reason = %reason, "overview time series: bucket cannot run");
            backend.bounce_threshold(site).await;
        }
        let sql = built?;
        let bounce_threshold = backend.bounce_threshold(site).await;
        let spec = QuerySpec::new(sql).param("siteId", site).param("bounceThreshold", bounce_threshold);
        let rows = backend.run_analytics_query(&spec).await?;
        debug!(site_id = site, rows = rows.len(), bounce_threshold, "overview time series fetched");
        Ok(Reply::ok(data_rows(rows)))
    }
    .await;
    result.or_else(|failure| route_failure(LABEL, &failure))
}

/// `{ data: rows }`.
pub fn data_rows(rows: Vec<super::Row>) -> Value {
    let mut body = Map::new();
    body.insert("data".to_string(), Value::Array(rows.into_iter().map(Value::Object).collect()));
    Value::Object(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> JsObject {
        pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
    }

    fn base(overrides: &[(&str, &str)]) -> JsObject {
        let mut object = query(&[
            ("start_date", "2026-07-17"),
            ("end_date", "2026-07-23"),
            ("time_zone", "UTC"),
            ("filters", ""),
            ("bucket", "day"),
        ]);
        for (key, value) in overrides {
            object.insert(*key, JsValue::from(*value));
        }
        object
    }

    // Ported from getOverview.test.ts
    #[test]
    fn bucketed_counts_users_by_identity() {
        let sql = build_overview_bucketed_query(&base(&[]), 1, &|| 0.0).unwrap();
        assert!(sql.contains("COUNT(DISTINCT COALESCE(NULLIF(identified_user_id, ''), user_id)) AS users"));
    }

    // Ported from sessionScopedQueries.test.ts
    #[test]
    fn bucketed_stats_come_from_all_rows_of_qualifying_sessions() {
        let campaign = r#"[{"parameter":"utm_campaign","type":"equals","value":["recipe_book_2026"]}]"#;
        let sql = build_overview_bucketed_query(
            &base(&[("start_date", "2026-08-01"), ("end_date", "2026-08-31"), ("filters", campaign)]),
            1,
            &|| 0.0,
        )
        .unwrap();
        assert!(sql.contains("FilteredSessions AS ("));
        assert!(sql.contains("INNER JOIN FilteredSessions"));
        let after = &sql[sql.find("SessionsWithStats AS (").unwrap()..];
        assert!(!after.contains("url_parameters['utm_campaign']"));
    }

    #[test]
    fn unknown_buckets_cannot_run() {
        for bucket in ["", "hours", "constructor", "__proto__"] {
            assert!(matches!(
                build_overview_bucketed_query(&base(&[("bucket", bucket)]), 1, &|| 0.0),
                Err(BuildError::Rejected(_))
            ));
        }
        let mut repeated = base(&[]);
        repeated.insert("bucket", JsValue::Array(vec!["day".into(), "day".into()]));
        assert!(build_overview_bucketed_query(&repeated, 1, &|| 0.0).is_err());
        let mut absent = base(&[]);
        absent.remove("bucket");
        assert!(build_overview_bucketed_query(&absent, 1, &|| 0.0).unwrap().contains("toStartOfHour"));
    }

    #[test]
    fn empty_rows_answer_an_empty_object() {
        assert_eq!(crate::js_json::stringify(&data_first_row(Vec::new())), "{}");
    }
}
