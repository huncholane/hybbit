//! Web vitals, ported from server/src/api/analytics/performance: percentiles over
//! the window (getPerformanceOverview.ts), per time bucket
//! (getPerformanceTimeSeries.ts) and per dimension value
//! (getPerformanceByDimension.ts).

use axum::{http::StatusCode, response::Response};
use serde_json::{Value, json};
use tracing::debug;

use crate::{
    analytics::{
        js::{JsObject, JsValue, number::string_to_number},
        types::TimeBucket,
        utils::{
            analytics_query::{QuerySpec, get_pagination_statements},
            session_filters::{build_session_and_row_filter_fragments, target_event_row_level_params},
            time_window::{TimeWindowParams, get_time_statement, resolve_time_window},
        },
    },
    state::AppState,
};

use super::support::{JsError, analytics_clickhouse, send_json, template};

type BuildResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn site_integer(site_id: f64) -> Result<i64, JsError> {
    (site_id.is_finite() && site_id.fract() == 0.0).then_some(site_id as i64).ok_or_else(|| JsError::new("site id is not an integer"))
}

/// The `FilteredSessions` CTE (or none) and the row-level `AND ...` filters.
fn filter_fragments(query: &JsObject, site_id: f64, time_statement: &str) -> BuildResult<(Option<String>, String)> {
    let fragments = build_session_and_row_filter_fragments(
        query.get_or_undefined("filters"),
        site_integer(site_id)?,
        time_statement,
        &target_event_row_level_params(),
        "FilteredSessions",
    )?;
    Ok((fragments.filtered_sessions_cte, fragments.row_filter_statement))
}

fn session_join(cte: &Option<String>) -> &'static str {
    if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" }
}

/// `buildPerformanceOverviewQuery(query, siteId)`.
pub fn build_performance_overview_query(query: &JsObject, site_id: f64) -> BuildResult<String> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let (cte, row_filters) = filter_fragments(query, site_id, &time_statement)?;
    Ok(template(
        r#"${with_cte}
    SELECT
      quantile(0.5)(lcp) AS lcp_p50,
      quantile(0.75)(lcp) AS lcp_p75,
      quantile(0.9)(lcp) AS lcp_p90,
      quantile(0.99)(lcp) AS lcp_p99,
      quantile(0.5)(cls) AS cls_p50,
      quantile(0.75)(cls) AS cls_p75,
      quantile(0.9)(cls) AS cls_p90,
      quantile(0.99)(cls) AS cls_p99,
      quantile(0.5)(inp) AS inp_p50,
      quantile(0.75)(inp) AS inp_p75,
      quantile(0.9)(inp) AS inp_p90,
      quantile(0.99)(inp) AS inp_p99,
      quantile(0.5)(fcp) AS fcp_p50,
      quantile(0.75)(fcp) AS fcp_p75,
      quantile(0.9)(fcp) AS fcp_p90,
      quantile(0.99)(fcp) AS fcp_p99,
      quantile(0.5)(ttfb) AS ttfb_p50,
      quantile(0.75)(ttfb) AS ttfb_p75,
      quantile(0.9)(ttfb) AS ttfb_p90,
      quantile(0.99)(ttfb) AS ttfb_p99,
      COUNT(*) AS total_performance_events
    FROM events
    ${session_join}
    WHERE
        site_id = {siteId:Int32}
        AND type = 'performance'
        ${row_filters}
        ${time_statement}"#,
        &[
            ("with_cte", &cte.as_ref().map(|cte| format!("WITH {cte}")).unwrap_or_default()),
            ("session_join", session_join(&cte)),
            ("row_filters", &row_filters),
            ("time_statement", &time_statement),
        ],
    ))
}

/// The bucket a time-series request names: `bucket = "hour"` by default, and only
/// the `TimeBucketToFn` keys produce a usable expression. Any other value (a
/// typo, a repeated parameter, an `Object.prototype` key) renders `undefined(...)`
/// or a native function's source into the SQL, which ClickHouse rejects.
pub fn requested_bucket(query: &JsObject) -> Result<TimeBucket, JsError> {
    let bucket = match query.get_or_undefined("bucket") {
        JsValue::Undefined => return Ok(TimeBucket::Hour),
        other => other.to_js_string(),
    };
    TimeBucket::parse(&bucket).ok_or_else(|| JsError::new(format!("bucket {bucket:?} renders SQL ClickHouse rejects")))
}

/// `buildPerformanceTimeSeriesQuery(params, siteId)`.
pub fn build_performance_time_series_query(query: &JsObject, site_id: f64) -> BuildResult<String> {
    let window = resolve_time_window(&TimeWindowParams::from_object(query))?;
    let time_statement = window.where_timestamp();
    let (cte, row_filters) = filter_fragments(query, site_id, &time_statement)?;
    let bucket = requested_bucket(query)?;
    Ok(template(
        r#"
${with_cte}
SELECT
    ${bucketed} AS time,
    quantile(0.5)(lcp) AS lcp_p50,
    quantile(0.75)(lcp) AS lcp_p75,
    quantile(0.9)(lcp) AS lcp_p90,
    quantile(0.99)(lcp) AS lcp_p99,
    quantile(0.5)(cls) AS cls_p50,
    quantile(0.75)(cls) AS cls_p75,
    quantile(0.9)(cls) AS cls_p90,
    quantile(0.99)(cls) AS cls_p99,
    quantile(0.5)(inp) AS inp_p50,
    quantile(0.75)(inp) AS inp_p75,
    quantile(0.9)(inp) AS inp_p90,
    quantile(0.99)(inp) AS inp_p99,
    quantile(0.5)(fcp) AS fcp_p50,
    quantile(0.75)(fcp) AS fcp_p75,
    quantile(0.9)(fcp) AS fcp_p90,
    quantile(0.99)(fcp) AS fcp_p99,
    quantile(0.5)(ttfb) AS ttfb_p50,
    quantile(0.75)(ttfb) AS ttfb_p75,
    quantile(0.9)(ttfb) AS ttfb_p90,
    quantile(0.99)(ttfb) AS ttfb_p99,
    COUNT(*) AS event_count
FROM events
${session_join}
WHERE
    site_id = {siteId:Int32}
    AND type = 'performance'
    ${row_filters}
    ${time_statement}
GROUP BY time ORDER BY time ${fill}"#,
        &[
            ("with_cte", &cte.as_ref().map(|cte| format!("WITH {cte}")).unwrap_or_default()),
            ("bucketed", &window.bucketed("timestamp", bucket)),
            ("session_join", session_join(&cte)),
            ("row_filters", &row_filters),
            ("time_statement", &time_statement),
            ("fill", &window.fill(bucket)),
        ],
    ))
}

const VALID_DIMENSIONS: [&str; 6] = ["pathname", "country", "device_type", "browser", "operating_system", "region"];

const METRIC_COLUMNS: [&str; 26] = [
    "event_count", "lcp_avg", "lcp_p50", "lcp_p75", "lcp_p90", "lcp_p99", "cls_avg", "cls_p50", "cls_p75", "cls_p90",
    "cls_p99", "inp_avg", "inp_p50", "inp_p75", "inp_p90", "inp_p99", "fcp_avg", "fcp_p50", "fcp_p75", "fcp_p90",
    "fcp_p99", "ttfb_avg", "ttfb_p50", "ttfb_p75", "ttfb_p90", "ttfb_p99",
];

/// `buildPerformanceByDimensionQuery(query, siteId, isCountQuery)`.
pub fn build_performance_by_dimension_query(query: &JsObject, site_id: f64, is_count_query: bool) -> BuildResult<String> {
    let dimension_value = query.get_or_undefined("dimension");
    let Some(dimension) = dimension_value.as_str().filter(|dimension| VALID_DIMENSIONS.contains(dimension)) else {
        return Err(JsError::new(format!("Invalid dimension: {}", dimension_value.to_js_string())).into());
    };

    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let (cte, row_filters) = filter_fragments(query, site_id, &time_statement)?;
    let pagination = get_pagination_statements(query.get_or_undefined("limit"), query.get_or_undefined("page"), 100.0, is_count_query);

    let sort_by = query.get_or_undefined("sort_by");
    let sort_by = match sort_by.as_str() {
        Some(column) if !column.is_empty() && (column == dimension || METRIC_COLUMNS.contains(&column)) => column,
        _ => "event_count",
    };
    let sort_order = if query.get_or_undefined("sort_order").as_str() == Some("asc") { "ASC" } else { "DESC" };
    let order_by = if is_count_query { String::new() } else { format!("ORDER BY {sort_by} {sort_order} NULLS LAST") };

    let base_cte = template(
        r#"
    PerformanceStats AS (
        SELECT
            ${dimension},
            COUNT(*) as event_count,
            avgIf(lcp, lcp IS NOT NULL) as lcp_avg,
            quantileIf(0.5)(lcp, lcp IS NOT NULL) as lcp_p50,
            quantileIf(0.75)(lcp, lcp IS NOT NULL) as lcp_p75,
            quantileIf(0.9)(lcp, lcp IS NOT NULL) as lcp_p90,
            quantileIf(0.99)(lcp, lcp IS NOT NULL) as lcp_p99,
            avgIf(cls, cls IS NOT NULL) as cls_avg,
            quantileIf(0.5)(cls, cls IS NOT NULL) as cls_p50,
            quantileIf(0.75)(cls, cls IS NOT NULL) as cls_p75,
            quantileIf(0.9)(cls, cls IS NOT NULL) as cls_p90,
            quantileIf(0.99)(cls, cls IS NOT NULL) as cls_p99,
            avgIf(inp, inp IS NOT NULL) as inp_avg,
            quantileIf(0.5)(inp, inp IS NOT NULL) as inp_p50,
            quantileIf(0.75)(inp, inp IS NOT NULL) as inp_p75,
            quantileIf(0.9)(inp, inp IS NOT NULL) as inp_p90,
            quantileIf(0.99)(inp, inp IS NOT NULL) as inp_p99,
            avgIf(fcp, fcp IS NOT NULL) as fcp_avg,
            quantileIf(0.5)(fcp, fcp IS NOT NULL) as fcp_p50,
            quantileIf(0.75)(fcp, fcp IS NOT NULL) as fcp_p75,
            quantileIf(0.9)(fcp, fcp IS NOT NULL) as fcp_p90,
            quantileIf(0.99)(fcp, fcp IS NOT NULL) as fcp_p99,
            avgIf(ttfb, ttfb IS NOT NULL) as ttfb_avg,
            quantileIf(0.5)(ttfb, ttfb IS NOT NULL) as ttfb_p50,
            quantileIf(0.75)(ttfb, ttfb IS NOT NULL) as ttfb_p75,
            quantileIf(0.9)(ttfb, ttfb IS NOT NULL) as ttfb_p90,
            quantileIf(0.99)(ttfb, ttfb IS NOT NULL) as ttfb_p99
        FROM events
        ${session_join}
        WHERE${space}
          site_id = {siteId:Int32}
          AND type = 'performance'
          AND ${dimension} IS NOT NULL${space}
          AND ${dimension} <> ''
          ${row_filters}
          ${time_statement}
        GROUP BY ${dimension}
    )
  "#,
        &[
            // Node's template has trailing spaces on these two lines
            ("space", " "),
            ("dimension", dimension),
            ("session_join", session_join(&cte)),
            ("row_filters", &row_filters),
            ("time_statement", &time_statement),
        ],
    );
    let cte_prefix = cte.as_ref().map(|cte| format!("{cte},")).unwrap_or_default();

    if is_count_query {
        return Ok(template(
            r#"
    WITH ${cte_prefix} ${base_cte}
    SELECT COUNT(DISTINCT ${dimension}) as totalCount FROM PerformanceStats;
    "#,
            &[("cte_prefix", &cte_prefix), ("base_cte", &base_cte), ("dimension", dimension)],
        ));
    }
    Ok(template(
        r#"
  WITH ${cte_prefix} ${base_cte}
  SELECT
      ${dimension},
      event_count,
      lcp_avg,
      lcp_p50,
      lcp_p75,
      lcp_p90,
      lcp_p99,
      cls_avg,
      cls_p50,
      cls_p75,
      cls_p90,
      cls_p99,
      inp_avg,
      inp_p50,
      inp_p75,
      inp_p90,
      inp_p99,
      fcp_avg,
      fcp_p50,
      fcp_p75,
      fcp_p90,
      fcp_p99,
      ttfb_avg,
      ttfb_p50,
      ttfb_p75,
      ttfb_p90,
      ttfb_p99
  FROM PerformanceStats
  ${order_by}
  ${limit}
  ${offset};
  "#,
        &[
            ("cte_prefix", &cte_prefix),
            ("base_cte", &base_cte),
            ("dimension", dimension),
            ("order_by", &order_by),
            ("limit", &pagination.limit_statement),
            ("offset", &pagination.offset_statement),
        ],
    ))
}

/// Runs a site-scoped analytics route: path parameters, the `publicAnalyticsRead`
/// chain, then the handler body with `analyticsRoute`'s error policy.
macro_rules! analytics_read_route {
    ($name:ident, $label:literal, $body:ident) => {
        pub async fn $name(
            axum::extract::State(state): axum::extract::State<$crate::state::AppState>,
            method: axum::http::Method,
            uri: axum::http::Uri,
            headers: axum::http::HeaderMap,
            raw_params: axum::extract::RawPathParams,
        ) -> axum::response::Response {
            let params = match super::support::path_params(&raw_params, &method, &uri).await {
                Ok(params) => params,
                Err(response) => return response,
            };
            let site_param = params.get("siteId").cloned().unwrap_or_default();
            let request = match $crate::analytics::chain::site_scoped(
                &state,
                &headers,
                &uri,
                &site_param,
                $crate::analytics::chain::SiteGuard::Public,
                $crate::analytics::chain::route_scope("analytics", "read"),
                $crate::analytics::chain::ChainSteps::FULL,
            )
            .await
            {
                Ok(request) => request,
                Err(response) => return response,
            };
            match $body(&state, &request.site_id, &request.query).await {
                Ok(response) => response,
                Err(err) => super::support::analytics_failure($label, err.as_ref()),
            }
        }
    };
}
pub(super) use analytics_read_route;

analytics_read_route!(get_performance_overview, "performance overview", performance_overview);
analytics_read_route!(get_performance_time_series, "performance time series", performance_time_series);
analytics_read_route!(get_performance_by_dimension, "performance by dimension", performance_by_dimension);

async fn performance_overview(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let site = string_to_number(site_id);
    let spec = QuerySpec::new(build_performance_overview_query(query, site)?).param("siteId", site);
    let rows = analytics_clickhouse(state)?.run_analytics_query(&spec).await?;
    debug!(site_id, rows = rows.len(), "Performance overview fetched");
    // `{ data: data[0] }`: an absent first row drops the key
    Ok(match rows.into_iter().next() {
        Some(row) => send_json(StatusCode::OK, &json!({ "data": Value::Object(row) })),
        None => send_json(StatusCode::OK, &json!({})),
    })
}

async fn performance_time_series(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let site = string_to_number(site_id);
    let spec = QuerySpec::new(build_performance_time_series_query(query, site)?).param("siteId", site);
    let rows = analytics_clickhouse(state)?.run_analytics_query(&spec).await?;
    debug!(site_id, rows = rows.len(), "Performance time series fetched");
    Ok(send_json(StatusCode::OK, &json!({ "data": rows })))
}

async fn performance_by_dimension(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let site = string_to_number(site_id);
    let data = QuerySpec::new(build_performance_by_dimension_query(query, site, false)?).param("siteId", site);
    let count = QuerySpec::new(build_performance_by_dimension_query(query, site, true)?).param("siteId", site);
    let result = analytics_clickhouse(state)?.run_paginated_query(&data, &count).await?;
    debug!(site_id, rows = result.data.len(), "Performance by dimension fetched");
    Ok(send_json(StatusCode::OK, &json!({ "data": { "data": result.data, "totalCount": result.total_count } })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> JsObject {
        pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
    }

    #[test]
    fn dimension_is_validated() {
        let err = build_performance_by_dimension_query(&query(&[("dimension", "city")]), 1.0, false).unwrap_err();
        assert_eq!(err.to_string(), "Invalid dimension: city");
        let sql = build_performance_by_dimension_query(&query(&[("dimension", "country"), ("sort_by", "lcp_p75"), ("sort_order", "asc")]), 1.0, false).unwrap();
        assert!(sql.contains("ORDER BY lcp_p75 ASC NULLS LAST"));
        assert!(sql.contains("LIMIT 100"));
        let count = build_performance_by_dimension_query(&query(&[("dimension", "country")]), 1.0, true).unwrap();
        assert!(count.contains("SELECT COUNT(DISTINCT country) as totalCount FROM PerformanceStats;"));
    }

    #[test]
    fn row_filters_stay_on_the_performance_rows() {
        let filters = r#"[{"parameter":"browser","type":"equals","value":["Chrome"]},{"parameter":"utm_source","type":"equals","value":["x"]}]"#;
        let sql = build_performance_overview_query(&query(&[("filters", filters)]), 3.0).unwrap();
        assert!(sql.starts_with("WITH FilteredSessions AS"));
        assert!(sql.contains("AND browser = 'Chrome'"));
        assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
    }
}
