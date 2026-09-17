//! Error tracking reads on the `publicAnalyticsRead` chain, ported from
//! server/src/api/analytics/getErrorNames.ts, getErrorEvents.ts and
//! getErrorBucketed.ts. Filters on acquisition and cohort fields qualify whole
//! sessions (a `FilteredSessions` CTE); filters describing the error event itself
//! stay on the measured row.

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::{Value, json};
use tracing::{error, info, warn};

use super::{
    common::{
        BuildError, RouteFailure, ZOD_LOG_TYPE_ERROR, bad_request, clickhouse, ok, path_params, query_value, render,
        route_failure, send_json, uncaught_error,
    },
};
use crate::analytics::{
    chain::{ChainSteps, SiteGuard, SiteRequest, route_scope, site_scoped},
    js::{JsObject, JsValue},
    types::TimeBucket,
    utils::{
        analytics_query::{QuerySpec, get_pagination_statements},
        session_filters::{build_session_and_row_filter_fragments, target_event_row_level_params},
        time_window::{TimeWindowParams, get_time_statement, resolve_time_window},
    },
};
use crate::state::AppState;

/// `publicAnalyticsRead`: resolveSiteId, `allowPublicSiteAccess` with
/// `analytics:read`, validateTimeParams, expandSegmentParam.
async fn analytics_chain(state: &AppState, method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<SiteRequest, Response> {
    let params = path_params(method, uri, &[3]).await?;
    site_scoped(state, headers, uri, &params[0], SiteGuard::Public, route_scope("analytics", "read"), ChainSteps::FULL).await
}

fn site_number(request: &SiteRequest) -> f64 {
    JsValue::from(request.site_id.as_str()).to_number()
}

/// The session CTE (prefix form `cte,` or `WITH cte`), its join and the row filter.
struct Fragments {
    cte: Option<String>,
    join: &'static str,
    row_filter: String,
}

fn fragments(query: &JsObject, site_id: i64, time_statement: &str) -> Result<Fragments, BuildError> {
    let built = build_session_and_row_filter_fragments(
        query_value(query, "filters"),
        site_id,
        time_statement,
        &target_event_row_level_params(),
        "FilteredSessions",
    )?;
    let join = if built.filtered_sessions_cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    Ok(Fragments { cte: built.filtered_sessions_cte, join, row_filter: built.row_filter_statement })
}

// ---------------------------------------------------------------------------
// GET /errors/names

const ERROR_STATS_CTE: &str = r#"
    ErrorStats AS (
        SELECT
            JSONExtractString(toString(props), 'message') as value,
            any(event_name) as errorName,
            count(*) as total_occurrences,
            count(DISTINCT session_id) as unique_sessions
        FROM events
        ${sessionJoin}
        WHERE
          site_id = {siteId:Int32}
          AND type = 'error'
          AND event_name IS NOT NULL
          AND event_name <> ''
          AND JSONHas(toString(props), 'message')
          AND JSONExtractString(toString(props), 'message') <> ''
          ${rowFilterStatement}
          ${timeStatement}
        GROUP BY value
    )
  "#;

const ERROR_NAMES_COUNT_TEMPLATE: &str = r#"
    WITH ${cte} ${baseCteQuery}
    SELECT COUNT(*) as totalCount FROM ErrorStats;
    "#;

const ERROR_NAMES_TEMPLATE: &str = r#"
    WITH ${cte} ${baseCteQuery}
    SELECT
        value,
        errorName,
        total_occurrences as count,
        unique_sessions as sessionCount,
        ROUND(
            unique_sessions * 100.0 / SUM(unique_sessions) OVER (),
            2
        ) as percentage
    FROM ErrorStats
    ORDER BY total_occurrences DESC
    ${limitStatement}
    ${offsetStatement}
  "#;

/// `buildErrorNamesQuery(query, siteId, isCountQuery)`.
pub fn build_error_names_query(query: &JsObject, site_id: i64, is_count_query: bool) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let fragments = fragments(query, site_id, &time_statement)?;
    let pagination =
        get_pagination_statements(query_value(query, "limit"), query_value(query, "page"), 10.0, is_count_query);
    let base_cte = render(
        ERROR_STATS_CTE,
        &[("sessionJoin", fragments.join), ("rowFilterStatement", &fragments.row_filter), ("timeStatement", &time_statement)],
    );
    let cte = fragments.cte.map(|cte| format!("{cte},")).unwrap_or_default();
    if is_count_query {
        return Ok(render(ERROR_NAMES_COUNT_TEMPLATE, &[("cte", &cte), ("baseCteQuery", &base_cte)]));
    }
    Ok(render(
        ERROR_NAMES_TEMPLATE,
        &[
            ("cte", &cte),
            ("baseCteQuery", &base_cte),
            ("limitStatement", &pagination.limit_statement),
            ("offsetStatement", &pagination.offset_statement),
        ],
    ))
}

/// `GET /api/sites/:siteId/errors/names`
pub async fn get_error_names(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let request = match analytics_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let query = &request.query;
    let site = site_number(&request);
    let paginated = !query_value(query, "page").is_undefined();

    let result: Result<Value, RouteFailure> = async {
        let data_spec = QuerySpec::new(build_error_names_query(query, site as i64, false)?).param("siteId", site);
        if paginated {
            let count_spec = QuerySpec::new(build_error_names_query(query, site as i64, true)?).param("siteId", site);
            let result = clickhouse(&state).run_paginated_query(&data_spec, &count_spec).await?;
            return Ok(json!({ "data": { "data": result.data, "totalCount": result.total_count } }));
        }
        let items = clickhouse(&state).run_analytics_query(&data_spec).await?;
        Ok(json!({ "data": items }))
    }
    .await;

    match result {
        Ok(body) => {
            info!(site_id = %request.site_id, paginated, "Served error names");
            ok(body)
        }
        Err(failure) => route_failure("error names", failure),
    }
}

// ---------------------------------------------------------------------------
// GET /errors/events

const ERROR_EVENTS_COUNT_TEMPLATE: &str = r#"
      ${withCte}
      SELECT COUNT(*) as totalCount
      FROM events
      ${sessionJoin}
      WHERE
        site_id = {siteId:Int32}
        AND type = 'error'
        AND JSONExtractString(toString(props), 'message') = {errorMessage:String}
        ${rowFilterStatement}
        ${timeStatement}
    "#;

const ERROR_EVENTS_TEMPLATE: &str = r#"
    ${withCte}
    SELECT
        timestamp,
        session_id,
        user_id,
        pathname,
        hostname,
        page_title,
        referrer,
        browser,
        browser_version,
        operating_system,
        operating_system_version,
        device_type,
        country,
        city,
        region,
        JSONExtractString(toString(props), 'message') as message,
        JSONExtractString(toString(props), 'stack') as stack,
        COALESCE(
          JSONExtractString(toString(props), 'fileName'),
          JSONExtractString(toString(props), 'filename')
        ) as fileName,
        CASE
          WHEN JSONHas(toString(props), 'lineNumber') THEN JSONExtractInt(toString(props), 'lineNumber')
          WHEN JSONHas(toString(props), 'lineno') THEN JSONExtractInt(toString(props), 'lineno')
          ELSE NULL
        END as lineNumber,
        CASE
          WHEN JSONHas(toString(props), 'columnNumber') THEN JSONExtractInt(toString(props), 'columnNumber')
          WHEN JSONHas(toString(props), 'colno') THEN JSONExtractInt(toString(props), 'colno')
          ELSE NULL
        END as columnNumber
    FROM events
    ${sessionJoin}
    WHERE
      site_id = {siteId:Int32}
      AND type = 'error'
      AND JSONExtractString(toString(props), 'message') = {errorMessage:String}
      ${rowFilterStatement}
      ${timeStatement}
    ORDER BY timestamp DESC
    ${limitStatement}
    ${offsetStatement}
  "#;

/// `buildErrorEventsQuery(query, siteId, isCountQuery)`.
pub fn build_error_events_query(query: &JsObject, site_id: i64, is_count_query: bool) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let fragments = fragments(query, site_id, &time_statement)?;
    let pagination =
        get_pagination_statements(query_value(query, "limit"), query_value(query, "page"), 20.0, is_count_query);
    let with_cte = fragments.cte.map(|cte| format!("WITH {cte}")).unwrap_or_default();
    let values = [
        ("withCte", with_cte.as_str()),
        ("sessionJoin", fragments.join),
        ("rowFilterStatement", fragments.row_filter.as_str()),
        ("timeStatement", time_statement.as_str()),
        ("limitStatement", pagination.limit_statement.as_str()),
        ("offsetStatement", pagination.offset_statement.as_str()),
    ];
    Ok(render(if is_count_query { ERROR_EVENTS_COUNT_TEMPLATE } else { ERROR_EVENTS_TEMPLATE }, &values))
}

/// `GET /api/sites/:siteId/errors/events`
pub async fn get_error_events(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let request = match analytics_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let query = &request.query;
    let error_message = query_value(query, "errorMessage");
    if !error_message.is_truthy() {
        return bad_request("errorMessage parameter is required");
    }
    let site = site_number(&request);
    let paginated = !query_value(query, "page").is_undefined();

    let result: Result<Value, RouteFailure> = async {
        let params = |sql: String| QuerySpec::new(sql).param("siteId", site).param("errorMessage", error_message);
        let data_spec = params(build_error_events_query(query, site as i64, false)?);
        if paginated {
            let count_spec = params(build_error_events_query(query, site as i64, true)?);
            let result = clickhouse(&state).run_paginated_query(&data_spec, &count_spec).await?;
            return Ok(json!({ "data": { "data": result.data, "totalCount": result.total_count } }));
        }
        let items = clickhouse(&state).run_analytics_query(&data_spec).await?;
        Ok(json!({ "data": items }))
    }
    .await;

    match result {
        Ok(body) => {
            info!(site_id = %request.site_id, paginated, "Served error events");
            ok(body)
        }
        Err(failure) => route_failure("error events", failure),
    }
}

// ---------------------------------------------------------------------------
// GET /errors/time-series

const ERROR_BUCKETED_TEMPLATE: &str = r#"
      ${withCte}
      SELECT
        ${bucketed} AS time,
        COUNT(*) AS error_count
      FROM events
      ${sessionJoin}
      WHERE
        site_id = {siteId:Int32}
        AND type = 'error'
        AND JSONExtractString(toString(props), 'message') = {errorMessage:String}
        ${rowFilterStatement}
        ${timeStatement}
      GROUP BY time
      ORDER BY time
      ${timeStatementFill}
    "#;

/// `buildErrorBucketedQuery(query, siteId)` for a bucket `TimeBucketToFn` knows.
pub fn build_error_bucketed_query(query: &JsObject, site_id: i64, bucket: TimeBucket) -> Result<String, BuildError> {
    let window = resolve_time_window(&TimeWindowParams::from_object(query))?;
    let time_statement = window.where_timestamp();
    let fragments = fragments(query, site_id, &time_statement)?;
    let fill = window.fill(bucket);
    let bucketed = window.bucketed("timestamp", bucket);
    let with_cte = fragments.cte.map(|cte| format!("WITH {cte}")).unwrap_or_default();
    Ok(render(
        ERROR_BUCKETED_TEMPLATE,
        &[
            ("withCte", &with_cte),
            ("bucketed", &bucketed),
            ("sessionJoin", fragments.join),
            ("rowFilterStatement", &fragments.row_filter),
            ("timeStatement", &time_statement),
            ("timeStatementFill", &fill),
        ],
    ))
}

/// `getErrorBucketed`'s own catch: 500 `{ success: false, error }`.
fn error_bucketed_failure(failure: &dyn std::fmt::Display) -> Response {
    error!(err = %failure, "Error getting error bucketed data");
    send_json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "success": false, "error": "Failed to get error data" }))
}

/// `GET /api/sites/:siteId/errors/time-series`
pub async fn get_error_bucketed(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let request = match analytics_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let query = &request.query;
    let error_message = query_value(query, "errorMessage");
    if !error_message.is_truthy() {
        return bad_request("errorMessage parameter is required");
    }
    let site = site_number(&request);

    // `const { bucket } = query` has no default: anything but a known bucket name
    // renders `undefined(...)` or function source into the SELECT, which
    // ClickHouse rejects
    let bucket = match query_value(query, "bucket") {
        JsValue::String(text) => TimeBucket::parse(text),
        _ => None,
    };
    // The query builds before ClickHouse sees it, so a time or filter error wins
    let sql = match build_error_bucketed_query(query, site as i64, bucket.unwrap_or(TimeBucket::Hour)) {
        Ok(sql) => sql,
        Err(failure) if failure.is_zod_error() => {
            warn!(error = %failure, "Filters failed schema validation; Node's error log throws here");
            return uncaught_error(ZOD_LOG_TYPE_ERROR);
        }
        Err(failure) => return error_bucketed_failure(&failure),
    };
    if bucket.is_none() {
        return error_bucketed_failure(&format!(
            "unknown bucket function for {}",
            query_value(query, "bucket").to_js_string()
        ));
    }
    let spec = QuerySpec::new(sql).param("siteId", site).param("errorMessage", error_message);
    match clickhouse(&state).run_analytics_query(&spec).await {
        Ok(rows) => {
            info!(site_id = %request.site_id, rows = rows.len(), "Served error time series");
            ok(json!({ "success": true, "data": rows }))
        }
        Err(failure) => error_bucketed_failure(&failure.original),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITE_ID: i64 = 1;
    const CAMPAIGN_FILTER: &str = r#"[{"parameter":"utm_campaign","type":"equals","value":["recipe_book_2026"]}]"#;

    fn base_params(extra: &[(&str, &str)]) -> JsObject {
        let mut query: JsObject = [
            ("start_date", "2026-08-01"),
            ("end_date", "2026-08-31"),
            ("time_zone", "UTC"),
            ("filters", CAMPAIGN_FILTER),
        ]
        .iter()
        .map(|(key, value)| (key.to_string(), JsValue::from(*value)))
        .collect();
        for (key, value) in extra {
            query.insert(*key, JsValue::from(*value));
        }
        query
    }

    fn expect_session_qualified_target(sql: &str, target_predicate: &str) {
        assert!(sql.contains("FilteredSessions AS ("), "{sql}");
        assert!(sql.contains("INNER JOIN FilteredSessions"), "{sql}");
        let target_query = &sql[sql.rfind(target_predicate).unwrap()..];
        assert!(!target_query.contains("url_parameters['utm_campaign']"), "{target_query}");
    }

    // Ported from sessionScopedQueries.test.ts (the error cases)
    #[test]
    fn error_names_qualify_sessions() {
        let sql = build_error_names_query(&base_params(&[]), SITE_ID, false).unwrap();
        expect_session_qualified_target(&sql, "AND type = 'error'");
    }

    #[test]
    fn error_pathname_filters_stay_on_the_row() {
        let path_filter = r#"[{"parameter":"pathname","type":"equals","value":["/checkout"]}]"#;
        let sql = build_error_names_query(&base_params(&[("filters", path_filter)]), SITE_ID, false).unwrap();
        assert!(sql.contains("AND pathname = '/checkout'"));
        assert!(!sql.contains("FilteredSessions AS ("));
    }

    #[test]
    fn error_time_series_qualifies_sessions() {
        let sql = build_error_bucketed_query(&base_params(&[("bucket", "day"), ("errorMessage", "boom")]), SITE_ID, TimeBucket::Day)
            .unwrap();
        expect_session_qualified_target(&sql, "AND type = 'error'");
    }

    #[test]
    fn error_events_qualify_sessions_in_data_and_count() {
        for is_count_query in [false, true] {
            let sql = build_error_events_query(&base_params(&[("errorMessage", "boom")]), SITE_ID, is_count_query).unwrap();
            expect_session_qualified_target(&sql, "AND type = 'error'");
        }
    }

    #[test]
    fn error_names_pagination() {
        let query = base_params(&[("filters", ""), ("page", "3"), ("limit", "5")]);
        let sql = build_error_names_query(&query, SITE_ID, false).unwrap();
        assert!(sql.contains("LIMIT 5") && sql.contains("OFFSET 10"));
        let count = build_error_names_query(&query, SITE_ID, true).unwrap();
        assert!(count.contains("SELECT COUNT(*) as totalCount FROM ErrorStats;") && !count.contains("LIMIT"));
        assert!(count.contains("WITH  \n    ErrorStats AS ("));
    }
}
