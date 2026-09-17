//! The lite dashboard endpoints (server/src/api/analytics/lite/): GET
//! /api/sites/:siteId/overview-lite, /overview-bucketed-lite and /metric-lite.
//!
//! They read the hourly materialized views instead of raw events and fall back
//! to the standard handlers whenever the rollups cannot answer the question: a
//! datetime range (sub-hour window), or a filter on a column or with an operator
//! the session rollup does not carry.

use serde_json::{Map, Value};
use tracing::debug;

use crate::analytics::{
    js::{JsObject, JsValue, number::number_to_string},
    types::{FilterParameter, FilterType, TimeBucket},
    utils::{
        analytics_query::QuerySpec,
        get_filter_statement::build_string_filter_condition,
        query_validation::validate_filters,
        time_window::{TimeWindow, resolve_time_window_with_clock},
    },
};

use super::{
    BucketLookup, BuildError, HandlerError, Outcome, OverviewBackend, Reply, catch_nested, js_number, metric::get_metric,
    overview::{data_first_row, data_rows, get_overview, get_overview_bucketed},
    route_failure, time_params,
};

/// `hasLiteFilters(filters)`: at least one valid filter (throws like `validateFilters`).
pub fn has_lite_filters(filters: &JsValue) -> Result<bool, BuildError> {
    if !filters.is_truthy() {
        return Ok(false);
    }
    Ok(!validate_filters(&filters.to_js_string())?.is_empty())
}

/// `LITE_SESSION_FILTER_COLUMNS`: session-invariant attributes on sessions_mv_target.
fn lite_session_filter_column(parameter: &FilterParameter) -> Option<&'static str> {
    match parameter {
        FilterParameter::Country => Some("country"),
        FilterParameter::Region => Some("region"),
        FilterParameter::DeviceType => Some("device_type"),
        FilterParameter::Browser => Some("browser"),
        FilterParameter::OperatingSystem => Some("operating_system"),
        FilterParameter::Hostname => Some("hostname"),
        _ => None,
    }
}

/// `LITE_SUPPORTED_FILTER_TYPES`.
fn is_lite_supported_filter_type(filter_type: FilterType) -> bool {
    matches!(
        filter_type,
        FilterType::Equals
            | FilterType::NotEquals
            | FilterType::Contains
            | FilterType::NotContains
            | FilterType::StartsWith
            | FilterType::EndsWith
    )
}

/// `getLiteSessionFilter`'s result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteSessionFilter {
    pub supported: bool,
    pub sql: String,
}

/// `getLiteSessionFilter(filters)`: a `WHERE` fragment against sessions_mv_target
/// columns, or `supported: false` to send the caller to the raw-events query.
pub fn get_lite_session_filter(filters: &JsValue) -> Result<LiteSessionFilter, BuildError> {
    let unsupported = LiteSessionFilter { supported: false, sql: String::new() };
    if !filters.is_truthy() {
        return Ok(LiteSessionFilter { supported: true, sql: String::new() });
    }
    let parsed = validate_filters(&filters.to_js_string())?;
    if parsed.is_empty() {
        return Ok(LiteSessionFilter { supported: true, sql: String::new() });
    }

    let mut conditions = Vec::new();
    for filter in &parsed {
        let Some(column) = lite_session_filter_column(&filter.parameter) else {
            return Ok(unsupported);
        };
        if matches!(filter.filter_type, FilterType::IsNull | FilterType::IsNotNull) {
            conditions.push(build_string_filter_condition(column, filter.filter_type, &filter.value)?);
            continue;
        }
        if !is_lite_supported_filter_type(filter.filter_type) || filter.value.is_empty() {
            return Ok(unsupported);
        }
        conditions.push(build_string_filter_condition(column, filter.filter_type, &filter.value)?);
    }
    let sql = if conditions.is_empty() { String::new() } else { format!("AND {}", conditions.join(" AND ")) };
    Ok(LiteSessionFilter { supported: true, sql })
}

/// `liteBucket(bucket)`: the views are hour-grained, so sub-hour buckets are promoted.
pub fn lite_bucket(bucket: &JsValue) -> (BucketLookup, JsValue) {
    if !bucket.is_truthy() {
        return (BucketLookup::Valid(TimeBucket::Hour), JsValue::from("hour"));
    }
    match BucketLookup::of(bucket) {
        BucketLookup::Valid(
            TimeBucket::Minute | TimeBucket::FiveMinutes | TimeBucket::TenMinutes | TimeBucket::FifteenMinutes,
        ) if bucket.as_str().is_some() => (BucketLookup::Valid(TimeBucket::Hour), JsValue::from("hour")),
        lookup => (lookup, bucket.clone()),
    }
}

/// `hasLiteDatetimeRange(params)`: a sub-hour window the rollups cannot express.
pub fn has_lite_datetime_range(query: &JsObject) -> bool {
    query.get_or_undefined("start_datetime").is_truthy() && query.get_or_undefined("end_datetime").is_truthy()
}

/// `buildOverviewLiteQuery(query, filterSql)`: `None` reads the refreshable
/// session_hourly_mv_target, `Some` the per-session rollup with the filter applied.
pub fn build_overview_lite_query(
    query: &JsObject,
    filter_sql: Option<&str>,
    now: &dyn Fn() -> f64,
) -> Result<String, BuildError> {
    let params = time_params(query);
    if let Some(filter_sql) = filter_sql {
        let sessions_time = get_time_statement_with_clock(&params, "start_time", now)?;
        return Ok(format!(
            "
      SELECT
        sessions,
        pageviews,
        users,
        if(sessions > 0, pageviews / sessions, 0) AS pages_per_session,
        if(sessions > 0, bounced_sessions * 100.0 / sessions, 0) AS bounce_rate,
        if(sessions > 0, total_session_duration_seconds / sessions, 0) AS session_duration
      FROM (
        SELECT
          count() AS sessions,
          sum(session_pageviews) AS pageviews,
          uniqExact(user_id) AS users,
          countIf(session_pageviews = 1) AS bounced_sessions,
          sum(toUInt64(session_end - session_start)) AS total_session_duration_seconds
        FROM (
          SELECT
            session_id,
            any(user_id) AS user_id,
            sum(pageviews) AS session_pageviews,
            min(start_time) AS session_start,
            max(end_time) AS session_end
          FROM sessions_mv_target
          WHERE site_id = {{siteId:Int32}}
            {sessions_time}
            {filter_sql}
          GROUP BY session_id
        )
      )
    "
        ));
    }

    let time_statement = get_time_statement_with_clock(&params, "session_hour", now)?;
    Ok(format!(
        "
      SELECT
        sessions,
        pageviews,
        users,
        if(sessions > 0, pageviews / sessions, 0) AS pages_per_session,
        if(sessions > 0, bounced_sessions * 100.0 / sessions, 0) AS bounce_rate,
        if(sessions > 0, total_session_duration_seconds / sessions, 0) AS session_duration
      FROM (
        SELECT
          sum(sessions) AS sessions,
          sum(pageviews) AS pageviews,
          uniqMerge(users) AS users,
          sum(bounced_sessions) AS bounced_sessions,
          sum(total_session_duration_seconds) AS total_session_duration_seconds
        FROM session_hourly_mv_target
        WHERE site_id = {{siteId:Int32}}
          {time_statement}
      )
    "
    ))
}

/// `getTimeStatement(params, column)` reading the injected clock.
fn get_time_statement_with_clock(
    params: &crate::analytics::utils::time_window::TimeWindowParams,
    column: &str,
    now: &dyn Fn() -> f64,
) -> Result<String, BuildError> {
    Ok(resolve_time_window_with_clock(params, now)?.where_clause(column))
}

/// What a lite handler decided to do.
enum LitePlan {
    /// The rollups cannot answer; the standard handler takes the request
    Fallback,
    Query(String),
}

/// `getOverviewLite`.
pub(crate) async fn get_overview_lite<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    const LABEL: &str = "overview";
    let site = js_number(site_id);
    if has_lite_datetime_range(query) {
        debug!(site_id = site, "overview-lite: datetime range, using the events query");
        return Ok(catch_nested(LABEL, get_overview(backend, site_id, query).await));
    }
    let result: Result<Result<Reply, LitePlan>, HandlerError> = async {
        let filters = query.get_or_undefined("filters");
        let sql = if has_lite_filters(filters)? {
            let filter = get_lite_session_filter(filters)?;
            if !filter.supported {
                return Ok(Err(LitePlan::Fallback));
            }
            build_overview_lite_query(query, Some(&filter.sql), &|| backend.now_ms())?
        } else {
            build_overview_lite_query(query, None, &|| backend.now_ms())?
        };
        let rows = backend.run_analytics_query(&QuerySpec::new(sql).param("siteId", site)).await?;
        Ok(Ok(Reply::ok(data_first_row(rows))))
    }
    .await;
    match result {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(_)) => {
            debug!(site_id = site, "overview-lite: filter not on the session rollup, using the events query");
            Ok(catch_nested(LABEL, get_overview(backend, site_id, query).await))
        }
        Err(failure) => route_failure(LABEL, &failure),
    }
}

/// `buildHourBucketQuery`: pageviews and users by event hour beside sessions by start.
fn build_hour_bucket_query(window: &TimeWindow, bucket: TimeBucket) -> String {
    let fill = window.fill(bucket);
    let event_hour = window.bucketed("event_hour", bucket);
    let overview_time = window.where_clause("event_hour");
    let session_start = window.bucketed("session_start", bucket);
    let sessions_time = window.where_clause("start_time");
    format!(
        "
    SELECT
      coalesce(p.time, s.time) AS time,
      coalesce(p.pageviews, 0) AS pageviews,
      coalesce(p.users, 0) AS users,
      coalesce(s.sessions, 0) AS sessions,
      coalesce(s.pages_per_session, 0) AS pages_per_session,
      coalesce(s.bounce_rate, 0) AS bounce_rate,
      coalesce(s.session_duration, 0) AS session_duration
    FROM (
      SELECT
        {event_hour} AS time,
        sum(pageviews) AS pageviews,
        uniqMerge(users) AS users
      FROM overview_hourly_mv_target
      WHERE site_id = {{siteId:Int32}}
        {overview_time}
      GROUP BY time
      ORDER BY time {fill}
    ) p
    FULL JOIN (
      SELECT
        {session_start} AS time,
        count() AS sessions,
        avg(session_pageviews) AS pages_per_session,
        countIf(session_pageviews = 1) / count() * 100 AS bounce_rate,
        avg(session_end - session_start) AS session_duration
      FROM (
        SELECT
          session_id,
          sum(pageviews) AS session_pageviews,
          min(start_time) AS session_start,
          max(end_time) AS session_end
        FROM sessions_mv_target
        WHERE site_id = {{siteId:Int32}}
          {sessions_time}
        GROUP BY session_id
      )
      GROUP BY time
      ORDER BY time {fill}
    ) s USING time
    ORDER BY time
  "
    )
}

/// `buildDayBucketQuery`: all six metrics from session_hourly_mv_target.
fn build_day_bucket_query(window: &TimeWindow, bucket: TimeBucket) -> String {
    let fill = window.fill(bucket);
    let session_hour = window.bucketed("session_hour", bucket);
    let session_time = window.where_clause("session_hour");
    format!(
        "
    SELECT
      time,
      sessions,
      pageviews,
      users,
      if(sessions > 0, pageviews / sessions, 0) AS pages_per_session,
      if(sessions > 0, bounced_sessions * 100.0 / sessions, 0) AS bounce_rate,
      if(sessions > 0, total_session_duration_seconds / sessions, 0) AS session_duration
    FROM (
      SELECT
        {session_hour} AS time,
        sum(sessions) AS sessions,
        sum(pageviews) AS pageviews,
        uniqMerge(users) AS users,
        sum(bounced_sessions) AS bounced_sessions,
        sum(total_session_duration_seconds) AS total_session_duration_seconds
      FROM session_hourly_mv_target
      WHERE site_id = {{siteId:Int32}}
        {session_time}
      GROUP BY time
      ORDER BY time {fill}
    )
    ORDER BY time
  "
    )
}

/// `buildSessionMvFilteredQuery`: filtered charts from the per-session rollup.
fn build_session_mv_filtered_query(window: &TimeWindow, bucket: TimeBucket, filter_sql: &str) -> String {
    let fill = window.fill(bucket);
    let session_start = window.bucketed("session_start", bucket);
    let sessions_time = window.where_clause("start_time");
    format!(
        "
    SELECT
      time,
      sessions,
      pageviews,
      users,
      if(sessions > 0, pageviews / sessions, 0) AS pages_per_session,
      if(sessions > 0, bounced_sessions * 100.0 / sessions, 0) AS bounce_rate,
      if(sessions > 0, total_session_duration_seconds / sessions, 0) AS session_duration
    FROM (
      SELECT
        {session_start} AS time,
        count() AS sessions,
        sum(session_pageviews) AS pageviews,
        uniqExact(user_id) AS users,
        countIf(session_pageviews = 1) AS bounced_sessions,
        sum(toUInt64(session_end - session_start)) AS total_session_duration_seconds
      FROM (
        SELECT
          session_id,
          any(user_id) AS user_id,
          sum(pageviews) AS session_pageviews,
          min(start_time) AS session_start,
          max(end_time) AS session_end
        FROM sessions_mv_target
        WHERE site_id = {{siteId:Int32}}
          {sessions_time}
          {filter_sql}
        GROUP BY session_id
      )
      GROUP BY time
      ORDER BY time {fill}
    )
    ORDER BY time
  "
    )
}

/// The query `getOverviewBucketedLite` runs, or a fallback to the events query.
fn plan_overview_bucketed_lite(query: &JsObject, now: &dyn Fn() -> f64) -> Result<LitePlan, BuildError> {
    let (bucket, raw_bucket) = lite_bucket(query.get_or_undefined("bucket"));
    // One window for every predicate: resolving per column re-read now()
    let window = resolve_time_window_with_clock(&time_params(query), now)?;
    let filters = query.get_or_undefined("filters");
    if has_lite_filters(filters)? {
        let filter = get_lite_session_filter(filters)?;
        if !filter.supported {
            return Ok(LitePlan::Fallback);
        }
        let bucket = bucket.require(&raw_bucket)?;
        return Ok(LitePlan::Query(build_session_mv_filtered_query(&window, bucket, &filter.sql)));
    }
    let bucket = bucket.require(&raw_bucket)?;
    let use_day_bucket = matches!(bucket, TimeBucket::Day | TimeBucket::Week | TimeBucket::Month | TimeBucket::Year);
    Ok(LitePlan::Query(if use_day_bucket {
        build_day_bucket_query(&window, bucket)
    } else {
        build_hour_bucket_query(&window, bucket)
    }))
}

/// `getOverviewBucketedLite`.
pub(crate) async fn get_overview_bucketed_lite<B: OverviewBackend>(
    backend: &B,
    site_id: &str,
    query: &JsObject,
) -> Outcome {
    const LABEL: &str = "overview";
    let site = js_number(site_id);
    if has_lite_datetime_range(query) {
        debug!(site_id = site, "overview-bucketed-lite: datetime range, using the events query");
        return Ok(catch_nested(LABEL, get_overview_bucketed(backend, site_id, query).await));
    }
    let result: Result<Option<Reply>, HandlerError> = async {
        match plan_overview_bucketed_lite(query, &|| backend.now_ms())? {
            LitePlan::Fallback => Ok(None),
            LitePlan::Query(sql) => {
                let rows = backend.run_analytics_query(&QuerySpec::new(sql).param("siteId", site)).await?;
                Ok(Some(Reply::ok(data_rows(rows))))
            }
        }
    }
    .await;
    match result {
        Ok(Some(reply)) => Ok(reply),
        Ok(None) => {
            debug!(site_id = site, "overview-bucketed-lite: filter not on the session rollup, using the events query");
            Ok(catch_nested(LABEL, get_overview_bucketed(backend, site_id, query).await))
        }
        Err(failure) => route_failure(LABEL, &failure),
    }
}

/// `getLitePagination(query)`: clamps (default 250, max 500) instead of validating.
fn lite_pagination(query: &JsObject) -> (f64, String) {
    let or = |value: f64, fallback: f64| if value.is_nan() || value == 0.0 { fallback } else { value };
    let limit = or(query.get_or_undefined("limit").to_number(), 250.0).min(500.0);
    let page = or(query.get_or_undefined("page").to_number(), 1.0).max(1.0);
    let offset = if page > 1.0 { format!("OFFSET {}", number_to_string((page - 1.0) * limit)) } else { String::new() };
    (limit, offset)
}

/// `buildMetricLiteSessionQuery(query, filterSql)`: filtered country/device_type lists
/// from sessions_mv_target. `parameter` is one of those two.
pub fn build_metric_lite_session_query(
    query: &JsObject,
    parameter: &str,
    filter_sql: &str,
    now: &dyn Fn() -> f64,
) -> Result<String, BuildError> {
    let (limit, offset_statement) = lite_pagination(query);
    let limit = number_to_string(limit);
    let sessions_time = get_time_statement_with_clock(&time_params(query), "start_time", now)?;
    let non_empty = if parameter == "device_type" { format!("AND {parameter} <> ''") } else { String::new() };
    Ok(format!(
        "
      SELECT
        value,
        pageviews,
        count,
        round(count * 100.0 / sum(count) OVER (), 2) AS percentage,
        round(pageviews * 100.0 / sum(pageviews) OVER (), 2) AS pageviews_percentage,
        count() OVER () AS total_count
      FROM (
        SELECT
          {parameter} AS value,
          sum(session_pageviews) AS pageviews,
          count() AS count
        FROM (
          SELECT
            session_id,
            any({parameter}) AS {parameter},
            sum(pageviews) AS session_pageviews
          FROM sessions_mv_target
          WHERE site_id = {{siteId:Int32}}
            {sessions_time}
            {non_empty}
            {filter_sql}
          GROUP BY session_id
        )
        GROUP BY {parameter}
      )
      ORDER BY count DESC, value ASC
      LIMIT {limit}
      {offset_statement}
    "
    ))
}

/// `buildMetricLiteQuery(query)`: unfiltered lists from the dimensioned hourly
/// views, `None` for a parameter lite mode does not support.
pub fn build_metric_lite_query(query: &JsObject, now: &dyn Fn() -> f64) -> Result<Option<String>, BuildError> {
    let (limit, offset_statement) = lite_pagination(query);
    let limit = number_to_string(limit);
    let time_statement = get_time_statement_with_clock(&time_params(query), "event_hour", now)?;
    let parameter = query.get_or_undefined("parameter");
    Ok(match parameter.as_str() {
        Some("pathname") => Some(format!(
            "
      SELECT
        value,
        hostname,
        pageviews,
        count,
        round(count * 100.0 / sum(count) OVER (), 2) AS percentage,
        round(pageviews * 100.0 / sum(pageviews) OVER (), 2) AS pageviews_percentage,
        count() OVER () AS total_count
      FROM (
        SELECT
          pathname AS value,
          any(hostname) AS hostname,
          sum(pageviews) AS pageviews,
          uniqMerge(sessions) AS count
        FROM pathname_hourly_mv_target
        WHERE site_id = {{siteId:Int32}}
          {time_statement}
        GROUP BY pathname
      )
      ORDER BY count DESC, value ASC
      LIMIT {limit}
      {offset_statement}
    "
        )),
        Some("country") => Some(format!(
            "
      SELECT
        value,
        pageviews,
        count,
        round(count * 100.0 / sum(count) OVER (), 2) AS percentage,
        round(pageviews * 100.0 / sum(pageviews) OVER (), 2) AS pageviews_percentage,
        count() OVER () AS total_count
      FROM (
        SELECT
          country AS value,
          sum(pageviews) AS pageviews,
          uniqMerge(sessions) AS count
        FROM country_hourly_mv_target
        WHERE site_id = {{siteId:Int32}}
          {time_statement}
        GROUP BY country
      )
      ORDER BY count DESC, value ASC
      LIMIT {limit}
      {offset_statement}
    "
        )),
        Some("device_type") => Some(format!(
            "
      SELECT
        value,
        pageviews,
        count,
        round(count * 100.0 / sum(count) OVER (), 2) AS percentage,
        round(pageviews * 100.0 / sum(pageviews) OVER (), 2) AS pageviews_percentage,
        count() OVER () AS total_count
      FROM (
        SELECT
          device_type AS value,
          sum(pageviews) AS pageviews,
          uniqMerge(sessions) AS count
        FROM device_type_hourly_mv_target
        WHERE site_id = {{siteId:Int32}}
          AND device_type <> ''
          {time_statement}
        GROUP BY device_type
      )
      ORDER BY count DESC, value ASC
      LIMIT {limit}
      {offset_statement}
    "
        )),
        _ => None,
    })
}

/// `sendMetric`: `totalCount` comes off the window column, which is then dropped
/// from every item so they match the standard /metric shape.
fn send_metric(rows: Vec<super::Row>) -> Reply {
    let total_count = match rows.first() {
        None => Value::from(0),
        Some(first) => match first.get("total_count") {
            None | Some(Value::Null) => Value::from(rows.len()),
            Some(value) => value.clone(),
        },
    };
    let items: Vec<Value> = rows
        .into_iter()
        .map(|mut row| {
            row.shift_remove("total_count");
            Value::Object(row)
        })
        .collect();
    let mut inner = Map::new();
    inner.insert("data".to_string(), Value::Array(items));
    inner.insert("totalCount".to_string(), total_count);
    let mut body = Map::new();
    body.insert("data".to_string(), Value::Object(inner));
    Reply::ok(Value::Object(body))
}

/// `getMetricLite`.
pub(crate) async fn get_metric_lite<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    const LABEL: &str = "metric";
    let site = js_number(site_id);
    if has_lite_datetime_range(query) {
        debug!(site_id = site, "metric-lite: datetime range, using the events query");
        return Ok(catch_nested(LABEL, get_metric(backend, site_id, query).await));
    }
    let parameter = query.get_or_undefined("parameter");
    let result: Result<Option<Reply>, HandlerError> = async {
        let filters = query.get_or_undefined("filters");
        if has_lite_filters(filters)? {
            let filter = get_lite_session_filter(filters)?;
            let session_parameter = match parameter.as_str() {
                Some(name @ ("country" | "device_type")) if filter.supported => name,
                _ => return Ok(None),
            };
            let sql = build_metric_lite_session_query(query, session_parameter, &filter.sql, &|| backend.now_ms())?;
            let rows = backend.run_analytics_query(&QuerySpec::new(sql).param("siteId", site)).await?;
            return Ok(Some(send_metric(rows)));
        }
        let Some(sql) = build_metric_lite_query(query, &|| backend.now_ms())? else {
            debug!(site_id = site, parameter = %parameter.to_js_string(), "metric-lite: unsupported parameter");
            return Ok(Some(Reply::error(
                axum::http::StatusCode::BAD_REQUEST,
                "Lite mode does not support this parameter",
            )));
        };
        let rows = backend.run_analytics_query(&QuerySpec::new(sql).param("siteId", site)).await?;
        Ok(Some(send_metric(rows)))
    }
    .await;
    match result {
        Ok(Some(reply)) => Ok(reply),
        Ok(None) => {
            debug!(site_id = site, "metric-lite: filter or parameter not on the session rollup, using the events query");
            Ok(catch_nested(LABEL, get_metric(backend, site_id, query).await))
        }
        Err(failure) => route_failure(LABEL, &failure),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn filters_of(value: Value) -> JsValue {
        JsValue::from(value.to_string())
    }

    fn session_filter(value: Value) -> LiteSessionFilter {
        get_lite_session_filter(&filters_of(value)).unwrap()
    }

    fn supported(sql: &str) -> LiteSessionFilter {
        LiteSessionFilter { supported: true, sql: sql.to_string() }
    }

    fn unsupported() -> LiteSessionFilter {
        LiteSessionFilter { supported: false, sql: String::new() }
    }

    // Ported from lite/utils.test.ts
    #[test]
    fn session_filter_empty_inputs() {
        assert_eq!(get_lite_session_filter(&JsValue::Undefined).unwrap(), supported(""));
        assert_eq!(get_lite_session_filter(&JsValue::from("[]")).unwrap(), supported(""));
        let error = get_lite_session_filter(&JsValue::from("not json")).unwrap_err();
        assert_eq!(error.to_string(), "Invalid JSON format");
    }

    #[test]
    fn session_filter_columns() {
        for parameter in ["country", "region", "device_type", "browser", "operating_system", "hostname"] {
            assert_eq!(
                session_filter(json!([{ "parameter": parameter, "type": "equals", "value": ["x"] }])),
                supported(&format!("AND {parameter} = 'x'"))
            );
        }
        for parameter in ["pathname", "page_title", "referrer", "channel", "entry_page", "utm_source"] {
            assert_eq!(session_filter(json!([{ "parameter": parameter, "type": "equals", "value": ["x"] }])), unsupported());
        }
        assert_eq!(
            session_filter(json!([
                { "parameter": "country", "type": "equals", "value": ["US"] },
                { "parameter": "pathname", "type": "equals", "value": ["/home"] }
            ])),
            unsupported()
        );
        for filter_type in ["regex", "not_regex", "greater_than", "less_than"] {
            assert_eq!(session_filter(json!([{ "parameter": "country", "type": filter_type, "value": ["US"] }])), unsupported());
        }
        assert_eq!(session_filter(json!([{ "parameter": "country", "type": "equals", "value": [] }])), unsupported());
    }

    #[test]
    fn session_filter_operators() {
        let one = |parameter: &str, filter_type: &str, value: Value| {
            session_filter(json!([{ "parameter": parameter, "type": filter_type, "value": value }]))
        };
        assert_eq!(one("country", "equals", json!(["US"])), supported("AND country = 'US'"));
        assert_eq!(one("country", "not_equals", json!(["US"])), supported("AND country != 'US'"));
        assert_eq!(one("browser", "contains", json!(["Chr"])), supported("AND browser LIKE '%Chr%'"));
        assert_eq!(one("browser", "not_contains", json!(["bot"])), supported("AND browser NOT LIKE '%bot%'"));
        assert_eq!(one("hostname", "starts_with", json!(["app."])), supported("AND hostname LIKE 'app.%'"));
        assert_eq!(one("hostname", "ends_with", json!([".dev"])), supported("AND hostname LIKE '%.dev'"));
        assert_eq!(one("region", "is_null", json!([])), supported("AND (region IS NULL OR region = '')"));
        assert_eq!(one("region", "is_not_null", json!([])), supported("AND (region IS NOT NULL AND region != '')"));
        assert_eq!(one("country", "equals", json!(["US", "DE"])), supported("AND (country = 'US' OR country = 'DE')"));
        assert_eq!(one("country", "not_equals", json!(["US", "DE"])), supported("AND (country != 'US' AND country != 'DE')"));
        assert_eq!(
            one("browser", "not_contains", json!(["bot", "spider"])),
            supported("AND (browser NOT LIKE '%bot%' AND browser NOT LIKE '%spider%')")
        );
        assert_eq!(
            session_filter(json!([
                { "parameter": "country", "type": "equals", "value": ["US"] },
                { "parameter": "device_type", "type": "equals", "value": ["Desktop"] }
            ])),
            supported("AND country = 'US' AND device_type = 'Desktop'")
        );
        assert_eq!(
            one("country", "equals", json!(["US'; DROP TABLE events;--"])).sql,
            "AND country = 'US\\'; DROP TABLE events;--'"
        );
        assert_eq!(one("browser", "contains", json!(["O'Brien"])).sql, "AND browser LIKE '%O\\'Brien%'");
        assert_eq!(one("country", "equals", json!([42])).sql, "AND country = '42'");
    }

    #[test]
    fn datetime_range_detection() {
        let query = |pairs: &[(&str, &str)]| -> JsObject {
            pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
        };
        assert!(has_lite_datetime_range(&query(&[("start_datetime", "2024-01-01 10:30:00"), ("end_datetime", "2024-01-01 14:45:00")])));
        assert!(!has_lite_datetime_range(&query(&[("start_datetime", "2024-01-01 10:30:00")])));
        assert!(!has_lite_datetime_range(&query(&[("end_datetime", "2024-01-01 14:45:00")])));
        assert!(!has_lite_datetime_range(&query(&[("start_date", "2024-01-01"), ("end_date", "2024-01-31")])));
        assert!(!has_lite_datetime_range(&query(&[])));
    }

    #[test]
    fn bucket_promotion() {
        assert_eq!(lite_bucket(&JsValue::Undefined).0, BucketLookup::Valid(TimeBucket::Hour));
        assert_eq!(lite_bucket(&JsValue::from("")).0, BucketLookup::Valid(TimeBucket::Hour));
        for bucket in ["minute", "five_minutes", "ten_minutes", "fifteen_minutes"] {
            assert_eq!(lite_bucket(&JsValue::from(bucket)).0, BucketLookup::Valid(TimeBucket::Hour));
        }
        for bucket in [TimeBucket::Hour, TimeBucket::Day, TimeBucket::Week, TimeBucket::Month, TimeBucket::Year] {
            assert_eq!(lite_bucket(&JsValue::from(bucket.as_str())).0, BucketLookup::Valid(bucket));
        }
        assert_eq!(lite_bucket(&JsValue::from("fortnight")).0, BucketLookup::Invalid);
    }

    #[test]
    fn lite_filter_presence() {
        assert!(!has_lite_filters(&JsValue::Undefined).unwrap());
        assert!(!has_lite_filters(&JsValue::from("")).unwrap());
        assert!(!has_lite_filters(&JsValue::from("[]")).unwrap());
        assert!(has_lite_filters(&filters_of(json!([{ "parameter": "country", "type": "equals", "value": ["US"] }]))).unwrap());
        assert_eq!(has_lite_filters(&JsValue::from("not json")).unwrap_err().to_string(), "Invalid JSON format");
    }

    #[test]
    fn pagination_clamps() {
        let query = |pairs: &[(&str, &str)]| -> JsObject {
            pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
        };
        assert_eq!(lite_pagination(&query(&[])), (250.0, String::new()));
        assert_eq!(lite_pagination(&query(&[("limit", "1000"), ("page", "3")])), (500.0, "OFFSET 1000".to_string()));
        assert_eq!(lite_pagination(&query(&[("limit", "abc"), ("page", "-4")])), (250.0, String::new()));
        assert_eq!(lite_pagination(&query(&[("limit", "10"), ("page", "2.5")])), (10.0, "OFFSET 15".to_string()));
    }

    #[test]
    fn metric_items_drop_the_window_count() {
        let row = |value: &str, total: Value| -> super::super::Row {
            let Value::Object(map) = json!({ "value": value, "pageviews": 3, "count": 2, "total_count": total }) else {
                unreachable!()
            };
            map
        };
        let reply = send_metric(vec![row("/a", json!(7)), row("/b", json!(7))]);
        assert_eq!(
            reply.body_text(),
            r#"{"data":{"data":[{"value":"/a","pageviews":3,"count":2},{"value":"/b","pageviews":3,"count":2}],"totalCount":7}}"#
        );
        assert_eq!(send_metric(Vec::new()).body_text(), r#"{"data":{"data":[],"totalCount":0}}"#);
    }
}
