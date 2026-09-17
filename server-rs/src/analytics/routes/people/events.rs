//! Event reads, ported from server/src/api/analytics/events (all on the
//! `publicEventsRead` chain): the event log (getEvents.ts), the top-event time
//! series (getEventBucketed.ts), event names and properties
//! (getEventNames.ts, getEventProperties.ts), autocapture groupings and value
//! suggestions (getAutocaptureEvents.ts, getAutocaptureValues.ts) and outbound
//! links (getOutboundLinks.ts).

use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::Response,
};
use serde_json::{Map, Value, json};
use tracing::info;

use super::{
    common::{
        BuildError, RouteFailure, clickhouse, is_object_prototype_key, ok, parse_int_radix_10, path_params, pg_integer,
        query_value, render,
        route_failure, with_default,
    },
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, SiteRequest, route_scope, site_scoped},
        js::{JsObject, JsValue},
        sql_string::escape_string,
        types::{FilterParameter, TimeBucket},
        utils::{
            analytics_query::QuerySpec,
            event_conditions::{AutocaptureTargetType, is_autocapture_target_type},
            get_filter_statement::{FilterStatementOptions, get_filter_statement},
            time_window::{TimeWindowParams, get_time_statement, time_bucket_fn},
            utils::enrich_with_traits,
        },
    },
    state::AppState,
};

/// The chain every event route runs: resolveSiteId, `allowPublicSiteAccess`
/// with `events:read`, validateTimeParams, expandSegmentParam.
async fn events_chain(state: &AppState, method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<SiteRequest, Response> {
    let params = path_params(method, uri, &[3]).await?;
    site_scoped(state, headers, uri, &params[0], SiteGuard::Public, route_scope("events", "read"), ChainSteps::FULL).await
}

/// `{ sessionLevelParams: ["channel"] }`: only channel stays session-attributed.
fn channel_only() -> FilterStatementOptions {
    FilterStatementOptions::session_level(vec![FilterParameter::Channel])
}

/// `filters ? getFilterStatement(filters, siteId, timeStatement, { sessionLevelParams: ["channel"] }) : ""`
fn channel_filter_statement(query: &JsObject, site_id: i64, time_statement: Option<&str>) -> Result<String, BuildError> {
    let filters = query_value(query, "filters");
    if !filters.is_truthy() {
        return Ok(String::new());
    }
    Ok(get_filter_statement(filters, Some(site_id), time_statement, &channel_only())?)
}

fn site_number(request: &SiteRequest) -> f64 {
    JsValue::from(request.site_id.as_str()).to_number()
}

// ---------------------------------------------------------------------------
// GET /events

const EVENT_COLUMNS: &str = "
  timestamp,
  event_name,
  toString(props) as properties,
  session_id,
  user_id,
  identified_user_id,
  pathname,
  querystring,
  hostname,
  page_title,
  referrer,
  browser,
  browser_version,
  operating_system,
  operating_system_version,
  language,
  country,
  region,
  city,
  lat,
  lon,
  screen_width,
  screen_height,
  device_type,
  type
";

const EVENT_TYPE_FILTER: &str =
    "AND type IN ('custom_event', 'pageview', 'outbound', 'button_click', 'copy', 'form_submit', 'input_change')";

const EVENTS_SINCE_TEMPLATE: &str = r#"
        SELECT ${EVENT_COLUMNS}
        FROM events
        WHERE
          site_id = {siteId:Int32}
          ${EVENT_TYPE_FILTER}
          AND timestamp > toDateTime64({sinceTimestamp:String}, 3)
          ${filterStatement}
        ORDER BY timestamp DESC
        LIMIT 500
      "#;

const EVENTS_PAGE_TEMPLATE: &str = r#"
      SELECT ${EVENT_COLUMNS}
      FROM events
      WHERE
        site_id = {siteId:Int32}
        ${EVENT_TYPE_FILTER}
        ${timeStatement}
        ${cursorCondition}
        ${filterStatement}
      ORDER BY timestamp DESC
      LIMIT {limit:Int32}
    "#;

/// `buildEventsQuery(query, siteId)`.
pub fn build_events_query(query: &JsObject, site_id: i64) -> Result<QuerySpec, BuildError> {
    let since_timestamp = query_value(query, "since_timestamp");
    let before_timestamp = query_value(query, "before_timestamp");
    let page_size = with_default(query_value(query, "page_size"), JsValue::from("50"));
    let limit = parse_int_radix_10(&page_size);
    // The event log filters individual rows; only channel remains session-attributed
    let filter_statement = channel_filter_statement(query, site_id, None)?;

    if since_timestamp.is_truthy() {
        let sql = render(
            EVENTS_SINCE_TEMPLATE,
            &[("EVENT_COLUMNS", EVENT_COLUMNS), ("EVENT_TYPE_FILTER", EVENT_TYPE_FILTER), ("filterStatement", &filter_statement)],
        );
        return Ok(QuerySpec::new(sql).param("siteId", site_id as f64).param("sinceTimestamp", since_timestamp));
    }

    let time_statement = if query_value(query, "start_date").is_truthy() || query_value(query, "end_date").is_truthy() {
        get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?
    } else {
        String::new()
    };
    let cursor_condition = if before_timestamp.is_truthy() {
        "AND timestamp < toDateTime64({beforeTimestamp:String}, 3)"
    } else {
        ""
    };
    let sql = render(
        EVENTS_PAGE_TEMPLATE,
        &[
            ("EVENT_COLUMNS", EVENT_COLUMNS),
            ("EVENT_TYPE_FILTER", EVENT_TYPE_FILTER),
            ("timeStatement", &time_statement),
            ("cursorCondition", cursor_condition),
            ("filterStatement", &filter_statement),
        ],
    );
    let mut spec = QuerySpec::new(sql).param("siteId", site_id as f64).param("limit", limit);
    if before_timestamp.is_truthy() {
        spec = spec.param("beforeTimestamp", before_timestamp);
    }
    Ok(spec)
}

/// `GET /api/sites/:siteId/events`
pub async fn get_events(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let request = match events_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let site = site_number(&request);
    let query = &request.query;

    let result: Result<Value, RouteFailure> = async {
        let spec = build_events_query(query, site as i64)?;
        let events = clickhouse(&state).run_analytics_query(&spec).await?;
        let event_count = events.len();
        let oldest_timestamp = events.last().map(|row| row.get("timestamp").cloned());
        let events = enrich_with_traits(&state.pg, events, pg_integer(site)?).await?;

        if query_value(query, "since_timestamp").is_truthy() {
            return Ok(json!({ "data": events }));
        }
        let limit = parse_int_radix_10(&with_default(query_value(query, "page_size"), JsValue::from("50")));
        let mut cursor = Map::new();
        cursor.insert("hasMore".into(), Value::Bool(event_count as f64 == limit));
        match oldest_timestamp {
            // `events[events.length - 1].timestamp`; an absent column is undefined and dropped
            Some(Some(timestamp)) => {
                cursor.insert("oldestTimestamp".into(), timestamp);
            }
            Some(None) => {}
            None => {
                cursor.insert("oldestTimestamp".into(), Value::Null);
            }
        }
        Ok(json!({ "data": events, "cursor": Value::Object(cursor) }))
    }
    .await;

    match result {
        Ok(body) => {
            info!(site_id = %request.site_id, "Served events");
            ok(body)
        }
        Err(failure) => route_failure("events", failure),
    }
}

// ---------------------------------------------------------------------------
// GET /events/time-series

const EVENT_BUCKETED_TEMPLATE: &str = r#"
    WITH top_events AS (
      SELECT
        event_name
      FROM events
      WHERE
        site_id = {siteId:Int32}
        AND type = 'custom_event'
        AND event_name IS NOT NULL
        AND event_name != ''
        ${timeStatement}
        ${filterStatement}
      GROUP BY event_name
      ORDER BY count() DESC
      LIMIT {limit:Int32}
    )
    SELECT
      toDateTime(${bucketFn}(toTimeZone(timestamp, {timeZone:String}))) AS time,
      event_name,
      count() AS event_count
    FROM events
    WHERE
      site_id = {siteId:Int32}
      AND type = 'custom_event'
      AND event_name IS NOT NULL
      AND event_name != ''
      ${timeStatement}
      ${filterStatement}
      AND event_name IN (SELECT event_name FROM top_events)
    GROUP BY time, event_name
    ORDER BY time
  "#;

/// `parseLimit(limit)`: `Number(limit ?? 5)`, clamped to 1..=10.
fn parse_limit(limit: &JsValue) -> f64 {
    let parsed = if limit.is_undefined() { 5.0 } else { limit.to_number() };
    if !parsed.is_finite() {
        return 5.0;
    }
    parsed.floor().clamp(1.0, 10.0)
}

/// `buildEventBucketedQuery(query, siteId)` for a bucket `TimeBucketToFn` knows.
pub fn build_event_bucketed_query(query: &JsObject, site_id: i64, bucket: TimeBucket) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = get_filter_statement(
        query_value(query, "filters"),
        Some(site_id),
        Some(&time_statement),
        &channel_only(),
    )?;
    Ok(render(
        EVENT_BUCKETED_TEMPLATE,
        &[("timeStatement", &time_statement), ("filterStatement", &filter_statement), ("bucketFn", time_bucket_fn(bucket))],
    ))
}

/// `GET /api/sites/:siteId/events/time-series`
pub async fn get_event_bucketed(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let request = match events_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let query = &request.query;
    let bucket = with_default(query_value(query, "bucket"), JsValue::from("hour"));
    let time_zone = match query_value(query, "time_zone") {
        value if value.is_truthy() => value.clone(),
        _ => JsValue::from("UTC"),
    };

    // `TimeBucketToFn[bucket]`: the property key is `String(bucket)`
    let key = bucket.to_js_string();
    let parsed_bucket = match &bucket {
        JsValue::String(text) => TimeBucket::parse(text),
        _ => None,
    };
    let site = site_number(&request);
    let Some(parsed_bucket) = parsed_bucket else {
        if is_object_prototype_key(&key) {
            // An inherited property passes the check; the query still builds (so a
            // time or filter error surfaces first) and then splices function source
            // text into the SQL, which ClickHouse rejects
            if let Err(failure) = build_event_bucketed_query(query, site as i64, TimeBucket::Hour) {
                return route_failure("bucketed event data", failure);
            }
            let failure = super::common::HandlerError::new(format!("Syntax error: bucket function {key}"));
            return route_failure("bucketed event data", failure);
        }
        return super::common::bad_request(&format!("Invalid bucket value: {key}"));
    };

    let sql = match build_event_bucketed_query(query, site as i64, parsed_bucket) {
        Ok(sql) => sql,
        Err(failure) => return route_failure("bucketed event data", failure),
    };
    let spec = QuerySpec::new(sql)
        .param("siteId", site)
        .param("limit", parse_limit(query_value(query, "limit")))
        .param("timeZone", &time_zone);
    match clickhouse(&state).run_analytics_query(&spec).await {
        Ok(rows) => {
            info!(site_id = %request.site_id, rows = rows.len(), "Served event time series");
            ok(json!({ "data": rows }))
        }
        Err(failure) => route_failure("bucketed event data", failure),
    }
}

// ---------------------------------------------------------------------------
// GET /events/names

const EVENT_NAMES_TEMPLATE: &str = r#"
    SELECT
      event_name AS eventName,
      count() AS count
    FROM events
    WHERE
      site_id = {siteId:Int32}
      AND type = 'custom_event'
      AND event_name IS NOT NULL
      AND event_name != ''
      ${timeStatement}
      ${filterStatement}
    GROUP BY event_name
    ORDER BY count DESC
    LIMIT 1000
  "#;

/// `buildEventNamesQuery(query, siteId)`.
pub fn build_event_names_query(query: &JsObject, site_id: i64) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = channel_filter_statement(query, site_id, Some(&time_statement))?;
    Ok(render(EVENT_NAMES_TEMPLATE, &[("timeStatement", &time_statement), ("filterStatement", &filter_statement)]))
}

/// `GET /api/sites/:siteId/events/names`
pub async fn get_event_names(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let request = match events_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let site = site_number(&request);
    let sql = match build_event_names_query(&request.query, site as i64) {
        Ok(sql) => sql,
        Err(failure) => return route_failure("event names", failure),
    };
    match clickhouse(&state).run_analytics_query(&QuerySpec::new(sql).param("siteId", site)).await {
        Ok(rows) => {
            info!(site_id = %request.site_id, rows = rows.len(), "Served event names");
            ok(json!({ "data": rows }))
        }
        Err(failure) => route_failure("event names", failure),
    }
}

// ---------------------------------------------------------------------------
// GET /events/properties

const EVENT_PROPERTIES_TEMPLATE: &str = r#"
    SELECT
      kv.1 AS propertyKey, -- Access tuple elements
      replaceRegexpAll(kv.2, '^"|"$', '') AS propertyValue, -- Remove surrounding quotes if they exist
      count() AS count
    FROM events
    ARRAY JOIN JSONExtractKeysAndValuesRaw(CAST(props AS String)) AS kv -- Alias the tuple elements directly
    WHERE
      site_id = {siteId:Int32}
      AND type = 'custom_event'
      AND event_name = {eventName:String}
      AND props != '{}' -- Check if the JSON object is not empty
      ${timeStatement}
      ${filterStatement}
    GROUP BY propertyKey, propertyValue
    ORDER BY propertyKey ASC, count DESC
    LIMIT 500
  "#;

/// `buildEventPropertiesQuery(query, siteId)`.
pub fn build_event_properties_query(query: &JsObject, site_id: i64) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = channel_filter_statement(query, site_id, Some(&time_statement))?;
    Ok(render(EVENT_PROPERTIES_TEMPLATE, &[("timeStatement", &time_statement), ("filterStatement", &filter_statement)]))
}

/// `GET /api/sites/:siteId/events/properties`
pub async fn get_event_properties(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let request = match events_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let event_name = query_value(&request.query, "event_name");
    if !event_name.is_truthy() {
        return super::common::bad_request("Event name is required");
    }
    let site = site_number(&request);
    let sql = match build_event_properties_query(&request.query, site as i64) {
        Ok(sql) => sql,
        Err(failure) => return route_failure("event properties", failure),
    };
    let spec = QuerySpec::new(sql).param("siteId", site).param("eventName", event_name);
    match clickhouse(&state).run_analytics_query(&spec).await {
        Ok(rows) => {
            info!(site_id = %request.site_id, rows = rows.len(), "Served event properties");
            ok(json!({ "data": rows }))
        }
        Err(failure) => route_failure("event properties", failure),
    }
}

// ---------------------------------------------------------------------------
// GET /events/autocapture and /events/autocapture-values

/// `VALUE_EXPRESSIONS[type]`: the display value each autocapture type groups by.
fn value_expression(target_type: AutocaptureTargetType) -> &'static str {
    match target_type {
        AutocaptureTargetType::Outbound => "JSONExtractString(toString(props), 'url')",
        AutocaptureTargetType::ButtonClick | AutocaptureTargetType::Copy => "JSONExtractString(toString(props), 'text')",
        AutocaptureTargetType::FormSubmit => {
            "coalesce(nullIf(JSONExtractString(toString(props), 'formName'), ''), nullIf(JSONExtractString(toString(props), 'formId'), ''), nullIf(JSONExtractString(toString(props), 'formAction'), ''), '')"
        }
    }
}

const AUTOCAPTURE_EVENTS_TEMPLATE: &str = r#"
    SELECT
      ${valueExpression} AS value,
      COUNT(*) AS count,
      toString(MAX(timestamp)) AS lastOccurred
    FROM events
    WHERE
      site_id = {siteId:Int32}
      AND type = ${type}
      AND ${valueExpression} != ''
      ${timeStatement}
      ${filterStatement}
    GROUP BY value
    ORDER BY count DESC
    LIMIT 1000
  "#;

/// `buildAutocaptureEventsQuery(query, siteId, type)`.
pub fn build_autocapture_events_query(
    query: &JsObject,
    site_id: i64,
    target_type: AutocaptureTargetType,
) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = channel_filter_statement(query, site_id, Some(&time_statement))?;
    Ok(render(
        AUTOCAPTURE_EVENTS_TEMPLATE,
        &[
            ("valueExpression", value_expression(target_type)),
            ("type", &escape_string(target_type.as_str())),
            ("timeStatement", &time_statement),
            ("filterStatement", &filter_statement),
        ],
    ))
}

const AUTOCAPTURE_VALUES_TEMPLATE: &str = r#"
    SELECT value, COUNT(*) AS count
    FROM (
      SELECT arrayJoin([${propExtracts}]) AS value
      FROM events
      WHERE
        site_id = {siteId:Int32}
        AND type = ${type}
        ${timeStatement}
        ${filterStatement}
    )
    WHERE value <> ''
    GROUP BY value
    ORDER BY count DESC
    LIMIT 500
  "#;

/// `buildAutocaptureValuesQuery(query, siteId, type)`.
pub fn build_autocapture_values_query(
    query: &JsObject,
    site_id: i64,
    target_type: AutocaptureTargetType,
) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = channel_filter_statement(query, site_id, Some(&time_statement))?;
    let prop_extracts = target_type
        .pattern_props()
        .iter()
        .map(|prop| format!("JSONExtractString(toString(props), {})", escape_string(prop)))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(render(
        AUTOCAPTURE_VALUES_TEMPLATE,
        &[
            ("propExtracts", &prop_extracts),
            ("type", &escape_string(target_type.as_str())),
            ("timeStatement", &time_statement),
            ("filterStatement", &filter_statement),
        ],
    ))
}

/// `data.map(row => ({ ...row, value: String(row.value) }))`: captured text that
/// looks numeric must stay a string.
fn stringify_values(rows: Vec<Map<String, Value>>) -> Vec<Value> {
    rows.into_iter()
        .map(|mut row| {
            let text = JsValue::from_serde(row.get("value").unwrap_or(&Value::Null)).to_js_string();
            let text = if row.contains_key("value") { text } else { "undefined".to_string() };
            row.insert("value".into(), Value::String(text));
            Value::Object(row)
        })
        .collect()
}

/// Shared body of the two autocapture routes.
async fn autocapture_route(
    state: AppState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    label: &'static str,
    build: fn(&JsObject, i64, AutocaptureTargetType) -> Result<String, BuildError>,
) -> Response {
    let request = match events_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let target_type = match query_value(&request.query, "type") {
        JsValue::String(text) => is_autocapture_target_type(text),
        _ => None,
    };
    let Some(target_type) = target_type else {
        return super::common::bad_request("Invalid autocapture event type");
    };
    let site = site_number(&request);
    let sql = match build(&request.query, site as i64, target_type) {
        Ok(sql) => sql,
        Err(failure) => return route_failure(label, failure),
    };
    match clickhouse(&state).run_analytics_query(&QuerySpec::new(sql).param("siteId", site)).await {
        Ok(rows) => {
            info!(site_id = %request.site_id, kind = target_type.as_str(), rows = rows.len(), label, "Served autocapture rows");
            ok(json!({ "data": stringify_values(rows) }))
        }
        Err(failure) => route_failure(label, failure),
    }
}

/// `GET /api/sites/:siteId/events/autocapture`
pub async fn get_autocapture_events(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    autocapture_route(state, method, uri, headers, "autocapture events", build_autocapture_events_query).await
}

/// `GET /api/sites/:siteId/events/autocapture-values`
pub async fn get_autocapture_values(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    autocapture_route(state, method, uri, headers, "autocapture values", build_autocapture_values_query).await
}

// ---------------------------------------------------------------------------
// GET /events/outbound

const OUTBOUND_LINKS_TEMPLATE: &str = r#"
    SELECT
      JSONExtractString(toString(props), 'url') AS url,
      COUNT(*) AS count,
      toString(MAX(timestamp)) AS lastClicked
    FROM events
    WHERE
      site_id = {siteId:Int32}
      AND type = 'outbound'
      ${timeStatement}
      ${filterStatement}
    GROUP BY url
    ORDER BY count DESC
    LIMIT 1000
  "#;

/// `buildOutboundLinksQuery(query, siteId)`.
pub fn build_outbound_links_query(query: &JsObject, site_id: i64) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = channel_filter_statement(query, site_id, Some(&time_statement))?;
    Ok(render(OUTBOUND_LINKS_TEMPLATE, &[("timeStatement", &time_statement), ("filterStatement", &filter_statement)]))
}

/// `GET /api/sites/:siteId/events/outbound`
pub async fn get_outbound_links(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let request = match events_chain(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let site = site_number(&request);
    let sql = match build_outbound_links_query(&request.query, site as i64) {
        Ok(sql) => sql,
        Err(failure) => return route_failure("outbound links", failure),
    };
    match clickhouse(&state).run_analytics_query(&QuerySpec::new(sql).param("siteId", site)).await {
        Ok(rows) => {
            info!(site_id = %request.site_id, rows = rows.len(), "Served outbound links");
            ok(json!({ "data": rows }))
        }
        Err(failure) => route_failure("outbound links", failure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITE_ID: i64 = 1;

    fn base_query(overrides: &[(&str, &str)]) -> JsObject {
        let mut query: JsObject = [("start_date", ""), ("end_date", ""), ("time_zone", "UTC"), ("filters", ""), ("page_size", "50")]
            .iter()
            .map(|(key, value)| (key.to_string(), JsValue::from(*value)))
            .collect();
        for (key, value) in overrides {
            query.insert(*key, JsValue::from(*value));
        }
        query
    }

    // Ported from getEvents.test.ts
    #[test]
    fn events_filter_event_names_at_row_level() {
        let filters = r#"[{"parameter":"event_name","type":"equals","value":["att_prompt_shown"]}]"#;
        let spec = build_events_query(&base_query(&[("filters", filters)]), SITE_ID).unwrap();
        assert!(spec.query.contains("AND event_name = 'att_prompt_shown'"));
        assert!(!spec.query.contains("SELECT DISTINCT session_id"));
    }

    #[test]
    fn events_keep_channel_filters_at_session_level() {
        let filters = r#"[{"parameter":"channel","type":"equals","value":["Direct"]}]"#;
        let spec = build_events_query(&base_query(&[("filters", filters)]), SITE_ID).unwrap();
        assert!(spec.query.contains("session_id IN"));
        assert!(spec.query.contains("session_channel = 'Direct'"));
    }

    #[test]
    fn events_without_filters_add_no_clause() {
        let spec = build_events_query(&base_query(&[]), SITE_ID).unwrap();
        assert!(!spec.query.contains("session_id IN"));
        assert_eq!(
            spec.params,
            vec![
                ("siteId".to_string(), crate::analytics::utils::analytics_query::QueryParam::Number(1.0)),
                ("limit".to_string(), crate::analytics::utils::analytics_query::QueryParam::Number(50.0)),
            ]
        );
    }

    #[test]
    fn event_summaries_keep_event_name_row_scoped() {
        let filter = r#"[{"parameter":"event_name","type":"equals","value":["signup"]}]"#;
        let with_filter = |extra: &[(&str, &str)]| {
            let mut overrides = vec![("filters", filter)];
            overrides.extend_from_slice(extra);
            base_query(&overrides)
        };
        let queries = [
            build_event_names_query(&with_filter(&[("event_name", "")]), SITE_ID).unwrap(),
            build_event_bucketed_query(&with_filter(&[("bucket", "day")]), SITE_ID, TimeBucket::Day).unwrap(),
            build_event_properties_query(&with_filter(&[("event_name", "signup")]), SITE_ID).unwrap(),
            build_autocapture_events_query(&with_filter(&[("type", "form_submit")]), SITE_ID, AutocaptureTargetType::FormSubmit)
                .unwrap(),
            build_autocapture_values_query(&with_filter(&[("type", "form_submit")]), SITE_ID, AutocaptureTargetType::FormSubmit)
                .unwrap(),
            build_outbound_links_query(&with_filter(&[]), SITE_ID).unwrap(),
        ];
        for query in queries {
            assert!(query.contains("AND event_name = 'signup'"), "{query}");
            assert!(!query.contains("SELECT DISTINCT session_id"), "{query}");
        }
    }

    #[test]
    fn bucket_limits_clamp_like_node() {
        assert_eq!(parse_limit(&JsValue::Undefined), 5.0);
        assert_eq!(parse_limit(&"abc".into()), 5.0);
        assert_eq!(parse_limit(&"".into()), 1.0);
        assert_eq!(parse_limit(&"7.9".into()), 7.0);
        assert_eq!(parse_limit(&"99".into()), 10.0);
        assert_eq!(parse_limit(&"-3".into()), 1.0);
        assert_eq!(parse_limit(&"Infinity".into()), 5.0);
    }

    #[test]
    fn autocapture_values_extract_every_pattern_prop() {
        let sql = build_autocapture_values_query(&base_query(&[]), SITE_ID, AutocaptureTargetType::FormSubmit).unwrap();
        assert!(sql.contains(
            "arrayJoin([JSONExtractString(toString(props), 'formName'), JSONExtractString(toString(props), 'formId'), JSONExtractString(toString(props), 'formAction')])"
        ));
        assert!(sql.contains("AND type = 'form_submit'"));
        let rows = stringify_values(vec![json!({ "value": 100, "count": 2 }).as_object().unwrap().clone()]);
        assert_eq!(rows, vec![json!({ "value": "100", "count": 2 })]);
    }
}
