//! Session reads, ported from server/src/api/analytics/sessions:
//! `GET /api/sites/:siteId/sessions` (getSessions.ts),
//! `GET /api/sites/:siteId/sessions/:sessionId` (getSession.ts) and
//! `GET /api/sites/:siteId/sessions/locations` (getSessionLocations.ts), all on
//! the `publicSessionsRead` chain.

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::{Value, json};
use tracing::{debug, info};

use super::common::{
    BuildError, HandlerError, RouteFailure, clickhouse, number_value, ok, parse_int_auto, parse_int_radix_10, path_params, pg_integer, query_value,
    render, route_failure, send_json, with_default,
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::{JsObject, JsValue, number::number_to_string},
        utils::{
            analytics_query::{QueryParam, QuerySpec},
            effective_user_id::matches_user,
            session_attribution::{SESSION_CHANNEL_AGG, SESSION_REFERRER_AGG},
            session_filters::{build_filtered_sessions_cte, get_session_filter_statement},
            time_window::{TimeWindowParams, get_time_statement},
            utils::enrich_with_traits,
        },
    },
    state::AppState,
};

const SESSIONS_TEMPLATE: &str = r#"
  WITH AggregatedSessions AS (
      SELECT
          session_id,
          argMax(user_id, timestamp) AS user_id,
          argMax(identified_user_id, timestamp) AS identified_user_id,
          argMax(country, timestamp) AS country,
          argMax(region, timestamp) AS region,
          argMax(city, timestamp) AS city,
          argMax(language, timestamp) AS language,
          argMax(device_type, timestamp) AS device_type,
          argMax(browser, timestamp) AS browser,
          argMax(browser_version, timestamp) AS browser_version,
          argMax(operating_system, timestamp) AS operating_system,
          argMax(operating_system_version, timestamp) AS operating_system_version,
          argMax(screen_width, timestamp) AS screen_width,
          argMax(screen_height, timestamp) AS screen_height,
          ${SESSION_REFERRER_AGG} AS referrer,
          ${SESSION_CHANNEL_AGG} AS channel,
          argMin(hostname, timestamp) AS hostname,
          argMin(url_parameters, timestamp)['utm_source'] AS utm_source,
          argMin(url_parameters, timestamp)['utm_medium'] AS utm_medium,
          argMin(url_parameters, timestamp)['utm_campaign'] AS utm_campaign,
          argMin(url_parameters, timestamp)['utm_term'] AS utm_term,
          argMin(url_parameters, timestamp)['utm_content'] AS utm_content,
          MAX(timestamp) AS session_end,
          MIN(timestamp) AS session_start,
          dateDiff('second', MIN(timestamp), MAX(timestamp)) AS session_duration,
          argMinIf(pathname, timestamp_ms, type = 'pageview') AS entry_page,
          argMaxIf(pathname, timestamp_ms, type = 'pageview') AS exit_page,
          countIf(type = 'pageview') AS pageviews,
          countIf(type = 'custom_event') AS events,
          countIf(type = 'error') AS errors,
          countIf(type = 'outbound') AS outbound,
          countIf(type = 'button_click') AS button_clicks,
          countIf(type = 'copy') AS copies,
          countIf(type = 'form_submit') AS form_submits,
          countIf(type = 'input_change') AS input_changes,
          argMax(ip, timestamp) AS ip,
          argMax(lat, timestamp) AS lat,
          argMax(lon, timestamp) AS lon,
          argMax(tag, timestamp) AS tag,
          argMax(timezone, timestamp) AS timezone
      FROM events
      WHERE
          site_id = {siteId:Int32}
          ${userClause}
          ${sessionClause}
          ${timeStatement}
      GROUP BY
          session_id
      ORDER BY session_end DESC
  ),
  ReplaySessions AS (
      SELECT DISTINCT session_id
      FROM session_replay_metadata_v2
      FINAL
      WHERE site_id = {siteId:Int32}
        AND event_count >= 2
  )
  SELECT
      a.*,
      if(r.session_id != '', 1, 0) AS has_replay
  FROM AggregatedSessions a
  LEFT JOIN ReplaySessions r ON a.session_id = r.session_id
  WHERE 1 = 1 ${filterStatement}
  ${identifiedClause}
  ${pageviewsClause}
  ${eventsClause}
  ${durationClause}
  LIMIT {limit:Int32} OFFSET {offset:Int32}
  "#;

/// `minStr ? parseInt(minStr, 10) : undefined`
fn optional_int(value: &JsValue) -> Option<f64> {
    value.is_truthy().then(|| parse_int_radix_10(value))
}

/// `buildSessionsQuery(query, siteId)`.
pub fn build_sessions_query(query: &JsObject, site_id: i64) -> Result<QuerySpec, BuildError> {
    let filters = query_value(query, "filters");
    let page = with_default(query_value(query, "page"), JsValue::Number(1.0));
    let user_id = query_value(query, "user_id");
    let session_id = query_value(query, "session_id");
    let limit = with_default(query_value(query, "limit"), JsValue::Number(100.0));
    let identified_only = with_default(query_value(query, "identified_only"), JsValue::from("false"));
    let filter_identified = identified_only.as_str() == Some("true");
    let min_pageviews = optional_int(query_value(query, "min_pageviews"));
    let min_events = optional_int(query_value(query, "min_events"));
    let min_duration = optional_int(query_value(query, "min_duration"));

    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = get_session_filter_statement(filters, site_id, &time_statement)?;

    let user_clause =
        if user_id.is_truthy() { format!(" AND {}", matches_user("{user_id:String}", "events")) } else { String::new() };
    let session_clause =
        if session_id.is_truthy() { " AND events.session_id = {session_id:String}".to_string() } else { String::new() };

    let sql = render(
        SESSIONS_TEMPLATE,
        &[
            ("SESSION_REFERRER_AGG", SESSION_REFERRER_AGG),
            ("SESSION_CHANNEL_AGG", SESSION_CHANNEL_AGG),
            ("userClause", &user_clause),
            ("sessionClause", &session_clause),
            ("timeStatement", &time_statement),
            ("filterStatement", &filter_statement),
            ("identifiedClause", if filter_identified { "AND a.identified_user_id != ''" } else { "" }),
            ("pageviewsClause", if min_pageviews.is_some() { "AND a.pageviews >= {minPageviews:Int32}" } else { "" }),
            ("eventsClause", if min_events.is_some() { "AND a.events >= {minEvents:Int32}" } else { "" }),
            ("durationClause", if min_duration.is_some() { "AND a.session_duration >= {minDuration:Int32}" } else { "" }),
        ],
    );

    // `limit || 100` and `(page - 1) * (limit || 100)` with JavaScript coercions
    let limit_or_default = if limit.is_truthy() { limit } else { JsValue::Number(100.0) };
    let offset = (page.to_number() - 1.0) * limit_or_default.to_number();

    Ok(QuerySpec::new(sql)
        .param("siteId", site_id as f64)
        .param("user_id", user_id)
        .param("session_id", session_id)
        .param("limit", &limit_or_default)
        .param("offset", offset)
        .param("minPageviews", min_pageviews.unwrap_or(0.0))
        .param("minEvents", min_events.unwrap_or(0.0))
        .param("minDuration", min_duration.unwrap_or(0.0)))
}

/// `GET /api/sites/:siteId/sessions`
pub async fn get_sessions(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match path_params(&method, &uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let request = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Public,
        route_scope("sessions", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };

    let site = JsValue::from(request.site_id.as_str()).to_number();
    let result: Result<Value, RouteFailure> = async {
        let spec = build_sessions_query(&request.query, site as i64)?;
        let rows = clickhouse(&state).run_analytics_query(&spec).await?;
        let rows = enrich_with_traits(&state.pg, rows, pg_integer(site)?).await?;
        Ok(json!({ "data": rows }))
    }
    .await;

    match result {
        Ok(body) => {
            info!(site_id = %request.site_id, "Served sessions");
            ok(body)
        }
        Err(failure) => route_failure("sessions", failure),
    }
}

/// The three queries `buildSessionQueries(query)` returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionQueries {
    pub session_query: String,
    pub count_query: String,
    pub events_query: String,
}

const SESSION_TEMPLATE: &str = r#"
SELECT
    session_id,
    any(user_id) as user_id,
    any(country) as country,
    any(region) as region,
    any(city) as city,
    any(language) as language,
    any(device_type) as device_type,
    any(browser) as browser,
    any(browser_version) as browser_version,
    any(operating_system) as operating_system,
    any(operating_system_version) as operating_system_version,
    any(screen_width) as screen_width,
    any(screen_height) as screen_height,
    ${SESSION_REFERRER_AGG} as referrer,
    ${SESSION_CHANNEL_AGG} as channel,
    min(timestamp) as session_start,
    max(timestamp) as session_end,
    dateDiff('second', min(timestamp), max(timestamp)) as session_duration,
    countIf(type = 'pageview') as pageviews,
    countIf(type != 'heartbeat') as events,
    argMinIf(pathname, timestamp_ms, type = 'pageview') as entry_page,
    argMaxIf(pathname, timestamp_ms, type = 'pageview') as exit_page,
    any(ip) AS ip
FROM events
WHERE
    site_id = {siteId:Int32}
    AND session_id = {sessionId:String}
    ${timeFilterWithConnector}
GROUP BY session_id
LIMIT 1
    "#;

const SESSION_COUNT_TEMPLATE: &str = r#"
SELECT
    COUNT(*) as total
FROM events
WHERE
    site_id = {siteId:Int32}
    AND session_id = {sessionId:String}
    AND type NOT IN ('performance', 'heartbeat')
    ${timeFilterWithConnector}
    "#;

const SESSION_EVENTS_TEMPLATE: &str = r#"
SELECT
    timestamp_ms AS timestamp,
    pathname,
    hostname,
    querystring,
    page_title,
    referrer,
    type,
    event_name,
    props
FROM events
WHERE
    site_id = {siteId:Int32}
    AND session_id = {sessionId:String}
    AND type NOT IN ('performance', 'heartbeat')
    ${timeFilterWithConnector}
ORDER BY timestamp_ms ASC
LIMIT {limit:Int32}
OFFSET {offset:Int32}
    "#;

/// `buildSessionQueries(query)`.
pub fn build_session_queries(query: &JsObject) -> SessionQueries {
    let minutes_raw = query_value(query, "minutes");
    // `query.minutes ? parseInt(query.minutes) : undefined`, then truthiness
    let minutes = minutes_raw.is_truthy().then(|| parse_int_auto(minutes_raw));
    let time_filter = match minutes {
        Some(minutes) if JsValue::Number(minutes).is_truthy() => {
            format!("timestamp > now() - interval {} minute", number_to_string(minutes))
        }
        _ => String::new(),
    };
    let with_connector = if time_filter.is_empty() { String::new() } else { format!("AND {time_filter}") };
    let values = [
        ("SESSION_REFERRER_AGG", SESSION_REFERRER_AGG),
        ("SESSION_CHANNEL_AGG", SESSION_CHANNEL_AGG),
        ("timeFilterWithConnector", with_connector.as_str()),
    ];
    SessionQueries {
        session_query: render(SESSION_TEMPLATE, &values),
        count_query: render(SESSION_COUNT_TEMPLATE, &values),
        events_query: render(SESSION_EVENTS_TEMPLATE, &values),
    }
}

/// `GET /api/sites/:siteId/sessions/:sessionId`
pub async fn get_session(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match path_params(&method, &uri, &[3, 5]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let request = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Public,
        route_scope("sessions", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };
    let session_id = params[1].as_str();
    let query = &request.query;

    let limit_raw = query_value(query, "limit");
    let offset_raw = query_value(query, "offset");
    let limit = if limit_raw.is_truthy() { parse_int_auto(limit_raw) } else { 100.0 };
    let offset = if offset_raw.is_truthy() { parse_int_auto(offset_raw) } else { 0.0 };
    let queries = build_session_queries(query);
    let site_number = JsValue::from(request.site_id.as_str()).to_number();

    let base = |sql: &str| QuerySpec::new(sql).param("siteId", site_number).param("sessionId", session_id);
    let session_spec = base(&queries.session_query);
    let count_spec = base(&queries.count_query);
    let events_spec = base(&queries.events_query).param("limit", limit).param("offset", offset);

    let client = clickhouse(&state);
    let (session_rows, count_rows, event_rows) = tokio::join!(
        client.run_analytics_query(&session_spec),
        client.run_analytics_query(&count_spec),
        client.run_analytics_query(&events_spec),
    );
    let (session_rows, count_rows, event_rows) = match (session_rows, count_rows, event_rows) {
        (Ok(session), Ok(count), Ok(events)) => (session, count, events),
        (Err(failure), _, _) | (_, Err(failure), _) | (_, _, Err(failure)) => {
            return route_failure("session data", failure);
        }
    };

    let Some(session) = session_rows.into_iter().next() else {
        debug!(site_id = %request.site_id, "Session not found");
        return send_json(StatusCode::NOT_FOUND, &json!({ "error": "Session not found" }));
    };

    // `countData[0].total` throws a TypeError when the count query returned no row
    let Some(count_row) = count_rows.first() else {
        let failure = HandlerError::new("Cannot read properties of undefined (reading 'total')");
        return route_failure("session data", failure);
    };
    let total = count_row.get("total");
    // `offset + events.length < total`; an absent column is `undefined` (NaN)
    let total_number = total.map_or(f64::NAN, |value| JsValue::from_serde(value).to_number());
    let has_more = offset + (event_rows.len() as f64) < total_number;

    let mut pagination = serde_json::Map::new();
    if let Some(total) = total {
        pagination.insert("total".into(), total.clone());
    }
    pagination.insert("limit".into(), number_value(limit));
    pagination.insert("offset".into(), number_value(offset));
    pagination.insert("hasMore".into(), Value::Bool(has_more));

    info!(site_id = %request.site_id, events = event_rows.len(), "Served session");
    ok(json!({
        "data": {
            "session": Value::Object(session),
            "events": Value::Array(event_rows.into_iter().map(Value::Object).collect()),
            "pagination": Value::Object(pagination),
        }
    }))
}

const SESSION_LOCATIONS_TEMPLATE: &str = r#"
WITH ${cte}
stuff AS (
    SELECT
        session_id,
        argMax(lat, timestamp) AS lat,
        argMax(lon, timestamp) AS lon,
        argMax(city, timestamp) AS city,
        argMax(country, timestamp) AS country
    FROM
        events
    ${filteredSessionsJoin}
    WHERE
        site_id = {site:Int32}
        ${timeStatement}
    GROUP BY
        session_id
)
SELECT
    lat,
    lon,
    city,
    country,
    count() as count
from
    stuff
GROUP BY
    lat,
    lon,
    city,
    country"#;

/// `buildSessionLocationsQuery(query, siteId)`.
pub fn build_session_locations_query(query: &JsObject, site_id: i64) -> Result<String, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let cte = build_filtered_sessions_cte(query_value(query, "filters"), site_id, &time_statement, "FilteredSessions")?;
    let join = if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    let cte_prefix = cte.map(|cte| format!("{cte},")).unwrap_or_default();
    Ok(render(
        SESSION_LOCATIONS_TEMPLATE,
        &[("cte", &cte_prefix), ("filteredSessionsJoin", join), ("timeStatement", &time_statement)],
    ))
}

/// `GET /api/sites/:siteId/sessions/locations`
pub async fn get_session_locations(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let params = match path_params(&method, &uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let request = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Public,
        route_scope("sessions", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };

    let site = JsValue::from(request.site_id.as_str()).to_number();
    let sql = match build_session_locations_query(&request.query, site as i64) {
        Ok(sql) => sql,
        Err(failure) => return route_failure("session locations", failure),
    };
    // `params: { site: siteId }` passes the route parameter string through
    let spec = QuerySpec::new(sql).param("site", QueryParam::String(request.site_id.clone()));
    match clickhouse(&state).run_analytics_query(&spec).await {
        Ok(rows) => {
            info!(site_id = %request.site_id, locations = rows.len(), "Served session locations");
            ok(json!({ "data": rows }))
        }
        Err(failure) => route_failure("session locations", failure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> JsObject {
        pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
    }

    // Ported from getSessionLocations.test.ts
    #[test]
    fn session_locations_keep_session_scoped_filters() {
        let filters = r#"[{"parameter":"utm_campaign","type":"equals","value":["recipe_book_2026"]},{"parameter":"pathname","type":"equals","value":["/thank-you"]}]"#;
        let sql = build_session_locations_query(
            &query(&[("filters", filters), ("start_date", ""), ("end_date", ""), ("time_zone", "UTC")]),
            1,
        )
        .unwrap();
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
        assert!(sql.contains("AND pathname = '/thank-you'"));
        assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(sql.contains("argMax(lat, timestamp) AS lat"));
        assert_eq!(sql.matches("utm_campaign = 'recipe_book_2026'").count(), 1);
        assert_eq!(sql.matches("pathname = '/thank-you'").count(), 1);
    }

    #[test]
    fn sessions_query_params_follow_javascript_coercions() {
        let spec = build_sessions_query(&query(&[("page", "3"), ("limit", "25"), ("min_pageviews", "2x")]), 7).unwrap();
        let param = |name: &str| spec.params.iter().find(|(key, _)| key == name).unwrap().1.clone();
        assert_eq!(param("limit"), QueryParam::String("25".into()));
        assert_eq!(param("offset"), QueryParam::Number(50.0));
        assert_eq!(param("minPageviews"), QueryParam::Number(2.0));
        assert_eq!(param("minEvents"), QueryParam::Number(0.0));
        assert_eq!(param("user_id"), QueryParam::Undefined);
        assert!(spec.query.contains("AND a.pageviews >= {minPageviews:Int32}"));
        assert!(!spec.query.contains("a.events >="));

        let defaults = build_sessions_query(&JsObject::new(), 7).unwrap();
        let param = |name: &str| defaults.params.iter().find(|(key, _)| key == name).unwrap().1.clone();
        assert_eq!(param("limit"), QueryParam::Number(100.0));
        assert_eq!(param("offset"), QueryParam::Number(0.0));

        let user = build_sessions_query(&query(&[("user_id", "u1"), ("identified_only", "true")]), 7).unwrap();
        assert!(user.query.contains(" AND (events.identified_user_id = {user_id:String} OR"));
        assert!(user.query.contains("AND a.identified_user_id != ''"));
    }

    #[test]
    fn session_queries_minutes() {
        assert!(build_session_queries(&query(&[("minutes", "30")])).session_query.contains("AND timestamp > now() - interval 30 minute"));
        assert!(build_session_queries(&query(&[("minutes", "0x10")])).count_query.contains("interval 16 minute"));
        assert!(!build_session_queries(&query(&[("minutes", "abc")])).events_query.contains("interval"));
        assert!(!build_session_queries(&query(&[("minutes", "0")])).events_query.contains("interval"));
    }
}
