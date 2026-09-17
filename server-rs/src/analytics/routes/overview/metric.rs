//! GET /api/sites/:siteId/metric (server/src/api/analytics/getMetric.ts): one
//! dimension's values ranked by sessions, paginated, with pageview shares, time on
//! page and bounce rate where they apply.

use serde_json::{Map, Value};
use tracing::debug;

use crate::analytics::{
    js::{JsObject, JsValue},
    types::FilterParameter,
    utils::{
        analytics_query::{QuerySpec, get_pagination_statements},
        get_filter_statement::get_sql_param,
        session_attribution::SESSION_CHANNEL_AGG,
        session_filters::build_session_and_row_filter_fragments,
        time_window::resolve_time_window_with_clock,
    },
};

use super::{Outcome, BuildError, HandlerError, OverviewBackend, Reply, integral_site_id, js_number, route_failure, time_params};

/// `buildMetricQuery(query, siteId, isCountQuery)`.
pub fn build_metric_query(
    query: &JsObject,
    site_id: i64,
    is_count_query: bool,
    now: &dyn Fn() -> f64,
) -> Result<String, BuildError> {
    let filters = query.get_or_undefined("filters");
    let parameter = query.get_or_undefined("parameter");
    let is_parameter = |name: &str| parameter.as_str() == Some(name);

    let time_statement = resolve_time_window_with_clock(&time_params(query), now)?.where_timestamp();
    let row_level_params = if is_parameter("event_name") { vec![FilterParameter::EventName] } else { Vec::new() };
    let fragments =
        build_session_and_row_filter_fragments(filters, site_id, &time_statement, &row_level_params, "FilteredSessions")?;
    let filtered_sessions_cte = fragments.filtered_sessions_cte;
    let row_filter_statement = fragments.row_filter_statement;
    let has_cte = filtered_sessions_cte.is_some();
    let session_join = if has_cte { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    let aliased_session_join = if has_cte { "INNER JOIN FilteredSessions fs ON e.session_id = fs.session_id" } else { "" };
    let with_filtered_sessions = filtered_sessions_cte.as_deref().map(|cte| format!("WITH {cte}")).unwrap_or_default();
    let cte_prefix = filtered_sessions_cte.as_deref().map(|cte| format!("{cte},")).unwrap_or_default();

    let pagination = get_pagination_statements(
        query.get_or_undefined("limit"),
        query.get_or_undefined("page"),
        100.0,
        is_count_query,
    );
    let limit_statement = &pagination.limit_statement;
    let offset_statement = &pagination.offset_statement;

    // A bounce is a session shorter than {bounceThreshold:UInt32} seconds; every
    // event in the window counts toward the length, heartbeats included
    let session_durations_cte = format!(
        "SessionDurations AS (
          SELECT
              session_id,
              dateDiff('second', min(timestamp), max(timestamp)) as session_duration
          FROM events
          WHERE
              site_id = {{siteId:Int32}}
              {time_statement}
          GROUP BY session_id
      )"
    );

    if is_parameter("event_name") {
        // Node's template carries a trailing space after `IS NOT NULL`
        let trailing_space = " ";
        if is_count_query {
            return Ok(format!(
                "
      {with_filtered_sessions}
      SELECT COUNT(DISTINCT event_name) as totalCount
      FROM events
      {session_join}
      WHERE
        site_id = {{siteId:Int32}}
        AND event_name IS NOT NULL{trailing_space}
        AND event_name <> ''
        {row_filter_statement}
        {time_statement}
        AND type = 'custom_event';
      "
            ));
        }
        return Ok(format!(
            "
    {with_filtered_sessions}
    SELECT
      event_name as value,
      COUNT(*) as count,
      ROUND(COUNT(distinct(session_id)) * 100.0 / SUM(COUNT(distinct(session_id))) OVER (), 2) as percentage
    FROM events
    {session_join}
    WHERE
      site_id = {{siteId:Int32}}
      AND event_name IS NOT NULL{trailing_space}
      AND event_name <> ''
      {row_filter_statement}
      {time_statement}
      AND type = 'custom_event'
    GROUP BY event_name ORDER BY count desc, event_name asc
    {limit_statement}
    {offset_statement};
  "
        ));
    }

    if is_parameter("page_title") {
        let core_page_title_logic = format!(
            "
      SELECT
          page_title as value,
          argMax(pathname, timestamp) as pathname,
          COUNT(DISTINCT session_id) as unique_sessions
      FROM events
      {session_join}
      WHERE
          site_id = {{siteId:Int32}}
          AND page_title IS NOT NULL
          AND page_title <> ''
          AND type = 'pageview'
          {time_statement}
      GROUP BY page_title
    "
        );
        if is_count_query {
            return Ok(format!("{with_filtered_sessions} SELECT COUNT(*) as totalCount FROM ({core_page_title_logic});"));
        }
        return Ok(format!(
            "
      WITH {cte_prefix} {session_durations_cte},
      TitleStatsWithSessions AS (
          SELECT
              e.page_title as value,
              e.pathname as pathname,
              e.session_id AS session_id,
              sd.session_duration
          FROM events e
          {aliased_session_join}
          LEFT JOIN SessionDurations sd ON e.session_id = sd.session_id
          WHERE
              e.site_id = {{siteId:Int32}}
              AND e.page_title IS NOT NULL
              AND e.page_title <> ''
              AND e.type = 'pageview'
              {time_statement}
      )
      SELECT
          value,       -- This is page_title
          any(pathname) as pathname,    -- This is the representative pathname
          COUNT(DISTINCT session_id) as count,
          ROUND(
              COUNT(DISTINCT session_id) * 100.0 / SUM(COUNT(DISTINCT session_id)) OVER (),
              2
          ) as percentage,
          ROUND(
              countIf(DISTINCT session_id, session_duration < {{bounceThreshold:UInt32}}) * 100.0 / nullIf(COUNT(DISTINCT session_id), 0),
              2
          ) as bounce_rate
      FROM TitleStatsWithSessions
      GROUP BY value
      ORDER BY count DESC, value ASC
      {limit_statement}
      {offset_statement};
    "
        ));
    }

    if is_parameter("exit_page") || is_parameter("entry_page") {
        let order_direction = if is_parameter("entry_page") { "ASC" } else { "DESC" };
        let base_cte_query = format!(
            "
      {session_durations_cte},
      RelevantEvents AS (
          SELECT
              e.session_id AS session_id,
              e.pathname AS pathname,
              e.hostname AS hostname,
              e.timestamp_ms AS timestamp_ms,
              sd.session_duration
          FROM events e
          {aliased_session_join}
          LEFT JOIN SessionDurations sd ON e.session_id = sd.session_id
          WHERE
              e.site_id = {{siteId:Int32}}
              AND e.type = 'pageview'
              {time_statement}
      ),
      EventTimes AS (
          SELECT
              session_id,
              pathname,
              hostname,
              timestamp_ms AS timestamp,
              session_duration,
              leadInFrame(timestamp_ms) OVER (PARTITION BY session_id ORDER BY timestamp_ms ROWS BETWEEN CURRENT ROW AND 1 FOLLOWING) as next_timestamp,
              row_number() OVER (PARTITION BY session_id ORDER BY timestamp_ms {order_direction}) as row_num
          FROM RelevantEvents
      ),
      PageDurations AS (
          SELECT
              session_id,
              pathname,
              hostname,
              timestamp,
              next_timestamp,
              row_num,
              session_duration,
              if(isNull(next_timestamp), 0, dateDiff('second', timestamp, next_timestamp)) as time_diff_seconds
          FROM EventTimes
      ),
      FilteredDurations AS (
          SELECT *
          FROM PageDurations
          WHERE row_num = 1
      ),
      PathStats AS (
          SELECT
              pathname,
              anyHeavy(hostname) as top_hostname,
              count(DISTINCT session_id) as unique_sessions,
              count() as visits,
              avg(if(time_diff_seconds < 0, 0, if(time_diff_seconds > 1800, 1800, time_diff_seconds))) as avg_time_on_page_seconds,
              countIf(DISTINCT session_id, session_duration < {{bounceThreshold:UInt32}}) as bounced_sessions
          FROM FilteredDurations
          WHERE pathname IS NOT NULL AND pathname <> ''
          GROUP BY pathname
      )
    "
        );
        if is_count_query {
            return Ok(format!(
                "
      WITH {cte_prefix} {base_cte_query}
      SELECT COUNT(DISTINCT pathname) as totalCount FROM PathStats;
      "
            ));
        }
        return Ok(format!(
            "
    WITH {cte_prefix} {base_cte_query}
    SELECT
        pathname as value,
        top_hostname as hostname,
        unique_sessions as count,
        round((unique_sessions / sum(unique_sessions) OVER ()) * 100, 2) as percentage,
        visits as pageviews,
        round((visits / sum(visits) OVER ()) * 100, 2) as pageviews_percentage,
        avg_time_on_page_seconds as time_on_page_seconds,
        round((bounced_sessions / nullIf(unique_sessions, 0)) * 100, 2) as bounce_rate
    FROM PathStats
    ORDER BY unique_sessions DESC, pathname ASC
    {limit_statement}
    {offset_statement};"
        ));
    }

    if is_parameter("pathname") {
        let base_cte_query = format!(
            "
      {session_durations_cte},
      EventTimes AS (
          SELECT
              e.session_id AS session_id,
              e.pathname,
              e.hostname,
              e.timestamp,
              sd.session_duration,
              leadInFrame(e.timestamp) OVER (PARTITION BY e.session_id ORDER BY e.timestamp ROWS BETWEEN CURRENT ROW AND 1 FOLLOWING) as next_timestamp
          FROM events e
          {aliased_session_join}
          LEFT JOIN SessionDurations sd ON e.session_id = sd.session_id
          WHERE
            e.site_id = {{siteId:Int32}}
            AND e.type = 'pageview'
            {time_statement}
      ),
      PageDurations AS (
          SELECT
              session_id,
              pathname,
              hostname,
              timestamp,
              next_timestamp,
              session_duration,
              if(isNull(next_timestamp), 0, dateDiff('second', timestamp, next_timestamp)) as time_diff_seconds
          FROM EventTimes
      ),
      PathStats AS (
          SELECT
              pathname,
              anyHeavy(hostname) as top_hostname,
              count() as visits,
              count(DISTINCT session_id) as unique_sessions,
              avg(if(time_diff_seconds < 0, 0, if(time_diff_seconds > 1800, 1800, time_diff_seconds))) as avg_time_on_page_seconds,
              countIf(DISTINCT session_id, session_duration < {{bounceThreshold:UInt32}}) as bounced_sessions
          FROM PageDurations
          GROUP BY pathname
      )
    "
        );
        if is_count_query {
            return Ok(format!(
                "
      WITH {cte_prefix} {base_cte_query}
      SELECT COUNT(DISTINCT pathname) as totalCount FROM PathStats;
      "
            ));
        }
        return Ok(format!(
            "
    WITH {cte_prefix} {base_cte_query}
    SELECT
        pathname as value,
        top_hostname as hostname,
        unique_sessions as count,
        round((unique_sessions / sum(unique_sessions) OVER ()) * 100, 2) as percentage,
        visits as pageviews,
        round((visits / sum(visits) OVER ()) * 100, 2) as pageviews_percentage,
        avg_time_on_page_seconds as time_on_page_seconds,
        round((bounced_sessions / nullIf(unique_sessions, 0)) * 100, 2) as bounce_rate
    FROM PathStats
    ORDER BY unique_sessions DESC, pathname ASC
    {limit_statement}
    {offset_statement};
    "
        ));
    }

    // Default case for other parameters: `getSqlParam` calls string methods on the
    // raw value, so anything but a string is a TypeError
    let Some(parameter_name) = parameter.as_str() else {
        return Err(BuildError::TypeError(format!(
            "parameter.startsWith is not a function (parameter is {})",
            parameter.type_of()
        )));
    };
    let sql_param = get_sql_param(parameter_name)?;

    // Sessions are attributed to their first attributed channel, not the first
    // event's channel (often 'Direct')
    let value_expression =
        if parameter_name == "channel" { SESSION_CHANNEL_AGG.to_string() } else { format!("argMin({sql_param}, e.timestamp)") };

    if is_count_query {
        return Ok(format!(
            "
    {with_filtered_sessions}
    SELECT COUNT(DISTINCT value) as totalCount
    FROM (
        SELECT
            {value_expression} as value
        FROM events e
        {aliased_session_join}
        WHERE
            e.site_id = {{siteId:Int32}}
            AND {sql_param} IS NOT NULL
            AND {sql_param} <> ''
            {time_statement}
        GROUP BY e.session_id
    );
    "
        ));
    }

    Ok(format!(
        "
    WITH {cte_prefix} {session_durations_cte},
    SessionData AS (
        SELECT
            {value_expression} as value,
            e.session_id AS session_id,
            any(sd.session_duration) as session_duration
        FROM events e
        {aliased_session_join}
        LEFT JOIN SessionDurations sd ON e.session_id = sd.session_id
        WHERE
            e.site_id = {{siteId:Int32}}
            AND {sql_param} IS NOT NULL
            AND {sql_param} <> ''
            {time_statement}
        GROUP BY e.session_id
    )
    SELECT
        value,
        COUNT(DISTINCT session_id) as count,
        round((COUNT(DISTINCT session_id) / sum(COUNT(DISTINCT session_id)) OVER ()) * 100, 2) as percentage,
        COUNT() as pageviews,
        round((COUNT() / sum(COUNT()) OVER ()) * 100, 2) as pageviews_percentage,
        round((countIf(DISTINCT session_id, session_duration < {{bounceThreshold:UInt32}}) / nullIf(COUNT(DISTINCT session_id), 0)) * 100, 2) as bounce_rate
    FROM SessionData
    GROUP BY value
    ORDER BY count desc, value asc
    {limit_statement}
    {offset_statement};
  "
    ))
}

/// `{ data: { data, totalCount } }`.
pub fn paginated_body(data: Vec<super::Row>, total_count: Value) -> Value {
    let mut inner = Map::new();
    inner.insert("data".to_string(), Value::Array(data.into_iter().map(Value::Object).collect()));
    inner.insert("totalCount".to_string(), total_count);
    let mut body = Map::new();
    body.insert("data".to_string(), Value::Object(inner));
    Value::Object(body)
}

/// `getMetric`: the error label is the raw `parameter` (`Failed to fetch undefined`
/// when it is missing).
pub(crate) async fn get_metric<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    let parameter = query.get_or_undefined("parameter");
    let label = parameter.to_js_string();
    let site = js_number(site_id);
    let result: Result<Reply, HandlerError> = async {
        let bounce_threshold = backend.bounce_threshold(site).await;
        let numeric_site = integral_site_id(site)?;
        let data_sql = build_metric_query(query, numeric_site, false, &|| backend.now_ms())?;
        let count_sql = build_metric_query(query, numeric_site, true, &|| backend.now_ms())?;
        let spec = |sql: String| QuerySpec::new(sql).param("siteId", site).param("bounceThreshold", bounce_threshold);
        let result = backend.run_paginated_query(&spec(data_sql), &spec(count_sql)).await?;
        debug!(site_id = site, parameter = %label, rows = result.data.len(), "metric fetched");
        Ok(Reply::ok(paginated_body(result.data, result.total_count)))
    }
    .await;
    result.or_else(|failure| route_failure(&label, &failure))
}

/// `parameter` as `getMetric` receives it, for tests and the lite fallback.
pub fn parameter_of(query: &JsObject) -> &JsValue {
    query.get_or_undefined("parameter")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::utils::session_attribution::SESSION_CHANNEL_AGG;

    fn base(overrides: &[(&str, JsValue)]) -> JsObject {
        let mut object: JsObject = [("start_date", ""), ("end_date", ""), ("time_zone", ""), ("filters", ""), ("parameter", "browser")]
            .iter()
            .map(|(key, value)| (key.to_string(), JsValue::from(*value)))
            .collect();
        for (key, value) in overrides {
            object.insert(*key, value.clone());
        }
        object
    }

    fn sql(overrides: &[(&str, JsValue)], count: bool) -> String {
        build_metric_query(&base(overrides), 1, count, &|| 0.0).unwrap()
    }

    fn parameter(name: &str) -> (&'static str, JsValue) {
        ("parameter", JsValue::from(name))
    }

    // Ported from getMetric.test.ts
    #[test]
    fn default_parameters_aggregate_per_session() {
        let text = sql(&[], false);
        assert!(text.contains("argMin(browser, e.timestamp) as value"));
        assert!(text.contains("GROUP BY e.session_id"));
        assert!(text.contains("LIMIT 100"));

        let text = sql(&[parameter("channel")], false);
        assert!(text.contains(&format!("{SESSION_CHANNEL_AGG} as value")));
        assert!(!text.contains("argMin(channel, e.timestamp)"));

        let text = sql(&[("limit", 25.0.into()), ("page", 3.0.into())], true);
        assert!(text.contains("COUNT(DISTINCT value) as totalCount"));
        assert!(!text.contains("LIMIT") && !text.contains("OFFSET"));
    }

    #[test]
    fn event_names() {
        let text = sql(&[parameter("event_name")], false);
        assert!(text.contains("event_name as value"));
        assert!(text.contains("AND type = 'custom_event'"));
        assert!(sql(&[parameter("event_name")], true).contains("COUNT(DISTINCT event_name) as totalCount"));

        let filters = r#"[{"parameter":"utm_campaign","type":"equals","value":["launch"]},{"parameter":"event_name","type":"equals","value":["signup"]}]"#;
        let text = sql(&[parameter("event_name"), ("filters", filters.into())], false);
        assert!(text.contains("FilteredSessions AS ("));
        assert!(text.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(text.contains("AND event_name = 'signup'"));
        assert!(!text[text.rfind("FROM events").unwrap()..].contains("url_parameters['utm_campaign']"));
    }

    #[test]
    fn page_titles() {
        let text = sql(&[parameter("page_title")], false);
        assert!(text.contains("SessionDurations"));
        assert!(text.contains("session_duration < {bounceThreshold:UInt32}"));
        assert!(text.contains("as bounce_rate"));
        assert!(sql(&[parameter("page_title")], true).contains("SELECT COUNT(*) as totalCount FROM ("));
    }

    #[test]
    fn entry_and_exit_pages() {
        let text = sql(&[parameter("entry_page")], false);
        assert!(text.contains("e.timestamp_ms AS timestamp_ms"));
        assert!(text.contains("timestamp_ms AS timestamp"));
        assert!(text.contains("ORDER BY timestamp_ms ASC) as row_num"));
        assert!(text.contains("WHERE row_num = 1"));
        assert!(text.contains("time_diff_seconds > 1800, 1800"));
        assert!(sql(&[parameter("exit_page")], false).contains("ORDER BY timestamp_ms DESC) as row_num"));
    }

    #[test]
    fn pathnames() {
        let text = sql(&[parameter("pathname")], false);
        assert!(text.contains("anyHeavy(hostname) as top_hostname"));
        assert!(text.contains("GROUP BY pathname"));

        let filters = r#"[{"parameter":"utm_campaign","type":"equals","value":["launch"]}]"#;
        let text = sql(&[parameter("pathname"), ("filters", filters.into())], false);
        assert!(text.contains("FilteredSessions AS ("));
        assert!(text.contains("INNER JOIN FilteredSessions fs ON e.session_id = fs.session_id"));
        assert!(!text[text.find("EventTimes AS (").unwrap()..].contains("url_parameters['utm_campaign']"));
    }

    #[test]
    fn pagination_and_windows() {
        let text = sql(&[("limit", 7.0.into()), ("page", 3.0.into())], false);
        assert!(text.contains("LIMIT 7") && text.contains("OFFSET 14"));
        let text = sql(&[("limit", 7.0.into()), ("page", 1.0.into())], false);
        assert!(text.contains("LIMIT 7") && !text.contains("OFFSET"));

        let text = sql(&[("start_date", "2024-01-01".into()), ("end_date", "2024-01-31".into()), ("time_zone", "UTC".into())], false);
        assert!(text.contains("AND timestamp >=") && text.contains("'2024-01-01'"));
        let text = sql(&[("filters", r#"[{"parameter":"country","type":"equals","value":["US"]}]"#.into())], false);
        assert!(text.contains("'US'"));
    }

    #[test]
    fn non_string_parameters_fail_like_node() {
        let mut query = base(&[]);
        query.remove("parameter");
        assert!(matches!(build_metric_query(&query, 1, false, &|| 0.0), Err(BuildError::TypeError(_))));
        assert!(matches!(
            build_metric_query(&base(&[parameter("nope")]), 1, false, &|| 0.0),
            Err(BuildError::UnknownParameter(_))
        ));
        assert!(sql(&[parameter("url_param:campaign")], false).contains("argMin(url_parameters['campaign'], e.timestamp)"));
    }
}
