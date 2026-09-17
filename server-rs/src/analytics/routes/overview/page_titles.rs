//! GET /api/sites/:siteId/page-titles (server/src/api/analytics/getPageTitles.ts):
//! page titles ranked by sessions, untitled pageviews kept as one row per pathname.

use tracing::debug;

use crate::analytics::{
    js::JsObject,
    utils::{
        analytics_query::{QuerySpec, get_pagination_statements},
        session_filters::build_filtered_sessions_cte,
        time_window::resolve_time_window_with_clock,
    },
};

use super::{Outcome, 
    BuildError, HandlerError, OverviewBackend, Reply, SESSION_JOIN, integral_site_id, js_number,
    metric::paginated_body, overview::data_rows, route_failure, time_params,
};

/// `buildPageTitlesQuery(query, siteId, isCountQuery)`.
pub fn build_page_titles_query(
    query: &JsObject,
    site_id: i64,
    is_count_query: bool,
    now: &dyn Fn() -> f64,
) -> Result<String, BuildError> {
    let time_statement = resolve_time_window_with_clock(&time_params(query), now)?.where_timestamp();
    let filtered_sessions_cte =
        build_filtered_sessions_cte(query.get_or_undefined("filters"), site_id, &time_statement, "FilteredSessions")?;
    let session_join = if filtered_sessions_cte.is_some() { SESSION_JOIN } else { "" };

    // StandardSection shows a handful of rows; 10 by default when not paginated
    let pagination =
        get_pagination_statements(query.get_or_undefined("limit"), query.get_or_undefined("page"), 10.0, is_count_query);
    let limit_statement = &pagination.limit_statement;
    let offset_statement = &pagination.offset_statement;
    let cte_prefix = filtered_sessions_cte.map(|cte| format!("{cte},")).unwrap_or_default();

    let base_cte_query = format!(
        "
    SessionDurations AS (
        -- A bounce is a session shorter than the Site's bounce threshold; every event
        -- counts toward the length, heartbeats included
        SELECT
            session_id,
            dateDiff('second', min(timestamp), max(timestamp)) as session_duration
        FROM events
        {session_join}
        WHERE
            site_id = {{siteId:Int32}}
            {time_statement}
        GROUP BY session_id
    ),
    EventTimes AS (
        SELECT
            session_id,
            page_title,
            pathname,
            timestamp,
            leadInFrame(timestamp) OVER (PARTITION BY session_id ORDER BY timestamp ROWS BETWEEN CURRENT ROW AND 1 FOLLOWING) as next_timestamp
        FROM events
        {session_join}
        WHERE
          site_id = {{siteId:Int32}}
          AND type = 'pageview'
          {time_statement}
    ),
    PageDurations AS (
        SELECT
            e.session_id as session_id,
            e.page_title as page_title,
            e.pathname as pathname,
            e.timestamp as timestamp,
            e.next_timestamp as next_timestamp,
            if(isNull(e.next_timestamp), 0, dateDiff('second', e.timestamp, e.next_timestamp)) as time_diff_seconds,
            sd.session_duration as session_duration
        FROM EventTimes e
        LEFT JOIN SessionDurations sd ON e.session_id = sd.session_id
    ),
    PageTitleStats AS (
        SELECT
            pd.page_title as value,
            -- Preserve the existing title grouping, but do not merge every untitled URL into one row.
            if(pd.page_title = '', pd.pathname, '') as untitled_pathname,
            argMax(pd.pathname, pd.timestamp) as pathname,
            count(DISTINCT session_id) as unique_sessions,
            count() as pageviews,
            countIf(DISTINCT session_id, session_duration < {{bounceThreshold:UInt32}}) as bounced_sessions,
            avg(if(time_diff_seconds < 0, 0, if(time_diff_seconds > 1800, 1800, time_diff_seconds))) as avg_time_on_page_seconds
        FROM PageDurations pd
        GROUP BY pd.page_title, untitled_pathname
    )
  "
    );

    if is_count_query {
        return Ok(format!(
            "
    WITH {cte_prefix} {base_cte_query}
    SELECT COUNT(*) as totalCount FROM PageTitleStats;
    "
        ));
    }

    Ok(format!(
        "
    WITH {cte_prefix} {base_cte_query}
    SELECT
        value,
        pathname,
        unique_sessions as count,
        ROUND(
            unique_sessions * 100.0 / SUM(unique_sessions) OVER (),
            2
        ) as percentage,
        pageviews,
        ROUND(
            bounced_sessions * 100.0 / nullIf(unique_sessions, 0),
            2
        ) as bounce_rate,
        avg_time_on_page_seconds as time_on_page_seconds
    FROM PageTitleStats
    ORDER BY count DESC
    {limit_statement}
    {offset_statement}
  "
    ))
}

/// `getPageTitles`: `{ data: { data, totalCount } }` when `page` is present,
/// `{ data: rows }` otherwise.
pub(crate) async fn get_page_titles<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    const LABEL: &str = "page titles";
    let site = js_number(site_id);
    let result: Result<Reply, HandlerError> = async {
        let bounce_threshold = backend.bounce_threshold(site).await;
        let numeric_site = integral_site_id(site)?;
        let spec = |sql: String| QuerySpec::new(sql).param("siteId", site).param("bounceThreshold", bounce_threshold);
        let data_spec = spec(build_page_titles_query(query, numeric_site, false, &|| backend.now_ms())?);

        if !query.get_or_undefined("page").is_undefined() {
            let count_spec = spec(build_page_titles_query(query, numeric_site, true, &|| backend.now_ms())?);
            let result = backend.run_paginated_query(&data_spec, &count_spec).await?;
            debug!(site_id = site, rows = result.data.len(), paginated = true, "page titles fetched");
            return Ok(Reply::ok(paginated_body(result.data, result.total_count)));
        }

        let rows = backend.run_analytics_query(&data_spec).await?;
        debug!(site_id = site, rows = rows.len(), paginated = false, "page titles fetched");
        Ok(Reply::ok(data_rows(rows)))
    }
    .await;
    result.or_else(|failure| route_failure(LABEL, &failure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::JsValue;

    fn base(overrides: &[(&str, JsValue)]) -> JsObject {
        let mut object: JsObject = [("start_date", ""), ("end_date", ""), ("time_zone", ""), ("filters", "")]
            .iter()
            .map(|(key, value)| (key.to_string(), JsValue::from(*value)))
            .collect();
        for (key, value) in overrides {
            object.insert(*key, value.clone());
        }
        object
    }

    // Ported from getPageTitles.test.ts
    #[test]
    fn untitled_pageviews_are_rows_per_pathname() {
        let sql = build_page_titles_query(&base(&[]), 1, false, &|| 0.0).unwrap();
        assert!(!sql.contains("page_title IS NOT NULL"));
        assert!(!sql.contains("page_title <> ''"));
        assert!(sql.contains("if(pd.page_title = '', pd.pathname, '') as untitled_pathname"));
        assert!(sql.contains("GROUP BY pd.page_title, untitled_pathname"));
    }

    #[test]
    fn untitled_rows_count_in_pagination_totals() {
        let sql = build_page_titles_query(&base(&[("limit", 25.0.into()), ("page", 2.0.into())]), 1, true, &|| 0.0).unwrap();
        assert!(sql.contains("GROUP BY pd.page_title, untitled_pathname"));
        assert!(sql.contains("SELECT COUNT(*) as totalCount FROM PageTitleStats"));
        assert!(!sql.contains("LIMIT 25") && !sql.contains("OFFSET 25"));
    }

    // Ported from sessionScopedQueries.test.ts
    #[test]
    fn titles_come_from_all_pageviews_of_qualifying_sessions() {
        let campaign = r#"[{"parameter":"utm_campaign","type":"equals","value":["recipe_book_2026"]}]"#;
        let query = base(&[
            ("start_date", "2026-08-01".into()),
            ("end_date", "2026-08-31".into()),
            ("time_zone", "UTC".into()),
            ("filters", campaign.into()),
        ]);
        let sql = build_page_titles_query(&query, 1, false, &|| 0.0).unwrap();
        assert!(sql.contains("FilteredSessions AS ("));
        assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(!sql[sql.find("EventTimes AS (").unwrap()..].contains("url_parameters['utm_campaign']"));
    }
}
