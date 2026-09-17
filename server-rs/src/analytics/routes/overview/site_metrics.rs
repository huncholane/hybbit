//! Port of server/src/services/siteMetrics/siteMetrics.ts: the one definition of a
//! Site's headline metrics (sessions, pageviews, users, pages per session, bounce
//! rate, session duration) and of the single-dimension breakdowns beside them.
//!
//! The dashboard overview, the PDF report and the weekly email all report these
//! numbers, so the builders are public for the report ports. Everything is a pure
//! string builder emitting Node's SQL byte for byte.

use crate::analytics::{
    js::JsValue,
    utils::{
        effective_user_id::EFFECTIVE_SESSION_USER_ID,
        session_filters::build_filtered_sessions_cte,
        time_window::{TimeWindowParams, resolve_time_window_with_clock},
    },
};

use super::{BuildError, SESSION_JOIN};

/// `SiteMetricsSpec`: the window and filters a metrics query runs over.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SiteMetricsSpec {
    pub time_statement: String,
    /// Identifies the qualifying sessions when filters are present
    pub filtered_sessions_cte: Option<String>,
}

impl SiteMetricsSpec {
    fn cte_prefix(&self) -> String {
        self.filtered_sessions_cte.as_deref().map(|cte| format!("{cte},")).unwrap_or_default()
    }

    fn session_join(&self) -> &'static str {
        if self.filtered_sessions_cte.is_some() { SESSION_JOIN } else { "" }
    }
}

/// `buildMetricsSpecForWindow(filters, siteId, timeStatement)`: pairs the filters
/// with the window they apply to, so a session-level filter subquery can never
/// scan outside the reported period.
pub fn build_metrics_spec_for_window(
    filters: &JsValue,
    site_id: i64,
    time_statement: String,
) -> Result<SiteMetricsSpec, BuildError> {
    let filtered_sessions_cte = build_filtered_sessions_cte(filters, site_id, &time_statement, "FilteredSessions")?;
    Ok(SiteMetricsSpec { time_statement, filtered_sessions_cte })
}

/// `buildMetricsSpec(params, siteId)` from the shared HTTP filter params.
pub fn build_metrics_spec(
    params: &TimeWindowParams,
    filters: &JsValue,
    site_id: i64,
    now: &dyn Fn() -> f64,
) -> Result<SiteMetricsSpec, BuildError> {
    let time_statement = resolve_time_window_with_clock(params, now)?.where_timestamp();
    build_metrics_spec_for_window(filters, site_id, time_statement)
}

/// `buildOverviewQuery(spec)`: binds `{siteId:Int32}` and `{bounceThreshold:UInt32}`.
/// Filters qualify session ids first, so a session keeps its full duration and
/// pageviews instead of turning into a bounce because the filter matched only its
/// landing event.
pub fn build_overview_query(spec: &SiteMetricsSpec) -> String {
    let cte = spec.cte_prefix();
    let session_join = spec.session_join();
    let time_statement = &spec.time_statement;
    format!(
        "
    WITH
    {cte}
    FilteredSessionsWithStats AS (
        SELECT
            session_id,
            -- Aliased away from `user_id` on purpose: an alias that shadows a column
            -- referenced inside its own expression is a cyclic-alias error in ClickHouse.
            {EFFECTIVE_SESSION_USER_ID} AS effective_user_id,
            MIN(timestamp) AS start_time,
            MAX(timestamp) AS end_time,
            countIf(type = 'pageview') AS pageviews
        FROM events
        {session_join}
        WHERE
            site_id = {{siteId:Int32}}
            {time_statement}
        GROUP BY session_id
    )
    SELECT
        COUNT() AS sessions,
        AVG(f.pageviews) AS pages_per_session,
        sumIf(1, dateDiff('second', f.start_time, f.end_time) < {{bounceThreshold:UInt32}}) / COUNT() * 100 AS bounce_rate,
        AVG(f.end_time - f.start_time) AS session_duration,
        SUM(f.pageviews) AS pageviews,
        COUNT(DISTINCT f.effective_user_id) AS users
    FROM FilteredSessionsWithStats f"
    )
}

/// `BreakdownDimension`: the dimensions a report can be broken down by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakdownDimension {
    Browser,
    City,
    Country,
    DeviceType,
    OperatingSystem,
    Pathname,
    Referrer,
    Region,
}

impl BreakdownDimension {
    pub const ALL: [BreakdownDimension; 8] = [
        BreakdownDimension::Browser,
        BreakdownDimension::City,
        BreakdownDimension::Country,
        BreakdownDimension::DeviceType,
        BreakdownDimension::OperatingSystem,
        BreakdownDimension::Pathname,
        BreakdownDimension::Referrer,
        BreakdownDimension::Region,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            BreakdownDimension::Browser => "browser",
            BreakdownDimension::City => "city",
            BreakdownDimension::Country => "country",
            BreakdownDimension::DeviceType => "device_type",
            BreakdownDimension::OperatingSystem => "operating_system",
            BreakdownDimension::Pathname => "pathname",
            BreakdownDimension::Referrer => "referrer",
            BreakdownDimension::Region => "region",
        }
    }

    /// `DIMENSIONS[dimension]`: the grouped expression and an extra predicate.
    fn definition(self) -> (&'static str, &'static str) {
        match self {
            // A page counts where it was actually viewed; the other dimensions are
            // session properties carried on every event
            BreakdownDimension::Pathname => ("pathname", "AND type = 'pageview'"),
            BreakdownDimension::Referrer => ("domainWithoutWWW(referrer)", ""),
            other => (other.as_str(), ""),
        }
    }
}

/// `buildBreakdownQuery(dimension, spec)`: the top values ranked by sessions with
/// each value's share. Binds `{siteId:Int32}` and `{limit:Int32}`. Empty values
/// are dropped for every dimension, `pathname` included.
pub fn build_breakdown_query(dimension: BreakdownDimension, spec: &SiteMetricsSpec) -> String {
    let (expression, restriction) = dimension.definition();
    let cte = spec.cte_prefix();
    let session_join = spec.session_join();
    let time_statement = &spec.time_statement;
    format!(
        "
    WITH {cte} BreakdownStats AS (
      SELECT
        {expression} AS value,
        COUNT(DISTINCT session_id) AS unique_sessions
      FROM events
      {session_join}
      WHERE
        site_id = {{siteId:Int32}}
        AND {expression} IS NOT NULL
        AND {expression} <> ''
        {restriction}
        {time_statement}
      GROUP BY value
    )
    SELECT
      value,
      unique_sessions AS count,
      round((unique_sessions / SUM(unique_sessions) OVER ()) * 100, 2) AS percentage
    FROM BreakdownStats
    ORDER BY count DESC, value ASC
    LIMIT {{limit:Int32}}"
    )
}

/// `ChartBucketFunction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChartBucketFunction {
    Hour,
    Day,
    Week,
}

impl ChartBucketFunction {
    pub fn as_str(self) -> &'static str {
        match self {
            ChartBucketFunction::Hour => "toStartOfHour",
            ChartBucketFunction::Day => "toStartOfDay",
            ChartBucketFunction::Week => "toStartOfWeek",
        }
    }
}

/// `buildChartQuery(spec, bucketFn)`: sessions bucketed by session start beside
/// pageviews bucketed by event time. Binds `{siteId:Int32}` and `{timeZone:String}`.
pub fn build_chart_query(spec: &SiteMetricsSpec, bucket_fn: ChartBucketFunction) -> String {
    let cte = spec.cte_prefix();
    let session_join = spec.session_join();
    let time_statement = &spec.time_statement;
    let bucket = |column: &str| {
        format!(
            "toString(toTimeZone({}(toTimeZone({column}, {{timeZone:String}})), {{timeZone:String}}))",
            bucket_fn.as_str()
        )
    };
    let session_start = bucket("session_start");
    let timestamp = bucket("timestamp");
    format!(
        "
    WITH
    {cte}
    SessionStarts AS (
      SELECT
        session_id,
        min(timestamp) AS session_start
      FROM events
      {session_join}
      WHERE
        site_id = {{siteId:Int32}}
        {time_statement}
      GROUP BY session_id
    ),
    SessionStats AS (
      SELECT
        {session_start} AS time,
        count() AS sessions
      FROM SessionStarts
      GROUP BY time
    ),
    PageStats AS (
      SELECT
        {timestamp} AS time,
        countIf(type = 'pageview') AS pageviews
      FROM events
      {session_join}
      WHERE
        site_id = {{siteId:Int32}}
        {time_statement}
      GROUP BY time
    )
    SELECT
      time,
      coalesce(sessions, 0) AS sessions,
      coalesce(pageviews, 0) AS pageviews
    FROM SessionStats
    FULL JOIN PageStats USING (time)
    ORDER BY time"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::{js::JsObject, utils::time_window::get_time_statement};

    const SITE_ID: i64 = 1;

    fn params(pairs: &[(&str, &str)]) -> TimeWindowParams {
        TimeWindowParams::from_object(&pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect::<JsObject>())
    }

    fn dashboard_params() -> TimeWindowParams {
        params(&[("start_date", "2026-07-17"), ("end_date", "2026-07-23"), ("time_zone", "UTC")])
    }

    fn spec_for(time: TimeWindowParams) -> SiteMetricsSpec {
        SiteMetricsSpec { time_statement: get_time_statement(&time, "timestamp").unwrap(), filtered_sessions_cte: None }
    }

    fn without_time_bound(sql: &str, spec: &SiteMetricsSpec) -> String {
        sql.replacen(&spec.time_statement, "<TIME>", 1).replacen(&spec.time_statement, "<TIME>", 1)
    }

    fn filters(json: &str) -> JsValue {
        JsValue::from(json)
    }

    // Ported from siteMetrics.test.ts
    #[test]
    fn one_overview_definition_across_surfaces() {
        let dashboard_spec =
            build_metrics_spec(&dashboard_params(), &JsValue::from(""), SITE_ID, &|| 0.0).unwrap();
        let dashboard = without_time_bound(&build_overview_query(&dashboard_spec), &dashboard_spec);
        let pdf_spec = spec_for(dashboard_params());
        let weekly_spec = spec_for(params(&[("start_datetime", "2026-07-17 00:00:00"), ("end_datetime", "2026-07-24 00:00:00")]));
        assert_eq!(without_time_bound(&build_overview_query(&pdf_spec), &pdf_spec), dashboard);
        assert_eq!(without_time_bound(&build_overview_query(&weekly_spec), &weekly_spec), dashboard);
        assert!(!dashboard.contains(&dashboard_spec.time_statement));

        let pdf = without_time_bound(&build_breakdown_query(BreakdownDimension::Country, &pdf_spec), &pdf_spec);
        let weekly = without_time_bound(&build_breakdown_query(BreakdownDimension::Country, &weekly_spec), &weekly_spec);
        assert_eq!(weekly, pdf);
    }

    #[test]
    fn overview_counts_users_by_identity_once_per_session() {
        let spec = spec_for(dashboard_params());
        let sql = build_overview_query(&spec);
        assert!(sql.contains("COUNT(DISTINCT f.effective_user_id) AS users"));
        assert!(sql.contains("anyIf(identified_user_id, identified_user_id != '')"));
        assert!(sql.contains("anyLast(user_id)"));
        let session_cte = sql.split("FilteredSessionsWithStats AS (").nth(1).unwrap().split("GROUP BY session_id").next().unwrap();
        assert!(session_cte.contains("anyIf(identified_user_id"));
        assert!(!sql.contains("anyLast(user_id)) AS user_id"));
    }

    #[test]
    fn overview_bounces_and_session_qualification() {
        let chrome = filters(r#"[{"parameter":"browser","type":"equals","value":["Chrome"]}]"#);
        let sql = build_overview_query(&build_metrics_spec_for_window(&chrome, SITE_ID, String::new()).unwrap());
        assert!(sql.contains(
            "sumIf(1, dateDiff('second', f.start_time, f.end_time) < {bounceThreshold:UInt32}) / COUNT() * 100 AS bounce_rate"
        ));
        assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(sql.contains("browser = 'Chrome'"));
        let filtered_cte = sql.split("FilteredSessionsWithStats AS (").nth(1).unwrap();
        assert!(filtered_cte.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(!filtered_cte.contains("browser = 'Chrome'"));
    }

    #[test]
    fn breakdown_dimensions() {
        let spec = spec_for(dashboard_params());
        for (dimension, column) in [
            (BreakdownDimension::Browser, "browser"),
            (BreakdownDimension::City, "city"),
            (BreakdownDimension::Country, "country"),
            (BreakdownDimension::DeviceType, "device_type"),
            (BreakdownDimension::OperatingSystem, "operating_system"),
            (BreakdownDimension::Pathname, "pathname"),
            (BreakdownDimension::Referrer, "domainWithoutWWW(referrer)"),
            (BreakdownDimension::Region, "region"),
        ] {
            let sql = build_breakdown_query(dimension, &spec);
            assert!(sql.contains(&format!("{column} AS value")), "{column}");
            assert!(sql.contains("COUNT(DISTINCT session_id) AS unique_sessions"));
            assert!(sql.contains("LIMIT {limit:Int32}"));
            assert!(sql.contains(&spec.time_statement));
            assert!(sql.contains(&format!("AND {column} <> ''")), "empty values dropped for {column}");
        }
        assert!(build_breakdown_query(BreakdownDimension::Pathname, &spec).contains("AND type = 'pageview'"));
        assert!(!build_breakdown_query(BreakdownDimension::Country, &spec).contains("AND type = 'pageview'"));
    }

    #[test]
    fn chart_buckets_sessions_by_start() {
        let spec = spec_for(dashboard_params());
        let sql = build_chart_query(&spec, ChartBucketFunction::Day);
        assert!(sql.contains("toString(toTimeZone(toStartOfDay(toTimeZone(session_start, {timeZone:String})), {timeZone:String})) AS time"));
        assert!(sql.contains("FULL JOIN PageStats USING (time)"));
        assert_eq!(sql.matches(&spec.time_statement).count(), 2);
    }
}
