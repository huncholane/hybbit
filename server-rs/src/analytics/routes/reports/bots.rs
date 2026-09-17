//! Bot analytics, ported from server/src/api/analytics/bots: detection totals
//! (getBotOverview.ts), requests over time (getBotTimeSeries.ts), breakdowns
//! (getBotDimension.ts), AI crawls against AI referrals (getBotAiSummary.ts) and
//! the clause builders they share (utils.ts).

use std::collections::HashSet;

use axum::{http::StatusCode, response::Response};
use serde_json::{Value, json};
use tracing::debug;

use crate::{
    analytics::{
        js::{JsObject, JsValue, number::string_to_number},
        types::FilterParameter,
        utils::{
            analytics_query::{QuerySpec, get_pagination_statements},
            get_filter_statement::{FilterStatementOptions, get_filter_statement, get_sql_param},
            time_window::{TimeWindowParams, get_time_statement, resolve_time_window},
        },
    },
    state::AppState,
};

use super::{
    performance::{analytics_read_route, requested_bucket},
    support::{JsError, analytics_clickhouse, object_prototype_text, send_json, template},
};

type BuildResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// `AI_PURPOSE_SQL_LIST`
const AI_PURPOSE_SQL_LIST: &str = "'ai_training', 'ai_search', 'ai_agent'";
/// `AI_CRAWLER_PURPOSE_SQL_LIST`
const AI_CRAWLER_PURPOSE_SQL_LIST: &str = "'ai_training', 'ai_search'";

/// `BOT_PURPOSES`
const BOT_PURPOSES: [&str; 10] =
    ["ai_training", "ai_search", "ai_agent", "search", "social_preview", "seo", "monitoring", "security", "scripted", "headless"];

/// `BOT_DIMENSIONS`
const BOT_DIMENSIONS: [&str; 19] = [
    "browser",
    "browser_version",
    "operating_system",
    "operating_system_version",
    "country",
    "region",
    "city",
    "device_type",
    "referrer",
    "hostname",
    "pathname",
    "dimensions",
    "asn_org",
    "asn_provider",
    "bot_category",
    "bot_name",
    "bot_operator",
    "bot_purpose",
    "matched_ua_pattern",
];

/// `BOT_ONLY_DIMENSIONS`: columns that exist only on `bot_events`.
const BOT_ONLY_DIMENSIONS: [&str; 7] =
    ["asn_org", "asn_provider", "bot_category", "bot_name", "bot_operator", "bot_purpose", "matched_ua_pattern"];

/// `AI_REFERRER_DOMAIN_TO_OPERATOR` (shared/src/aiOperators.ts), in insertion order.
pub const AI_REFERRER_DOMAIN_TO_OPERATOR: [(&str, &str); 13] = [
    ("chatgpt.com", "OpenAI"),
    ("chat.openai.com", "OpenAI"),
    ("claude.ai", "Anthropic"),
    ("gemini.google.com", "Google"),
    ("copilot.microsoft.com", "Microsoft"),
    ("perplexity.ai", "Perplexity"),
    ("meta.ai", "Meta"),
    ("chat.mistral.ai", "Mistral"),
    ("mistral.ai", "Mistral"),
    ("grok.com", "xAI"),
    ("you.com", "You.com"),
    ("cursor.com", "Cursor"),
    ("coral.cohere.com", "Cohere"),
];

/// `getBotPurposeStatement(purpose)`: a known purpose or family, else nothing (the
/// value is interpolated, so only allowlisted spellings reach SQL).
pub fn get_bot_purpose_statement(purpose: &JsValue) -> String {
    if !purpose.is_truthy() {
        return String::new();
    }
    match purpose.as_str() {
        Some("ai") => format!("AND bot_purpose IN ({AI_PURPOSE_SQL_LIST})"),
        Some("ai_crawler") => format!("AND bot_purpose IN ({AI_CRAWLER_PURPOSE_SQL_LIST})"),
        Some(known) if BOT_PURPOSES.contains(&known) => format!("AND bot_purpose = '{known}'"),
        _ => String::new(),
    }
}

/// `getBotLayerStatement(layer)`: `BOT_LAYER_COLUMNS[layer]`, which also finds the
/// `Object.prototype` members (a native function prints its source, and
/// ClickHouse rejects the result).
pub fn get_bot_layer_statement(layer: &JsValue) -> String {
    if !layer.is_truthy() {
        return String::new();
    }
    let key = layer.to_js_string();
    let column = match key.as_str() {
        "ua_pattern" => "detected_ua_pattern",
        "header_heuristics" => "detected_header_heuristics",
        "client_signals" => "detected_client_signals",
        "bot_asn" => "detected_bot_asn",
        "rate_anomaly" => "detected_rate_anomaly",
        other => match object_prototype_text(other) {
            Some(text) => text,
            None => return String::new(),
        },
    };
    format!("AND {column}")
}

/// `getBotSqlParam(dimension)` for a dimension already in `BOT_DIMENSIONS`.
pub fn get_bot_sql_param(dimension: &str) -> BuildResult<String> {
    if BOT_ONLY_DIMENSIONS.contains(&dimension) {
        return Ok(dimension.to_string());
    }
    Ok(get_sql_param(dimension)?)
}

/// `BOT_FILTER_PARAMETERS`
fn bot_filter_parameters() -> HashSet<FilterParameter> {
    use FilterParameter::*;
    [
        Browser,
        BrowserVersion,
        OperatingSystem,
        OperatingSystemVersion,
        Country,
        Region,
        City,
        DeviceType,
        Referrer,
        Hostname,
        Pathname,
        Querystring,
        Dimensions,
        UserId,
        Lat,
        Lon,
    ]
    .into_iter()
    .collect()
}

/// `getBotFilterStatement(filters)`: `bot_events` is flat (no session subqueries),
/// has no `identified_user_id`, and only a subset of parameters apply; the rest
/// are dropped silently.
pub fn get_bot_filter_statement(filters: &JsValue) -> BuildResult<String> {
    let options = FilterStatementOptions {
        session_level_params: Some(Vec::new()),
        field_mappings: None,
        parameter_allowlist: Some(bot_filter_parameters()),
        dual_user_id_columns: Some(false),
    };
    Ok(get_filter_statement(filters, None, None, &options)?)
}

/// `buildBotOverviewQuery(query)`.
pub fn build_bot_overview_query(query: &JsObject) -> BuildResult<String> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = get_bot_filter_statement(query.get_or_undefined("filters"))?;
    let layer_statement = get_bot_layer_statement(query.get_or_undefined("layer"));
    Ok(template(
        r#"
    WITH
      bot_stats AS (
        SELECT
          count() AS bot_requests,
          countIf(detected_ua_pattern) AS ua_pattern,
          countIf(detected_header_heuristics) AS header_heuristics,
          countIf(detected_client_signals) AS client_signals,
          countIf(detected_bot_asn) AS bot_asn,
          countIf(detected_rate_anomaly) AS rate_anomaly,
          -- Purpose is only set on rows written since bot identity shipped, so
          -- these read 0 for older windows rather than being wrong.
          countIf(bot_purpose IN (${ai_purposes})) AS ai_requests,
          countIf(bot_purpose = 'ai_agent') AS ai_agent_requests,
          countIf(bot_purpose IN (${ai_crawler_purposes})) AS ai_crawler_requests
        FROM bot_events
        WHERE site_id = {siteId:Int32}
          ${filter_statement}
          ${layer_statement}
          ${time_statement}
      ),
      all_bot_stats AS (
        SELECT count() AS all_bot_requests
        FROM bot_events
        WHERE site_id = {siteId:Int32}
          ${filter_statement}
          ${time_statement}
      ),
      event_stats AS (
        SELECT count() AS event_requests
        FROM events
        WHERE site_id = {siteId:Int32}
          ${filter_statement}
          ${time_statement}
      )
    SELECT
      bot_requests,
      all_bot_requests + event_requests AS total_events,
      if(
        all_bot_requests + event_requests = 0,
        0,
        round(bot_requests * 100.0 / (all_bot_requests + event_requests), 2)
      ) AS bot_percentage,
      ua_pattern,
      header_heuristics,
      client_signals,
      bot_asn,
      rate_anomaly,
      ai_requests,
      ai_agent_requests,
      ai_crawler_requests
    FROM bot_stats
    CROSS JOIN all_bot_stats
    CROSS JOIN event_stats
  "#,
        &[
            ("ai_purposes", AI_PURPOSE_SQL_LIST),
            ("ai_crawler_purposes", AI_CRAWLER_PURPOSE_SQL_LIST),
            ("filter_statement", &filter_statement),
            ("layer_statement", &layer_statement),
            ("time_statement", &time_statement),
        ],
    ))
}

/// `buildBotTimeSeriesQuery(query)`.
pub fn build_bot_time_series_query(query: &JsObject) -> BuildResult<String> {
    let window = resolve_time_window(&TimeWindowParams::from_object(query))?;
    let time_statement = window.where_timestamp();
    let filter_statement = get_bot_filter_statement(query.get_or_undefined("filters"))?;
    let layer_statement = get_bot_layer_statement(query.get_or_undefined("layer"));
    let purpose_statement = get_bot_purpose_statement(query.get_or_undefined("purpose"));
    let bucket = requested_bucket(query)?;
    Ok(template(
        r#"
    SELECT
      ${bucketed} AS time,
      count() AS bot_requests,
      -- Returned on every bucket so the chart can draw agents against crawlers
      -- without a second round trip; both read 0 on windows predating identity.
      countIf(bot_purpose = 'ai_agent') AS ai_agent_requests,
      countIf(bot_purpose IN (${ai_crawler_purposes})) AS ai_crawler_requests
    FROM bot_events
    WHERE site_id = {siteId:Int32}
      ${filter_statement}
      ${layer_statement}
      ${purpose_statement}
      ${time_statement}
    GROUP BY time
    ORDER BY time ${fill}
  "#,
        &[
            ("bucketed", &window.bucketed("timestamp", bucket)),
            ("ai_crawler_purposes", AI_CRAWLER_PURPOSE_SQL_LIST),
            ("filter_statement", &filter_statement),
            ("layer_statement", &layer_statement),
            ("purpose_statement", &purpose_statement),
            ("time_statement", &time_statement),
            ("fill", &window.fill(bucket)),
        ],
    ))
}

/// `buildBotDimensionQuery(query, isCountQuery)`.
pub fn build_bot_dimension_query(query: &JsObject, is_count_query: bool) -> BuildResult<String> {
    let dimension_value = query.get_or_undefined("dimension");
    let Some(dimension) = dimension_value.as_str().filter(|dimension| BOT_DIMENSIONS.contains(dimension)) else {
        return Err(JsError::new(format!("Unsupported bot dimension: {}", dimension_value.to_js_string())).into());
    };

    let expression = get_bot_sql_param(dimension)?;
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filter_statement = get_bot_filter_statement(query.get_or_undefined("filters"))?;
    let layer_statement = get_bot_layer_statement(query.get_or_undefined("layer"));
    let purpose_statement = get_bot_purpose_statement(query.get_or_undefined("purpose"));
    let pagination = get_pagination_statements(query.get_or_undefined("limit"), query.get_or_undefined("page"), 100.0, is_count_query);

    let grouped = template(
        r#"
    SELECT
      ${expression} AS value,
      ${hostname} AS hostname,
      count() AS count,
      round(count() * 100.0 / sum(count()) OVER (), 2) AS percentage
    FROM bot_events
    WHERE site_id = {siteId:Int32}
      ${filter_statement}
      ${layer_statement}
      ${purpose_statement}
      ${time_statement}
    GROUP BY value
  "#,
        &[
            ("expression", &expression),
            ("hostname", if dimension == "pathname" { "any(hostname)" } else { "''" }),
            ("filter_statement", &filter_statement),
            ("layer_statement", &layer_statement),
            ("purpose_statement", &purpose_statement),
            ("time_statement", &time_statement),
        ],
    );

    if is_count_query {
        return Ok(template(
            r#"
      SELECT count() AS totalCount
      FROM (${grouped})
    "#,
            &[("grouped", &grouped)],
        ));
    }
    Ok(template(
        r#"
    ${grouped}
    ORDER BY count DESC
    ${limit}
    ${offset}
  "#,
        &[("grouped", &grouped), ("limit", &pagination.limit_statement), ("offset", &pagination.offset_statement)],
    ))
}

/// `buildReferrerOperatorExpression()`: a `transform()` mapping a referrer domain
/// onto its operator, spelled as the bot patterns spell it so the halves join.
fn referrer_operator_expression() -> String {
    let domains = AI_REFERRER_DOMAIN_TO_OPERATOR.iter().map(|(domain, _)| format!("'{domain}'")).collect::<Vec<_>>().join(", ");
    let operators = AI_REFERRER_DOMAIN_TO_OPERATOR.iter().map(|(_, operator)| format!("'{operator}'")).collect::<Vec<_>>().join(", ");
    format!("transform(domainWithoutWWW(referrer), [{domains}], [{operators}], '')")
}

/// `buildBotAiSummaryQuery(query)`.
pub fn build_bot_ai_summary_query(query: &JsObject) -> BuildResult<String> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let filters = query.get_or_undefined("filters");
    let bot_filter_statement = get_bot_filter_statement(filters)?;
    // The referral half reads `events`, so it takes the events-surface builder
    let event_filter_statement = get_filter_statement(filters, None, None, &FilterStatementOptions::default())?;
    Ok(template(
        r#"
    WITH
      crawls AS (
        SELECT
          bot_operator AS operator,
          count() AS crawls,
          countIf(bot_purpose = 'ai_training') AS training_crawls,
          countIf(bot_purpose = 'ai_search') AS search_crawls,
          countIf(bot_purpose = 'ai_agent') AS agent_requests
        FROM bot_events
        WHERE site_id = {siteId:Int32}
          AND bot_operator != ''
          AND bot_purpose IN (${ai_purposes})
          ${bot_filter_statement}
          ${time_statement}
        GROUP BY operator
      ),
      referrals AS (
        SELECT
          ${referrer_operator} AS operator,
          count() AS referrals
        FROM events
        WHERE site_id = {siteId:Int32}
          AND channel = 'AI'
          ${event_filter_statement}
          ${time_statement}
        GROUP BY operator
        HAVING operator != ''
      )
    SELECT
      -- FULL OUTER JOIN so an operator that only crawls and one that only
      -- refers both survive; the empty side of the join reads 0, not absent.
      if(crawls.operator != '', crawls.operator, referrals.operator) AS operator,
      crawls.crawls AS crawls,
      crawls.training_crawls AS training_crawls,
      crawls.search_crawls AS search_crawls,
      crawls.agent_requests AS agent_requests,
      referrals.referrals AS referrals,
      if(referrals.referrals = 0, 0, round(crawls.crawls / referrals.referrals, 1)) AS crawls_per_referral
    FROM crawls
    FULL OUTER JOIN referrals ON crawls.operator = referrals.operator
    ORDER BY crawls DESC, referrals DESC
  "#,
        &[
            ("ai_purposes", AI_PURPOSE_SQL_LIST),
            ("bot_filter_statement", &bot_filter_statement),
            ("time_statement", &time_statement),
            ("referrer_operator", &referrer_operator_expression()),
            ("event_filter_statement", &event_filter_statement),
        ],
    ))
}

analytics_read_route!(get_bot_overview, "bot overview", bot_overview);
analytics_read_route!(get_bot_time_series, "bot time series", bot_time_series);
analytics_read_route!(get_bot_dimension, "bot dimension", bot_dimension);
analytics_read_route!(get_bot_ai_summary, "bot ai summary", bot_ai_summary);

async fn bot_overview(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let spec = QuerySpec::new(build_bot_overview_query(query)?).param("siteId", string_to_number(site_id));
    let rows = analytics_clickhouse(state)?.run_analytics_query(&spec).await?;
    debug!(site_id, rows = rows.len(), "Bot overview fetched");
    Ok(match rows.into_iter().next() {
        Some(row) => send_json(StatusCode::OK, &json!({ "data": Value::Object(row) })),
        None => send_json(StatusCode::OK, &json!({})),
    })
}

async fn bot_time_series(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let spec = QuerySpec::new(build_bot_time_series_query(query)?).param("siteId", string_to_number(site_id));
    let rows = analytics_clickhouse(state)?.run_analytics_query(&spec).await?;
    debug!(site_id, rows = rows.len(), "Bot time series fetched");
    Ok(send_json(StatusCode::OK, &json!({ "data": rows })))
}

async fn bot_dimension(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let site = string_to_number(site_id);
    let data = QuerySpec::new(build_bot_dimension_query(query, false)?).param("siteId", site);
    let count = QuerySpec::new(build_bot_dimension_query(query, true)?).param("siteId", site);
    let result = analytics_clickhouse(state)?.run_paginated_query(&data, &count).await?;
    debug!(site_id, rows = result.data.len(), "Bot dimension fetched");
    Ok(send_json(StatusCode::OK, &json!({ "data": { "data": result.data, "totalCount": result.total_count } })))
}

async fn bot_ai_summary(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let spec = QuerySpec::new(build_bot_ai_summary_query(query)?).param("siteId", string_to_number(site_id));
    let rows = analytics_clickhouse(state)?.run_analytics_query(&spec).await?;
    debug!(site_id, operators = rows.len(), "Bot AI summary fetched");
    Ok(send_json(StatusCode::OK, &json!({ "data": rows })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters(text: &str) -> String {
        get_bot_filter_statement(&JsValue::from(text)).unwrap()
    }

    fn query(pairs: &[(&str, &str)]) -> JsObject {
        pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
    }

    // Ported from bots/utils.test.ts
    #[test]
    fn layer_statements() {
        assert_eq!(get_bot_layer_statement(&JsValue::Undefined), "");
        assert_eq!(get_bot_layer_statement(&JsValue::Null), "");
        assert_eq!(get_bot_layer_statement(&"".into()), "");
        assert_eq!(get_bot_layer_statement(&"ua_pattern".into()), "AND detected_ua_pattern");
        assert_eq!(get_bot_layer_statement(&"header_heuristics".into()), "AND detected_header_heuristics");
        assert_eq!(get_bot_layer_statement(&"client_signals".into()), "AND detected_client_signals");
        assert_eq!(get_bot_layer_statement(&"bot_asn".into()), "AND detected_bot_asn");
        assert_eq!(get_bot_layer_statement(&"rate_anomaly".into()), "AND detected_rate_anomaly");
        assert_eq!(get_bot_layer_statement(&"nonsense_layer".into()), "");
        assert_eq!(get_bot_layer_statement(&"ua_pattern; DROP TABLE events".into()), "");
    }

    #[test]
    fn sql_params() {
        assert_eq!(get_bot_sql_param("referrer").unwrap(), "domainWithoutWWW(referrer)");
        assert_eq!(get_bot_sql_param("dimensions").unwrap(), "concat(toString(screen_width), 'x', toString(screen_height))");
        assert_eq!(get_bot_sql_param("city").unwrap(), "concat(toString(region), '-', toString(city))");
        assert_eq!(get_bot_sql_param("browser_version").unwrap(), "concat(toString(browser), ' ', toString(browser_version))");
        let os = get_bot_sql_param("operating_system_version").unwrap();
        assert!(os.contains("CASE") && os.contains("Windows 10/11"));
        for passthrough in ["browser", "pathname", "asn_org", "bot_category", "matched_ua_pattern"] {
            assert_eq!(get_bot_sql_param(passthrough).unwrap(), passthrough);
        }
    }

    #[test]
    fn filter_statements() {
        assert_eq!(get_bot_filter_statement(&JsValue::Undefined).unwrap(), "");
        assert_eq!(filters(""), "");
        assert_eq!(filters("[]"), "");
        assert_eq!(get_bot_filter_statement(&"invalid json".into()).unwrap_err().to_string(), "Invalid JSON format");
        assert_eq!(filters(r#"[{"parameter":"event_name","type":"equals","value":["click"]}]"#), "");
        assert_eq!(
            filters(
                r#"[{"parameter":"channel","type":"equals","value":["Organic Search"]},{"parameter":"utm_source","type":"equals","value":["google"]},{"parameter":"entry_page","type":"equals","value":["/home"]},{"parameter":"exit_page","type":"equals","value":["/bye"]}]"#
            ),
            ""
        );
        assert_eq!(
            filters(r#"[{"parameter":"event_name","type":"equals","value":["click"]},{"parameter":"browser","type":"equals","value":["Chrome"]}]"#),
            "AND browser = 'Chrome'"
        );
        assert_eq!(
            filters(r#"[{"parameter":"browser","type":"equals","value":["Chrome","Firefox"]}]"#),
            "AND (browser = 'Chrome' OR browser = 'Firefox')"
        );
        assert_eq!(
            filters(r#"[{"parameter":"browser","type":"not_equals","value":["Chrome","Firefox"]}]"#),
            "AND (browser != 'Chrome' AND browser != 'Firefox')"
        );
        assert_eq!(filters(r#"[{"parameter":"pathname","type":"contains","value":["/blog"]}]"#), "AND pathname LIKE '%/blog%'");
        assert_eq!(filters(r#"[{"parameter":"pathname","type":"not_contains","value":["/admin"]}]"#), "AND pathname NOT LIKE '%/admin%'");
        assert_eq!(filters(r#"[{"parameter":"pathname","type":"starts_with","value":["50%"]}]"#), "AND pathname LIKE '50\\\\%%'");
        assert_eq!(filters(r#"[{"parameter":"pathname","type":"ends_with","value":["/checkout"]}]"#), "AND pathname LIKE '%/checkout'");
        assert_eq!(filters(r#"[{"parameter":"browser","type":"is_null","value":[]}]"#), "AND (browser IS NULL OR browser = '')");
        assert_eq!(filters(r#"[{"parameter":"country","type":"is_not_null","value":[]}]"#), "AND (country IS NOT NULL AND country != '')");
        assert_eq!(filters(r#"[{"parameter":"pathname","type":"regex","value":["^/blog/.*"]}]"#), "AND match(pathname, '^/blog/.*')");
        assert_eq!(filters(r#"[{"parameter":"pathname","type":"not_regex","value":["^/admin/.*"]}]"#), "AND NOT match(pathname, '^/admin/.*')");
        assert_eq!(filters(r#"[{"parameter":"lat","type":"greater_than_or_equal","value":["40.5"]}]"#), "AND lat >= 40.5");
        assert_eq!(filters(r#"[{"parameter":"lon","type":"less_than_or_equal","value":["-70.25"]}]"#), "AND lon <= -70.25");
        assert!(
            get_bot_filter_statement(&r#"[{"parameter":"lat","type":"greater_than","value":["not-a-number"]}]"#.into())
                .unwrap_err()
                .to_string()
                .contains("Invalid numeric value")
        );
        let lat = filters(r#"[{"parameter":"lat","type":"equals","value":["40.7128"]}]"#);
        assert!(lat.contains("lat >= 40.7118") && lat.contains("lat <= 40.7138"));
        assert!(filters(r#"[{"parameter":"lon","type":"not_equals","value":["-74.006"]}]"#).contains("NOT (lon >= -74.007 AND lon <= -74.005)"));
        assert_eq!(
            filters(r#"[{"parameter":"browser","type":"equals","value":["Chrome'; DROP TABLE users;--"]}]"#),
            "AND browser = 'Chrome\\'; DROP TABLE users;--'"
        );
        assert_eq!(
            filters(r#"[{"parameter":"browser","type":"equals","value":["Chrome"]},{"parameter":"country","type":"not_equals","value":["CN"]}]"#),
            "AND browser = 'Chrome' AND country != 'CN'"
        );
        assert_eq!(filters(r#"[{"parameter":"user_id","type":"equals","value":["user123"]}]"#), "AND user_id = 'user123'");
        let transforms = filters(
            r#"[{"parameter":"referrer","type":"equals","value":["google.com"]},{"parameter":"city","type":"equals","value":["CA-San Francisco"]}]"#,
        );
        assert!(transforms.contains("domainWithoutWWW(referrer) = 'google.com'"));
        assert!(transforms.contains("concat(toString(region), '-', toString(city)) = 'CA-San Francisco'"));
    }

    #[test]
    fn purpose_statements() {
        assert_eq!(get_bot_purpose_statement(&JsValue::Undefined), "");
        assert_eq!(get_bot_purpose_statement(&JsValue::Null), "");
        assert_eq!(get_bot_purpose_statement(&"".into()), "");
        assert_eq!(get_bot_purpose_statement(&"ai".into()), "AND bot_purpose IN ('ai_training', 'ai_search', 'ai_agent')");
        assert_eq!(get_bot_purpose_statement(&"ai_crawler".into()), "AND bot_purpose IN ('ai_training', 'ai_search')");
        assert_eq!(get_bot_purpose_statement(&"ai_agent".into()), "AND bot_purpose = 'ai_agent'");
        assert_eq!(get_bot_purpose_statement(&"seo".into()), "AND bot_purpose = 'seo'");
        assert_eq!(get_bot_purpose_statement(&"'; DROP TABLE bot_events; --".into()), "");
        assert_eq!(get_bot_purpose_statement(&"nonsense".into()), "");
    }

    // Ported from getBotAiSummary.test.ts
    #[test]
    fn ai_summary_query() {
        let sql = build_bot_ai_summary_query(&query(&[("start_date", "2024-01-01"), ("end_date", "2024-01-31"), ("time_zone", "UTC")])).unwrap();
        assert!(sql.contains("bot_operator AS operator"));
        assert!(sql.contains("countIf(bot_purpose = 'ai_training') AS training_crawls"));
        assert!(sql.contains("countIf(bot_purpose = 'ai_search') AS search_crawls"));
        assert!(sql.contains("countIf(bot_purpose = 'ai_agent') AS agent_requests"));
        assert!(sql.contains("AND bot_operator != ''"));
        assert!(sql.contains("AND bot_purpose IN ('ai_training', 'ai_search', 'ai_agent')"));
        assert!(sql.contains("'chatgpt.com'") && sql.contains("'OpenAI'"));
        assert!(sql.contains("domainWithoutWWW(referrer)"));
        assert!(sql.contains("AND channel = 'AI'"));
        assert!(!sql.contains("duckduckgo.com"));
        assert!(sql.contains("FULL OUTER JOIN referrals ON crawls.operator = referrals.operator"));
        assert!(sql.contains("if(crawls.operator != '', crawls.operator, referrals.operator) AS operator"));
        assert!(sql.contains("if(referrals.referrals = 0, 0,"));
        assert!(sql.matches("toStartOfDay").count() >= 2);
    }

    #[test]
    fn dimensions_are_allowlisted() {
        let err = build_bot_dimension_query(&query(&[("dimension", "event_name")]), false).unwrap_err();
        assert_eq!(err.to_string(), "Unsupported bot dimension: event_name");
        let sql = build_bot_dimension_query(&query(&[("dimension", "pathname"), ("limit", "5"), ("page", "2")]), false).unwrap();
        assert!(sql.contains("any(hostname) AS hostname") && sql.contains("LIMIT 5") && sql.contains("OFFSET 5"));
    }
}
