//! GET /api/sites/:siteId/retention (server/src/api/analytics/getRetention.ts):
//! day or week cohorts of users by first activity, with the share retained in
//! every later period.

use serde_json::{Map, Value};
use tracing::debug;

use crate::analytics::{
    js::{
        JsObject, JsValue,
        number::parse_int_10,
        string::is_js_space_char,
    },
    utils::{analytics_query::QuerySpec, effective_user_id::effective_user_id},
};

use super::{Outcome, HandlerError, OverviewBackend, Reply, Row, js_number, route_failure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionMode {
    Day,
    Week,
}

impl RetentionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RetentionMode::Day => "day",
            RetentionMode::Week => "week",
        }
    }
}

/// `buildRetentionQuery(retentionMode)`. Binds `{siteId:UInt16}` and `{timeRange:UInt16}`.
pub fn build_retention_query(mode: RetentionMode) -> String {
    let period_function = match mode {
        RetentionMode::Day => "toDate",
        RetentionMode::Week => "toStartOfWeek",
    };
    let period_diff_func = mode.as_str();
    let week_argument = if mode == RetentionMode::Week { ", 1" } else { "" };
    let user = effective_user_id("");
    format!(
        "
WITH UserFirstPeriod AS (
    SELECT
        -- Use effective user ID: identified_user_id for identified users, user_id for anonymous
        {user} AS effective_user_id,
        {period_function}(min(timestamp){week_argument}) AS cohort_period
    FROM events
    WHERE site_id = {{siteId:UInt16}}
    -- Use the configurable time range
    AND timestamp >= addDays(today(), -{{timeRange:UInt16}})
    GROUP BY effective_user_id
),
PeriodActivity AS (
    SELECT DISTINCT
        {user} AS effective_user_id,
        {period_function}(timestamp{week_argument}) AS activity_period
    FROM events
    WHERE site_id = {{siteId:UInt16}}
    -- Match the date range filter
    AND timestamp >= addDays(today(), -{{timeRange:UInt16}})
),
CohortRetention AS (
    SELECT
        ufp.cohort_period,
        dateDiff('{period_diff_func}', ufp.cohort_period, pa.activity_period) AS period_difference,
        count(DISTINCT pa.effective_user_id) AS retained_users
    FROM UserFirstPeriod ufp
    JOIN PeriodActivity pa ON ufp.effective_user_id = pa.effective_user_id
    WHERE pa.activity_period >= ufp.cohort_period
    GROUP BY
        ufp.cohort_period,
        period_difference
),
CohortSize AS (
    SELECT
        cohort_period,
        count(DISTINCT effective_user_id) AS total_users
    FROM UserFirstPeriod
    GROUP BY cohort_period
)
SELECT
    cr.cohort_period,
    cr.period_difference,
    cs.total_users AS cohort_size,
    cr.retained_users,
    round(cr.retained_users * 100.0 / cs.total_users, 2) AS retention_percentage
FROM CohortRetention cr
JOIN CohortSize cs ON cr.cohort_period = cs.cohort_period
ORDER BY
    cr.cohort_period DESC,
    cr.period_difference ASC;
    "
    )
}

/// `parseInt(text)` with no radix: a `0x`/`0X` prefix switches to base 16.
pub fn parse_int_auto(text: &str) -> f64 {
    let trimmed = text.trim_start_matches(is_js_space_char);
    let (negative, unsigned) = match trimmed.chars().next() {
        Some('-') => (true, &trimmed[1..]),
        Some('+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let Some(hex) = unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")) else {
        return parse_int_10(text);
    };
    let digits: Vec<u32> = hex.chars().map_while(|c| c.to_digit(16)).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    let value = digits.iter().fold(0.0_f64, |acc, digit| acc * 16.0 + f64::from(*digit));
    if negative { -value } else { value }
}

/// `mode === "day" ? "day" : "week"` after defaulting to "week".
pub fn retention_mode(query: &JsObject) -> RetentionMode {
    match query.get_or_undefined("mode") {
        JsValue::String(mode) if mode == "day" => RetentionMode::Day,
        _ => RetentionMode::Week,
    }
}

/// `Math.min(365, Math.max(7, parseInt(range) || 90))` after defaulting to "90".
pub fn retention_range(query: &JsObject) -> f64 {
    let raw = match query.get_or_undefined("range") {
        JsValue::Undefined => "90".to_string(),
        other => other.to_js_string(),
    };
    let parsed = parse_int_auto(&raw);
    let range = if parsed.is_nan() || parsed == 0.0 { 90.0 } else { parsed };
    // `range` is never NaN here, so clamp matches Math.min(365, Math.max(7, range))
    range.clamp(7.0, 365.0)
}

/// A row field as a JavaScript value (`row.x` on the parsed JSON).
fn field(row: &Row, name: &str) -> JsValue {
    row.get(name).map_or(JsValue::Undefined, JsValue::from_serde)
}

/// `processRetentionData(rows)`: cohorts keyed by period in first-seen order,
/// every percentage list padded with nulls to the longest period.
pub fn process_retention_data(rows: &[Row]) -> (Map<String, Value>, Value) {
    let mut cohorts: JsObject = JsObject::new();
    let mut percentages_by_cohort: Vec<(String, Vec<Value>)> = Vec::new();
    let mut sizes: Vec<(String, Value)> = Vec::new();
    let mut max_period_diff = 0.0_f64;

    for row in rows {
        let cohort = field(row, "cohort_period").to_js_string();
        if cohorts.get(&cohort).is_none() {
            cohorts.insert(cohort.clone(), JsValue::Null);
            sizes.push((cohort.clone(), row.get("cohort_size").cloned().unwrap_or(Value::Null)));
            percentages_by_cohort.push((cohort.clone(), Vec::new()));
        }
        let period = field(row, "period_difference").to_number();
        let percentage = row.get("retention_percentage").cloned().unwrap_or(Value::Null);
        let percentages = &mut percentages_by_cohort.iter_mut().find(|(name, _)| *name == cohort).expect("inserted").1;
        // `while (length <= period) push(null)`, then assign at the index
        if period.is_finite() && period >= 0.0 && period.fract() == 0.0 {
            let index = period as usize;
            while percentages.len() <= index {
                percentages.push(Value::Null);
            }
            percentages[index] = percentage;
        }
        if period > max_period_diff {
            max_period_diff = period;
        }
    }

    let final_max_periods = max_period_diff.max(0.0);
    let mut processed = Map::new();
    for cohort in cohorts.keys() {
        let size = sizes.iter().find(|(name, _)| name == cohort).map(|(_, size)| size.clone()).unwrap_or(Value::Null);
        let mut percentages =
            percentages_by_cohort.iter().find(|(name, _)| name == cohort).map(|(_, list)| list.clone()).unwrap_or_default();
        while (percentages.len() as f64) <= final_max_periods {
            percentages.push(Value::Null);
        }
        let mut entry = Map::new();
        entry.insert("size".to_string(), size);
        entry.insert("percentages".to_string(), Value::Array(percentages));
        processed.insert(cohort.to_string(), Value::Object(entry));
    }
    (processed, crate::analytics::js::value::number_to_serde(final_max_periods))
}

/// `getRetention`: `{ data: { cohorts, maxPeriods, mode, range } }`.
pub(crate) async fn get_retention<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    const LABEL: &str = "retention";
    let mode = retention_mode(query);
    let time_range = retention_range(query);
    let site = js_number(site_id);
    let result: Result<Reply, HandlerError> = async {
        let spec = QuerySpec::new(build_retention_query(mode)).param("siteId", site).param("timeRange", time_range);
        let rows = backend.run_analytics_query(&spec).await?;
        let (cohorts, max_periods) = if rows.is_empty() {
            (Map::new(), Value::from(0))
        } else {
            process_retention_data(&rows)
        };
        debug!(site_id = site, mode = mode.as_str(), range = time_range, rows = rows.len(), cohorts = cohorts.len(), "retention fetched");
        let mut data = Map::new();
        data.insert("cohorts".to_string(), Value::Object(cohorts));
        data.insert("maxPeriods".to_string(), max_periods);
        data.insert("mode".to_string(), Value::from(mode.as_str()));
        data.insert("range".to_string(), crate::analytics::js::value::number_to_serde(time_range));
        let mut body = Map::new();
        body.insert("data".to_string(), Value::Object(data));
        Ok(Reply::ok(Value::Object(body)))
    }
    .await;
    result.or_else(|failure| route_failure(LABEL, &failure))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn query(pairs: &[(&str, &str)]) -> JsObject {
        pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
    }

    #[test]
    fn parse_int_without_radix() {
        assert_eq!(parse_int_auto("0x1f"), 31.0);
        assert_eq!(parse_int_auto("  -0X10"), -16.0);
        assert!(parse_int_auto("0x").is_nan());
        assert_eq!(parse_int_auto("42abc"), 42.0);
        assert_eq!(parse_int_auto("012"), 12.0);
        assert!(parse_int_auto("abc").is_nan());
    }

    #[test]
    fn mode_and_range_defaults() {
        assert_eq!(retention_mode(&query(&[])), RetentionMode::Week);
        assert_eq!(retention_mode(&query(&[("mode", "day")])), RetentionMode::Day);
        assert_eq!(retention_mode(&query(&[("mode", "DAY")])), RetentionMode::Week);
        assert_eq!(retention_range(&query(&[])), 90.0);
        assert_eq!(retention_range(&query(&[("range", "3")])), 7.0);
        assert_eq!(retention_range(&query(&[("range", "0")])), 90.0);
        assert_eq!(retention_range(&query(&[("range", "1000")])), 365.0);
        assert_eq!(retention_range(&query(&[("range", "0x20")])), 32.0);
        assert_eq!(retention_range(&query(&[("range", "")])), 90.0);
        assert_eq!(retention_range(&query(&[("range", "-5")])), 7.0);
    }

    #[test]
    fn week_mode_passes_the_monday_argument() {
        let week = build_retention_query(RetentionMode::Week);
        assert!(week.contains("toStartOfWeek(min(timestamp), 1) AS cohort_period"));
        assert!(week.contains("dateDiff('week',"));
        let day = build_retention_query(RetentionMode::Day);
        assert!(day.contains("toDate(min(timestamp)) AS cohort_period"));
        assert!(day.contains("toDate(timestamp) AS activity_period"));
    }

    #[test]
    fn cohorts_pad_to_the_longest_period() {
        let rows: Vec<Row> = [
            json!({ "cohort_period": "2026-09-07", "period_difference": 0, "cohort_size": 4, "retained_users": 4, "retention_percentage": 100 }),
            json!({ "cohort_period": "2026-09-07", "period_difference": 2, "cohort_size": 4, "retained_users": 1, "retention_percentage": 25 }),
            json!({ "cohort_period": "2026-08-31", "period_difference": 0, "cohort_size": 3, "retained_users": 3, "retention_percentage": 100 }),
        ]
        .into_iter()
        .map(|value| if let Value::Object(map) = value { map } else { unreachable!() })
        .collect();
        let (cohorts, max_periods) = process_retention_data(&rows);
        assert_eq!(
            crate::js_json::stringify(&Value::Object(cohorts)),
            r#"{"2026-09-07":{"size":4,"percentages":[100,null,25]},"2026-08-31":{"size":3,"percentages":[100,null,null]}}"#
        );
        assert_eq!(max_periods, json!(2));
    }
}
