//! GET /api/sites/:siteId/journeys (server/src/api/analytics/getJourneys.ts): the
//! most common page sequences per session, optionally pinned to a path (or a
//! wildcard pattern) at given steps.

use axum::http::StatusCode;
use serde_json::{Map, Value};
use tracing::{debug, error};

use crate::analytics::{
    js::{JsObject, JsValue, json, number::{number_to_string, parse_int_10}, string::utf16_len},
    sql_string::escape_string,
    utils::{
        analytics_query::QuerySpec, session_filters::build_filtered_sessions_cte,
        time_window::resolve_time_window_with_clock, utils::pattern_to_regex,
    },
};

use super::{
    BuildError, HandlerError, Outcome, OverviewBackend, Reply, SESSION_JOIN, Thrown, integral_site_id, js_number, time_params,
};

/// `stepFiltersSchema.parse(JSON.parse(stepFilters))`: an object whose keys are
/// digit strings and whose values are strings of at most 2048 UTF-16 units. Keys
/// keep `JSON.parse` property order (array indices first).
pub fn parse_step_filters(text: &str) -> Option<Vec<(String, String)>> {
    let JsValue::Object(object) = json::parse(text).ok()? else { return None };
    let mut entries = Vec::with_capacity(object.len());
    for (key, value) in object.iter() {
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let JsValue::String(path) = value else { return None };
        if utf16_len(path) > 2048 {
            return None;
        }
        entries.push((key.to_string(), path.clone()));
    }
    Some(entries)
}

/// `buildJourneysQuery(query, siteId, parsedStepFilters)`.
pub fn build_journeys_query(
    query: &JsObject,
    site_id: i64,
    step_filters: &[(String, String)],
    now: &dyn Fn() -> f64,
) -> Result<String, BuildError> {
    let time_statement = resolve_time_window_with_clock(&time_params(query), now)?.where_timestamp();
    let filtered_sessions_cte =
        build_filtered_sessions_cte(query.get_or_undefined("filters"), site_id, &time_statement, "FilteredSessions")?;
    let filtered_sessions_join = if filtered_sessions_cte.is_some() { SESSION_JOIN } else { "" };

    // Wildcards: `*` matches one path segment, `**` any number of them
    let step_filter_conditions = step_filters
        .iter()
        .map(|(step, path)| {
            // ClickHouse arrays are 1-indexed
            let step_index = number_to_string(parse_int_10(step) + 1.0);
            if path.contains('*') {
                format!("match(journey[{step_index}], {})", escape_string(&pattern_to_regex(path)))
            } else {
                format!("journey[{step_index}] = {}", escape_string(path))
            }
        })
        .collect::<Vec<_>>()
        .join(" AND ");
    let having = if step_filter_conditions.is_empty() { String::new() } else { format!("HAVING {step_filter_conditions}") };

    let denominator = if filtered_sessions_cte.is_some() {
        "SELECT count() FROM FilteredSessions".to_string()
    } else {
        format!(
            "SELECT count(DISTINCT session_id)
                   FROM events
                   WHERE site_id = {{siteId:Int32}}
                   {time_statement}"
        )
    };
    let cte_prefix = filtered_sessions_cte.map(|cte| format!("{cte},")).unwrap_or_default();

    Ok(format!(
        "
        WITH {cte_prefix}
        user_paths AS (
          SELECT
            session_id,
            arrayCompact(groupArray(pathname)) AS path_sequence
          FROM (
            SELECT
              session_id,
              pathname,
              timestamp
            FROM events
            {filtered_sessions_join}
            WHERE
              site_id = {{siteId:Int32}}
              {time_statement}
              AND type = 'pageview'
            ORDER BY session_id, timestamp
          )
          GROUP BY session_id
          HAVING length(path_sequence) >= 2
        ),

        journey_segments AS (
          SELECT
            arraySlice(path_sequence, 1, {{maxSteps:Int32}}) AS journey,
            count() AS sessions_count
          FROM user_paths
          GROUP BY journey
          {having}
          ORDER BY sessions_count DESC
          LIMIT {{journeyLimit:Int32}}
        )

        SELECT
          journey,
          sessions_count,
          sessions_count * 100 / (
            {denominator}
          ) AS percentage
        FROM journey_segments
      "
    ))
}

/// `getJourneys`: its own try/catch rather than `analyticsRoute`, so failures
/// answer `Failed to get journeys`.
pub(crate) async fn get_journeys<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    let string_param = |name: &str, default: &str| match query.get_or_undefined(name) {
        JsValue::Undefined => default.to_string(),
        other => other.to_js_string(),
    };
    let max_steps = parse_int_10(&string_param("steps", "3"));
    let journey_limit = parse_int_10(&string_param("limit", "100"));

    if max_steps.is_nan() || !(2.0..=10.0).contains(&max_steps) {
        debug!(steps = max_steps, "journeys: steps out of range");
        return Ok(Reply::error(StatusCode::BAD_REQUEST, "Steps parameter must be a number between 2 and 10"));
    }
    if journey_limit.is_nan() || !(1.0..=500.0).contains(&journey_limit) {
        debug!(limit = journey_limit, "journeys: limit out of range");
        return Ok(Reply::error(StatusCode::BAD_REQUEST, "Limit parameter must be a number between 1 and 500"));
    }

    let raw_step_filters = query.get_or_undefined("stepFilters");
    let step_filters = if raw_step_filters.is_truthy() {
        match parse_step_filters(&raw_step_filters.to_js_string()) {
            Some(entries) => entries,
            None => {
                debug!("journeys: stepFilters rejected");
                return Ok(Reply::error(StatusCode::BAD_REQUEST, "Invalid stepFilters format"));
            }
        }
    } else {
        Vec::new()
    };

    let site = js_number(site_id);
    let result: Result<Vec<super::Row>, HandlerError> = async {
        let sql = build_journeys_query(query, integral_site_id(site)?, &step_filters, &|| backend.now_ms())?;
        let spec = QuerySpec::new(sql)
            .param("siteId", parse_int_10(site_id))
            .param("maxSteps", max_steps)
            .param("journeyLimit", journey_limit);
        Ok(backend.run_analytics_query(&spec).await?)
    }
    .await;

    match result {
        Ok(rows) => {
            debug!(site_id = site, steps = max_steps, limit = journey_limit, journeys = rows.len(), "journeys fetched");
            let journeys: Vec<Value> = rows
                .into_iter()
                .map(|row| {
                    let number = |name: &str| {
                        let value = row.get(name).map_or(JsValue::Undefined, JsValue::from_serde);
                        crate::analytics::js::value::number_to_serde(value.to_number())
                    };
                    let mut item = Map::new();
                    // `path: item.journey` is undefined (and dropped) when the column is missing
                    if let Some(path) = row.get("journey") {
                        item.insert("path".to_string(), path.clone());
                    }
                    item.insert("count".to_string(), number("sessions_count"));
                    item.insert("percentage".to_string(), number("percentage"));
                    Value::Object(item)
                })
                .collect();
            let mut body = Map::new();
            body.insert("journeys".to_string(), Value::Array(journeys));
            Ok(Reply::ok(Value::Object(body)))
        }
        Err(failure) => {
            match &failure {
                HandlerError::Query(query_error) => error!(err = %query_error.original, "Error getting journeys"),
                HandlerError::Build(build_error) => error!(err = %build_error, "Error getting journeys"),
            }
            if failure.is_zod_error() {
                // Node's catch logs the ZodError, and that logging call throws
                let thrown = Thrown::zod_error_logged();
                error!(message = %thrown.message, "Validation error escaped the journeys route");
                return Err(thrown);
            }
            Ok(Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get journeys"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(filters: &str) -> JsObject {
        [("filters", filters), ("start_date", ""), ("end_date", ""), ("time_zone", "UTC")]
            .iter()
            .map(|(key, value)| (key.to_string(), JsValue::from(*value)))
            .collect()
    }

    fn filter(parameter: &str, value: &str) -> String {
        format!(r#"{{"parameter":"{parameter}","type":"equals","value":["{value}"]}}"#)
    }

    // Ported from getJourneys.test.ts
    #[test]
    fn referrer_lives_only_on_the_acquisition_row() {
        let sql = build_journeys_query(&base(&format!("[{}]", filter("referrer", "google.com"))), 1, &[], &|| 0.0).unwrap();
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("argMinIf(referrer, timestamp, referrer != '') AS referrer"));
        assert!(sql.contains("WHERE 1 = 1 AND domainWithoutWWW(referrer) = 'google.com'"));
        assert!(sql.contains("FROM events\n            INNER JOIN FilteredSessions USING (session_id)"));
        assert!(sql.contains("AND type = 'pageview'"));
        assert!(sql.contains("SELECT count() FROM FilteredSessions"));
        assert_eq!(sql.matches("domainWithoutWWW(referrer) = 'google.com'").count(), 1);
    }

    #[test]
    fn campaign_and_later_pathname_qualify_on_different_rows() {
        let filters = format!("[{},{}]", filter("utm_campaign", "recipe_book_2026"), filter("pathname", "/thank-you"));
        let sql = build_journeys_query(&base(&filters), 1, &[], &|| 0.0).unwrap();
        assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
        assert!(sql.contains("SELECT DISTINCT session_id\n            FROM events"));
        assert!(sql.contains("AND pathname = '/thank-you'"));
        assert_eq!(sql.matches("utm_campaign = 'recipe_book_2026'").count(), 1);
        assert_eq!(sql.matches("pathname = '/thank-you'").count(), 1);
    }

    #[test]
    fn step_filters() {
        assert_eq!(
            parse_step_filters(r#"{"b":"x"}"#),
            None,
            "non-digit keys are rejected"
        );
        assert_eq!(parse_step_filters("[]"), None);
        assert_eq!(parse_step_filters("null"), None);
        assert_eq!(parse_step_filters(r#"{"0":1}"#), None);
        assert_eq!(
            parse_step_filters(r#"{"2":"/b","01":"/c","0":"/a"}"#).unwrap(),
            vec![("0".into(), "/a".into()), ("2".into(), "/b".into()), ("01".into(), "/c".into())]
        );
        let sql = build_journeys_query(
            &base(""),
            1,
            &[("0".into(), "/blog/*".into()), ("1".into(), "/it's".into())],
            &|| 0.0,
        )
        .unwrap();
        assert!(sql.contains("HAVING match(journey[1], '^/blog/[^/]+$') AND journey[2] = '/it\\'s'"));
    }
}
