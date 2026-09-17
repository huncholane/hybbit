//! Port of server/src/api/analytics/utils/sessionFilters.ts: filters applied to
//! whole sessions, as a `FilteredSessions` CTE or a session-aggregate `WHERE`.

use indexmap::IndexSet;

use crate::analytics::{
    js::{JsValue, json},
    types::{Filter, FilterParameter},
};

use super::{
    get_filter_statement::{FilterStatementError, FilterStatementOptions, get_filter_statement},
    query_validation::validate_filters,
    session_attribution::SESSION_REFERRER_AGG,
};

/// `SESSION_EVENT_LEVEL_PARAMS`.
fn session_event_level_params() -> Vec<FilterParameter> {
    vec![
        FilterParameter::EventName,
        FilterParameter::Pathname,
        FilterParameter::PageTitle,
        FilterParameter::Querystring,
        FilterParameter::Channel,
    ]
}

/// `SESSION_FIELD_MAPPINGS`.
fn session_field_mappings() -> Vec<(String, String)> {
    ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"]
        .iter()
        .map(|name| (format!("url_parameters['{name}']"), name.to_string()))
        .collect()
}

/// `TARGET_EVENT_ROW_LEVEL_PARAMS`.
pub fn target_event_row_level_params() -> Vec<FilterParameter> {
    vec![
        FilterParameter::Hostname,
        FilterParameter::Browser,
        FilterParameter::BrowserVersion,
        FilterParameter::OperatingSystem,
        FilterParameter::OperatingSystemVersion,
        FilterParameter::Language,
        FilterParameter::Country,
        FilterParameter::Region,
        FilterParameter::City,
        FilterParameter::DeviceType,
        FilterParameter::Pathname,
        FilterParameter::PageTitle,
        FilterParameter::Querystring,
        FilterParameter::Dimensions,
        FilterParameter::Lat,
        FilterParameter::Lon,
        FilterParameter::Timezone,
        FilterParameter::Tag,
    ]
}

/// `getSessionFilterStatement(filters, siteId, timeStatement)`, `filters` being
/// the raw request value.
pub fn get_session_filter_statement(
    filters: &JsValue,
    site_id: i64,
    time_statement: &str,
) -> Result<String, FilterStatementError> {
    get_filter_statement(
        filters,
        Some(site_id),
        Some(time_statement),
        &FilterStatementOptions {
            session_level_params: Some(session_event_level_params()),
            field_mappings: Some(session_field_mappings()),
            ..Default::default()
        },
    )
}

/// `buildFilteredSessionsCTE(filters, siteId, timeStatement, cteName)`.
pub fn build_filtered_sessions_cte(
    filters: &JsValue,
    site_id: i64,
    time_statement: &str,
    cte_name: &str,
) -> Result<Option<String>, FilterStatementError> {
    if !filters.is_truthy() {
        return Ok(None);
    }
    let parsed = validate_filters(&filters.to_js_string())?;
    if parsed.is_empty() {
        return Ok(None);
    }
    let filter_statement = get_session_filter_statement(filters, site_id, time_statement)?;
    if filter_statement.is_empty() {
        return Ok(None);
    }

    let mut subquery_only = session_event_level_params();
    subquery_only.extend([FilterParameter::EntryPage, FilterParameter::ExitPage]);

    let mut aggregates: IndexSet<String> = IndexSet::new();
    for Filter { parameter, .. } in &parsed {
        if subquery_only.contains(parameter) {
            continue;
        }
        match parameter {
            FilterParameter::UserId => {
                aggregates.insert("argMax(user_id, timestamp) AS user_id".to_string());
                aggregates.insert("argMax(identified_user_id, timestamp) AS identified_user_id".to_string());
            }
            FilterParameter::Referrer => {
                aggregates.insert(format!("{SESSION_REFERRER_AGG} AS referrer"));
            }
            FilterParameter::UtmSource
            | FilterParameter::UtmMedium
            | FilterParameter::UtmCampaign
            | FilterParameter::UtmTerm
            | FilterParameter::UtmContent => {
                let name = parameter.as_string();
                aggregates.insert(format!("argMin(url_parameters, timestamp)['{name}'] AS {name}"));
            }
            FilterParameter::Hostname => {
                aggregates.insert("argMin(hostname, timestamp) AS hostname".to_string());
            }
            FilterParameter::Dimensions => {
                aggregates.insert("argMax(screen_width, timestamp) AS screen_width".to_string());
                aggregates.insert("argMax(screen_height, timestamp) AS screen_height".to_string());
            }
            FilterParameter::City => {
                aggregates.insert("argMax(region, timestamp) AS region".to_string());
                aggregates.insert("argMax(city, timestamp) AS city".to_string());
            }
            FilterParameter::BrowserVersion => {
                aggregates.insert("argMax(browser, timestamp) AS browser".to_string());
                aggregates.insert("argMax(browser_version, timestamp) AS browser_version".to_string());
            }
            FilterParameter::OperatingSystemVersion => {
                aggregates.insert("argMax(operating_system, timestamp) AS operating_system".to_string());
                aggregates.insert("argMax(operating_system_version, timestamp) AS operating_system_version".to_string());
            }
            FilterParameter::FeatureFlag(_) => {
                aggregates.insert("argMax(feature_flags, timestamp) AS feature_flags".to_string());
            }
            other => {
                let name = other.as_string();
                aggregates.insert(format!("argMax({name}, timestamp) AS {name}"));
            }
        }
    }

    let aggregate_projection = if aggregates.is_empty() {
        String::new()
    } else {
        format!(",\n          {}", aggregates.iter().map(String::as_str).collect::<Vec<_>>().join(",\n          "))
    };

    Ok(Some(format!(
        "{cte_name} AS (
      SELECT session_id
      FROM (
        SELECT
          session_id{aggregate_projection}
        FROM events
        WHERE site_id = {site_id}
          {time_statement}
        GROUP BY session_id
      )
      WHERE 1 = 1 {filter_statement}
    )"
    )))
}

/// The two fragments `buildSessionAndRowFilterFragments` returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionAndRowFilterFragments {
    pub filtered_sessions_cte: Option<String>,
    pub row_filter_statement: String,
}

/// `buildSessionAndRowFilterFragments(filters, siteId, timeStatement, rowLevelParams, cteName)`.
///
/// Each half is re-serialized with `JSON.stringify` and validated again, as in
/// Node: a value that does not survive the round trip (`1e999` becomes `null`)
/// fails there.
pub fn build_session_and_row_filter_fragments(
    filters: &JsValue,
    site_id: i64,
    time_statement: &str,
    row_level_params: &[FilterParameter],
    cte_name: &str,
) -> Result<SessionAndRowFilterFragments, FilterStatementError> {
    if !filters.is_truthy() {
        return Ok(SessionAndRowFilterFragments { filtered_sessions_cte: None, row_filter_statement: String::new() });
    }
    let parsed = validate_filters(&filters.to_js_string())?;
    let (row_filters, session_filters): (Vec<Filter>, Vec<Filter>) =
        parsed.into_iter().partition(|filter| row_level_params.contains(&filter.parameter));

    let stringify = |list: &[Filter]| {
        JsValue::String(
            json::stringify(&JsValue::Array(list.iter().map(Filter::to_js).collect())).expect("arrays always stringify"),
        )
    };

    let filtered_sessions_cte = if session_filters.is_empty() {
        None
    } else {
        build_filtered_sessions_cte(&stringify(&session_filters), site_id, time_statement, cte_name)?
    };
    let row_filter_statement = if row_filters.is_empty() {
        String::new()
    } else {
        get_filter_statement(
            &stringify(&row_filters),
            Some(site_id),
            Some(time_statement),
            &FilterStatementOptions::session_level(Vec::new()),
        )?
    };
    Ok(SessionAndRowFilterFragments { filtered_sessions_cte, row_filter_statement })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIME: &str = "AND timestamp >= toDateTime('2026-08-01 00:00:00')";

    fn build(parameter: &str, value: &str) -> String {
        let filters = format!(r#"[{{"parameter":"{parameter}","type":"equals","value":["{value}"]}}]"#);
        build_filtered_sessions_cte(&JsValue::String(filters), 1, TIME, "FilteredSessions").unwrap().unwrap()
    }

    // Ported from sessionFilters.test.ts
    #[test]
    fn projects_only_needed_aggregates() {
        let sql = build("utm_campaign", "launch");
        assert!(sql.contains("argMin(url_parameters, timestamp)['utm_campaign'] AS utm_campaign"));
        assert!(!sql.contains("argMax(browser,") && !sql.contains("AS utm_source") && !sql.contains("feature_flags"));

        let sql = build("browser_version", "Chrome 140");
        assert!(sql.contains("argMax(browser, timestamp) AS browser"));
        assert!(sql.contains("argMax(browser_version, timestamp) AS browser_version"));
        assert!(!sql.contains("argMax(country,"));

        let sql = build("pathname", "/pricing");
        assert!(sql.contains("session_id IN (") && sql.contains("pathname = '/pricing'"));
        assert!(!sql.contains("argMax(pathname,") && !sql.contains("argMax(browser,"));
    }
}
