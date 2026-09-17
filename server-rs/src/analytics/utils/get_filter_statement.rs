//! Port of server/src/api/analytics/utils/getFilterStatement.ts: turn the
//! `filters` query param into an `AND ...` SQL fragment with every user value
//! inlined through `SqlString.escape`.

use std::collections::HashSet;

use tracing::debug;

use crate::analytics::{
    js::{
        JsValue,
        number::number_to_string,
        regexp,
        string::{trim, utf16_len},
        zod::{self, ZodIssue},
    },
    sql_string::{escape_number, escape_string},
    types::{Filter, FilterParameter, FilterType, FilterValue},
};

use super::{
    effective_user_id::{does_not_match_user, matches_user},
    query_validation::{FiltersError, filter_parameter_schema_parse, validate_filters},
    session_attribution::SESSION_CHANNEL_AGG,
};

/// Everything `getFilterStatement` can throw.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum FilterStatementError {
    #[error(transparent)]
    Filters(#[from] FiltersError),
    /// `validateRegexPattern` rejected a regex filter's pattern
    #[error("{0}")]
    Regex(String),
    #[error("Invalid numeric value for {filter_type} filter: {value}")]
    InvalidNumber { filter_type: FilterType, value: String },
}

/// `getSqlParam` threw: the parameter is not one `filterParamSchema` accepts.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[error("{}", zod::error_message(.0))]
pub struct UnknownParameter(pub Vec<ZodIssue>);

/// `FilterStatementOptions`.
#[derive(Clone, Debug, Default)]
pub struct FilterStatementOptions {
    /// Parameters matched by session membership; `None` is the default
    /// `["event_name", "channel"]`
    pub session_level_params: Option<Vec<FilterParameter>>,
    /// Emitted column expression to CTE alias, applied to column identifiers only
    pub field_mappings: Option<Vec<(String, String)>>,
    /// Filters on parameters outside this set are dropped
    pub parameter_allowlist: Option<HashSet<FilterParameter>>,
    /// Match `user_id` filters against `identified_user_id` too (default true)
    pub dual_user_id_columns: Option<bool>,
}

impl FilterStatementOptions {
    pub fn session_level(params: Vec<FilterParameter>) -> Self {
        Self { session_level_params: Some(params), ..Self::default() }
    }
}

fn default_session_level_params() -> Vec<FilterParameter> {
    vec![FilterParameter::EventName, FilterParameter::Channel]
}

/// `filterTypeToOperator`; `None` for the types with no infix operator.
pub fn filter_type_to_operator(filter_type: FilterType) -> Option<&'static str> {
    match filter_type {
        FilterType::Equals => Some("="),
        FilterType::NotEquals => Some("!="),
        FilterType::Contains | FilterType::StartsWith | FilterType::EndsWith => Some("LIKE"),
        FilterType::NotContains => Some("NOT LIKE"),
        FilterType::GreaterThan => Some(">"),
        FilterType::LessThan => Some("<"),
        FilterType::GreaterThanOrEqual => Some(">="),
        FilterType::LessThanOrEqual => Some("<="),
        FilterType::Regex | FilterType::NotRegex | FilterType::IsNull | FilterType::IsNotNull => None,
    }
}

/// How a missing operator prints inside a template literal.
fn operator_text(filter_type: FilterType) -> &'static str {
    filter_type_to_operator(filter_type).unwrap_or("null")
}

/// `escapeLikePattern`: backslash-escape `\`, `%` and `_`.
fn escape_like_pattern(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(character);
    }
    out
}

pub const MAX_REGEX_PATTERN_LENGTH: usize = 500;

/// `RE2_UNSUPPORTED`: `/\(\?<?[=!]|\\[1-9]/`.
fn uses_re2_unsupported_syntax(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    bytes.windows(2).enumerate().any(|(position, pair)| {
        (pair[0] == b'\\' && (b'1'..=b'9').contains(&pair[1]))
            || (pair == b"(?"
                && match bytes.get(position + 2) {
                    Some(b'=' | b'!') => true,
                    Some(b'<') => matches!(bytes.get(position + 3), Some(b'=' | b'!')),
                    _ => false,
                })
    })
}

/// `validateRegexPattern`: why a regex filter pattern cannot run, or `None`.
pub fn validate_regex_pattern(pattern: &str) -> Option<String> {
    if pattern.is_empty() {
        return Some("Regex pattern cannot be empty".to_string());
    }
    if utf16_len(pattern) > MAX_REGEX_PATTERN_LENGTH {
        return Some(format!("Regex pattern too long (max {MAX_REGEX_PATTERN_LENGTH} characters)"));
    }
    if let Err(message) = regexp::validate(pattern) {
        return Some(format!("Invalid regex pattern: {message}"));
    }
    if uses_re2_unsupported_syntax(pattern) {
        return Some("Regex pattern uses lookaround or backreferences, which are not supported".to_string());
    }
    None
}

/// `wrapLikeValue`.
pub fn wrap_like_value(filter_type: FilterType, value: &FilterValue) -> String {
    let text = value.to_js_string();
    match filter_type {
        FilterType::Contains | FilterType::NotContains => format!("%{}%", escape_like_pattern(&text)),
        FilterType::StartsWith => format!("{}%", escape_like_pattern(&text)),
        FilterType::EndsWith => format!("%{}", escape_like_pattern(&text)),
        _ => text,
    }
}

/// `SqlString.escape(value)` for a filter value.
fn escape_filter_value(value: &FilterValue) -> String {
    match value {
        FilterValue::String(text) => escape_string(text),
        FilterValue::Number(number) => escape_number(*number),
    }
}

fn is_negative_joiner(filter_type: FilterType) -> bool {
    matches!(filter_type, FilterType::NotEquals | FilterType::NotContains)
}

/// `buildStringFilterCondition`: one filter against one column expression.
pub fn build_string_filter_condition(
    expression: &str,
    filter_type: FilterType,
    values: &[FilterValue],
) -> Result<String, FilterStatementError> {
    match filter_type {
        FilterType::IsNull => return Ok(format!("({expression} IS NULL OR {expression} = '')")),
        FilterType::IsNotNull => return Ok(format!("({expression} IS NOT NULL AND {expression} != '')")),
        FilterType::Regex | FilterType::NotRegex => {
            let pattern = values.first().map(FilterValue::to_js_string).unwrap_or_default();
            if let Some(error) = validate_regex_pattern(&pattern) {
                debug!(error = %error, "regex filter rejected");
                return Err(FilterStatementError::Regex(error));
            }
            let match_expr = format!("match({expression}, {})", escape_string(&pattern));
            return Ok(if filter_type == FilterType::Regex { match_expr } else { format!("NOT {match_expr}") });
        }
        _ => {}
    }

    let operator = operator_text(filter_type);
    let joiner = if is_negative_joiner(filter_type) { " AND " } else { " OR " };
    let render = |value: &FilterValue| format!("{expression} {operator} {}", escape_string(&wrap_like_value(filter_type, value)));
    Ok(if values.len() == 1 {
        render(&values[0])
    } else {
        format!("({})", values.iter().map(render).collect::<Vec<_>>().join(joiner))
    })
}

/// `getSqlParam(parameter)` for a validated parameter.
pub fn sql_param(parameter: &FilterParameter) -> String {
    match parameter {
        FilterParameter::FeatureFlag(key) => format!("feature_flags[{}]", escape_string(key)),
        other => sql_param_for_name(other.base_name().expect("base parameter")).expect("base parameters are valid"),
    }
}

/// `getSqlParam(parameter)` for an arbitrary string (callers pass the raw
/// `parameter` query param), throwing like `filterParamSchema.parse`.
pub fn get_sql_param(parameter: &str) -> Result<String, UnknownParameter> {
    sql_param_for_name(parameter)
}

fn sql_param_for_name(parameter: &str) -> Result<String, UnknownParameter> {
    if let Some(key) = parameter.strip_prefix("feature_flag:") {
        return Ok(format!("feature_flags[{}]", escape_string(key)));
    }
    if let Some(name) = parameter.strip_prefix("url_param:") {
        return Ok(format!("url_parameters[{}]", escape_string(name)));
    }
    if parameter.starts_with("utm_") {
        return Ok(format!("url_parameters[{}]", escape_string(parameter)));
    }
    Ok(match parameter {
        "referrer" => "domainWithoutWWW(referrer)".to_string(),
        "entry_page" => {
            "(SELECT argMinIf(pathname, timestamp_ms, type = 'pageview') FROM events WHERE session_id = events.session_id)"
                .to_string()
        }
        "exit_page" => {
            "(SELECT argMaxIf(pathname, timestamp_ms, type = 'pageview') FROM events WHERE session_id = events.session_id)"
                .to_string()
        }
        "dimensions" => "concat(toString(screen_width), 'x', toString(screen_height))".to_string(),
        "city" => "concat(toString(region), '-', toString(city))".to_string(),
        "browser_version" => "concat(toString(browser), ' ', toString(browser_version))".to_string(),
        "operating_system_version" => "CASE
      WHEN concat(toString(operating_system), ' ', toString(operating_system_version)) = 'Windows 10'
      THEN 'Windows 10/11'
      ELSE concat(toString(operating_system), ' ', toString(operating_system_version))
    END"
        .to_string(),
        other => filter_parameter_schema_parse(other).map_err(UnknownParameter)?.as_string(),
    })
}

/// `getFilterStatement(filters, siteId, timeStatement, options)`.
///
/// `filters` is the raw request value: `undefined` and "" produce no statement,
/// a string is parsed as JSON, and an array (a repeated query param) is joined
/// with commas first, exactly as `JSON.parse` would coerce it. `site_id` of
/// `None` or `Some(0)` adds no site predicate, like a falsy `siteId`.
pub fn get_filter_statement(
    filters: &JsValue,
    site_id: Option<i64>,
    time_statement: Option<&str>,
    options: &FilterStatementOptions,
) -> Result<String, FilterStatementError> {
    if !filters.is_truthy() {
        return Ok(String::new());
    }
    let filters = validate_filters(&filters.to_js_string())?;
    build_filter_statement(filters, site_id, time_statement, options)
}

/// [`get_filter_statement`] for filters that are already a string.
pub fn get_filter_statement_str(
    filters: &str,
    site_id: Option<i64>,
    time_statement: Option<&str>,
    options: &FilterStatementOptions,
) -> Result<String, FilterStatementError> {
    get_filter_statement(&JsValue::from(filters), site_id, time_statement, options)
}

/// `timeStatement.replace(/^AND\s+/i, "").trim()`.
fn strip_leading_and(time_statement: &str) -> String {
    let bytes = time_statement.as_bytes();
    let mut rest = time_statement;
    if bytes.len() >= 3 && bytes[..3].eq_ignore_ascii_case(b"AND") {
        let after = &time_statement[3..];
        let trimmed = after.trim_start_matches(crate::analytics::js::string::is_js_space_char);
        if trimmed.len() < after.len() {
            rest = trimmed;
        }
    }
    trim(rest).to_string()
}

/// The body of `getFilterStatement` after validation.
pub fn build_filter_statement(
    filters: Vec<Filter>,
    site_id: Option<i64>,
    time_statement: Option<&str>,
    options: &FilterStatementOptions,
) -> Result<String, FilterStatementError> {
    let filters: Vec<Filter> = match &options.parameter_allowlist {
        Some(allowlist) => filters.into_iter().filter(|filter| allowlist.contains(&filter.parameter)).collect(),
        None => filters,
    };
    if filters.is_empty() {
        return Ok(String::new());
    }

    let session_level_params = options.session_level_params.clone().unwrap_or_else(default_session_level_params);
    let map_field = |expression: String| -> String {
        options
            .field_mappings
            .as_ref()
            .and_then(|mappings| mappings.iter().find(|(from, _)| *from == expression).map(|(_, to)| to.clone()))
            .unwrap_or(expression)
    };

    let site_id_filter = match site_id {
        Some(id) if id != 0 => format!("site_id = {}", number_to_string(id as f64)),
        _ => String::new(),
    };
    let time_filter = match time_statement {
        Some(statement) if !statement.is_empty() => strip_leading_and(statement),
        _ => String::new(),
    };
    let join_nonempty = |parts: &[&str]| parts.iter().filter(|part| !part.is_empty()).copied().collect::<Vec<_>>().join(" AND ");

    let session_level_subquery = |parameter: &FilterParameter, filter_type: FilterType, values: &[FilterValue]| {
        let where_clause = join_nonempty(&[&site_id_filter, &time_filter]);
        let negated = match filter_type {
            FilterType::NotEquals => Some(FilterType::Equals),
            FilterType::NotContains => Some(FilterType::Contains),
            FilterType::NotRegex => Some(FilterType::Regex),
            FilterType::IsNull => Some(FilterType::IsNotNull),
            _ => None,
        };
        let positive = negated.unwrap_or(filter_type);
        let condition = build_string_filter_condition(&sql_param(parameter), positive, values)?;
        let membership = if negated.is_some() { "NOT IN" } else { "IN" };
        let final_where =
            if where_clause.is_empty() { format!("WHERE {condition}") } else { format!("WHERE {where_clause} AND {condition}") };
        Ok::<_, FilterStatementError>(format!(
            "session_id {membership} (
            SELECT DISTINCT session_id
            FROM events
            {final_where}
          )"
        ))
    };

    let session_channel_subquery = |filter_type: FilterType, values: &[FilterValue]| {
        let where_clause = join_nonempty(&[&site_id_filter, &time_filter]);
        let where_statement = if where_clause.is_empty() { String::new() } else { format!("WHERE {where_clause}") };
        let condition = build_string_filter_condition("session_channel", filter_type, values)?;
        Ok::<_, FilterStatementError>(format!(
            "session_id IN (
            SELECT session_id
            FROM (
              SELECT
                session_id,
                {SESSION_CHANNEL_AGG} AS session_channel
              FROM events
              {where_statement}
              GROUP BY session_id
            )
            WHERE {condition}
          )"
        ))
    };

    let mut parts = Vec::with_capacity(filters.len());
    for filter in &filters {
        let parameter = &filter.parameter;
        let filter_type = filter.filter_type;
        let values = &filter.value;
        let is_null_check = matches!(filter_type, FilterType::IsNull | FilterType::IsNotNull);

        if session_level_params.contains(parameter) {
            parts.push(if *parameter == FilterParameter::Channel {
                session_channel_subquery(filter_type, values)?
            } else {
                session_level_subquery(parameter, filter_type, values)?
            });
            continue;
        }

        if matches!(parameter, FilterParameter::EntryPage | FilterParameter::ExitPage) {
            let (aggregate, alias) = if *parameter == FilterParameter::EntryPage {
                ("argMin", "entry_pathname")
            } else {
                ("argMax", "exit_pathname")
            };
            let where_clause = join_nonempty(&[&site_id_filter, &time_filter, "type = 'pageview'"]);
            let where_statement = if where_clause.is_empty() { String::new() } else { format!("WHERE {where_clause}") };
            let condition = build_string_filter_condition(alias, filter_type, values)?;
            parts.push(format!(
                "session_id IN (
            SELECT session_id
            FROM (
              SELECT
                session_id,
                {aggregate}(pathname, timestamp_ms) AS {alias}
              FROM events
              {where_statement}
              GROUP BY session_id
            )
            WHERE {condition}
          )"
            ));
            continue;
        }

        if *parameter == FilterParameter::UserId && options.dual_user_id_columns.unwrap_or(true) {
            match filter_type {
                FilterType::IsNull => {
                    parts.push(
                        "((user_id IS NULL OR user_id = '') AND (identified_user_id IS NULL OR identified_user_id = ''))"
                            .to_string(),
                    );
                    continue;
                }
                FilterType::IsNotNull => {
                    parts.push(
                        "((user_id IS NOT NULL AND user_id != '') OR (identified_user_id IS NOT NULL AND identified_user_id != ''))"
                            .to_string(),
                    );
                    continue;
                }
                FilterType::Equals | FilterType::NotEquals => {
                    let render = |value: &FilterValue| {
                        let escaped = escape_filter_value(value);
                        if filter_type == FilterType::Equals {
                            matches_user(&escaped, "")
                        } else {
                            does_not_match_user(&escaped, "")
                        }
                    };
                    if values.len() == 1 {
                        parts.push(render(&values[0]));
                    } else {
                        let joiner = if filter_type == FilterType::Equals { " OR " } else { " AND " };
                        parts.push(format!("({})", values.iter().map(render).collect::<Vec<_>>().join(joiner)));
                    }
                    continue;
                }
                _ => {}
            }
        }

        if is_null_check || matches!(filter_type, FilterType::Regex | FilterType::NotRegex) {
            parts.push(build_string_filter_condition(&map_field(sql_param(parameter)), filter_type, values)?);
            continue;
        }

        if matches!(
            filter_type,
            FilterType::GreaterThan | FilterType::LessThan | FilterType::GreaterThanOrEqual | FilterType::LessThanOrEqual
        ) {
            let first = values.first();
            let numeric_value = first.map_or(f64::NAN, FilterValue::to_number);
            if numeric_value.is_nan() {
                let value = first.map_or_else(|| "undefined".to_string(), FilterValue::to_js_string);
                return Err(FilterStatementError::InvalidNumber { filter_type, value });
            }
            parts.push(format!(
                "{} {} {}",
                map_field(sql_param(parameter)),
                operator_text(filter_type),
                number_to_string(numeric_value)
            ));
            continue;
        }

        if matches!(filter_type, FilterType::StartsWith | FilterType::EndsWith) {
            parts.push(build_string_filter_condition(&map_field(sql_param(parameter)), filter_type, values)?);
            continue;
        }

        if matches!(parameter, FilterParameter::Lat | FilterParameter::Lon) {
            const TOLERANCE: f64 = 0.001;
            let column = map_field(sql_param(parameter));
            let ranges: Vec<String> = values
                .iter()
                .map(|value| {
                    let target = value.to_number();
                    format!(
                        "({column} >= {} AND {column} <= {})",
                        number_to_string(target - TOLERANCE),
                        number_to_string(target + TOLERANCE)
                    )
                })
                .collect();
            let range_condition = if ranges.len() == 1 { ranges[0].clone() } else { format!("({})", ranges.join(" OR ")) };
            parts.push(if filter_type == FilterType::NotEquals { format!("NOT {range_condition}") } else { range_condition });
            continue;
        }

        let column = map_field(sql_param(parameter));
        let operator = operator_text(filter_type);
        let render = |value: &FilterValue| format!("{column} {operator} {}", escape_string(&wrap_like_value(filter_type, value)));
        if values.len() == 1 {
            parts.push(render(&values[0]));
        } else {
            let joiner = if is_negative_joiner(filter_type) { " AND " } else { " OR " };
            parts.push(format!("({})", values.iter().map(render).collect::<Vec<_>>().join(joiner)));
        }
    }

    Ok(format!("AND {}", parts.join(" AND ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(filters: &str) -> String {
        get_filter_statement_str(filters, None, None, &FilterStatementOptions::default()).unwrap()
    }

    fn statement_with(filters: &str, site_id: Option<i64>, time: Option<&str>, options: FilterStatementOptions) -> String {
        get_filter_statement_str(filters, site_id, time, &options).unwrap()
    }

    fn one(parameter: &str, filter_type: &str, values: &str) -> String {
        format!(r#"[{{"parameter":"{parameter}","type":"{filter_type}","value":{values}}}]"#)
    }

    fn normalize(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn mappings(pairs: &[(&str, &str)]) -> FilterStatementOptions {
        FilterStatementOptions {
            field_mappings: Some(pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()),
            ..Default::default()
        }
    }

    // Ported from getFilterStatement.test.ts
    #[test]
    fn get_sql_param_cases() {
        for utm in ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"] {
            assert_eq!(get_sql_param(utm).unwrap(), format!("url_parameters['{utm}']"));
        }
        assert_eq!(get_sql_param("url_param:campaign_id").unwrap(), "url_parameters['campaign_id']");
        assert_eq!(get_sql_param("url_param:ref").unwrap(), "url_parameters['ref']");
        assert_eq!(get_sql_param("feature_flag:new_checkout").unwrap(), "feature_flags['new_checkout']");
        assert_eq!(get_sql_param("referrer").unwrap(), "domainWithoutWWW(referrer)");
        assert_eq!(
            get_sql_param("entry_page").unwrap(),
            "(SELECT argMinIf(pathname, timestamp_ms, type = 'pageview') FROM events WHERE session_id = events.session_id)"
        );
        assert_eq!(
            get_sql_param("exit_page").unwrap(),
            "(SELECT argMaxIf(pathname, timestamp_ms, type = 'pageview') FROM events WHERE session_id = events.session_id)"
        );
        assert_eq!(get_sql_param("dimensions").unwrap(), "concat(toString(screen_width), 'x', toString(screen_height))");
        assert_eq!(get_sql_param("city").unwrap(), "concat(toString(region), '-', toString(city))");
        assert_eq!(get_sql_param("browser_version").unwrap(), "concat(toString(browser), ' ', toString(browser_version))");
        let os = get_sql_param("operating_system_version").unwrap();
        assert!(os.contains("CASE") && os.contains("Windows 10/11"));
        for plain in ["browser", "country", "pathname", "device_type"] {
            assert_eq!(get_sql_param(plain).unwrap(), plain);
        }
        assert!(get_sql_param("password").is_err());
    }

    #[test]
    fn empty_invalid_and_basic() {
        assert_eq!(statement(""), "");
        assert_eq!(statement("[]"), "");
        assert_eq!(
            get_filter_statement_str("invalid json", None, None, &FilterStatementOptions::default()).unwrap_err().to_string(),
            "Invalid JSON format"
        );
        assert_eq!(statement(&one("browser", "equals", r#"["Chrome"]"#)), "AND browser = 'Chrome'");
        assert_eq!(statement(&one("browser", "equals", r#"["Chrome","Firefox"]"#)), "AND (browser = 'Chrome' OR browser = 'Firefox')");
        assert_eq!(
            statement(r#"[{"parameter":"browser","type":"equals","value":["Chrome"]},{"parameter":"country","type":"equals","value":["US"]}]"#),
            "AND browser = 'Chrome' AND country = 'US'"
        );
        assert_eq!(statement(&one("browser", "not_equals", r#"["Chrome"]"#)), "AND browser != 'Chrome'");
        assert_eq!(
            statement(&one("browser", "not_equals", r#"["Chrome","Firefox"]"#)),
            "AND (browser != 'Chrome' AND browser != 'Firefox')"
        );
        assert_eq!(statement(&one("pathname", "contains", r#"["/blog"]"#)), "AND pathname LIKE '%/blog%'");
        assert_eq!(statement(&one("pathname", "not_contains", r#"["/admin"]"#)), "AND pathname NOT LIKE '%/admin%'");
    }

    #[test]
    fn regex_filters() {
        assert_eq!(statement(&one("pathname", "regex", r#"["^/blog/.*"]"#)), "AND match(pathname, '^/blog/.*')");
        assert_eq!(statement(&one("pathname", "not_regex", r#"["^/admin/.*"]"#)), "AND NOT match(pathname, '^/admin/.*')");
        let error = |values: &str| {
            get_filter_statement_str(&one("pathname", "regex", values), None, None, &FilterStatementOptions::default())
                .unwrap_err()
                .to_string()
        };
        assert!(error(r#"[""]"#).contains("Regex pattern cannot be empty"));
        assert!(error(r#"["[invalid"]"#).contains("Invalid regex pattern"));
        assert!(error(&format!(r#"["{}"]"#, "a".repeat(501))).contains("Regex pattern too long"));
    }

    #[test]
    fn numeric_and_lat_lon() {
        assert_eq!(statement(&one("lat", "greater_than", r#"["40.0"]"#)), "AND lat > 40");
        assert_eq!(statement(&one("lon", "less_than", r#"["-70.0"]"#)), "AND lon < -70");
        assert!(
            get_filter_statement_str(&one("lat", "greater_than", r#"["not-a-number"]"#), None, None, &FilterStatementOptions::default())
                .unwrap_err()
                .to_string()
                .contains("Invalid numeric value")
        );
        let lat = statement(&one("lat", "equals", r#"["40.7128"]"#));
        assert!(lat.contains("lat >= 40.7118") && lat.contains("lat <= 40.7138"));
        let lon = statement(&one("lon", "equals", r#"["-74.006","-73.5"]"#));
        for part in ["lon >= -74.007", "lon <= -74.005", "lon >= -73.501", "lon <= -73.499", " OR "] {
            assert!(lon.contains(part), "{part}");
        }
        assert_eq!(statement(&one("lat", "greater_than_or_equal", r#"["40.5"]"#)), "AND lat >= 40.5");
        assert_eq!(statement(&one("lon", "less_than_or_equal", r#"["-70.25"]"#)), "AND lon <= -70.25");
        assert_eq!(statement(&one("lat", "greater_than_or_equal", r#"["10","20"]"#)), "AND lat >= 10");
        assert_eq!(statement(&one("pathname", "greater_than_or_equal", r#"["10"]"#)), "AND pathname >= 10");
        assert!(
            get_filter_statement_str(&one("lat", "greater_than_or_equal", r#"["abc"]"#), None, None, &FilterStatementOptions::default())
                .unwrap_err()
                .to_string()
                .contains("Invalid numeric value")
        );
    }

    #[test]
    fn user_id_filters() {
        assert_eq!(
            statement(&one("user_id", "equals", r#"["user123"]"#)),
            "AND (identified_user_id = 'user123' OR (user_id = 'user123' AND identified_user_id = ''))"
        );
        assert_eq!(
            statement(&one("user_id", "not_equals", r#"["user123"]"#)),
            "AND NOT (identified_user_id = 'user123' OR (user_id = 'user123' AND identified_user_id = ''))"
        );
        let many = statement(&one("user_id", "equals", r#"["user1","user2"]"#));
        assert!(many.contains("identified_user_id = 'user1' OR (user_id = 'user1' AND identified_user_id = '')"));
        assert!(many.contains("identified_user_id = 'user2' OR (user_id = 'user2' AND identified_user_id = '')"));
        assert!(many.contains(" OR "));
        let not_many = statement(&one("user_id", "not_equals", r#"["user1","user2"]"#));
        assert!(not_many.contains("NOT (identified_user_id = 'user1' OR (user_id = 'user1' AND identified_user_id = ''))"));
        assert!(not_many.contains("NOT (identified_user_id = 'user2' OR (user_id = 'user2' AND identified_user_id = ''))"));
        assert!(not_many.contains(" AND "));
        let fp = statement(&one("user_id", "equals", r#"["fp1"]"#));
        assert!(fp.contains("identified_user_id = ''") && !fp.trim_end().ends_with("user_id = 'fp1')"));
    }

    #[test]
    fn session_level_filters() {
        let event = statement(&one("event_name", "equals", r#"["click"]"#));
        for part in ["session_id IN", "SELECT DISTINCT session_id", "FROM events", "event_name = 'click'"] {
            assert!(event.contains(part), "{part}");
        }
        assert!(statement_with(&one("event_name", "equals", r#"["click"]"#), Some(123), None, Default::default()).contains("site_id = 123"));
        assert!(
            statement_with(&one("event_name", "equals", r#"["click"]"#), Some(123), Some("AND timestamp > now() - INTERVAL 1 DAY"), Default::default())
                .contains("timestamp > now() - INTERVAL 1 DAY")
        );
        let channel = statement_with(
            &one("channel", "equals", r#"["Organic Search"]"#),
            Some(123),
            Some("AND timestamp > now() - INTERVAL 1 DAY"),
            Default::default(),
        );
        for part in [
            "session_id IN",
            "argMinIf(channel, timestamp, channel NOT IN ('Direct', 'Internal', ''))",
            "AS session_channel",
            "site_id = 123",
            "timestamp > now() - INTERVAL 1 DAY",
            "session_channel = 'Organic Search'",
        ] {
            assert!(channel.contains(part), "{part}");
        }
        assert_eq!(
            statement_with(
                &one("channel", "equals", r#"["Organic Search"]"#),
                None,
                None,
                FilterStatementOptions::session_level(vec![FilterParameter::EventName])
            ),
            "AND channel = 'Organic Search'"
        );
        let entry = statement(&one("entry_page", "equals", r#"["/home"]"#));
        for part in ["session_id IN", "argMin(pathname, timestamp_ms) AS entry_pathname", "type = 'pageview'", "entry_pathname = '/home'"] {
            assert!(entry.contains(part), "{part}");
        }
        let entries = statement(&one("entry_page", "equals", r#"["/home","/landing"]"#));
        assert!(entries.contains("entry_pathname = '/home'") && entries.contains("entry_pathname = '/landing'") && entries.contains(" OR "));
        assert!(statement(&one("entry_page", "contains", r#"["/blog"]"#)).contains("entry_pathname LIKE '%/blog%'"));
        let exit = statement(&one("exit_page", "equals", r#"["/checkout"]"#));
        for part in ["session_id IN", "argMax(pathname, timestamp_ms) AS exit_pathname", "type = 'pageview'", "exit_pathname = '/checkout'"] {
            assert!(exit.contains(part), "{part}");
        }
        let exits = statement(&one("exit_page", "equals", r#"["/checkout","/thank-you"]"#));
        assert!(exits.contains("exit_pathname = '/checkout'") && exits.contains("exit_pathname = '/thank-you'") && exits.contains(" OR "));
    }

    #[test]
    fn utm_injection_and_transforms() {
        assert_eq!(statement(&one("utm_source", "equals", r#"["google"]"#)), "AND url_parameters['utm_source'] = 'google'");
        assert_eq!(statement(&one("utm_medium", "equals", r#"["cpc"]"#)), "AND url_parameters['utm_medium'] = 'cpc'");
        let injected = statement(&one("browser", "equals", r#"["Chrome'; DROP TABLE users;--"]"#));
        assert!(injected.contains("\\'"));
        assert_eq!(injected, "AND browser = 'Chrome\\'; DROP TABLE users;--'");
        assert!(statement(&one("pathname", "equals", r#"["/path\\with\\backslashes"]"#)).contains("\\\\"));
        assert_eq!(statement(&one("referrer", "equals", r#"["google.com"]"#)), "AND domainWithoutWWW(referrer) = 'google.com'");
        let dims = statement(&one("dimensions", "equals", r#"["1920x1080"]"#));
        assert!(dims.contains("concat(toString(screen_width), 'x', toString(screen_height))") && dims.contains("= '1920x1080'"));
        let city = statement(&one("city", "equals", r#"["CA-San Francisco"]"#));
        assert!(city.contains("concat(toString(region), '-', toString(city))") && city.contains("= 'CA-San Francisco'"));
        let complex = statement(
            r#"[{"parameter":"browser","type":"equals","value":["Chrome"]},{"parameter":"pathname","type":"contains","value":["/blog"]},{"parameter":"country","type":"not_equals","value":["CN"]}]"#,
        );
        assert!(complex.contains("browser = 'Chrome'") && complex.contains("pathname LIKE '%/blog%'") && complex.contains("country != 'CN'"));
        assert_eq!(complex.matches("AND").count(), 3);
    }

    #[test]
    fn null_checks_and_like_variants() {
        assert_eq!(statement(&one("browser", "is_null", "[]")), "AND (browser IS NULL OR browser = '')");
        assert_eq!(statement(&one("country", "is_not_null", "[]")), "AND (country IS NOT NULL AND country != '')");
        assert_eq!(
            statement(&one("utm_source", "is_null", "[]")),
            "AND (url_parameters['utm_source'] IS NULL OR url_parameters['utm_source'] = '')"
        );
        let event = statement(&one("event_name", "is_not_null", "[]"));
        assert!(event.contains("session_id IN") && event.contains("(event_name IS NOT NULL AND event_name != '')"));
        assert_eq!(statement(&one("pathname", "starts_with", r#"["/blog"]"#)), "AND pathname LIKE '/blog%'");
        assert_eq!(statement(&one("pathname", "ends_with", r#"["/checkout"]"#)), "AND pathname LIKE '%/checkout'");
        assert_eq!(statement(&one("pathname", "starts_with", r#"["/blog","/docs"]"#)), "AND (pathname LIKE '/blog%' OR pathname LIKE '/docs%')");
        assert_eq!(statement(&one("pathname", "starts_with", r#"["50%"]"#)), "AND pathname LIKE '50\\\\%%'");
        assert_eq!(statement(&one("pathname", "ends_with", r#"["a_b"]"#)), "AND pathname LIKE '%a\\\\_b'");
        assert_eq!(statement(&one("pathname", "starts_with", r#"["C:\\temp"]"#)), "AND pathname LIKE 'C:\\\\\\\\temp%'");
        assert_eq!(statement(&one("pathname", "contains", r#"["/blog","/docs"]"#)), "AND (pathname LIKE '%/blog%' OR pathname LIKE '%/docs%')");
        assert_eq!(
            statement(&one("pathname", "not_contains", r#"["/admin","/internal"]"#)),
            "AND (pathname NOT LIKE '%/admin%' AND pathname NOT LIKE '%/internal%')"
        );
        assert_eq!(
            statement(&one("pathname", "contains", r#"["100%","a_b"]"#)),
            "AND (pathname LIKE '%100\\\\%%' OR pathname LIKE '%a\\\\_b%')"
        );
        assert_eq!(
            statement(&one("utm_source", "contains", r#"["google","bing"]"#)),
            "AND (url_parameters['utm_source'] LIKE '%google%' OR url_parameters['utm_source'] LIKE '%bing%')"
        );
    }

    #[test]
    fn generic_session_subqueries() {
        let options = |params: Vec<FilterParameter>| FilterStatementOptions::session_level(params);
        assert_eq!(
            normalize(&statement_with(&one("pathname", "equals", r#"["/pricing"]"#), None, None, options(vec![FilterParameter::Pathname]))),
            "AND session_id IN ( SELECT DISTINCT session_id FROM events WHERE pathname = '/pricing' )"
        );
        assert_eq!(
            normalize(&statement_with(
                &one("hostname", "equals", r#"["app.example.com"]"#),
                Some(42),
                Some("AND timestamp > now() - INTERVAL 1 DAY"),
                options(vec![FilterParameter::Hostname])
            )),
            "AND session_id IN ( SELECT DISTINCT session_id FROM events WHERE site_id = 42 AND timestamp > now() - INTERVAL 1 DAY AND hostname = 'app.example.com' )"
        );
        assert_eq!(
            normalize(&statement_with(&one("hostname", "not_equals", r#"["bad.example.com"]"#), None, None, options(vec![FilterParameter::Hostname]))),
            "AND session_id NOT IN ( SELECT DISTINCT session_id FROM events WHERE hostname = 'bad.example.com' )"
        );
        assert_eq!(
            normalize(&statement_with(&one("pathname", "not_contains", r#"["/admin","/debug"]"#), None, None, options(vec![FilterParameter::Pathname]))),
            "AND session_id NOT IN ( SELECT DISTINCT session_id FROM events WHERE (pathname LIKE '%/admin%' OR pathname LIKE '%/debug%') )"
        );
        assert_eq!(
            normalize(&statement_with(&one("event_name", "is_null", "[]"), None, None, options(vec![FilterParameter::EventName]))),
            "AND session_id NOT IN ( SELECT DISTINCT session_id FROM events WHERE (event_name IS NOT NULL AND event_name != '') )"
        );
        assert_eq!(
            normalize(&statement_with(&one("city", "equals", r#"["CA-San Francisco"]"#), None, None, options(vec![FilterParameter::City]))),
            "AND session_id IN ( SELECT DISTINCT session_id FROM events WHERE concat(toString(region), '-', toString(city)) = 'CA-San Francisco' )"
        );
    }

    #[test]
    fn field_mappings_option() {
        assert_eq!(
            statement_with(&one("utm_source", "equals", r#"["google"]"#), None, None, mappings(&[("url_parameters['utm_source']", "utm_source")])),
            "AND utm_source = 'google'"
        );
        assert_eq!(
            statement_with(
                r#"[{"parameter":"utm_source","type":"equals","value":["google"]},{"parameter":"utm_medium","type":"contains","value":["cpc"]}]"#,
                None,
                None,
                mappings(&[("url_parameters['utm_source']", "utm_source"), ("url_parameters['utm_medium']", "utm_medium")])
            ),
            "AND utm_source = 'google' AND utm_medium LIKE '%cpc%'"
        );
        assert_eq!(
            statement_with(
                r#"[{"parameter":"pathname","type":"equals","value":["/pricing"]},{"parameter":"page_title","type":"equals","value":["pathname"]}]"#,
                None,
                None,
                mappings(&[("pathname", "page_path")])
            ),
            "AND page_path = '/pricing' AND page_title = 'pathname'"
        );
        let lat = statement_with(&one("lat", "equals", r#"["40.7128"]"#), None, None, mappings(&[("lat", "latitude")]));
        assert!(lat.contains("latitude >= 40.7118") && lat.contains("latitude <= 40.7138") && !lat.contains("(lat >="));
        let lon = statement_with(&one("lon", "not_equals", r#"["-74.006","-73.5"]"#), None, None, mappings(&[("lon", "longitude")]));
        assert!(lon.contains("NOT ((longitude >= -74.007 AND longitude <= -74.005)"));
        assert!(lon.contains("(longitude >= -73.501 AND longitude <= -73.499)"));
        assert_eq!(
            statement_with(
                &one("page_title", "equals", r#"["url_parameters['utm_source']"]"#),
                None,
                None,
                mappings(&[("url_parameters['utm_source']", "utm_source")])
            ),
            "AND page_title = 'url_parameters[\\'utm_source\\']'"
        );
    }

    #[test]
    fn re2_unsupported_detection() {
        for pattern in ["^(?!.*test).*$", "^/docs/(?=guide)", "(a)\\1", "(?<=a)b", "(?<!a)b"] {
            assert!(uses_re2_unsupported_syntax(pattern), "{pattern}");
        }
        for pattern in ["^/docs/[a-z-]+$", "(?<name>x)", "\\0", "a(?:b)"] {
            assert!(!uses_re2_unsupported_syntax(pattern), "{pattern}");
        }
    }
}
