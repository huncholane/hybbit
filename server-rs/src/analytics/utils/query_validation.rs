//! Port of server/src/api/analytics/utils/query-validation.ts: the zod schemas
//! guarding the `filters` query param and the shared time query params.

use std::cmp::Ordering;

use tracing::debug;

use crate::analytics::{
    js::{
        JsObject, JsValue, json,
        zod::{self, Parsed, Path, PathSegment, Status, ZodIssue},
    },
    types::{Filter, FilterParameter, FilterType, FilterValue},
};

use super::time_window::{is_date_format, is_date_time_format, is_valid_time_zone_value, parse_date_time_ms};

/// Why `validateFilters` threw. Node's handlers turn any of these into a 500
/// (or a 400 "Invalid filters" during segment expansion); the message is what
/// Node logs.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum FiltersError {
    #[error("Invalid JSON format")]
    InvalidJson,
    /// A `ZodError`; `Display` is its message (the issues as indented JSON)
    #[error("{}", zod::error_message(.0))]
    Schema(Vec<ZodIssue>),
}

/// `z.string().regex(/^feature_flag:[A-Za-z][A-Za-z0-9_.:-]{0,99}$/)`.
fn is_feature_flag_parameter(text: &str) -> bool {
    let Some(key) = text.strip_prefix("feature_flag:") else { return false };
    let bytes = key.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 100
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..].iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

/// `filterParamSchema`: the base enum, or a feature flag string. A string that is
/// neither comes back dirty (the regex option's issue), not aborted.
pub fn parse_filter_parameter(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<String> {
    let base_names = FilterParameter::base_names();
    zod::union2(
        path,
        issues,
        |option_issues| zod::enumeration(value, &base_names, path, option_issues),
        |option_issues| match value {
            JsValue::String(text) => {
                if is_feature_flag_parameter(text) {
                    Some((Status::Valid, text.clone()))
                } else {
                    option_issues.push(zod::invalid_string_regex(path, None));
                    Some((Status::Dirty, text.clone()))
                }
            }
            other => {
                option_issues.push(zod::invalid_type(path, "string", other));
                None
            }
        },
    )
}

/// `filterParamSchema.parse(parameter)` for a string.
pub fn filter_parameter_schema_parse(parameter: &str) -> Result<FilterParameter, Vec<ZodIssue>> {
    let mut issues = Vec::new();
    match parse_filter_parameter(&JsValue::String(parameter.to_string()), &Vec::new(), &mut issues) {
        Some((Status::Valid, name)) => Ok(FilterParameter::from_name(&name).expect("validated parameter")),
        _ => Err(issues),
    }
}

/// A filter as zod hands it on, possibly dirty (an invalid parameter string).
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedFilter {
    pub parameter: String,
    pub filter_type: FilterType,
    pub value: Vec<FilterValue>,
}

impl ParsedFilter {
    pub fn into_filter(self) -> Option<Filter> {
        Some(Filter { parameter: FilterParameter::from_name(&self.parameter)?, filter_type: self.filter_type, value: self.value })
    }
}

/// `z.string().or(z.number())`.
fn parse_filter_value(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<FilterValue> {
    zod::union2(
        path,
        issues,
        |option_issues| match value {
            JsValue::String(text) => Some((Status::Valid, FilterValue::String(text.clone()))),
            other => {
                option_issues.push(zod::invalid_type(path, "string", other));
                None
            }
        },
        |option_issues| match value {
            JsValue::Number(number) if !number.is_nan() => Some((Status::Valid, FilterValue::Number(*number))),
            other => {
                option_issues.push(zod::invalid_type(path, "number", other));
                None
            }
        },
    )
}

/// `filterSchema`: `z.object({ parameter, type, value })`, unknown keys stripped.
pub fn parse_filter(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<ParsedFilter> {
    let JsValue::Object(object) = value else {
        issues.push(zod::invalid_type(path, "object", value));
        return None;
    };
    let parameter = parse_filter_parameter(object.get_or_undefined("parameter"), &zod::key(path, "parameter"), issues);
    let filter_type = zod::enumeration(object.get_or_undefined("type"), &FilterType::names(), &zod::key(path, "type"), issues);

    let value_path = zod::key(path, "value");
    let values = match object.get_or_undefined("value") {
        JsValue::Array(items) => {
            let parsed: Vec<Parsed<FilterValue>> = items
                .iter()
                .enumerate()
                .map(|(position, item)| parse_filter_value(item, &zod::index(&value_path, position), issues))
                .collect();
            let mut status = Status::Valid;
            let mut values = Vec::with_capacity(parsed.len());
            let mut aborted = false;
            for item in parsed {
                match item {
                    Some((item_status, item_value)) => {
                        status = status.merge(item_status);
                        values.push(item_value);
                    }
                    None => aborted = true,
                }
            }
            (!aborted).then_some((status, values))
        }
        other => {
            issues.push(zod::invalid_type(&value_path, "array", other));
            None
        }
    };

    let (parameter_status, parameter) = parameter?;
    let (type_status, filter_type) = filter_type?;
    let (value_status, value) = values?;
    let status = parameter_status.merge(type_status).merge(value_status);
    let filter_type = FilterType::parse(&filter_type).expect("enum-validated filter type");
    Some((status, ParsedFilter { parameter, filter_type, value }))
}

/// `z.array(filterSchema).parse(value)`.
pub fn parse_filters_array(value: &JsValue) -> Result<Vec<Filter>, Vec<ZodIssue>> {
    let mut issues = Vec::new();
    let path: Path = Vec::new();
    let JsValue::Array(items) = value else {
        return Err(vec![zod::invalid_type(&path, "array", value)]);
    };
    let parsed: Vec<Parsed<ParsedFilter>> =
        items.iter().enumerate().map(|(position, item)| parse_filter(item, &zod::index(&path, position), &mut issues)).collect();
    if !issues.is_empty() {
        return Err(issues);
    }
    Ok(parsed
        .into_iter()
        .map(|item| item.and_then(|(_, filter)| filter.into_filter()).expect("valid filters carry no issues"))
        .collect())
}

/// `validateFilters(filtersStr)`: `JSON.parse`, then `z.array(filterSchema).parse`.
pub fn validate_filters(filters: &str) -> Result<Vec<Filter>, FiltersError> {
    let parsed = json::parse(filters).map_err(|_| FiltersError::InvalidJson)?;
    parse_filters_array(&parsed).map_err(|issues| {
        debug!(issue_count = issues.len(), "filters failed schema validation");
        FiltersError::Schema(issues)
    })
}

/// A present-or-undefined field of the time params schema.
type Field = Parsed<JsValue>;

/// A string check and the message its failure reports.
type StringCheck<'a> = (fn(&str) -> bool, &'a str);

fn optional_string_field(
    value: &JsValue,
    path: &Path,
    issues: &mut Vec<ZodIssue>,
    format: Option<StringCheck<'_>>,
    refine: StringCheck<'_>,
) -> Field {
    match value {
        JsValue::Undefined => Some((Status::Valid, JsValue::Undefined)),
        JsValue::String(text) => {
            let mut status = Status::Valid;
            if let Some((matches, message)) = format
                && !matches(text)
            {
                issues.push(zod::invalid_string_regex(path, Some(message)));
                status = Status::Dirty;
            }
            let (check, message) = refine;
            if !check(text) {
                issues.push(zod::custom(path, message));
                status = Status::Dirty;
            }
            Some((status, value.clone()))
        }
        other => {
            issues.push(zod::invalid_type(path, "string", other));
            None
        }
    }
}

/// `z.union([z.string(), z.number()]).optional().refine(non-negative)`.
fn optional_minutes_field(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Field {
    if value.is_undefined() {
        return Some((Status::Valid, JsValue::Undefined));
    }
    let (status, parsed) = zod::union2(
        path,
        issues,
        |option_issues| match value {
            JsValue::String(_) => Some((Status::Valid, value.clone())),
            other => {
                option_issues.push(zod::invalid_type(path, "string", other));
                None
            }
        },
        |option_issues| match value {
            JsValue::Number(number) if !number.is_nan() => Some((Status::Valid, value.clone())),
            other => {
                option_issues.push(zod::invalid_type(path, "number", other));
                None
            }
        },
    )?;
    let number = parsed.to_number();
    if !number.is_nan() && number >= 0.0 {
        Some((status, parsed))
    } else {
        issues.push(zod::custom(path, "past_minutes values must be non-negative numbers"));
        Some((Status::Dirty, parsed))
    }
}

/// `validateHttpTimeParams(query)`: the joined issue messages when the time
/// params are present but invalid, `None` when valid or absent. Empty-string
/// values count as absent.
pub fn validate_http_time_params(query: &JsValue) -> Option<String> {
    let without_empty: JsObject = match query {
        JsValue::Object(object) => object
            .iter()
            .filter(|(_, value)| !matches!(value, JsValue::String(text) if text.is_empty()))
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect(),
        // Arrays have only index keys and primitives no entries: nothing to check
        _ => return None,
    };
    let root: Path = Vec::new();
    let field = |name: &str| without_empty.get_or_undefined(name);
    let path = |name: &str| vec![PathSegment::Key(name.to_string())];
    let mut issues = Vec::new();

    let start_date = optional_string_field(
        field("start_date"),
        &path("start_date"),
        &mut issues,
        Some((is_date_format, "Invalid start_date format. Use YYYY-MM-DD")),
        (|date| !crate::analytics::js::date::parse(date).is_nan(), "Invalid start_date value"),
    );
    let end_date = optional_string_field(
        field("end_date"),
        &path("end_date"),
        &mut issues,
        Some((is_date_format, "Invalid end_date format. Use YYYY-MM-DD")),
        (|date| !crate::analytics::js::date::parse(date).is_nan(), "Invalid end_date value"),
    );
    let time_zone = optional_string_field(
        field("time_zone"),
        &path("time_zone"),
        &mut issues,
        None,
        (|zone| is_valid_time_zone_value(&JsValue::String(zone.to_string())), "Invalid time_zone"),
    );
    let start_datetime = optional_string_field(
        field("start_datetime"),
        &path("start_datetime"),
        &mut issues,
        Some((is_date_time_format, "Invalid start_datetime format. Use YYYY-MM-DD HH:mm:ss")),
        (|value| !parse_date_time_ms(value).is_nan(), "Invalid start_datetime value"),
    );
    let end_datetime = optional_string_field(
        field("end_datetime"),
        &path("end_datetime"),
        &mut issues,
        Some((is_date_time_format, "Invalid end_datetime format. Use YYYY-MM-DD HH:mm:ss")),
        (|value| !parse_date_time_ms(value).is_nan(), "Invalid end_datetime value"),
    );
    let past_minutes_start = optional_minutes_field(field("past_minutes_start"), &path("past_minutes_start"), &mut issues);
    let past_minutes_end = optional_minutes_field(field("past_minutes_end"), &path("past_minutes_end"), &mut issues);

    // The object refinements only run when no field aborted
    if let (Some((_, start_date)), Some((_, end_date)), Some(_), Some((_, start_datetime)), Some((_, end_datetime)), Some((_, pms)), Some((_, pme))) =
        (start_date, end_date, time_zone, start_datetime, end_datetime, past_minutes_start, past_minutes_end)
    {
        if start_date.is_truthy() != end_date.is_truthy() {
            issues.push(zod::custom(&root, "start_date and end_date must be provided together"));
        }
        if start_datetime.is_truthy() != end_datetime.is_truthy() {
            issues.push(zod::custom(&root, "start_datetime and end_datetime must be provided together"));
        }
        if pms.is_undefined() != pme.is_undefined() {
            issues.push(zod::custom(&root, "past_minutes_start and past_minutes_end must be provided together"));
        }
        if start_datetime.is_truthy()
            && end_datetime.is_truthy()
            && parse_date_time_ms(&start_datetime.to_js_string()).partial_cmp(&parse_date_time_ms(&end_datetime.to_js_string()))
                != Some(Ordering::Less)
        {
            issues.push(zod::custom(&root, "start_datetime must be before end_datetime"));
        }
        if !pms.is_undefined() && !pme.is_undefined() && pms.to_number().partial_cmp(&pme.to_number()) != Some(Ordering::Greater) {
            issues.push(zod::custom(
                &root,
                "past_minutes_start must be greater than past_minutes_end (start = older, end = newer)",
            ));
        }
    }

    if issues.is_empty() {
        return None;
    }
    let message = issues.iter().map(ZodIssue::message).collect::<Vec<_>>().join("; ");
    debug!(issue_count = issues.len(), "time params failed validation");
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json;

    fn check(query: &str) -> Option<String> {
        validate_http_time_params(&json::parse(query).unwrap())
    }

    // Ported from query-validation.test.ts
    #[test]
    fn validate_http_time_params_cases() {
        assert_eq!(check("{}"), None);
        assert_eq!(check(r#"{"site":"1","filters":"[]"}"#), None);
        assert_eq!(validate_http_time_params(&JsValue::Undefined), None);
        assert_eq!(validate_http_time_params(&JsValue::Null), None);
        assert_eq!(validate_http_time_params(&"start_date=2025-01-01".into()), None);
        assert_eq!(check(r#"{"start_date":"","end_date":""}"#), None);
        assert_eq!(
            check(r#"{"start_date":"","end_date":"","time_zone":"","start_datetime":"","end_datetime":"","past_minutes_start":"","past_minutes_end":""}"#),
            None
        );
        assert_eq!(check(r#"{"start_date":"","end_date":"2025-01-31"}"#).as_deref(), Some("start_date and end_date must be provided together"));
        assert_eq!(check(r#"{"start_date":"2025-01-01","end_date":"2025-01-31","time_zone":"America/New_York"}"#), None);
        assert_eq!(check(r#"{"start_date":"2025-01-01"}"#).as_deref(), Some("start_date and end_date must be provided together"));
        assert_eq!(check(r#"{"end_date":"2025-01-31"}"#).as_deref(), Some("start_date and end_date must be provided together"));
        assert_eq!(check(r#"{"start_date":"01/01/2025","end_date":"2025-01-31"}"#).as_deref(), Some("Invalid start_date format. Use YYYY-MM-DD"));
        assert_eq!(check(r#"{"start_date":"2025-01-01","end_date":"2025-1-31"}"#).as_deref(), Some("Invalid end_date format. Use YYYY-MM-DD"));
        assert_eq!(check(r#"{"start_date":"2025-13-45","end_date":"2025-01-31"}"#).as_deref(), Some("Invalid start_date value"));
        assert_eq!(check(r#"{"time_zone":"Asia/Tokyo"}"#), None);
        assert_eq!(check(r#"{"time_zone":"UTC"}"#), None);
        assert_eq!(check(r#"{"time_zone":"Not/AZone"}"#).as_deref(), Some("Invalid time_zone"));
        assert_eq!(check(r#"{"start_datetime":"2025-01-01 00:00:00","end_datetime":"2025-01-02 00:00:00"}"#), None);
        assert_eq!(check(r#"{"start_datetime":"2025-01-01T00:00:00Z","end_datetime":"2025-01-02T00:00:00Z"}"#), None);
        assert_eq!(check(r#"{"start_datetime":"2025-01-01T00:00:00+05:00","end_datetime":"2025-01-02T00:00:00+0500"}"#), None);
        assert_eq!(
            check(r#"{"start_datetime":"2025-01-01 00:00:00"}"#).as_deref(),
            Some("start_datetime and end_datetime must be provided together")
        );
        assert_eq!(
            check(r#"{"start_datetime":"2025-01-01","end_datetime":"2025-01-02 00:00:00"}"#).as_deref(),
            Some("Invalid start_datetime format. Use YYYY-MM-DD HH:mm:ss")
        );
        assert_eq!(
            check(r#"{"start_datetime":"2025-01-02 00:00:00","end_datetime":"2025-01-01 00:00:00"}"#).as_deref(),
            Some("start_datetime must be before end_datetime")
        );
        assert_eq!(
            check(r#"{"start_datetime":"2025-01-01 00:00:00","end_datetime":"2025-01-01 00:00:00"}"#).as_deref(),
            Some("start_datetime must be before end_datetime")
        );
        assert_eq!(check(r#"{"past_minutes_start":"60","past_minutes_end":"0"}"#), None);
        assert_eq!(check(r#"{"past_minutes_start":1440,"past_minutes_end":30}"#), None);
        assert_eq!(
            check(r#"{"past_minutes_start":"60"}"#).as_deref(),
            Some("past_minutes_start and past_minutes_end must be provided together")
        );
        assert_eq!(
            check(r#"{"past_minutes_end":"0"}"#).as_deref(),
            Some("past_minutes_start and past_minutes_end must be provided together")
        );
        let ordering = "past_minutes_start must be greater than past_minutes_end (start = older, end = newer)";
        assert_eq!(check(r#"{"past_minutes_start":"30","past_minutes_end":"60"}"#).as_deref(), Some(ordering));
        assert_eq!(check(r#"{"past_minutes_start":"60","past_minutes_end":"60"}"#).as_deref(), Some(ordering));
        assert_eq!(
            check(r#"{"past_minutes_start":"60","past_minutes_end":"-5"}"#).as_deref(),
            Some("past_minutes values must be non-negative numbers")
        );
        assert!(check(r#"{"past_minutes_start":"-5","past_minutes_end":"0"}"#).unwrap().contains("past_minutes values must be non-negative numbers"));
        assert!(check(r#"{"past_minutes_start":"abc","past_minutes_end":"0"}"#).unwrap().contains("past_minutes values must be non-negative numbers"));
        assert_eq!(
            check(r#"{"start_date":"bogus","past_minutes_start":"60"}"#).as_deref(),
            Some(
                "Invalid start_date format. Use YYYY-MM-DD; Invalid start_date value; start_date and end_date must be provided together; past_minutes_start and past_minutes_end must be provided together"
            )
        );
    }

    #[test]
    fn validate_filters_cases() {
        let filters = r#"[{"parameter":"browser","type":"equals","value":["Chrome"]}]"#;
        assert_eq!(
            validate_filters(filters).unwrap(),
            vec![Filter {
                parameter: FilterParameter::Browser,
                filter_type: FilterType::Equals,
                value: vec![FilterValue::String("Chrome".into())]
            }]
        );
        assert_eq!(validate_filters("[]").unwrap(), vec![]);
        assert_eq!(
            validate_filters(r#"[{"parameter":"lat","type":"greater_than","value":[45.5,"46"]}]"#).unwrap()[0].value,
            vec![FilterValue::Number(45.5), FilterValue::String("46".into())]
        );
        assert_eq!(validate_filters("not json"), Err(FiltersError::InvalidJson));
        assert_eq!(validate_filters("[{"), Err(FiltersError::InvalidJson));
        assert!(validate_filters(r#"{"parameter":"browser","type":"equals","value":["x"]}"#).is_err());
        assert!(validate_filters(r#"[{"parameter":"password","type":"equals","value":["x"]}]"#).is_err());
        assert!(validate_filters(r#"[{"parameter":"browser","type":"like","value":["x"]}]"#).is_err());
        assert!(validate_filters(r#"[{"parameter":"browser","type":"equals","value":"Chrome"}]"#).is_err());
        assert!(validate_filters(r#"[{"parameter":"browser","type":"equals","value":[true]}]"#).is_err());
        assert_eq!(
            validate_filters(r#"[{"parameter":"feature_flag:new_checkout","type":"equals","value":["true"]}]"#).unwrap()[0].parameter,
            FilterParameter::FeatureFlag("new_checkout".into())
        );
    }

    #[test]
    fn filter_param_schema_cases() {
        let ok = |text: &str| filter_parameter_schema_parse(text).is_ok();
        assert!(ok("browser") && ok("pathname") && ok("utm_source") && ok("tag"));
        assert!(!ok("screen_class") && !ok("") && !ok("BROWSER"));
        assert!(!ok("url_param:campaign_id"));
        assert!(ok("feature_flag:new_checkout") && ok("feature_flag:A") && ok("feature_flag:my.flag:v2-x_1"));
        assert!(ok(&format!("feature_flag:a{}", "b".repeat(99))));
        assert!(!ok(&format!("feature_flag:a{}", "b".repeat(100))));
        assert!(!ok("feature_flag:"));
        assert!(!ok("feature_flag:1abc") && !ok("feature_flag:has space") && !ok("feature_flag:x'; DROP") && !ok("feature_flag:flag\n"));
    }
}
