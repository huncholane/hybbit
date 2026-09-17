//! Port of server/src/api/analytics/segments/segmentSchema.ts: the zod schemas
//! for saved segments. createSegment/updateSegment answer a failed parse with
//! 400 `{ "error": "Validation error", "details": <zod issues> }`, so the issue
//! objects here are built exactly as zod builds them.

use tracing::debug;

use crate::analytics::{
    js::{
        JsObject, JsValue,
        string::{trim, utf16_len},
        zod::{self, Parsed, Path, PathSegment, SizedKind, Status, ZodIssue},
    },
    types::{Filter, FilterType},
    utils::{
        get_filter_statement::validate_regex_pattern,
        query_validation::{ParsedFilter, parse_filter},
    },
};

pub const SEGMENT_NAME_MAX_LENGTH: usize = 80;
pub const SEGMENT_DESCRIPTION_MAX_LENGTH: usize = 500;
pub const SEGMENT_MAX_FILTERS: usize = 20;
pub const SEGMENT_MAX_VALUES_PER_FILTER: usize = 50;
pub const SEGMENT_MAX_VALUE_LENGTH: usize = 500;

/// `segmentFilterSchema`: `filterSchema` plus the stored-segment constraints.
pub fn parse_segment_filter(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<ParsedFilter> {
    let (status, filter) = parse_filter(value, path, issues)?;
    let messages = segment_filter_refinement(&filter);
    if messages.is_empty() {
        return Some((status, filter));
    }
    let value_path = zod::key(path, "value");
    issues.extend(messages.iter().map(|message| zod::custom(&value_path, message)));
    Some((Status::Dirty, filter))
}

/// The `superRefine` body: the messages it adds, in order.
fn segment_filter_refinement(filter: &ParsedFilter) -> Vec<String> {
    let mut messages = Vec::new();
    if matches!(filter.filter_type, FilterType::IsNull | FilterType::IsNotNull) {
        return messages;
    }
    if filter.value.is_empty() {
        messages.push(format!("Filter on \"{}\" needs at least one value", filter.parameter));
        return messages;
    }
    if filter.value.len() > SEGMENT_MAX_VALUES_PER_FILTER {
        messages.push(format!("A filter can have at most {SEGMENT_MAX_VALUES_PER_FILTER} values"));
        return messages;
    }
    if filter.value.iter().any(|item| utf16_len(&item.to_js_string()) > SEGMENT_MAX_VALUE_LENGTH) {
        messages.push(format!("Filter values are limited to {SEGMENT_MAX_VALUE_LENGTH} characters"));
        return messages;
    }
    if matches!(filter.filter_type, FilterType::Regex | FilterType::NotRegex) {
        if filter.value.len() != 1 {
            messages.push("A regex filter takes exactly one pattern".to_string());
        }
        for item in &filter.value {
            if let Some(error) = validate_regex_pattern(&item.to_js_string()) {
                messages.push(error);
            }
        }
    }
    let numeric = matches!(
        filter.filter_type,
        FilterType::GreaterThan | FilterType::LessThan | FilterType::GreaterThanOrEqual | FilterType::LessThanOrEqual
    );
    if numeric || filter.parameter == "lat" || filter.parameter == "lon" {
        for item in &filter.value {
            if !item.to_number().is_finite() {
                messages.push(format!("Filter on \"{}\" needs numeric values", filter.parameter));
            }
        }
    }
    messages
}

/// `segmentFiltersSchema`: 1 to 20 segment filters.
pub fn parse_segment_filters(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<Vec<ParsedFilter>> {
    let JsValue::Array(items) = value else {
        issues.push(zod::invalid_type(path, "array", value));
        return None;
    };
    let mut status = Status::Valid;
    if items.is_empty() {
        issues.push(zod::too_small(path, SizedKind::Array, 1, Some("A segment needs at least one filter")));
        status = Status::Dirty;
    }
    if items.len() > SEGMENT_MAX_FILTERS {
        let message = format!("A segment can have at most {SEGMENT_MAX_FILTERS} filters");
        issues.push(zod::too_big(path, SizedKind::Array, SEGMENT_MAX_FILTERS, Some(&message)));
        status = Status::Dirty;
    }
    let parsed: Vec<Parsed<ParsedFilter>> =
        items.iter().enumerate().map(|(position, item)| parse_segment_filter(item, &zod::index(path, position), issues)).collect();
    let mut filters = Vec::with_capacity(parsed.len());
    for item in parsed {
        let (item_status, filter) = item?;
        status = status.merge(item_status);
        filters.push(filter);
    }
    Some((status, filters))
}

/// `segmentFiltersSchema.safeParse(value)`.
pub fn segment_filters_schema_parse(value: &JsValue) -> Result<Vec<Filter>, Vec<ZodIssue>> {
    let mut issues = Vec::new();
    match parse_segment_filters(value, &Vec::new(), &mut issues) {
        Some((Status::Valid, filters)) if issues.is_empty() => {
            Ok(filters.into_iter().map(|filter| filter.into_filter().expect("valid filter")).collect())
        }
        _ => Err(issues),
    }
}

/// `segmentScopeSchema`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentScope {
    Site,
    Organization,
}

impl SegmentScope {
    pub fn as_str(self) -> &'static str {
        match self {
            SegmentScope::Site => "site",
            SegmentScope::Organization => "organization",
        }
    }
}

/// An optional field that may also be `null` (`.nullable().optional()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nullable<T> {
    Absent,
    Null,
    Value(T),
}

/// `CreateSegmentBody` / `UpdateSegmentBody`; a create body always has `name`
/// and `filters`.
#[derive(Clone, Debug, PartialEq)]
pub struct SegmentBody {
    pub name: Option<String>,
    pub description: Nullable<String>,
    pub filters: Option<Vec<Filter>>,
    pub is_public: Option<bool>,
    pub scope: Option<SegmentScope>,
}

/// `z.string().trim()` with `.min`/`.max` checks (messages optional).
fn trimmed_string(
    value: &JsValue,
    path: &Path,
    issues: &mut Vec<ZodIssue>,
    min: Option<(usize, &str)>,
    max: usize,
) -> Parsed<String> {
    let JsValue::String(text) = value else {
        issues.push(zod::invalid_type(path, "string", value));
        return None;
    };
    let trimmed = trim(text).to_string();
    let length = utf16_len(&trimmed);
    let mut status = Status::Valid;
    if let Some((minimum, message)) = min
        && length < minimum
    {
        issues.push(zod::too_small(path, SizedKind::String, minimum, Some(message)));
        status = Status::Dirty;
    }
    if length > max {
        issues.push(zod::too_big(path, SizedKind::String, max, None));
        status = Status::Dirty;
    }
    Some((status, trimmed))
}

fn parse_segment_body(body: &JsValue, partial: bool) -> Result<SegmentBody, Vec<ZodIssue>> {
    let root: Path = Vec::new();
    let mut issues = Vec::new();
    let JsValue::Object(object) = body else {
        return Err(vec![zod::invalid_type(&root, "object", body)]);
    };
    let path = |name: &str| vec![PathSegment::Key(name.to_string())];
    let mut status = Status::Valid;
    let mut aborted = false;
    let mut merge = |parsed_status: Option<Status>| match parsed_status {
        Some(field_status) => status = status.merge(field_status),
        None => aborted = true,
    };

    let name_value = object.get_or_undefined("name");
    let name = if partial && name_value.is_undefined() {
        Some((Status::Valid, None))
    } else {
        trimmed_string(name_value, &path("name"), &mut issues, Some((1, "Segment name is required")), SEGMENT_NAME_MAX_LENGTH)
            .map(|(field_status, text)| (field_status, Some(text)))
    };
    merge(name.as_ref().map(|(field_status, _)| *field_status));

    let description = match object.get_or_undefined("description") {
        JsValue::Undefined => Some((Status::Valid, Nullable::Absent)),
        JsValue::Null => Some((Status::Valid, Nullable::Null)),
        other => trimmed_string(other, &path("description"), &mut issues, None, SEGMENT_DESCRIPTION_MAX_LENGTH)
            .map(|(field_status, text)| (field_status, Nullable::Value(text))),
    };
    merge(description.as_ref().map(|(field_status, _)| *field_status));

    let filters_value = object.get_or_undefined("filters");
    let filters = if partial && filters_value.is_undefined() {
        Some((Status::Valid, None))
    } else {
        parse_segment_filters(filters_value, &path("filters"), &mut issues).map(|(field_status, list)| (field_status, Some(list)))
    };
    merge(filters.as_ref().map(|(field_status, _)| *field_status));

    let is_public = match object.get_or_undefined("isPublic") {
        JsValue::Undefined => Some((Status::Valid, None)),
        JsValue::Bool(flag) => Some((Status::Valid, Some(*flag))),
        other => {
            issues.push(zod::invalid_type(&path("isPublic"), "boolean", other));
            None
        }
    };
    merge(is_public.as_ref().map(|(field_status, _)| *field_status));

    let scope = match object.get_or_undefined("scope") {
        JsValue::Undefined => Some((Status::Valid, None)),
        other => zod::enumeration(other, &["site", "organization"], &path("scope"), &mut issues).map(|(field_status, text)| {
            (field_status, Some(if text == "site" { SegmentScope::Site } else { SegmentScope::Organization }))
        }),
    };
    merge(scope.as_ref().map(|(field_status, _)| *field_status));

    const SHAPE: [&str; 5] = ["name", "description", "filters", "isPublic", "scope"];
    let extra_keys: Vec<&str> = object.keys().filter(|key| !SHAPE.contains(key)).collect();
    if !extra_keys.is_empty() {
        issues.push(zod::unrecognized_keys(&root, &extra_keys));
        status = Status::Dirty;
    }

    if aborted || status == Status::Dirty || !issues.is_empty() {
        debug!(issue_count = issues.len(), "segment body failed validation");
        return Err(issues);
    }
    let (Some((_, name)), Some((_, description)), Some((_, filters)), Some((_, is_public)), Some((_, scope))) =
        (name, description, filters, is_public, scope)
    else {
        return Err(issues);
    };
    Ok(SegmentBody {
        name,
        description,
        filters: filters.map(|list| list.into_iter().map(|filter| filter.into_filter().expect("valid filter")).collect()),
        is_public,
        scope,
    })
}

/// `createSegmentSchema.parse(body)`.
pub fn parse_create_segment_body(body: &JsValue) -> Result<SegmentBody, Vec<ZodIssue>> {
    parse_segment_body(body, false)
}

/// `updateSegmentSchema.parse(body)` (`createSegmentSchema.partial().strict()`).
pub fn parse_update_segment_body(body: &JsValue) -> Result<SegmentBody, Vec<ZodIssue>> {
    parse_segment_body(body, true)
}

/// The 400 body both segment write handlers send for a `ZodError`.
pub fn validation_error_body(issues: &[ZodIssue]) -> JsValue {
    let mut body = JsObject::new();
    body.insert("error", "Validation error".into());
    body.insert("details", zod::issues_value(issues));
    JsValue::Object(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json;

    fn parse(text: &str) -> JsValue {
        json::parse(text).unwrap()
    }

    fn filters_ok(text: &str) -> bool {
        segment_filters_schema_parse(&parse(text)).is_ok()
    }

    fn first_message(text: &str) -> String {
        segment_filters_schema_parse(&parse(text)).unwrap_err()[0].message()
    }

    // Ported from segmentSchema.test.ts
    #[test]
    fn segment_filters_schema_cases() {
        let accepted = r#"[
            {"parameter":"device_type","type":"equals","value":["Mobile"]},
            {"parameter":"country","type":"equals","value":["DE"]},
            {"parameter":"pathname","type":"starts_with","value":["/docs"]},
            {"parameter":"user_id","type":"is_not_null","value":[]},
            {"parameter":"referrer","type":"regex","value":["^https://(www\\.)?producthunt\\.com"]},
            {"parameter":"lat","type":"greater_than","value":[48.1]},
            {"parameter":"feature_flag:new-checkout","type":"equals","value":["true"]},
            {"parameter":"channel","type":"not_equals","value":["Paid Search","Paid Social"]}
        ]"#;
        assert_eq!(segment_filters_schema_parse(&parse(accepted)).unwrap().len(), 8);
        assert!(!filters_ok(r#"[{"parameter":"session_id","type":"equals","value":["x"]}]"#));
        assert!(!filters_ok(r#"[{"parameter":"browser","type":"like","value":["Chrome"]}]"#));
        assert!(first_message(r#"[{"parameter":"browser","type":"equals","value":[]}]"#).contains("at least one value"));
        assert!(filters_ok(r#"[{"parameter":"user_id","type":"is_null","value":[]}]"#));
        assert!(first_message(r#"[{"parameter":"pathname","type":"regex","value":["(unclosed"]}]"#).contains("Invalid regular expression"));
        let regex = |values: &str| filters_ok(&format!(r#"[{{"parameter":"pathname","type":"regex","value":{values}}}]"#));
        assert!(!regex(r#"[""]"#));
        assert!(!regex(&format!(r#"["{}"]"#, "a".repeat(501))));
        assert!(!regex(r#"["^(?!.*test).*$"]"#));
        assert!(!regex(r#"["^/docs/(?=guide)"]"#));
        assert!(!regex(r#"["(a)\\1"]"#));
        assert!(!regex(r#"["^/a","^/b"]"#));
        assert!(regex(r#"["^/docs/[a-z-]+$"]"#));
        assert!(!filters_ok(r#"[{"parameter":"lat","type":"equals","value":["north"]}]"#));
        assert!(!filters_ok(r#"[{"parameter":"browser_version","type":"greater_than","value":["latest"]}]"#));
        assert!(!filters_ok(r#"[{"parameter":"browser","type":"equals","value":[{"name":"Chrome"}]}]"#));
        let many: Vec<String> = (0..51).map(|i| format!("\"v{i}\"")).collect();
        assert!(!filters_ok(&format!(r#"[{{"parameter":"country","type":"equals","value":[{}]}}]"#, many.join(","))));
        assert!(!filters_ok(&format!(r#"[{{"parameter":"pathname","type":"contains","value":["{}"]}}]"#, "x".repeat(501))));
        assert!(filters_ok(&format!(r#"[{{"parameter":"country","type":"equals","value":[{}]}}]"#, many[..50].join(","))));
        assert!(!filters_ok("[]"));
        let too_many: Vec<String> =
            (0..21).map(|i| format!(r#"{{"parameter":"browser","type":"equals","value":["b{i}"]}}"#)).collect();
        assert!(!filters_ok(&format!("[{}]", too_many.join(","))));
    }

    const MOBILE_DE: &str =
        r#"[{"parameter":"device_type","type":"equals","value":["Mobile"]},{"parameter":"country","type":"equals","value":["DE"]}]"#;

    #[test]
    fn create_segment_schema_cases() {
        let parsed = parse_create_segment_body(&parse(&format!(r#"{{"name":"  Mobile DE  ","filters":{MOBILE_DE}}}"#))).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("Mobile DE"));
        assert_eq!(parsed.is_public, None);
        assert_eq!(parsed.scope, None);
        assert!(parse_create_segment_body(&parse(&format!(r#"{{"name":"   ","filters":{MOBILE_DE}}}"#))).is_err());
        assert!(parse_create_segment_body(&parse(&format!(r#"{{"name":"x","filters":{MOBILE_DE},"scope":"team"}}"#))).is_err());
        assert!(parse_create_segment_body(&parse(&format!(r#"{{"name":"x","filters":{MOBILE_DE},"siteId":4}}"#))).is_err());
        assert!(parse_create_segment_body(&parse(&format!(r#"{{"name":"{}","filters":{MOBILE_DE}}}"#, "n".repeat(81)))).is_err());
        assert!(
            parse_create_segment_body(&parse(&format!(r#"{{"name":"ok","description":"{}","filters":{MOBILE_DE}}}"#, "d".repeat(501))))
                .is_err()
        );
    }

    #[test]
    fn update_segment_schema_cases() {
        assert!(parse_update_segment_body(&parse(r#"{"name":"Renamed"}"#)).is_ok());
        assert!(parse_update_segment_body(&parse(r#"{"isPublic":true}"#)).is_ok());
        assert!(parse_update_segment_body(&parse(r#"{"filters":[]}"#)).is_err());
        assert!(parse_update_segment_body(&parse(r#"{"filters":[{"parameter":"nope","type":"equals","value":["x"]}]}"#)).is_err());
    }
}
