//! Port of server/src/api/analytics/utils/eventConditions.ts: SQL predicates for
//! the targets goals and funnel steps match (pages, custom events, autocapture).

use crate::analytics::{
    js::string::trim,
    sql_string::{escape_number, escape_string},
};

use super::utils::pattern_to_regex;

/// `PropertyFilter.value`: `string | number | boolean`.
#[derive(Clone, Debug, PartialEq)]
pub enum PropertyValue {
    String(String),
    Number(f64),
    Bool(bool),
}

impl PropertyValue {
    /// `String(value)`.
    fn to_js_string(&self) -> String {
        match self {
            PropertyValue::String(text) => text.clone(),
            PropertyValue::Number(number) => crate::analytics::js::number::number_to_string(*number),
            PropertyValue::Bool(flag) => flag.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PropertyFilter {
    pub key: String,
    pub value: PropertyValue,
}

/// `AutocaptureTargetType`, in `AUTOCAPTURE_TARGET_TYPES` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutocaptureTargetType {
    Outbound,
    ButtonClick,
    FormSubmit,
    Copy,
}

impl AutocaptureTargetType {
    pub const ALL: [AutocaptureTargetType; 4] = [
        AutocaptureTargetType::Outbound,
        AutocaptureTargetType::ButtonClick,
        AutocaptureTargetType::FormSubmit,
        AutocaptureTargetType::Copy,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AutocaptureTargetType::Outbound => "outbound",
            AutocaptureTargetType::ButtonClick => "button_click",
            AutocaptureTargetType::FormSubmit => "form_submit",
            AutocaptureTargetType::Copy => "copy",
        }
    }

    /// `AUTOCAPTURE_PATTERN_PROPS[type]`.
    pub fn pattern_props(self) -> &'static [&'static str] {
        match self {
            AutocaptureTargetType::Outbound => &["url"],
            AutocaptureTargetType::ButtonClick | AutocaptureTargetType::Copy => &["text"],
            AutocaptureTargetType::FormSubmit => &["formName", "formId", "formAction"],
        }
    }
}

/// `isAutocaptureTargetType(type)`.
pub fn is_autocapture_target_type(target_type: &str) -> Option<AutocaptureTargetType> {
    AutocaptureTargetType::ALL.into_iter().find(|kind| kind.as_str() == target_type)
}

/// The legacy single-property fields next to `propertyFilters`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LegacyPropertyConfig {
    pub event_property_key: Option<String>,
    pub event_property_value: Option<PropertyValue>,
    pub property_filters: Option<Vec<PropertyFilter>>,
}

/// `resolvePropertyFilters(config)`: `propertyFilters` when present (even
/// empty), else the legacy key/value pair when the key is non-empty.
pub fn resolve_property_filters(config: &LegacyPropertyConfig) -> Vec<PropertyFilter> {
    if let Some(filters) = &config.property_filters {
        return filters.clone();
    }
    match (&config.event_property_key, &config.event_property_value) {
        (Some(key), Some(value)) if !key.is_empty() => vec![PropertyFilter { key: key.clone(), value: value.clone() }],
        _ => Vec::new(),
    }
}

/// `propsFilterCondition`.
fn props_filter_condition(filter: &PropertyFilter) -> String {
    let key = escape_string(&filter.key);
    match &filter.value {
        PropertyValue::Number(number) => {
            format!("toFloat64(JSONExtractString(toString(props), {key})) = {}", escape_number(*number))
        }
        other => format!("JSONExtractString(toString(props), {key}) = {}", escape_string(&other.to_js_string())),
    }
}

/// `buildPageCondition(pathPattern, filters)`.
pub fn build_page_condition(path_pattern: &str, filters: &[PropertyFilter]) -> String {
    let regex = pattern_to_regex(path_pattern);
    let mut condition = format!("type = 'pageview' AND match(pathname, {})", escape_string(&regex));
    for filter in filters {
        condition.push_str(&format!(
            " AND url_parameters[{}] = {}",
            escape_string(&filter.key),
            escape_string(&filter.value.to_js_string())
        ));
    }
    condition
}

/// `buildEventCondition(eventName, filters)`.
pub fn build_event_condition(event_name: &str, filters: &[PropertyFilter]) -> String {
    let mut condition = format!("type = 'custom_event' AND event_name = {}", escape_string(event_name));
    for filter in filters {
        condition.push_str(&format!(" AND {}", props_filter_condition(filter)));
    }
    condition
}

/// `textPatternToRegex`: like `patternToRegex`, but `*` may cross `/`.
fn text_pattern_to_regex(pattern: &str) -> String {
    let escaped = super::utils::escape_regex_metacharacters(pattern);
    let with_double_star = escaped.replace("**", "{{DOUBLE_STAR}}");
    let with_single_star = with_double_star.replace('*', ".+");
    format!("^{}$", with_single_star.replace("{{DOUBLE_STAR}}", ".*"))
}

/// `buildAutocaptureCondition(type, pattern, filters)`.
pub fn build_autocapture_condition(
    target_type: AutocaptureTargetType,
    pattern: Option<&str>,
    filters: &[PropertyFilter],
) -> String {
    let mut condition = format!("type = {}", escape_string(target_type.as_str()));
    if let Some(trimmed) = pattern.map(trim).filter(|text| !text.is_empty()) {
        let regex = escape_string(&text_pattern_to_regex(trimmed));
        let matches: Vec<String> = target_type
            .pattern_props()
            .iter()
            .map(|prop| format!("match(JSONExtractString(toString(props), {}), {regex})", escape_string(prop)))
            .collect();
        condition.push_str(&format!(" AND ({})", matches.join(" OR ")));
    }
    for filter in filters {
        condition.push_str(&format!(" AND {}", props_filter_condition(filter)));
    }
    condition
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(key: &str, value: &str) -> PropertyFilter {
        PropertyFilter { key: key.into(), value: PropertyValue::String(value.into()) }
    }

    fn num(key: &str, value: f64) -> PropertyFilter {
        PropertyFilter { key: key.into(), value: PropertyValue::Number(value) }
    }

    fn flag(key: &str, value: bool) -> PropertyFilter {
        PropertyFilter { key: key.into(), value: PropertyValue::Bool(value) }
    }

    // Ported from eventConditions.test.ts
    #[test]
    fn autocapture_types() {
        assert_eq!(AutocaptureTargetType::ALL.map(AutocaptureTargetType::as_str), ["outbound", "button_click", "form_submit", "copy"]);
        for kind in AutocaptureTargetType::ALL {
            assert_eq!(is_autocapture_target_type(kind.as_str()), Some(kind));
            assert!(!kind.pattern_props().is_empty());
        }
        for other in ["page", "path", "event", "pageview", "", "Outbound", "outbound ", "buttonclick"] {
            assert_eq!(is_autocapture_target_type(other), None);
        }
        assert_eq!(AutocaptureTargetType::FormSubmit.pattern_props(), ["formName", "formId", "formAction"]);
    }

    #[test]
    fn resolve_property_filters_cases() {
        assert_eq!(resolve_property_filters(&LegacyPropertyConfig::default()), vec![]);
        let filters = vec![s("plan", "pro")];
        assert_eq!(
            resolve_property_filters(&LegacyPropertyConfig { property_filters: Some(filters.clone()), ..Default::default() }),
            filters
        );
        assert_eq!(
            resolve_property_filters(&LegacyPropertyConfig {
                property_filters: Some(vec![]),
                event_property_key: Some("plan".into()),
                event_property_value: Some(PropertyValue::String("pro".into())),
            }),
            vec![]
        );
        let legacy = |key: Option<&str>, value: Option<PropertyValue>| {
            resolve_property_filters(&LegacyPropertyConfig {
                event_property_key: key.map(str::to_string),
                event_property_value: value,
                property_filters: None,
            })
        };
        assert_eq!(legacy(Some("plan"), Some(PropertyValue::String("pro".into()))), vec![s("plan", "pro")]);
        assert_eq!(legacy(Some("count"), Some(PropertyValue::Number(0.0))), vec![num("count", 0.0)]);
        assert_eq!(legacy(Some("optedIn"), Some(PropertyValue::Bool(false))), vec![flag("optedIn", false)]);
        assert_eq!(legacy(Some("note"), Some(PropertyValue::String(String::new()))), vec![s("note", "")]);
        assert_eq!(legacy(Some("plan"), None), vec![]);
        assert_eq!(legacy(None, Some(PropertyValue::String("pro".into()))), vec![]);
        assert_eq!(legacy(Some(""), Some(PropertyValue::String("pro".into()))), vec![]);
    }

    #[test]
    fn page_conditions() {
        assert_eq!(build_page_condition("/pricing", &[]), "type = 'pageview' AND match(pathname, '^/pricing$')");
        assert_eq!(build_page_condition("/blog/*", &[]), "type = 'pageview' AND match(pathname, '^/blog/[^/]+$')");
        assert_eq!(build_page_condition("/docs/**", &[]), "type = 'pageview' AND match(pathname, '^/docs/.*$')");
        assert_eq!(build_page_condition("/a.b+c", &[]), "type = 'pageview' AND match(pathname, '^/a\\\\.b\\\\+c$')");
        assert_eq!(
            build_page_condition("/pricing", &[s("utm_source", "google")]),
            "type = 'pageview' AND match(pathname, '^/pricing$') AND url_parameters['utm_source'] = 'google'"
        );
        assert_eq!(
            build_page_condition("/pricing", &[s("utm_source", "google"), s("utm_medium", "cpc")]),
            "type = 'pageview' AND match(pathname, '^/pricing$') AND url_parameters['utm_source'] = 'google' AND url_parameters['utm_medium'] = 'cpc'"
        );
        assert_eq!(
            build_page_condition("/pricing", &[num("n", 42.0)]),
            "type = 'pageview' AND match(pathname, '^/pricing$') AND url_parameters['n'] = '42'"
        );
        assert_eq!(
            build_page_condition("/pricing", &[flag("b", true)]),
            "type = 'pageview' AND match(pathname, '^/pricing$') AND url_parameters['b'] = 'true'"
        );
        assert_eq!(build_page_condition("/a') OR 1=1--", &[]), "type = 'pageview' AND match(pathname, '^/a\\'\\\\) OR 1=1--$')");
        assert_eq!(
            build_page_condition("/x", &[s("k'ey", "v') OR 1=1--")]),
            "type = 'pageview' AND match(pathname, '^/x$') AND url_parameters['k\\'ey'] = 'v\\') OR 1=1--'"
        );
        assert_eq!(
            build_page_condition("/x", &[s("p", "a\\b")]),
            "type = 'pageview' AND match(pathname, '^/x$') AND url_parameters['p'] = 'a\\\\b'"
        );
        assert_eq!(
            build_page_condition("/{{DOUBLE_STAR}}", &[]),
            "type = 'pageview' AND match(pathname, '^/\\\\{\\\\{DOUBLE_STAR\\\\}\\\\}$')"
        );
    }

    #[test]
    fn event_conditions() {
        assert_eq!(build_event_condition("signup", &[]), "type = 'custom_event' AND event_name = 'signup'");
        assert_eq!(
            build_event_condition("purchase", &[s("plan", "pro")]),
            "type = 'custom_event' AND event_name = 'purchase' AND JSONExtractString(toString(props), 'plan') = 'pro'"
        );
        assert_eq!(
            build_event_condition("purchase", &[num("amount", 42.0)]),
            "type = 'custom_event' AND event_name = 'purchase' AND toFloat64(JSONExtractString(toString(props), 'amount')) = 42"
        );
        assert_eq!(
            build_event_condition("purchase", &[num("amount", 9.5)]),
            "type = 'custom_event' AND event_name = 'purchase' AND toFloat64(JSONExtractString(toString(props), 'amount')) = 9.5"
        );
        assert_eq!(
            build_event_condition("purchase", &[flag("gift", true)]),
            "type = 'custom_event' AND event_name = 'purchase' AND JSONExtractString(toString(props), 'gift') = 'true'"
        );
        assert_eq!(
            build_event_condition("purchase", &[flag("gift", false)]),
            "type = 'custom_event' AND event_name = 'purchase' AND JSONExtractString(toString(props), 'gift') = 'false'"
        );
        assert_eq!(
            build_event_condition("purchase", &[s("plan", "pro"), num("seats", 3.0)]),
            "type = 'custom_event' AND event_name = 'purchase' AND JSONExtractString(toString(props), 'plan') = 'pro' AND toFloat64(JSONExtractString(toString(props), 'seats')) = 3"
        );
        assert_eq!(
            build_event_condition("evt'; DROP TABLE events;--", &[]),
            "type = 'custom_event' AND event_name = 'evt\\'; DROP TABLE events;--'"
        );
        assert_eq!(
            build_event_condition("evt", &[s("k'ey", "v'al")]),
            "type = 'custom_event' AND event_name = 'evt' AND JSONExtractString(toString(props), 'k\\'ey') = 'v\\'al'"
        );
        assert_eq!(
            build_event_condition("a\\b", &[s("p", "c\\d")]),
            "type = 'custom_event' AND event_name = 'a\\\\b' AND JSONExtractString(toString(props), 'p') = 'c\\\\d'"
        );
        assert_eq!(build_event_condition("", &[]), "type = 'custom_event' AND event_name = ''");
    }

    #[test]
    fn autocapture_conditions() {
        use AutocaptureTargetType::*;
        assert_eq!(build_autocapture_condition(Outbound, None, &[]), "type = 'outbound'");
        assert_eq!(build_autocapture_condition(ButtonClick, None, &[]), "type = 'button_click'");
        assert_eq!(build_autocapture_condition(FormSubmit, None, &[]), "type = 'form_submit'");
        assert_eq!(build_autocapture_condition(Copy, None, &[]), "type = 'copy'");
        assert_eq!(build_autocapture_condition(Outbound, Some(""), &[]), "type = 'outbound'");
        assert_eq!(build_autocapture_condition(Outbound, Some("   "), &[]), "type = 'outbound'");
        assert_eq!(
            build_autocapture_condition(Copy, Some("  hello  "), &[]),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^hello$'))"
        );
        assert_eq!(
            build_autocapture_condition(Outbound, Some("https://example.com/*"), &[]),
            "type = 'outbound' AND (match(JSONExtractString(toString(props), 'url'), '^https://example\\\\.com/.+$'))"
        );
        assert_eq!(
            build_autocapture_condition(ButtonClick, Some("Buy now"), &[]),
            "type = 'button_click' AND (match(JSONExtractString(toString(props), 'text'), '^Buy now$'))"
        );
        assert_eq!(
            build_autocapture_condition(FormSubmit, Some("signup"), &[]),
            "type = 'form_submit' AND (match(JSONExtractString(toString(props), 'formName'), '^signup$') OR \
             match(JSONExtractString(toString(props), 'formId'), '^signup$') OR \
             match(JSONExtractString(toString(props), 'formAction'), '^signup$'))"
        );
        assert_eq!(
            build_autocapture_condition(Copy, Some("coupon-*"), &[]),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^coupon-.+$'))"
        );
        assert!(build_autocapture_condition(Outbound, Some("https://example.com/*"), &[]).contains("/.+$"));
        assert!(build_page_condition("/a/*", &[]).contains("[^/]+"));
        assert_eq!(
            build_autocapture_condition(Copy, Some("a**b"), &[]),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^a.*b$'))"
        );
        assert_eq!(
            build_autocapture_condition(Copy, Some("a.b(c)"), &[]),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^a\\\\.b\\\\(c\\\\)$'))"
        );
        assert_eq!(
            build_autocapture_condition(Outbound, Some("https://x.com"), &[s("target", "_blank")]),
            "type = 'outbound' AND (match(JSONExtractString(toString(props), 'url'), '^https://x\\\\.com$')) AND JSONExtractString(toString(props), 'target') = '_blank'"
        );
        assert_eq!(
            build_autocapture_condition(ButtonClick, None, &[s("id", "cta"), num("count", 2.0)]),
            "type = 'button_click' AND JSONExtractString(toString(props), 'id') = 'cta' AND toFloat64(JSONExtractString(toString(props), 'count')) = 2"
        );
        assert_eq!(
            build_autocapture_condition(Copy, Some("a') OR 1=1--"), &[]),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^a\\'\\\\) OR 1=1--$'))"
        );
        assert_eq!(
            build_autocapture_condition(Copy, Some("a\\b"), &[]),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^a\\\\\\\\b$'))"
        );
        assert_eq!(
            build_autocapture_condition(Copy, Some("{{DOUBLE_STAR}}"), &[]),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^\\\\{\\\\{DOUBLE_STAR\\\\}\\\\}$'))"
        );
    }
}
