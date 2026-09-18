//! `buildGoalCondition` from server/src/api/analytics/goals/goalConditions.ts, as
//! the experiment results endpoint calls it.
//!
//! A goal's `config` is jsonb, so every member can be any JSON value. Node
//! interpolates whatever arrives through `SqlString.escape` and `String()`; some
//! of that produces SQL ClickHouse accepts (a `null` event name), some throws a
//! `TypeError` (a numeric path pattern) that the handler's catch turns into a
//! 500. Both outcomes are kept here.
//!
//! The report group carries the same port for funnel steps in its own private
//! `conditions` module. This copy exists because that module is not visible
//! outside it; the shared, well-typed builders in
//! `crate::analytics::utils::event_conditions` do the actual SQL.

use crate::analytics::{
    js::{JsObject, JsValue, number::number_to_string},
    sql_string::{escape, escape_string},
    utils::event_conditions::{
        AutocaptureTargetType, build_autocapture_condition, build_page_condition, is_autocapture_target_type,
    },
};

use super::support::{JsError, property};

/// `resolvePropertyFilters(config)`: `config.propertyFilters` when truthy, else the
/// legacy key and value as a one-element list when the key is truthy and the value
/// defined, else `[]`.
fn resolve_property_filters(config: &JsValue) -> Result<JsValue, JsError> {
    let filters = property(config, "propertyFilters")?;
    if filters.is_truthy() {
        return Ok(filters);
    }
    let key = property(config, "eventPropertyKey")?;
    if key.is_truthy() {
        let value = property(config, "eventPropertyValue")?;
        if !value.is_undefined() {
            let mut filter = JsObject::new();
            filter.insert("key", key);
            filter.insert("value", value);
            return Ok(JsValue::Array(vec![JsValue::Object(filter)]));
        }
    }
    Ok(JsValue::Array(Vec::new()))
}

/// `for (const filter of filters)`: arrays by element, strings by code point,
/// anything else is not iterable.
fn iterate(filters: &JsValue) -> Result<Vec<JsValue>, JsError> {
    match filters {
        JsValue::Array(items) => Ok(items.clone()),
        JsValue::String(text) => Ok(text.chars().map(|character| JsValue::String(character.to_string())).collect()),
        _ => Err(JsError::new("filters is not iterable")),
    }
}

/// `propsFilterCondition(filter)`.
fn props_filter_condition(filter: &JsValue) -> Result<String, JsError> {
    let key = escape(&property(filter, "key")?);
    Ok(match property(filter, "value")? {
        JsValue::Number(number) => {
            format!("toFloat64(JSONExtractString(toString(props), {key})) = {}", number_to_string(number))
        }
        JsValue::Bool(flag) => {
            format!("JSONExtractString(toString(props), {key}) = {}", escape_string(if flag { "true" } else { "false" }))
        }
        other => format!("JSONExtractString(toString(props), {key}) = {}", escape(&other)),
    })
}

/// `buildPageCondition(pathPattern, filters)`: `patternToRegex` needs a string, and
/// page targets compare `String(filter.value)` against URL parameters.
fn page_condition(path_pattern: &JsValue, filters: &JsValue) -> Result<String, JsError> {
    let JsValue::String(pattern) = path_pattern else {
        return Err(JsError::new("pattern.replace is not a function"));
    };
    let mut condition = build_page_condition(pattern, &[]);
    for filter in iterate(filters)? {
        let key = escape(&property(&filter, "key")?);
        let value = property(&filter, "value")?.to_js_string();
        condition.push_str(&format!(" AND url_parameters[{key}] = {}", escape_string(&value)));
    }
    Ok(condition)
}

/// `buildEventCondition(eventName, filters)`: the name goes through
/// `SqlString.escape` whatever its type.
fn event_condition(event_name: &JsValue, filters: &JsValue) -> Result<String, JsError> {
    let mut condition = format!("type = 'custom_event' AND event_name = {}", escape(event_name));
    for filter in iterate(filters)? {
        condition.push_str(&format!(" AND {}", props_filter_condition(&filter)?));
    }
    Ok(condition)
}

/// `buildAutocaptureCondition(type, pattern, filters)`: `pattern?.trim()` needs a
/// string or a nullish value.
fn autocapture_condition(
    target_type: AutocaptureTargetType,
    pattern: &JsValue,
    filters: &JsValue,
) -> Result<String, JsError> {
    let pattern = match pattern {
        JsValue::Undefined | JsValue::Null => None,
        JsValue::String(text) => Some(text.as_str()),
        _ => return Err(JsError::new("pattern?.trim is not a function")),
    };
    let mut condition = build_autocapture_condition(target_type, pattern, &[]);
    for filter in iterate(filters)? {
        condition.push_str(&format!(" AND {}", props_filter_condition(&filter)?));
    }
    Ok(condition)
}

/// `buildGoalCondition(goal)`: `Ok(None)` is Node's `null` (no usable condition).
pub fn build_goal_condition(goal_type: &str, config: &JsValue) -> Result<Option<String>, JsError> {
    let filters = resolve_property_filters(config)?;
    if goal_type == "path" {
        let path_pattern = property(config, "pathPattern")?;
        if !path_pattern.is_truthy() {
            return Ok(None);
        }
        return page_condition(&path_pattern, &filters).map(Some);
    }
    if goal_type == "event" {
        let event_name = property(config, "eventName")?;
        if !event_name.is_truthy() {
            return Ok(None);
        }
        return event_condition(&event_name, &filters).map(Some);
    }
    if let Some(target_type) = is_autocapture_target_type(goal_type) {
        return autocapture_condition(target_type, &property(config, "valuePattern")?, &filters).map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json::parse;

    fn goal(goal_type: &str, config: &str) -> Option<String> {
        build_goal_condition(goal_type, &parse(config).unwrap()).unwrap()
    }

    #[test]
    fn goal_conditions_match_node() {
        assert_eq!(
            goal("event", r#"{"eventName":"signup"}"#).as_deref(),
            Some("type = 'custom_event' AND event_name = 'signup'")
        );
        assert_eq!(
            goal("path", r#"{"pathPattern":"/pricing"}"#).as_deref(),
            Some("type = 'pageview' AND match(pathname, '^/pricing$')")
        );
        assert_eq!(goal("event", "{}"), None);
        assert_eq!(goal("nope", r#"{"eventName":"x"}"#), None);
        assert_eq!(
            goal("event", r#"{"eventName":"buy","propertyFilters":[{"key":"amount","value":5}]}"#).as_deref(),
            Some(
                "type = 'custom_event' AND event_name = 'buy' AND toFloat64(JSONExtractString(toString(props), 'amount')) = 5"
            )
        );
    }
}
