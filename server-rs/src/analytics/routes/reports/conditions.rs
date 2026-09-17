//! The event predicates funnel steps and goals match, over untyped values.
//!
//! Ports `buildFunnelStepCondition` (funnels/funnelSteps.ts) and
//! `buildGoalCondition` (goals/goalConditions.ts) together with the parts of
//! utils/eventConditions.ts they drive. Funnel steps arrive straight from a
//! request body with no schema, so a step's `value`, `hostname`, `name` and
//! property filters can be any JSON value. Node interpolates whatever arrives
//! through `SqlString.escape`, `String()` and `for...of`; some of those produce
//! SQL ClickHouse accepts (a `null` event name), others throw a `TypeError` (a
//! numeric page pattern). This module keeps both outcomes: the SQL text for the
//! values Node renders, a [`JsError`] where Node throws. Well-typed inputs go
//! through the shared builders in `utils::event_conditions`.

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
pub fn resolve_property_filters(config: &JsValue) -> Result<JsValue, JsError> {
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

/// `buildFunnelStepCondition(step)`.
pub fn build_funnel_step_condition(step: &JsValue) -> Result<String, JsError> {
    let filters = resolve_property_filters(step)?;
    let step_type = property(step, "type")?;
    let value = property(step, "value")?;
    let mut condition = if step_type.as_str() == Some("page") {
        page_condition(&value, &filters)?
    } else if let Some(target_type) = step_type.as_str().and_then(is_autocapture_target_type) {
        autocapture_condition(target_type, &value, &filters)?
    } else {
        // "event" and unknown legacy types match custom events
        event_condition(&value, &filters)?
    };
    let hostname = property(step, "hostname")?;
    if hostname.is_truthy() {
        condition.push_str(&format!(" AND hostname = {}", escape(&hostname)));
    }
    Ok(condition)
}

/// `buildGoalCondition(goal)` for a stored goal: `Ok(None)` is Node's `null` (no
/// usable condition).
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
    use crate::analytics::js::json::parse;

    use super::*;

    fn step(text: &str) -> Result<String, JsError> {
        build_funnel_step_condition(&parse(text).unwrap())
    }

    fn goal(goal_type: &str, config: &str) -> Option<String> {
        build_goal_condition(goal_type, &parse(config).unwrap()).unwrap()
    }

    // Ported from funnelSteps.test.ts
    #[test]
    fn page_steps() {
        assert_eq!(step(r#"{"type":"page","value":"/pricing"}"#).unwrap(), "type = 'pageview' AND match(pathname, '^/pricing$')");
        assert_eq!(step(r#"{"type":"page","value":"/blog/*"}"#).unwrap(), "type = 'pageview' AND match(pathname, '^/blog/[^/]+$')");
        assert_eq!(step(r#"{"type":"page","value":"/docs/**"}"#).unwrap(), "type = 'pageview' AND match(pathname, '^/docs/.*$')");
        assert_eq!(
            step(r#"{"type":"page","value":"/pricing","propertyFilters":[{"key":"utm_source","value":"google"}]}"#).unwrap(),
            "type = 'pageview' AND match(pathname, '^/pricing$') AND url_parameters['utm_source'] = 'google'"
        );
        assert_eq!(step(r#"{"type":"page","value":""}"#).unwrap(), "type = 'pageview' AND match(pathname, '^$')");
    }

    #[test]
    fn event_steps() {
        assert_eq!(step(r#"{"type":"event","value":"signup"}"#).unwrap(), "type = 'custom_event' AND event_name = 'signup'");
        assert_eq!(
            step(r#"{"type":"event","value":"purchase","propertyFilters":[{"key":"plan","value":"pro"}]}"#).unwrap(),
            "type = 'custom_event' AND event_name = 'purchase' AND JSONExtractString(toString(props), 'plan') = 'pro'"
        );
        assert_eq!(
            step(r#"{"type":"event","value":"purchase","propertyFilters":[{"key":"amount","value":10}]}"#).unwrap(),
            "type = 'custom_event' AND event_name = 'purchase' AND toFloat64(JSONExtractString(toString(props), 'amount')) = 10"
        );
        assert_eq!(
            step(r#"{"type":"event","value":"purchase","eventPropertyKey":"plan","eventPropertyValue":"pro"}"#).unwrap(),
            "type = 'custom_event' AND event_name = 'purchase' AND JSONExtractString(toString(props), 'plan') = 'pro'"
        );
        assert_eq!(
            step(r#"{"type":"event","value":"purchase","propertyFilters":[{"key":"new","value":"yes"}],"eventPropertyKey":"legacy","eventPropertyValue":"no"}"#)
                .unwrap(),
            "type = 'custom_event' AND event_name = 'purchase' AND JSONExtractString(toString(props), 'new') = 'yes'"
        );
        assert_eq!(step(r#"{"type":"legacy_thing","value":"signup"}"#).unwrap(), "type = 'custom_event' AND event_name = 'signup'");
        assert_eq!(step(r#"{"type":"","value":"signup"}"#).unwrap(), "type = 'custom_event' AND event_name = 'signup'");
        assert_eq!(step(r#"{"type":"path","value":"/pricing"}"#).unwrap(), "type = 'custom_event' AND event_name = '/pricing'");
        assert_eq!(
            step(r#"{"type":"event","value":"evt'; DROP TABLE events;--"}"#).unwrap(),
            "type = 'custom_event' AND event_name = 'evt\\'; DROP TABLE events;--'"
        );
    }

    #[test]
    fn autocapture_steps() {
        assert_eq!(
            step(r#"{"type":"outbound","value":"https://partner.com/*"}"#).unwrap(),
            "type = 'outbound' AND (match(JSONExtractString(toString(props), 'url'), '^https://partner\\\\.com/.+$'))"
        );
        assert_eq!(
            step(r#"{"type":"button_click","value":"Buy now"}"#).unwrap(),
            "type = 'button_click' AND (match(JSONExtractString(toString(props), 'text'), '^Buy now$'))"
        );
        assert_eq!(
            step(r#"{"type":"form_submit","value":"signup"}"#).unwrap(),
            "type = 'form_submit' AND (match(JSONExtractString(toString(props), 'formName'), '^signup$') OR \
             match(JSONExtractString(toString(props), 'formId'), '^signup$') OR \
             match(JSONExtractString(toString(props), 'formAction'), '^signup$'))"
        );
        assert_eq!(
            step(r#"{"type":"copy","value":"coupon-*"}"#).unwrap(),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^coupon-.+$'))"
        );
        assert_eq!(step(r#"{"type":"outbound","value":""}"#).unwrap(), "type = 'outbound'");
        assert_eq!(step(r#"{"type":"copy","value":"   "}"#).unwrap(), "type = 'copy'");
        assert_eq!(
            step(r#"{"type":"outbound","value":"https://x.com","propertyFilters":[{"key":"target","value":"_blank"}]}"#).unwrap(),
            "type = 'outbound' AND (match(JSONExtractString(toString(props), 'url'), '^https://x\\\\.com$')) AND JSONExtractString(toString(props), 'target') = '_blank'"
        );
    }

    #[test]
    fn hostnames() {
        assert_eq!(
            step(r#"{"type":"page","value":"/pricing","hostname":"app.example.com"}"#).unwrap(),
            "type = 'pageview' AND match(pathname, '^/pricing$') AND hostname = 'app.example.com'"
        );
        assert_eq!(
            step(r#"{"type":"event","value":"signup","hostname":"app.example.com"}"#).unwrap(),
            "type = 'custom_event' AND event_name = 'signup' AND hostname = 'app.example.com'"
        );
        assert_eq!(
            step(r#"{"type":"copy","value":"coupon","propertyFilters":[{"key":"page","value":"/x"}],"hostname":"app.example.com"}"#).unwrap(),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^coupon$')) AND JSONExtractString(toString(props), 'page') = '/x' AND hostname = 'app.example.com'"
        );
        assert_eq!(step(r#"{"type":"page","value":"/pricing","hostname":""}"#).unwrap(), "type = 'pageview' AND match(pathname, '^/pricing$')");
        assert_eq!(
            step(r#"{"type":"page","value":"/x","hostname":"a'; DROP TABLE events;--"}"#).unwrap(),
            "type = 'pageview' AND match(pathname, '^/x$') AND hostname = 'a\\'; DROP TABLE events;--'"
        );
    }

    #[test]
    fn untyped_step_values() {
        assert_eq!(step(r#"{"type":"event","value":null}"#).unwrap(), "type = 'custom_event' AND event_name = NULL");
        assert_eq!(step(r#"{"type":"event"}"#).unwrap(), "type = 'custom_event' AND event_name = NULL");
        assert_eq!(step(r#"{"type":"event","value":["a","b"]}"#).unwrap(), "type = 'custom_event' AND event_name = 'a', 'b'");
        assert_eq!(step(r#"{"type":"event","value":5}"#).unwrap(), "type = 'custom_event' AND event_name = 5");
        assert_eq!(step(r#"{"type":"event","value":{"a":1}}"#).unwrap(), "type = 'custom_event' AND event_name = `a` = 1");
        assert!(step(r#"{"type":"page","value":5}"#).is_err());
        assert!(step(r#"{"type":"copy","value":5}"#).is_err());
        assert!(step("null").is_err());
        assert_eq!(step("5").unwrap(), "type = 'custom_event' AND event_name = NULL");
        assert_eq!(
            step(r#"{"type":"page","value":"/","propertyFilters":"ab"}"#).unwrap(),
            "type = 'pageview' AND match(pathname, '^/$') AND url_parameters[NULL] = 'undefined' AND url_parameters[NULL] = 'undefined'"
        );
        assert!(step(r#"{"type":"page","value":"/","propertyFilters":5}"#).is_err());
        assert!(step(r#"{"type":"page","value":"/","propertyFilters":[null]}"#).is_err());
        assert_eq!(
            step(r#"{"type":"event","value":"e","propertyFilters":[{"key":["k"],"value":[1,{"x":2}]}]}"#).unwrap(),
            "type = 'custom_event' AND event_name = 'e' AND JSONExtractString(toString(props), 'k') = 1, '[object Object]'"
        );
        assert_eq!(
            step(r#"{"type":"page","value":"/","hostname":true}"#).unwrap(),
            "type = 'pageview' AND match(pathname, '^/$') AND hostname = true"
        );
    }

    // Ported from goalConditions.test.ts
    #[test]
    fn goal_conditions() {
        assert_eq!(goal("path", r#"{"pathPattern":"/checkout/success"}"#).unwrap(), "type = 'pageview' AND match(pathname, '^/checkout/success$')");
        assert_eq!(goal("path", r#"{"pathPattern":"/blog/*"}"#).unwrap(), "type = 'pageview' AND match(pathname, '^/blog/[^/]+$')");
        assert_eq!(
            goal("path", r#"{"pathPattern":"/pricing","propertyFilters":[{"key":"utm_source","value":"google"},{"key":"utm_medium","value":"cpc"}]}"#).unwrap(),
            "type = 'pageview' AND match(pathname, '^/pricing$') AND url_parameters['utm_source'] = 'google' AND url_parameters['utm_medium'] = 'cpc'"
        );
        assert_eq!(
            goal("path", r#"{"pathPattern":"/pricing","eventPropertyKey":"utm_source","eventPropertyValue":"google"}"#).unwrap(),
            "type = 'pageview' AND match(pathname, '^/pricing$') AND url_parameters['utm_source'] = 'google'"
        );
        assert_eq!(goal("path", "{}"), None);
        assert_eq!(goal("path", r#"{"pathPattern":""}"#), None);
        assert_eq!(goal("path", r#"{"eventName":"signup"}"#), None);
        assert_eq!(goal("path", r#"{"pathPattern":"/a'b"}"#).unwrap(), "type = 'pageview' AND match(pathname, '^/a\\'b$')");
        assert_eq!(goal("event", r#"{"eventName":"signup"}"#).unwrap(), "type = 'custom_event' AND event_name = 'signup'");
        assert_eq!(
            goal("event", r#"{"eventName":"purchase","propertyFilters":[{"key":"amount","value":99.5}]}"#).unwrap(),
            "type = 'custom_event' AND event_name = 'purchase' AND toFloat64(JSONExtractString(toString(props), 'amount')) = 99.5"
        );
        assert_eq!(goal("event", "{}"), None);
        assert_eq!(goal("event", r#"{"eventName":""}"#), None);
        assert_eq!(goal("outbound", "{}").unwrap(), "type = 'outbound'");
        assert_eq!(goal("button_click", "{}").unwrap(), "type = 'button_click'");
        assert_eq!(goal("form_submit", "{}").unwrap(), "type = 'form_submit'");
        assert_eq!(goal("copy", "{}").unwrap(), "type = 'copy'");
        assert_eq!(
            goal("outbound", r#"{"valuePattern":"https://partner.com/**"}"#).unwrap(),
            "type = 'outbound' AND (match(JSONExtractString(toString(props), 'url'), '^https://partner\\\\.com/.*$'))"
        );
        assert_eq!(
            goal("copy", r#"{"valuePattern":"coupon-*","propertyFilters":[{"key":"page","value":"/pricing"}]}"#).unwrap(),
            "type = 'copy' AND (match(JSONExtractString(toString(props), 'text'), '^coupon-.+$')) AND JSONExtractString(toString(props), 'page') = '/pricing'"
        );
        assert_eq!(goal("outbound", r#"{"pathPattern":"/x","eventName":"y"}"#).unwrap(), "type = 'outbound'");
        for unknown in ["unknown", "pageview", "", "Path", "EVENT", "Outbound", "page"] {
            assert_eq!(goal(unknown, r#"{"pathPattern":"/x","eventName":"signup"}"#), None);
        }
        assert!(build_goal_condition("path", &JsValue::Null).is_err());
    }
}
