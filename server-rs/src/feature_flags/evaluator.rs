//! Flag evaluation, ported from server/src/services/featureFlags/evaluator.ts.
//!
//! Definitions are evaluated as the JSON values Node holds (see [`super::js`]):
//! every property read, `String()` conversion, `Math.max`/`Math.min` clamp and
//! truthiness test follows JavaScript, so hand-edited or oddly shaped rows give the
//! same assignments, and the same failures, as in Node. Assignment objects keep
//! Node's key order and leave out the keys Node leaves `undefined`, because clients
//! receive them as JSON.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{
    js::{self, JsError},
    regex::{RegexCache, compile::CompiledRegex, shared_cache},
};

/// `FeatureFlagContext`: what the request tells us about the visitor.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FeatureFlagContext {
    pub anonymous_id: String,
    pub identified_user_id: Option<String>,
    pub hostname: Option<String>,
    pub pathname: Option<String>,
    /// A JSON object of query parameters (`query?.[key]`), or None
    pub query: Option<Value>,
    pub referrer: Option<String>,
    pub language: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub device_type: Option<String>,
    /// The user's stored traits (any JSON; an object in practice), or None
    pub traits: Option<Value>,
}

/// `bucketPercentage`: the first 32 bits of the seed's SHA-256 as a percentage in
/// [0, 100], with JavaScript's double arithmetic (`parseInt(hex) / 0xffffffff * 100`).
pub fn bucket_percentage(seed: &str) -> f64 {
    let digest = Sha256::digest(seed.as_bytes());
    let prefix = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let bucket = f64::from(prefix) / f64::from(u32::MAX);
    bucket * 100.0
}

/// Compiled patterns as the shared cache held them right after the flag's rules were
/// precompiled. Node evaluates a flag synchronously, so nothing can change the cache
/// between precompiling and matching; reading from this snapshot keeps that
/// guarantee without holding the cache lock while regexes run.
#[derive(Default)]
pub struct RegexSnapshot {
    compiled: HashMap<String, Option<Arc<CompiledRegex>>>,
}

impl RegexSnapshot {
    fn get(&self, pattern: &str) -> Option<&CompiledRegex> {
        self.compiled.get(pattern).and_then(|compiled| compiled.as_deref())
    }
}

/// Every string value of every `regex` rule in a rules array.
fn regex_patterns<'a>(rules: Option<&'a Value>, into: &mut Vec<&'a str>) {
    let Some(Value::Array(rules)) = rules else {
        return;
    };
    for rule in rules {
        let Value::Object(rule) = rule else {
            continue;
        };
        if rule.get("operator").and_then(Value::as_str) != Some("regex") {
            continue;
        }
        match rule.get("value") {
            Some(Value::String(pattern)) => into.push(pattern),
            Some(Value::Array(values)) => into.extend(values.iter().filter_map(Value::as_str)),
            _ => {}
        }
    }
}

fn get<'a>(base: &'a Value, name: &str) -> Option<&'a Value> {
    match base {
        Value::Object(map) => map.get(name),
        _ => None,
    }
}

/// `getContextValue` followed by `normalizeComparableValue`.
fn actual_value(rule: &Value, context: &FeatureFlagContext) -> Result<String, JsError> {
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    // `rule.key ? context.query?.[rule.key] : undefined`
    let keyed = |container: &Option<Value>| -> Result<String, JsError> {
        let key = get(rule, "key");
        match container {
            Some(container) if js::truthy(key) => js::lookup_comparable(container, &js::to_string(key)?),
            _ => Ok(String::new()),
        }
    };
    Ok(match get(rule, "field").and_then(Value::as_str) {
        Some("hostname") => text(&context.hostname),
        Some("pathname") => text(&context.pathname),
        Some("query") => keyed(&context.query)?,
        Some("referrer") => text(&context.referrer),
        Some("language") => text(&context.language),
        Some("country") => text(&context.country),
        Some("region") => text(&context.region),
        Some("city") => text(&context.city),
        Some("device_type") => text(&context.device_type),
        Some("user_id") => match &context.identified_user_id {
            Some(identified) if !identified.is_empty() => identified.clone(),
            _ => context.anonymous_id.clone(),
        },
        Some("trait") => keyed(&context.traits)?,
        _ => String::new(),
    })
}

/// `matchesFeatureFlagRule`. `includes`/`startsWith`/`endsWith` on UTF-16 agree with
/// byte-wise matching on well-formed strings, which is all Rust strings can be.
pub fn matches_feature_flag_rule(
    rule: &Value,
    context: &FeatureFlagContext,
    regexes: &RegexSnapshot,
) -> Result<bool, JsError> {
    js::get(Some(rule), "field")?;
    let actual = actual_value(rule, context)?;
    let rule_value = get(rule, "value");
    let expected_values: Vec<Option<&Value>> = match rule_value {
        Some(Value::Array(values)) => values.iter().map(Some).collect(),
        other => vec![other],
    };
    // Every expected value is converted before the operator is looked at
    let expected_strings = expected_values.iter().map(|value| js::comparable(*value)).collect::<Result<Vec<_>, _>>()?;
    let expected = || expected_strings.iter();

    Ok(match get(rule, "operator").and_then(Value::as_str) {
        Some("equals") => expected().any(|value| actual == *value),
        Some("not_equals") => expected().all(|value| actual != *value),
        Some("contains") => expected().any(|value| actual.contains(value.as_str())),
        Some("starts_with") => expected().any(|value| actual.starts_with(value.as_str())),
        Some("ends_with") => expected().any(|value| actual.ends_with(value.as_str())),
        Some("regex") => expected_values.iter().any(|value| match value {
            Some(Value::String(pattern)) => regexes.get(pattern).is_some_and(|compiled| compiled.test(&actual)),
            _ => false,
        }),
        // An unknown operator returns undefined, which fails `every`
        _ => false,
    })
}

/// `clampPercentage(value, fallback)`: `Math.min(100, Math.max(0, value ?? fallback))`.
fn clamp_percentage(value: Option<&Value>, fallback: f64) -> Result<f64, JsError> {
    let number = match value {
        None | Some(Value::Null) => fallback,
        other => js::to_number(other)?,
    };
    Ok(js::math_min(100.0, js::math_max(0.0, number)))
}

/// A condition set as `getConditionSets` returns it: a stored one, or the one built
/// from the flag's top-level fields when `conditionSets` is not a non-empty array.
#[derive(Clone, Copy)]
enum ConditionSet<'a> {
    Stored(&'a Value),
    FromFlag(&'a Value),
}

impl<'a> ConditionSet<'a> {
    fn rules(self) -> Option<&'a Value> {
        match self {
            ConditionSet::Stored(set) => get(set, "rules"),
            ConditionSet::FromFlag(flag) => get(flag, "rules").filter(|rules| rules.is_array()),
        }
    }

    fn rollout_percentage(self) -> Option<&'a Value> {
        match self {
            ConditionSet::Stored(set) => get(set, "rolloutPercentage"),
            ConditionSet::FromFlag(flag) => get(flag, "rolloutPercentage"),
        }
    }

    fn variants(self) -> Option<&'a Value> {
        match self {
            ConditionSet::Stored(set) => get(set, "variants"),
            ConditionSet::FromFlag(flag) => get(flag, "variants").filter(|variants| variants.is_array()),
        }
    }

    fn name(self) -> Option<&'a Value> {
        match self {
            ConditionSet::Stored(set) => get(set, "name"),
            ConditionSet::FromFlag(_) => None,
        }
    }

    /// `getPayload`: the set's payload unless undefined, else the flag's.
    fn payload(self, flag: &'a Value) -> Option<&'a Value> {
        match self {
            ConditionSet::Stored(set) => get(set, "payload").or_else(|| get(flag, "payload")),
            ConditionSet::FromFlag(flag) => get(flag, "payload"),
        }
    }
}

fn condition_sets(flag: &Value) -> Vec<ConditionSet<'_>> {
    match get(flag, "conditionSets") {
        Some(Value::Array(sets)) if !sets.is_empty() => sets.iter().map(ConditionSet::Stored).collect(),
        _ => vec![ConditionSet::FromFlag(flag)],
    }
}

fn matches_condition_set(
    set: ConditionSet<'_>,
    context: &FeatureFlagContext,
    regexes: &RegexSnapshot,
) -> Result<bool, JsError> {
    let Some(Value::Array(rules)) = set.rules() else {
        return Ok(true);
    };
    for rule in rules {
        if !matches_feature_flag_rule(rule, context, regexes)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `selectVariant`: the first variant whose cumulative rollout exceeds the bucket, and
/// the (capped) total rollout.
fn select_variant(variants: &[Value], bucket: f64) -> Result<(Option<&Value>, f64), JsError> {
    let mut cumulative = 0.0;
    for variant in variants {
        cumulative += clamp_percentage(js::get(Some(variant), "rolloutPercentage")?, 0.0)?;
        if bucket < cumulative {
            return Ok((Some(variant), js::math_min(100.0, cumulative)));
        }
    }
    Ok((None, js::math_min(100.0, cumulative)))
}

/// Builds an assignment object, leaving out `undefined` members like `JSON.stringify`.
struct Assignment(Map<String, Value>);

impl Assignment {
    fn new() -> Self {
        Self(Map::new())
    }

    fn raw(mut self, name: &str, value: Option<&Value>) -> Self {
        if let Some(value) = value {
            self.0.insert(name.to_string(), value.clone());
        }
        self
    }

    fn value(mut self, name: &str, value: Value) -> Self {
        self.0.insert(name.to_string(), value);
        self
    }
}

/// `evaluateFeatureFlag` on the shared regex cache.
pub fn evaluate_feature_flag(flag: &Value, context: &FeatureFlagContext) -> Result<Map<String, Value>, JsError> {
    evaluate_feature_flag_with_cache(flag, context, None)
}

/// `evaluateFeatureFlag` with an explicit cache (tests replay Node's cache history).
pub fn evaluate_feature_flag_with_cache(
    flag: &Value,
    context: &FeatureFlagContext,
    cache: Option<&Mutex<RegexCache>>,
) -> Result<Map<String, Value>, JsError> {
    let rollout_percentage = clamp_percentage(js::get(Some(flag), "rolloutPercentage")?, 100.0)?;

    let regexes = {
        let mut guard = match cache {
            Some(cache) => CacheGuard::Local(cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())),
            None => CacheGuard::Shared(shared_cache()),
        };
        let cache = guard.cache();
        cache.precompile_rule_regexes(get(flag, "rules"))?;
        cache.precompile_condition_set_regexes(get(flag, "conditionSets"))?;

        let mut patterns = Vec::new();
        regex_patterns(get(flag, "rules"), &mut patterns);
        if let Some(Value::Array(sets)) = get(flag, "conditionSets") {
            for set in sets {
                regex_patterns(get(set, "rules"), &mut patterns);
            }
        }
        RegexSnapshot {
            compiled: patterns.into_iter().map(|pattern| (pattern.to_string(), cache.get(pattern))).collect(),
        }
    };

    if !js::truthy(get(flag, "enabled")) {
        return Ok(Assignment::new()
            .raw("key", get(flag, "key"))
            .value("value", Value::Bool(false))
            .raw("flagType", get(flag, "flagType"))
            .raw("version", get(flag, "version"))
            .value("reason", "disabled".into())
            .value("matched", Value::Bool(false))
            .value("rolloutPercentage", js::number_json(rollout_percentage))
            .0);
    }

    let seed = format!(
        "{}:{}:{}:{}",
        js::to_string(get(flag, "siteId"))?,
        js::to_string(get(flag, "key"))?,
        context.anonymous_id,
        js::to_string(get(flag, "salt"))?,
    );
    let bucket = bucket_percentage(&seed);
    let flag_type = get(flag, "flagType");

    for (index, set) in condition_sets(flag).into_iter().enumerate() {
        if !matches_condition_set(set, context, &regexes)? {
            continue;
        }

        let name = set.name();
        let condition_set_name = if js::truthy(name) {
            name.cloned().unwrap_or(Value::Null)
        } else {
            Value::String(format!("condition_{}", index + 1))
        };

        match flag_type.and_then(Value::as_str) {
            Some("remote_config") => {
                return Ok(Assignment::new()
                    .raw("key", get(flag, "key"))
                    .value("value", Value::Bool(true))
                    .raw("flagType", flag_type)
                    .raw("payload", set.payload(flag))
                    .value("conditionSet", condition_set_name)
                    .raw("version", get(flag, "version"))
                    .value("reason", "remote_config".into())
                    .value("matched", Value::Bool(true))
                    .value("rolloutPercentage", 100.into())
                    .0);
            }
            Some("multivariate") => {
                let variants = match set.variants() {
                    Some(Value::Array(variants)) if !variants.is_empty() => variants.as_slice(),
                    _ => match get(flag, "variants") {
                        Some(Value::Array(variants)) => variants.as_slice(),
                        _ => &[],
                    },
                };
                let (variant, total_rollout) = select_variant(variants, bucket)?;
                if let Some(variant) = variant {
                    return Ok(Assignment::new()
                        .raw("key", get(flag, "key"))
                        .raw("value", get(variant, "key"))
                        .raw("flagType", flag_type)
                        .raw("variant", get(variant, "key"))
                        .raw("payload", get(variant, "payload"))
                        .value("conditionSet", condition_set_name)
                        .raw("version", get(flag, "version"))
                        .value("reason", "variant".into())
                        .value("matched", Value::Bool(true))
                        .raw("rolloutPercentage", get(variant, "rolloutPercentage"))
                        .0);
                }
                return Ok(Assignment::new()
                    .raw("key", get(flag, "key"))
                    .value("value", Value::Bool(false))
                    .raw("flagType", flag_type)
                    .value("conditionSet", condition_set_name)
                    .raw("version", get(flag, "version"))
                    .value("reason", "fallthrough".into())
                    .value("matched", Value::Bool(false))
                    .value("rolloutPercentage", js::number_json(total_rollout))
                    .0);
            }
            _ => {
                let condition_rollout = clamp_percentage(set.rollout_percentage(), rollout_percentage)?;
                let in_rollout = condition_rollout >= 100.0 || (condition_rollout > 0.0 && bucket < condition_rollout);
                return Ok(Assignment::new()
                    .raw("key", get(flag, "key"))
                    .value("value", Value::Bool(in_rollout))
                    .raw("flagType", flag_type)
                    .raw("payload", if in_rollout { set.payload(flag) } else { None })
                    .value("conditionSet", condition_set_name)
                    .raw("version", get(flag, "version"))
                    .value("reason", if in_rollout { "rollout" } else { "fallthrough" }.into())
                    .value("matched", Value::Bool(in_rollout))
                    .value("rolloutPercentage", js::number_json(condition_rollout))
                    .0);
            }
        }
    }

    Ok(Assignment::new()
        .raw("key", get(flag, "key"))
        .value("value", Value::Bool(false))
        .raw("flagType", flag_type)
        .raw("version", get(flag, "version"))
        .value("reason", "target_mismatch".into())
        .value("matched", Value::Bool(false))
        .value("rolloutPercentage", js::number_json(rollout_percentage))
        .0)
}

enum CacheGuard<'a> {
    Shared(std::sync::MutexGuard<'static, RegexCache>),
    Local(std::sync::MutexGuard<'a, RegexCache>),
}

impl CacheGuard<'_> {
    fn cache(&mut self) -> &mut RegexCache {
        match self {
            CacheGuard::Shared(guard) => guard,
            CacheGuard::Local(guard) => guard,
        }
    }
}

/// `evaluateFeatureFlagDefinitions`: one assignment per flag of the runtime (all flags
/// when `runtime` is None), keyed by flag key with JavaScript object semantics: a
/// repeated key keeps its first position and the last assignment, `__proto__` is
/// swallowed by the prototype setter, and array-index keys come first.
pub fn evaluate_feature_flag_definitions(
    rows: &[Value],
    context: &FeatureFlagContext,
    runtime: Option<&str>,
) -> Result<Map<String, Value>, JsError> {
    evaluate_feature_flag_definitions_with_cache(rows, context, runtime, None)
}

/// [`evaluate_feature_flag_definitions`] with an explicit regex cache.
pub fn evaluate_feature_flag_definitions_with_cache(
    rows: &[Value],
    context: &FeatureFlagContext,
    runtime: Option<&str>,
    cache: Option<&Mutex<RegexCache>>,
) -> Result<Map<String, Value>, JsError> {
    let mut assignments = Map::new();
    for flag in rows {
        let flag_runtime = js::get(Some(flag), "runtime")?;
        if let Some(runtime) = runtime.filter(|runtime| !runtime.is_empty()) {
            let flag_runtime = flag_runtime.and_then(Value::as_str);
            if flag_runtime != Some("both") && flag_runtime != Some(runtime) {
                continue;
            }
        }
        let key = js::to_string(get(flag, "key"))?.into_owned();
        let assignment = evaluate_feature_flag_with_cache(flag, context, cache)?;
        if key == "__proto__" {
            continue;
        }
        assignments.insert(key, Value::Object(assignment));
    }
    js::order_map_keys_like_js(&mut assignments);
    Ok(assignments)
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/featureFlags/evaluator.test.ts.

    use serde_json::json;

    use super::*;

    fn base_flag() -> Value {
        json!({
            "flagId": 1,
            "siteId": 10,
            "key": "new_checkout",
            "description": null,
            "enabled": true,
            "runtime": "client",
            "flagType": "boolean",
            "payload": null,
            "variants": [],
            "rolloutPercentage": 100,
            "rules": [],
            "conditionSets": [],
            "salt": "salt",
            "version": 1,
            "createdAt": "2026-01-01T00:00:00.000Z",
            "updatedAt": "2026-01-01T00:00:00.000Z",
        })
    }

    fn with(mut flag: Value, overrides: Value) -> Value {
        let (Value::Object(flag_map), Value::Object(overrides)) = (&mut flag, overrides) else { unreachable!() };
        flag_map.extend(overrides);
        flag
    }

    fn visitor() -> FeatureFlagContext {
        FeatureFlagContext { anonymous_id: "visitor-1".into(), ..Default::default() }
    }

    /// `toMatchObject`: every member of `expected` is present and equal.
    fn assert_matches(actual: &Map<String, Value>, expected: Value) {
        let Value::Object(expected) = expected else { unreachable!() };
        for (key, value) in expected {
            assert_eq!(actual.get(&key), Some(&value), "member {key} of {actual:?}");
        }
    }

    #[test]
    fn matches_targeting_rules_against_request_context() {
        let context = FeatureFlagContext { pathname: Some("/pricing/pro".into()), ..visitor() };
        let rule = json!({ "field": "pathname", "operator": "starts_with", "value": "/pricing" });
        assert!(matches_feature_flag_rule(&rule, &context, &RegexSnapshot::default()).unwrap());

        let context = FeatureFlagContext { query: Some(json!({ "plan": "team" })), ..visitor() };
        let rule = json!({ "field": "query", "key": "plan", "operator": "equals", "value": ["pro", "team"] });
        assert!(matches_feature_flag_rule(&rule, &context, &RegexSnapshot::default()).unwrap());
    }

    #[test]
    fn matches_regex_rules_using_precompiled_patterns() {
        let cache = Mutex::new(RegexCache::new());
        let pattern = "^/pricing(/|$)";
        let flag =
            with(base_flag(), json!({ "rules": [{ "field": "pathname", "operator": "regex", "value": pattern }] }));
        let context = FeatureFlagContext { pathname: Some("/pricing/pro".into()), ..visitor() };
        let assignment = evaluate_feature_flag_with_cache(&flag, &context, Some(&cache)).unwrap();
        assert_matches(&assignment, json!({ "value": true, "reason": "rollout" }));

        // Without precompiling, the rule reads an empty cache and cannot match
        let rule = json!({ "field": "pathname", "operator": "regex", "value": pattern });
        assert!(!matches_feature_flag_rule(&rule, &context, &RegexSnapshot::default()).unwrap());
    }

    #[test]
    fn returns_off_value_when_disabled_or_targeting_fails() {
        let disabled = evaluate_feature_flag(&with(base_flag(), json!({ "enabled": false })), &visitor()).unwrap();
        assert_matches(&disabled, json!({ "value": false, "reason": "disabled", "matched": false }));

        let flag = with(base_flag(), json!({ "rules": [{ "field": "country", "operator": "equals", "value": "US" }] }));
        let context = FeatureFlagContext { country: Some("GB".into()), ..visitor() };
        let mismatch = evaluate_feature_flag(&flag, &context).unwrap();
        assert_matches(&mismatch, json!({ "value": false, "reason": "target_mismatch", "matched": false }));
    }

    #[test]
    fn applies_rollout_after_targeting_matches() {
        let full = evaluate_feature_flag(&with(base_flag(), json!({ "rolloutPercentage": 100 })), &visitor()).unwrap();
        assert_matches(&full, json!({ "value": true, "payload": null, "reason": "rollout", "matched": true }));

        let none = evaluate_feature_flag(&with(base_flag(), json!({ "rolloutPercentage": 0 })), &visitor()).unwrap();
        assert_matches(&none, json!({ "value": false, "reason": "fallthrough", "matched": false }));
    }

    #[test]
    fn uses_the_first_matching_condition_set() {
        let flag = with(
            base_flag(),
            json!({ "conditionSets": [
                { "name": "us beta", "rules": [{ "field": "country", "operator": "equals", "value": "US" }], "rolloutPercentage": 0 },
                { "name": "all traffic", "rules": [], "rolloutPercentage": 100, "payload": { "copy": "fallback" } },
            ]}),
        );
        let context = FeatureFlagContext { country: Some("GB".into()), ..visitor() };
        assert_matches(
            &evaluate_feature_flag(&flag, &context).unwrap(),
            json!({ "value": true, "payload": { "copy": "fallback" }, "conditionSet": "all traffic", "reason": "rollout", "matched": true }),
        );
    }

    #[test]
    fn assigns_multivariate_variants_by_rollout_percentage() {
        let flag = with(
            base_flag(),
            json!({ "flagType": "multivariate", "variants": [
                { "key": "control", "rolloutPercentage": 100, "payload": { "color": "blue" } },
                { "key": "test", "rolloutPercentage": 0, "payload": { "color": "green" } },
            ]}),
        );
        assert_matches(
            &evaluate_feature_flag(&flag, &visitor()).unwrap(),
            json!({ "value": "control", "variant": "control", "payload": { "color": "blue" }, "reason": "variant", "matched": true }),
        );
    }

    #[test]
    fn assigns_multivariate_variants_from_the_first_matching_condition_set() {
        let flag = with(
            base_flag(),
            json!({ "flagType": "multivariate", "variants": [], "conditionSets": [
                { "name": "wrong country", "rules": [{ "field": "country", "operator": "equals", "value": "GB" }],
                  "variants": [{ "key": "gb_control", "rolloutPercentage": 100 }, { "key": "gb_test", "rolloutPercentage": 0 }] },
                { "name": "us traffic", "rules": [{ "field": "country", "operator": "equals", "value": "US" }],
                  "variants": [
                    { "key": "us_control", "rolloutPercentage": 100, "payload": { "color": "blue" } },
                    { "key": "us_test", "rolloutPercentage": 0, "payload": { "color": "green" } },
                  ] },
            ]}),
        );
        let context = FeatureFlagContext { country: Some("US".into()), ..visitor() };
        assert_matches(
            &evaluate_feature_flag(&flag, &context).unwrap(),
            json!({ "value": "us_control", "variant": "us_control", "payload": { "color": "blue" }, "conditionSet": "us traffic", "reason": "variant", "matched": true }),
        );
    }

    #[test]
    fn returns_remote_config_payload_from_the_first_matching_condition_set() {
        let flag = with(
            base_flag(),
            json!({ "flagType": "remote_config", "conditionSets": [
                { "name": "wrong country", "rules": [{ "field": "country", "operator": "equals", "value": "US" }], "payload": { "checkoutColor": "blue" } },
                { "name": "fallback", "rules": [], "payload": { "checkoutColor": "green" } },
            ]}),
        );
        let context = FeatureFlagContext { country: Some("GB".into()), ..visitor() };
        assert_matches(
            &evaluate_feature_flag(&flag, &context).unwrap(),
            json!({ "value": true, "payload": { "checkoutColor": "green" }, "conditionSet": "fallback", "reason": "remote_config", "matched": true }),
        );
    }

    #[test]
    fn uses_stable_hash_buckets() {
        let bucket = bucket_percentage("site:flag:visitor:salt");
        assert_eq!(bucket, bucket_percentage("site:flag:visitor:salt"));
        assert!((0.0..=100.0).contains(&bucket));
    }

    #[test]
    fn assignment_members_follow_node_order_and_omit_undefined() {
        let flag = json!({ "key": "k", "enabled": false });
        let assignment = evaluate_feature_flag(&flag, &visitor()).unwrap();
        assert_eq!(
            serde_json::to_string(&assignment).unwrap(),
            r#"{"key":"k","value":false,"reason":"disabled","matched":false,"rolloutPercentage":100}"#
        );
    }

    #[test]
    fn javascript_value_semantics_carry_over() {
        // Number rule values compare through String(): 1.0 is "1"
        let flag = with(
            base_flag(),
            json!({ "rules": [{ "field": "trait", "key": "plan", "operator": "equals", "value": 1.0 }] }),
        );
        let context = FeatureFlagContext { traits: Some(json!({ "plan": 1 })), ..visitor() };
        assert_matches(&evaluate_feature_flag(&flag, &context).unwrap(), json!({ "reason": "rollout" }));

        // Inherited properties answer missing trait keys
        let flag = with(
            base_flag(),
            json!({ "rules": [{ "field": "trait", "key": "constructor", "operator": "equals", "value": "function Object() { [native code] }" }] }),
        );
        let context = FeatureFlagContext { traits: Some(json!({})), ..visitor() };
        assert_matches(&evaluate_feature_flag(&flag, &context).unwrap(), json!({ "reason": "rollout" }));

        // A null variant throws when the selection reads it
        let flag = with(base_flag(), json!({ "flagType": "multivariate", "variants": [null] }));
        assert_eq!(
            evaluate_feature_flag(&flag, &visitor()).unwrap_err().0,
            "TypeError: Cannot read properties of null (reading 'rolloutPercentage')"
        );
    }
}
