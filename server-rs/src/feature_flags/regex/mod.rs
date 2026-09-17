//! Regex targeting rules, ported from server/src/services/featureFlags/regex.ts.
//!
//! A pattern is accepted when it is non-empty, at most 256 UTF-16 code units, valid
//! for `new RegExp(pattern)` and judged safe by safe-regex2 (at most 25 repetitions,
//! none nested). Accepted patterns are compiled once into a bounded, first-in
//! first-out cache that evaluation reads without compiling.

mod case_table;
pub mod compile;
mod identifier_tables;
pub mod safe_regex;
pub mod syntax;

use std::{
    collections::HashSet,
    sync::{Arc, LazyLock, Mutex, MutexGuard},
};

use indexmap::IndexMap;
use serde_json::Value;

use self::compile::CompiledRegex;
use super::js::{self, JsError};
use crate::js_json::utf16_len;

pub const MAX_REGEX_PATTERN_LENGTH: usize = 256;
pub const MAX_REGEX_REPETITIONS: usize = 25;
pub const MAX_REGEX_CACHE_SIZE: usize = 1000;
/// Node's `invalidRegexCache` is an unbounded Set. Forgetting an invalid pattern only
/// costs a re-validation (the answer is the same), so the port bounds it.
const MAX_INVALID_CACHE_SIZE: usize = 10_000;

/// `validateFeatureFlagRegexPattern`: the error the dashboard shows, or None.
pub fn validate_feature_flag_regex_pattern(pattern: &str) -> Option<String> {
    if pattern.is_empty() {
        return Some("Regex pattern cannot be empty".to_string());
    }
    if utf16_len(pattern) > MAX_REGEX_PATTERN_LENGTH {
        return Some(format!("Regex pattern cannot exceed {MAX_REGEX_PATTERN_LENGTH} characters"));
    }
    let units: Vec<u16> = pattern.encode_utf16().collect();
    if let Err(error) = syntax::parse(&units) {
        return Some(format!("Invalid regex pattern: {}", v8_syntax_error_message(pattern, error)));
    }
    if !safe_regex::is_safe(pattern, MAX_REGEX_REPETITIONS) {
        return Some("Regex pattern is too complex".to_string());
    }
    None
}

/// The `message` of V8's SyntaxError for `new RegExp(pattern)`:
/// `Invalid regular expression: /<pattern>/: <reason>` (the pattern as written, and
/// no flags).
pub fn v8_syntax_error_message(pattern: &str, error: syntax::RegExpError) -> String {
    format!("Invalid regular expression: /{pattern}/: {}", error.message())
}

/// The compiled-pattern caches (`compiledRegexCache` and `invalidRegexCache`).
#[derive(Debug, Default)]
pub struct RegexCache {
    compiled: IndexMap<String, Arc<CompiledRegex>>,
    invalid: HashSet<String>,
}

impl RegexCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// `precompileFeatureFlagRegexPattern`: the cached pattern, else validate, compile
    /// and cache it (evicting the oldest entry when full). None for invalid patterns.
    pub fn precompile(&mut self, pattern: &str) -> Option<Arc<CompiledRegex>> {
        if let Some(cached) = self.compiled.get(pattern) {
            return Some(cached.clone());
        }
        if self.invalid.contains(pattern) {
            return None;
        }
        if let Some(error) = validate_feature_flag_regex_pattern(pattern) {
            tracing::debug!(pattern, error, "feature flag regex rejected");
            if self.invalid.len() >= MAX_INVALID_CACHE_SIZE {
                self.invalid.clear();
            }
            self.invalid.insert(pattern.to_string());
            return None;
        }

        let units: Vec<u16> = pattern.encode_utf16().collect();
        let compiled = match syntax::parse(&units).map(|parsed| CompiledRegex::new(&parsed)) {
            Ok(Ok(compiled)) => Arc::new(compiled),
            Ok(Err(error)) => {
                // Node would hold a RegExp here; the rule can never match in Rust
                tracing::error!(pattern, error = %error, "feature flag regex valid for V8 but rejected by the matcher");
                return None;
            }
            Err(error) => {
                tracing::error!(pattern, error = error.message(), "feature flag regex validated but failed to parse");
                return None;
            }
        };

        if self.compiled.len() >= MAX_REGEX_CACHE_SIZE
            && let Some((evicted, _)) = self.compiled.shift_remove_index(0)
        {
            tracing::debug!(pattern = evicted, "feature flag regex evicted from the compile cache");
        }
        self.compiled.insert(pattern.to_string(), compiled.clone());
        tracing::debug!(
            pattern,
            spelled = compiled.spelled(),
            cached = self.compiled.len(),
            "feature flag regex compiled"
        );
        Some(compiled)
    }

    /// `getCompiledFeatureFlagRegex`: a pure cache read.
    pub fn get(&self, pattern: &str) -> Option<Arc<CompiledRegex>> {
        self.compiled.get(pattern).cloned()
    }

    /// `precompileFeatureFlagRuleRegexes`: every string value of every `regex` rule.
    /// Reading `operator` off a null rule throws, as in Node.
    pub fn precompile_rule_regexes(&mut self, rules: Option<&Value>) -> Result<(), JsError> {
        let Some(Value::Array(rules)) = rules else {
            return Ok(());
        };
        for rule in rules {
            let operator = js::get(Some(rule), "operator")?;
            if operator.and_then(Value::as_str) != Some("regex") {
                continue;
            }
            match js::get(Some(rule), "value")? {
                Some(Value::Array(values)) => {
                    for value in values {
                        if let Value::String(pattern) = value {
                            self.precompile(pattern);
                        }
                    }
                }
                Some(Value::String(pattern)) => {
                    self.precompile(pattern);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// `precompileFeatureFlagConditionSetRegexes`.
    pub fn precompile_condition_set_regexes(&mut self, condition_sets: Option<&Value>) -> Result<(), JsError> {
        let Some(Value::Array(condition_sets)) = condition_sets else {
            return Ok(());
        };
        for condition_set in condition_sets {
            self.precompile_rule_regexes(js::get(Some(condition_set), "rules")?)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.compiled.len()
    }
}

/// The process-wide cache shared by every evaluation, like Node's module state.
static REGEX_CACHE: LazyLock<Mutex<RegexCache>> = LazyLock::new(|| Mutex::new(RegexCache::new()));

/// The shared cache, recovering from a poisoned lock (the cache stays consistent:
/// every mutation is a single insert or remove).
pub fn shared_cache() -> MutexGuard<'static, RegexCache> {
    REGEX_CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `precompileFeatureFlagRegexPattern` on the shared cache.
pub fn precompile_feature_flag_regex_pattern(pattern: &str) -> Option<Arc<CompiledRegex>> {
    shared_cache().precompile(pattern)
}

/// `getCompiledFeatureFlagRegex` on the shared cache.
pub fn get_compiled_feature_flag_regex(pattern: &str) -> Option<Arc<CompiledRegex>> {
    shared_cache().get(pattern)
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/featureFlags/regex.test.ts. Each test uses its
    //! own cache instead of unique patterns on the shared one.

    use serde_json::json;

    use super::*;

    fn unique_pattern(body: &str, counter: &mut usize) -> String {
        *counter += 1;
        format!("^{body}-unique-{}-{counter}$", std::process::id())
    }

    #[test]
    fn accepts_a_plain_valid_pattern() {
        assert_eq!(validate_feature_flag_regex_pattern("^/pricing"), None);
        assert_eq!(validate_feature_flag_regex_pattern("foo|bar"), None);
        assert_eq!(validate_feature_flag_regex_pattern("[a-z]+\\d{2}"), None);
    }

    #[test]
    fn rejects_an_empty_pattern() {
        assert_eq!(validate_feature_flag_regex_pattern("").as_deref(), Some("Regex pattern cannot be empty"));
    }

    #[test]
    fn accepts_a_whitespace_only_pattern() {
        assert_eq!(validate_feature_flag_regex_pattern(" "), None);
    }

    #[test]
    fn rejects_a_pattern_over_the_256_character_limit() {
        assert_eq!(validate_feature_flag_regex_pattern(&"a".repeat(256)), None);
        assert_eq!(
            validate_feature_flag_regex_pattern(&"a".repeat(257)).as_deref(),
            Some("Regex pattern cannot exceed 256 characters")
        );
    }

    #[test]
    fn checks_length_before_parseability() {
        assert_eq!(
            validate_feature_flag_regex_pattern(&format!("[{}", "a".repeat(300))).as_deref(),
            Some("Regex pattern cannot exceed 256 characters")
        );
    }

    #[test]
    fn rejects_an_unparseable_pattern_and_includes_the_engine_message() {
        let error = validate_feature_flag_regex_pattern("[invalid").expect("invalid");
        assert!(error.starts_with("Invalid regex pattern: "));
        assert!(error.contains("Unterminated character class"));
        assert_eq!(
            error,
            "Invalid regex pattern: Invalid regular expression: /[invalid/: Unterminated character class"
        );
    }

    #[test]
    fn rejects_other_malformed_patterns() {
        for pattern in ["(unclosed", "a{2,1}", "*"] {
            let error = validate_feature_flag_regex_pattern(pattern).expect("invalid");
            assert!(error.starts_with("Invalid regex pattern: "), "{pattern}: {error}");
        }
    }

    #[test]
    fn rejects_catastrophic_backtracking_patterns_as_too_complex() {
        for pattern in ["(a+)+$", "^(x+x+)+y$", "(a{2,3}){2,3}"] {
            assert_eq!(validate_feature_flag_regex_pattern(pattern).as_deref(), Some("Regex pattern is too complex"));
        }
    }

    #[test]
    fn allows_up_to_25_repetition_operators_and_rejects_26() {
        assert_eq!(validate_feature_flag_regex_pattern(&"a*".repeat(25)), None);
        assert_eq!(
            validate_feature_flag_regex_pattern(&"a*".repeat(26)).as_deref(),
            Some("Regex pattern is too complex")
        );
    }

    #[test]
    fn does_not_reject_a_nested_quantifier_free_alternation() {
        assert_eq!(validate_feature_flag_regex_pattern("(a|a)*$"), None);
    }

    #[test]
    fn precompile_returns_a_regex_for_a_valid_pattern() {
        let mut cache = RegexCache::new();
        let mut counter = 0;
        let pattern = unique_pattern("ok", &mut counter);
        assert!(cache.precompile(&pattern).is_some());
    }

    #[test]
    fn precompile_compiles_a_pattern_that_actually_matches() {
        let mut cache = RegexCache::new();
        let compiled = cache.precompile("^/pricing").expect("compiles");
        assert!(compiled.test("/pricing/pro"));
        assert!(!compiled.test("/docs"));
    }

    #[test]
    fn precompile_returns_none_for_invalid_empty_complex_and_long_patterns() {
        let mut cache = RegexCache::new();
        assert!(cache.precompile("").is_none());
        assert!(cache.precompile("[invalid-1").is_none());
        assert!(cache.precompile("(a+)+2").is_none());
        assert!(cache.precompile(&"a".repeat(300)).is_none());
    }

    #[test]
    fn precompile_returns_the_identical_cached_instance_on_repeat_calls() {
        let mut cache = RegexCache::new();
        let mut counter = 0;
        let pattern = unique_pattern("cached", &mut counter);
        let first = cache.precompile(&pattern).expect("compiles");
        let second = cache.precompile(&pattern).expect("compiles");
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn precompile_keeps_distinct_patterns_as_distinct_instances() {
        let mut cache = RegexCache::new();
        let mut counter = 0;
        let a = cache.precompile(&unique_pattern("a", &mut counter)).expect("compiles");
        let b = cache.precompile(&unique_pattern("b", &mut counter)).expect("compiles");
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn precompile_keeps_returning_none_for_a_rejected_pattern() {
        let mut cache = RegexCache::new();
        let bad = "(bad+)+3";
        assert!(cache.precompile(bad).is_none());
        assert!(cache.precompile(bad).is_none());
        assert!(cache.get(bad).is_none());
    }

    #[test]
    fn get_is_a_pure_cache_read() {
        let mut cache = RegexCache::new();
        let mut counter = 0;
        let pattern = unique_pattern("lookup", &mut counter);
        assert!(cache.get(&pattern).is_none());
        assert!(cache.get(&pattern).is_none());
        let compiled = cache.precompile(&pattern).expect("compiles");
        assert!(Arc::ptr_eq(&cache.get(&pattern).expect("cached"), &compiled));
        let bad = "[nope-4";
        cache.precompile(bad);
        assert!(cache.get(bad).is_none());
    }

    #[test]
    fn evicts_the_oldest_entry_when_full() {
        let mut cache = RegexCache::new();
        for index in 0..MAX_REGEX_CACHE_SIZE {
            cache.precompile(&format!("^p{index}$"));
        }
        assert_eq!(cache.len(), MAX_REGEX_CACHE_SIZE);
        // A cache hit does not refresh the entry's position
        assert!(cache.precompile("^p0$").is_some());
        cache.precompile("^overflow$");
        assert_eq!(cache.len(), MAX_REGEX_CACHE_SIZE);
        assert!(cache.get("^p0$").is_none());
        assert!(cache.get("^p1$").is_some());
    }

    #[test]
    fn rule_precompilation_follows_node() {
        let mut cache = RegexCache::new();
        let mut counter = 0;
        assert!(cache.precompile_rule_regexes(None).is_ok());
        assert!(cache.precompile_rule_regexes(Some(&json!([]))).is_ok());
        assert!(cache.precompile_rule_regexes(Some(&json!({}))).is_ok());
        assert!(cache.precompile_rule_regexes(Some(&Value::Null)).is_ok());

        let single = unique_pattern("rule", &mut counter);
        cache
            .precompile_rule_regexes(Some(&json!([{ "field": "pathname", "operator": "regex", "value": single }])))
            .unwrap();
        assert!(cache.get(&single).is_some());

        let (a, b) = (unique_pattern("arr-a", &mut counter), unique_pattern("arr-b", &mut counter));
        cache
            .precompile_rule_regexes(Some(&json!([{ "field": "pathname", "operator": "regex", "value": [a, b] }])))
            .unwrap();
        assert!(cache.get(&a).is_some() && cache.get(&b).is_some());

        let not_regex = unique_pattern("notregex", &mut counter);
        cache
            .precompile_rule_regexes(Some(&json!([{ "field": "pathname", "operator": "equals", "value": not_regex }])))
            .unwrap();
        assert!(cache.get(&not_regex).is_none());

        cache
            .precompile_rule_regexes(Some(&json!([{ "field": "pathname", "operator": "regex", "value": [1, true] }])))
            .unwrap();
        assert!(cache.get("1").is_none() && cache.get("true").is_none());

        let good = unique_pattern("multi", &mut counter);
        let bad = "(bad+)+5";
        cache
            .precompile_rule_regexes(Some(&json!([
                { "field": "pathname", "operator": "regex", "value": good },
                { "field": "country", "operator": "equals", "value": "US" },
                { "field": "referrer", "operator": "regex", "value": bad },
            ])))
            .unwrap();
        assert!(cache.get(&good).is_some());
        assert!(cache.get(bad).is_none());

        let shared = unique_pattern("shared", &mut counter);
        cache
            .precompile_rule_regexes(Some(&json!([
                { "field": "pathname", "operator": "regex", "value": shared },
                { "field": "referrer", "operator": "regex", "value": shared },
            ])))
            .unwrap();
        assert!(Arc::ptr_eq(&cache.get(&shared).unwrap(), &cache.precompile(&shared).unwrap()));

        let error = cache.precompile_rule_regexes(Some(&json!([null]))).unwrap_err();
        assert_eq!(error.0, "TypeError: Cannot read properties of null (reading 'operator')");
    }

    #[test]
    fn condition_set_precompilation_follows_node() {
        let mut cache = RegexCache::new();
        let mut counter = 0;
        assert!(cache.precompile_condition_set_regexes(None).is_ok());
        assert!(cache.precompile_condition_set_regexes(Some(&json!([]))).is_ok());
        assert!(cache.precompile_condition_set_regexes(Some(&json!({}))).is_ok());

        let (a, b) = (unique_pattern("cs-a", &mut counter), unique_pattern("cs-b", &mut counter));
        cache
            .precompile_condition_set_regexes(Some(&json!([
                { "rules": [{ "field": "pathname", "operator": "regex", "value": a }] },
                { "rules": [{ "field": "referrer", "operator": "regex", "value": b }] },
            ])))
            .unwrap();
        assert!(cache.get(&a).is_some() && cache.get(&b).is_some());

        assert!(cache.precompile_condition_set_regexes(Some(&json!([{ "rules": [] }, {}]))).is_ok());

        let equals = unique_pattern("cs-equals", &mut counter);
        cache
            .precompile_condition_set_regexes(Some(
                &json!([{ "rules": [{ "field": "pathname", "operator": "equals", "value": equals }] }]),
            ))
            .unwrap();
        assert!(cache.get(&equals).is_none());

        let error = cache.precompile_condition_set_regexes(Some(&json!([null]))).unwrap_err();
        assert_eq!(error.0, "TypeError: Cannot read properties of null (reading 'rules')");
    }
}
