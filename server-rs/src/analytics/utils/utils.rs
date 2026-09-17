//! Port of server/src/api/analytics/utils/utils.ts: result shaping, wildcard
//! path patterns and user-trait enrichment.

use std::collections::HashMap;

use serde_json::{Map, Value};
use sqlx::{PgPool, Row};
use tracing::debug;

use crate::analytics::js::JsValue;

/// `processResults`: numeric-looking string columns become numbers when the
/// conversion is lossless; identifier columns stay text. Shared with the Phase 0
/// port in `json_shape`.
pub fn process_results(rows: &mut [Map<String, Value>]) {
    crate::json_shape::coerce_rows(rows);
}

/// The escape step shared by `patternToRegex` and `textPatternToRegex`:
/// `pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&")`.
pub(crate) fn escape_regex_metacharacters(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for character in pattern.chars() {
        if matches!(character, '.' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(character);
    }
    out
}

/// `patternToRegex`: `*` matches one path segment, `**` any number, anchored.
pub fn pattern_to_regex(pattern: &str) -> String {
    let escaped = escape_regex_metacharacters(pattern);
    let with_double_star = escaped.replace("**", "{{DOUBLE_STAR}}");
    let with_single_star = with_double_star.replace('*', "[^/]+");
    format!("^{}$", with_single_star.replace("{{DOUBLE_STAR}}", ".*"))
}

/// `enrichWithTraits(data, siteId)`: attach each identified user's traits from
/// Postgres (`{}` for a non-object traits column, `null` when there is no
/// profile or no identity).
pub async fn enrich_with_traits(
    pg: &PgPool,
    mut rows: Vec<Map<String, Value>>,
    site_id: i32,
) -> Result<Vec<Map<String, Value>>, sqlx::Error> {
    let mut identified_user_ids: Vec<String> = Vec::new();
    for row in &rows {
        if let Some(Value::String(id)) = row.get("identified_user_id")
            && !id.is_empty()
            && !identified_user_ids.contains(id)
        {
            identified_user_ids.push(id.clone());
        }
    }

    let mut traits_by_user: HashMap<String, Value> = HashMap::new();
    if !identified_user_ids.is_empty() {
        let profiles = sqlx::query("SELECT user_id, traits FROM user_profiles WHERE site_id = $1 AND user_id = ANY($2)")
            .bind(site_id)
            .bind(&identified_user_ids)
            .fetch_all(pg)
            .await?;
        debug!(site_id, requested = identified_user_ids.len(), found = profiles.len(), "loaded user traits");
        for profile in profiles {
            let user_id: String = profile.try_get("user_id")?;
            let traits: Option<Value> = profile.try_get("traits")?;
            // JSON.parse orders integer-like keys first; jsonb orders by key length
            let traits = match traits {
                Some(value @ Value::Object(_)) => JsValue::from_serde(&value).to_serde(),
                _ => Value::Object(Map::new()),
            };
            traits_by_user.insert(user_id, traits);
        }
    }

    for row in &mut rows {
        let traits = match row.get("identified_user_id") {
            Some(Value::String(id)) => traits_by_user.get(id).cloned().unwrap_or(Value::Null),
            _ => Value::Null,
        };
        row.insert("traits".to_string(), traits);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // Ported from utils.test.ts
    #[test]
    fn pattern_to_regex_cases() {
        assert_eq!(pattern_to_regex("/blog/*"), "^/blog/[^/]+$");
        assert_eq!(pattern_to_regex("/blog/**"), "^/blog/.*$");
        assert_eq!(pattern_to_regex("/docs/**/intro"), "^/docs/.*/intro$");
        assert_eq!(pattern_to_regex("*"), "^[^/]+$");
        assert_eq!(pattern_to_regex("**"), "^.*$");
        assert_eq!(pattern_to_regex("/path.html"), "^/path\\.html$");
        assert_eq!(pattern_to_regex("/a+b?c"), "^/a\\+b\\?c$");
        assert_eq!(pattern_to_regex("/(x)|[y]"), "^/\\(x\\)\\|\\[y\\]$");
        assert_eq!(pattern_to_regex("/p{1}^$"), "^/p\\{1\\}\\^\\$$");
        assert_eq!(pattern_to_regex("/back\\slash"), "^/back\\\\slash$");
        assert_eq!(pattern_to_regex("/{{DOUBLE_STAR}}"), "^/\\{\\{DOUBLE_STAR\\}\\}$");
        assert_eq!(pattern_to_regex("/a/***"), "^/a/.*[^/]+$");
        assert_eq!(pattern_to_regex("/pricing"), "^/pricing$");
    }

    fn processed(value: Value) -> Value {
        let Value::Array(items) = value else { unreachable!() };
        let mut rows: Vec<Map<String, Value>> =
            items.into_iter().map(|item| if let Value::Object(map) = item { map } else { unreachable!() }).collect();
        process_results(&mut rows);
        Value::Array(rows.into_iter().map(Value::Object).collect())
    }

    #[test]
    fn process_results_cases() {
        assert_eq!(
            processed(json!([{ "count": "123", "ratio": "45.6", "negative": "-7" }])),
            json!([{ "count": 123, "ratio": 45.6, "negative": -7 }])
        );
        assert_eq!(processed(json!([{ "count": 42 }])), json!([{ "count": 42 }]));
        assert_eq!(
            processed(json!([{ "session_id": "12345", "user_id": "67890", "identified_user_id": "111", "effective_user_id": "222", "site_id": "999" }])),
            json!([{ "session_id": "12345", "user_id": "67890", "identified_user_id": "111", "effective_user_id": "222", "site_id": 999 }])
        );
        assert_eq!(
            processed(json!([{ "flagOn": true, "flagOff": false, "empty": "", "missing": null }])),
            json!([{ "flagOn": true, "flagOff": false, "empty": "", "missing": null }])
        );
        assert_eq!(
            processed(json!([{ "browser": "Chrome", "date": "2024-01-01", "version": "1.2.3", "word": "true" }])),
            json!([{ "browser": "Chrome", "date": "2024-01-01", "version": "1.2.3", "word": "true" }])
        );
        assert_eq!(processed(json!([{ "blank": " ", "tab": "\t" }])), json!([{ "blank": " ", "tab": "\t" }]));
        assert_eq!(
            processed(json!([{ "value": "120248430174340693", "count": "42" }])),
            json!([{ "value": "120248430174340693", "count": 42 }])
        );
        assert_eq!(
            processed(json!([{ "leadingZeros": "007", "plus": "+5", "trailingZero": "1.50", "exponent": "1e5" }])),
            json!([{ "leadingZeros": "007", "plus": "+5", "trailingZero": "1.50", "exponent": "1e5" }])
        );
        assert_eq!(processed(json!([{ "a": "NaN", "b": "Infinity", "c": "-Infinity" }])), json!([{ "a": "NaN", "b": "Infinity", "c": "-Infinity" }]));
        assert_eq!(
            processed(json!([{ "pathname": "/a", "visitors": "10" }, { "pathname": "/b", "visitors": "20" }])),
            json!([{ "pathname": "/a", "visitors": 10 }, { "pathname": "/b", "visitors": 20 }])
        );
    }
}
