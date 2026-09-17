//! The JavaScript JSON quirks Better Auth's stored-JSON columns go through.
//!
//! * `parse_json_strict` is better-json's `parseJSON(value, { strict: true })`
//!   (better-auth/client): special words, a signature check, prototype pollution
//!   guards and ISO date revival through `Date.UTC` arithmetic.
//! * `safe_json_parse` is `@better-auth/core/utils/json` `safeJSONParse`:
//!   `JSON.parse` with a `new Date(...)` reviver; failures become `null`.
//!
//! Revived dates are returned as the ISO strings `JSON.stringify` would print for
//! the resulting `Date`, and object keys are reordered the way a JS object orders
//! them (array-index keys first, ascending).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

/// ECMAScript's time value limit (+-8.64e15 ms).
const MAX_TIME_MS: i128 = 8_640_000_000_000_000;

static JSON_SIGNATURE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*["\[{]|^\s*-?\d{1,16}(\.\d{1,17})?([Ee][+-]?\d+)?\s*$"#).expect("signature regex"));
static PROTO_POLLUTION: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    [
        Regex::new(r#""(?:_|\\u0{2}5[Ff]){2}(?:p|\\u0{2}70)(?:r|\\u0{2}72)(?:o|\\u0{2}6[Ff])(?:t|\\u0{2}74)(?:o|\\u0{2}6[Ff])(?:_|\\u0{2}5[Ff]){2}"\s*:"#)
            .expect("proto regex"),
        Regex::new(r#""(?:c|\\u0063)(?:o|\\u006[Ff])(?:n|\\u006[Ee])(?:s|\\u0073)(?:t|\\u0074)(?:r|\\u0072)(?:u|\\u0075)(?:c|\\u0063)(?:t|\\u0074)(?:o|\\u006[Ff])(?:r|\\u0072)"\s*:"#)
            .expect("constructor regex"),
        Regex::new(r#""__proto__"\s*:"#).expect("proto short regex"),
        Regex::new(r#""constructor"\s*:"#).expect("constructor short regex"),
    ]
});
static BETTER_ISO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(?:Z|([+-])(\d{2}):(\d{2}))$").expect("iso regex")
});
static CORE_ISO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$").expect("core iso regex"));

/// Why a strict parse threw; the caller turns it into whatever the Node call site
/// did with the exception (usually a 500).
#[derive(Debug, PartialEq)]
pub enum StrictParseError {
    InvalidJson,
    PrototypePollution,
    Syntax(String),
}

/// `parseJSON(text, { strict: true })`. `Ok(None)` is `undefined`.
pub fn parse_json_strict(text: &str) -> Result<Option<Value>, StrictParseError> {
    let trimmed = js_trim(text);
    let lower = trimmed.to_lowercase();
    if crate::js_json::utf16_len(&lower) <= 9 {
        match lower.as_str() {
            "true" => return Ok(Some(Value::Bool(true))),
            "false" => return Ok(Some(Value::Bool(false))),
            // NaN and the infinities serialise as null wherever the value ends up
            "null" | "nan" | "infinity" | "-infinity" => return Ok(Some(Value::Null)),
            "undefined" => return Ok(None),
            _ => {}
        }
    }
    if !JSON_SIGNATURE.is_match(trimmed) {
        return Err(StrictParseError::InvalidJson);
    }
    if PROTO_POLLUTION.iter().any(|pattern| pattern.is_match(trimmed)) {
        return Err(StrictParseError::PrototypePollution);
    }
    let parsed: Value = serde_json::from_str(trimmed).map_err(|err| StrictParseError::Syntax(err.to_string()))?;
    Ok(Some(revive(parsed, &better_json_date)))
}

/// Whether `parse_json_strict(text)` yields a revived `Date` at the top level (a
/// JSON string literal holding an ISO timestamp), as opposed to a JS string.
pub fn parses_to_date(text: &str) -> bool {
    matches!(serde_json::from_str::<Value>(js_trim(text)), Ok(Value::String(inner)) if better_json_date(&inner).is_some())
}

/// `safeJSONParse(text)` for a string input.
pub fn safe_json_parse(text: &str) -> Value {
    match serde_json::from_str::<Value>(text) {
        Ok(parsed) => revive(parsed, &core_date),
        Err(err) => {
            tracing::debug!(error = %err, "safeJSONParse failed; using null");
            Value::Null
        }
    }
}

/// `JSON.parse(text)` without a reviver, `None` when it throws.
pub fn js_json_parse(text: &str) -> Option<Value> {
    serde_json::from_str::<Value>(text).ok().map(|parsed| revive(parsed, &|_| None))
}

/// An already parsed value with its object keys in JS order (what `JSON.parse` of
/// Postgres' jsonb text yields in Node).
pub fn js_object_order(value: Value) -> Value {
    revive(value, &|_| None)
}

/// JS truthiness of a JSON value.
pub fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|double| double != 0.0 && !double.is_nan()),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String.prototype.trim`: Unicode whitespace plus the BOM.
fn js_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// Rebuild parsed JSON with JS object key order and date revival for strings.
fn revive(value: Value, date: &dyn Fn(&str) -> Option<String>) -> Value {
    match value {
        Value::String(text) => match date(&text) {
            Some(iso) => Value::String(iso),
            None => Value::String(text),
        },
        Value::Array(items) => Value::Array(items.into_iter().map(|item| revive(item, date)).collect()),
        Value::Object(map) => {
            let mut index_keys: Vec<(u32, String, Value)> = Vec::new();
            let mut other_keys: Vec<(String, Value)> = Vec::new();
            for (key, item) in map {
                let item = revive(item, date);
                match array_index(&key) {
                    Some(index) => index_keys.push((index, key, item)),
                    None => other_keys.push((key, item)),
                }
            }
            index_keys.sort_by_key(|(index, _, _)| *index);
            let mut out = Map::new();
            for (_, key, item) in index_keys {
                out.insert(key, item);
            }
            for (key, item) in other_keys {
                out.insert(key, item);
            }
            Value::Object(out)
        }
        other => other,
    }
}

/// A canonical array index (`0` to `2^32 - 2`), which JS objects list first.
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || (key.len() > 1 && key.starts_with('0')) || !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    key.parse::<u64>().ok().filter(|index| *index < u64::from(u32::MAX)).map(|index| index as u32)
}

/// better-json `parseISODate`: `Date.UTC` with overflowing components, then the
/// offset applied, valid unless outside the time value range.
fn better_json_date(text: &str) -> Option<String> {
    let caps = BETTER_ISO.captures(text)?;
    let num = |index: usize| caps.get(index).map_or(0, |m| m.as_str().parse::<i64>().unwrap_or(0));
    let mut year = num(1);
    // Date.UTC maps years 0..=99 to 1900..=1999
    if (0..=99).contains(&year) {
        year += 1900;
    }
    let ms = caps.get(7).map_or(0, |m| format!("{:0<3}", m.as_str()).parse::<i64>().unwrap_or(0));
    let mut time = make_date(year, num(2) - 1, num(3), num(4), num(5), num(6), ms)?;
    if let Some(sign) = caps.get(8) {
        let offset_minutes = (num(9) * 60 + num(10)) * if sign.as_str() == "+" { -1 } else { 1 };
        time += i128::from(offset_minutes) * 60_000;
    }
    (time.abs() <= MAX_TIME_MS).then(|| to_iso_string(time))
}

/// `new Date(text)` for text matching core's ISO regex: V8 validates each field
/// (hour 24 only as 24:00:00.000) but lets the day overflow the month up to 31.
fn core_date(text: &str) -> Option<String> {
    let caps = CORE_ISO.captures(text)?;
    let num = |index: usize| caps[index].parse::<i64>().unwrap_or(0);
    let (year, month, day, hour, minute, second) = (num(1), num(2), num(3), num(4), num(5), num(6));
    let ms = caps.get(7).map_or(0, |m| {
        let digits: String = m.as_str().chars().take(3).collect();
        format!("{digits:0<3}").parse::<i64>().unwrap_or(0)
    });
    let valid = (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && (0..=59).contains(&minute)
        && (0..=59).contains(&second)
        && (hour < 24 || (hour == 24 && minute == 0 && second == 0 && ms == 0));
    if !valid {
        return None;
    }
    let time = make_date(year, month - 1, day, hour, minute, second, ms)?;
    (time.abs() <= MAX_TIME_MS).then(|| to_iso_string(time))
}

/// ECMAScript MakeDate(MakeDay(year, month, day), MakeTime(h, m, s, ms)).
fn make_date(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64, ms: i64) -> Option<i128> {
    let year = year.checked_add(month.div_euclid(12))?;
    let month = month.rem_euclid(12);
    let days = days_from_civil(year, month + 1, 1) + i128::from(day) - 1;
    let time = i128::from(hour) * 3_600_000 + i128::from(minute) * 60_000 + i128::from(second) * 1000 + i128::from(ms);
    Some(days * 86_400_000 + time)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
fn days_from_civil(year: i64, month: i64, day: i64) -> i128 {
    let year = i128::from(if month <= 2 { year - 1 } else { year });
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = i128::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i128::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `Date.prototype.toISOString` for a valid time value.
fn to_iso_string(time: i128) -> String {
    let days = time.div_euclid(86_400_000);
    let ms_of_day = time.rem_euclid(86_400_000);
    // civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i128::from(month <= 2);
    let year_text = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    format!(
        "{year_text}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        ms_of_day / 3_600_000,
        ms_of_day / 60_000 % 60,
        ms_of_day / 1000 % 60,
        ms_of_day % 1000
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Expectations captured from Node 26 (better-auth 1.6.25 parser and V8 Date).
    #[test]
    fn better_json_dates_match_node() {
        let cases = [
            ("2023-02-31T00:00:00Z", "2023-03-03T00:00:00.000Z"),
            ("2024-01-01T24:00:00Z", "2024-01-02T00:00:00.000Z"),
            ("2024-01-01T23:59:60Z", "2024-01-02T00:00:00.000Z"),
            ("2024-01-01T10:00:00.1234567Z", "2024-01-01T10:20:34.567Z"),
            ("0000-01-01T00:00:00Z", "1900-01-01T00:00:00.000Z"),
            ("2024-13-01T00:00:00Z", "2025-01-01T00:00:00.000Z"),
            ("2024-01-01T25:00:00Z", "2024-01-02T01:00:00.000Z"),
            ("2024-00-10T00:00:00Z", "2023-12-10T00:00:00.000Z"),
            ("2024-01-01T10:00:00.5Z", "2024-01-01T10:00:00.500Z"),
        ];
        for (input, expected) in cases {
            let parsed = parse_json_strict(&json!({ "a": input }).to_string()).unwrap().unwrap();
            assert_eq!(parsed["a"], json!(expected), "{input}");
        }
    }

    #[test]
    fn core_dates_match_v8() {
        let cases = [
            ("2023-02-31T00:00:00Z", Some("2023-03-03T00:00:00.000Z")),
            ("2024-01-01T24:00:00Z", Some("2024-01-02T00:00:00.000Z")),
            ("2024-01-01T23:59:60Z", None),
            ("2024-01-01T10:00:00.1234567Z", Some("2024-01-01T10:00:00.123Z")),
            ("0000-01-01T00:00:00Z", Some("0000-01-01T00:00:00.000Z")),
            ("2024-13-01T00:00:00Z", None),
            ("2024-01-01T25:00:00Z", None),
            ("2024-00-10T00:00:00Z", None),
            ("2024-01-00T00:00:00Z", None),
            ("2024-01-32T00:00:00Z", None),
            ("2024-04-31T00:00:00Z", Some("2024-05-01T00:00:00.000Z")),
            ("2024-01-01T24:30:00Z", None),
            ("2024-01-01T24:00:00.001Z", None),
            ("2024-01-01T10:00:00.9999Z", Some("2024-01-01T10:00:00.999Z")),
            ("9999-12-31T24:00:00Z", Some("+010000-01-01T00:00:00.000Z")),
        ];
        for (input, expected) in cases {
            assert_eq!(core_date(input).as_deref(), expected, "{input}");
        }
    }

    #[test]
    fn strict_parse_words_and_errors() {
        assert_eq!(parse_json_strict(" 12 "), Ok(Some(json!(12))));
        assert_eq!(parse_json_strict("True"), Ok(Some(json!(true))));
        assert_eq!(parse_json_strict("undefined"), Ok(None));
        assert_eq!(parse_json_strict("NaN"), Ok(Some(Value::Null)));
        assert_eq!(parse_json_strict("\"x\""), Ok(Some(json!("x"))));
        assert_eq!(parse_json_strict("1e5"), Ok(Some(json!(1e5))));
        assert_eq!(parse_json_strict("hello"), Err(StrictParseError::InvalidJson));
        assert_eq!(parse_json_strict("12345678901234567"), Err(StrictParseError::InvalidJson));
        assert_eq!(parse_json_strict("{\"__proto__\": 1}"), Err(StrictParseError::PrototypePollution));
        assert!(matches!(parse_json_strict("[1,2"), Err(StrictParseError::Syntax(_))));
    }

    #[test]
    fn object_keys_follow_js_order() {
        let parsed = safe_json_parse(r#"{"b":1,"1":2,"a":3,"0":4}"#);
        assert_eq!(crate::js_json::stringify(&parsed), r#"{"0":4,"1":2,"b":1,"a":3}"#);
        assert_eq!(safe_json_parse("{bad"), Value::Null);
        assert_eq!(safe_json_parse(r#"{"at":"2024-01-01T00:00:00Z"}"#), json!({"at": "2024-01-01T00:00:00.000Z"}));
    }

    #[test]
    fn truthiness() {
        assert!(!is_truthy(&json!(0)));
        assert!(!is_truthy(&json!("")));
        assert!(is_truthy(&json!("0")));
        assert!(is_truthy(&json!({})));
    }
}
