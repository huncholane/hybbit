//! Shaping ClickHouse rows the way `processResults` does in
//! server/src/api/analytics/utils/utils.ts.
#![allow(dead_code)] // used by the analytics routes as they are ported

use serde_json::{Map, Number, Value};

/// Identifiers stay text even when they look numeric.
const OPAQUE_ID_COLUMNS: [&str; 4] = ["session_id", "user_id", "identified_user_id", "effective_user_id"];

/// ClickHouse sends 64-bit integers and decimals as JSON strings. Turn each
/// top-level string column back into a number, but only when JavaScript's
/// `String(Number(value)) === value` holds, so nothing is rounded or reformatted.
pub fn coerce_row(row: &mut Map<String, Value>) {
    for (key, value) in row.iter_mut() {
        if OPAQUE_ID_COLUMNS.contains(&key.as_str()) {
            continue;
        }
        if let Value::String(text) = value
            && let Some(number) = lossless_number(text)
        {
            *value = Value::Number(number);
        }
    }
}

pub fn coerce_rows(rows: &mut [Map<String, Value>]) {
    rows.iter_mut().for_each(coerce_row);
}

fn lossless_number(text: &str) -> Option<Number> {
    let parsed: f64 = text.parse().ok()?;
    if !parsed.is_finite() {
        return None;
    }

    let mut buffer = ryu_js::Buffer::new();
    if buffer.format(parsed) != text {
        return None;
    }

    // Integral values print without a trailing ".0", as JSON.stringify would
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    if parsed.fract() == 0.0 && parsed.abs() <= MAX_SAFE_INTEGER {
        Some(Number::from(parsed as i64))
    } else {
        Number::from_f64(parsed)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn coerce(value: Value) -> Value {
        let Value::Object(mut row) = value else { unreachable!() };
        coerce_row(&mut row);
        Value::Object(row)
    }

    #[test]
    fn converts_counts_and_plain_decimals() {
        assert_eq!(
            coerce(json!({ "sessions": "51", "bounce_rate": "81.4", "negative": "-3", "zero": "0" })),
            json!({ "sessions": 51, "bounce_rate": 81.4, "negative": -3, "zero": 0 })
        );
    }

    #[test]
    fn keeps_text_that_would_not_round_trip() {
        let untouched = json!({
            "campaign": "120248430174340693",
            "padded": "007",
            "trailing_zero": "1.50",
            "exponent": "1e5",
            "tiny": "0.0000001",
            "negative_zero": "-0",
            "spaced": " 1",
            "not_a_number": "NaN",
            "infinite": "Infinity",
            "empty": "",
        });
        assert_eq!(coerce(untouched.clone()), untouched);
    }

    #[test]
    fn never_touches_identifier_columns_or_non_strings() {
        let row = json!({ "session_id": "123", "user_id": "42", "identified_user_id": "7", "effective_user_id": "9", "lat": 13.75, "flag": true });
        assert_eq!(coerce(row.clone()), row);
    }
}
