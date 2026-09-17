//! `JSON.stringify` for JSON values, so bodies written to ClickHouse and Redis are
//! the bytes Node writes. serde_json differs only on numbers: it keeps `1.0` and
//! `1e21` where JavaScript prints `1` and `1e+21`, and ClickHouse parses some
//! columns (DateTime64 from a number, for one) differently for those spellings.
#![allow(dead_code)] // consumed as ingestion is ported

use serde::Serialize;
use serde_json::Value;

/// `JSON.stringify(value)` for a value that went through JSON: every number is a
/// double and prints as `Number.prototype.toString` would.
pub fn stringify(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// Serialise any `Serialize` value as `JSON.stringify` would, via a `Value`.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    Ok(stringify(&serde_json::to_value(value)?))
}

/// JavaScript's `string.length`: UTF-16 code units, not bytes.
pub fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// `Number.prototype.toString` for a finite double.
pub fn number_to_string(number: f64) -> String {
    ryu_js::Buffer::new().format(number).to_string()
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        // as_f64 is exact for doubles and rounds large integers the way JS parsing does
        Value::Number(number) => match number.as_f64() {
            Some(double) if double.is_finite() => out.push_str(ryu_js::Buffer::new().format(double)),
            _ => out.push_str("null"),
        },
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

/// JSON.stringify's QuoteJSONString: the short escapes, `\u00xx` (lowercase hex)
/// for other control characters, everything else verbatim. Rust strings cannot
/// hold the lone surrogates JavaScript would escape.
fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", control as u32)),
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn numbers_print_like_javascript() {
        // JSON.stringify([1.0, 1e21, 0.1, -0, 1700000000000.5, 123456789012345678901, 5e-7])
        let value: Value =
            serde_json::from_str("[1.0, 1e21, 0.1, -0.0, 1700000000000.5, 123456789012345678901, 5e-7]").unwrap();
        assert_eq!(stringify(&value), "[1,1e+21,0.1,0,1700000000000.5,123456789012345680000,5e-7]");
    }

    #[test]
    fn strings_escape_like_javascript() {
        // JSON.stringify({ 'a"b': "\b\t\n\f\r\\/ " + "é" })
        let value = json!({"a\"b": "\u{1}\u{8}\t\n\u{c}\r\\/\u{7f}\u{2028}\u{e9}"});
        assert_eq!(
            stringify(&value),
            "{\"a\\\"b\":\"\\u0001\\b\\t\\n\\f\\r\\\\/\u{7f}\u{2028}\u{e9}\"}"
        );
    }

    #[test]
    fn length_counts_utf16_units() {
        assert_eq!(utf16_len("\u{e9}\u{1f600}a"), 4);
    }
}
