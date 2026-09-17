//! `SqlString.escape` from the `sqlstring` 2.3.3 package, which the Node
//! analytics layer uses to inline filter values into ClickHouse SQL.

use super::js::{JsValue, number::number_to_string};

/// `escapeString`: backslash-escape NUL, backspace, tab, newline, carriage
/// return, SUB (0x1a, as `\Z`), both quotes and backslash, then single-quote.
pub fn escape_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for character in value.chars() {
        match character {
            '\0' => out.push_str("\\0"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{1a}' => out.push_str("\\Z"),
            '"' => out.push_str("\\\""),
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

/// `SqlString.escape(number)`: the number's string form, unquoted.
pub fn escape_number(value: f64) -> String {
    number_to_string(value)
}

/// `SqlString.escape(value)` for the JSON-shaped values request input can hold.
/// Arrays become comma-separated lists; objects become `` `key` = value `` lists.
pub fn escape(value: &JsValue) -> String {
    match value {
        JsValue::Undefined | JsValue::Null => "NULL".to_string(),
        JsValue::Bool(flag) => flag.to_string(),
        JsValue::Number(number) => escape_number(*number),
        JsValue::String(text) => escape_string(text),
        JsValue::Array(items) => array_to_list(items),
        JsValue::Object(object) => object
            .iter()
            .map(|(key, item)| format!("{} = {}", escape_id(key), escape_stringify_objects(item)))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// `SqlString.escape(val, true)` as used inside lists: objects are stringified.
fn escape_stringify_objects(value: &JsValue) -> String {
    match value {
        JsValue::Object(_) => escape_string("[object Object]"),
        other => escape(other),
    }
}

fn array_to_list(items: &[JsValue]) -> String {
    items
        .iter()
        .map(|item| match item {
            JsValue::Array(nested) => format!("({})", array_to_list(nested)),
            other => escape_stringify_objects(other),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `SqlString.escapeId` (qualified names allowed).
pub fn escape_id(value: &str) -> String {
    format!("`{}`", value.replace('`', "``").replace('.', "`.`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_sqlstring() {
        assert_eq!(escape_string("Chrome'; DROP TABLE users;--"), "'Chrome\\'; DROP TABLE users;--'");
        assert_eq!(escape_string("a\0b\u{8}\t\n\r\u{1a}\"\\"), "'a\\0b\\b\\t\\n\\r\\Z\\\"\\\\'");
        assert_eq!(escape(&JsValue::Number(40.5)), "40.5");
        assert_eq!(escape(&JsValue::Array(vec!["UTC".into(), JsValue::Number(1.0)])), "'UTC', 1");
        assert_eq!(escape(&JsValue::Null), "NULL");
    }
}
