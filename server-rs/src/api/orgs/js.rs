//! JavaScript semantics the handlers in this group lean on where they read
//! `request.body` without a schema: destructuring, truthiness, `.length`, spreading
//! and `String(value)`, plus the responses Fastify sends when one of those throws.
//!
//! Node's handlers differ in where the throw lands: a destructuring TypeError
//! before the `try` becomes Fastify's own 500 (`{statusCode, error, message}` with
//! the V8 message), while one inside the `try` becomes the handler's catch branch.
//! Both shapes live here so each handler can pick the right one.

use axum::{body::Body, http::{HeaderValue, StatusCode, header}, response::Response};
use serde_json::json;
use tracing::warn;

use crate::analytics::{
    js::{JsObject, JsValue, date, number::number_to_string, string::trim},
    utils::time_window::now_ms,
};

/// `new Date().toISOString()`
pub fn now_iso() -> String {
    date::to_iso_string(now_ms()).unwrap_or_default()
}

/// Fastify's default error handler for an uncaught throw: `{statusCode, error,
/// message}` with the thrown error's message.
pub fn fastify_uncaught(message: &str) -> Response {
    warn!(message, "Handler threw before its try block");
    let body = json!({"statusCode": 500, "error": "Internal Server Error", "message": message});
    let mut response = Response::new(Body::from(crate::js_json::stringify(&body)));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

/// V8's message for `const { first, ... } = source` when `source` is nullish.
pub fn destructure_message(first: &str, source: &str, value: &JsValue) -> String {
    let what = if matches!(value, JsValue::Null) { "null" } else { "undefined" };
    format!("Cannot destructure property '{first}' of '{source}' as it is {what}.")
}

/// `const { first, ... } = request.body`: only `undefined` and `null` throw; every
/// other value is boxed and yields `undefined` for each property.
pub fn destructure<'a>(body: &'a JsValue, first: &str) -> Result<Fields<'a>, String> {
    match body {
        JsValue::Undefined | JsValue::Null => Err(destructure_message(first, "request.body", body)),
        JsValue::Object(object) => Ok(Fields { object: Some(object) }),
        _ => Ok(Fields { object: None }),
    }
}

/// The destructured properties of a body.
pub struct Fields<'a> {
    object: Option<&'a JsObject>,
}

impl Fields<'_> {
    pub fn get(&self, name: &str) -> &JsValue {
        const UNDEFINED: &JsValue = &JsValue::Undefined;
        self.object.map_or(UNDEFINED, |object| object.get_or_undefined(name))
    }
}

/// `!!value`
pub fn truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Undefined | JsValue::Null => false,
        JsValue::Bool(flag) => *flag,
        JsValue::Number(number) => *number != 0.0 && !number.is_nan(),
        JsValue::String(text) => !text.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}

/// V8's message for calling a missing method on a value.
pub fn not_a_function_message(expression: &str, method: &str) -> String {
    format!("{expression}.{method} is not a function")
}

/// V8's message for reading a property of a nullish value.
pub fn nullish_property_message(value: &JsValue, property: &str) -> String {
    let what = if matches!(value, JsValue::Null) { "null" } else { "undefined" };
    format!("Cannot read properties of {what} (reading '{property}')")
}

/// `value.trim()`: the trimmed text, or the message the call throws with.
pub fn trim_call(value: &JsValue, expression: &str) -> Result<String, String> {
    match value {
        JsValue::String(text) => Ok(trim(text).to_string()),
        JsValue::Undefined | JsValue::Null => Err(nullish_property_message(value, "trim")),
        _ => Err(not_a_function_message(expression, "trim")),
    }
}

/// An argument a handler treats as a list without validating it: what JavaScript
/// answers for the operations those handlers perform on it.
pub struct ListArg<'a> {
    value: &'a JsValue,
}

impl<'a> ListArg<'a> {
    pub fn new(value: &'a JsValue) -> Self {
        Self { value }
    }

    pub fn value(&self) -> &JsValue {
        self.value
    }

    pub fn is_undefined(&self) -> bool {
        matches!(self.value, JsValue::Undefined)
    }

    pub fn is_nullish(&self) -> bool {
        matches!(self.value, JsValue::Undefined | JsValue::Null)
    }

    pub fn truthy(&self) -> bool {
        truthy(self.value)
    }

    /// `value.length`, or `None` when the value has no such property. Reading it
    /// from a nullish value throws, which callers check with [`Self::is_nullish`].
    pub fn length(&self) -> Option<usize> {
        match self.value {
            JsValue::Array(items) => Some(items.len()),
            JsValue::String(text) => Some(crate::analytics::js::string::utf16_len(text)),
            JsValue::Object(object) => object.get("length").and_then(|value| {
                let number = value.to_number();
                (number.is_finite() && number >= 0.0).then_some(number as usize)
            }),
            _ => None,
        }
    }

    /// `value.length > 0`
    pub fn has_items(&self) -> bool {
        self.length().is_some_and(|length| length > 0)
    }

    pub fn items(&self) -> Option<&'a [JsValue]> {
        match self.value {
            JsValue::Array(items) => Some(items),
            _ => None,
        }
    }

    /// `[...(value || [])]`: arrays and strings are iterable, anything else throws.
    pub fn spread(&self) -> Result<Vec<JsValue>, String> {
        if !self.truthy() {
            return Ok(Vec::new());
        }
        match self.value {
            JsValue::Array(items) => Ok(items.clone()),
            JsValue::String(text) => Ok(text.chars().map(|c| JsValue::String(c.to_string())).collect()),
            other => Err(format!("{} is not iterable", describe(other))),
        }
    }

    /// `value || []` as it appears in a response body.
    pub fn or_empty_array(&self) -> JsValue {
        if self.truthy() { self.value.clone() } else { JsValue::Array(Vec::new()) }
    }
}

/// How V8 names a value in a "not iterable" message.
fn describe(value: &JsValue) -> String {
    match value {
        JsValue::Object(_) => "object".into(),
        JsValue::Number(number) => number_to_string(*number),
        JsValue::Bool(flag) => flag.to_string(),
        _ => "value".into(),
    }
}

/// One value drizzle binds as a query parameter.
///
/// Probed against postgres-js 3 and this Postgres (scratchpad probe_pg.mjs). The
/// parameter's type comes from the statement's own description, and the value is
/// serialised for it:
///
/// - a `boolean` column uses `x === true ? 't' : 'f'`, so **only** `true` stores
///   true: `"yes"`, `1` and `"true"` all store false;
/// - every other column gets `String(value)`, so an array is its comma-joined text
///   (`["a"]` is `"a"`), any other object is `"[object Object]"`, and a number is
///   its decimal text;
/// - `null` is SQL NULL;
/// - `true`/`false` are the only values sent with a type of their own (`bool`), so
///   they are the only ones a text or integer column rejects outright.
pub enum Bind {
    Text(String),
    Null,
    Throws,
}

/// How postgres-js sends one value to a `text` or `integer` column.
pub fn bind_value(value: &JsValue) -> Bind {
    match value {
        JsValue::Null | JsValue::Undefined => Bind::Null,
        JsValue::Bool(_) => Bind::Throws,
        other => Bind::Text(to_display(other)),
    }
}

/// How postgres-js sends one value to a `boolean` column.
pub fn bind_boolean(value: &JsValue) -> Option<bool> {
    match value {
        JsValue::Null | JsValue::Undefined => None,
        other => Some(other == &JsValue::Bool(true)),
    }
}

/// What Postgres accepts for an `integer` column from an untyped parameter:
/// surrounding whitespace, an optional sign, and decimal digits or a `0x`, `0o` or
/// `0b` prefix, inside the int4 range. (`"0x10"` stores 16; `"1e3"` is rejected.)
pub fn pg_int_literal(text: &str) -> Option<i32> {
    let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let lower = digits.to_ascii_lowercase();
    let (radix, body) = match lower.strip_prefix("0x") {
        Some(rest) => (16, rest.to_string()),
        None => match lower.strip_prefix("0o") {
            Some(rest) => (8, rest.to_string()),
            None => match lower.strip_prefix("0b") {
                Some(rest) => (2, rest.to_string()),
                None => (10, lower.clone()),
            },
        },
    };
    let body = body.replace('_', "");
    if body.is_empty() || !body.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let magnitude = i64::from_str_radix(&body, radix).ok()?;
    let value = if negative { -magnitude } else { magnitude };
    i32::try_from(value).ok()
}

/// `set.has(value)` for a `Set` of strings loaded from Postgres: strict equality,
/// so only a string value can ever be a member. A numeric string that matched in
/// SQL is still not in a `Set` of numbers, and the other way round.
pub fn is_present_string(value: &JsValue, present: &[String]) -> bool {
    matches!(value, JsValue::String(text) if present.iter().any(|found| found == text))
}

/// The same for a `Set` of numbers: only a number equal to one of them matches.
pub fn is_present_number(value: &JsValue, present: &[i32]) -> bool {
    matches!(value, JsValue::Number(number) if present.iter().any(|found| f64::from(*found) == *number))
}

/// `Array.prototype.join`: `null` and `undefined` render as the empty string.
pub fn join_display(values: &[JsValue], separator: &str) -> String {
    values
        .iter()
        .map(|value| match value {
            JsValue::Null | JsValue::Undefined => String::new(),
            other => to_display(other),
        })
        .collect::<Vec<_>>()
        .join(separator)
}

/// `String(value)`, which is both how these handlers interpolate a value into a
/// message and how postgres-js serialises an untyped parameter. An array joins its
/// elements with commas (nullish elements render as nothing); any other object is
/// `"[object Object]"`.
pub fn to_display(value: &JsValue) -> String {
    match value {
        JsValue::String(text) => text.clone(),
        JsValue::Number(number) => number_to_string(*number),
        JsValue::Bool(flag) => flag.to_string(),
        JsValue::Null => "null".into(),
        JsValue::Undefined => "undefined".into(),
        JsValue::Array(items) => join_display(items, ","),
        JsValue::Object(_) => "[object Object]".into(),
    }
}
