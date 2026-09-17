//! JavaScript value semantics over JSON data.
//!
//! Flag definitions reach Node as whatever `JSON.parse` (Redis) or postgres-js plus
//! drizzle (Postgres) produced, and the evaluator reads them with plain property
//! access, `String(value)`, `Math.max(0, value)` and truthiness tests. Nothing
//! validates the shape again at evaluation time, so a hand-edited row can hold a
//! string where a number belongs, `null` where an object belongs, and so on. These
//! helpers reproduce what V8 does with such values so the Rust evaluator gives the
//! same answers (and fails with a TypeError in the same places) for any JSON.

use std::{borrow::Cow, fmt};

use serde_json::{Map, Number, Value};

use crate::js_json;

/// A JavaScript exception raised while walking data, such as reading a property of
/// `null`. Node lets these escape to the route's catch block, which answers 500.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsError(pub String);

impl fmt::Display for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JsError {}

/// `TypeError: Cannot read properties of null (reading 'name')`, V8's wording.
pub fn read_of_nullish(base: Option<&Value>, name: &str) -> JsError {
    let what = if base.is_none() { "undefined" } else { "null" };
    JsError(format!("TypeError: Cannot read properties of {what} (reading '{name}')"))
}

/// `base[name]` for a property name that no prototype of a JSON value defines
/// (`rules`, `key`, `rolloutPercentage`, ...), so only own properties of objects can
/// answer. `None` is `undefined`; a `null` or `undefined` base throws like V8.
pub fn get<'a>(base: Option<&'a Value>, name: &str) -> Result<Option<&'a Value>, JsError> {
    match base {
        None | Some(Value::Null) => Err(read_of_nullish(base, name)),
        Some(Value::Object(map)) => Ok(map.get(name)),
        Some(_) => Ok(None),
    }
}

/// JavaScript truthiness. `None` is `undefined`.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => {
            let double = number_value(number);
            double != 0.0 && !double.is_nan()
        }
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(_)) | Some(Value::Object(_)) => true,
    }
}

/// The double JavaScript holds for a JSON number. Integers beyond 2^53 round the
/// way `JSON.parse` rounds them.
pub fn number_value(number: &Number) -> f64 {
    number.as_f64().unwrap_or(f64::NAN)
}

/// `String(value)` (also a template literal's and `ToPropertyKey`'s conversion). `None`
/// is `undefined`.
///
/// An object converts through `OrdinaryToPrimitive`: its `toString`, else its
/// `valueOf`, whichever is callable and returns a primitive. A JSON object with its own
/// `toString` member (never callable) hides `Object.prototype.toString`, and the
/// inherited `valueOf` returns the object itself, so V8 throws.
pub fn to_string(value: Option<&Value>) -> Result<Cow<'_, str>, JsError> {
    Ok(match value {
        None => Cow::Borrowed("undefined"),
        Some(Value::Null) => Cow::Borrowed("null"),
        Some(Value::Bool(true)) => Cow::Borrowed("true"),
        Some(Value::Bool(false)) => Cow::Borrowed("false"),
        Some(Value::Number(number)) => Cow::Owned(number_to_string(number_value(number))),
        Some(Value::String(text)) => Cow::Borrowed(text),
        Some(Value::Array(items)) => Cow::Owned(array_join(items)?),
        Some(Value::Object(map)) if map.contains_key("toString") => return Err(not_primitive()),
        Some(Value::Object(_)) => Cow::Borrowed("[object Object]"),
    })
}

fn not_primitive() -> JsError {
    JsError("TypeError: Cannot convert object to primitive value".to_string())
}

/// `Number.prototype.toString()` including the non-finite spellings.
pub fn number_to_string(number: f64) -> String {
    if number.is_nan() {
        "NaN".to_string()
    } else if number.is_infinite() {
        if number > 0.0 { "Infinity" } else { "-Infinity" }.to_string()
    } else {
        js_json::number_to_string(number)
    }
}

/// `Array.prototype.join(",")`, which `String(array)` calls: `null` and `undefined`
/// elements become empty strings, everything else goes through `String`.
fn array_join(items: &[Value]) -> Result<String, JsError> {
    let mut out = String::new();
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        if !item.is_null() {
            out.push_str(&to_string(Some(item))?);
        }
    }
    Ok(out)
}

/// `ToNumber(value)`. `None` is `undefined`. Objects go through `valueOf` (which
/// returns the object) and then `toString`, so an own `toString` member throws.
pub fn to_number(value: Option<&Value>) -> Result<f64, JsError> {
    Ok(match value {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(flag)) => f64::from(u8::from(*flag)),
        Some(Value::Number(number)) => number_value(number),
        Some(Value::String(text)) => string_to_number(text),
        // Arrays convert through their join, objects through "[object Object]"
        Some(Value::Array(items)) => string_to_number(&array_join(items)?),
        Some(Value::Object(map)) if map.contains_key("toString") => return Err(not_primitive()),
        Some(Value::Object(_)) => f64::NAN,
    })
}

/// `Math.max(a, b)` for doubles: NaN wins, and +0 beats -0.
pub fn math_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_positive() || b.is_sign_positive() { 0.0 } else { -0.0 }
    } else if a > b {
        a
    } else {
        b
    }
}

/// `Math.min(a, b)` for doubles: NaN wins, and -0 beats +0.
pub fn math_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_negative() || b.is_sign_negative() { -0.0 } else { 0.0 }
    } else if a < b {
        a
    } else {
        b
    }
}

/// A double as `JSON.stringify` would write it: NaN and the infinities become `null`,
/// integral values are stored as integers so serde_json prints no fraction.
pub fn number_json(number: f64) -> Value {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    if !number.is_finite() {
        Value::Null
    } else if number.fract() == 0.0 && number.abs() <= MAX_SAFE_INTEGER {
        // -0 prints as 0 in JavaScript too
        Value::Number(Number::from(number as i64))
    } else {
        Number::from_f64(number).map_or(Value::Null, Value::Number)
    }
}

/// `String.prototype.trim` removes WhiteSpace and LineTerminator code points, a set
/// that differs from Rust's `char::is_whitespace` (U+FEFF in, U+0085 out).
pub fn is_js_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// `String.prototype.trim`.
pub fn trim(text: &str) -> &str {
    text.trim_matches(is_js_whitespace)
}

/// `StringToNumber`: trims, accepts `Infinity`, signed decimals with optional
/// fraction and exponent, and unsigned `0x`/`0o`/`0b` integers; the empty string is 0
/// and anything else is NaN.
pub fn string_to_number(text: &str) -> f64 {
    let text = trim(text);
    if text.is_empty() {
        return 0.0;
    }
    let bytes = text.as_bytes();
    if bytes.len() > 2 && bytes[0] == b'0' {
        let radix = match bytes[1] {
            b'x' | b'X' => Some(16),
            b'o' | b'O' => Some(8),
            b'b' | b'B' => Some(2),
            _ => None,
        };
        if let Some(radix) = radix {
            return radix_integer(&text[2..], radix);
        }
    }
    let (sign, unsigned) = match bytes[0] {
        b'+' => (1.0, &text[1..]),
        b'-' => (-1.0, &text[1..]),
        _ => (1.0, text),
    };
    if unsigned == "Infinity" {
        return sign * f64::INFINITY;
    }
    if !is_decimal_literal(unsigned) {
        return f64::NAN;
    }
    // The grammar is checked above; Rust's parser rounds correctly like V8's
    text.parse::<f64>().unwrap_or(f64::NAN)
}

/// StrUnsignedDecimalLiteral: digits with an optional fraction (at least one digit
/// overall) and an optional exponent.
fn is_decimal_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut digits = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
        digits += 1;
    }
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return false;
    }
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        index += 1;
        if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            index += 1;
        }
        let exponent_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == exponent_start {
            return false;
        }
    }
    index == bytes.len()
}

/// A `0x`/`0o`/`0b` literal body, rounded to the nearest double (ties to even) at any
/// length, like V8's `InternalStringToIntDouble`.
fn radix_integer(digits: &str, radix: u32) -> f64 {
    if digits.is_empty() {
        return f64::NAN;
    }
    let bits_per_digit = radix.trailing_zeros();
    let mut bits: Vec<bool> = Vec::with_capacity(digits.len() * bits_per_digit as usize);
    for character in digits.chars() {
        let Some(digit) = character.to_digit(radix) else {
            return f64::NAN;
        };
        bits.extend((0..bits_per_digit).rev().map(|shift| (digit >> shift) & 1 == 1));
    }
    let Some(first_one) = bits.iter().position(|bit| *bit) else {
        return 0.0;
    };
    let significant = &bits[first_one..];
    const MANTISSA_BITS: usize = 53;
    if significant.len() <= MANTISSA_BITS {
        return significant.iter().fold(0u64, |value, bit| value * 2 + u64::from(*bit)) as f64;
    }
    let mut mantissa = significant[..MANTISSA_BITS].iter().fold(0u64, |value, bit| value * 2 + u64::from(*bit));
    let half = significant[MANTISSA_BITS];
    let sticky = significant[MANTISSA_BITS + 1..].iter().any(|bit| *bit);
    if half && (sticky || mantissa & 1 == 1) {
        mantissa += 1;
    }
    let exponent = (significant.len() - MANTISSA_BITS) as i32;
    (mantissa as f64) * 2f64.powi(exponent)
}

/// The index an ECMAScript array index key names: the canonical decimal spelling of an
/// integer below 2^32 - 1. Objects list these keys first, in numeric order.
pub fn array_index(key: &str) -> Option<u32> {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > 10 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if bytes.len() > 1 && bytes[0] == b'0' {
        return None;
    }
    let value: u64 = key.parse().ok()?;
    (value < u64::from(u32::MAX)).then_some(value as u32)
}

/// Reorder every object the way a JavaScript object built from it orders its keys:
/// array index keys ascending, then the rest in insertion order. `JSON.parse` output
/// and anything Node later serialises follow that order.
pub fn order_keys_like_js(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(order_keys_like_js),
        Value::Object(map) => {
            map.values_mut().for_each(order_keys_like_js);
            order_map_keys_like_js(map);
        }
        _ => {}
    }
}

/// [`order_keys_like_js`] for one object level.
pub fn order_map_keys_like_js(map: &mut Map<String, Value>) {
    if !map.keys().any(|key| array_index(key).is_some()) {
        return;
    }
    let entries = std::mem::take(map);
    let (mut indexed, named): (Vec<_>, Vec<_>) = entries.into_iter().partition(|(key, _)| array_index(key).is_some());
    indexed.sort_by_key(|(key, _)| array_index(key));
    map.extend(indexed);
    map.extend(named);
}

/// `JSON.parse` with the key order a JavaScript object gets.
pub fn parse_json(text: &str) -> Result<Value, serde_json::Error> {
    let mut value: Value = serde_json::from_str(text)?;
    order_keys_like_js(&mut value);
    Ok(value)
}

/// What drizzle's `jsonb` column mapper hands Node for a value postgres-js already
/// parsed: a JSON string whose text is itself valid JSON is parsed a second time
/// (`"123"` becomes 123, `"{\"a\":1}"` an object); any other string stays a string.
pub fn drizzle_jsonb(value: Value) -> Value {
    if let Value::String(text) = &value
        && let Ok(parsed) = parse_json(text)
    {
        return parsed;
    }
    value
}

/// `String(container[key])` for a key chosen by data (a rule's query or trait key),
/// with `null` and `undefined` read as the empty string the way the evaluator's
/// `normalizeComparableValue` does. Keys missing from the value fall through to the
/// prototype chain: `traits.constructor` is the `Object` function, for example.
pub fn lookup_comparable(container: &Value, key: &str) -> Result<String, JsError> {
    Ok(match container {
        Value::Object(map) => match map.get(key) {
            Some(value) => comparable(Some(value))?,
            None if key == "__proto__" => "[object Object]".to_string(),
            None => inherited(OBJECT_PROTOTYPE, key),
        },
        Value::Array(items) => {
            if let Some(index) = array_index(key) {
                return match items.get(index as usize) {
                    Some(item) => comparable(Some(item)),
                    None => Ok(String::new()),
                };
            }
            match key {
                "length" => items.len().to_string(),
                // Array.prototype is itself an empty array
                "__proto__" => String::new(),
                _ => inherited(ARRAY_PROTOTYPE, key),
            }
        }
        Value::String(text) => {
            if let Some(index) = array_index(key) {
                // One UTF-16 code unit; a lone surrogate half cannot live in a Rust
                // string and reads as U+FFFD
                return Ok(text
                    .encode_utf16()
                    .nth(index as usize)
                    .map(|unit| char::decode_utf16([unit]).map(|decoded| decoded.unwrap_or('\u{fffd}')).collect())
                    .unwrap_or_default());
            }
            match key {
                "length" => js_json::utf16_len(text).to_string(),
                // String.prototype is a String wrapper around ""
                "__proto__" => String::new(),
                _ => inherited(STRING_PROTOTYPE, key),
            }
        }
        Value::Number(_) => match key {
            "__proto__" => "0".to_string(),
            _ => inherited(NUMBER_PROTOTYPE, key),
        },
        Value::Bool(_) => match key {
            "__proto__" => "false".to_string(),
            _ => inherited(BOOLEAN_PROTOTYPE, key),
        },
        // Callers never pass null (Node substitutes `{}`), and reading from it would throw
        Value::Null => String::new(),
    })
}

/// `normalizeComparableValue`: `null`/`undefined` become "", everything else `String()`.
pub fn comparable(value: Option<&Value>) -> Result<String, JsError> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        other => Ok(to_string(other)?.into_owned()),
    }
}

fn inherited(table: &[(&str, &str)], key: &str) -> String {
    table.iter().find(|(name, _)| *name == key).map(|(_, text)| (*text).to_string()).unwrap_or_default()
}

// Generated from Node 26.7.0: for every string-keyed property on the prototype chain
// of `{}`, `[]`, `""`, `0` and `false`, the text `String(sample[name])` produces.
/// `String(value[name])` for the properties a JSON object inherits (own `length` excluded).
const OBJECT_PROTOTYPE: &[(&str, &str)] = &[
    ("__defineGetter__", "function __defineGetter__() { [native code] }"),
    ("__defineSetter__", "function __defineSetter__() { [native code] }"),
    ("__lookupGetter__", "function __lookupGetter__() { [native code] }"),
    ("__lookupSetter__", "function __lookupSetter__() { [native code] }"),
    ("constructor", "function Object() { [native code] }"),
    ("hasOwnProperty", "function hasOwnProperty() { [native code] }"),
    ("isPrototypeOf", "function isPrototypeOf() { [native code] }"),
    ("propertyIsEnumerable", "function propertyIsEnumerable() { [native code] }"),
    ("toLocaleString", "function toLocaleString() { [native code] }"),
    ("toString", "function toString() { [native code] }"),
    ("valueOf", "function valueOf() { [native code] }"),
];

/// `String(value[name])` for the properties a JSON array inherits (own `length` excluded).
const ARRAY_PROTOTYPE: &[(&str, &str)] = &[
    ("__defineGetter__", "function __defineGetter__() { [native code] }"),
    ("__defineSetter__", "function __defineSetter__() { [native code] }"),
    ("__lookupGetter__", "function __lookupGetter__() { [native code] }"),
    ("__lookupSetter__", "function __lookupSetter__() { [native code] }"),
    ("at", "function at() { [native code] }"),
    ("concat", "function concat() { [native code] }"),
    ("constructor", "function Array() { [native code] }"),
    ("copyWithin", "function copyWithin() { [native code] }"),
    ("entries", "function entries() { [native code] }"),
    ("every", "function every() { [native code] }"),
    ("fill", "function fill() { [native code] }"),
    ("filter", "function filter() { [native code] }"),
    ("find", "function find() { [native code] }"),
    ("findIndex", "function findIndex() { [native code] }"),
    ("findLast", "function findLast() { [native code] }"),
    ("findLastIndex", "function findLastIndex() { [native code] }"),
    ("flat", "function flat() { [native code] }"),
    ("flatMap", "function flatMap() { [native code] }"),
    ("forEach", "function forEach() { [native code] }"),
    ("hasOwnProperty", "function hasOwnProperty() { [native code] }"),
    ("includes", "function includes() { [native code] }"),
    ("indexOf", "function indexOf() { [native code] }"),
    ("isPrototypeOf", "function isPrototypeOf() { [native code] }"),
    ("join", "function join() { [native code] }"),
    ("keys", "function keys() { [native code] }"),
    ("lastIndexOf", "function lastIndexOf() { [native code] }"),
    ("map", "function map() { [native code] }"),
    ("pop", "function pop() { [native code] }"),
    ("propertyIsEnumerable", "function propertyIsEnumerable() { [native code] }"),
    ("push", "function push() { [native code] }"),
    ("reduce", "function reduce() { [native code] }"),
    ("reduceRight", "function reduceRight() { [native code] }"),
    ("reverse", "function reverse() { [native code] }"),
    ("shift", "function shift() { [native code] }"),
    ("slice", "function slice() { [native code] }"),
    ("some", "function some() { [native code] }"),
    ("sort", "function sort() { [native code] }"),
    ("splice", "function splice() { [native code] }"),
    ("toLocaleString", "function toLocaleString() { [native code] }"),
    ("toReversed", "function toReversed() { [native code] }"),
    ("toSorted", "function toSorted() { [native code] }"),
    ("toSpliced", "function toSpliced() { [native code] }"),
    ("toString", "function toString() { [native code] }"),
    ("unshift", "function unshift() { [native code] }"),
    ("valueOf", "function valueOf() { [native code] }"),
    ("values", "function values() { [native code] }"),
    ("with", "function with() { [native code] }"),
];

/// `String(value[name])` for the properties a JSON string inherits (own `length` excluded).
const STRING_PROTOTYPE: &[(&str, &str)] = &[
    ("__defineGetter__", "function __defineGetter__() { [native code] }"),
    ("__defineSetter__", "function __defineSetter__() { [native code] }"),
    ("__lookupGetter__", "function __lookupGetter__() { [native code] }"),
    ("__lookupSetter__", "function __lookupSetter__() { [native code] }"),
    ("anchor", "function anchor() { [native code] }"),
    ("at", "function at() { [native code] }"),
    ("big", "function big() { [native code] }"),
    ("blink", "function blink() { [native code] }"),
    ("bold", "function bold() { [native code] }"),
    ("charAt", "function charAt() { [native code] }"),
    ("charCodeAt", "function charCodeAt() { [native code] }"),
    ("codePointAt", "function codePointAt() { [native code] }"),
    ("concat", "function concat() { [native code] }"),
    ("constructor", "function String() { [native code] }"),
    ("endsWith", "function endsWith() { [native code] }"),
    ("fixed", "function fixed() { [native code] }"),
    ("fontcolor", "function fontcolor() { [native code] }"),
    ("fontsize", "function fontsize() { [native code] }"),
    ("hasOwnProperty", "function hasOwnProperty() { [native code] }"),
    ("includes", "function includes() { [native code] }"),
    ("indexOf", "function indexOf() { [native code] }"),
    ("isPrototypeOf", "function isPrototypeOf() { [native code] }"),
    ("isWellFormed", "function isWellFormed() { [native code] }"),
    ("italics", "function italics() { [native code] }"),
    ("lastIndexOf", "function lastIndexOf() { [native code] }"),
    ("link", "function link() { [native code] }"),
    ("localeCompare", "function localeCompare() { [native code] }"),
    ("match", "function match() { [native code] }"),
    ("matchAll", "function matchAll() { [native code] }"),
    ("normalize", "function normalize() { [native code] }"),
    ("padEnd", "function padEnd() { [native code] }"),
    ("padStart", "function padStart() { [native code] }"),
    ("propertyIsEnumerable", "function propertyIsEnumerable() { [native code] }"),
    ("repeat", "function repeat() { [native code] }"),
    ("replace", "function replace() { [native code] }"),
    ("replaceAll", "function replaceAll() { [native code] }"),
    ("search", "function search() { [native code] }"),
    ("slice", "function slice() { [native code] }"),
    ("small", "function small() { [native code] }"),
    ("split", "function split() { [native code] }"),
    ("startsWith", "function startsWith() { [native code] }"),
    ("strike", "function strike() { [native code] }"),
    ("sub", "function sub() { [native code] }"),
    ("substr", "function substr() { [native code] }"),
    ("substring", "function substring() { [native code] }"),
    ("sup", "function sup() { [native code] }"),
    ("toLocaleLowerCase", "function toLocaleLowerCase() { [native code] }"),
    ("toLocaleString", "function toLocaleString() { [native code] }"),
    ("toLocaleUpperCase", "function toLocaleUpperCase() { [native code] }"),
    ("toLowerCase", "function toLowerCase() { [native code] }"),
    ("toString", "function toString() { [native code] }"),
    ("toUpperCase", "function toUpperCase() { [native code] }"),
    ("toWellFormed", "function toWellFormed() { [native code] }"),
    ("trim", "function trim() { [native code] }"),
    ("trimEnd", "function trimEnd() { [native code] }"),
    ("trimLeft", "function trimStart() { [native code] }"),
    ("trimRight", "function trimEnd() { [native code] }"),
    ("trimStart", "function trimStart() { [native code] }"),
    ("valueOf", "function valueOf() { [native code] }"),
];

/// `String(value[name])` for the properties a JSON number inherits (own `length` excluded).
const NUMBER_PROTOTYPE: &[(&str, &str)] = &[
    ("__defineGetter__", "function __defineGetter__() { [native code] }"),
    ("__defineSetter__", "function __defineSetter__() { [native code] }"),
    ("__lookupGetter__", "function __lookupGetter__() { [native code] }"),
    ("__lookupSetter__", "function __lookupSetter__() { [native code] }"),
    ("constructor", "function Number() { [native code] }"),
    ("hasOwnProperty", "function hasOwnProperty() { [native code] }"),
    ("isPrototypeOf", "function isPrototypeOf() { [native code] }"),
    ("propertyIsEnumerable", "function propertyIsEnumerable() { [native code] }"),
    ("toExponential", "function toExponential() { [native code] }"),
    ("toFixed", "function toFixed() { [native code] }"),
    ("toLocaleString", "function toLocaleString() { [native code] }"),
    ("toPrecision", "function toPrecision() { [native code] }"),
    ("toString", "function toString() { [native code] }"),
    ("valueOf", "function valueOf() { [native code] }"),
];

/// `String(value[name])` for the properties a JSON boolean inherits (own `length` excluded).
const BOOLEAN_PROTOTYPE: &[(&str, &str)] = &[
    ("__defineGetter__", "function __defineGetter__() { [native code] }"),
    ("__defineSetter__", "function __defineSetter__() { [native code] }"),
    ("__lookupGetter__", "function __lookupGetter__() { [native code] }"),
    ("__lookupSetter__", "function __lookupSetter__() { [native code] }"),
    ("constructor", "function Boolean() { [native code] }"),
    ("hasOwnProperty", "function hasOwnProperty() { [native code] }"),
    ("isPrototypeOf", "function isPrototypeOf() { [native code] }"),
    ("propertyIsEnumerable", "function propertyIsEnumerable() { [native code] }"),
    ("toLocaleString", "function toLocaleString() { [native code] }"),
    ("toString", "function toString() { [native code] }"),
    ("valueOf", "function valueOf() { [native code] }"),
];

#[cfg(test)]
mod tests {
    //! Expectations recorded from Node 26.7.0.

    use serde_json::json;

    use super::*;

    #[test]
    fn string_to_number_follows_the_ecmascript_grammar() {
        let cases: &[(&str, &str)] = &[
            (" 12 ", "12"),
            ("", "0"),
            ("0x10", "16"),
            ("0X1f", "31"),
            ("0b101", "5"),
            ("0o17", "15"),
            ("-0x10", "NaN"),
            ("1e3", "1000"),
            (".5", "0.5"),
            ("5.", "5"),
            (".", "NaN"),
            ("1e", "NaN"),
            ("Infinity", "Infinity"),
            ("-Infinity", "-Infinity"),
            ("+Infinity", "Infinity"),
            ("infinity", "NaN"),
            ("1_000", "NaN"),
            (" 12\u{feff}", "12"),
            ("12px", "NaN"),
            ("+.5e-3", "0.0005"),
            ("0x", "NaN"),
            ("00012", "12"),
            ("\u{85}1", "NaN"),
            ("0x1fffffffffffffffffffffffffffffffff", "1.0889035741470031e+40"),
        ];
        for (text, expected) in cases {
            assert_eq!(number_to_string(string_to_number(text)), *expected, "Number({text:?})");
        }
        assert!(string_to_number("-0").is_sign_negative());
    }

    #[test]
    fn conversions_follow_ordinary_to_primitive() {
        let cases = [
            (json!(null), Some("null"), Some("0")),
            (json!(true), Some("true"), Some("1")),
            (json!([]), Some(""), Some("0")),
            (json!([5]), Some("5"), Some("5")),
            (json!([1, [2, [3]], null]), Some("1,2,3,"), Some("NaN")),
            (json!({}), Some("[object Object]"), Some("NaN")),
            (json!({ "toString": 1 }), None, None),
            (json!({ "valueOf": 1 }), Some("[object Object]"), Some("NaN")),
            (json!([{ "toString": 1 }]), None, None),
            (json!("abc"), Some("abc"), Some("NaN")),
        ];
        for (value, string, number) in cases {
            assert_eq!(to_string(Some(&value)).ok().as_deref(), string, "String({value})");
            assert_eq!(to_number(Some(&value)).ok().map(number_to_string).as_deref(), number, "Number({value})");
        }
    }

    #[test]
    fn lookups_reach_the_prototype_chain() {
        let cases = [
            (json!({}), "constructor", "function Object() { [native code] }"),
            (json!({}), "__proto__", "[object Object]"),
            (json!({ "a": 1 }), "hasOwnProperty", "function hasOwnProperty() { [native code] }"),
            (json!(["x", "y"]), "1", "y"),
            (json!(["x", "y"]), "length", "2"),
            (json!(["x"]), "01", ""),
            (json!(["x"]), "__proto__", ""),
            (json!(["x"]), "map", "function map() { [native code] }"),
            (json!("hello"), "1", "e"),
            (json!("hello"), "length", "5"),
            (json!("hello"), "__proto__", ""),
            (json!("hello"), "trimLeft", "function trimStart() { [native code] }"),
            (json!(5), "toFixed", "function toFixed() { [native code] }"),
            (json!(5), "__proto__", "0"),
            (json!(true), "__proto__", "false"),
            (json!(true), "valueOf", "function valueOf() { [native code] }"),
        ];
        for (container, key, expected) in cases {
            assert_eq!(lookup_comparable(&container, key).unwrap(), expected, "{container}[{key:?}]");
        }
    }

    #[test]
    fn objects_list_array_index_keys_first() {
        let parsed =
            parse_json(r#"{"b":1,"10":2,"2":3,"-1":4,"a":5,"4294967294":6,"4294967295":7,"1.5":8,"0":9}"#).unwrap();
        let keys: Vec<&str> = parsed.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["0", "2", "10", "4294967294", "b", "-1", "a", "4294967295", "1.5"]);
    }

    #[test]
    fn drizzle_parses_json_strings_twice() {
        assert_eq!(drizzle_jsonb(json!("123")), json!(123));
        assert_eq!(drizzle_jsonb(json!("{\"a\":1}")), json!({ "a": 1 }));
        assert_eq!(drizzle_jsonb(json!("hello")), json!("hello"));
        assert_eq!(drizzle_jsonb(json!("\"123\"")), json!("123"));
        assert_eq!(drizzle_jsonb(json!([1])), json!([1]));
    }

    #[test]
    fn trim_uses_javascript_whitespace() {
        assert_eq!(trim("\u{feff}\u{a0} a \u{2028}"), "a");
        assert_eq!(trim("\u{85}a"), "\u{85}a");
    }
}
