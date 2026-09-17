//! A JavaScript value as the Node handlers see request input: what Fastify's
//! query-string parser and `JSON.parse` produce, with JavaScript's property order
//! and conversions.

use serde_json::{Map, Number, Value};

use super::number::{number_to_string, string_to_number};

#[derive(Clone, Debug, PartialEq)]
pub enum JsValue {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsValue>),
    Object(JsObject),
}

/// An ordinary object's own enumerable properties in `OrdinaryOwnPropertyKeys`
/// order: array-index keys ascending, then string keys in insertion order. The
/// order is observable (`for..in`, `Object.entries`, `JSON.stringify`), and zod
/// reports unrecognized keys in it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct JsObject {
    entries: Vec<(String, JsValue)>,
}

/// Canonical array index: "0" or a digit string without leading zeros, below 2^32 - 1.
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || key.len() > 10 || !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if key.len() > 1 && key.starts_with('0') {
        return None;
    }
    let value: u64 = key.parse().ok()?;
    (value < u32::MAX as u64).then_some(value as u32)
}

impl JsObject {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&JsValue> {
        self.entries.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    /// The property value, `undefined` when absent (property access on a plain
    /// object whose keys never collide with `Object.prototype`).
    pub fn get_or_undefined(&self, key: &str) -> &JsValue {
        const UNDEFINED: &JsValue = &JsValue::Undefined;
        self.get(key).unwrap_or(UNDEFINED)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(name, _)| name == key)
    }

    /// `CreateDataProperty`: an existing key keeps its position, a new array
    /// index is placed among the other indices, anything else is appended.
    pub fn insert(&mut self, key: impl Into<String>, value: JsValue) {
        let key = key.into();
        if let Some(slot) = self.entries.iter_mut().find(|(name, _)| *name == key) {
            slot.1 = value;
            return;
        }
        match array_index(&key) {
            Some(index) => {
                let position = self
                    .entries
                    .iter()
                    .position(|(name, _)| array_index(name).is_none_or(|other| other > index))
                    .unwrap_or(self.entries.len());
                self.entries.insert(position, (key, value));
            }
            None => self.entries.push((key, value)),
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<JsValue> {
        let position = self.entries.iter().position(|(name, _)| name == key)?;
        Some(self.entries.remove(position).1)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &JsValue)> {
        self.entries.iter().map(|(name, value)| (name.as_str(), value))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(name, _)| name.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl FromIterator<(String, JsValue)> for JsObject {
    fn from_iter<T: IntoIterator<Item = (String, JsValue)>>(iter: T) -> Self {
        let mut object = JsObject::new();
        for (key, value) in iter {
            object.insert(key, value);
        }
        object
    }
}

impl From<&str> for JsValue {
    fn from(value: &str) -> Self {
        JsValue::String(value.to_string())
    }
}

impl From<String> for JsValue {
    fn from(value: String) -> Self {
        JsValue::String(value)
    }
}

impl From<f64> for JsValue {
    fn from(value: f64) -> Self {
        JsValue::Number(value)
    }
}

impl From<bool> for JsValue {
    fn from(value: bool) -> Self {
        JsValue::Bool(value)
    }
}

impl JsValue {
    pub fn is_undefined(&self) -> bool {
        matches!(self, JsValue::Undefined)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsValue::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&JsObject> {
        match self {
            JsValue::Object(object) => Some(object),
            _ => None,
        }
    }

    /// `typeof`, with arrays and null reported as "object".
    pub fn type_of(&self) -> &'static str {
        match self {
            JsValue::Undefined => "undefined",
            JsValue::Null | JsValue::Array(_) | JsValue::Object(_) => "object",
            JsValue::Bool(_) => "boolean",
            JsValue::Number(_) => "number",
            JsValue::String(_) => "string",
        }
    }

    /// `ToBoolean`.
    pub fn is_truthy(&self) -> bool {
        match self {
            JsValue::Undefined | JsValue::Null => false,
            JsValue::Bool(value) => *value,
            JsValue::Number(number) => !(number.is_nan() || *number == 0.0),
            JsValue::String(text) => !text.is_empty(),
            JsValue::Array(_) | JsValue::Object(_) => true,
        }
    }

    /// `ToString` (arrays join their elements with commas, null and undefined
    /// elements printing as empty).
    pub fn to_js_string(&self) -> String {
        match self {
            JsValue::Undefined => "undefined".to_string(),
            JsValue::Null => "null".to_string(),
            JsValue::Bool(value) => value.to_string(),
            JsValue::Number(number) => number_to_string(*number),
            JsValue::String(text) => text.clone(),
            JsValue::Array(items) => items
                .iter()
                .map(|item| match item {
                    JsValue::Undefined | JsValue::Null => String::new(),
                    other => other.to_js_string(),
                })
                .collect::<Vec<_>>()
                .join(","),
            JsValue::Object(_) => "[object Object]".to_string(),
        }
    }

    /// `ToNumber`.
    pub fn to_number(&self) -> f64 {
        match self {
            JsValue::Undefined => f64::NAN,
            JsValue::Null => 0.0,
            JsValue::Bool(value) => f64::from(u8::from(*value)),
            JsValue::Number(number) => *number,
            JsValue::String(text) => string_to_number(text),
            JsValue::Array(_) => string_to_number(&self.to_js_string()),
            JsValue::Object(_) => f64::NAN,
        }
    }

    /// Converts JSON read by serde (a Postgres jsonb column, say) the way
    /// `JSON.parse` would have produced it. Numbers become doubles.
    pub fn from_serde(value: &Value) -> JsValue {
        match value {
            Value::Null => JsValue::Null,
            Value::Bool(flag) => JsValue::Bool(*flag),
            Value::Number(number) => JsValue::Number(number.as_f64().unwrap_or(f64::NAN)),
            Value::String(text) => JsValue::String(text.clone()),
            Value::Array(items) => JsValue::Array(items.iter().map(JsValue::from_serde).collect()),
            Value::Object(map) => {
                JsValue::Object(map.iter().map(|(key, item)| (key.clone(), JsValue::from_serde(item))).collect())
            }
        }
    }

    /// The value `JSON.parse(JSON.stringify(value))` would give, as serde JSON:
    /// undefined object members are dropped, undefined array items and
    /// non-finite numbers become null, integral doubles become integers.
    pub fn to_serde(&self) -> Value {
        match self {
            JsValue::Undefined | JsValue::Null => Value::Null,
            JsValue::Bool(flag) => Value::Bool(*flag),
            JsValue::Number(number) => number_to_serde(*number),
            JsValue::String(text) => Value::String(text.clone()),
            JsValue::Array(items) => Value::Array(items.iter().map(JsValue::to_serde).collect()),
            JsValue::Object(object) => {
                let mut map = Map::new();
                for (key, item) in object.iter() {
                    if !item.is_undefined() {
                        map.insert(key.to_string(), item.to_serde());
                    }
                }
                Value::Object(map)
            }
        }
    }
}

/// A double as serde JSON, integers kept integral so serde prints them without
/// a fraction.
pub fn number_to_serde(number: f64) -> Value {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    if !number.is_finite() {
        Value::Null
    } else if number.fract() == 0.0 && number.abs() <= MAX_SAFE_INTEGER {
        Value::Number(Number::from(number as i64))
    } else {
        Number::from_f64(number).map(Value::Number).unwrap_or(Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_order_puts_indices_first() {
        let mut object = JsObject::new();
        object.insert("b", JsValue::Null);
        object.insert("2", JsValue::Null);
        object.insert("a", JsValue::Null);
        object.insert("1", JsValue::Null);
        object.insert("01", JsValue::Null);
        object.insert("4294967295", JsValue::Null);
        object.insert("b", JsValue::Bool(true));
        assert_eq!(object.keys().collect::<Vec<_>>(), ["1", "2", "b", "a", "01", "4294967295"]);
        assert_eq!(object.get("b"), Some(&JsValue::Bool(true)));
    }

    #[test]
    fn conversions_follow_ecmascript() {
        let list = JsValue::Array(vec!["7".into(), JsValue::Null, 8.0.into()]);
        assert_eq!(list.to_js_string(), "7,,8");
        assert!(list.to_number().is_nan());
        assert_eq!(JsValue::Array(vec!["7".into()]).to_number(), 7.0);
        assert_eq!(JsValue::Array(vec![]).to_number(), 0.0);
        assert!(!JsValue::Number(f64::NAN).is_truthy());
        assert!(JsValue::Array(vec![]).is_truthy());
    }
}
