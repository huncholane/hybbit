//! A port of `JSON.parse` for the tracking ingest path.
//!
//! serde_json is not used here because it disagrees with V8 on inputs Node accepts:
//! numbers that overflow (`1e400` is `Infinity` to JavaScript and passes
//! `z.number().min(0)`), lone surrogate escapes (`"\ud800"` is a valid JavaScript
//! string), and nesting deeper than serde_json's recursion limit. This parser is
//! iterative, so no input depth can overflow the stack, and it only materialises the
//! levels a caller reads: the tracking schema looks two levels deep, so deeper
//! containers are validated and then dropped rather than allocated for an attacker
//! (a level below the kept ones costs a few bytes of parser state).
//!
//! It also reports what `secure-json-parse` (Fastify's JSON body parser) rejects: an
//! own `__proto__` key anywhere, or a `constructor` key whose value is an object with
//! its own `prototype` key.

use indexmap::IndexMap;

use super::js::into_js_key_order;

#[derive(Clone, Debug, PartialEq)]
pub enum JsValue {
    Null,
    Bool(bool),
    /// Every JavaScript number is a double; overflow gives ±Infinity like V8
    Number(f64),
    /// Lone surrogate escapes, which Rust strings cannot hold, become U+FFFD
    /// (one UTF-16 unit either way, so string lengths still agree with Node)
    String(String),
    Array(Vec<JsValue>),
    /// Keys in JavaScript own-property order (array indices first); a repeated key
    /// keeps its first position and its last value, as `JSON.parse` does
    Object(IndexMap<String, JsValue>),
    /// An array deeper than the parse was asked to keep
    UnreadArray,
    /// An object deeper than the parse was asked to keep
    UnreadObject,
}

impl JsValue {
    /// zod's `getParsedType` names, used in "Expected X, received Y" messages.
    pub fn zod_type_name(&self) -> &'static str {
        match self {
            JsValue::Null => "null",
            JsValue::Bool(_) => "boolean",
            JsValue::Number(number) if number.is_nan() => "nan",
            JsValue::Number(_) => "number",
            JsValue::String(_) => "string",
            JsValue::Array(_) | JsValue::UnreadArray => "array",
            JsValue::Object(_) | JsValue::UnreadObject => "object",
        }
    }

    /// `typeof`
    pub fn type_of(&self) -> &'static str {
        match self {
            JsValue::Null | JsValue::Array(_) | JsValue::UnreadArray | JsValue::Object(_) | JsValue::UnreadObject => {
                "object"
            }
            JsValue::Bool(_) => "boolean",
            JsValue::Number(_) => "number",
            JsValue::String(_) => "string",
        }
    }

    /// JavaScript truthiness
    pub fn is_truthy(&self) -> bool {
        match self {
            JsValue::Null => false,
            JsValue::Bool(value) => *value,
            JsValue::Number(number) => *number != 0.0 && !number.is_nan(),
            JsValue::String(text) => !text.is_empty(),
            JsValue::Array(_) | JsValue::UnreadArray | JsValue::Object(_) | JsValue::UnreadObject => true,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsValue::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&IndexMap<String, JsValue>> {
        match self {
            JsValue::Object(entries) => Some(entries),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct JsonParse {
    pub value: JsValue,
    /// secure-json-parse would throw "Object contains forbidden prototype property"
    pub prototype_poisoned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonSyntaxError {
    pub position: usize,
}

/// `JSON.parse(text)`. Containers at a depth below `keep_depth` (the root is depth 0)
/// keep their contents; deeper ones are checked and returned as `Unread*`.
pub fn parse_json(text: &str, keep_depth: usize) -> Result<JsonParse, JsonSyntaxError> {
    Parser { bytes: text.as_bytes(), text, pos: 0, keep_depth, poisoned: false }.run()
}

/// A container the parse keeps.
enum Frame {
    Array(Vec<JsValue>),
    Object { entries: IndexMap<String, JsValue>, key: String, poison: ObjectPoison },
}

/// A container below `keep_depth`, reduced to what validation still needs.
#[derive(Clone, Copy)]
struct DeepFrame {
    object: bool,
    key: KeyKind,
    poison: ObjectPoison,
}

/// The member names secure-json-parse looks at.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Proto,
    Prototype,
    Constructor,
    Other,
}

impl KeyKind {
    fn of(key: &str) -> Self {
        match key {
            "__proto__" => KeyKind::Proto,
            "prototype" => KeyKind::Prototype,
            "constructor" => KeyKind::Constructor,
            _ => KeyKind::Other,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ObjectPoison {
    has_proto_key: bool,
    has_prototype_key: bool,
    /// The latest `constructor` value is an object with its own `prototype`
    constructor_poisoned: bool,
}

impl ObjectPoison {
    fn record(&mut self, key: KeyKind, value_is_object_with_prototype: bool) {
        match key {
            KeyKind::Proto => self.has_proto_key = true,
            KeyKind::Prototype => self.has_prototype_key = true,
            KeyKind::Constructor => self.constructor_poisoned = value_is_object_with_prototype,
            KeyKind::Other => {}
        }
    }

    fn is_poisoned(self) -> bool {
        self.has_proto_key || self.constructor_poisoned
    }
}

/// A finished value plus the one fact secure-json-parse needs from a child object.
struct Completed {
    value: JsValue,
    object_with_prototype_key: bool,
}

impl Completed {
    fn plain(value: JsValue) -> Self {
        Self { value, object_with_prototype_key: false }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
    keep_depth: usize,
    poisoned: bool,
}

impl Parser<'_> {
    fn error<T>(&self) -> Result<T, JsonSyntaxError> {
        Err(JsonSyntaxError { position: self.pos })
    }

    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.pos) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn run(mut self) -> Result<JsonParse, JsonSyntaxError> {
        let mut kept: Vec<Frame> = Vec::new();
        let mut deep: Vec<DeepFrame> = Vec::new();

        'value: loop {
            self.skip_whitespace();
            let depth = kept.len() + deep.len();
            let keep = depth < self.keep_depth;

            let mut completed = match self.peek() {
                Some(b'{') => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        Completed::plain(if keep { JsValue::Object(IndexMap::new()) } else { JsValue::UnreadObject })
                    } else {
                        let key = self.object_key()?;
                        if keep {
                            kept.push(Frame::Object { entries: IndexMap::new(), key, poison: ObjectPoison::default() });
                        } else {
                            let key = KeyKind::of(&key);
                            deep.push(DeepFrame { object: true, key, poison: ObjectPoison::default() });
                        }
                        continue 'value;
                    }
                }
                Some(b'[') => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        Completed::plain(if keep { JsValue::Array(Vec::new()) } else { JsValue::UnreadArray })
                    } else {
                        if keep {
                            kept.push(Frame::Array(Vec::new()));
                        } else {
                            deep.push(DeepFrame {
                                object: false,
                                key: KeyKind::Other,
                                poison: ObjectPoison::default(),
                            });
                        }
                        continue 'value;
                    }
                }
                Some(b'"') => {
                    self.pos += 1;
                    // A primitive is stored only when its container is kept
                    let text = self.string(depth <= self.keep_depth)?;
                    Completed::plain(JsValue::String(text))
                }
                Some(b't') => self.literal(b"true", JsValue::Bool(true))?,
                Some(b'f') => self.literal(b"false", JsValue::Bool(false))?,
                Some(b'n') => self.literal(b"null", JsValue::Null)?,
                Some(b'-' | b'0'..=b'9') => Completed::plain(JsValue::Number(self.number()?)),
                _ => return self.error(),
            };

            // Hand the finished value to its container, closing containers as they end
            loop {
                if let Some(frame) = deep.last_mut() {
                    self.skip_whitespace();
                    if frame.object {
                        frame.poison.record(frame.key, completed.object_with_prototype_key);
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                self.skip_whitespace();
                                frame.key = KeyKind::of(&self.object_key()?);
                                continue 'value;
                            }
                            Some(b'}') => {
                                self.pos += 1;
                                let poison = frame.poison;
                                deep.pop();
                                self.poisoned |= poison.is_poisoned();
                                completed = Completed {
                                    value: JsValue::UnreadObject,
                                    object_with_prototype_key: poison.has_prototype_key,
                                };
                            }
                            _ => return self.error(),
                        }
                    } else {
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                continue 'value;
                            }
                            Some(b']') => {
                                self.pos += 1;
                                deep.pop();
                                completed = Completed::plain(JsValue::UnreadArray);
                            }
                            _ => return self.error(),
                        }
                    }
                    continue;
                }

                let Some(frame) = kept.last_mut() else {
                    self.skip_whitespace();
                    if self.pos != self.bytes.len() {
                        return self.error();
                    }
                    return Ok(JsonParse { value: completed.value, prototype_poisoned: self.poisoned });
                };

                match frame {
                    Frame::Array(items) => {
                        items.push(completed.value);
                        self.skip_whitespace();
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                continue 'value;
                            }
                            Some(b']') => {
                                self.pos += 1;
                                let Some(Frame::Array(items)) = kept.pop() else { unreachable!() };
                                completed = Completed::plain(JsValue::Array(items));
                            }
                            _ => return self.error(),
                        }
                    }
                    Frame::Object { entries, key, poison } => {
                        poison.record(KeyKind::of(key), completed.object_with_prototype_key);
                        entries.insert(std::mem::take(key), completed.value);
                        self.skip_whitespace();
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                self.skip_whitespace();
                                *key = self.object_key()?;
                                continue 'value;
                            }
                            Some(b'}') => {
                                self.pos += 1;
                                let Some(Frame::Object { entries, poison, .. }) = kept.pop() else { unreachable!() };
                                self.poisoned |= poison.is_poisoned();
                                completed = Completed {
                                    value: JsValue::Object(into_js_key_order(entries)),
                                    object_with_prototype_key: poison.has_prototype_key,
                                };
                            }
                            _ => return self.error(),
                        }
                    }
                }
            }
        }
    }

    /// `"key"` followed by `:`; leaves the position at the value.
    fn object_key(&mut self) -> Result<String, JsonSyntaxError> {
        if self.peek() != Some(b'"') {
            return self.error();
        }
        self.pos += 1;
        let key = self.string(true)?;
        self.skip_whitespace();
        if self.peek() != Some(b':') {
            return self.error();
        }
        self.pos += 1;
        Ok(key)
    }

    fn literal(&mut self, word: &[u8], value: JsValue) -> Result<Completed, JsonSyntaxError> {
        if self.bytes[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(Completed::plain(value))
        } else {
            self.error()
        }
    }

    fn number(&mut self) -> Result<f64, JsonSyntaxError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return self.error(),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.error();
            }
            self.digits();
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.error();
            }
            self.digits();
        }
        // Rust's float parsing is correctly rounded and saturates to infinity, like V8
        self.text[start..self.pos].parse::<f64>().or_else(|_| self.error())
    }

    fn digits(&mut self) {
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
    }

    fn hex4(&self, at: usize) -> Option<u16> {
        let digits = self.bytes.get(at..at + 4)?;
        let text = std::str::from_utf8(digits).ok()?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(text, 16).ok()
    }

    /// The body of a string literal, after its opening quote. With `store` false the
    /// contents are only validated.
    fn string(&mut self, store: bool) -> Result<String, JsonSyntaxError> {
        let mut out = String::new();
        loop {
            let run_start = self.pos;
            while let Some(&byte) = self.bytes.get(self.pos) {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            if store {
                // Only ASCII delimiters end a run, so the slice is on char boundaries
                out.push_str(&self.text[run_start..self.pos]);
            }

            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let escaped = match self.peek() {
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'/') => '/',
                        Some(b'b') => '\u{0008}',
                        Some(b'f') => '\u{000C}',
                        Some(b'n') => '\n',
                        Some(b'r') => '\r',
                        Some(b't') => '\t',
                        Some(b'u') => {
                            let Some(unit) = self.hex4(self.pos + 1) else { return self.error() };
                            self.pos += 4;
                            match unit {
                                0xD800..=0xDBFF => {
                                    let low = (self.bytes.get(self.pos + 1..self.pos + 3) == Some(b"\\u"))
                                        .then(|| self.hex4(self.pos + 3))
                                        .flatten()
                                        .filter(|low| (0xDC00..=0xDFFF).contains(low));
                                    match low {
                                        Some(low) => {
                                            self.pos += 6;
                                            let code = 0x10000 + ((unit as u32 - 0xD800) << 10) + (low as u32 - 0xDC00);
                                            char::from_u32(code).unwrap_or('\u{FFFD}')
                                        }
                                        None => '\u{FFFD}',
                                    }
                                }
                                0xDC00..=0xDFFF => '\u{FFFD}',
                                _ => char::from_u32(unit as u32).unwrap_or('\u{FFFD}'),
                            }
                        }
                        _ => return self.error(),
                    };
                    self.pos += 1;
                    if store {
                        out.push(escaped);
                    }
                }
                // A raw control character, or the end of input inside the string
                _ => return self.error(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Option<JsValue> {
        parse_json(text, usize::MAX).ok().map(|parsed| parsed.value)
    }

    #[test]
    fn parses_the_json_grammar() {
        assert_eq!(parse(" [1, -0.5e1, true, false, null, \"a\\n\\u00e9\"] "), {
            Some(JsValue::Array(vec![
                JsValue::Number(1.0),
                JsValue::Number(-5.0),
                JsValue::Bool(true),
                JsValue::Bool(false),
                JsValue::Null,
                JsValue::String("a\né".into()),
            ]))
        });
        for invalid in [
            "",
            " ",
            "01",
            "1.",
            ".5",
            "+1",
            "[1,]",
            "{\"a\":1,}",
            "{'a':1}",
            "\"\t\"",
            "\u{FEFF}{}",
            "[1] x",
            "tru",
            "\"\\x\"",
            "[[1,]]",
            "[[{\"a\" 1}]]",
            "[[[",
        ] {
            assert!(parse(invalid).is_none(), "{invalid:?} must be rejected");
            assert!(parse_json(invalid, 0).is_err(), "{invalid:?} must be rejected unread");
        }
    }

    #[test]
    fn keeps_javascript_number_and_string_quirks() {
        assert_eq!(parse("1e400"), Some(JsValue::Number(f64::INFINITY)));
        assert_eq!(parse("123456789012345678901"), Some(JsValue::Number(123456789012345680000.0)));
        assert_eq!(parse("\"\\ud800x\\udc00\""), Some(JsValue::String("\u{FFFD}x\u{FFFD}".into())));
        assert_eq!(parse("\"\\ud83d\\ude00\""), Some(JsValue::String("😀".into())));
    }

    #[test]
    fn repeated_keys_keep_their_first_position_and_last_value() {
        let Some(JsValue::Object(entries)) = parse(r#"{"b":1,"a":2,"b":3,"1":4}"#) else { panic!() };
        assert_eq!(entries.keys().collect::<Vec<_>>(), ["1", "b", "a"]);
        assert_eq!(entries["b"], JsValue::Number(3.0));
    }

    #[test]
    fn survives_deep_nesting_and_skips_what_it_does_not_keep() {
        let deep = format!("{}{}", "[".repeat(1_000_000), "]".repeat(1_000_000));
        assert_eq!(
            parse_json(&deep, 2).unwrap().value,
            JsValue::Array(vec![JsValue::Array(vec![JsValue::UnreadArray])])
        );
        let objects = format!("{}1{}", r#"{"a":"#.repeat(500_000), "}".repeat(500_000));
        assert!(parse_json(&objects, 2).is_ok());
        let parsed = parse_json(r#"{"a":{"b":{"c":"d"}}}"#, 1).unwrap().value;
        assert_eq!(parsed.as_object().unwrap()["a"], JsValue::UnreadObject);
    }

    #[test]
    fn flags_prototype_poisoning_like_secure_json_parse() {
        for keep_depth in [0, 1, 2, usize::MAX] {
            let poisoned = |text: &str| parse_json(text, keep_depth).unwrap().prototype_poisoned;
            assert!(poisoned(r#"{"__proto__":{}}"#));
            assert!(poisoned(r#"[{"a":[{"\u005f_proto__":1}]}]"#));
            assert!(poisoned(r#"{"constructor":{"prototype":{}}}"#));
            assert!(poisoned(r#"[[{"x":{"constructor":{"a":1,"prototype":null}}}]]"#));
            assert!(!poisoned(r#"{"constructor":{"prototype":1},"constructor":2}"#));
            assert!(!poisoned(r#"{"constructor":[1],"prototype":1}"#));
            assert!(!poisoned(r#"{"constructor":{"a":{"prototype":1}}}"#));
            assert!(!poisoned(r#"{"a":"__proto__"}"#));
        }
    }
}
