//! `JSON.parse` and `JSON.stringify` over [`JsValue`].
//!
//! serde_json is close but not interchangeable for request input: it rejects
//! numbers outside the double range (JavaScript reads `1e400` as Infinity) and
//! lone surrogate escapes, and it does not order integer-like keys first. The
//! parser is iterative, like V8's, so hostile nesting cannot overflow the stack.

use super::{
    number::number_to_string,
    value::{JsObject, JsValue},
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Unexpected token in JSON at position {position}")]
pub struct JsonSyntaxError {
    /// Byte offset of the offending input
    pub position: usize,
}

enum Frame {
    Array(Vec<JsValue>),
    Object(JsObject, String),
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    position: usize,
}

impl<'a> Parser<'a> {
    fn error<T>(&self) -> Result<T, JsonSyntaxError> {
        Err(JsonSyntaxError { position: self.position })
    }

    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.position) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn expect_literal(&mut self, literal: &str) -> Result<(), JsonSyntaxError> {
        if self.text[self.position..].starts_with(literal) {
            self.position += literal.len();
            Ok(())
        } else {
            self.error()
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonSyntaxError> {
        // Caller checked the opening quote
        self.position += 1;
        let mut units: Vec<u16> = Vec::new();
        loop {
            let Some(byte) = self.peek() else { return self.error() };
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(String::from_utf16_lossy(&units));
                }
                b'\\' => {
                    self.position += 1;
                    let Some(escape) = self.peek() else { return self.error() };
                    self.position += 1;
                    let unit = match escape {
                        b'"' => 0x22,
                        b'\\' => 0x5C,
                        b'/' => 0x2F,
                        b'b' => 0x08,
                        b'f' => 0x0C,
                        b'n' => 0x0A,
                        b'r' => 0x0D,
                        b't' => 0x09,
                        b'u' => {
                            let Some(hex) = self.text.get(self.position..self.position + 4) else {
                                return self.error();
                            };
                            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                                return self.error();
                            }
                            self.position += 4;
                            u16::from_str_radix(hex, 16).map_err(|_| JsonSyntaxError { position: self.position })?
                        }
                        _ => {
                            self.position -= 1;
                            return self.error();
                        }
                    };
                    units.push(unit);
                }
                0x00..=0x1F => return self.error(),
                _ => {
                    let character = self.text[self.position..].chars().next().expect("peeked a byte");
                    let mut buffer = [0u16; 2];
                    units.extend_from_slice(character.encode_utf16(&mut buffer));
                    self.position += character.len_utf8();
                }
            }
        }
    }

    fn parse_number(&mut self) -> Result<f64, JsonSyntaxError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                while let Some(b'0'..=b'9') = self.peek() {
                    self.position += 1;
                }
            }
            _ => return self.error(),
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.error();
            }
            while let Some(b'0'..=b'9') = self.peek() {
                self.position += 1;
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.position += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.error();
            }
            while let Some(b'0'..=b'9') = self.peek() {
                self.position += 1;
            }
        }
        self.text[start..self.position]
            .parse::<f64>()
            .map_err(|_| JsonSyntaxError { position: start })
    }
}

/// `JSON.parse(text)`.
pub fn parse(text: &str) -> Result<JsValue, JsonSyntaxError> {
    let mut parser = Parser { bytes: text.as_bytes(), text, position: 0 };
    let mut stack: Vec<Frame> = Vec::new();

    'value: loop {
        parser.skip_whitespace();
        let mut value = match parser.peek() {
            Some(b'{') => {
                parser.position += 1;
                parser.skip_whitespace();
                if parser.peek() == Some(b'}') {
                    parser.position += 1;
                    JsValue::Object(JsObject::new())
                } else {
                    let key = parse_key(&mut parser)?;
                    stack.push(Frame::Object(JsObject::new(), key));
                    continue 'value;
                }
            }
            Some(b'[') => {
                parser.position += 1;
                parser.skip_whitespace();
                if parser.peek() == Some(b']') {
                    parser.position += 1;
                    JsValue::Array(Vec::new())
                } else {
                    stack.push(Frame::Array(Vec::new()));
                    continue 'value;
                }
            }
            Some(b'"') => JsValue::String(parser.parse_string()?),
            Some(b't') => {
                parser.expect_literal("true")?;
                JsValue::Bool(true)
            }
            Some(b'f') => {
                parser.expect_literal("false")?;
                JsValue::Bool(false)
            }
            Some(b'n') => {
                parser.expect_literal("null")?;
                JsValue::Null
            }
            Some(b'-' | b'0'..=b'9') => JsValue::Number(parser.parse_number()?),
            _ => return parser.error(),
        };

        // Fold the finished value into its containers
        loop {
            match stack.last_mut() {
                None => {
                    parser.skip_whitespace();
                    if parser.position != text.len() {
                        return parser.error();
                    }
                    return Ok(value);
                }
                Some(Frame::Array(items)) => {
                    items.push(value);
                    parser.skip_whitespace();
                    match parser.peek() {
                        Some(b',') => {
                            parser.position += 1;
                            continue 'value;
                        }
                        Some(b']') => {
                            parser.position += 1;
                            let Some(Frame::Array(items)) = stack.pop() else { unreachable!() };
                            value = JsValue::Array(items);
                        }
                        _ => return parser.error(),
                    }
                }
                Some(Frame::Object(object, key)) => {
                    object.insert(std::mem::take(key), value);
                    parser.skip_whitespace();
                    match parser.peek() {
                        Some(b',') => {
                            parser.position += 1;
                            parser.skip_whitespace();
                            *key = parse_key(&mut parser)?;
                            continue 'value;
                        }
                        Some(b'}') => {
                            parser.position += 1;
                            let Some(Frame::Object(object, _)) = stack.pop() else { unreachable!() };
                            value = JsValue::Object(object);
                        }
                        _ => return parser.error(),
                    }
                }
            }
        }
    }
}

/// `"key" :` with the parser on the opening quote.
fn parse_key(parser: &mut Parser<'_>) -> Result<String, JsonSyntaxError> {
    if parser.peek() != Some(b'"') {
        return parser.error();
    }
    let key = parser.parse_string()?;
    parser.skip_whitespace();
    if parser.peek() != Some(b':') {
        return parser.error();
    }
    parser.position += 1;
    Ok(key)
}

/// `JSON.stringify(value)`; `None` where JavaScript returns undefined.
pub fn stringify(value: &JsValue) -> Option<String> {
    let mut out = String::new();
    write_value(&mut out, value, None, 0).then_some(out)
}

/// `JSON.stringify(value, null, indent)`.
pub fn stringify_pretty(value: &JsValue, indent: usize) -> Option<String> {
    let mut out = String::new();
    let gap = " ".repeat(indent.min(10));
    write_value(&mut out, value, Some(&gap), 0).then_some(out)
}

fn newline(out: &mut String, gap: &str, depth: usize) {
    out.push('\n');
    for _ in 0..depth {
        out.push_str(gap);
    }
}

/// Returns false when the value serialises to nothing (undefined).
fn write_value(out: &mut String, value: &JsValue, gap: Option<&str>, depth: usize) -> bool {
    match value {
        JsValue::Undefined => return false,
        JsValue::Null => out.push_str("null"),
        JsValue::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        JsValue::Number(number) => {
            if number.is_finite() {
                out.push_str(&number_to_string(*number));
            } else {
                out.push_str("null");
            }
        }
        JsValue::String(text) => quote(out, text),
        JsValue::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return true;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                if let Some(gap) = gap {
                    newline(out, gap, depth + 1);
                }
                if !write_value(out, item, gap, depth + 1) {
                    out.push_str("null");
                }
            }
            if let Some(gap) = gap {
                newline(out, gap, depth);
            }
            out.push(']');
        }
        JsValue::Object(object) => {
            let mut wrote_any = false;
            out.push('{');
            for (key, item) in object.iter() {
                if item.is_undefined() {
                    continue;
                }
                if wrote_any {
                    out.push(',');
                }
                if let Some(gap) = gap {
                    newline(out, gap, depth + 1);
                }
                quote(out, key);
                out.push(':');
                if gap.is_some() {
                    out.push(' ');
                }
                write_value(out, item, gap, depth + 1);
                wrote_any = true;
            }
            if wrote_any && let Some(gap) = gap {
                newline(out, gap, depth);
            }
            out.push('}');
        }
    }
    true
}

/// QuoteJSONString.
pub fn quote(out: &mut String, text: &str) {
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
    use super::*;

    #[test]
    fn parses_like_json_parse() {
        let value = parse(r#" {"b":1,"2":[true,null,-0,1e400,"\ud83d\ude00\u0041"],"a":{},"b":2} "#).unwrap();
        assert_eq!(stringify(&value).unwrap(), r#"{"2":[true,null,0,null,"😀A"],"b":2,"a":{}}"#);
        for bad in ["", "[1,]", "{\"a\":1,}", "01", "1.", ".5", "[\"\t\"]", "'a'", "[1] x", "\u{feff}[]", "{a:1}", "\"\\x\""] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse("\"\\ud800\"").unwrap(), JsValue::String("\u{fffd}".into()));
    }

    #[test]
    fn deep_nesting_does_not_overflow() {
        let text = format!("{}{}", "[".repeat(5_000), "]".repeat(5_000));
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn pretty_matches_json_stringify() {
        let value = parse(r#"[{"code":"custom","path":["value",0],"keys":[],"o":{}}]"#).unwrap();
        assert_eq!(
            stringify_pretty(&value, 2).unwrap(),
            "[\n  {\n    \"code\": \"custom\",\n    \"path\": [\n      \"value\",\n      0\n    ],\n    \"keys\": [],\n    \"o\": {}\n  }\n]"
        );
    }
}
