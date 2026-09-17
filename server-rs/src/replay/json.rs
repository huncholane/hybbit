//! `JSON.parse` and `JSON.stringify` for replay recordings, and the UTF-16 strings
//! JavaScript hands to them.
//!
//! Replay ingest stores `JSON.stringify(event.data)` for every rrweb event, and the
//! replay read route answers `JSON.parse(event_data)` re-serialised by Fastify. Both
//! are `JSON.stringify(JSON.parse(text))` of arbitrary client JSON, so the bytes in
//! ClickHouse (and `event_size_bytes`, a UTF-16 length) only match Node when every
//! V8 rule is kept:
//!
//! - numbers print as `Number.prototype.toString` (`1.0` is `1`, `1e21` is
//!   `1e+21`), and ones that overflow (`1e400`) are `null`;
//! - strings are re-escaped by QuoteJSONString: only `"`, `\`, control characters
//!   and *lone surrogates* are escaped, so `"\ud800"` survives as the six characters
//!   `\ud800` while `"\u00e9"` becomes a raw `é`;
//! - objects enumerate array-index keys first in ascending order, then the other
//!   keys in insertion order, and a repeated key keeps its first position with its
//!   last value.
//!
//! serde_json cannot do this (it rejects lone surrogates and `1e400`, and has no
//! JavaScript key order), and a tree of values would make both the parse and its
//! drop recursive, which a 10 MB body nested a million levels deep turns into a
//! stack overflow. The parse therefore writes a flat token tape (scalars already in
//! their `JSON.stringify` spelling) and serialisation walks it with an explicit
//! stack: both are iterative and linear in the input. Only objects that actually
//! need reordering pay for building their member list.

use std::collections::HashMap;

use crate::tracking::js::{is_array_index, is_js_whitespace};

/// A position `JSON.parse` would reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Unexpected token in JSON at position {position}")]
pub struct JsonSyntaxError {
    /// Byte offset of the offending input
    pub position: usize,
}

/// What a JSON value is, in zod's `getParsedType` vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Null,
    True,
    False,
    Number,
    String,
    Key,
    ArrayStart,
    ArrayEnd,
    ObjectStart,
    ObjectEnd,
}

/// Number flag: the literal overflowed to +Infinity (serialised as `null`)
const POSITIVE_INFINITY: u8 = 1;
/// Number flag: the literal overflowed to -Infinity
const NEGATIVE_INFINITY: u8 = 2;
/// Object flag: array-index or repeated keys, so members are not in source order
const REORDER: u8 = 1;

#[derive(Debug, Clone, Copy)]
struct Token {
    tag: Tag,
    flags: u8,
    /// Scalars and keys: start of their serialised text. Containers: the index of
    /// the matching end (on a start token) or start (on an end token).
    a: u32,
    /// Scalars and keys: end of their serialised text
    b: u32,
}

/// A parsed JSON document: tokens in document order plus the `JSON.stringify`
/// spelling of every scalar and key.
#[derive(Debug, Default)]
pub struct Tape {
    tokens: Vec<Token>,
    text: String,
}

/// A value inside a [`Tape`].
#[derive(Debug, Clone, Copy)]
pub struct Node<'a> {
    tape: &'a Tape,
    index: usize,
}

fn to_u32(value: usize, position: usize) -> Result<u32, JsonSyntaxError> {
    u32::try_from(value).map_err(|_| JsonSyntaxError { position })
}

/// `JSON.parse(text)` onto a tape.
pub fn parse(input: &str) -> Result<Tape, JsonSyntaxError> {
    let mut parser = Parser { input, bytes: input.as_bytes(), pos: 0, tape: Tape::default(), keys: Vec::new() };
    parser.run()?;
    Ok(parser.tape)
}

/// `JSON.stringify(JSON.parse(text))`.
pub fn canonicalize(input: &str) -> Result<String, JsonSyntaxError> {
    let tape = parse(input)?;
    let mut out = String::with_capacity(input.len());
    tape.root().write(&mut out);
    Ok(out)
}

/// An open container while parsing.
struct Open {
    start: usize,
    object: bool,
    /// Where this object's keys begin in `Parser::keys`
    keys_from: usize,
}

struct Parser<'a> {
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
    tape: Tape,
    /// Serialised key ranges of every open object, innermost last
    keys: Vec<(u32, u32)>,
}

impl Parser<'_> {
    fn error<T>(&self) -> Result<T, JsonSyntaxError> {
        Err(JsonSyntaxError { position: self.pos })
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.pos) {
            self.pos += 1;
        }
    }

    fn push_scalar(&mut self, tag: Tag, flags: u8, start: usize) -> Result<(), JsonSyntaxError> {
        let token = Token { tag, flags, a: to_u32(start, self.pos)?, b: to_u32(self.tape.text.len(), self.pos)? };
        self.tape.tokens.push(token);
        Ok(())
    }

    fn open(&mut self, tag: Tag) -> Result<usize, JsonSyntaxError> {
        let start = self.tape.tokens.len();
        to_u32(start, self.pos)?;
        self.tape.tokens.push(Token { tag, flags: 0, a: 0, b: 0 });
        Ok(start)
    }

    fn close(&mut self, start: usize, end_tag: Tag, flags: u8) -> Result<(), JsonSyntaxError> {
        let end = self.tape.tokens.len();
        let end_u32 = to_u32(end, self.pos)?;
        let start_token = &mut self.tape.tokens[start];
        start_token.a = end_u32;
        start_token.flags = flags;
        self.tape.tokens.push(Token { tag: end_tag, flags: 0, a: start as u32, b: 0 });
        Ok(())
    }

    fn run(&mut self) -> Result<(), JsonSyntaxError> {
        let mut stack: Vec<Open> = Vec::new();

        'value: loop {
            self.skip_whitespace();
            match self.peek() {
                Some(b'{') => {
                    self.pos += 1;
                    let start = self.open(Tag::ObjectStart)?;
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        self.close(start, Tag::ObjectEnd, 0)?;
                    } else {
                        stack.push(Open { start, object: true, keys_from: self.keys.len() });
                        self.key()?;
                        continue 'value;
                    }
                }
                Some(b'[') => {
                    self.pos += 1;
                    let start = self.open(Tag::ArrayStart)?;
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        self.close(start, Tag::ArrayEnd, 0)?;
                    } else {
                        stack.push(Open { start, object: false, keys_from: 0 });
                        continue 'value;
                    }
                }
                Some(b'"') => {
                    let start = self.tape.text.len();
                    self.string()?;
                    self.push_scalar(Tag::String, 0, start)?;
                }
                Some(b't') => self.literal("true", Tag::True)?,
                Some(b'f') => self.literal("false", Tag::False)?,
                Some(b'n') => self.literal("null", Tag::Null)?,
                Some(b'-' | b'0'..=b'9') => self.number()?,
                _ => return self.error(),
            }

            // The value is complete: hand it to its container, closing containers as they end
            loop {
                let Some(open) = stack.last() else {
                    self.skip_whitespace();
                    if self.pos != self.bytes.len() {
                        return self.error();
                    }
                    return Ok(());
                };
                self.skip_whitespace();
                if open.object {
                    match self.peek() {
                        Some(b',') => {
                            self.pos += 1;
                            self.skip_whitespace();
                            self.key()?;
                            continue 'value;
                        }
                        Some(b'}') => {
                            self.pos += 1;
                            let open = stack.pop().expect("an open object");
                            let flags = if self.needs_reorder(open.keys_from) { REORDER } else { 0 };
                            self.keys.truncate(open.keys_from);
                            self.close(open.start, Tag::ObjectEnd, flags)?;
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
                            let open = stack.pop().expect("an open array");
                            self.close(open.start, Tag::ArrayEnd, 0)?;
                        }
                        _ => return self.error(),
                    }
                }
            }
        }
    }

    /// Whether the object whose keys start at `keys_from` has an array-index key or
    /// a repeated key, either of which moves members out of source order.
    fn needs_reorder(&self, keys_from: usize) -> bool {
        let keys = &self.keys[keys_from..];
        let text = &self.tape.text;
        let name = |&(start, end): &(u32, u32)| &text[start as usize..end as usize];
        if keys.iter().any(|key| is_array_index(unquote_plain(name(key)))) {
            return true;
        }
        if keys.len() <= 16 {
            for (index, key) in keys.iter().enumerate() {
                if keys[..index].iter().any(|earlier| name(earlier) == name(key)) {
                    return true;
                }
            }
            false
        } else {
            let mut seen = std::collections::HashSet::with_capacity(keys.len());
            !keys.iter().all(|key| seen.insert(name(key)))
        }
    }

    /// `"key"` then `:`, leaving the position at the value.
    fn key(&mut self) -> Result<(), JsonSyntaxError> {
        if self.peek() != Some(b'"') {
            return self.error();
        }
        let start = self.tape.text.len();
        self.string()?;
        self.push_scalar(Tag::Key, 0, start)?;
        let range = (start as u32, self.tape.text.len() as u32);
        self.keys.push(range);
        self.skip_whitespace();
        if self.peek() != Some(b':') {
            return self.error();
        }
        self.pos += 1;
        Ok(())
    }

    fn literal(&mut self, word: &str, tag: Tag) -> Result<(), JsonSyntaxError> {
        if !self.input[self.pos..].starts_with(word) {
            return self.error();
        }
        self.pos += word.len();
        let start = self.tape.text.len();
        self.tape.text.push_str(word);
        self.push_scalar(tag, 0, start)
    }

    fn digits(&mut self) {
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
    }

    fn number(&mut self) -> Result<(), JsonSyntaxError> {
        let literal_start = self.pos;
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
        let value: f64 = self.input[literal_start..self.pos].parse().or_else(|_| self.error())?;
        let start = self.tape.text.len();
        let flags = if value.is_finite() {
            self.tape.text.push_str(ryu_js::Buffer::new().format(value));
            0
        } else {
            self.tape.text.push_str("null");
            if value > 0.0 { POSITIVE_INFINITY } else { NEGATIVE_INFINITY }
        };
        self.push_scalar(Tag::Number, flags, start)
    }

    fn hex4(&self, at: usize) -> Option<u16> {
        let digits = self.bytes.get(at..at + 4)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u16::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
    }

    /// A string literal at its opening quote, written to the text buffer as
    /// QuoteJSONString would write the parsed string.
    fn string(&mut self) -> Result<(), JsonSyntaxError> {
        self.pos += 1;
        self.tape.text.push('"');
        loop {
            let run_start = self.pos;
            while let Some(&byte) = self.bytes.get(self.pos) {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // Only ASCII delimiters end a run, so the slice is on char boundaries, and
            // nothing in it needs escaping again
            self.tape.text.push_str(&self.input[run_start..self.pos]);

            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    self.tape.text.push('"');
                    return Ok(());
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let out = &mut self.tape.text;
                    match self.bytes.get(self.pos) {
                        Some(b'"') => out.push_str("\\\""),
                        Some(b'\\') => out.push_str("\\\\"),
                        Some(b'/') => out.push('/'),
                        Some(b'b') => out.push_str("\\b"),
                        Some(b'f') => out.push_str("\\f"),
                        Some(b'n') => out.push_str("\\n"),
                        Some(b'r') => out.push_str("\\r"),
                        Some(b't') => out.push_str("\\t"),
                        Some(b'u') => {
                            let Some(unit) = self.hex4(self.pos + 1) else { return self.error() };
                            self.pos += 4;
                            let low = (0xD800..=0xDBFF)
                                .contains(&unit)
                                .then(|| {
                                    (self.bytes.get(self.pos + 1..self.pos + 3) == Some(b"\\u"))
                                        .then(|| self.hex4(self.pos + 3))
                                        .flatten()
                                })
                                .flatten()
                                .filter(|low| (0xDC00..=0xDFFF).contains(low));
                            let out = &mut self.tape.text;
                            match low {
                                Some(low) => {
                                    self.pos += 6;
                                    let code = 0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                                    out.push(char::from_u32(code).expect("a surrogate pair is a scalar value"));
                                }
                                None => push_quoted_unit(out, unit),
                            }
                        }
                        _ => return self.error(),
                    }
                    self.pos += 1;
                }
                // A raw control character, or the end of input inside the string
                _ => return self.error(),
            }
        }
    }
}

/// One UTF-16 unit that is not part of a pair, as QuoteJSONString writes it.
fn push_quoted_unit(out: &mut String, unit: u16) {
    match char::from_u32(u32::from(unit)) {
        Some(character) => push_quoted_char(out, character),
        // A lone surrogate: `\u` and four lowercase hex digits
        None => out.push_str(&format!("\\u{unit:04x}")),
    }
}

/// One character inside a JSON string, as QuoteJSONString writes it.
fn push_quoted_char(out: &mut String, character: char) {
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

/// The contents of a serialised key that has no escapes (all an array index can be).
fn unquote_plain(quoted: &str) -> &str {
    &quoted[1..quoted.len() - 1]
}

/// One step of serialisation.
enum Frame {
    /// A container whose members are written in tape order
    InOrder { next: usize, end: usize, object: bool, first: bool },
    /// An object whose members were reordered: (key token, value token) pairs
    Reordered { members: Vec<(usize, usize)>, position: usize },
}

impl Tape {
    pub fn root(&self) -> Node<'_> {
        Node { tape: self, index: 0 }
    }

    fn slice(&self, token: Token) -> &str {
        &self.text[token.a as usize..token.b as usize]
    }

    /// The token after the value starting at `index`.
    fn value_end(&self, index: usize) -> usize {
        match self.tokens[index].tag {
            Tag::ArrayStart | Tag::ObjectStart => self.tokens[index].a as usize + 1,
            _ => index + 1,
        }
    }

    /// Members of the object at `start` in JavaScript property order, repeated keys
    /// collapsed onto their first position with their last value.
    fn ordered_members(&self, start: usize) -> Vec<(usize, usize)> {
        let end = self.tokens[start].a as usize;
        let mut members: Vec<(usize, usize)> = Vec::new();
        let mut positions: HashMap<&str, usize> = HashMap::new();
        let mut cursor = start + 1;
        while cursor < end {
            let (key, value) = (cursor, cursor + 1);
            cursor = self.value_end(value);
            match positions.get(self.slice(self.tokens[key])) {
                Some(&position) => members[position].1 = value,
                None => {
                    positions.insert(self.slice(self.tokens[key]), members.len());
                    members.push((key, value));
                }
            }
        }
        let array_index = |key: usize| {
            let name = unquote_plain(self.slice(self.tokens[key]));
            is_array_index(name).then(|| name.parse::<u64>().unwrap_or(u64::MAX))
        };
        let (mut indices, named): (Vec<_>, Vec<_>) = members.into_iter().partition(|(key, _)| array_index(*key).is_some());
        indices.sort_by_key(|(key, _)| array_index(*key));
        indices.extend(named);
        indices
    }

    /// Writes one value, pushing a frame when it is a container.
    fn open_value(&self, index: usize, out: &mut String, stack: &mut Vec<Frame>) {
        let token = self.tokens[index];
        match token.tag {
            Tag::ArrayStart => {
                out.push('[');
                stack.push(Frame::InOrder { next: index + 1, end: token.a as usize, object: false, first: true });
            }
            Tag::ObjectStart if token.flags & REORDER != 0 => {
                out.push('{');
                stack.push(Frame::Reordered { members: self.ordered_members(index), position: 0 });
            }
            Tag::ObjectStart => {
                out.push('{');
                stack.push(Frame::InOrder { next: index + 1, end: token.a as usize, object: true, first: true });
            }
            _ => out.push_str(self.slice(token)),
        }
    }

    fn write_from(&self, index: usize, out: &mut String) {
        let mut stack: Vec<Frame> = Vec::new();
        self.open_value(index, out, &mut stack);
        loop {
            let next_value = match stack.last_mut() {
                None => return,
                Some(Frame::InOrder { next, end, object, first }) => {
                    if *next == *end {
                        out.push(if *object { '}' } else { ']' });
                        stack.pop();
                        continue;
                    }
                    if !*first {
                        out.push(',');
                    }
                    *first = false;
                    let mut value = *next;
                    if *object {
                        out.push_str(self.slice(self.tokens[value]));
                        out.push(':');
                        value += 1;
                    }
                    *next = self.value_end(value);
                    value
                }
                Some(Frame::Reordered { members, position }) => {
                    if *position == members.len() {
                        out.push('}');
                        stack.pop();
                        continue;
                    }
                    if *position > 0 {
                        out.push(',');
                    }
                    let (key, value) = members[*position];
                    *position += 1;
                    out.push_str(self.slice(self.tokens[key]));
                    out.push(':');
                    value
                }
            };
            self.open_value(next_value, out, &mut stack);
        }
    }
}

impl<'a> Node<'a> {
    pub fn kind(&self) -> Kind {
        match self.tape.tokens[self.index].tag {
            Tag::Null => Kind::Null,
            Tag::True | Tag::False => Kind::Boolean,
            Tag::Number => Kind::Number,
            Tag::String | Tag::Key => Kind::String,
            Tag::ArrayStart | Tag::ArrayEnd => Kind::Array,
            Tag::ObjectStart | Tag::ObjectEnd => Kind::Object,
        }
    }

    /// `JSON.stringify(value)` appended to `out`.
    pub fn write(&self, out: &mut String) {
        self.tape.write_from(self.index, out);
    }

    /// `JSON.stringify(value)`.
    pub fn stringify(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// The number a Number node holds (overflowed literals are ±Infinity).
    pub fn as_number(&self) -> Option<f64> {
        let token = self.tape.tokens[self.index];
        if token.tag != Tag::Number {
            return None;
        }
        Some(match token.flags {
            POSITIVE_INFINITY => f64::INFINITY,
            NEGATIVE_INFINITY => f64::NEG_INFINITY,
            // The shortest round-trip spelling parses back to the same double
            _ => self.tape.slice(token).parse().unwrap_or(f64::NAN),
        })
    }

    /// The string a String node holds, UTF-16 exact.
    pub fn as_js_string(&self) -> Option<JsString> {
        let token = self.tape.tokens[self.index];
        (token.tag == Tag::String).then(|| JsString::from_quoted(self.tape.slice(token)))
    }

    /// The elements of an array, in order.
    pub fn elements(&self) -> Vec<Node<'a>> {
        let token = self.tape.tokens[self.index];
        if token.tag != Tag::ArrayStart {
            return Vec::new();
        }
        let mut elements = Vec::new();
        let mut cursor = self.index + 1;
        while cursor < token.a as usize {
            elements.push(Node { tape: self.tape, index: cursor });
            cursor = self.tape.value_end(cursor);
        }
        elements
    }

    /// `object[name]` for a plain ASCII name: the last value given for the key.
    pub fn member(&self, name: &str) -> Option<Node<'a>> {
        let token = self.tape.tokens[self.index];
        if token.tag != Tag::ObjectStart {
            return None;
        }
        let mut found = None;
        let mut cursor = self.index + 1;
        while cursor < token.a as usize {
            let key = self.tape.slice(self.tape.tokens[cursor]);
            if key.len() == name.len() + 2 && unquote_plain(key) == name {
                found = Some(Node { tape: self.tape, index: cursor + 1 });
            }
            cursor = self.tape.value_end(cursor + 1);
        }
        found
    }
}

/// A JavaScript string: UTF-16 code units, lone surrogates included. Rust strings
/// cannot hold those, and Node writes them to ClickHouse as `\udXXX` escapes, so
/// values that reach a row keep their exact units until they are serialised.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JsString(Vec<u16>);

impl JsString {
    #[cfg(test)]
    pub fn from_units(units: Vec<u16>) -> Self {
        Self(units)
    }

    /// Decodes a string already in QuoteJSONString form (what the tape stores).
    fn from_quoted(quoted: &str) -> Self {
        let inner = unquote_plain(quoted);
        let mut units = Vec::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(character) = chars.next() {
            if character != '\\' {
                let mut buffer = [0u16; 2];
                units.extend_from_slice(character.encode_utf16(&mut buffer));
                continue;
            }
            let unit = match chars.next() {
                Some('"') => 0x22,
                Some('\\') => 0x5C,
                Some('b') => 0x08,
                Some('f') => 0x0C,
                Some('n') => 0x0A,
                Some('r') => 0x0D,
                Some('t') => 0x09,
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    u16::from_str_radix(&hex, 16).unwrap_or(0xFFFD)
                }
                _ => 0xFFFD,
            };
            units.push(unit);
        }
        Self(units)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `string.length`
    #[cfg(test)]
    pub fn utf16_len(&self) -> usize {
        self.0.len()
    }

    /// The string with each lone surrogate as U+FFFD: what Node's UTF-8 encoders
    /// (hashing, Redis keys, the URL parser's USVString conversion) see.
    pub fn to_lossy(&self) -> String {
        String::from_utf16_lossy(&self.0)
    }

    /// `String.prototype.trim`
    pub fn trim(&self) -> JsString {
        let is_space = |unit: &u16| char::from_u32(u32::from(*unit)).is_some_and(is_js_whitespace);
        let start = self.0.iter().position(|unit| !is_space(unit)).unwrap_or(self.0.len());
        let end = self.0.iter().rposition(|unit| !is_space(unit)).map_or(start, |last| last + 1);
        JsString(self.0[start..end].to_vec())
    }

    /// `JSON.stringify(string)` appended to `out`.
    pub fn write_quoted(&self, out: &mut String) {
        out.push('"');
        for decoded in char::decode_utf16(self.0.iter().copied()) {
            match decoded {
                Ok(character) => push_quoted_char(out, character),
                Err(lone) => push_quoted_unit(out, lone.unpaired_surrogate()),
            }
        }
        out.push('"');
    }

    /// `JSON.stringify(string)`
    #[cfg(test)]
    pub fn quoted(&self) -> String {
        let mut out = String::with_capacity(self.0.len() + 2);
        self.write_quoted(&mut out);
        out
    }
}

impl From<&str> for JsString {
    fn from(text: &str) -> Self {
        Self(text.encode_utf16().collect())
    }
}

/// `JSON.stringify` of a Rust string (no lone surrogates possible).
pub fn quote_str(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        push_quoted_char(out, character);
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(text: &str) -> String {
        canonicalize(text).unwrap_or_else(|error| panic!("{text:?} failed: {error}"))
    }

    #[test]
    fn rewrites_like_json_stringify_of_json_parse() {
        assert_eq!(roundtrip(r#" { "a" : [ 1.0 , -0 , 1e21 , 5e-7 , 1e400 , -1e400 , true , null ] } "#), r#"{"a":[1,0,1e+21,5e-7,null,null,true,null]}"#);
        assert_eq!(roundtrip(r#""\u00e9\/\u0001\b\f\n\r\t\"\\\u2028""#), "\"é/\\u0001\\b\\f\\n\\r\\t\\\"\\\\\u{2028}\"");
        assert_eq!(roundtrip(r#"123456789012345678901"#), "123456789012345680000");
        assert_eq!(roundtrip("[]"), "[]");
        assert_eq!(roundtrip("{}"), "{}");
        assert_eq!(roundtrip("[[],{},[{}]]"), "[[],{},[{}]]");
    }

    #[test]
    fn keeps_lone_surrogates_as_escapes() {
        assert_eq!(roundtrip(r#""\ud800""#), r#""\ud800""#);
        assert_eq!(roundtrip(r#""\uDC00x\uD83D""#), r#""\udc00x\ud83d""#);
        assert_eq!(roundtrip(r#""\ud83d\ude00""#), "\"\u{1F600}\"");
        assert_eq!(roundtrip(r#""\ud83d\ud83d\ude00""#), "\"\\ud83d\u{1F600}\"");
        assert_eq!(roundtrip(r#"{"\ud800":1,"\ufffd":2}"#), "{\"\\ud800\":1,\"\u{FFFD}\":2}");
    }

    #[test]
    fn orders_keys_like_v8() {
        assert_eq!(roundtrip(r#"{"b":1,"a":2,"b":3}"#), r#"{"b":3,"a":2}"#);
        assert_eq!(roundtrip(r#"{"b":1,"2":2,"a":3,"1":4,"01":5,"4294967295":6,"4294967294":7}"#), r#"{"1":4,"2":2,"4294967294":7,"b":1,"a":3,"01":5,"4294967295":6}"#);
        assert_eq!(roundtrip(r#"{"x":{"1":1,"0":0},"x":[{"a":1,"a":{"c":1,"c":2}}]}"#), r#"{"x":[{"a":{"c":2}}]}"#);
        assert_eq!(roundtrip(r#"{"\u0031":1,"0":0}"#), r#"{"0":0,"1":1}"#);
    }

    #[test]
    fn rejects_what_json_parse_rejects() {
        for invalid in ["", " ", "01", "1.", ".5", "+1", "[1,]", "{\"a\":1,}", "{'a':1}", "\"\t\"", "[1] x", "tru", "\"\\x\"", "[", "{\"a\"}", "\"\\u12\"", "\u{FEFF}1"] {
            assert!(canonicalize(invalid).is_err(), "{invalid:?} must be rejected");
        }
    }

    #[test]
    fn survives_deep_nesting() {
        let depth = 1_000_000;
        let arrays = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(roundtrip(&arrays), arrays);
        let objects = format!("{}1{}", r#"{"0":1,"a":"#.repeat(depth / 10), "}".repeat(depth / 10));
        assert_eq!(roundtrip(&objects), objects);
    }

    #[test]
    fn navigates_members_and_elements() {
        let tape = parse(r#"{"events":[{"type":2,"data":{"b":1}},"x"],"events":[{"type":"a\u0000","timestamp":1e400}],"u":"\ud800 "}"#).unwrap();
        let root = tape.root();
        let events = root.member("events").unwrap().elements();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].member("type").unwrap().as_js_string().unwrap().quoted(), r#""a\u0000""#);
        assert_eq!(events[0].member("timestamp").unwrap().as_number(), Some(f64::INFINITY));
        assert!(events[0].member("data").is_none());
        let user = root.member("u").unwrap().as_js_string().unwrap();
        assert_eq!(user.utf16_len(), 2);
        assert_eq!(user.trim().quoted(), r#""\ud800""#);
        assert_eq!(user.to_lossy(), "\u{FFFD} ");
    }

    #[test]
    fn trims_javascript_whitespace() {
        let text = JsString::from("\u{FEFF}\t a b \u{3000}\n");
        assert_eq!(text.trim(), JsString::from("a b"));
        assert_eq!(JsString::from("   ").trim(), JsString::default());
    }

    /// Differential fixture: inputs and `JSON.stringify(JSON.parse(input))` from
    /// Node, generated by parity/replay/gen_canonical.mjs.
    #[test]
    fn matches_node_on_generated_documents() {
        let fixture = include_str!("testdata/canonical.json");
        let cases: Vec<(String, Option<String>)> = serde_json::from_str(fixture).expect("fixture parses");
        assert!(cases.len() > 100);
        for (input, expected) in cases {
            assert_eq!(canonicalize(&input).ok(), expected, "input {input:?}");
        }
    }
}
