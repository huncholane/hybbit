//! `new URLSearchParams(string)` as Node 26.7.0 implements it (lib/internal/url.js
//! `parseParams`), which is not the WHATWG algorithm: a name or value containing a
//! valid `%XX` goes through `querystring.unescape`, which tries `decodeURIComponent`
//! and, if that throws, decodes byte-wise with every UTF-16 code unit truncated to
//! its low byte (`querystring.unescapeBuffer`) before reading the bytes as UTF-8.

use serde_json::{Map, Value};

use super::js;

/// `parseQuery` from server/src/api/featureFlags/index.ts:
/// `Object.fromEntries(new URLSearchParams(querystring without a leading "?"))`.
/// A repeated name keeps its first position and its last value; the result has
/// JavaScript's key order.
pub fn parse_query(querystring: Option<&str>) -> Value {
    let mut entries = Map::new();
    let Some(querystring) = querystring.filter(|querystring| !querystring.is_empty()) else {
        return Value::Object(entries);
    };
    let querystring = querystring.strip_prefix('?').unwrap_or(querystring);
    let units: Vec<u16> = querystring.encode_utf16().collect();
    // `init ? parseParams(init) : []`
    if !units.is_empty() {
        for (name, value) in parse_params(&units) {
            entries.insert(name, Value::String(value));
        }
    }
    js::order_map_keys_like_js(&mut entries);
    Value::Object(entries)
}

const AMPERSAND: u16 = b'&' as u16;
const EQUAL: u16 = b'=' as u16;
const PLUS: u16 = b'+' as u16;
const PERCENT: u16 = b'%' as u16;
const QUESTION: u16 = b'?' as u16;

fn hex_value(unit: u16) -> Option<u8> {
    char::from_u32(u32::from(unit)).and_then(|character| character.to_digit(16)).map(|digit| digit as u8)
}

/// `parseParams(qs)`: name/value pairs in order.
pub fn parse_params(qs: &[u16]) -> Vec<(String, String)> {
    let mut out: Vec<String> = Vec::new();
    let mut seen_separator = false;
    let mut buffer: Vec<u16> = Vec::new();
    let mut encoded = false;
    let mut encode_check = 0;
    let mut index = usize::from(qs.first() == Some(&QUESTION));
    let mut pair_start = index;
    let mut last_position = index;

    let finish = |buffer: &mut Vec<u16>, encoded: bool| -> String {
        let text = if encoded { unescape(buffer) } else { String::from_utf16_lossy(buffer) };
        buffer.clear();
        text
    };

    while index < qs.len() {
        let code = qs[index];
        if code == AMPERSAND {
            if pair_start == index {
                // An empty substring between separators
                last_position = index + 1;
                pair_start = index + 1;
                index += 1;
                continue;
            }
            if last_position < index {
                buffer.extend_from_slice(&qs[last_position..index]);
            }
            out.push(finish(&mut buffer, encoded));
            if !seen_separator {
                out.push(String::new());
            }
            seen_separator = false;
            encoded = false;
            encode_check = 0;
            last_position = index + 1;
            pair_start = index + 1;
            index += 1;
            continue;
        }

        if !seen_separator && code == EQUAL {
            if last_position < index {
                buffer.extend_from_slice(&qs[last_position..index]);
            }
            out.push(finish(&mut buffer, encoded));
            seen_separator = true;
            encoded = false;
            encode_check = 0;
            last_position = index + 1;
            index += 1;
            continue;
        }

        if code == PLUS {
            if last_position < index {
                buffer.extend_from_slice(&qs[last_position..index]);
            }
            buffer.push(u16::from(b' '));
            last_position = index + 1;
        } else if !encoded {
            // Look for one valid %XX so plain text skips the decoders
            if code == PERCENT {
                encode_check = 1;
            } else if encode_check > 0 {
                if hex_value(code).is_some() {
                    encode_check += 1;
                    if encode_check == 3 {
                        encoded = true;
                    }
                } else {
                    encode_check = 0;
                }
            }
        }
        index += 1;
    }

    // A trailing `&` (or nothing at all) leaves no pair behind
    if pair_start != index {
        if last_position < index {
            buffer.extend_from_slice(&qs[last_position..index]);
        }
        out.push(finish(&mut buffer, encoded));
        if !seen_separator {
            out.push(String::new());
        }
    }

    let mut pairs = Vec::with_capacity(out.len() / 2);
    let mut items = out.into_iter();
    while let (Some(name), Some(value)) = (items.next(), items.next()) {
        pairs.push((name, value));
    }
    pairs
}

/// `querystring.unescape(s)`: `decodeURIComponent(s)`, or on URIError the byte-wise
/// `unescapeBuffer(s).toString()`.
fn unescape(units: &[u16]) -> String {
    decode_uri_component(units).unwrap_or_else(|| {
        let bytes = unescape_buffer(units);
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// `decodeURIComponent`, None where it throws a URIError.
fn decode_uri_component(units: &[u16]) -> Option<String> {
    let mut out: Vec<u16> = Vec::with_capacity(units.len());
    let percent_byte = |at: usize| -> Option<u8> {
        if units.get(at) != Some(&PERCENT) {
            return None;
        }
        Some(hex_value(*units.get(at + 1)?)? * 16 + hex_value(*units.get(at + 2)?)?)
    };
    let mut index = 0;
    while index < units.len() {
        if units[index] != PERCENT {
            out.push(units[index]);
            index += 1;
            continue;
        }
        let first = percent_byte(index)?;
        index += 3;
        if first < 0x80 {
            out.push(u16::from(first));
            continue;
        }
        let length = match first {
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => return None,
        };
        let mut bytes = vec![first];
        for _ in 1..length {
            let continuation = percent_byte(index)?;
            if continuation & 0xc0 != 0x80 {
                return None;
            }
            bytes.push(continuation);
            index += 3;
        }
        // Overlong forms, surrogates and values past U+10FFFF are not valid UTF-8
        let text = std::str::from_utf8(&bytes).ok()?;
        out.extend(text.encode_utf16());
    }
    String::from_utf16(&out).ok()
}

/// `querystring.unescapeBuffer(s)`: `%XX` decoded, everything else one byte per UTF-16
/// code unit (its low byte, as a Buffer store truncates).
fn unescape_buffer(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len());
    let max_length = units.len().saturating_sub(2);
    let mut index = 0;
    while index < units.len() {
        let mut current = units[index];
        if current == PERCENT && index < max_length {
            index += 1;
            current = units[index];
            match hex_value(current) {
                None => {
                    out.push(b'%');
                    continue;
                }
                Some(high) => {
                    index += 1;
                    match hex_value(units[index]) {
                        None => {
                            out.push(b'%');
                            index -= 1;
                        }
                        Some(low) => current = u16::from(high * 16 + low),
                    }
                }
            }
        }
        out.push(current as u8);
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn follows_node_url_search_params() {
        // Expectations recorded from Node 26.7.0
        assert_eq!(parse_query(None), json!({}));
        assert_eq!(parse_query(Some("")), json!({}));
        assert_eq!(parse_query(Some("??a=1")), json!({ "a": "1" }));
        assert_eq!(parse_query(Some("?a=1&b=%20x+y&a=2&c&=v")), json!({ "a": "2", "b": " x y", "c": "", "": "v" }));
        assert_eq!(serde_json::to_string(&parse_query(Some("b=1&2=x&1=y"))).unwrap(), r#"{"1":"y","2":"x","b":"1"}"#);
        assert_eq!(parse_query(Some("%C3\u{e9}")), json!({ "\u{fffd}\u{fffd}": "" }));
        assert_eq!(parse_query(Some("%C3?\u{1f600}")), json!({ "\u{fffd}?=\u{0}": "" }));
        assert_eq!(parse_query(Some("%41\u{e9}")), json!({ "A\u{e9}": "" }));
        assert_eq!(parse_query(Some("%zz\u{e9}")), json!({ "%zz\u{e9}": "" }));
    }
}
