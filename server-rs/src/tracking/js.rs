//! The handful of JavaScript string semantics the tracking code leans on: `trim`,
//! `length` in UTF-16 code units, own-property key order, and the latin1 view Node
//! gives of header bytes. Porting them once keeps the call sites reading like Node.

use indexmap::IndexMap;

/// `String.prototype.trim` whitespace: WhiteSpace plus LineTerminator. Differs from
/// Rust's `char::is_whitespace` (which adds U+0085 and lacks U+FEFF).
pub fn is_js_whitespace(c: char) -> bool {
    const SPACES: [char; 13] = [
        '\u{0009}', '\u{000A}', '\u{000B}', '\u{000C}', '\u{000D}', '\u{0020}', '\u{00A0}', '\u{1680}', '\u{2028}',
        '\u{2029}', '\u{202F}', '\u{205F}', '\u{3000}',
    ];
    SPACES.contains(&c) || ('\u{2000}'..='\u{200A}').contains(&c) || c == '\u{FEFF}'
}

/// `String.prototype.trim`
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_whitespace)
}

/// `String.prototype.trimStart`
pub fn js_trim_start(text: &str) -> &str {
    text.trim_start_matches(is_js_whitespace)
}

/// `String.prototype.trimEnd`
pub fn js_trim_end(text: &str) -> &str {
    text.trim_end_matches(is_js_whitespace)
}

/// `string.length`: UTF-16 code units, which is what zod's `.min()`/`.max()` count.
pub fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// Whether a property key is an ECMAScript array index (a canonical decimal integer
/// below 2^32 - 1). Such keys enumerate before every other key, in numeric order.
pub fn is_array_index(key: &str) -> bool {
    if key.is_empty() || key.len() > 10 || !key.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if key.len() > 1 && key.starts_with('0') {
        return false;
    }
    key.parse::<u64>().is_ok_and(|index| index < u32::MAX as u64)
}

/// Reorders a map built in insertion order into JavaScript's own-property order:
/// array-index keys ascending, then the rest as inserted (`Object.keys`, `for...in`).
pub fn into_js_key_order<V>(map: IndexMap<String, V>) -> IndexMap<String, V> {
    if !map.keys().any(|key| is_array_index(key)) {
        return map;
    }
    let (mut indices, named): (Vec<_>, Vec<_>) = map.into_iter().partition(|(key, _)| is_array_index(key));
    indices.sort_by_key(|(key, _)| key.parse::<u64>().unwrap_or(u64::MAX));
    indices.into_iter().chain(named).collect()
}

/// Node decodes header values as latin1, one char per byte, so nothing is lost or
/// rejected the way `HeaderValue::to_str` would.
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

/// `String.prototype.toLowerCase` (full Unicode mapping, final sigma included).
pub fn js_to_lower(text: &str) -> String {
    if text.is_ascii() { text.to_ascii_lowercase() } else { text.to_lowercase() }
}

/// `String.prototype.toUpperCase`
pub fn js_to_upper(text: &str) -> String {
    if text.is_ascii() { text.to_ascii_uppercase() } else { text.to_uppercase() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_like_javascript() {
        assert_eq!(js_trim("\u{FEFF}\u{00A0} a b\u{2028}\n"), "a b");
        // NEL is whitespace to Rust but not to JavaScript
        assert_eq!(js_trim("\u{0085}a"), "\u{0085}a");
    }

    #[test]
    fn counts_utf16_units() {
        assert_eq!(utf16_len("abc"), 3);
        assert_eq!(utf16_len("é"), 1);
        assert_eq!(utf16_len("😀"), 2);
    }

    #[test]
    fn orders_keys_like_object_keys() {
        let map: IndexMap<String, u8> =
            ["b", "2", "1", "4294967295", "4294967294", "01"].into_iter().map(|key| (key.to_string(), 0)).collect();
        let keys: Vec<_> = into_js_key_order(map).into_keys().collect();
        assert_eq!(keys, ["1", "2", "4294967294", "b", "4294967295", "01"]);
    }
}
