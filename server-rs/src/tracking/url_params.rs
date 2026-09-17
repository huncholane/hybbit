//! URL helpers from server/src/services/tracker/utils.ts (`getUTMParams`,
//! `getAllUrlParams`, `clearSelfReferrer`) and the Node `URLSearchParams` string
//! parser they sit on.
//!
//! Node's parser is not the WHATWG one byte for byte: a pair containing at least one
//! valid `%XX` goes through `querystring.unescape`, which tries `decodeURIComponent`
//! and, when that throws (a stray `%`, invalid UTF-8), falls back to
//! `unescapeBuffer`, writing each UTF-16 unit truncated to a byte. So `é%41%zz`
//! decodes to `\u{FFFD}A%zz` in Node, and the port keeps that.

use indexmap::IndexMap;

use super::js::{into_js_key_order, js_to_lower};

/// `[...new URLSearchParams(init).entries()]` for a string `init`.
pub fn url_search_params(init: &str) -> Vec<(String, String)> {
    let mut flat: Vec<String> = Vec::new();
    if init.is_empty() {
        return Vec::new();
    }

    let bytes = init.as_bytes();
    let mut seen_separator = false;
    let mut buffer = String::new();
    let mut encoded = false;
    let mut encode_check = 0u8;
    let mut i = usize::from(bytes[0] == b'?');
    let mut pair_start = i;
    let mut last_pos = i;

    // Every position compared against is an ASCII delimiter, so slices stay on char
    // boundaries, and a non-ASCII byte resets the %XX detection exactly as the
    // UTF-16 unit it belongs to does in JavaScript
    while i < bytes.len() {
        let code = bytes[i];

        if code == b'&' {
            if pair_start == i {
                pair_start = i + 1;
                last_pos = i + 1;
                i += 1;
                continue;
            }
            if last_pos < i {
                buffer.push_str(&init[last_pos..i]);
            }
            if encoded {
                buffer = qs_unescape(&buffer);
            }
            flat.push(std::mem::take(&mut buffer));
            if !seen_separator {
                flat.push(String::new());
            }
            seen_separator = false;
            encoded = false;
            encode_check = 0;
            pair_start = i + 1;
            last_pos = i + 1;
            i += 1;
            continue;
        }

        if !seen_separator && code == b'=' {
            if last_pos < i {
                buffer.push_str(&init[last_pos..i]);
            }
            if encoded {
                buffer = qs_unescape(&buffer);
            }
            flat.push(std::mem::take(&mut buffer));
            seen_separator = true;
            encoded = false;
            encode_check = 0;
            last_pos = i + 1;
            i += 1;
            continue;
        }

        if code == b'+' {
            if last_pos < i {
                buffer.push_str(&init[last_pos..i]);
            }
            buffer.push(' ');
            last_pos = i + 1;
        } else if !encoded {
            if code == b'%' {
                encode_check = 1;
            } else if encode_check > 0 {
                if code.is_ascii_hexdigit() {
                    encode_check += 1;
                    if encode_check == 3 {
                        encoded = true;
                    }
                } else {
                    encode_check = 0;
                }
            }
        }
        i += 1;
    }

    if pair_start != i {
        if last_pos < i {
            buffer.push_str(&init[last_pos..i]);
        }
        if encoded {
            buffer = qs_unescape(&buffer);
        }
        flat.push(buffer);
        if !seen_separator {
            flat.push(String::new());
        }
    }

    let mut pairs = Vec::with_capacity(flat.len() / 2);
    let mut items = flat.into_iter();
    while let (Some(name), Some(value)) = (items.next(), items.next()) {
        pairs.push((name, value));
    }
    pairs
}

/// Node's `querystring.unescape`
fn qs_unescape(text: &str) -> String {
    decode_uri_component(text).unwrap_or_else(|| String::from_utf8_lossy(&unescape_buffer(text)).into_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

/// `decodeURIComponent`, or None where it throws `URIError`.
fn decode_uri_component(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut k = 0;
    while k < bytes.len() {
        if bytes[k] != b'%' {
            let next = text[k..].find('%').map_or(bytes.len(), |offset| k + offset);
            out.push_str(&text[k..next]);
            k = next;
            continue;
        }

        let byte_at = |at: usize| -> Option<u8> {
            if bytes.get(at) != Some(&b'%') {
                return None;
            }
            Some(hex_value(*bytes.get(at + 1)?)? * 16 + hex_value(*bytes.get(at + 2)?)?)
        };
        let lead = byte_at(k)?;
        let length = match lead {
            0x00..=0x7F => 1,
            _ if lead & 0xE0 == 0xC0 => 2,
            _ if lead & 0xF0 == 0xE0 => 3,
            _ if lead & 0xF8 == 0xF0 => 4,
            _ => return None,
        };
        let mut octets = vec![lead];
        for index in 1..length {
            let continuation = byte_at(k + 3 * index)?;
            if continuation & 0xC0 != 0x80 {
                return None;
            }
            octets.push(continuation);
        }
        // Rejects overlong forms, surrogates and code points past U+10FFFF
        out.push_str(std::str::from_utf8(&octets).ok()?);
        k += 3 * length;
    }
    Some(out)
}

/// `QueryString.unescapeBuffer(s)`: `%XX` becomes its byte, every other UTF-16 unit
/// is written truncated to its low byte.
fn unescape_buffer(text: &str) -> Vec<u8> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let mut out = Vec::with_capacity(units.len());
    let unhex = |unit: u16| -> Option<u8> { u8::try_from(unit).ok().and_then(hex_value) };
    let max_length = units.len() as isize - 2;
    let mut index = 0usize;
    while index < units.len() {
        let mut current = units[index];
        if current == u16::from(b'%') && (index as isize) < max_length {
            index += 1;
            current = units[index];
            match unhex(current) {
                None => {
                    out.push(b'%');
                    continue;
                }
                Some(high) => {
                    index += 1;
                    match unhex(units[index]) {
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

/// `getUTMParams`: `utm_*`, `gclid` and `gad_source`, keys and values lowercased.
pub fn get_utm_params(querystring: &str) -> IndexMap<String, String> {
    let mut params = IndexMap::new();
    if querystring.is_empty() {
        return params;
    }
    for (key, value) in url_search_params(querystring) {
        if key.starts_with("utm_") || key == "gclid" || key == "gad_source" {
            params.insert(js_to_lower(&key), js_to_lower(&value));
        }
    }
    params
}

/// `getAllUrlParams`: every parameter, keys lowercased, later duplicates winning, in
/// JavaScript object key order (this becomes the `url_parameters` column).
pub fn get_all_url_params(querystring: &str) -> IndexMap<String, String> {
    let mut params = IndexMap::new();
    if querystring.is_empty() {
        return params;
    }
    // Node strips one `?` here and URLSearchParams strips another
    let clean = querystring.strip_prefix('?').unwrap_or(querystring);
    for (key, value) in url_search_params(clean) {
        let key = js_to_lower(&key);
        // `params["__proto__"] = "x"` hits the prototype setter and stores nothing
        if key == "__proto__" {
            continue;
        }
        params.insert(key, value);
    }
    into_js_key_order(params)
}

/// `new URL(input).hostname`, or None where the constructor throws.
///
/// Parsing is the `url` crate's, corrected where differential fuzzing against Node
/// (whose parser, ada, follows the current WHATWG spec) found it disagreeing:
/// an `@` followed by an empty host (`foo://@`) and a non-digit in a non-special
/// URL's port (`foo://a:\x`) are failures, and a `file:` host is kept when the path
/// starts with a Windows drive letter (`file://host/C|`), which the crate clears.
pub fn url_hostname(input: &str) -> Option<String> {
    let authority = UrlAuthority::of(input);
    if authority.as_ref().is_some_and(UrlAuthority::fails_in_node) {
        return None;
    }

    let url = url::Url::parse(input).ok()?;
    let host = url.host_str().unwrap_or_default();
    if host.is_empty()
        && let Some(authority) = authority.filter(|authority| authority.scheme == "file")
        && !authority.text.is_empty()
        && !is_windows_drive_letter(&authority.text)
    {
        // Host-parse the same text without the drive-letter path the crate reacts to
        return url::Url::parse(&format!("file://{}/", authority.text))
            .ok()
            .map(|file| file.host_str().unwrap_or_default().to_string());
    }
    Some(host.to_string())
}

/// The scheme and authority text of a URL as the WHATWG parser splits them.
struct UrlAuthority {
    scheme: String,
    special: bool,
    /// Everything from after the slashes up to the first authority terminator
    text: String,
}

impl UrlAuthority {
    fn of(input: &str) -> Option<Self> {
        // The parser trims C0 controls and spaces, then drops tabs and newlines anywhere
        let cleaned: String =
            input.trim_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\n' | '\r')).collect();

        let colon = cleaned.find(':')?;
        let scheme = &cleaned[..colon];
        let valid_scheme = scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if !valid_scheme {
            return None;
        }
        let scheme = scheme.to_ascii_lowercase();
        let rest = &cleaned[colon + 1..];

        let special = matches!(scheme.as_str(), "http" | "https" | "ws" | "wss" | "ftp" | "file");
        let after_slashes = match scheme.as_str() {
            // file slash state: exactly two slashes or backslashes lead to the host
            "file" => {
                let mut chars = rest.chars();
                match (chars.next(), chars.next()) {
                    (Some('/' | '\\'), Some('/' | '\\')) => &rest[2..],
                    _ => return None,
                }
            }
            // special authority ignore slashes state
            _ if special => rest.trim_start_matches(['/', '\\']),
            _ => rest.strip_prefix("//")?,
        };

        let end = after_slashes
            .find(|c: char| matches!(c, '/' | '?' | '#') || (special && c == '\\'))
            .unwrap_or(after_slashes.len());
        Some(Self { scheme, special, text: after_slashes[..end].to_string() })
    }

    fn fails_in_node(&self) -> bool {
        if self.scheme == "file" {
            return false;
        }
        let host_and_port = match self.text.rfind('@') {
            // authority state: credentials followed by nothing
            Some(at) if at + 1 == self.text.len() => return true,
            Some(at) => &self.text[at + 1..],
            None => self.text.as_str(),
        };
        if self.special {
            return false;
        }
        // host state: the first ':' outside brackets starts the port, which must be
        // digits up to the end of the authority
        let mut inside_brackets = false;
        for (index, c) in host_and_port.char_indices() {
            match c {
                '[' => inside_brackets = true,
                ']' => inside_brackets = false,
                ':' if !inside_brackets => {
                    return !host_and_port[index + 1..].bytes().all(|b| b.is_ascii_digit());
                }
                _ => {}
            }
        }
        false
    }
}

/// An ASCII letter followed by `:` or `|`
fn is_windows_drive_letter(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && matches!(bytes[1], b':' | b'|')
}

/// `clearSelfReferrer`: an empty referrer for internal navigation.
pub fn clear_self_referrer<'a>(referrer: &'a str, hostname: &str) -> &'a str {
    if referrer.is_empty() || hostname.is_empty() {
        return referrer;
    }
    match url_hostname(referrer) {
        Some(referrer_host) if referrer_host == hostname => "",
        _ => referrer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(init: &str) -> Vec<(String, String)> {
        url_search_params(init)
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[test]
    fn splits_pairs_like_url_search_params() {
        assert_eq!(entries("a=b=c&&=x&y"), [pair("a", "b=c"), pair("", "x"), pair("y", "")]);
        assert_eq!(entries("??a=1"), [pair("?a", "1")]);
        assert_eq!(entries("?"), []);
        assert_eq!(entries("a+b=c+d%20e"), [pair("a b", "c d e")]);
    }

    #[test]
    fn keeps_nodes_fallback_decoding() {
        assert_eq!(entries("a=é%zz"), [pair("a", "é%zz")]);
        assert_eq!(entries("a=é%41%zz"), [pair("a", "\u{FFFD}A%zz")]);
        assert_eq!(entries("a=%41%zz€"), [pair("a", "A%zz\u{FFFD}")]);
        assert_eq!(entries("a=%E2%82"), [pair("a", "\u{FFFD}")]);
        assert_eq!(entries("a=%FF+x"), [pair("a", "\u{FFFD} x")]);
        assert_eq!(entries("a=%ED%A0%80"), [pair("a", "\u{FFFD}\u{FFFD}\u{FFFD}")]);
        assert_eq!(entries("a=%F0%9F%98%80"), [pair("a", "😀")]);
    }

    #[test]
    fn utm_and_url_params() {
        let utm = get_utm_params("?utm_Source=Google&UTM_MEDIUM=cpc&gclid=X&utm_source=Bing");
        assert_eq!(utm.into_iter().collect::<Vec<_>>(), [pair("utm_source", "bing"), pair("gclid", "x")]);
        // Both `?` go: getAllUrlParams strips one and URLSearchParams the other
        let all = get_all_url_params("??B=1&2=x&__PROTO__=y&1=z&b=2");
        assert_eq!(all.into_iter().collect::<Vec<_>>(), [pair("1", "z"), pair("2", "x"), pair("b", "2")]);
        let triple = get_all_url_params("???a=1");
        assert_eq!(triple.into_iter().collect::<Vec<_>>(), [pair("?a", "1")]);
    }

    #[test]
    fn rejects_credentials_without_a_host_like_node() {
        // Node's results for each input
        let cases: [(&str, Option<&str>); 31] = [
            ("http://@", None),
            ("http://@/", None),
            ("https://user@", None),
            ("foo://@", None),
            ("foo://@/x", None),
            ("foo://user:pass@", None),
            ("foo://@host", Some("host")),
            ("http://@host", Some("host")),
            ("http://a@@", None),
            ("foo://@@", None),
            ("foo://a@b@", None),
            ("http://@:80", None),
            ("foo://@:80", None),
            ("file://@", None),
            ("file://user@host/", None),
            ("foo://@?q", None),
            ("foo://@#f", None),
            ("foo://a@\\x", None),
            ("http://a@\\x", None),
            ("foo:@", Some("")),
            ("foo:/@", Some("")),
            ("foo:///@", Some("")),
            ("http:@", None),
            ("http:/@x", Some("x")),
            ("HTTP://@", None),
            ("http://\t@", None),
            ("h\ttp://@", None),
            ("foo://:@", None),
            ("foo://@@x", Some("x")),
            ("sc://@/", None),
            ("foo://%40@", None),
        ];
        for (input, node) in cases {
            assert_eq!(url_hostname(input).as_deref(), node, "{input:?}");
        }
    }

    #[test]
    fn ports_and_file_hosts_like_node() {
        // Node's results for each input
        let cases: [(&str, Option<&str>); 30] = [
            ("android-app://+:\\x", None),
            ("foo://a:\\x", None),
            ("foo://a:1\\x", None),
            ("foo://a:\\", None),
            ("foo://a:/x", Some("a")),
            ("foo://a:x", None),
            ("http://a:\\x", Some("a")),
            ("http://a:1\\x", Some("a")),
            ("htp://a:\\x", None),
            ("http://☃www:\\x", Some("xn--www-rm5a")),
            ("file://测试\\K|?a=%zz#", Some("xn--0zwm56d")),
            ("file://host/C|", Some("host")),
            ("file://host\\C|", Some("host")),
            ("file://测试/K|", Some("xn--0zwm56d")),
            ("file://host/K|/x", Some("host")),
            ("file://a\\b", Some("a")),
            ("file://h/c:", Some("h")),
            ("foo://a:65536", None),
            ("foo://a:99999999999", None),
            ("foo://[::1]:\\x", None),
            ("foo://a:%31", None),
            ("foo://a: 1", None),
            ("foo://a:1 ", Some("a")),
            ("file://localhost/C|", Some("")),
            ("file://host/C:", Some("host")),
            ("file://host/C:/", Some("host")),
            ("file://host/c|x", Some("host")),
            ("file:C|", Some("")),
            ("file:///C|", Some("")),
            ("file://C|/", Some("")),
        ];
        for (input, node) in cases {
            assert_eq!(url_hostname(input).as_deref(), node, "{input:?}");
        }
    }

    // Ported from the clearSelfReferrer behaviour documented in utils.ts
    #[test]
    fn clears_only_same_host_referrers() {
        assert_eq!(clear_self_referrer("https://example.com/a", "example.com"), "");
        assert_eq!(clear_self_referrer("https://www.example.com/a", "example.com"), "https://www.example.com/a");
        assert_eq!(clear_self_referrer("not a url", "example.com"), "not a url");
        assert_eq!(clear_self_referrer("", "example.com"), "");
        assert_eq!(clear_self_referrer("https://example.com/a", ""), "https://example.com/a");
    }
}
