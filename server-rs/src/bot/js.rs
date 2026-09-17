//! The pieces of JavaScript semantics the bot rules lean on, reproduced exactly.
//!
//! Every rule in this module was written against V8, and several of its answers
//! depend on details Rust does differently by default: regex `\w`, `\b` and case
//! folding are ASCII-only in a non-unicode JavaScript regex, quantifiers count
//! UTF-16 code units, `String.prototype.trim` has its own whitespace set, and
//! numbers print and parse by ECMAScript rules. A difference in any of these is
//! a request convicted by one backend and not the other, so they live here once.

use std::{cell::OnceCell, sync::LazyLock};

use regress::{Flags, Match, Regex};

/// A string as a JavaScript regex sees it: UTF-16 code units, plus (computed on
/// first use) the same units with ASCII letters lowercased, which is what the
/// case-insensitive regexes match against.
pub struct JsText {
    units: Vec<u16>,
    ascii_folded: OnceCell<Vec<u16>>,
}

impl JsText {
    pub fn new(text: &str) -> Self {
        Self { units: text.encode_utf16().collect(), ascii_folded: OnceCell::new() }
    }

    pub fn units(&self) -> &[u16] {
        &self.units
    }

    fn ascii_folded(&self) -> &[u16] {
        self.ascii_folded.get_or_init(|| {
            self.units
                .iter()
                .map(|&unit| if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) { unit + 32 } else { unit })
                .collect()
        })
    }

    /// The text of a match group, or None when the group did not participate.
    /// Always the original text, as `exec` returns it, whatever case the regex
    /// matched in.
    pub fn group(&self, found: &Match, group: usize) -> Option<String> {
        found.group(group).map(|range| String::from_utf16_lossy(&self.units[range]))
    }
}

/// A regex literal compiled with JavaScript's non-unicode semantics, matched
/// against UTF-16 code units the way V8 matches a JS string.
///
/// `regress` implements ECMAScript syntax (lookbehind included) and, through
/// `find_from_ucs2`, the non-unicode matching mode: `\w`, `\d` and `\b` are
/// ASCII and `[^ ]{50,}` counts code units, so an emoji is two.
///
/// The one place it departs from V8 is the `i` flag: it folds case with Unicode
/// rules even without `u`, so `k` would match the Kelvin sign and `s` the long s.
/// V8's non-unicode `Canonicalize` never maps a non-ASCII character to an ASCII
/// one, which makes `i` on an ASCII-only pattern mean exactly "ASCII letters in
/// either case". [`JsRegex::ignore_case`] expresses that directly: the pattern's
/// letters and the input's ASCII letters are both lowercased, and the regex runs
/// without `i`. The class escapes (`\w`, `\W`, `\b`, `\s`, `\d`) are unchanged by
/// ASCII case, and no pattern names an uppercase-only class, so the answers are
/// the same, and regress keeps its fast literal search.
pub struct JsRegex {
    regex: Regex,
    ignore_case: bool,
}

impl JsRegex {
    /// Compile a case-sensitive JavaScript regex source. Panics on an invalid
    /// pattern: every caller passes a fixed pattern, and the tests compile all of
    /// them.
    pub fn new(source: &str) -> Self {
        Self::compile(source, source.to_string(), false)
    }

    /// Compile a JavaScript regex source with the `i` flag.
    pub fn ignore_case(source: &str) -> Self {
        Self::compile(source, ascii_lowercase_pattern(source), true)
    }

    fn compile(source: &str, pattern: String, ignore_case: bool) -> Self {
        assert!(source.is_ascii(), "bot regex sources are ASCII: {source}");
        let regex = Regex::with_flags(&pattern, Flags::default())
            .unwrap_or_else(|error| panic!("invalid bot regex {source:?} (compiled as {pattern:?}): {error}"));
        Self { regex, ignore_case }
    }

    fn input<'t>(&self, text: &'t JsText) -> &'t [u16] {
        if self.ignore_case { text.ascii_folded() } else { text.units() }
    }

    /// `RegExp.prototype.test` for a non-global regex.
    pub fn test(&self, text: &JsText) -> bool {
        self.regex.find_from_ucs2(self.input(text), 0).next().is_some()
    }

    /// `RegExp.prototype.exec` for a non-global regex. Ranges in the match are
    /// UTF-16 code unit offsets; read groups through [`JsText::group`].
    pub fn exec(&self, text: &JsText) -> Option<Match> {
        self.regex.find_from_ucs2(self.input(text), 0).next()
    }
}

/// Lowercase the ASCII letters of a regex source, leaving escapes (`\W`, `\S`,
/// `\B`, `\D`) intact.
fn ascii_lowercase_pattern(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let escaped = chars.next().expect("dangling escape in bot regex");
            assert!(
                matches!(escaped, 'b' | 'B' | 'w' | 'W' | 'd' | 'D' | 's' | 'S') || !escaped.is_ascii_alphanumeric(),
                "unsupported escape \\{escaped} in bot regex {source}"
            );
            out.push('\\');
            out.push(escaped);
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// ECMAScript `WhiteSpace` and `LineTerminator`, the set `String.prototype.trim`
/// strips. Differs from Rust's `char::is_whitespace`: U+FEFF is in, U+0085 is out.
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

/// `String.prototype.trim`.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_whitespace)
}

/// `value?.trim().toLowerCase() || ""`, the anomaly scorer's `normalizeDimension`.
/// Rust's `to_lowercase` applies the same full Unicode mapping as V8's
/// `toLowerCase`, final sigma included.
pub fn normalize_dimension(value: Option<&str>) -> String {
    value.map(|text| js_trim(text).to_lowercase()).unwrap_or_default()
}

/// `Number(string)` (ECMAScript StringToNumber): NaN for anything that is not a
/// numeric literal. Rust's `f64::from_str` alone would accept `inf`, `nan` and
/// `infinity` in any case, which JavaScript does not.
pub fn js_string_to_number(text: &str) -> f64 {
    let trimmed = js_trim(text);
    if trimmed.is_empty() {
        return 0.0;
    }

    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(digits) = trimmed.strip_prefix(prefix) {
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return f64::NAN;
            }
            return digits
                .chars()
                .fold(0.0, |total, digit| total * f64::from(radix) + f64::from(digit.to_digit(radix).unwrap_or(0)));
        }
    }

    let (sign, unsigned) = match trimmed.as_bytes()[0] {
        b'+' => (1.0, &trimmed[1..]),
        b'-' => (-1.0, &trimmed[1..]),
        _ => (1.0, trimmed),
    };
    if unsigned == "Infinity" {
        return sign * f64::INFINITY;
    }
    if !is_str_unsigned_decimal_literal(unsigned) {
        return f64::NAN;
    }
    unsigned.parse::<f64>().map(|value| sign * value).unwrap_or(f64::NAN)
}

/// StrUnsignedDecimalLiteral without `Infinity`: `1`, `1.`, `.5`, `1.5e-3`.
fn is_str_unsigned_decimal_literal(text: &str) -> bool {
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

/// `String(number)`.
pub fn js_number_to_string(value: f64) -> String {
    ryu_js::Buffer::new().format(value).to_string()
}

/// `Number.prototype.toFixed(digits)`: the n for which n / 10^digits is closest
/// to the exact value, the larger n on a tie. Rust's `{:.N}` breaks exact ties
/// to even, so the digits are rounded here from the exact decimal expansion.
pub fn js_to_fixed(value: f64, digits: usize) -> String {
    if !value.is_finite() {
        return js_number_to_string(value);
    }
    if value.abs() >= 1e21 {
        return js_number_to_string(value);
    }

    let negative = value < 0.0;
    // 1074 fractional digits hold any double's binary fraction exactly.
    let exact = format!("{:.1074}", value.abs());
    let (integer, fraction) = exact.split_once('.').unwrap_or((&exact, ""));
    let mut kept: Vec<u8> = integer.bytes().chain(fraction.bytes().take(digits)).collect();
    let rest = &fraction.as_bytes()[digits.min(fraction.len())..];
    let round_up = match rest.first() {
        Some(first) if *first > b'5' => true,
        Some(b'5') => true, // exactly half or above: JavaScript picks the larger n
        _ => false,
    };
    if round_up {
        let mut position = kept.len();
        loop {
            if position == 0 {
                kept.insert(0, b'1');
                break;
            }
            position -= 1;
            if kept[position] == b'9' {
                kept[position] = b'0';
            } else {
                kept[position] += 1;
                break;
            }
        }
    }

    let integer_len = kept.len() - digits;
    let mut text = String::with_capacity(kept.len() + 2);
    let integer_part = std::str::from_utf8(&kept[..integer_len]).unwrap_or("0");
    let fraction_part = std::str::from_utf8(&kept[integer_len..]).unwrap_or("");
    // JavaScript prints -0.00 for a negative value that rounds to zero.
    if negative {
        text.push('-');
    }
    text.push_str(integer_part);
    if digits > 0 {
        text.push('.');
        text.push_str(fraction_part);
    }
    text
}

/// `Number(x.toFixed(digits))`, used for logged ratios.
pub fn js_round_to_fixed(value: f64, digits: usize) -> f64 {
    js_string_to_number(&js_to_fixed(value, digits))
}

/// Milliseconds since the Unix epoch, `Date.now()`.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// The process id Node would put into a counter token.
pub static PROCESS_ID: LazyLock<u32> = LazyLock::new(std::process::id);

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(source: &str, ignore_case: bool, text: &str) -> bool {
        let regex = if ignore_case { JsRegex::ignore_case(source) } else { JsRegex::new(source) };
        regex.test(&JsText::new(text))
    }

    #[test]
    fn case_insensitivity_is_ascii_only() {
        assert!(matches("okhttp", true, "OkHttp/4"));
        assert!(matches("OKHTTP", true, "okhttp/4"));
        assert!(!matches("okhttp", false, "OkHttp/4"));
        // Kelvin sign and long s fold to k and s under Unicode rules, not in a
        // non-unicode JavaScript regex.
        assert!(!matches("k", true, "\u{212A}"));
        assert!(!matches(r"\w", true, "\u{212A}"));
        assert!(!matches("s", true, "\u{017F}"));
        assert!(matches("[^g]x", true, "ax"));
        assert!(!matches("[^g]x", true, "Gx"));
        assert!(matches("@[a-z][\\w-]+\\.", true, "@AB-c."));
        // Escapes keep their case: \W is not \w.
        assert!(matches(r"^\W", true, "-a"));
        assert!(!matches(r"^\W", true, "Aa"));
    }

    #[test]
    fn groups_read_the_original_text() {
        let text = JsText::new("Mozilla CHROME/120");
        let regex = JsRegex::ignore_case(r"(chrome)\/(\d+)");
        let found = regex.exec(&text).unwrap();
        assert_eq!(text.group(&found, 1).as_deref(), Some("CHROME"));
        assert_eq!(text.group(&found, 2).as_deref(), Some("120"));
    }

    #[test]
    fn classes_and_boundaries_follow_javascript() {
        // \b is an ASCII word boundary: accented letters are not word characters.
        assert!(matches(r"\bfoo\b", true, "\u{e9}foo\u{e9}"));
        // Quantifiers count UTF-16 code units.
        assert!(matches("^[^ ]{3,}$", false, "\u{1F600}a"));
        // Annex B: a class escape before `-` makes the dash literal.
        assert!(matches(r"^[\w\d-.]+$", true, "-."));
        // \s includes U+FEFF and excludes U+0085.
        assert!(matches(r"\s", false, "\u{FEFF}"));
        assert!(!matches(r"\s", false, "\u{0085}"));
        assert!(matches("(?<! cu)bots?(?:\\b|_)", true, "Googlebot/2.1"));
        assert!(!matches("(?<! cu)bots?(?:\\b|_)", true, "a cubot"));
    }

    #[test]
    fn trims_like_javascript() {
        assert_eq!(js_trim("\u{FEFF} a \u{3000}"), "a");
        assert_eq!(js_trim("\u{0085}a"), "\u{0085}a");
        assert_eq!(normalize_dimension(Some("  Example.COM ")), "example.com");
        assert_eq!(normalize_dimension(None), "");
    }

    #[test]
    fn parses_numbers_like_javascript() {
        assert_eq!(js_string_to_number("12"), 12.0);
        assert_eq!(js_string_to_number(" 12 "), 12.0);
        assert_eq!(js_string_to_number(""), 0.0);
        assert_eq!(js_string_to_number("0x10"), 16.0);
        assert_eq!(js_string_to_number("1e3"), 1000.0);
        assert_eq!(js_string_to_number(".5"), 0.5);
        assert_eq!(js_string_to_number("5."), 5.0);
        assert!(js_string_to_number("Infinity").is_infinite());
        assert!(js_string_to_number("inf").is_nan());
        assert!(js_string_to_number("nan").is_nan());
        assert!(js_string_to_number("12abc").is_nan());
        assert!(js_string_to_number("-0x10").is_nan());
    }

    #[test]
    fn formats_numbers_like_javascript() {
        assert_eq!(js_number_to_string(1920.0), "1920");
        assert_eq!(js_number_to_string(1.5), "1.5");
        assert_eq!(js_number_to_string(1e21), "1e+21");
        assert_eq!(js_to_fixed(0.0625, 3), "0.063");
        assert_eq!(js_to_fixed(0.9375, 3), "0.938");
        // Expected values printed by V8.
        assert_eq!(js_to_fixed(12.345, 2), "12.35");
        assert_eq!(js_to_fixed(1.005, 2), "1.00");
        assert_eq!(js_to_fixed(-0.0001, 2), "-0.00");
        assert_eq!(js_to_fixed(2.5, 0), "3");
        assert_eq!(js_to_fixed(99.999, 2), "100.00");
        assert_eq!(js_to_fixed(20.0, 2), "20.00");
        assert_eq!(js_round_to_fixed(1.0 / 3.0 * 100.0, 2), 33.33);
    }
}
