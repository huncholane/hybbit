//! Number conversions ported from V8 13.6 `src/numbers/conversions.cc`.

use super::string::is_js_space_char;

/// `Number.prototype.toString()` / `String(number)`.
pub fn number_to_string(number: f64) -> String {
    if number.is_nan() {
        "NaN".to_string()
    } else if number == f64::INFINITY {
        "Infinity".to_string()
    } else if number == f64::NEG_INFINITY {
        "-Infinity".to_string()
    } else {
        ryu_js::Buffer::new().format(number).to_string()
    }
}

/// `Number(string)`: V8 `StringToDouble(.., ALLOW_NON_DECIMAL_PREFIX, 0)`.
///
/// Surrounding ECMAScript whitespace is ignored, the empty string is 0,
/// `0x`/`0o`/`0b` prefixes are accepted without a sign, decimals may start or end
/// with a dot, and `Infinity` is the only spelled-out value.
pub fn string_to_number(text: &str) -> f64 {
    let chars: Vec<char> = text.chars().collect();
    let end = chars.len();
    let mut current = 0;
    while current < end && is_js_space_char(chars[current]) {
        current += 1;
    }
    if current == end {
        return 0.0;
    }

    // Non-decimal prefixes must come first, unsigned
    if chars[current] == '0' {
        let prefixed = current + 1;
        if prefixed == end {
            return 0.0;
        }
        let radix_log_2 = match chars[prefixed] {
            'x' | 'X' => Some(4),
            'o' | 'O' => Some(3),
            'b' | 'B' => Some(1),
            _ => None,
        };
        if let Some(radix_log_2) = radix_log_2 {
            let digits = prefixed + 1;
            if digits == end {
                return f64::NAN;
            }
            return string_to_int_double(&chars[digits..], radix_log_2, false);
        }
    }

    // StrDecimalLiteral via fast_float (general | no_infnan | allow_leading_plus)
    if let Some((value, consumed)) = parse_decimal_prefix(&chars[current..]) {
        let after = current + consumed;
        if chars[after..].iter().all(|&c| is_js_space_char(c)) {
            return value;
        }
        return f64::NAN;
    }

    // No decimal number: only a signed or unsigned Infinity remains
    let (negative, word_start) = match chars[current] {
        '+' => (false, current + 1),
        '-' => (true, current + 1),
        _ => (false, current),
    };
    const INFINITY: [char; 8] = ['I', 'n', 'f', 'i', 'n', 'i', 't', 'y'];
    if word_start >= end || chars[word_start] != 'I' {
        return f64::NAN;
    }
    if end - word_start < INFINITY.len() || chars[word_start..word_start + INFINITY.len()] != INFINITY {
        return f64::NAN;
    }
    if !chars[word_start + INFINITY.len()..].iter().all(|&c| is_js_space_char(c)) {
        return f64::NAN;
    }
    if negative { f64::NEG_INFINITY } else { f64::INFINITY }
}

/// fast_float's decimal grammar: `[+-]? digits? (. digits?)? ([eE] [+-]? digits)?`
/// with at least one mantissa digit. An exponent marker without digits is left
/// unconsumed. Returns the correctly rounded value and the characters consumed.
fn parse_decimal_prefix(chars: &[char]) -> Option<(f64, usize)> {
    let end = chars.len();
    let mut p = 0;
    if p < end && (chars[p] == '-' || chars[p] == '+') {
        p += 1;
        if p == end || !(chars[p].is_ascii_digit() || chars[p] == '.') {
            return None;
        }
    }
    let mut digit_count = 0;
    while p < end && chars[p].is_ascii_digit() {
        p += 1;
        digit_count += 1;
    }
    if p < end && chars[p] == '.' {
        p += 1;
        while p < end && chars[p].is_ascii_digit() {
            p += 1;
            digit_count += 1;
        }
    }
    if digit_count == 0 {
        return None;
    }
    if p < end && (chars[p] == 'e' || chars[p] == 'E') {
        let location_of_e = p;
        p += 1;
        if p < end && (chars[p] == '-' || chars[p] == '+') {
            p += 1;
        }
        if p == end || !chars[p].is_ascii_digit() {
            p = location_of_e;
        } else {
            while p < end && chars[p].is_ascii_digit() {
                p += 1;
            }
        }
    }
    let literal: String = chars[..p].iter().collect();
    let value: f64 = literal.parse().ok()?;
    Some((value, p))
}

/// V8 `InternalStringToIntDouble` for power-of-two radixes without trailing junk:
/// exact up to 53 bits, then rounded half to even using the dropped bits.
fn string_to_int_double(chars: &[char], radix_log_2: u32, negative: bool) -> f64 {
    let end = chars.len();
    // `start` stays before the skipped zeros, as in V8: "0x00 " is 0, not junk
    let start = 0;
    let mut current = 0;
    while chars[current] == '0' {
        current += 1;
        if current == end {
            return if negative { -0.0 } else { 0.0 };
        }
    }
    let radix: i64 = 1 << radix_log_2;
    let digit_of = |c: char| -> Option<i64> {
        let value = c.to_digit(36)? as i64;
        (value < radix).then_some(value)
    };

    let mut number: i64 = 0;
    let mut exponent: i32 = 0;
    loop {
        let Some(digit) = digit_of(chars[current]) else {
            if current == start {
                return f64::NAN;
            }
            if chars[current..].iter().all(|&c| is_js_space_char(c)) {
                break;
            }
            return f64::NAN;
        };
        number = number * radix + digit;
        let mut overflow = (number >> 53) as i32;
        if overflow != 0 {
            let mut overflow_bits_count = 1;
            while overflow > 1 {
                overflow_bits_count += 1;
                overflow >>= 1;
            }
            let dropped_bits_mask = (1i64 << overflow_bits_count) - 1;
            let dropped_bits = number & dropped_bits_mask;
            number >>= overflow_bits_count;
            exponent = overflow_bits_count;

            let mut zero_tail = true;
            loop {
                current += 1;
                if current == end || digit_of(chars[current]).is_none() {
                    break;
                }
                zero_tail = zero_tail && chars[current] == '0';
                exponent += radix_log_2 as i32;
            }
            if !chars[current..].iter().all(|&c| is_js_space_char(c)) {
                return f64::NAN;
            }
            let middle_value = 1i64 << (overflow_bits_count - 1);
            if dropped_bits > middle_value || (dropped_bits == middle_value && ((number & 1) != 0 || !zero_tail)) {
                number += 1;
            }
            if number & (1i64 << 53) != 0 {
                exponent += 1;
                number >>= 1;
            }
            break;
        }
        current += 1;
        if current == end {
            break;
        }
    }

    if exponent == 0 {
        if negative {
            if number == 0 {
                return -0.0;
            }
            return -(number as f64);
        }
        return number as f64;
    }
    let signed = if negative { -number } else { number } as f64;
    signed * 2f64.powi(exponent)
}

/// `parseInt(text, 10)`: leading whitespace and sign, then the longest run of
/// decimal digits (NaN when there is none).
pub fn parse_int_10(text: &str) -> f64 {
    let chars: Vec<char> = text.chars().collect();
    let end = chars.len();
    let mut current = 0;
    while current < end && is_js_space_char(chars[current]) {
        current += 1;
    }
    if current == end {
        return f64::NAN;
    }
    let mut negative = false;
    if chars[current] == '+' || chars[current] == '-' {
        negative = chars[current] == '-';
        current += 1;
        if current == end {
            return f64::NAN;
        }
    }
    let mut leading_zero = false;
    while chars[current] == '0' {
        leading_zero = true;
        current += 1;
        if current == end {
            return if negative { -0.0 } else { 0.0 };
        }
    }
    if !chars[current].is_ascii_digit() {
        return if leading_zero {
            if negative { -0.0 } else { 0.0 }
        } else {
            f64::NAN
        };
    }
    // V8 keeps at most 310 digits; anything that long is Infinity anyway
    let digits: String = chars[current..].iter().take_while(|c| c.is_ascii_digit()).take(310).collect();
    let value: f64 = digits.parse().unwrap_or(f64::NAN);
    if negative { -value } else { value }
}

/// `Number.isInteger`.
pub fn is_integer(number: f64) -> bool {
    number.is_finite() && number.trunc() == number
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_of_string() {
        let cases: &[(&str, f64)] = &[
            ("", 0.0),
            ("  ", 0.0),
            ("42", 42.0),
            (" 42 ", 42.0),
            ("\u{feff}42\u{3000}", 42.0),
            ("+5", 5.0),
            ("-5", -5.0),
            ("1.", 1.0),
            (".5", 0.5),
            ("+.5", 0.5),
            ("1e3", 1000.0),
            ("1E+3", 1000.0),
            ("0x1f", 31.0),
            ("0X1F", 31.0),
            ("0o17", 15.0),
            ("0b101", 5.0),
            ("0", 0.0),
            ("00012", 12.0),
            ("Infinity", f64::INFINITY),
            ("-Infinity", f64::NEG_INFINITY),
            ("+Infinity", f64::INFINITY),
            ("1e400", f64::INFINITY),
            ("0x20000000000001", 9007199254740992.0),
        ];
        for (text, expected) in cases {
            assert_eq!(string_to_number(text), *expected, "{text:?}");
        }
        for text in ["abc", ".", "1e", "1_000", "0x", "-0x10", "infinity", "1 2", "+", "-", "--1", "0b2", "Infinityx", "NaN"] {
            assert!(string_to_number(text).is_nan(), "{text:?}");
        }
        assert!(string_to_number("-0").is_sign_negative());
    }

    #[test]
    fn parse_int_matches_javascript() {
        assert_eq!(parse_int_10("25"), 25.0);
        assert_eq!(parse_int_10(" 25abc"), 25.0);
        assert_eq!(parse_int_10("-5"), -5.0);
        assert_eq!(parse_int_10("1e5"), 1.0);
        assert_eq!(parse_int_10("0x10"), 0.0);
        assert_eq!(parse_int_10("007"), 7.0);
        assert!(parse_int_10("abc").is_nan());
        assert!(parse_int_10("").is_nan());
        assert!(parse_int_10("- 5").is_nan());
        assert!(parse_int_10("-0").is_sign_negative());
    }

    #[test]
    fn to_string_matches_javascript() {
        assert_eq!(number_to_string(40.0), "40");
        assert_eq!(number_to_string(-0.0), "0");
        assert_eq!(number_to_string(1e21), "1e+21");
        assert_eq!(number_to_string(40.7128 - 0.001), "40.711800000000004");
        assert_eq!(number_to_string(5e-7), "5e-7");
        assert_eq!(number_to_string(f64::NAN), "NaN");
    }
}
