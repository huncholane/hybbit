//! String predicates with ECMAScript's definitions, which differ from Rust's
//! `char::is_whitespace` (JavaScript counts U+FEFF and excludes U+0085).

use super::unicode_tables::{ID_CONTINUE, ID_START, SPACE_SEPARATOR};

fn in_ranges(table: &[(u32, u32)], code_point: u32) -> bool {
    table
        .binary_search_by(|&(start, end)| {
            if end < code_point {
                std::cmp::Ordering::Less
            } else if start > code_point {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// V8 `IsWhiteSpace`: general category Zs plus TAB, VT, FF and BOM.
pub fn is_white_space(code_point: u32) -> bool {
    matches!(code_point, 0x09 | 0x0B | 0x0C | 0xFEFF) || in_ranges(SPACE_SEPARATOR, code_point)
}

/// V8 `IsLineTerminator`: LF, CR, LS, PS.
pub fn is_line_terminator(code_point: u32) -> bool {
    matches!(code_point, 0x0A | 0x0D | 0x2028 | 0x2029)
}

/// ECMAScript WhiteSpace or LineTerminator: what `\s`, `String.prototype.trim`,
/// `Number(string)` and `parseInt` skip.
pub fn is_js_space(code_point: u32) -> bool {
    is_white_space(code_point) || is_line_terminator(code_point)
}

pub fn is_js_space_char(character: char) -> bool {
    is_js_space(character as u32)
}

/// `String.prototype.trim`.
pub fn trim(text: &str) -> &str {
    text.trim_matches(is_js_space_char)
}

/// `String.prototype.length`: UTF-16 code units.
pub fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// ID_Start from the ICU data Node ships (V8 `IsIdentifierStart` without the
/// ASCII extras).
pub fn has_id_start(code_point: u32) -> bool {
    in_ranges(ID_START, code_point)
}

pub fn has_id_continue(code_point: u32) -> bool {
    in_ranges(ID_CONTINUE, code_point)
}

/// V8 `IsIdentifierStart`: ID_Start, `$`, `_` and `\`.
pub fn is_identifier_start(code_point: u32) -> bool {
    matches!(code_point, 0x24 | 0x5C | 0x5F) || has_id_start(code_point)
}

/// V8 `IsIdentifierPart`: ID_Continue, `$`, `_`, `\`, ZWNJ and ZWJ.
pub fn is_identifier_part(code_point: u32) -> bool {
    matches!(code_point, 0x24 | 0x5C | 0x5F | 0x200C | 0x200D) || has_id_continue(code_point)
}

/// A JavaScript regex character class for `\s` (non-unicode mode), for building
/// `regex` crate patterns that must agree with a JavaScript regex.
pub const JS_SPACE_CLASS: &str =
    r"[\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_matches_ecmascript() {
        for code_point in [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2000, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF] {
            assert!(is_js_space(code_point), "{code_point:#x}");
        }
        for code_point in [0x85, 0x180E, 0x200B, 0x41] {
            assert!(!is_js_space(code_point), "{code_point:#x}");
        }
        assert_eq!(trim("\u{feff} a b\u{3000}\n"), "a b");
    }

    #[test]
    fn identifier_classes() {
        assert!(is_identifier_start('a' as u32));
        assert!(is_identifier_start('$' as u32));
        assert!(!is_identifier_start('1' as u32));
        assert!(is_identifier_part('1' as u32));
        assert!(is_identifier_start(0x1D400)); // MATHEMATICAL BOLD CAPITAL A
    }
}
