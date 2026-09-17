//! Translation of ua-parser-js regex sources (JavaScript syntax, non-Unicode mode,
//! Annex B) into `regex` / `fancy-regex` syntax.
//!
//! The translated patterns only ever run against the ASCII haystack built in
//! parser.rs, with Unicode off, which is how JS treats ASCII patterns under `/i`
//! without `/u`: `\w`, `\d`, `\b` and case folding are ASCII-only there too. Case
//! folding is done up front instead of by the engine: the haystack is lowercased
//! and so is every letter in the pattern (literals and class members), which for
//! ASCII is the same relation as `/i` and lets the engines use plain SIMD literal
//! prefilters rather than case-insensitive ones. What still needs rewriting is
//! syntax and the few semantic gaps:
//! - `.` excludes `\r` as well as `\n` in JS;
//! - `-` is literal next to a class escape (`[\w- ]`), and `[`, `&`, `~` are
//!   plain characters inside JS classes;
//! - `{` that does not start a quantifier is a literal;
//! - a quantified lookahead is legal in JS: with a minimum of zero it is a no-op
//!   (`(?=comodo_)?dragon`), otherwise it runs once;
//! - lookarounds and backreferences need fancy-regex, so for those patterns a
//!   regular over-approximation (lookarounds dropped, backreferences widened) is
//!   also produced to cheaply rule out most haystacks before backtracking.

use std::fmt::Write as _;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Translated {
    /// Exact translation, for `regex::bytes` or fancy-regex (ASCII bytes mode).
    pub pattern: String,
    /// True when the pattern keeps a lookaround or a backreference.
    pub fancy: bool,
    /// For fancy patterns: a lookaround-free pattern that matches whenever the
    /// exact one does.
    pub approximation: Option<String>,
    /// Number of capture groups, which property lists index into.
    pub capture_groups: usize,
    /// A capture group nested inside a group that can repeat. JS clears such
    /// captures on every iteration while Rust engines keep the last participating
    /// value, so these patterns need a reason to be safe (checked by a test).
    pub capture_in_repeated_group: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct TranslateError(pub String);

#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupKind {
    Capture,
    NonCapture,
    Lookaround,
}

struct Group {
    kind: GroupKind,
    exact_start: usize,
    captures_at_open: usize,
}

struct Translator<'a> {
    chars: Vec<char>,
    pos: usize,
    exact: String,
    approx: String,
    /// Depth of lookarounds currently open; the approximation drops their contents.
    approx_suppressed: usize,
    groups: Vec<Group>,
    captures: usize,
    total_captures: usize,
    fancy_features: usize,
    capture_in_repeated_group: bool,
    source: &'a str,
}

pub(super) fn translate(source: &str) -> Result<Translated, TranslateError> {
    let chars: Vec<char> = source.chars().collect();
    let total_captures = count_capture_groups(&chars);
    let mut t = Translator {
        chars,
        pos: 0,
        exact: String::with_capacity(source.len() + 16),
        approx: String::with_capacity(source.len() + 16),
        approx_suppressed: 0,
        groups: Vec::new(),
        captures: 0,
        total_captures,
        fancy_features: 0,
        capture_in_repeated_group: false,
        source,
    };
    t.run()?;
    let fancy = t.fancy_features > 0;
    Ok(Translated {
        approximation: fancy.then_some(t.approx),
        pattern: t.exact,
        fancy,
        capture_groups: t.captures,
        capture_in_repeated_group: t.capture_in_repeated_group,
    })
}

/// Counts `(` that open capture groups, so `\N` can be told apart from an octal
/// escape the way JS does.
fn count_capture_groups(chars: &[char]) -> usize {
    let mut count = 0;
    let mut i = 0;
    let mut in_class = false;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '[' => in_class = true,
            ']' => in_class = false,
            '(' if !in_class && chars.get(i + 1) != Some(&'?') => count += 1,
            _ => {}
        }
        i += 1;
    }
    count
}

impl Translator<'_> {
    fn err(&self, message: impl Into<String>) -> TranslateError {
        TranslateError(format!("/{}/ at {}: {}", self.source, self.pos, message.into()))
    }

    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn emit(&mut self, text: &str) {
        self.exact.push_str(text);
        if self.approx_suppressed == 0 {
            self.approx.push_str(text);
        }
    }

    fn run(&mut self) -> Result<(), TranslateError> {
        while let Some(c) = self.peek(0) {
            match c {
                '\\' => self.escape()?,
                '.' => {
                    self.pos += 1;
                    self.emit(r"[^\n\r]");
                }
                '[' => self.class()?,
                '(' => self.open_group()?,
                ')' => self.close_group()?,
                '*' | '+' | '?' => {
                    self.pos += 1;
                    self.emit(&c.to_string());
                    self.lazy_suffix();
                }
                '{' => match self.brace_quantifier() {
                    Some((text, _, _)) => {
                        self.emit(&text);
                        self.lazy_suffix();
                    }
                    None => {
                        self.pos += 1;
                        self.emit(r"\{");
                    }
                },
                '^' | '$' | '|' => {
                    self.pos += 1;
                    self.emit(&c.to_string());
                }
                _ => {
                    self.pos += 1;
                    let literal = literal(c).map_err(|message| self.err(message))?;
                    self.emit(&literal);
                }
            }
        }
        if !self.groups.is_empty() {
            return Err(self.err("unclosed group"));
        }
        Ok(())
    }

    fn lazy_suffix(&mut self) {
        if self.peek(0) == Some('?') {
            self.pos += 1;
            self.emit("?");
        }
    }

    /// Parses `{n}`, `{n,}` or `{n,m}` at the cursor, advancing past it.
    fn brace_quantifier(&mut self) -> Option<(String, u32, Option<u32>)> {
        let rest: String = self.chars[self.pos..].iter().take(24).collect();
        let close = rest.find('}')?;
        let body = &rest[1..close];
        let (min, max) = match body.split_once(',') {
            None => {
                let n = parse_digits(body)?;
                (n, Some(n))
            }
            Some((low, "")) => (parse_digits(low)?, None),
            Some((low, high)) => (parse_digits(low)?, Some(parse_digits(high)?)),
        };
        self.pos += rest[..=close].chars().count();
        Some((format!("{{{body}}}"), min, max))
    }

    /// Reads a quantifier after a closed group, returning (min, max) and the text.
    fn take_quantifier(&mut self) -> Option<(String, u32, Option<u32>)> {
        let (text, min, max) = match self.peek(0)? {
            '*' => {
                self.pos += 1;
                ("*".to_string(), 0, None)
            }
            '+' => {
                self.pos += 1;
                ("+".to_string(), 1, None)
            }
            '?' => {
                self.pos += 1;
                ("?".to_string(), 0, Some(1))
            }
            '{' => self.brace_quantifier()?,
            _ => return None,
        };
        let lazy = if self.peek(0) == Some('?') {
            self.pos += 1;
            "?"
        } else {
            ""
        };
        Some((format!("{text}{lazy}"), min, max))
    }

    fn open_group(&mut self) -> Result<(), TranslateError> {
        let exact_start = self.exact.len();
        let captures_at_open = self.captures;
        let kind = if self.peek(1) == Some('?') {
            match (self.peek(2), self.peek(3)) {
                (Some(':'), _) => {
                    self.pos += 3;
                    self.emit("(?:");
                    GroupKind::NonCapture
                }
                (Some(look @ ('=' | '!')), _) => {
                    self.pos += 3;
                    self.exact.push_str(&format!("(?{look}"));
                    self.approx_suppressed += 1;
                    GroupKind::Lookaround
                }
                (Some('<'), Some(look @ ('=' | '!'))) => {
                    self.pos += 4;
                    self.exact.push_str(&format!("(?<{look}"));
                    self.approx_suppressed += 1;
                    GroupKind::Lookaround
                }
                _ => return Err(self.err("unsupported group syntax")),
            }
        } else {
            self.pos += 1;
            self.captures += 1;
            self.emit("(");
            GroupKind::Capture
        };
        self.groups.push(Group { kind, exact_start, captures_at_open });
        Ok(())
    }

    fn close_group(&mut self) -> Result<(), TranslateError> {
        self.pos += 1;
        let group = self.groups.pop().ok_or_else(|| self.err("unbalanced )"))?;
        let has_inner_captures = self.captures > group.captures_at_open + usize::from(group.kind == GroupKind::Capture);

        if group.kind == GroupKind::Lookaround {
            self.exact.push(')');
            self.approx_suppressed -= 1;
            match self.take_quantifier() {
                // Annex B: an optional lookahead can always match empty, so it never
                // constrains anything
                Some((_, 0, _)) => {
                    if self.captures > group.captures_at_open {
                        return Err(self.err("optional lookahead with capture groups"));
                    }
                    self.exact.truncate(group.exact_start);
                }
                // a lookahead repeated at least once behaves as a single one
                Some(_) | None => self.fancy_features += 1,
            }
            return Ok(());
        }

        self.emit(")");
        if let Some((text, _, max)) = self.take_quantifier() {
            if has_inner_captures && max != Some(1) {
                self.capture_in_repeated_group = true;
            }
            self.emit(&text);
        }
        Ok(())
    }

    fn escape(&mut self) -> Result<(), TranslateError> {
        let c = self.peek(1).ok_or_else(|| self.err("trailing backslash"))?;
        self.pos += 2;
        match c {
            'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'b' | 'B' => self.emit(&format!("\\{c}")),
            '1'..='9' => {
                let mut digits = c.to_string();
                while let Some(next @ '0'..='9') = self.peek(0) {
                    digits.push(next);
                    self.pos += 1;
                }
                let group: usize = digits.parse().map_err(|_| self.err("bad backreference"))?;
                if group > self.total_captures {
                    return Err(self.err("octal escapes are not supported"));
                }
                self.exact.push_str(&format!("\\{group}"));
                if self.approx_suppressed == 0 {
                    // a backreference repeats some earlier text: any text will do
                    self.approx.push_str(r"(?s:.*)");
                }
                self.fancy_features += 1;
            }
            _ => {
                let resolved = control_escape(c).unwrap_or(c);
                let literal = literal(resolved).map_err(|message| self.err(message))?;
                self.emit(&literal);
            }
        }
        Ok(())
    }

    fn class(&mut self) -> Result<(), TranslateError> {
        self.pos += 1;
        let mut out = String::from("[");
        if self.peek(0) == Some('^') {
            self.pos += 1;
            out.push('^');
        }
        if self.peek(0) == Some(']') {
            return Err(self.err("empty classes are not supported"));
        }
        let mut items = 0;
        let mut members: u128 = 0;
        loop {
            let atom = match self.peek(0) {
                None => return Err(self.err("unclosed class")),
                Some(']') => {
                    self.pos += 1;
                    break;
                }
                Some(_) => self.class_atom()?,
            };
            items += 1;
            // a range needs a character on both sides; otherwise '-' is literal
            if let ClassAtom::Char(low) = atom
                && self.peek(0) == Some('-')
                && self.peek(1).is_some_and(|next| next != ']')
            {
                let save = self.pos;
                self.pos += 1;
                match self.class_atom()? {
                    ClassAtom::Char(high) => {
                        if high < low {
                            return Err(self.err("range out of order"));
                        }
                        if !high.is_ascii() {
                            return Err(self.err("non-ASCII class range"));
                        }
                        for member in low as u8..=high as u8 {
                            members |= 1 << member.to_ascii_lowercase();
                        }
                        continue;
                    }
                    ClassAtom::Escape(_) => self.pos = save,
                }
            }
            match atom {
                ClassAtom::Char(ch) if ch.is_ascii() => members |= 1 << (ch as u8).to_ascii_lowercase(),
                ClassAtom::Char(ch) => return Err(self.err(format!("non-ASCII class member {ch:?}"))),
                ClassAtom::Escape(name) => {
                    out.push('\\');
                    out.push(name);
                }
            }
        }
        debug_assert!(items > 0);
        // members are case-folded to lowercase, like every literal (see `literal`)
        let mut byte = 0u32;
        while byte < 128 {
            if members & (1 << byte) == 0 {
                byte += 1;
                continue;
            }
            let start = byte;
            while byte + 1 < 128 && members & (1 << (byte + 1)) != 0 {
                byte += 1;
            }
            out.push_str(&class_char(start as u8));
            if byte > start {
                if byte > start + 1 {
                    out.push('-');
                }
                out.push_str(&class_char(byte as u8));
            }
            byte += 1;
        }
        out.push(']');
        self.emit(&out);
        Ok(())
    }

    fn class_atom(&mut self) -> Result<ClassAtom, TranslateError> {
        let c = self.peek(0).ok_or_else(|| self.err("unclosed class"))?;
        if c != '\\' {
            self.pos += 1;
            return Ok(ClassAtom::Char(c));
        }
        let escaped = self.peek(1).ok_or_else(|| self.err("trailing backslash"))?;
        self.pos += 2;
        Ok(match escaped {
            'd' | 'D' | 'w' | 'W' | 's' | 'S' => ClassAtom::Escape(escaped),
            // inside a class \b is a backspace
            'b' => ClassAtom::Char('\u{08}'),
            other => ClassAtom::Char(control_escape(other).unwrap_or(other)),
        })
    }
}

enum ClassAtom {
    Char(char),
    Escape(char),
}

fn parse_digits(text: &str) -> Option<u32> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok()).flatten()
}

fn control_escape(c: char) -> Option<char> {
    Some(match c {
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => '\u{0B}',
        'f' => '\u{0C}',
        '0' => '\0',
        _ => return None,
    })
}

/// A literal character outside a class, lowercased. Only ASCII is accepted: the
/// haystack is ASCII by construction, so a non-ASCII literal could never match as
/// it does in JS.
fn literal(c: char) -> Result<String, String> {
    if !c.is_ascii() {
        return Err(format!("non-ASCII literal {c:?}"));
    }
    let c = c.to_ascii_lowercase();
    Ok(match c {
        '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '#' | '&' | '-' | '~' => format!("\\{c}"),
        _ if c.is_ascii_graphic() || c == ' ' => c.to_string(),
        _ => hex_escape(c as u8),
    })
}

/// A class member, escaped where `-`, `&&`, `~~` and `[` mean something to the
/// Rust parser but not to JS.
fn class_char(byte: u8) -> String {
    let c = byte as char;
    match c {
        '\\' | ']' | '[' | '^' | '-' | '&' | '~' => format!("\\{c}"),
        _ if c.is_ascii_graphic() || c == ' ' => c.to_string(),
        _ => hex_escape(byte),
    }
}

fn hex_escape(byte: u8) -> String {
    let mut out = String::with_capacity(4);
    let _ = write!(out, "\\x{byte:02X}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(source: &str) -> String {
        translate(source).unwrap().pattern
    }

    #[test]
    fn rewrites_js_only_syntax() {
        assert_eq!(exact(r"\b(?:crmo|crios)\/([\w\.]+)"), r"\b(?:crmo|crios)/([\w.]+)");
        assert_eq!(exact(r"(ideatab[-\w ]+|a3500-hv)"), r"(ideatab[\w \-]+|a3500\-hv)");
        assert_eq!(exact(r"((?:red)?mi[-_ ]?pad[\w- ]*)"), r"((?:red)?mi[ \-_]?pad[\w \-]*)");
        // letters are lowercased, class members folded and merged into ranges
        assert_eq!(exact(r"(Klarna)\/[A-Fa-cX]"), r"(klarna)/[a-fx]");
        assert_eq!(exact(r"[^\);]+[mobiletab]{3,6}"), r"[^);]+[abeilmot]{3,6}");
        assert_eq!(exact(r"webkit.+?(mobile ?safari)"), r"webkit[^\n\r]+?(mobile ?safari)");
        assert_eq!(exact(r"[c-g]\d{4}"), r"[c-g]\d{4}");
        assert_eq!(exact(r"a{x"), r"a\{x");
        assert_eq!(exact(r"\(ipad\)[;\]]"), r"\(ipad\)[;\]]");
    }

    #[test]
    fn optional_lookahead_is_dropped() {
        let t = translate(r"(flock|(?=comodo_)?dragon)\/([-\w\.]+)").unwrap();
        assert_eq!(t.pattern, r"(flock|dragon)/([\w\-.]+)");
        assert!(!t.fancy);
        assert_eq!(t.capture_groups, 2);
    }

    #[test]
    fn lookarounds_and_backreferences_are_fancy_with_approximation() {
        let t = translate(r"(whale(?!.+naver)|brave)\/([\w\.]+)").unwrap();
        assert!(t.fancy);
        assert_eq!(t.pattern, r"(whale(?![^\n\r]+naver)|brave)/([\w.]+)");
        assert_eq!(t.approximation.as_deref(), Some(r"(whale|brave)/([\w.]+)"));

        let t = translate(r"\b; (\w+) build\/hm\1").unwrap();
        assert!(t.fancy);
        assert_eq!(t.pattern, r"\b; (\w+) build/hm\1");
        assert_eq!(t.approximation.as_deref(), Some(r"\b; (\w+) build/hm(?s:.*)"));
    }

    #[test]
    fn flags_captures_inside_repeats() {
        assert!(translate(r"(aix) ((\d)(?=\.|\)| )[\w\.])*").unwrap().capture_in_repeated_group);
        assert!(!translate(r"(a(b))?").unwrap().capture_in_repeated_group);
        assert!(translate(r"(?:(a)|b)+").unwrap().capture_in_repeated_group);
    }
}
