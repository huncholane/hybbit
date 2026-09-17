//! Matching for compiled flag patterns: V8's syntax tree re-spelled for `regress`.
//!
//! `regress` implements ECMAScript backtracking (lookbehind, backreferences, lazy and
//! bounded loops, the empty-iteration rule) and can read the subject as UTF-16 code
//! units, which is what a flagless JavaScript RegExp matches. Where it differs from
//! V8, the pattern is spelled so the difference cannot show:
//!
//! - Its parser reads some Annex B syntax differently, so the tree from
//!   [`super::syntax`] (V8's reading, V8's rewrites included) is written out with
//!   plain syntax only: characters as `\uXXXX`, classes as explicit ranges, every
//!   group non-capturing or numbered.
//! - It joins an escaped surrogate pair into one code point even without the `u`
//!   flag (and misreads an escaped lead surrogate followed by any other `\u`
//!   escape), so lead surrogates are passed as raw pattern units, never escaped.
//! - Its non-Unicode case folding maps characters V8 keeps apart (`ſ` and `s`, `K`
//!   and `k`, `ß` and `ẞ`), so case-insensitive characters and classes are expanded
//!   here with the spec's `Canonicalize` (as V8 implements it) and matched exactly.
//!   Only case-insensitive backreferences still use regress's folding, which differs
//!   from V8 for 29 pairs of code units (U+017F with `s`/`S`, U+0131 with `i`/`I`, and
//!   Greek letters with prosgegrammeni and their ypogegrammeni forms): a
//!   `(?i:(ſ)\1)` matches "ſs" here and not in Node.
//! - A backreference to a duplicated group name becomes a sequence of numbered
//!   backreferences, V8's own lowering (at most one of the groups has matched, and
//!   the others match empty).

use std::{collections::BTreeMap, fmt::Write, sync::LazyLock};

use super::{
    case_table::CANONICALIZE,
    syntax::{Assertion, BackReference, INFINITY, Node, ParsedRegExp},
};

/// A pattern ready to run `RegExp.prototype.test` on strings.
#[derive(Debug)]
pub struct CompiledRegex {
    source: Vec<u32>,
    regex: regress::Regex,
}

impl CompiledRegex {
    /// Compile a parsed pattern. Errors only if regress rejects the re-spelled
    /// pattern, which would be a bug in [`spell`].
    pub fn new(parsed: &ParsedRegExp) -> Result<Self, regress::Error> {
        let source = spell(parsed);
        let regex = regress::Regex::from_unicode(source.iter().copied(), regress::Flags::default())?;
        Ok(Self { source, regex })
    }

    /// The pattern given to regress, raw lead surrogates shown as `\u{...}` (for logs
    /// and tests).
    pub fn spelled(&self) -> String {
        self.source
            .iter()
            .map(|&unit| match char::from_u32(unit) {
                Some(character) => character.to_string(),
                None => format!("\\u{{{unit:X}}}"),
            })
            .collect()
    }

    /// `regexp.test(text)` for a flagless RegExp: a match anywhere, reading the
    /// subject as UTF-16 code units.
    pub fn test(&self, text: &str) -> bool {
        let units: Vec<u16> = text.encode_utf16().collect();
        self.regex.find_from_ucs2(&units, 0).next().is_some()
    }
}

/// `Canonicalize` for every UTF-16 code unit.
static CANONICAL: LazyLock<Vec<u16>> = LazyLock::new(|| {
    let mut table: Vec<u16> = (0..=u16::MAX).collect();
    for &(unit, canonical) in CANONICALIZE {
        table[usize::from(unit)] = canonical;
    }
    table
});

/// Pattern text (as the code units regress reads) for a parsed tree.
pub fn spell(parsed: &ParsedRegExp) -> Vec<u32> {
    let mut out = Out(Vec::new());
    let speller = Speller { named: &parsed.named_captures };
    speller.node(&parsed.root, false, &mut out);
    out.0
}

/// Pattern units under construction.
struct Out(Vec<u32>);

impl Out {
    fn push(&mut self, character: char) {
        self.0.push(u32::from(character));
    }

    fn push_str(&mut self, text: &str) {
        self.0.extend(text.chars().map(u32::from));
    }
}

impl Write for Out {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.push_str(text);
        Ok(())
    }
}

struct Speller<'a> {
    named: &'a BTreeMap<Vec<u16>, Vec<i32>>,
}

impl Speller<'_> {
    fn node(&self, node: &Node, ignore_case: bool, out: &mut Out) {
        match node {
            Node::Empty => {}
            Node::Disjunction(alternatives) => {
                for (index, alternative) in alternatives.iter().enumerate() {
                    if index > 0 {
                        out.push('|');
                    }
                    self.node(alternative, ignore_case, out);
                }
            }
            Node::Alternative(nodes) => {
                for node in nodes {
                    if matches!(node, Node::Disjunction(_)) {
                        out.push_str("(?:");
                        self.node(node, ignore_case, out);
                        out.push(')');
                    } else {
                        self.node(node, ignore_case, out);
                    }
                }
            }
            Node::Char(unit) => {
                if ignore_case {
                    class(&case_closure(&[(u32::from(*unit), u32::from(*unit))]), false, out);
                } else {
                    unit_text(*unit, out);
                }
            }
            Node::Class { ranges, negated } => {
                let units = if ignore_case { case_closure(ranges) } else { bmp_ranges(ranges) };
                class(&units, *negated, out);
            }
            Node::Assertion(assertion) => out.push_str(match assertion {
                Assertion::StartOfInput => "(?-m:^)",
                Assertion::StartOfLine => "(?m:^)",
                Assertion::EndOfInput => "(?-m:$)",
                Assertion::EndOfLine => "(?m:$)",
                Assertion::Boundary => "\\b",
                Assertion::NonBoundary => "\\B",
            }),
            Node::Capture { body, .. } => {
                out.push('(');
                self.node(body, ignore_case, out);
                out.push(')');
            }
            Node::Group { flags, body } => {
                // `m` and `s` only affect assertions and dots, which are spelled out
                out.push_str("(?:");
                self.node(body, flags.ignore_case, out);
                out.push(')');
            }
            Node::Lookaround { positive, behind, body } => {
                out.push_str(match (*behind, *positive) {
                    (false, true) => "(?=",
                    (false, false) => "(?!",
                    (true, true) => "(?<=",
                    (true, false) => "(?<!",
                });
                self.node(body, ignore_case, out);
                out.push(')');
            }
            Node::BackReference(reference) => {
                let indices: Vec<i32> = match reference {
                    BackReference::Numbered(index) => vec![*index],
                    BackReference::Named(name) => self.named.get(name).cloned().unwrap_or_default(),
                };
                out.push_str(if ignore_case { "(?i:" } else { "(?:" });
                for index in indices {
                    let _ = write!(out, "(?:\\{index})");
                }
                out.push(')');
            }
            Node::Quantifier { min, max, greedy, body } => {
                let atomic = matches!(
                    body.as_ref(),
                    Node::Class { .. } | Node::Capture { .. } | Node::Group { .. } | Node::Lookaround { .. }
                ) || matches!(body.as_ref(), Node::Char(_) if !ignore_case);
                if atomic {
                    self.node(body, ignore_case, out);
                } else {
                    out.push_str("(?:");
                    self.node(body, ignore_case, out);
                    out.push(')');
                }
                if *max == INFINITY {
                    let _ = write!(out, "{{{min},}}");
                } else {
                    let _ = write!(out, "{{{min},{max}}}");
                }
                if !greedy {
                    out.push('?');
                }
            }
        }
    }
}

fn is_lead_surrogate(unit: u16) -> bool {
    (0xd800..=0xdbff).contains(&unit)
}

/// Class ranges restricted to code units (nothing above U+FFFF can match a code unit).
fn bmp_ranges(ranges: &[(u32, u32)]) -> Vec<(u16, u16)> {
    ranges.iter().filter(|(from, _)| *from <= 0xffff).map(|&(from, to)| (from as u16, to.min(0xffff) as u16)).collect()
}

/// Every code unit whose `Canonicalize` equals that of some member: what a
/// case-insensitive class or character matches.
fn case_closure(ranges: &[(u32, u32)]) -> Vec<(u16, u16)> {
    let canonical = &*CANONICAL;
    let mut images = vec![false; 0x10000];
    for (from, to) in bmp_ranges(ranges) {
        for unit in from..=to {
            images[usize::from(canonical[usize::from(unit)])] = true;
        }
    }
    let mut closure: Vec<(u16, u16)> = Vec::new();
    for unit in 0..=u16::MAX {
        if !images[usize::from(canonical[usize::from(unit)])] {
            continue;
        }
        match closure.last_mut() {
            Some(last) if last.1.checked_add(1) == Some(unit) => last.1 = unit,
            _ => closure.push((unit, unit)),
        }
    }
    closure
}

/// A class over code units.
fn class(ranges: &[(u16, u16)], negated: bool, out: &mut Out) {
    out.push('[');
    if negated {
        out.push('^');
    }
    for &(from, to) in ranges {
        unit_text(from, out);
        if to != from {
            out.push('-');
            unit_text(to, out);
        }
    }
    out.push(']');
}

fn unit_text(unit: u16, out: &mut Out) {
    match char::from_u32(u32::from(unit)) {
        Some(character) if character.is_ascii_alphanumeric() => out.push(character),
        // Raw, so regress cannot join it with a following escape
        _ if is_lead_surrogate(unit) => out.0.push(u32::from(unit)),
        _ => {
            let _ = write!(out, "\\u{unit:04X}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::syntax::parse;
    use super::*;

    fn compile(pattern: &str) -> CompiledRegex {
        let units: Vec<u16> = pattern.encode_utf16().collect();
        CompiledRegex::new(&parse(&units).expect("valid pattern")).expect("regress accepts the spelling")
    }

    #[test]
    fn matches_like_a_flagless_javascript_regexp() {
        // Expectations recorded from Node 26.7.0
        let cases: &[(&str, &str, bool)] = &[
            ("^/pricing(/|$)", "/pricing/pro", true),
            ("^/pricing(/|$)", "/pricingx", false),
            ("a]", "a]", true),
            ("x{2,3}{", "xx{", true),
            ("\\c1", "\\c1", true),
            ("[\\c_]", "\u{1f}", true),
            ("^.$", "\u{1f600}", false),
            ("^..$", "\u{1f600}", true),
            ("^\u{1f600}+$", "\u{1f600}\u{1f600}", false),
            ("\\uD83D\\uDE00", "\u{1f600}", true),
            ("[\u{1f600}]", "\u{1f600}", true),
            ("(?<a>x)|(?<a>y)\\k<a>", "yy", true),
            ("(?:(?<a>x)|(?<a>y))\\k<a>", "x{2}", false),
            ("(?i:abc)", "ABC", true),
            ("(?i:a)b", "AB", false),
            ("(?i:s)", "\u{17f}", false),
            ("(?i:[a-z])", "\u{212a}", false),
            ("(?i:[^a-z])", "\u{212a}", true),
            ("(?i:\u{df})", "\u{1e9e}", false),
            ("(?<=\\$)\\d+", "$42", true),
            ("\\2(a)(b)", "ab", true),
            ("(a\\1)", "a", true),
            ("\\0123", "\n3", true),
            ("\\8", "8", true),
            ("[^]", "", false),
            ("[]", "a", false),
            ("(?=a)*b", "b", true),
        ];
        for &(pattern, text, expected) in cases {
            let compiled = compile(pattern);
            assert_eq!(compiled.test(text), expected, "{pattern:?} on {text:?} (spelled {})", compiled.spelled());
        }
    }
}
