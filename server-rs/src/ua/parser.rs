//! The matching half of the port: `UAParser(ua)`'s truncation, the compiled
//! tables and `rgxMapper`.
//!
//! JS runs these regexes over UTF-16 without the `u` flag, where every non-ASCII
//! code unit is a non-word character that no ASCII literal or class matches. So
//! each UA is first rewritten into an ASCII haystack with the same behaviour
//! (see [`Haystack`]); the regexes then run with ASCII-only semantics, captures
//! are mapped back onto the original text, and no Unicode case folding or
//! Unicode `\w`/`\b` can creep in. Nearly every real UA is ASCII already, in which
//! case the haystack is the UA itself.

use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

use super::{
    regexes,
    table::{Fields, RuleSrc, is_js_whitespace, trim_start_js},
    translate::translate,
};

/// `UA_MAX_LENGTH`, in UTF-16 code units.
pub(super) const UA_MAX_LENGTH: usize = 500;

/// fancy-regex refuses to backtrack forever (JS has no such limit). ua-parser-js
/// fuzzes its patterns against ReDoS on 500-character input, so this is far above
/// anything a legitimate match needs; hitting it is logged and treated as no match.
const BACKTRACK_LIMIT: usize = 10_000_000;

/// The UA as ua-parser-js sees it after `setUA`: longer than `UA_MAX_LENGTH`
/// code units, it loses its leading whitespace and is cut to that many units.
pub(super) fn truncate(ua: &str) -> (&str, bool) {
    // UTF-16 length is at least the char count and at most the byte count
    if ua.len() <= UA_MAX_LENGTH || ua.encode_utf16().nth(UA_MAX_LENGTH).is_none() {
        return (ua, false);
    }
    let trimmed = trim_start_js(ua);
    let mut units = 0;
    for (offset, c) in trimmed.char_indices() {
        let width = c.len_utf16();
        if units + width > UA_MAX_LENGTH {
            // `substring` can split a surrogate pair and keep a lone high surrogate,
            // which a Rust string cannot hold; it is reported so the haystack can
            // still see one code unit there
            return (&trimmed[..offset], units < UA_MAX_LENGTH);
        }
        units += width;
    }
    (trimmed, false)
}

/// An ASCII stand-in for the UA that every table regex treats exactly like JS
/// treats the UTF-16 original, plus the map back to original byte offsets.
///
/// Each UTF-16 code unit becomes one byte: ASCII stays; U+2028/U+2029 (line
/// terminators that are also `\s`) become `\n`; other JS whitespace becomes
/// `\x0B`; anything else becomes `\x01`, which like a non-ASCII unit is matched
/// only by `.` and negated classes. Astral characters are two units, as in JS.
/// ASCII letters are lowercased to pair with the lowercased patterns (see
/// translate.rs), which leaves every offset where it was.
pub(super) struct Haystack<'a> {
    pub original: &'a str,
    bytes: Vec<u8>,
    /// For a non-ASCII UA: original byte offset of every haystack position.
    offsets: Option<Vec<usize>>,
}

impl<'a> Haystack<'a> {
    pub fn new(original: &'a str, dangling_high_surrogate: bool) -> Self {
        if original.is_ascii() && !dangling_high_surrogate {
            return Self { original, bytes: original.as_bytes().to_ascii_lowercase(), offsets: None };
        }
        let mut bytes = Vec::with_capacity(original.len() + 1);
        let mut offsets = Vec::with_capacity(original.len() + 2);
        for (offset, c) in original.char_indices() {
            let stand_in = if c.is_ascii() {
                (c as u8).to_ascii_lowercase()
            } else if c == '\u{2028}' || c == '\u{2029}' {
                b'\n'
            } else if is_js_whitespace(c) {
                0x0B
            } else {
                0x01
            };
            for _ in 0..c.len_utf16() {
                bytes.push(stand_in);
                offsets.push(offset);
            }
        }
        if dangling_high_surrogate {
            bytes.push(0x01);
            offsets.push(original.len());
        }
        offsets.push(original.len());
        Self { original, bytes, offsets: Some(offsets) }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The original text a haystack range covers. A range edge inside an astral
    /// character (a JS capture holding half a surrogate pair) snaps to its start.
    pub fn slice(&self, start: usize, end: usize) -> &'a str {
        match &self.offsets {
            None => &self.original[start..end],
            Some(offsets) => &self.original[offsets[start]..offsets[end]],
        }
    }
}

enum Engine {
    Plain(regex::bytes::Regex),
    Fancy { exact: fancy_regex::Regex, approximation: regex::bytes::Regex },
}

pub(super) struct CompiledRegex {
    source: &'static str,
    engine: Engine,
}

/// Capture group byte ranges of one match, indexed like JS `matches` (0 is the
/// whole match).
pub(super) type Groups = Vec<Option<(usize, usize)>>;

impl CompiledRegex {
    fn compile(source: &'static str) -> Result<Self, String> {
        let translated = translate(source).map_err(|error| error.0)?;
        // case-sensitive on purpose: patterns and haystack are both lowercased
        let plain = |pattern: &str| {
            regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .map_err(|error| format!("/{source}/ as {pattern}: {error}"))
        };
        let engine = if translated.fancy {
            let exact = fancy_regex::RegexBuilder::new(&translated.pattern)
                .bytes_mode(fancy_regex::BytesMode::Ascii)
                .backtrack_limit(BACKTRACK_LIMIT)
                .build()
                .map_err(|error| format!("/{source}/ as {}: {error}", translated.pattern))?;
            let approximation = plain(translated.approximation.as_deref().unwrap_or(".*"))?;
            Engine::Fancy { exact, approximation }
        } else {
            Engine::Plain(plain(&translated.pattern)?)
        };
        Ok(Self { source, engine })
    }

    pub fn is_fancy(&self) -> bool {
        matches!(self.engine, Engine::Fancy { .. })
    }

    /// For tests: the fancy pattern matches where its approximation does not,
    /// which would make the pre-check drop a real match.
    #[cfg(test)]
    pub fn approximation_misses(&self, haystack: &Haystack<'_>) -> bool {
        match &self.engine {
            Engine::Plain(_) => false,
            Engine::Fancy { exact, approximation } => {
                exact.is_match(haystack.bytes()).unwrap_or(false) && !approximation.is_match(haystack.bytes())
            }
        }
    }

    pub fn source(&self) -> &'static str {
        self.source
    }

    /// `regex.exec(ua)`: the capture ranges of the leftmost match, if any.
    pub fn captures(&self, haystack: &Haystack<'_>) -> Option<Groups> {
        let bytes = haystack.bytes();
        match &self.engine {
            Engine::Plain(regex) => {
                // most regexes miss; is_match skips the capture bookkeeping for those
                if !regex.is_match(bytes) {
                    return None;
                }
                let mut locations = regex.capture_locations();
                regex.captures_read(&mut locations, bytes)?;
                Some((0..locations.len()).map(|group| locations.get(group)).collect())
            }
            Engine::Fancy { exact, approximation } => {
                // An exact match starting at p is also an approximation match starting
                // at p, so the leftmost exact match is found by trying the backtracker
                // anchored at each approximation start, in order. That keeps the
                // backtracker off every other position (the Linux distro OS pattern
                // alone cost 3.6 µs per UA when scanned unanchored).
                let mut from = 0;
                while from <= bytes.len() {
                    let start = approximation.find_at(bytes, from)?.start();
                    let input = fancy_regex::RegexInput::new(bytes).from_pos(start).anchored(true);
                    match exact.captures_input(input) {
                        Ok(Some(captures)) => {
                            return Some(
                                (0..captures.len()).map(|group| captures.get(group).map(|m| (m.start(), m.end()))).collect(),
                            );
                        }
                        Ok(None) => from = start + 1,
                        Err(error) => {
                            tracing::warn!(
                                pattern = self.source,
                                ua_length = haystack.original.len(),
                                error = %error,
                                "user agent regex gave up backtracking; treating it as no match"
                            );
                            return None;
                        }
                    }
                }
                None
            }
        }
    }
}

pub(super) struct CompiledRule {
    pub regexes: Vec<CompiledRegex>,
    pub src: &'static RuleSrc,
}

pub(super) struct Tables {
    pub browser: Vec<CompiledRule>,
    pub cpu: Vec<CompiledRule>,
    pub device: Vec<CompiledRule>,
    pub engine: Vec<CompiledRule>,
    pub os: Vec<CompiledRule>,
}

fn compile_table(item: &'static str, rules: &'static [RuleSrc]) -> Vec<CompiledRule> {
    rules
        .iter()
        .map(|src| CompiledRule {
            regexes: src
                .patterns
                .iter()
                .map(|source| {
                    CompiledRegex::compile(source).unwrap_or_else(|error| {
                        tracing::error!(item, error = %error, "ua-parser regex failed to compile");
                        panic!("ua-parser {item} regex failed to compile: {error}")
                    })
                })
                .collect(),
            src,
        })
        .collect()
}

/// Every table, compiled once on first use (about 30 ms in a release build, so the
/// tracking path should touch it at startup rather than on an event; see
/// `super::warm_up`).
pub(super) static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let started = Instant::now();
    let tables = Tables {
        browser: compile_table("browser", regexes::BROWSER),
        cpu: compile_table("cpu", regexes::CPU),
        device: compile_table("device", regexes::DEVICE),
        engine: compile_table("engine", regexes::ENGINE),
        os: compile_table("os", regexes::OS),
    };
    let all = || {
        [&tables.browser, &tables.cpu, &tables.device, &tables.engine, &tables.os]
            .into_iter()
            .flat_map(|rules| rules.iter().flat_map(|rule| rule.regexes.iter()))
    };
    tracing::info!(
        regexes = all().count(),
        fancy = all().filter(|regex| regex.is_fancy()).count(),
        elapsed_ms = duration_ms(started.elapsed()),
        "ua-parser regex tables compiled"
    );
    tables
});

fn duration_ms(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64() * 1000.0
}

/// `rgxMapper.call(fields, ua, rules)`: the first regex that matches, in rule
/// order, sets its rule's properties; nothing else is touched.
pub(super) fn rgx_mapper(haystack: &Haystack<'_>, rules: &[CompiledRule]) -> Fields {
    let mut fields = Fields::default();
    for rule in rules {
        for regex in &rule.regexes {
            let Some(groups) = regex.captures(haystack) else { continue };
            for (index, prop) in rule.src.props.iter().enumerate() {
                let capture = groups
                    .get(index + 1)
                    .copied()
                    .flatten()
                    .map(|(start, end)| haystack.slice(start, end));
                fields.apply(prop, capture);
            }
            return fields;
        }
    }
    fields
}

/// `majorize`: digits and dots only, up to the first dot.
pub(super) fn majorize(version: Option<&str>) -> Option<String> {
    let version = version?;
    let cleaned: String = version.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
    Some(cleaned.split('.').next().unwrap_or_default().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_regex_compiles() {
        let tables = &*TABLES;
        let regexes: Vec<&CompiledRegex> = [&tables.browser, &tables.cpu, &tables.device, &tables.engine, &tables.os]
            .into_iter()
            .flat_map(|rules| rules.iter().flat_map(|rule| rule.regexes.iter()))
            .collect();
        assert_eq!(regexes.len(), 295);
        // lookarounds or backreferences; the rest run on the regex crate alone
        assert_eq!(regexes.iter().filter(|regex| regex.is_fancy()).count(), 31);
    }

    #[test]
    fn only_known_safe_patterns_capture_inside_repeats() {
        // JS resets captures nested in a repeated group on every iteration, Rust
        // engines keep the last participating value. In the AIX pattern the inner
        // group participates in every iteration, so the two agree.
        let flagged: Vec<&str> = [regexes::BROWSER, regexes::CPU, regexes::DEVICE, regexes::ENGINE, regexes::OS]
            .iter()
            .flat_map(|rules| rules.iter().flat_map(|rule| rule.patterns.iter()))
            .copied()
            .filter(|source| translate(source).unwrap().capture_in_repeated_group)
            .collect();
        assert_eq!(flagged, vec![r"(aix) ((\d)(?=\.|\)| )[\w\.])*"]);
    }

    #[test]
    fn truncation_counts_utf16_units_and_trims_only_when_long() {
        assert_eq!(truncate("  short"), ("  short", false));
        let long = format!("  {}", "a".repeat(600));
        assert_eq!(truncate(&long), (&long[2..502], false));
        let exact = "a".repeat(500);
        assert_eq!(truncate(&exact), (exact.as_str(), false));
        // 499 units then an astral char: JS keeps the high surrogate as unit 500
        let split = format!("{}\u{1F600}tail", "a".repeat(499));
        assert_eq!(truncate(&split), (&split[..499], true));
        let fits = format!("{}\u{1F600}tail", "a".repeat(498));
        assert_eq!(truncate(&fits), (&fits[..502], false));
        // 400 three-byte chars: 1200 bytes but only 400 units
        let wide = "\u{4E2D}".repeat(400);
        assert_eq!(truncate(&wide), (wide.as_str(), false));
    }

    #[test]
    fn haystack_maps_units_to_ascii_and_back() {
        let ua = "a\u{E9}\u{1F600}\u{2028}\u{A0}b";
        let haystack = Haystack::new(ua, false);
        assert_eq!(haystack.bytes(), b"a\x01\x01\x01\n\x0Bb");
        assert_eq!(Haystack::new("Mozilla/5.0 (X11)", false).bytes(), b"mozilla/5.0 (x11)");
        assert_eq!(haystack.slice(0, 2), "a\u{E9}");
        assert_eq!(haystack.slice(2, 4), "\u{1F600}");
        assert_eq!(haystack.slice(6, 7), "b");
    }

    #[test]
    fn majorize_matches_js() {
        assert_eq!(majorize(Some("131.0.6778.85")).as_deref(), Some("131"));
        assert_eq!(majorize(Some("v.1")).as_deref(), Some(""));
        assert_eq!(majorize(Some("1\u{661}2.3")).as_deref(), Some("12"));
        assert_eq!(majorize(None), None);
    }
}
