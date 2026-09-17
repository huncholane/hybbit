//! `new RegExp(pattern)` syntax, ported from V8 14.6.202.34 (Node 26.7.0)
//! `src/regexp/regexp-parser.cc` for patterns without flags.
//!
//! Feature flag rules compile their patterns with `new RegExp(pattern)` and report
//! V8's SyntaxError text to the dashboard, so validation has to reject exactly what
//! V8 rejects, with V8's first error, and accept everything else (Annex B quirks
//! included: `\c` without a letter, `]` and `{` as literals, octal escapes, `\8`).
//! The parser follows `RegExpParserImpl` step by step for the non-Unicode mode,
//! including what is reachable inside it: the `(?ims-ims:...)` modifier groups,
//! duplicate named groups in separate alternatives and group names that switch the
//! scanner to Unicode mode. Unicode (`u`) and Unicode-sets (`v`) syntax is not
//! reachable without flags and is not ported.
//!
//! The result is V8's syntax tree, including the rewrites `RegExpBuilder` applies
//! while parsing (backreferences inside their own group match empty, quantified
//! zero-width atoms collapse), which `compile` turns into a pattern for the matcher.

use std::collections::BTreeMap;

use super::identifier_tables::{ID_CONTINUE, ID_START};

/// `RegExpTree::kInfinity`: unbounded quantifier maxima and overflowing counts.
pub const INFINITY: i32 = i32::MAX;
/// `RegExpMacroAssembler::kMaxCaptures`.
const MAX_CAPTURES: i32 = 1 << 16;
/// `kEndMarker`: what `current()` reads past the end of the pattern.
const END: u32 = 1 << 21;
/// `String::kMaxCodePoint`.
pub const MAX_CODE_POINT: u32 = 0x10ffff;

/// The `RegExpError` values reachable without flags, with V8's message text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegExpError {
    UnterminatedGroup,
    UnmatchedParen,
    EscapeAtEndOfPattern,
    InvalidEscape,
    InvalidUnicodeEscape,
    NothingToRepeat,
    RangeOutOfOrder,
    InvalidQuantifier,
    InvalidGroup,
    MultipleFlagDashes,
    RepeatedFlag,
    InvalidFlagGroup,
    TooManyCaptures,
    InvalidCaptureGroupName,
    DuplicateCaptureGroupName,
    InvalidNamedReference,
    InvalidNamedCaptureReference,
    UnterminatedCharacterClass,
    OutOfOrderCharacterClass,
}

impl RegExpError {
    /// `RegExpErrorString`.
    pub fn message(self) -> &'static str {
        match self {
            RegExpError::UnterminatedGroup => "Unterminated group",
            RegExpError::UnmatchedParen => "Unmatched ')'",
            RegExpError::EscapeAtEndOfPattern => "\\ at end of pattern",
            RegExpError::InvalidEscape => "Invalid escape",
            RegExpError::InvalidUnicodeEscape => "Invalid Unicode escape",
            RegExpError::NothingToRepeat => "Nothing to repeat",
            RegExpError::RangeOutOfOrder => "numbers out of order in {} quantifier",
            RegExpError::InvalidQuantifier => "Invalid quantifier",
            RegExpError::InvalidGroup => "Invalid group",
            RegExpError::MultipleFlagDashes => "Multiple dashes in flag group",
            RegExpError::RepeatedFlag => "Repeated flag in flag group",
            RegExpError::InvalidFlagGroup => "Invalid flag group",
            RegExpError::TooManyCaptures => "Too many captures",
            RegExpError::InvalidCaptureGroupName => "Invalid capture group name",
            RegExpError::DuplicateCaptureGroupName => "Duplicate capture group name",
            RegExpError::InvalidNamedReference => "Invalid named reference",
            RegExpError::InvalidNamedCaptureReference => "Invalid named capture referenced",
            RegExpError::UnterminatedCharacterClass => "Unterminated character class",
            RegExpError::OutOfOrderCharacterClass => "Range out of order in character class",
        }
    }
}

/// The modifiers a group can switch (`RegExpFlags` restricted to i, m and s).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub ignore_case: bool,
    pub multiline: bool,
    pub dot_all: bool,
}

impl Flags {
    fn get(self, flag: u32) -> bool {
        match char::from_u32(flag) {
            Some('i') => self.ignore_case,
            Some('m') => self.multiline,
            _ => self.dot_all,
        }
    }

    fn set(&mut self, flag: u32, value: bool) {
        match char::from_u32(flag) {
            Some('i') => self.ignore_case = value,
            Some('m') => self.multiline = value,
            _ => self.dot_all = value,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assertion {
    StartOfInput,
    StartOfLine,
    EndOfInput,
    EndOfLine,
    Boundary,
    NonBoundary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackReference {
    Numbered(i32),
    /// Resolved against every group carrying the name (duplicates live in separate
    /// alternatives, so at most one of them has participated)
    Named(Vec<u16>),
}

/// V8's `RegExpTree` for the non-Unicode mode. Character data are UTF-16 code units;
/// class ranges are inclusive and may reach `MAX_CODE_POINT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Empty,
    Disjunction(Vec<Node>),
    Alternative(Vec<Node>),
    Char(u16),
    Class { ranges: Vec<(u32, u32)>, negated: bool },
    Assertion(Assertion),
    Capture { index: i32, name: Option<Vec<u16>>, body: Box<Node> },
    Group { flags: Flags, body: Box<Node> },
    Lookaround { positive: bool, behind: bool, body: Box<Node> },
    BackReference(BackReference),
    Quantifier { min: i32, max: i32, greedy: bool, body: Box<Node> },
}

impl Node {
    /// `RegExpTree::max_match`, which decides whether a quantified atom can only match
    /// the empty string. Only zero versus non-zero matters to the parser.
    pub fn max_match(&self) -> i32 {
        match self {
            Node::Empty | Node::Assertion(_) | Node::Lookaround { .. } => 0,
            Node::Char(_) => 1,
            // One code unit, or two for a surrogate pair; never zero
            Node::Class { .. } => 2,
            Node::BackReference(_) => INFINITY,
            Node::Capture { body, .. } | Node::Group { body, .. } => body.max_match(),
            Node::Quantifier { max, body, .. } => {
                let body_max = body.max_match();
                if *max > 0 && body_max > INFINITY / max { INFINITY } else { max * body_max }
            }
            Node::Alternative(nodes) => nodes.iter().fold(0, |total, node| {
                let increase = node.max_match();
                if INFINITY - total < increase { INFINITY } else { total + increase }
            }),
            Node::Disjunction(nodes) => nodes.iter().map(Node::max_match).max().unwrap_or(0),
        }
    }
}

/// A successfully parsed pattern.
#[derive(Clone, Debug)]
pub struct ParsedRegExp {
    pub root: Node,
    pub capture_count: i32,
    /// Every group name with the capture indices that carry it
    pub named_captures: BTreeMap<Vec<u16>, Vec<i32>>,
}

/// `RegExpParser::VerifyRegExpSyntax` for a pattern given as UTF-16 code units and
/// no flags.
pub fn parse(pattern: &[u16]) -> Result<ParsedRegExp, RegExpError> {
    let mut parser = Parser::new(pattern);
    let root = parser.parse_pattern();
    match (parser.failed, root) {
        (Some(error), _) => Err(error),
        (None, Some(root)) => Ok(ParsedRegExp {
            root,
            capture_count: parser.captures_started,
            named_captures: parser.named_captures.unwrap_or_default(),
        }),
        // Every path that returns no tree reports an error first
        (None, None) => Err(RegExpError::UnterminatedGroup),
    }
}

/// `RegExpBuilder` (with its `RegExpTextBuilder`): accumulates terms and alternatives
/// for one disjunction.
#[derive(Debug)]
struct Builder {
    flags: Flags,
    pending_empty: bool,
    /// Text elements (characters and classes) not yet flushed into `terms`
    text: Vec<Node>,
    terms: Vec<Node>,
    alternatives: Vec<Node>,
}

impl Builder {
    fn new(flags: Flags) -> Self {
        Self { flags, pending_empty: false, text: Vec::new(), terms: Vec::new(), alternatives: Vec::new() }
    }

    fn add_character(&mut self, character: u32) {
        self.pending_empty = false;
        self.text.push(Node::Char(character as u16));
    }

    fn add_empty(&mut self) {
        self.pending_empty = true;
    }

    fn add_class_ranges(&mut self, class: Node) {
        self.pending_empty = false;
        self.text.push(class);
    }

    fn add_atom(&mut self, atom: Node) {
        if atom == Node::Empty {
            self.add_empty();
            return;
        }
        self.pending_empty = false;
        match atom {
            Node::Char(_) | Node::Class { .. } => self.text.push(atom),
            other => {
                self.flush_text();
                self.terms.push(other);
            }
        }
    }

    fn add_assertion(&mut self, assertion: Assertion) {
        self.flush_text();
        self.pending_empty = false;
        self.terms.push(Node::Assertion(assertion));
    }

    fn new_alternative(&mut self) {
        self.flush_terms();
    }

    fn flush_text(&mut self) {
        self.terms.append(&mut self.text);
    }

    fn flush_terms(&mut self) {
        self.flush_text();
        let alternative = match self.terms.len() {
            0 => Node::Empty,
            1 => self.terms.pop().unwrap_or(Node::Empty),
            _ => Node::Alternative(std::mem::take(&mut self.terms)),
        };
        self.alternatives.push(alternative);
    }

    fn into_regexp(mut self) -> Node {
        self.flush_terms();
        match self.alternatives.len() {
            0 => Node::Empty,
            1 => self.alternatives.pop().unwrap_or(Node::Empty),
            _ => Node::Disjunction(self.alternatives),
        }
    }

    /// `AddQuantifierToAtom`. False means V8 reports `kInvalidQuantifier` (a quantified
    /// lookbehind).
    fn add_quantifier_to_atom(&mut self, min: i32, max: i32, greedy: bool) -> bool {
        if self.pending_empty {
            self.pending_empty = false;
            return true;
        }
        let atom = if let Some(atom) = self.text.pop() {
            self.flush_text();
            atom
        } else if let Some(atom) = self.terms.pop() {
            if let Node::Lookaround { behind: true, .. } = atom {
                return false;
            }
            if atom.max_match() == 0 {
                if min == 0 {
                    // V8 drops the atom. It is kept as a zero-times loop so the capture
                    // groups inside it keep their numbers; it can never participate.
                    self.terms.push(Node::Quantifier { min: 0, max: 0, greedy: true, body: Box::new(atom) });
                } else {
                    self.terms.push(atom);
                }
                return true;
            }
            atom
        } else {
            // V8: UNREACHABLE (a quantifier only follows an atom)
            return true;
        };
        self.terms.push(Node::Quantifier { min, max, greedy, body: Box::new(atom) });
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroupType {
    Initial,
    Capture,
    PositiveLookaround,
    NegativeLookaround,
    Grouping,
}

/// `RegExpParserState`: one open parenthesis (or the whole pattern).
#[derive(Debug)]
struct State {
    builder: Builder,
    group_type: GroupType,
    lookbehind: bool,
    capture_index: i32,
    capture_name: Option<Vec<u16>>,
    /// Closed intervals of capture indices started in earlier alternatives
    non_participating: Vec<(i32, i32)>,
}

impl State {
    /// `NewAlternative`: captures opened so far in this disjunction cannot take part
    /// in the next alternative.
    fn new_alternative(&mut self, captures_started: i32) {
        if self.capture_index == captures_started {
            return;
        }
        let from = self.capture_index + 1;
        let to = captures_started;
        match self.non_participating.last_mut() {
            Some(last) if last.1 + 1 == to => *last = (last.0.min(from), last.1.max(to)),
            _ => self.non_participating.push((from, to)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InClass {
    Yes,
    No,
}

struct Parser<'a> {
    input: &'a [u16],
    current: u32,
    /// V8's `next_pos_`; signed because rewinding computes before re-reading
    next_pos: isize,
    has_more: bool,
    failed: Option<RegExpError>,
    force_unicode: bool,
    captures_started: i32,
    capture_count: i32,
    is_scanned_for_captures: bool,
    has_named_captures: bool,
    named_captures: Option<BTreeMap<Vec<u16>, Vec<i32>>>,
    named_back_references: Vec<Vec<u16>>,
    states: Vec<State>,
}

const fn ch(character: char) -> u32 {
    character as u32
}

fn is_lead_surrogate(unit: u32) -> bool {
    (0xd800..=0xdbff).contains(&unit)
}

fn is_trail_surrogate(unit: u32) -> bool {
    (0xdc00..=0xdfff).contains(&unit)
}

fn combine_surrogates(lead: u32, trail: u32) -> u32 {
    0x10000 + ((lead - 0xd800) << 10) + (trail - 0xdc00)
}

fn hex_value(character: u32) -> Option<u32> {
    char::from_u32(character).and_then(|character| character.to_digit(16))
}

fn is_decimal_digit(character: u32) -> bool {
    (ch('0')..=ch('9')).contains(&character)
}

fn in_ranges(table: &[(u32, u32)], character: u32) -> bool {
    table
        .binary_search_by(|&(from, to)| {
            if to < character {
                std::cmp::Ordering::Less
            } else if from > character {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `IsIdentifierStart`: ID_Start plus `$`, `_` and `\`.
fn is_identifier_start(character: u32) -> bool {
    character == ch('$') || character == ch('_') || character == ch('\\') || in_ranges(ID_START, character)
}

/// `IsIdentifierPart`: ID_Continue plus `$`, `_`, `\`, ZWNJ and ZWJ.
fn is_identifier_part(character: u32) -> bool {
    character == ch('$')
        || character == ch('_')
        || character == ch('\\')
        || character == 0x200c
        || character == 0x200d
        || in_ranges(ID_CONTINUE, character)
}

/// `push_code_unit`: a code point appended as UTF-16.
fn push_code_unit(name: &mut Vec<u16>, code_point: u32) {
    if code_point <= 0xffff {
        name.push(code_point as u16);
    } else {
        let offset = code_point - 0x10000;
        name.push((0xd800 + (offset >> 10)) as u16);
        name.push((0xdc00 + (offset & 0x3ff)) as u16);
    }
}

/// `CharacterRange::AddClassEscape` without Unicode case equivalents.
pub fn class_escape_ranges(kind: u32, ranges: &mut Vec<(u32, u32)>) {
    const SPACE: &[(u32, u32)] = &[
        (0x09, 0x0d),
        (0x20, 0x20),
        (0xa0, 0xa0),
        (0x1680, 0x1680),
        (0x2000, 0x200a),
        (0x2028, 0x2029),
        (0x202f, 0x202f),
        (0x205f, 0x205f),
        (0x3000, 0x3000),
        (0xfeff, 0xfeff),
    ];
    const WORD: &[(u32, u32)] = &[(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)];
    const DIGIT: &[(u32, u32)] = &[(0x30, 0x39)];
    const LINE_TERMINATOR: &[(u32, u32)] = &[(0x0a, 0x0a), (0x0d, 0x0d), (0x2028, 0x2029)];

    let (table, negated) = match char::from_u32(kind) {
        Some('s') => (SPACE, false),
        Some('S') => (SPACE, true),
        Some('w') => (WORD, false),
        Some('W') => (WORD, true),
        Some('d') => (DIGIT, false),
        Some('D') => (DIGIT, true),
        Some('n') => (LINE_TERMINATOR, false),
        Some('.') => (LINE_TERMINATOR, true),
        _ => {
            ranges.push((0, MAX_CODE_POINT));
            return;
        }
    };
    if !negated {
        ranges.extend_from_slice(table);
        return;
    }
    // AddClassNegated
    let mut last = 0;
    for &(from, to) in table {
        if from > last {
            ranges.push((last, from - 1));
        }
        last = to + 1;
    }
    ranges.push((last, MAX_CODE_POINT));
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u16]) -> Self {
        let mut parser = Self {
            input,
            current: END,
            next_pos: 0,
            has_more: true,
            failed: None,
            force_unicode: false,
            captures_started: 0,
            capture_count: 0,
            is_scanned_for_captures: false,
            has_named_captures: false,
            named_captures: None,
            named_back_references: Vec::new(),
            states: Vec::new(),
        };
        parser.advance();
        parser
    }

    fn len(&self) -> isize {
        self.input.len() as isize
    }

    fn is_unicode_mode(&self) -> bool {
        self.force_unicode
    }

    fn has_next(&self) -> bool {
        self.next_pos < self.len()
    }

    /// `ReadNext`: one code unit, or a whole surrogate pair in Unicode mode.
    fn read_next(&self) -> (u32, isize) {
        let mut position = self.next_pos;
        let first = u32::from(self.input[position as usize]);
        position += 1;
        let mut result = first;
        if self.is_unicode_mode() && position < self.len() && is_lead_surrogate(first) {
            let second = u32::from(self.input[position as usize]);
            if is_trail_surrogate(second) {
                result = combine_surrogates(first, second);
                position += 1;
            }
        }
        (result, position)
    }

    fn next(&self) -> u32 {
        if self.has_next() { self.read_next().0 } else { END }
    }

    fn advance(&mut self) {
        if self.has_next() {
            let (character, position) = self.read_next();
            self.current = character;
            self.next_pos = position;
        } else {
            self.current = END;
            // position() then points one past the last character, so Reset() to it works
            self.next_pos = self.len() + 1;
            self.has_more = false;
        }
    }

    fn advance_by(&mut self, distance: isize) {
        self.next_pos += distance - 1;
        self.advance();
    }

    fn rewind_by_one_codepoint(&mut self) {
        if !self.has_more {
            return;
        }
        let rewind_by = if self.current > 0xffff { -2 } else { -1 };
        self.advance_by(rewind_by);
    }

    fn reset(&mut self, position: isize) {
        self.next_pos = position;
        self.has_more = position < self.len();
        self.advance();
    }

    fn position(&self) -> isize {
        let current_is_surrogate_pair = self.current != END && self.current > 0xffff;
        self.next_pos - if current_is_surrogate_pair { 2 } else { 1 }
    }

    /// `ReportError`: keeps the first error and zips to the end of the input.
    fn report_error(&mut self, error: RegExpError) {
        if self.failed.is_some() {
            return;
        }
        self.failed = Some(error);
        self.current = END;
        self.next_pos = self.len();
        self.has_more = false;
    }

    fn failed(&self) -> bool {
        self.failed.is_some()
    }

    fn builder(&mut self) -> &mut Builder {
        let state = self.states.last_mut().expect("parser state");
        &mut state.builder
    }

    fn parse_pattern(&mut self) -> Option<Node> {
        let result = self.parse_disjunction()?;
        self.patch_named_back_references();
        if self.failed() {
            return None;
        }
        Some(result)
    }

    /// `ParseDisjunction`: the main loop over terms, with an explicit stack of open
    /// groups.
    fn parse_disjunction(&mut self) -> Option<Node> {
        self.states.push(State {
            builder: Builder::new(Flags::default()),
            group_type: GroupType::Initial,
            lookbehind: false,
            capture_index: 0,
            capture_name: None,
            non_participating: Vec::new(),
        });

        loop {
            let current = self.current;
            if current == END {
                if self.failed() {
                    return None;
                }
                if self.states.len() > 1 {
                    self.report_error(RegExpError::UnterminatedGroup);
                    return None;
                }
                let state = self.states.pop().expect("initial state");
                return Some(state.builder.into_regexp());
            }

            match char::from_u32(current) {
                Some(')') => {
                    if self.states.len() == 1 {
                        self.report_error(RegExpError::UnmatchedParen);
                        return None;
                    }
                    self.advance();
                    let state = self.states.pop().expect("group state");
                    let flags = state.builder.flags;
                    let body = Box::new(state.builder.into_regexp());
                    let node = match state.group_type {
                        GroupType::Capture => {
                            if let Some(name) = &state.capture_name
                                && !self.create_named_capture_at_index(
                                    name,
                                    &state.non_participating,
                                    state.capture_index,
                                )
                            {
                                return None;
                            }
                            Node::Capture { index: state.capture_index, name: state.capture_name, body }
                        }
                        GroupType::Grouping => Node::Group { flags, body },
                        GroupType::PositiveLookaround | GroupType::NegativeLookaround => Node::Lookaround {
                            positive: state.group_type == GroupType::PositiveLookaround,
                            behind: state.lookbehind,
                            body,
                        },
                        GroupType::Initial => unreachable!("the initial state is never closed"),
                    };
                    self.builder().add_atom(node);
                }
                Some('|') => {
                    self.advance();
                    let captures_started = self.captures_started;
                    let state = self.states.last_mut().expect("parser state");
                    state.new_alternative(captures_started);
                    state.builder.new_alternative();
                    continue;
                }
                Some('*' | '+' | '?') => {
                    self.report_error(RegExpError::NothingToRepeat);
                    return None;
                }
                Some('^') => {
                    self.advance();
                    let builder = self.builder();
                    let assertion =
                        if builder.flags.multiline { Assertion::StartOfLine } else { Assertion::StartOfInput };
                    builder.add_assertion(assertion);
                    continue;
                }
                Some('$') => {
                    self.advance();
                    let builder = self.builder();
                    let assertion = if builder.flags.multiline { Assertion::EndOfLine } else { Assertion::EndOfInput };
                    builder.add_assertion(assertion);
                    continue;
                }
                Some('.') => {
                    self.advance();
                    let mut ranges = Vec::new();
                    let kind = if self.builder().flags.dot_all { ch('*') } else { ch('.') };
                    class_escape_ranges(kind, &mut ranges);
                    self.builder().add_class_ranges(Node::Class { ranges, negated: false });
                }
                Some('(') => {
                    if !self.parse_open_parenthesis() {
                        return None;
                    }
                    continue;
                }
                Some('[') => {
                    let class = self.parse_character_class()?;
                    self.builder().add_class_ranges(class);
                }
                Some('\\') => {
                    if !self.parse_atom_escape()? {
                        continue;
                    }
                }
                Some('{') => {
                    let parsed = self.parse_interval_quantifier();
                    if self.failed() {
                        return None;
                    }
                    if parsed.is_some() {
                        self.report_error(RegExpError::NothingToRepeat);
                        return None;
                    }
                    self.builder().add_character(current);
                    self.advance();
                }
                // `}` and `]` are literals outside Unicode mode, like every other character
                _ => {
                    self.builder().add_character(current);
                    self.advance();
                }
            }

            // QuantifierPrefix
            let (min, max) = match char::from_u32(self.current) {
                Some('*') => {
                    self.advance();
                    (0, INFINITY)
                }
                Some('+') => {
                    self.advance();
                    (1, INFINITY)
                }
                Some('?') => {
                    self.advance();
                    (0, 1)
                }
                Some('{') => match self.parse_interval_quantifier() {
                    Some((min, max)) => {
                        if max < min {
                            self.report_error(RegExpError::RangeOutOfOrder);
                            return None;
                        }
                        (min, max)
                    }
                    None => continue,
                },
                _ => continue,
            };
            let mut greedy = true;
            if self.current == ch('?') {
                greedy = false;
                self.advance();
            }
            if !self.builder().add_quantifier_to_atom(min, max, greedy) {
                self.report_error(RegExpError::InvalidQuantifier);
                return None;
            }
        }
    }

    /// The `case '\\'` arm of `ParseDisjunction`. `Some(true)` continues with a
    /// quantifier check (`break`), `Some(false)` skips it (`continue`), `None` failed.
    fn parse_atom_escape(&mut self) -> Option<bool> {
        let next = self.next();
        if next == END {
            self.report_error(RegExpError::EscapeAtEndOfPattern);
            return None;
        }
        match char::from_u32(next) {
            Some('1'..='9') => {
                let backreference = self.parse_back_reference_index();
                if self.failed() {
                    return None;
                }
                if let Some(index) = backreference {
                    if self.is_inside_capture_group_index(index) {
                        // Nothing can have been captured yet, so V8 matches empty
                        self.builder().add_empty();
                    } else {
                        self.builder().add_atom(Node::BackReference(BackReference::Numbered(index)));
                    }
                    return Some(true);
                }
                let first_digit = self.next();
                if first_digit == ch('8') || first_digit == ch('9') {
                    self.builder().add_character(first_digit);
                    self.advance_by(2);
                    return Some(true);
                }
                self.advance();
                let octal = self.parse_octal_literal();
                self.builder().add_character(octal);
                Some(true)
            }
            Some('0') => {
                self.advance();
                let octal = self.parse_octal_literal();
                self.builder().add_character(octal);
                Some(true)
            }
            Some('b') => {
                self.advance_by(2);
                self.builder().add_assertion(Assertion::Boundary);
                Some(false)
            }
            Some('B') => {
                self.advance_by(2);
                self.builder().add_assertion(Assertion::NonBoundary);
                Some(false)
            }
            Some('d' | 'D' | 's' | 'S' | 'w' | 'W') => {
                let mut ranges = Vec::new();
                class_escape_ranges(next, &mut ranges);
                self.advance_by(2);
                self.builder().add_class_ranges(Node::Class { ranges, negated: false });
                Some(true)
            }
            Some('p' | 'P') => {
                // Property escapes need Unicode mode; otherwise an identity escape
                self.advance_by(2);
                self.builder().add_character(next);
                Some(true)
            }
            Some('k') => {
                let has_named_captures = self.has_named_captures_scan(InClass::No);
                if self.failed() {
                    return None;
                }
                if has_named_captures {
                    self.advance_by(2);
                    self.parse_named_back_reference();
                    if self.failed() {
                        return None;
                    }
                    return Some(true);
                }
                let character = self.parse_character_escape(InClass::No);
                if self.failed() {
                    return None;
                }
                self.builder().add_character(character);
                Some(true)
            }
            _ => {
                let character = self.parse_character_escape(InClass::No);
                if self.failed() {
                    return None;
                }
                self.builder().add_character(character);
                Some(true)
            }
        }
    }

    /// `ParseOpenParenthesis`: pushes the new group state, or reports an error and
    /// returns false.
    fn parse_open_parenthesis(&mut self) -> bool {
        let top = self.states.last().expect("parser state");
        let mut lookbehind = top.lookbehind;
        let mut flags = top.builder.flags;
        let non_participating = top.non_participating.clone();
        let mut is_named_capture = false;
        let mut subexpression = GroupType::Capture;
        let mut parsing_modifiers = false;
        let mut modifiers_polarity = true;
        let mut modifiers = Flags::default();
        let mut modifiers_seen = false;

        self.advance();
        if self.current == ch('?') {
            loop {
                let next = self.next();
                match char::from_u32(next) {
                    Some('-') => {
                        self.advance();
                        parsing_modifiers = true;
                        if !modifiers_polarity {
                            self.report_error(RegExpError::MultipleFlagDashes);
                            return false;
                        }
                        modifiers_polarity = false;
                    }
                    Some('m' | 'i' | 's') => {
                        self.advance();
                        parsing_modifiers = true;
                        if modifiers.get(next) {
                            self.report_error(RegExpError::RepeatedFlag);
                            return false;
                        }
                        modifiers.set(next, true);
                        modifiers_seen = true;
                        flags.set(next, modifiers_polarity);
                    }
                    Some(':') => {
                        self.advance_by(2);
                        parsing_modifiers = false;
                        subexpression = GroupType::Grouping;
                    }
                    Some('=') => {
                        self.advance_by(2);
                        if parsing_modifiers {
                            self.report_error(RegExpError::InvalidGroup);
                            return false;
                        }
                        lookbehind = false;
                        subexpression = GroupType::PositiveLookaround;
                    }
                    Some('!') => {
                        self.advance_by(2);
                        if parsing_modifiers {
                            self.report_error(RegExpError::InvalidGroup);
                            return false;
                        }
                        lookbehind = false;
                        subexpression = GroupType::NegativeLookaround;
                    }
                    Some('<') => {
                        self.advance();
                        if parsing_modifiers {
                            self.report_error(RegExpError::InvalidGroup);
                            return false;
                        }
                        if self.next() == ch('=') {
                            self.advance_by(2);
                            lookbehind = true;
                            subexpression = GroupType::PositiveLookaround;
                        } else if self.next() == ch('!') {
                            self.advance_by(2);
                            lookbehind = true;
                            subexpression = GroupType::NegativeLookaround;
                        } else {
                            is_named_capture = true;
                            self.has_named_captures = true;
                            self.advance();
                        }
                    }
                    _ => {
                        self.report_error(RegExpError::InvalidGroup);
                        return false;
                    }
                }
                if !parsing_modifiers {
                    break;
                }
            }
        }
        if !modifiers_polarity && !modifiers_seen {
            self.report_error(RegExpError::InvalidFlagGroup);
            return false;
        }

        let mut capture_name = None;
        if subexpression == GroupType::Capture {
            if self.captures_started >= MAX_CAPTURES {
                self.report_error(RegExpError::TooManyCaptures);
                return false;
            }
            self.captures_started += 1;
            if is_named_capture {
                match self.parse_capture_group_name() {
                    Some(name) => capture_name = Some(name),
                    None => return false,
                }
            }
        }

        self.states.push(State {
            builder: Builder::new(flags),
            group_type: subexpression,
            lookbehind,
            capture_index: self.captures_started,
            capture_name,
            non_participating,
        });
        true
    }

    /// `ScanForCaptures`: counts every capturing group in the pattern (and notes named
    /// ones) without parsing, then returns to the current position.
    fn scan_for_captures(&mut self, in_class: InClass) {
        let saved_position = self.position();
        let mut capture_count = self.captures_started;
        if in_class == InClass::Yes {
            while self.current != END {
                let character = self.current;
                self.advance();
                if character == ch('\\') {
                    self.advance();
                } else if character == ch(']') {
                    break;
                }
            }
        }
        while self.current != END {
            let character = self.current;
            self.advance();
            if character == ch('\\') {
                self.advance();
            } else if character == ch('[') {
                while self.current != END {
                    let inner = self.current;
                    self.advance();
                    if inner == ch('\\') {
                        self.advance();
                    } else if inner == ch(']') {
                        break;
                    }
                }
            } else if character == ch('(') {
                if self.current == ch('?') {
                    self.advance();
                    if self.current != ch('<') {
                        continue;
                    }
                    self.advance();
                    if self.current == ch('=') || self.current == ch('!') {
                        continue;
                    }
                    self.has_named_captures = true;
                }
                capture_count += 1;
            }
        }
        self.capture_count = capture_count;
        self.is_scanned_for_captures = true;
        self.reset(saved_position);
    }

    /// `ParseBackReferenceIndex`: a decimal escape naming an existing group, or None
    /// with the position restored to the backslash.
    fn parse_back_reference_index(&mut self) -> Option<i32> {
        let start = self.position();
        let mut value = (self.next() - ch('0')) as i32;
        self.advance_by(2);
        loop {
            let character = self.current;
            if !is_decimal_digit(character) {
                break;
            }
            value = 10 * value + (character - ch('0')) as i32;
            if value > MAX_CAPTURES {
                self.reset(start);
                return None;
            }
            self.advance();
        }
        if value > self.captures_started {
            if !self.is_scanned_for_captures {
                self.scan_for_captures(InClass::No);
            }
            if value > self.capture_count {
                self.reset(start);
                return None;
            }
        }
        Some(value)
    }

    /// `ParseCaptureGroupName`: an identifier (with `\u` escapes and surrogate pairs,
    /// as in Unicode mode) followed by `>`.
    fn parse_capture_group_name(&mut self) -> Option<Vec<u16>> {
        self.rewind_by_one_codepoint();
        let mut name = Vec::new();
        self.force_unicode = true;
        let mut at_start = true;
        let outcome = loop {
            self.advance();
            let mut character = self.current;

            if character == ch('\\') && self.next() == ch('u') {
                self.advance_by(2);
                match self.parse_unicode_escape() {
                    Some(value) => character = value,
                    None => {
                        self.report_error(RegExpError::InvalidUnicodeEscape);
                        break false;
                    }
                }
                self.rewind_by_one_codepoint();
            }

            // The backslash is misclassified as both ID_Start and ID_Continue
            if character == ch('\\') {
                self.report_error(RegExpError::InvalidCaptureGroupName);
                break false;
            }

            if at_start {
                if !is_identifier_start(character) {
                    self.report_error(RegExpError::InvalidCaptureGroupName);
                    break false;
                }
                push_code_unit(&mut name, character);
                at_start = false;
            } else if character == ch('>') {
                break true;
            } else if is_identifier_part(character) {
                push_code_unit(&mut name, character);
            } else {
                self.report_error(RegExpError::InvalidCaptureGroupName);
                break false;
            }
        };
        self.force_unicode = false;
        if !outcome {
            return None;
        }
        self.advance();
        Some(name)
    }

    /// `CreateNamedCaptureAtIndex`: registers a group name, rejecting duplicates that
    /// could participate in the same match.
    fn create_named_capture_at_index(&mut self, name: &[u16], non_participating: &[(i32, i32)], index: i32) -> bool {
        let named_captures = self.named_captures.get_or_insert_with(BTreeMap::new);
        if let Some(indices) = named_captures.get(name) {
            for &named_index in indices {
                let mut is_duplicate = true;
                for &(from, to) in non_participating {
                    if from <= named_index && named_index <= to {
                        is_duplicate = false;
                        break;
                    }
                    if named_index <= from {
                        break;
                    }
                }
                if is_duplicate {
                    self.report_error(RegExpError::DuplicateCaptureGroupName);
                    return false;
                }
            }
        }
        // A group of the same name enclosing this one is a duplicate in the same disjunct
        if self.states.iter().any(|state| state.capture_name.as_deref() == Some(name)) {
            self.report_error(RegExpError::DuplicateCaptureGroupName);
            return false;
        }
        self.named_captures.get_or_insert_with(BTreeMap::new).entry(name.to_vec()).or_default().push(index);
        true
    }

    /// `ParseNamedBackReference`, positioned on the `<` of `\k<name>`.
    fn parse_named_back_reference(&mut self) {
        if self.current != ch('<') {
            self.report_error(RegExpError::InvalidNamedReference);
            return;
        }
        self.advance();
        let Some(name) = self.parse_capture_group_name() else {
            return;
        };
        if self.states.iter().any(|state| state.capture_name.as_deref() == Some(name.as_slice())) {
            self.builder().add_empty();
        } else {
            self.builder().add_atom(Node::BackReference(BackReference::Named(name.clone())));
            self.named_back_references.push(name);
        }
    }

    /// `PatchNamedBackReferences`: every `\k<name>` must name some group.
    fn patch_named_back_references(&mut self) {
        if self.named_back_references.is_empty() {
            return;
        }
        let Some(named_captures) = &self.named_captures else {
            self.report_error(RegExpError::InvalidNamedCaptureReference);
            return;
        };
        if self.named_back_references.iter().any(|name| !named_captures.contains_key(name)) {
            self.report_error(RegExpError::InvalidNamedCaptureReference);
        }
    }

    /// `RegExpParserState::IsInsideCaptureGroup(int)`.
    fn is_inside_capture_group_index(&self, index: i32) -> bool {
        for state in self.states.iter().rev() {
            if state.group_type != GroupType::Capture {
                continue;
            }
            if index == state.capture_index {
                return true;
            }
            if index > state.capture_index {
                return false;
            }
        }
        false
    }

    /// `HasNamedCaptures`.
    fn has_named_captures_scan(&mut self, in_class: InClass) -> bool {
        if self.has_named_captures || self.is_scanned_for_captures {
            return self.has_named_captures;
        }
        self.scan_for_captures(in_class);
        self.has_named_captures
    }

    /// `ParseIntervalQuantifier`: `{n}`, `{n,}` or `{n,m}`, else None with the position
    /// restored to the brace.
    fn parse_interval_quantifier(&mut self) -> Option<(i32, i32)> {
        let start = self.position();
        self.advance();
        if !is_decimal_digit(self.current) {
            self.reset(start);
            return None;
        }
        let mut min: i32 = 0;
        while is_decimal_digit(self.current) {
            let next = (self.current - ch('0')) as i32;
            if min > (INFINITY - next) / 10 {
                loop {
                    self.advance();
                    if !is_decimal_digit(self.current) {
                        break;
                    }
                }
                min = INFINITY;
                break;
            }
            min = 10 * min + next;
            self.advance();
        }
        let mut max: i32 = 0;
        if self.current == ch('}') {
            max = min;
            self.advance();
        } else if self.current == ch(',') {
            self.advance();
            if self.current == ch('}') {
                max = INFINITY;
                self.advance();
            } else {
                while is_decimal_digit(self.current) {
                    let next = (self.current - ch('0')) as i32;
                    if max > (INFINITY - next) / 10 {
                        loop {
                            self.advance();
                            if !is_decimal_digit(self.current) {
                                break;
                            }
                        }
                        max = INFINITY;
                        break;
                    }
                    max = 10 * max + next;
                    self.advance();
                }
                if self.current != ch('}') {
                    self.reset(start);
                    return None;
                }
                self.advance();
            }
        } else {
            self.reset(start);
            return None;
        }
        Some((min, max))
    }

    /// `ParseOctalLiteral`: up to three octal digits with a value below 256.
    fn parse_octal_literal(&mut self) -> u32 {
        let mut value = self.current.wrapping_sub(ch('0'));
        self.advance();
        if (ch('0')..=ch('7')).contains(&self.current) {
            value = value * 8 + self.current - ch('0');
            self.advance();
            if value < 32 && (ch('0')..=ch('7')).contains(&self.current) {
                value = value * 8 + self.current - ch('0');
                self.advance();
            }
        }
        value
    }

    /// `ParseHexEscape`: exactly `length` hex digits, else None with the position
    /// restored.
    fn parse_hex_escape(&mut self, length: usize) -> Option<u32> {
        let start = self.position();
        let mut value = 0;
        for _ in 0..length {
            let Some(digit) = hex_value(self.current) else {
                self.reset(start);
                return None;
            };
            value = value * 16 + digit;
            self.advance();
        }
        Some(value)
    }

    /// `ParseUnicodeEscape` (the `\u` is already consumed).
    fn parse_unicode_escape(&mut self) -> Option<u32> {
        if self.current == ch('{') && self.is_unicode_mode() {
            let start = self.position();
            self.advance();
            if let Some(value) = self.parse_unlimited_length_hex_number(MAX_CODE_POINT)
                && self.current == ch('}')
            {
                self.advance();
                return Some(value);
            }
            self.reset(start);
            return None;
        }
        let result = self.parse_hex_escape(4);
        if let Some(lead) = result
            && self.is_unicode_mode()
            && is_lead_surrogate(lead)
            && self.current == ch('\\')
        {
            let start = self.position();
            if self.next() == ch('u') {
                self.advance_by(2);
                if let Some(trail) = self.parse_hex_escape(4)
                    && is_trail_surrogate(trail)
                {
                    return Some(combine_surrogates(lead, trail));
                }
            }
            self.reset(start);
        }
        result
    }

    /// `ParseUnlimitedLengthHexNumber`.
    fn parse_unlimited_length_hex_number(&mut self, max_value: u32) -> Option<u32> {
        let mut value: u32 = 0;
        let mut digit = hex_value(self.current)?;
        loop {
            value = value * 16 + digit;
            if value > max_value {
                return None;
            }
            self.advance();
            match hex_value(self.current) {
                Some(next) => digit = next,
                None => return Some(value),
            }
        }
    }

    /// `ParseCharacterEscape` outside Unicode mode, positioned on the backslash.
    fn parse_character_escape(&mut self, in_class: InClass) -> u32 {
        self.advance();
        let character = self.current;
        match char::from_u32(character) {
            Some('f') => {
                self.advance();
                0x0c
            }
            Some('n') => {
                self.advance();
                0x0a
            }
            Some('r') => {
                self.advance();
                0x0d
            }
            Some('t') => {
                self.advance();
                0x09
            }
            Some('v') => {
                self.advance();
                0x0b
            }
            Some('c') => {
                let control_letter = self.next();
                let letter = control_letter & !(ch('A') ^ ch('a'));
                if (ch('A')..=ch('Z')).contains(&letter) {
                    self.advance_by(2);
                    return control_letter & 0x1f;
                }
                if in_class == InClass::Yes && (is_decimal_digit(control_letter) || control_letter == ch('_')) {
                    self.advance_by(2);
                    return control_letter & 0x1f;
                }
                // Read the backslash as a literal; the `c` is parsed again after it
                ch('\\')
            }
            Some('0') if !is_decimal_digit(self.next()) => {
                self.advance();
                0
            }
            Some('0'..='7') => self.parse_octal_literal(),
            Some('x') => {
                self.advance();
                self.parse_hex_escape(2).unwrap_or(ch('x'))
            }
            Some('u') => {
                self.advance();
                self.parse_unicode_escape().unwrap_or(ch('u'))
            }
            _ => {
                // IdentityEscape: any character, except `\k` once named groups exist
                self.advance();
                if character == ch('k') && self.has_named_captures_scan(in_class) {
                    self.report_error(RegExpError::InvalidEscape);
                    return 0;
                }
                character
            }
        }
    }

    /// `ParseCharacterClass` outside Unicode-sets mode.
    fn parse_character_class(&mut self) -> Option<Node> {
        self.advance();
        let mut negated = false;
        if self.current == ch('^') {
            negated = true;
            self.advance();
        }
        let mut ranges = Vec::new();
        if self.current == ch(']') {
            self.advance();
            return Some(Node::Class { ranges, negated });
        }
        self.parse_class_ranges(&mut ranges);
        if self.failed() {
            return None;
        }
        if !self.has_more {
            self.report_error(RegExpError::UnterminatedCharacterClass);
            return None;
        }
        self.advance();
        Some(Node::Class { ranges, negated })
    }

    /// `ParseClassRanges`.
    fn parse_class_ranges(&mut self, ranges: &mut Vec<(u32, u32)>) {
        while self.has_more && self.current != ch(']') {
            let (first, first_is_class) = self.parse_class_escape(ranges);
            if self.failed() {
                return;
            }
            if self.current == ch('-') {
                self.advance();
                if !self.has_more {
                    // The caller reports the unterminated class
                    break;
                } else if self.current == ch(']') {
                    if !first_is_class {
                        ranges.push((first, first));
                    }
                    ranges.push((ch('-'), ch('-')));
                    break;
                }
                let (second, second_is_class) = self.parse_class_escape(ranges);
                if self.failed() {
                    return;
                }
                if first_is_class || second_is_class {
                    // An escaped class at either end makes the dash literal
                    if !first_is_class {
                        ranges.push((first, first));
                    }
                    ranges.push((ch('-'), ch('-')));
                    if !second_is_class {
                        ranges.push((second, second));
                    }
                    continue;
                }
                if first > second {
                    self.report_error(RegExpError::OutOfOrderCharacterClass);
                    return;
                }
                ranges.push((first, second));
            } else if !first_is_class {
                ranges.push((first, first));
            }
        }
    }

    /// `ParseClassEscape`: a class atom. Returns the character, or true in the second
    /// slot when an escaped class (`\d`, ...) was added to `ranges` instead.
    fn parse_class_escape(&mut self, ranges: &mut Vec<(u32, u32)>) -> (u32, bool) {
        if self.current != ch('\\') {
            let character = self.current;
            self.advance();
            return (character, false);
        }
        let next = self.next();
        if next == ch('b') {
            self.advance_by(2);
            return (0x08, false);
        }
        if next == END {
            self.report_error(RegExpError::EscapeAtEndOfPattern);
            return (0, false);
        }
        if matches!(char::from_u32(next), Some('d' | 'D' | 's' | 'S' | 'w' | 'W')) {
            class_escape_ranges(next, ranges);
            self.advance_by(2);
            return (0, true);
        }
        (self.parse_character_escape(InClass::Yes), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(pattern: &str) -> Option<&'static str> {
        let units: Vec<u16> = pattern.encode_utf16().collect();
        parse(&units).err().map(RegExpError::message)
    }

    #[test]
    fn accepts_annex_b_syntax() {
        for pattern in [
            "a]",
            "a}",
            "{",
            "a{",
            "a{,5}",
            "x{2,3}{",
            "\\c",
            "[\\c]",
            "\\c1",
            "[\\c_]",
            "\\8",
            "\\18",
            "\\0123",
            "\\k",
            "\\p{L}",
            "\\u{1F600}",
            "(?=a)*",
            "(?!a){2}",
            "(?<a>x)|(?<a>y)",
            "(?i:a)",
            "(?i-ms:a)",
            "(?i-:a)",
            "(?<\\u{1d465}>a)",
            "(?<$_\u{200c}>a)",
            "\\2(a)(b)",
            "[a-]",
            "[-a]",
            "[\\d-z]",
            "[\\w-\\d]",
            "(a\\1)",
            "(?<n>a\\k<n>)",
            "\\k<n>(?<n>x)",
            "a{2147483648}",
            "",
        ] {
            assert_eq!(error(pattern), None, "{pattern:?} should parse");
        }
    }

    #[test]
    fn reports_the_first_v8_error() {
        let cases = [
            ("(", "Unterminated group"),
            ("a)", "Unmatched ')'"),
            ("\\", "\\ at end of pattern"),
            ("[\\", "\\ at end of pattern"),
            ("*", "Nothing to repeat"),
            ("a**", "Nothing to repeat"),
            ("^*", "Nothing to repeat"),
            ("\\b+", "Nothing to repeat"),
            ("{1}", "Nothing to repeat"),
            ("a{2}{3}", "Nothing to repeat"),
            ("a{2,1}", "numbers out of order in {} quantifier"),
            ("(?<=a)*", "Invalid quantifier"),
            ("(?", "Invalid group"),
            ("(?i)", "Invalid group"),
            ("(?i=a)", "Invalid group"),
            ("(?--i:a)", "Multiple dashes in flag group"),
            ("(?ii:a)", "Repeated flag in flag group"),
            ("(?i-i:a)", "Repeated flag in flag group"),
            ("(?-:a)", "Invalid flag group"),
            ("(?<1a>x)", "Invalid capture group name"),
            ("(?<a", "Invalid capture group name"),
            ("(?<\\u{110000}>x)", "Invalid Unicode escape"),
            ("(?<a>x)(?<a>y)", "Duplicate capture group name"),
            ("(?<a>(?<a>y))", "Duplicate capture group name"),
            ("\\k<a>(?<b>x)", "Invalid named capture referenced"),
            ("\\k(?<b>x)", "Invalid named reference"),
            ("[\\k](?<b>x)", "Invalid escape"),
            ("[a", "Unterminated character class"),
            ("[z-a]", "Range out of order in character class"),
        ];
        for (pattern, message) in cases {
            assert_eq!(error(pattern), Some(message), "{pattern:?}");
        }
    }

    #[test]
    fn quantified_zero_width_atoms_collapse_like_v8() {
        let units: Vec<u16> = "(?=a)*b".encode_utf16().collect();
        let parsed = parse(&units).expect("valid");
        assert_eq!(
            parsed.root,
            Node::Alternative(vec![
                Node::Quantifier {
                    min: 0,
                    max: 0,
                    greedy: true,
                    body: Box::new(Node::Lookaround {
                        positive: true,
                        behind: false,
                        body: Box::new(Node::Char(u16::from(b'a'))),
                    }),
                },
                Node::Char(u16::from(b'b')),
            ])
        );
    }
}
