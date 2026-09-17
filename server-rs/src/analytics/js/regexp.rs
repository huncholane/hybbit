//! `new RegExp(pattern)` syntax checking, ported from V8 13.6
//! `src/regexp/regexp-parser.cc` for patterns without flags (Annex B,
//! non-unicode mode). Only the parts that decide whether the pattern is valid
//! and which error it reports are kept; no AST is built.
//!
//! Stored segments surface the error text to API clients, e.g.
//! `Invalid regular expression: /(unclosed/: Unterminated group`.

use std::collections::BTreeMap;

use super::string::{is_identifier_part, is_identifier_start};

const END_MARKER: u32 = 1 << 21;
const MAX_CAPTURES: i32 = 1 << 16;
const INFINITY: i32 = i32::MAX;

/// `RegExpError` messages that a flagless pattern can produce.
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

/// Checks `new RegExp(pattern)`; the error is the `SyntaxError` message V8 throws.
pub fn validate(pattern: &str) -> Result<(), String> {
    let units: Vec<u16> = pattern.encode_utf16().collect();
    let mut parser = Parser::new(&units);
    parser.parse_disjunction();
    if parser.failed.is_none() {
        parser.patch_named_back_references();
    }
    match parser.failed {
        None => Ok(()),
        Some(error) => Err(format!("Invalid regular expression: /{pattern}/: {}", error.message())),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupType {
    Initial,
    Capture,
    PositiveLookaround,
    NegativeLookaround,
    Grouping,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lookaround {
    Ahead,
    Behind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClassState {
    InClass,
    NotInClass,
}

struct State {
    group_type: GroupType,
    lookaround: Lookaround,
    capture_index: i32,
    capture_name: Option<Vec<u16>>,
    /// Capture indices `]first, second]` in other alternatives (V8 13.6 keeps one interval)
    non_participating: (i32, i32),
}

impl State {
    fn new_alternative(&mut self, captures_started: i32) {
        if self.non_participating.1 != 0 {
            self.non_participating.1 = captures_started;
        } else {
            self.non_participating = (self.capture_index, captures_started);
        }
    }
}

fn is_char(value: u32, character: char) -> bool {
    value == character as u32
}

fn hex_value(value: u32) -> Option<u32> {
    char::from_u32(value).and_then(|c| c.to_digit(16)).filter(|_| value < 0x80)
}

fn is_lead_surrogate(unit: u32) -> bool {
    (0xD800..=0xDBFF).contains(&unit)
}

fn is_trail_surrogate(unit: u32) -> bool {
    (0xDC00..=0xDFFF).contains(&unit)
}

fn is_decimal_digit(value: u32) -> bool {
    (b'0' as u32..=b'9' as u32).contains(&value)
}

struct Parser<'a> {
    input: &'a [u16],
    current: u32,
    next_pos: usize,
    has_more: bool,
    failed: Option<RegExpError>,
    force_unicode: bool,
    captures_started: i32,
    capture_count: i32,
    is_scanned_for_captures: bool,
    has_named_captures: bool,
    named_captures: Option<BTreeMap<Vec<u16>, Vec<i32>>>,
    named_back_references: Option<Vec<Vec<u16>>>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u16]) -> Self {
        let mut parser = Self {
            input,
            current: END_MARKER,
            next_pos: 0,
            has_more: true,
            failed: None,
            force_unicode: false,
            captures_started: 0,
            capture_count: 0,
            is_scanned_for_captures: false,
            has_named_captures: false,
            named_captures: None,
            named_back_references: None,
        };
        parser.advance();
        parser
    }

    fn has_next(&self) -> bool {
        self.next_pos < self.input.len()
    }

    fn read_next(&mut self, update_position: bool) -> u32 {
        let mut position = self.next_pos;
        let c0 = self.input[position] as u32;
        let mut result = c0;
        position += 1;
        if self.force_unicode && position < self.input.len() && is_lead_surrogate(c0) {
            let c1 = self.input[position] as u32;
            if is_trail_surrogate(c1) {
                result = 0x10000 + ((c0 - 0xD800) << 10) + (c1 - 0xDC00);
                position += 1;
            }
        }
        if update_position {
            self.next_pos = position;
        }
        result
    }

    fn next(&mut self) -> u32 {
        if self.has_next() { self.read_next(false) } else { END_MARKER }
    }

    fn advance(&mut self) {
        if self.has_next() {
            self.current = self.read_next(true);
        } else {
            self.current = END_MARKER;
            self.next_pos = self.input.len() + 1;
            self.has_more = false;
        }
    }

    fn advance_by(&mut self, distance: isize) {
        self.next_pos = (self.next_pos as isize + distance - 1) as usize;
        self.advance();
    }

    fn rewind_by_one_codepoint(&mut self) {
        if !self.has_more {
            return;
        }
        let rewind_by = if self.current > 0xFFFF { -2 } else { -1 };
        self.advance_by(rewind_by);
    }

    fn reset(&mut self, position: usize) {
        self.next_pos = position;
        self.has_more = position < self.input.len();
        self.advance();
    }

    fn position(&self) -> usize {
        let current_is_surrogate = self.current != END_MARKER && self.current > 0xFFFF;
        self.next_pos - if current_is_surrogate { 2 } else { 1 }
    }

    fn report_error(&mut self, error: RegExpError) {
        if self.failed.is_some() {
            return;
        }
        self.failed = Some(error);
        self.current = END_MARKER;
        self.next_pos = self.input.len();
        self.has_more = false;
    }

    fn parse_disjunction(&mut self) {
        let mut states = vec![State {
            group_type: GroupType::Initial,
            lookaround: Lookaround::Ahead,
            capture_index: 0,
            capture_name: None,
            non_participating: (0, 0),
        }];
        loop {
            let mut closed_lookbehind = false;
            let current = self.current;
            match current {
                END_MARKER => {
                    if self.failed.is_some() {
                        return;
                    }
                    if states.len() > 1 {
                        self.report_error(RegExpError::UnterminatedGroup);
                    }
                    return;
                }
                _ if is_char(current, ')') => {
                    if states.len() == 1 {
                        self.report_error(RegExpError::UnmatchedParen);
                        return;
                    }
                    self.advance();
                    let state = states.last().expect("inside a group");
                    match state.group_type {
                        GroupType::Capture => {
                            if state.capture_name.is_some() {
                                let index = state.capture_index;
                                if !self.create_named_capture_at_index(state, index) {
                                    return;
                                }
                            }
                        }
                        GroupType::PositiveLookaround | GroupType::NegativeLookaround => {
                            closed_lookbehind = state.lookaround == Lookaround::Behind;
                        }
                        GroupType::Grouping | GroupType::Initial => {}
                    }
                    states.pop();
                }
                _ if is_char(current, '|') => {
                    self.advance();
                    let captures_started = self.captures_started;
                    states.last_mut().expect("state").new_alternative(captures_started);
                    continue;
                }
                _ if is_char(current, '*') || is_char(current, '+') || is_char(current, '?') => {
                    self.report_error(RegExpError::NothingToRepeat);
                    return;
                }
                _ if is_char(current, '^') || is_char(current, '$') => {
                    self.advance();
                    continue;
                }
                _ if is_char(current, '.') => self.advance(),
                _ if is_char(current, '(') => {
                    self.parse_open_parenthesis(&mut states);
                    if self.failed.is_some() {
                        return;
                    }
                    continue;
                }
                _ if is_char(current, '[') => {
                    self.parse_character_class();
                    if self.failed.is_some() {
                        return;
                    }
                }
                _ if is_char(current, '\\') => {
                    let next = self.next();
                    if next == END_MARKER {
                        self.report_error(RegExpError::EscapeAtEndOfPattern);
                        return;
                    }
                    match char::from_u32(next).unwrap_or('\0') {
                        '1'..='9' => {
                            let is_backref = self.parse_back_reference_index();
                            if self.failed.is_some() {
                                return;
                            }
                            if !is_backref {
                                let first_digit = self.next();
                                if is_char(first_digit, '8') || is_char(first_digit, '9') {
                                    self.advance_by(2);
                                } else {
                                    self.advance();
                                    self.parse_octal_literal();
                                }
                            }
                        }
                        '0' => {
                            self.advance();
                            self.parse_octal_literal();
                        }
                        'b' | 'B' => {
                            self.advance_by(2);
                            continue;
                        }
                        // Character class escapes, and \p \P as identity escapes without /u
                        'd' | 'D' | 's' | 'S' | 'w' | 'W' | 'p' | 'P' => self.advance_by(2),
                        'k' => {
                            let has_named_captures = self.has_named_captures(ClassState::NotInClass);
                            if self.failed.is_some() {
                                return;
                            }
                            if has_named_captures {
                                self.advance_by(2);
                                self.parse_named_back_reference(&states);
                            } else {
                                self.parse_character_escape(ClassState::NotInClass);
                            }
                            if self.failed.is_some() {
                                return;
                            }
                        }
                        _ => {
                            self.parse_character_escape(ClassState::NotInClass);
                            if self.failed.is_some() {
                                return;
                            }
                        }
                    }
                }
                _ if is_char(current, '{') => {
                    if self.parse_interval_quantifier().is_some() {
                        self.report_error(RegExpError::NothingToRepeat);
                        return;
                    }
                    self.advance();
                }
                _ => self.advance(),
            }

            // Quantifier on the atom just added
            let quantifier = match self.current {
                c if is_char(c, '*') || is_char(c, '+') || is_char(c, '?') => {
                    self.advance();
                    Some(())
                }
                c if is_char(c, '{') => match self.parse_interval_quantifier() {
                    Some((min, max)) => {
                        if max < min {
                            self.report_error(RegExpError::RangeOutOfOrder);
                            return;
                        }
                        Some(())
                    }
                    None => None,
                },
                _ => None,
            };
            if quantifier.is_none() {
                continue;
            }
            if is_char(self.current, '?') {
                self.advance();
            }
            // Lookbehinds are not quantifiable
            if closed_lookbehind {
                self.report_error(RegExpError::InvalidQuantifier);
                return;
            }
        }
    }

    fn parse_open_parenthesis(&mut self, states: &mut Vec<State>) {
        let parent = states.last().expect("state");
        let mut lookaround = parent.lookaround;
        let parent_interval = parent.non_participating;
        let mut is_named_capture = false;
        let mut group_type = GroupType::Capture;
        let mut parsing_modifiers = false;
        let mut modifiers_polarity = true;
        let mut modifiers = 0u8;
        self.advance();
        if is_char(self.current, '?') {
            loop {
                let next = self.next();
                match char::from_u32(next).unwrap_or('\0') {
                    '-' => {
                        self.advance();
                        parsing_modifiers = true;
                        if !modifiers_polarity {
                            self.report_error(RegExpError::MultipleFlagDashes);
                            return;
                        }
                        modifiers_polarity = false;
                    }
                    flag @ ('m' | 'i' | 's') => {
                        self.advance();
                        parsing_modifiers = true;
                        let bit = match flag {
                            'i' => 1,
                            'm' => 2,
                            _ => 4,
                        };
                        if modifiers & bit != 0 {
                            self.report_error(RegExpError::RepeatedFlag);
                            return;
                        }
                        modifiers |= bit;
                    }
                    ':' => {
                        self.advance_by(2);
                        parsing_modifiers = false;
                        group_type = GroupType::Grouping;
                    }
                    '=' | '!' => {
                        self.advance_by(2);
                        if parsing_modifiers {
                            self.report_error(RegExpError::InvalidGroup);
                            return;
                        }
                        lookaround = Lookaround::Ahead;
                        group_type =
                            if next == '=' as u32 { GroupType::PositiveLookaround } else { GroupType::NegativeLookaround };
                    }
                    '<' => {
                        self.advance();
                        if parsing_modifiers {
                            self.report_error(RegExpError::InvalidGroup);
                            return;
                        }
                        let after = self.next();
                        if is_char(after, '=') || is_char(after, '!') {
                            self.advance_by(2);
                            lookaround = Lookaround::Behind;
                            group_type = if is_char(after, '=') {
                                GroupType::PositiveLookaround
                            } else {
                                GroupType::NegativeLookaround
                            };
                        } else {
                            is_named_capture = true;
                            self.has_named_captures = true;
                            self.advance();
                        }
                    }
                    _ => {
                        self.report_error(RegExpError::InvalidGroup);
                        return;
                    }
                }
                if !parsing_modifiers {
                    break;
                }
            }
        }
        if !modifiers_polarity && modifiers == 0 {
            self.report_error(RegExpError::InvalidFlagGroup);
            return;
        }
        let mut capture_name = None;
        if group_type == GroupType::Capture {
            if self.captures_started >= MAX_CAPTURES {
                self.report_error(RegExpError::TooManyCaptures);
                return;
            }
            self.captures_started += 1;
            if is_named_capture {
                capture_name = self.parse_capture_group_name();
                if self.failed.is_some() {
                    return;
                }
            }
        }
        states.push(State {
            group_type,
            lookaround,
            capture_index: self.captures_started,
            capture_name,
            non_participating: parent_interval,
        });
    }

    fn scan_for_captures(&mut self, class_state: ClassState) {
        let saved_position = self.position();
        let mut capture_count = self.captures_started;
        if class_state == ClassState::InClass {
            while self.current != END_MARKER {
                let c = self.current;
                self.advance();
                if is_char(c, '\\') {
                    self.advance();
                } else if is_char(c, ']') {
                    break;
                }
            }
        }
        while self.current != END_MARKER {
            let n = self.current;
            self.advance();
            if is_char(n, '\\') {
                self.advance();
            } else if is_char(n, '[') {
                while self.current != END_MARKER {
                    let c = self.current;
                    self.advance();
                    if is_char(c, '\\') {
                        self.advance();
                    } else if is_char(c, ']') {
                        break;
                    }
                }
            } else if is_char(n, '(') {
                if is_char(self.current, '?') {
                    self.advance();
                    if !is_char(self.current, '<') {
                        continue;
                    }
                    self.advance();
                    if is_char(self.current, '=') || is_char(self.current, '!') {
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

    fn parse_back_reference_index(&mut self) -> bool {
        let start = self.position();
        let mut value = self.next() as i32 - '0' as i32;
        self.advance_by(2);
        loop {
            let c = self.current;
            if is_decimal_digit(c) {
                value = 10 * value + (c as i32 - '0' as i32);
                if value > MAX_CAPTURES {
                    self.reset(start);
                    return false;
                }
                self.advance();
            } else {
                break;
            }
        }
        if value > self.captures_started {
            if !self.is_scanned_for_captures {
                self.scan_for_captures(ClassState::NotInClass);
            }
            if value > self.capture_count {
                self.reset(start);
                return false;
            }
        }
        true
    }

    fn parse_capture_group_name(&mut self) -> Option<Vec<u16>> {
        self.rewind_by_one_codepoint();
        self.force_unicode = true;
        let result = self.parse_capture_group_name_forced();
        self.force_unicode = false;
        if result.is_some() {
            self.advance();
        }
        result
    }

    fn parse_capture_group_name_forced(&mut self) -> Option<Vec<u16>> {
        let mut name: Vec<u16> = Vec::new();
        let mut at_start = true;
        loop {
            self.advance();
            let mut c = self.current;
            if is_char(c, '\\') && is_char(self.next(), 'u') {
                self.advance_by(2);
                match self.parse_unicode_escape() {
                    Some(value) => c = value,
                    None => {
                        self.report_error(RegExpError::InvalidUnicodeEscape);
                        return None;
                    }
                }
                self.rewind_by_one_codepoint();
            }
            if is_char(c, '\\') {
                self.report_error(RegExpError::InvalidCaptureGroupName);
                return None;
            }
            if at_start {
                if !is_identifier_start(c) {
                    self.report_error(RegExpError::InvalidCaptureGroupName);
                    return None;
                }
                push_code_unit(&mut name, c);
                at_start = false;
            } else if is_char(c, '>') {
                break;
            } else if is_identifier_part(c) {
                push_code_unit(&mut name, c);
            } else {
                self.report_error(RegExpError::InvalidCaptureGroupName);
                return None;
            }
        }
        Some(name)
    }

    fn create_named_capture_at_index(&mut self, state: &State, index: i32) -> bool {
        let name = state.capture_name.clone().expect("named capture");
        let (first, second) = state.non_participating;
        match &mut self.named_captures {
            None => {
                self.named_captures = Some(BTreeMap::from([(name, vec![index])]));
            }
            Some(captures) => {
                if let Some(indices) = captures.get(&name)
                    && indices.iter().any(|&named_index| named_index < first || named_index > second)
                {
                    self.report_error(RegExpError::DuplicateCaptureGroupName);
                    return false;
                }
                captures.entry(name).or_default().push(index);
            }
        }
        true
    }

    fn parse_named_back_reference(&mut self, states: &[State]) {
        if !is_char(self.current, '<') {
            self.report_error(RegExpError::InvalidNamedReference);
            return;
        }
        self.advance();
        let Some(name) = self.parse_capture_group_name() else { return };
        let inside = states.iter().any(|state| state.capture_name.as_ref() == Some(&name));
        if !inside {
            self.named_back_references.get_or_insert_with(Vec::new).push(name);
        }
    }

    fn patch_named_back_references(&mut self) {
        let Some(references) = &self.named_back_references else { return };
        let Some(captures) = &self.named_captures else {
            self.report_error(RegExpError::InvalidNamedCaptureReference);
            return;
        };
        if references.iter().any(|name| !captures.contains_key(name)) {
            self.report_error(RegExpError::InvalidNamedCaptureReference);
        }
    }

    fn has_named_captures(&mut self, class_state: ClassState) -> bool {
        if self.has_named_captures || self.is_scanned_for_captures {
            return self.has_named_captures;
        }
        self.scan_for_captures(class_state);
        self.has_named_captures
    }

    fn parse_interval_quantifier(&mut self) -> Option<(i32, i32)> {
        let start = self.position();
        self.advance();
        let mut min: i32 = 0;
        if !is_decimal_digit(self.current) {
            self.reset(start);
            return None;
        }
        while is_decimal_digit(self.current) {
            let next = self.current as i32 - '0' as i32;
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
        let max;
        if is_char(self.current, '}') {
            max = min;
            self.advance();
        } else if is_char(self.current, ',') {
            self.advance();
            if is_char(self.current, '}') {
                max = INFINITY;
                self.advance();
            } else {
                let mut value: i32 = 0;
                while is_decimal_digit(self.current) {
                    let next = self.current as i32 - '0' as i32;
                    if value > (INFINITY - next) / 10 {
                        loop {
                            self.advance();
                            if !is_decimal_digit(self.current) {
                                break;
                            }
                        }
                        value = INFINITY;
                        break;
                    }
                    value = 10 * value + next;
                    self.advance();
                }
                if !is_char(self.current, '}') {
                    self.reset(start);
                    return None;
                }
                self.advance();
                max = value;
            }
        } else {
            self.reset(start);
            return None;
        }
        Some((min, max))
    }

    fn parse_octal_literal(&mut self) -> u32 {
        let in_octal = |c: u32| (b'0' as u32..=b'7' as u32).contains(&c);
        let mut value = self.current.wrapping_sub('0' as u32);
        self.advance();
        if in_octal(self.current) {
            value = value.wrapping_mul(8).wrapping_add(self.current - '0' as u32);
            self.advance();
            if value < 32 && in_octal(self.current) {
                value = value * 8 + self.current - '0' as u32;
                self.advance();
            }
        }
        value
    }

    fn parse_hex_escape(&mut self, length: usize) -> Option<u32> {
        let start = self.position();
        let mut value = 0u32;
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

    fn parse_unicode_escape(&mut self) -> Option<u32> {
        if is_char(self.current, '{') && self.force_unicode {
            let start = self.position();
            self.advance();
            if let Some(value) = self.parse_unlimited_length_hex_number(0x10FFFF)
                && is_char(self.current, '}')
            {
                self.advance();
                return Some(value);
            }
            self.reset(start);
            return None;
        }
        let result = self.parse_hex_escape(4);
        if let Some(lead) = result
            && self.force_unicode
            && is_lead_surrogate(lead)
            && is_char(self.current, '\\')
        {
            let start = self.position();
            if is_char(self.next(), 'u') {
                self.advance_by(2);
                if let Some(trail) = self.parse_hex_escape(4)
                    && is_trail_surrogate(trail)
                {
                    return Some(0x10000 + ((lead - 0xD800) << 10) + (trail - 0xDC00));
                }
            }
            self.reset(start);
        }
        result
    }

    fn parse_unlimited_length_hex_number(&mut self, max_value: u32) -> Option<u32> {
        let mut value = hex_value(self.current)?;
        loop {
            if value > max_value {
                return None;
            }
            self.advance();
            match hex_value(self.current) {
                Some(digit) => value = value * 16 + digit,
                None => return Some(value),
            }
        }
    }

    fn parse_character_escape(&mut self, class_state: ClassState) -> u32 {
        self.advance();
        let c = self.current;
        match char::from_u32(c).unwrap_or('\0') {
            'f' => {
                self.advance();
                return 0x0C;
            }
            'n' => {
                self.advance();
                return 0x0A;
            }
            'r' => {
                self.advance();
                return 0x0D;
            }
            't' => {
                self.advance();
                return 0x09;
            }
            'v' => {
                self.advance();
                return 0x0B;
            }
            'c' if c == 'c' as u32 => {
                let control_letter = self.next();
                let letter = control_letter & !(('A' as u32) ^ ('a' as u32));
                if (b'A' as u32..=b'Z' as u32).contains(&letter) {
                    self.advance_by(2);
                    return control_letter & 0x1F;
                }
                if class_state == ClassState::InClass
                    && (is_decimal_digit(control_letter) || is_char(control_letter, '_'))
                {
                    self.advance_by(2);
                    return control_letter & 0x1F;
                }
                return '\\' as u32;
            }
            '0' if c == '0' as u32 && !is_decimal_digit(self.next()) => {
                self.advance();
                return 0;
            }
            '0'..='7' if c < 0x80 => return self.parse_octal_literal(),
            'x' if c == 'x' as u32 => {
                self.advance();
                return self.parse_hex_escape(2).unwrap_or('x' as u32);
            }
            'u' if c == 'u' as u32 => {
                self.advance();
                return self.parse_unicode_escape().unwrap_or('u' as u32);
            }
            _ => {}
        }
        self.advance();
        if is_char(c, 'k') && self.has_named_captures(class_state) {
            self.report_error(RegExpError::InvalidEscape);
            return 0;
        }
        c
    }

    fn parse_character_class(&mut self) {
        self.advance();
        if is_char(self.current, '^') {
            self.advance();
        }
        if is_char(self.current, ']') {
            self.advance();
            return;
        }
        self.parse_class_ranges();
        if self.failed.is_some() {
            return;
        }
        if !self.has_more {
            self.report_error(RegExpError::UnterminatedCharacterClass);
            return;
        }
        self.advance();
    }

    fn parse_class_ranges(&mut self) {
        while self.has_more && !is_char(self.current, ']') {
            let (char_1, is_class_1) = self.parse_class_escape();
            if self.failed.is_some() {
                return;
            }
            if is_char(self.current, '-') {
                self.advance();
                if !self.has_more || is_char(self.current, ']') {
                    break;
                }
                let (char_2, is_class_2) = self.parse_class_escape();
                if self.failed.is_some() {
                    return;
                }
                if is_class_1 || is_class_2 {
                    continue;
                }
                if char_1 > char_2 {
                    self.report_error(RegExpError::OutOfOrderCharacterClass);
                    return;
                }
            }
        }
    }

    fn parse_class_escape(&mut self) -> (u32, bool) {
        if !is_char(self.current, '\\') {
            let c = self.current;
            self.advance();
            return (c, false);
        }
        let next = self.next();
        if is_char(next, 'b') {
            self.advance_by(2);
            return (0x08, false);
        }
        if next == END_MARKER {
            self.report_error(RegExpError::EscapeAtEndOfPattern);
            return (0, false);
        }
        if ['d', 'D', 's', 'S', 'w', 'W'].iter().any(|&escape| is_char(next, escape)) {
            self.advance_by(2);
            return (0, true);
        }
        (self.parse_character_escape(ClassState::InClass), false)
    }
}

fn push_code_unit(name: &mut Vec<u16>, code_point: u32) {
    if code_point <= 0xFFFF {
        name.push(code_point as u16);
    } else {
        let offset = code_point - 0x10000;
        name.push((0xD800 + (offset >> 10)) as u16);
        name.push((0xDC00 + (offset & 0x3FF)) as u16);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(pattern: &str) -> String {
        match validate(pattern) {
            Ok(()) => "ok".to_string(),
            Err(message) => message,
        }
    }

    #[test]
    fn matches_v8_messages() {
        let cases = [
            ("(?i:a)", "ok"),
            ("(?ii:a)", "Invalid regular expression: /(?ii:a)/: Repeated flag in flag group"),
            ("(?-:a)", "Invalid regular expression: /(?-:a)/: Invalid flag group"),
            ("(?--i:a)", "Invalid regular expression: /(?--i:a)/: Multiple dashes in flag group"),
            ("(?<a>x)|(?<a>y)", "ok"),
            ("(?<a>x)(?<a>y)", "Invalid regular expression: /(?<a>x)(?<a>y)/: Duplicate capture group name"),
            ("(?:(?<a>x)|(?<a>y))|(?<a>z)", "ok"),
            ("((?<a>x)|(?<b>y))(?<a>z)", "Invalid regular expression: /((?<a>x)|(?<b>y))(?<a>z)/: Duplicate capture group name"),
            ("(", "Invalid regular expression: /(/: Unterminated group"),
            ("[z-a]", "Invalid regular expression: /[z-a]/: Range out of order in character class"),
            ("a{2,1}", "Invalid regular expression: /a{2,1}/: numbers out of order in {} quantifier"),
            ("(?<=a)*", "Invalid regular expression: /(?<=a)*/: Invalid quantifier"),
            ("(?=a)*", "ok"),
            ("\\k<a>", "ok"),
            ("\\k<a>(?<b>c)", "Invalid regular expression: /\\k<a>(?<b>c)/: Invalid named capture referenced"),
            ("(?<a>b)\\k", "Invalid regular expression: /(?<a>b)\\k/: Invalid named reference"),
            ("{1}", "Invalid regular expression: /{1}/: Nothing to repeat"),
            ("a{1", "ok"),
            ("\\", "Invalid regular expression: /\\/: \\ at end of pattern"),
            ("[\\", "Invalid regular expression: /[\\/: \\ at end of pattern"),
            ("(?<1a>x)", "Invalid regular expression: /(?<1a>x)/: Invalid capture group name"),
            ("(?<a", "Invalid regular expression: /(?<a/: Invalid capture group name"),
            ("\\c", "ok"),
            ("[\\c_]", "ok"),
            ("x**", "Invalid regular expression: /x**/: Nothing to repeat"),
            ("(?i)", "Invalid regular expression: /(?i)/: Invalid group"),
            ("(?P<a>x)", "Invalid regular expression: /(?P<a>x)/: Invalid group"),
            ("[invalid", "Invalid regular expression: /[invalid/: Unterminated character class"),
            ("a)", "Invalid regular expression: /a)/: Unmatched ')'"),
            ("^/docs/[a-z-]+$", "ok"),
        ];
        for (pattern, expected) in cases {
            assert_eq!(error(pattern), expected, "{pattern:?}");
        }
    }
}
