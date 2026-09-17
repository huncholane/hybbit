//! `Date.parse` and `Date.prototype.toISOString`, ported from V8 13.6
//! (`src/date/dateparser*.{h,cc}`, `ParseDateTimeString` in `src/date/date.cc`).
//!
//! The analytics validators call `Date.parse` on request input that has *failed*
//! the format regex too (zod keeps running refinements on a dirty string), so
//! whether a second "Invalid ... value" message appears depends on V8's legacy
//! fallback parser accepting strings like `01/01/2025`. Production runs with
//! TZ=UTC, so local time is UTC here.

use super::string::{is_js_space, is_white_space};

const MS_PER_DAY: f64 = 86_400_000.0;
const MAX_TIME_IN_MS: f64 = 864_000_000.0 * 10_000_000.0;
const MAX_TIME_BEFORE_UTC_IN_MS: f64 = MAX_TIME_IN_MS + MS_PER_DAY * 30.0;
const NONE: i32 = i32::MAX;
const MAX_SIGNIFICANT_DIGITS: usize = 9;
const SMI_MAX: i64 = (1 << 30) - 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KeywordType {
    Invalid,
    MonthName,
    TimeZoneName,
    TimeSeparator,
    AmPm,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Token {
    Invalid,
    Unknown,
    WhiteSpace,
    Number { value: i32, length: usize },
    Symbol(u16),
    EndOfInput,
    Keyword { kind: KeywordType, value: i32, length: usize },
}

impl Token {
    fn is_number(self) -> bool {
        matches!(self, Token::Number { .. })
    }
    fn is_fixed_length_number(self, length: usize) -> bool {
        matches!(self, Token::Number { length: l, .. } if l == length)
    }
    fn number(self) -> i32 {
        match self {
            Token::Number { value, .. } => value,
            _ => 0,
        }
    }
    fn is_symbol(self, symbol: u8) -> bool {
        self == Token::Symbol(symbol as u16)
    }
    fn is_ascii_sign(self) -> bool {
        self.is_symbol(b'+') || self.is_symbol(b'-')
    }
    fn ascii_sign(self) -> i32 {
        match self {
            Token::Symbol(symbol) => 44 - symbol as i32,
            _ => 0,
        }
    }
    fn is_keyword_type(self, kind: KeywordType) -> bool {
        matches!(self, Token::Keyword { kind: k, .. } if k == kind)
    }
    fn is_keyword_z(self) -> bool {
        matches!(self, Token::Keyword { kind: KeywordType::TimeZoneName, length: 1, value: 0 })
    }
}

/// `{prefix, type, value}` rows of V8's KeywordTable, in lookup order.
const KEYWORDS: [([u8; 3], KeywordType, i32); 27] = [
    (*b"jan", KeywordType::MonthName, 1),
    (*b"feb", KeywordType::MonthName, 2),
    (*b"mar", KeywordType::MonthName, 3),
    (*b"apr", KeywordType::MonthName, 4),
    (*b"may", KeywordType::MonthName, 5),
    (*b"jun", KeywordType::MonthName, 6),
    (*b"jul", KeywordType::MonthName, 7),
    (*b"aug", KeywordType::MonthName, 8),
    (*b"sep", KeywordType::MonthName, 9),
    (*b"oct", KeywordType::MonthName, 10),
    (*b"nov", KeywordType::MonthName, 11),
    (*b"dec", KeywordType::MonthName, 12),
    (*b"am\0", KeywordType::AmPm, 0),
    (*b"pm\0", KeywordType::AmPm, 12),
    (*b"ut\0", KeywordType::TimeZoneName, 0),
    (*b"utc", KeywordType::TimeZoneName, 0),
    (*b"z\0\0", KeywordType::TimeZoneName, 0),
    (*b"gmt", KeywordType::TimeZoneName, 0),
    (*b"cdt", KeywordType::TimeZoneName, -5),
    (*b"cst", KeywordType::TimeZoneName, -6),
    (*b"edt", KeywordType::TimeZoneName, -4),
    (*b"est", KeywordType::TimeZoneName, -5),
    (*b"mdt", KeywordType::TimeZoneName, -6),
    (*b"mst", KeywordType::TimeZoneName, -7),
    (*b"pdt", KeywordType::TimeZoneName, -7),
    (*b"pst", KeywordType::TimeZoneName, -8),
    (*b"t\0\0", KeywordType::TimeSeparator, 0),
];

fn keyword_lookup(prefix: [u32; 3], length: usize) -> (KeywordType, i32) {
    for (word, kind, value) in KEYWORDS {
        let matches = prefix.iter().zip(word.iter()).all(|(&have, &want)| have == want as u32);
        if matches && (length <= 3 || kind == KeywordType::MonthName) {
            return (kind, value);
        }
    }
    (KeywordType::Invalid, 0)
}

fn between(x: i32, lo: i32, hi: i32) -> bool {
    (x.wrapping_sub(lo) as u32) <= (hi.wrapping_sub(lo) as u32)
}

struct InputReader<'a> {
    buffer: &'a [u16],
    index: usize,
    ch: u32,
}

impl<'a> InputReader<'a> {
    fn new(buffer: &'a [u16]) -> Self {
        let mut reader = Self { buffer, index: 0, ch: 0 };
        reader.next();
        reader
    }
    fn next(&mut self) {
        self.ch = self.buffer.get(self.index).map_or(0, |&unit| unit as u32);
        self.index += 1;
    }
    fn position(&self) -> usize {
        self.index
    }
    fn read_unsigned_numeral(&mut self) -> i32 {
        let mut n: i32 = 0;
        let mut i = 0;
        while self.ch == '0' as u32 {
            self.next();
        }
        while self.is_ascii_digit() {
            if i < MAX_SIGNIFICANT_DIGITS {
                n = n * 10 + (self.ch as i32 - '0' as i32);
            }
            i += 1;
            self.next();
        }
        n
    }
    fn read_word(&mut self) -> ([u32; 3], usize) {
        let mut prefix = [0u32; 3];
        let mut length = 0;
        while self.is_ascii_alpha_or_above() && !self.is_white_space_char() {
            if length < 3 {
                prefix[length] = self.ch | 0x20;
            }
            length += 1;
            self.next();
        }
        (prefix, length)
    }
    fn skip(&mut self, c: u8) -> bool {
        if self.ch == c as u32 {
            self.next();
            true
        } else {
            false
        }
    }
    fn skip_white_space(&mut self) -> bool {
        if is_js_space(self.ch) {
            self.next();
            true
        } else {
            false
        }
    }
    fn skip_parentheses(&mut self) -> bool {
        if self.ch != '(' as u32 {
            return false;
        }
        let mut balance = 0;
        loop {
            if self.ch == ')' as u32 {
                balance -= 1;
            } else if self.ch == '(' as u32 {
                balance += 1;
            }
            self.next();
            if !(balance > 0 && self.ch != 0) {
                break;
            }
        }
        true
    }
    fn is_end(&self) -> bool {
        self.ch == 0
    }
    fn is_ascii_digit(&self) -> bool {
        (b'0' as u32..=b'9' as u32).contains(&self.ch)
    }
    fn is_ascii_alpha_or_above(&self) -> bool {
        self.ch >= 'A' as u32
    }
    fn is_white_space_char(&self) -> bool {
        is_white_space(self.ch)
    }
}

struct Tokenizer<'a> {
    input: InputReader<'a>,
    next: Token,
}

impl<'a> Tokenizer<'a> {
    fn new(buffer: &'a [u16]) -> Self {
        let mut input = InputReader::new(buffer);
        let next = Self::scan(&mut input);
        Self { input, next }
    }
    fn next(&mut self) -> Token {
        let result = self.next;
        self.next = Self::scan(&mut self.input);
        result
    }
    fn peek(&self) -> Token {
        self.next
    }
    fn skip_symbol(&mut self, symbol: u8) -> bool {
        if self.next.is_symbol(symbol) {
            self.next = Self::scan(&mut self.input);
            true
        } else {
            false
        }
    }
    fn scan(input: &mut InputReader<'_>) -> Token {
        let pre_pos = input.position();
        if input.is_end() {
            return Token::EndOfInput;
        }
        if input.is_ascii_digit() {
            let value = input.read_unsigned_numeral();
            return Token::Number { value, length: input.position() - pre_pos };
        }
        for symbol in [b':', b'-', b'+', b'.', b')'] {
            if input.skip(symbol) {
                return Token::Symbol(symbol as u16);
            }
        }
        if input.is_ascii_alpha_or_above() && !input.is_white_space_char() {
            let (prefix, length) = input.read_word();
            let (kind, value) = keyword_lookup(prefix, length);
            return Token::Keyword { kind, value, length };
        }
        if input.skip_white_space() {
            return Token::WhiteSpace;
        }
        if input.skip_parentheses() {
            return Token::Unknown;
        }
        input.next();
        Token::Unknown
    }
}

struct TimeZoneComposer {
    sign: i32,
    hour: i32,
    minute: i32,
}

impl TimeZoneComposer {
    fn new() -> Self {
        Self { sign: NONE, hour: NONE, minute: NONE }
    }
    fn set(&mut self, offset_in_hours: i32) {
        self.sign = if offset_in_hours < 0 { -1 } else { 1 };
        self.hour = offset_in_hours * self.sign;
        self.minute = 0;
    }
    fn set_sign(&mut self, sign: i32) {
        self.sign = if sign < 0 { -1 } else { 1 };
    }
    fn is_expecting(&self, n: i32) -> bool {
        self.hour != NONE && self.minute == NONE && TimeComposer::is_minute(n)
    }
    fn is_utc(&self) -> bool {
        self.hour == 0 && self.minute == 0
    }
    fn is_empty(&self) -> bool {
        self.hour == NONE
    }
    /// Offset in seconds, NaN when absent, `None` when out of Smi range.
    fn write(&mut self) -> Option<f64> {
        if self.sign == NONE {
            return Some(f64::NAN);
        }
        if self.hour == NONE {
            self.hour = 0;
        }
        if self.minute == NONE {
            self.minute = 0;
        }
        let total = (self.hour as u32).wrapping_mul(3600).wrapping_add((self.minute as u32).wrapping_mul(60));
        if total as i64 > SMI_MAX {
            return None;
        }
        let total = total as i32;
        Some(f64::from(if self.sign < 0 { -total } else { total }))
    }
}

struct TimeComposer {
    comp: [i32; 4],
    index: usize,
    hour_offset: i32,
}

impl TimeComposer {
    fn new() -> Self {
        Self { comp: [0; 4], index: 0, hour_offset: NONE }
    }
    fn is_empty(&self) -> bool {
        self.index == 0
    }
    fn is_expecting(&self, n: i32) -> bool {
        (self.index == 1 && Self::is_minute(n))
            || (self.index == 2 && Self::is_second(n))
            || (self.index == 3 && Self::is_millisecond(n))
    }
    fn add(&mut self, n: i32) -> bool {
        if self.index < 4 {
            self.comp[self.index] = n;
            self.index += 1;
            true
        } else {
            false
        }
    }
    fn add_final(&mut self, n: i32) -> bool {
        if !self.add(n) {
            return false;
        }
        while self.index < 4 {
            self.comp[self.index] = 0;
            self.index += 1;
        }
        true
    }
    fn set_hour_offset(&mut self, n: i32) {
        self.hour_offset = n;
    }
    fn is_minute(x: i32) -> bool {
        between(x, 0, 59)
    }
    fn is_hour(x: i32) -> bool {
        between(x, 0, 23)
    }
    fn is_second(x: i32) -> bool {
        between(x, 0, 59)
    }
    fn is_hour12(x: i32) -> bool {
        between(x, 0, 12)
    }
    fn is_millisecond(x: i32) -> bool {
        between(x, 0, 999)
    }
    fn write(&mut self) -> Option<[i32; 4]> {
        while self.index < 4 {
            self.comp[self.index] = 0;
            self.index += 1;
        }
        let [mut hour, minute, second, millisecond] = self.comp;
        if self.hour_offset != NONE {
            if !Self::is_hour12(hour) {
                return None;
            }
            hour %= 12;
            hour += self.hour_offset;
        }
        let in_range =
            Self::is_hour(hour) && Self::is_minute(minute) && Self::is_second(second) && Self::is_millisecond(millisecond);
        // A 24th hour is allowed when minutes, seconds and milliseconds are 0
        if !in_range && (hour != 24 || minute != 0 || second != 0 || millisecond != 0) {
            return None;
        }
        Some([hour, minute, second, millisecond])
    }
}

struct DayComposer {
    comp: [i32; 3],
    index: usize,
    named_month: i32,
    is_iso_date: bool,
}

impl DayComposer {
    fn new() -> Self {
        Self { comp: [0; 3], index: 0, named_month: NONE, is_iso_date: false }
    }
    fn is_empty(&self) -> bool {
        self.index == 0
    }
    fn add(&mut self, n: i32) -> bool {
        if self.index < 3 {
            self.comp[self.index] = n;
            self.index += 1;
            true
        } else {
            false
        }
    }
    fn is_month(x: i32) -> bool {
        between(x, 1, 12)
    }
    fn is_day(x: i32) -> bool {
        between(x, 1, 31)
    }
    /// `[year, month (0-based), day]`
    fn write(&mut self) -> Option<[i32; 3]> {
        if self.index < 1 {
            return None;
        }
        while self.index < 3 {
            self.comp[self.index] = 1;
            self.index += 1;
        }
        let mut year = 0;
        let month;
        let day;
        if self.named_month == NONE {
            if self.is_iso_date || (self.index == 3 && !Self::is_day(self.comp[0])) {
                year = self.comp[0];
                month = self.comp[1];
                day = self.comp[2];
            } else {
                month = self.comp[0];
                day = self.comp[1];
                if self.index == 3 {
                    year = self.comp[2];
                }
            }
        } else {
            month = self.named_month;
            if self.index == 1 {
                day = self.comp[0];
            } else if !Self::is_day(self.comp[0]) {
                year = self.comp[0];
                day = self.comp[1];
            } else {
                day = self.comp[0];
                year = self.comp[1];
            }
        }
        if !self.is_iso_date {
            if between(year, 0, 49) {
                year += 2000;
            } else if between(year, 50, 99) {
                year += 1900;
            }
        }
        if !(-(1 << 30)..=SMI_MAX as i32).contains(&year) || !Self::is_month(month) || !Self::is_day(day) {
            return None;
        }
        Some([year, month - 1, day])
    }
}

fn read_milliseconds(token: Token) -> i32 {
    let Token::Number { value, length } = token else { return 0 };
    let mut number = value;
    let mut length = length;
    if length < 3 {
        if length == 1 {
            number *= 100;
        } else if length == 2 {
            number *= 10;
        }
    } else if length > 3 {
        if length > MAX_SIGNIFICANT_DIGITS {
            length = MAX_SIGNIFICANT_DIGITS;
        }
        let mut factor = 1;
        loop {
            factor *= 10;
            length -= 1;
            if length <= 3 {
                break;
            }
        }
        number /= factor;
    }
    number
}

fn parse_es5_date_time(
    scanner: &mut Tokenizer<'_>,
    day: &mut DayComposer,
    time: &mut TimeComposer,
    tz: &mut TimeZoneComposer,
) -> Token {
    if scanner.peek().is_ascii_sign() {
        let sign_token = scanner.next();
        if !scanner.peek().is_fixed_length_number(6) {
            return sign_token;
        }
        let sign = sign_token.ascii_sign();
        let year = scanner.next().number();
        if sign < 0 && year == 0 {
            return sign_token;
        }
        day.add(sign * year);
    } else if scanner.peek().is_fixed_length_number(4) {
        day.add(scanner.next().number());
    } else {
        return scanner.next();
    }
    if scanner.skip_symbol(b'-') {
        if !scanner.peek().is_fixed_length_number(2) || !DayComposer::is_month(scanner.peek().number()) {
            return scanner.next();
        }
        day.add(scanner.next().number());
        if scanner.skip_symbol(b'-') {
            if !scanner.peek().is_fixed_length_number(2) || !DayComposer::is_day(scanner.peek().number()) {
                return scanner.next();
            }
            day.add(scanner.next().number());
        }
    }
    if !scanner.peek().is_keyword_type(KeywordType::TimeSeparator) {
        if scanner.peek() != Token::EndOfInput {
            return scanner.next();
        }
    } else {
        scanner.next();
        if !scanner.peek().is_fixed_length_number(2) || !between(scanner.peek().number(), 0, 24) {
            return Token::Invalid;
        }
        let hour_is_24 = scanner.peek().number() == 24;
        time.add(scanner.next().number());
        if !scanner.skip_symbol(b':') {
            return Token::Invalid;
        }
        if !scanner.peek().is_fixed_length_number(2)
            || !TimeComposer::is_minute(scanner.peek().number())
            || (hour_is_24 && scanner.peek().number() > 0)
        {
            return Token::Invalid;
        }
        time.add(scanner.next().number());
        if scanner.skip_symbol(b':') {
            if !scanner.peek().is_fixed_length_number(2)
                || !TimeComposer::is_second(scanner.peek().number())
                || (hour_is_24 && scanner.peek().number() > 0)
            {
                return Token::Invalid;
            }
            time.add(scanner.next().number());
            if scanner.skip_symbol(b'.') {
                if !scanner.peek().is_number() || (hour_is_24 && scanner.peek().number() > 0) {
                    return Token::Invalid;
                }
                time.add(read_milliseconds(scanner.next()));
            }
        }
        if scanner.peek().is_keyword_z() {
            scanner.next();
            tz.set(0);
        } else if scanner.peek().is_symbol(b'+') || scanner.peek().is_symbol(b'-') {
            tz.set_sign(if scanner.next().is_symbol(b'+') { 1 } else { -1 });
            if scanner.peek().is_fixed_length_number(4) {
                let hourmin = scanner.next().number();
                let hour = hourmin / 100;
                let min = hourmin % 100;
                if !TimeComposer::is_hour(hour) || !TimeComposer::is_minute(min) {
                    return Token::Invalid;
                }
                tz.hour = hour;
                tz.minute = min;
            } else {
                if !scanner.peek().is_fixed_length_number(2) || !TimeComposer::is_hour(scanner.peek().number()) {
                    return Token::Invalid;
                }
                tz.hour = scanner.next().number();
                if !scanner.skip_symbol(b':') {
                    return Token::Invalid;
                }
                if !scanner.peek().is_fixed_length_number(2) || !TimeComposer::is_minute(scanner.peek().number()) {
                    return Token::Invalid;
                }
                tz.minute = scanner.next().number();
            }
        }
        if scanner.peek() != Token::EndOfInput {
            return Token::Invalid;
        }
    }
    if tz.is_empty() && time.is_empty() {
        tz.set(0);
    }
    day.is_iso_date = true;
    Token::EndOfInput
}

/// `DateParser::Parse`: `[year, month, day, hour, minute, second, ms, utc offset]`.
fn parse_fields(units: &[u16]) -> Option<[f64; 8]> {
    let mut scanner = Tokenizer::new(units);
    let mut tz = TimeZoneComposer::new();
    let mut time = TimeComposer::new();
    let mut day = DayComposer::new();

    let next_unhandled = parse_es5_date_time(&mut scanner, &mut day, &mut time, &mut tz);
    if next_unhandled == Token::Invalid {
        return None;
    }
    let mut has_read_number = !day.is_empty();
    let mut token = next_unhandled;
    while token != Token::EndOfInput {
        match token {
            Token::Number { value: n, .. } => {
                has_read_number = true;
                if scanner.skip_symbol(b':') {
                    if scanner.skip_symbol(b':') {
                        if !time.is_empty() {
                            return None;
                        }
                        time.add(n);
                        time.add(0);
                    } else {
                        if !time.add(n) {
                            return None;
                        }
                        if scanner.peek().is_symbol(b'.') {
                            scanner.next();
                        }
                    }
                } else if scanner.skip_symbol(b'.') && time.is_expecting(n) {
                    time.add(n);
                    if !scanner.peek().is_number() {
                        return None;
                    }
                    let ms = read_milliseconds(scanner.next());
                    if ms < 0 {
                        return None;
                    }
                    time.add_final(ms);
                } else if tz.is_expecting(n) {
                    tz.minute = n;
                } else if time.is_expecting(n) {
                    time.add_final(n);
                    let peek = scanner.peek();
                    if peek != Token::EndOfInput && peek != Token::WhiteSpace && !peek.is_keyword_z() && !peek.is_ascii_sign()
                    {
                        return None;
                    }
                } else {
                    if !day.add(n) {
                        return None;
                    }
                    scanner.skip_symbol(b'-');
                }
            }
            Token::Keyword { kind, value, .. } => {
                if kind == KeywordType::AmPm && !time.is_empty() {
                    time.set_hour_offset(value);
                } else if kind == KeywordType::MonthName {
                    day.named_month = value;
                    scanner.skip_symbol(b'-');
                } else if kind == KeywordType::TimeZoneName && has_read_number {
                    tz.set(value);
                } else {
                    if has_read_number {
                        return None;
                    }
                    if scanner.peek().is_number() {
                        return None;
                    }
                }
            }
            _ if token.is_ascii_sign() && (tz.is_utc() || !time.is_empty()) => {
                tz.set_sign(token.ascii_sign());
                let mut n = 0;
                let mut length = 0;
                if scanner.peek().is_number() {
                    let next_token = scanner.next();
                    if let Token::Number { value, length: l } = next_token {
                        n = value;
                        length = l;
                    }
                }
                has_read_number = true;
                if scanner.peek().is_symbol(b':') {
                    tz.hour = n;
                    tz.minute = NONE;
                } else if length == 2 || length == 1 {
                    tz.hour = n;
                    tz.minute = 0;
                } else if length == 4 || length == 3 {
                    tz.hour = n / 100;
                    tz.minute = n % 100;
                } else {
                    return None;
                }
            }
            _ if (token.is_ascii_sign() || token.is_symbol(b')')) && has_read_number => return None,
            _ => {}
        }
        token = scanner.next();
    }

    let [year, month, day_of_month] = day.write()?;
    let [hour, minute, second, millisecond] = time.write()?;
    let offset = tz.write()?;
    Some([
        f64::from(year),
        f64::from(month),
        f64::from(day_of_month),
        f64::from(hour),
        f64::from(minute),
        f64::from(second),
        f64::from(millisecond),
        offset,
    ])
}

/// V8 `MakeDay` for the integral inputs the parser produces.
fn make_day(year: f64, month: f64, date: f64) -> f64 {
    if !((-1_000_000.0..=1_000_000.0).contains(&year) && (-10_000_000.0..=10_000_000.0).contains(&month) && date.is_finite())
    {
        return f64::NAN;
    }
    let mut y = year as i64;
    let mut m = month as i64;
    y += m / 12;
    m %= 12;
    if m < 0 {
        m += 12;
        y -= 1;
    }
    const YEAR_DELTA: i64 = 399_999;
    let base_day = 365 * (1970 + YEAR_DELTA) + (1970 + YEAR_DELTA) / 4 - (1970 + YEAR_DELTA) / 100 + (1970 + YEAR_DELTA) / 400;
    let mut day_from_year =
        365 * (y + YEAR_DELTA) + (y + YEAR_DELTA) / 4 - (y + YEAR_DELTA) / 100 + (y + YEAR_DELTA) / 400 - base_day;
    const COMMON: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    const LEAP: [i64; 12] = [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335];
    if (y % 4 != 0) || (y % 100 == 0 && y % 400 != 0) {
        day_from_year += COMMON[m as usize];
    } else {
        day_from_year += LEAP[m as usize];
    }
    (day_from_year - 1) as f64 + date.trunc()
}

/// `Date.parse(text)` with TZ=UTC: milliseconds since the epoch, or NaN.
pub fn parse(text: &str) -> f64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let Some(fields) = parse_fields(&units) else { return f64::NAN };
    let day = make_day(fields[0], fields[1], fields[2]);
    let time = fields[3] * 3_600_000.0 + fields[4] * 60_000.0 + fields[5] * 1000.0 + fields[6];
    let mut date = if day.is_finite() { time + day * MS_PER_DAY } else { f64::NAN };
    if fields[7].is_nan() {
        // Local time; production runs with TZ=UTC so there is no offset to apply
        if !(-MAX_TIME_BEFORE_UTC_IN_MS..=MAX_TIME_BEFORE_UTC_IN_MS).contains(&date) {
            return f64::NAN;
        }
        date = (date as i64) as f64;
    } else {
        date -= fields[7] * 1000.0;
    }
    time_clip(date)
}

/// ECMAScript TimeClip.
pub fn time_clip(time: f64) -> f64 {
    if (-MAX_TIME_IN_MS..=MAX_TIME_IN_MS).contains(&time) {
        time.trunc() + 0.0
    } else {
        f64::NAN
    }
}

/// `new Date(ms).toISOString()`; `None` for an invalid date, where JavaScript
/// throws `RangeError: Invalid time value`.
pub fn to_iso_string(ms: f64) -> Option<String> {
    let ms = time_clip(ms);
    if ms.is_nan() {
        return None;
    }
    let ms = ms as i64;
    let days = ms.div_euclid(86_400_000);
    let time_in_day = ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let hour = time_in_day / 3_600_000;
    let minute = time_in_day / 60_000 % 60;
    let second = time_in_day / 1000 % 60;
    let millisecond = time_in_day % 1000;
    let year_text = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    Some(format!("{year_text}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millisecond:03}Z"))
}

/// Proleptic Gregorian date for a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso(text: &str) -> Option<String> {
        to_iso_string(parse(text))
    }

    #[test]
    fn es5_formats() {
        assert_eq!(iso("2024-01-15T10:30:00Z").as_deref(), Some("2024-01-15T10:30:00.000Z"));
        assert_eq!(iso("2024-01-15T10:30:00+02:00").as_deref(), Some("2024-01-15T08:30:00.000Z"));
        assert_eq!(iso("2024-01-15T10:30:00-0500").as_deref(), Some("2024-01-15T15:30:00.000Z"));
        assert_eq!(iso("2024-01-15T10:30:00.999Z").as_deref(), Some("2024-01-15T10:30:00.999Z"));
        assert_eq!(iso("2024-01-15").as_deref(), Some("2024-01-15T00:00:00.000Z"));
        assert_eq!(iso("2024-02-31").as_deref(), Some("2024-03-02T00:00:00.000Z"));
        assert_eq!(iso("2024-01-15T24:00:00Z").as_deref(), Some("2024-01-16T00:00:00.000Z"));
        assert_eq!(iso("0000-01-01T00:00:00+01:00").as_deref(), Some("-000001-12-31T23:00:00.000Z"));
        assert!(parse("2024-13-01").is_nan());
        assert!(parse("2024-01-01T25:00:00Z").is_nan());
        assert!(parse("2024-01-01T10:00:00+24:00").is_nan());
    }

    #[test]
    fn legacy_formats() {
        assert_eq!(iso("01/01/2025").as_deref(), Some("2025-01-01T00:00:00.000Z"));
        assert_eq!(iso("0001-01-00").as_deref(), Some("2000-01-01T00:00:00.000Z"));
        assert_eq!(iso("Jan 5 2024 10:00 PM").as_deref(), Some("2024-01-05T22:00:00.000Z"));
        assert!(parse("bogus").is_nan());
        assert!(parse("not-a-dateZ").is_nan());
    }
}
