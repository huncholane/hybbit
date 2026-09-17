//! `safe-regex2` 5.0.0 on top of `ret` 0.5.0, ported from
//! server/node_modules/safe-regex2/index.js and server/node_modules/ret/dist/.
//!
//! safe-regex2 tokenizes the pattern with ret, then walks the tokens counting
//! repetitions and their nesting ("star height"). ret is not a JavaScript regex
//! parser: it pre-decodes some escapes with a string replace, rejects syntax V8
//! accepts (lookbehinds, modifier groups, non-ASCII group names), and the walk skips
//! the alternatives of a repeated group. Validation therefore depends on ret's exact
//! token tree, which this module reproduces (object identity included, since ret
//! rewrites unresolved backreferences in place after tokenizing).

use serde_json::{Map, Value, json};

/// ret's `types` enum values.
mod types {
    pub const ROOT: u8 = 0;
    pub const GROUP: u8 = 1;
    pub const POSITION: u8 = 2;
    pub const SET: u8 = 3;
    pub const RANGE: u8 = 4;
    pub const REPETITION: u8 = 5;
    pub const REFERENCE: u8 = 6;
    pub const CHAR: u8 = 7;
}

/// `safeRegex(pattern, { limit })`: false when ret cannot tokenize the pattern, when
/// a repetition is nested inside another walked repetition, or when more than
/// `limit` repetitions are walked.
pub fn is_safe(pattern: &str, limit: usize) -> bool {
    let units: Vec<u16> = pattern.encode_utf16().collect();
    let Ok(tree) = tokenize(&units) else {
        return false;
    };
    let mut repetitions = 0;
    walk(&tree, NodeRef::Token(tree.root), 0, &mut repetitions, limit)
}

/// A token inside a class (`set` entries): never shared, so owned.
#[derive(Clone, Debug, PartialEq)]
enum SetToken {
    Set { set: Vec<SetToken>, not: bool },
    Range { from: u32, to: u32 },
    Char(u32),
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Root(Container),
    Group {
        container: Container,
        remember: bool,
        followed_by: bool,
        not_followed_by: bool,
        name: Option<String>,
    },
    Position(u8),
    Set {
        set: Vec<SetToken>,
        not: bool,
    },
    Repetition {
        min: f64,
        max: f64,
        value: usize,
    },
    Reference(f64),
    /// A double: references rewritten by `updateReferences` can hold any number
    Char(f64),
}

/// A root or group: a `stack` until the first `|`, then `options` (the old stack
/// becomes the first option and `stack` is deleted).
#[derive(Clone, Debug, PartialEq)]
struct Container {
    stack: Option<usize>,
    options: Option<Vec<usize>>,
}

impl Container {
    fn new(stack: usize) -> Self {
        Self { stack: Some(stack), options: None }
    }

    /// The stack new tokens go to (`last` in ret).
    fn last(&self) -> usize {
        match &self.options {
            Some(options) => *options.last().expect("options are never empty"),
            None => self.stack.expect("a container without options has a stack"),
        }
    }
}

/// Tokens and stacks by index, so a stack keeps its identity when it moves into
/// `options` and a reference can be rewritten after it was wrapped in a repetition.
#[derive(Debug)]
struct Tree {
    tokens: Vec<Token>,
    stacks: Vec<Vec<usize>>,
    root: usize,
}

impl Tree {
    fn push_token(&mut self, token: Token) -> usize {
        self.tokens.push(token);
        self.tokens.len() - 1
    }

    fn new_stack(&mut self) -> usize {
        self.stacks.push(Vec::new());
        self.stacks.len() - 1
    }

    fn container(&mut self, token: usize) -> &mut Container {
        match &mut self.tokens[token] {
            Token::Root(container) | Token::Group { container, .. } => container,
            _ => unreachable!("only roots and groups hold stacks"),
        }
    }
}

/// ret throws a SyntaxError; safe-regex2 only needs to know that it did.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenizeError {
    Syntax,
    /// `updateReferences` searches for an 8 or 9 in the number's text forever when
    /// the reference has neither (`\99999999999999999999` prints as 1 and zeros).
    /// Node never returns from the validation; the port treats it as unsafe.
    NodeHangs,
}

const fn ch(character: char) -> u32 {
    character as u32
}

fn unit_is(units: &[u16], index: usize, character: char) -> bool {
    units.get(index).is_some_and(|&unit| u32::from(unit) == ch(character))
}

fn is_ascii_digit_unit(unit: u16) -> bool {
    (u16::from(b'0')..=u16::from(b'9')).contains(&unit)
}

/// `util.strToChars`: `[\b]`, `\uXXXX`, `\xXX`, `\cX`, `\0`, `\t`, `\n`, `\v`, `\f` and
/// `\r` become the characters they name (regex syntax characters get a backslash),
/// unless the escape's backslash is itself escaped. Hex digits must be uppercase.
fn str_to_chars(units: &[u16]) -> Vec<u16> {
    const CTRL: &str = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^ ?";
    let is_hex = |unit: u16| {
        (u16::from(b'0')..=u16::from(b'9')).contains(&unit) || (u16::from(b'A')..=u16::from(b'F')).contains(&unit)
    };
    let hex_value = |digits: &[u16]| {
        digits.iter().fold(0u32, |value, &unit| value * 16 + (unit as u8 as char).to_digit(16).unwrap_or(0))
    };

    // The escape after a backslash at `at`: its length and code, if it is one
    let escape_at = |at: usize| -> Option<(usize, u32)> {
        let first = *units.get(at)?;
        match char::from_u32(u32::from(first))? {
            'u' if at + 5 <= units.len() && units[at + 1..at + 5].iter().all(|&unit| is_hex(unit)) => {
                Some((5, hex_value(&units[at + 1..at + 5])))
            }
            'x' if at + 3 <= units.len() && units[at + 1..at + 3].iter().all(|&unit| is_hex(unit)) => {
                Some((3, hex_value(&units[at + 1..at + 3])))
            }
            'c' => {
                let control = char::from_u32(u32::from(*units.get(at + 1)?))?;
                let index =
                    CTRL.find(control).filter(|_| matches!(control, '@' | 'A'..='Z' | '[' | '\\' | ']' | '^' | '?'))?;
                Some((2, index as u32))
            }
            '0' => Some((1, 0)),
            't' => Some((1, 9)),
            'n' => Some((1, 10)),
            'v' => Some((1, 11)),
            'f' => Some((1, 12)),
            'r' => Some((1, 13)),
            _ => None,
        }
    };

    let mut out = Vec::with_capacity(units.len());
    let mut index = 0;
    while index < units.len() {
        // (\[\\b\])
        if unit_is(units, index, '[')
            && unit_is(units, index + 1, '\\')
            && unit_is(units, index + 2, 'b')
            && unit_is(units, index + 3, ']')
        {
            out.push(8);
            index += 4;
            continue;
        }
        if unit_is(units, index, '\\') {
            // (\\)?\\(...): with the optional backslash first (greedy), then without
            if unit_is(units, index + 1, '\\')
                && let Some((length, _)) = escape_at(index + 2)
            {
                out.extend_from_slice(&units[index..index + 2 + length]);
                index += 2 + length;
                continue;
            }
            if let Some((length, code)) = escape_at(index + 1) {
                let character = code as u16;
                if matches!(
                    char::from_u32(code),
                    Some('[' | ']' | '{' | '}' | '^' | '$' | '.' | '|' | '?' | '*' | '+' | '(' | ')')
                ) {
                    out.push(u16::from(b'\\'));
                }
                out.push(character);
                index += 1 + length;
                continue;
            }
        }
        out.push(units[index]);
        index += 1;
    }
    out
}

/// `util.tokenizeClass`: the tokens of a class body up to its closing `]`, and how
/// many code units that consumed.
fn tokenize_class(units: &[u16]) -> Result<(Vec<SetToken>, usize), TokenizeError> {
    let is_line_terminator = |unit: u16| matches!(unit, 0x0a | 0x0d | 0x2028 | 0x2029);
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let next = units.get(index + 1).copied();

        // \\(?:(w)|(d)|(s)|(W)|(D)|(S))
        if unit == u16::from(b'\\')
            && let Some(kind) = next.and_then(|next| char::from_u32(u32::from(next)))
            && matches!(kind, 'w' | 'd' | 's' | 'W' | 'D' | 'S')
        {
            tokens.push(class_set(kind));
            index += 2;
            continue;
        }

        // ((?:\\(.)|([^\]\\]))-(\\]|(\\)?([^\]]))
        let from = if unit == u16::from(b'\\') {
            next.filter(|&next| !is_line_terminator(next)).map(|next| (next, 2))
        } else if unit != u16::from(b']') {
            Some((unit, 1))
        } else {
            None
        };
        if let Some((from, from_length)) = from
            && unit_is(units, index + from_length, '-')
        {
            let to_start = index + from_length + 1;
            let to = if unit_is(units, to_start, '\\') && unit_is(units, to_start + 1, ']') {
                Some((u32::from(b']'), 2))
            } else if unit_is(units, to_start, '\\')
                && let Some(&escaped) = units.get(to_start + 1)
            {
                // `]` after the backslash was the previous branch
                Some((u32::from(escaped), 2))
            } else {
                units.get(to_start).filter(|&&to| to != u16::from(b']')).map(|&to| (u32::from(to), 1))
            };
            if let Some((to, to_length)) = to {
                tokens.push(SetToken::Range { from: u32::from(from), to });
                index = to_start + to_length;
                continue;
            }
        }

        // (\]) ends the class
        if unit == u16::from(b']') {
            return Ok((tokens, index + 1));
        }

        // (?:\\)?([^])
        if unit == u16::from(b'\\')
            && let Some(escaped) = next
        {
            tokens.push(SetToken::Char(u32::from(escaped)));
            index += 2;
        } else {
            tokens.push(SetToken::Char(u32::from(unit)));
            index += 1;
        }
    }
    Err(TokenizeError::Syntax)
}

/// `sets.words()` and friends.
fn class_set(kind: char) -> SetToken {
    let ranges: Vec<SetToken> = match kind.to_ascii_lowercase() {
        'w' => vec![
            SetToken::Char(95),
            SetToken::Range { from: 97, to: 122 },
            SetToken::Range { from: 65, to: 90 },
            SetToken::Range { from: 48, to: 57 },
        ],
        'd' => vec![SetToken::Range { from: 48, to: 57 }],
        _ => vec![
            SetToken::Char(9),
            SetToken::Char(10),
            SetToken::Char(11),
            SetToken::Char(12),
            SetToken::Char(13),
            SetToken::Char(32),
            SetToken::Char(160),
            SetToken::Char(5760),
            SetToken::Range { from: 8192, to: 8202 },
            SetToken::Char(8232),
            SetToken::Char(8233),
            SetToken::Char(8239),
            SetToken::Char(8287),
            SetToken::Char(12288),
            SetToken::Char(65279),
        ],
    };
    SetToken::Set { set: ranges, not: kind.is_ascii_uppercase() }
}

/// `sets.anyChar()`.
fn any_char() -> Token {
    Token::Set {
        set: vec![SetToken::Char(10), SetToken::Char(13), SetToken::Char(8232), SetToken::Char(8233)],
        not: true,
    }
}

fn set_token(set: SetToken) -> Token {
    match set {
        SetToken::Set { set, not } => Token::Set { set, not },
        SetToken::Range { .. } | SetToken::Char(_) => unreachable!("class escapes are sets"),
    }
}

/// `/^[a-zA-Z_$]$/i` (non-Unicode case folding never maps non-ASCII to ASCII).
fn is_capture_first_char(unit: Option<u16>) -> bool {
    unit.and_then(|unit| char::from_u32(u32::from(unit)))
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_' || character == '$')
}

/// `/^[a-zA-Z0-9_$]$/i`.
fn is_capture_char(unit: Option<u16>) -> bool {
    unit.and_then(|unit| char::from_u32(u32::from(unit)))
        .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_' || character == '$')
}

/// `parseInt` of an ASCII digit run.
fn parse_decimal(digits: &[u16]) -> f64 {
    let text: String = digits.iter().map(|&unit| unit as u8 as char).collect();
    text.parse::<f64>().unwrap_or(f64::NAN)
}

struct PendingReference {
    token: usize,
    stack: usize,
    index: usize,
}

/// ret's `tokenizer`.
fn tokenize(pattern: &[u16]) -> Result<Tree, TokenizeError> {
    let str = str_to_chars(pattern);
    let mut tree = Tree { tokens: Vec::new(), stacks: Vec::new(), root: 0 };
    let root_stack = tree.new_stack();
    let root = tree.push_token(Token::Root(Container::new(root_stack)));
    tree.root = root;

    let mut last_group = root;
    let mut last = root_stack;
    let mut group_stack: Vec<usize> = Vec::new();
    let mut references: Vec<PendingReference> = Vec::new();
    let mut group_count = 0u32;
    let mut index = 0usize;

    while index < str.len() {
        let character = str[index];
        index += 1;
        match char::from_u32(u32::from(character)) {
            Some('\\') => {
                if index == str.len() {
                    return Err(TokenizeError::Syntax);
                }
                let escaped = str[index];
                index += 1;
                let token = match char::from_u32(u32::from(escaped)) {
                    Some('b') => Token::Position(b'b'),
                    Some('B') => Token::Position(b'B'),
                    Some(kind @ ('w' | 'W' | 'd' | 'D' | 's' | 'S')) => set_token(class_set(kind)),
                    _ if is_ascii_digit_unit(escaped) => {
                        let start = index - 1;
                        while index < str.len() && is_ascii_digit_unit(str[index]) {
                            index += 1;
                        }
                        let value = parse_decimal(&str[start..index]);
                        let token = tree.push_token(Token::Reference(value));
                        tree.stacks[last].push(token);
                        references.push(PendingReference { token, stack: last, index: tree.stacks[last].len() - 1 });
                        continue;
                    }
                    _ => Token::Char(f64::from(escaped)),
                };
                let token = tree.push_token(token);
                tree.stacks[last].push(token);
            }
            Some('^') => {
                let token = tree.push_token(Token::Position(b'^'));
                tree.stacks[last].push(token);
            }
            Some('$') => {
                let token = tree.push_token(Token::Position(b'$'));
                tree.stacks[last].push(token);
            }
            Some('[') => {
                let not = unit_is(&str, index, '^');
                if not {
                    index += 1;
                }
                let (set, consumed) = tokenize_class(&str[index..])?;
                index += consumed;
                let token = tree.push_token(Token::Set { set, not });
                tree.stacks[last].push(token);
            }
            Some('.') => {
                let token = tree.push_token(any_char());
                tree.stacks[last].push(token);
            }
            Some('(') => {
                let stack = tree.new_stack();
                let mut remember = true;
                let mut followed_by = false;
                let mut not_followed_by = false;
                let mut name = None;
                if unit_is(&str, index, '?') {
                    let kind = str.get(index + 1).copied();
                    index += 2;
                    match kind.and_then(|kind| char::from_u32(u32::from(kind))) {
                        Some('=') => {
                            followed_by = true;
                            remember = false;
                        }
                        Some('!') => {
                            not_followed_by = true;
                            remember = false;
                        }
                        Some('<') => {
                            if !is_capture_first_char(str.get(index).copied()) {
                                return Err(TokenizeError::Syntax);
                            }
                            let start = index;
                            index += 1;
                            while index < str.len() && is_capture_char(Some(str[index])) {
                                index += 1;
                            }
                            if !unit_is(&str, index, '>') {
                                return Err(TokenizeError::Syntax);
                            }
                            name = Some(String::from_utf16_lossy(&str[start..index]));
                            index += 1;
                        }
                        Some(':') => remember = false,
                        _ => return Err(TokenizeError::Syntax),
                    }
                } else {
                    group_count += 1;
                }
                let group = tree.push_token(Token::Group {
                    container: Container::new(stack),
                    remember,
                    followed_by,
                    not_followed_by,
                    name,
                });
                tree.stacks[last].push(group);
                group_stack.push(last_group);
                last_group = group;
                last = stack;
            }
            Some(')') => {
                let Some(previous) = group_stack.pop() else {
                    return Err(TokenizeError::Syntax);
                };
                last_group = previous;
                last = tree.container(last_group).last();
            }
            Some('|') => {
                let stack = tree.new_stack();
                let container = tree.container(last_group);
                if container.options.is_none() {
                    container.options = Some(vec![container.stack.take().expect("stack before the first pipe")]);
                }
                container.options.as_mut().expect("options").push(stack);
                last = stack;
            }
            Some('{') => {
                // /^(\d+)(,(\d+)?)?\}/
                let rest = &str[index..];
                let min_digits = rest.iter().take_while(|&&unit| is_ascii_digit_unit(unit)).count();
                let mut quantifier = None;
                if min_digits > 0 {
                    let mut cursor = min_digits;
                    let mut max = None;
                    if unit_is(rest, cursor, ',') {
                        let max_digits =
                            rest[cursor + 1..].iter().take_while(|&&unit| is_ascii_digit_unit(unit)).count();
                        if unit_is(rest, cursor + 1 + max_digits, '}') {
                            max = Some(if max_digits > 0 {
                                parse_decimal(&rest[cursor + 1..cursor + 1 + max_digits])
                            } else {
                                f64::INFINITY
                            });
                            cursor += 1 + max_digits;
                        }
                    }
                    if unit_is(rest, cursor, '}') {
                        let min = parse_decimal(&rest[..min_digits]);
                        quantifier = Some((min, max.unwrap_or(min), cursor + 1));
                    }
                }
                match quantifier {
                    Some((min, max, consumed)) => {
                        let Some(value) = tree.stacks[last].pop() else {
                            return Err(TokenizeError::Syntax);
                        };
                        index += consumed;
                        let token = tree.push_token(Token::Repetition { min, max, value });
                        tree.stacks[last].push(token);
                    }
                    None => {
                        let token = tree.push_token(Token::Char(123.0));
                        tree.stacks[last].push(token);
                    }
                }
            }
            Some(symbol @ ('?' | '+' | '*')) => {
                let Some(value) = tree.stacks[last].pop() else {
                    return Err(TokenizeError::Syntax);
                };
                let (min, max) = match symbol {
                    '?' => (0.0, 1.0),
                    '+' => (1.0, f64::INFINITY),
                    _ => (0.0, f64::INFINITY),
                };
                let token = tree.push_token(Token::Repetition { min, max, value });
                tree.stacks[last].push(token);
            }
            _ => {
                let token = tree.push_token(Token::Char(f64::from(character)));
                tree.stacks[last].push(token);
            }
        }
    }

    if !group_stack.is_empty() {
        return Err(TokenizeError::Syntax);
    }
    update_references(&mut tree, references, group_count)?;
    Ok(tree)
}

/// `updateReferences`: a backreference past the number of groups becomes the octal
/// character (and literal digits) it would be in a JavaScript RegExp.
fn update_references(
    tree: &mut Tree,
    mut references: Vec<PendingReference>,
    group_count: u32,
) -> Result<(), TokenizeError> {
    references.reverse();
    for reference in references {
        let Token::Reference(value) = tree.tokens[reference.token] else {
            continue;
        };
        if f64::from(group_count) >= value {
            continue;
        }
        let text = super::super::js::number_to_string(value);
        let digits: Vec<u8> = text.bytes().collect();
        let octal = |digits: &[u8]| -> f64 {
            // parseInt(text, 8) stops at the first non-octal digit
            let mut result = 0.0;
            let mut any = false;
            for &digit in digits {
                if !(b'0'..=b'7').contains(&digit) {
                    break;
                }
                any = true;
                result = result * 8.0 + f64::from(digit - b'0');
            }
            if any { result } else { f64::NAN }
        };

        if digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
            tree.tokens[reference.token] = Token::Char(octal(&digits));
            continue;
        }
        let Some(mut split) = digits.iter().position(|&digit| digit == b'8' || digit == b'9') else {
            tracing::warn!(
                value,
                "feature flag regex backreference would hang Node's safe-regex2; treating the pattern as unsafe"
            );
            return Err(TokenizeError::NodeHangs);
        };
        let value = if split == 0 {
            split = 1;
            f64::from(digits[0])
        } else {
            octal(&digits[..split])
        };
        tree.tokens[reference.token] = Token::Char(value);
        if digits.len() > split {
            let tail = tree.stacks[reference.stack].split_off(reference.index + 1);
            for &digit in &digits[split..] {
                tree.tokens.push(Token::Char(f64::from(digit)));
                let id = tree.tokens.len() - 1;
                tree.stacks[reference.stack].push(id);
            }
            tree.stacks[reference.stack].extend(tail);
        }
    }
    Ok(())
}

enum NodeRef {
    Token(usize),
    /// `{ stack: option }`, the wrapper safe-regex2 walks alternatives through
    Stack(usize),
}

/// safe-regex2's `walk`.
fn walk(tree: &Tree, node: NodeRef, star_height: usize, repetitions: &mut usize, limit: usize) -> bool {
    let mut star_height = star_height;
    let (options, stack) = match node {
        NodeRef::Stack(stack) => (None, Some(stack)),
        NodeRef::Token(token) => match &tree.tokens[token] {
            Token::Repetition { value, .. } => {
                star_height += 1;
                *repetitions += 1;
                if star_height > 1 || *repetitions > limit {
                    return false;
                }
                // node.value?.stack: only a group still without options has one
                let stack = match &tree.tokens[*value] {
                    Token::Root(container) | Token::Group { container, .. } => container.stack,
                    _ => None,
                };
                (None, stack)
            }
            Token::Root(container) | Token::Group { container, .. } => (container.options.as_ref(), container.stack),
            _ => (None, None),
        },
    };
    if let Some(options) = options {
        for &option in options {
            if !walk(tree, NodeRef::Stack(option), star_height, repetitions, limit) {
                return false;
            }
        }
    }
    let Some(stack) = stack else {
        return true;
    };
    tree.stacks[stack].iter().all(|&child| walk(tree, NodeRef::Token(child), star_height, repetitions, limit))
}

/// ret's token tree as JSON, with `JSON.stringify`'s view of it (Infinity is null),
/// for comparing against the real tokenizer. `Err` when ret throws.
pub fn tokens_json(pattern: &str) -> Result<Value, TokenizeError> {
    let units: Vec<u16> = pattern.encode_utf16().collect();
    let tree = tokenize(&units)?;
    Ok(token_json(&tree, tree.root))
}

fn number(value: f64) -> Value {
    super::super::js::number_json(value)
}

fn set_json(token: &SetToken) -> Value {
    match token {
        SetToken::Set { set, not } => {
            json!({ "type": types::SET, "set": set.iter().map(set_json).collect::<Vec<_>>(), "not": not })
        }
        SetToken::Range { from, to } => json!({ "type": types::RANGE, "from": from, "to": to }),
        SetToken::Char(value) => json!({ "type": types::CHAR, "value": value }),
    }
}

fn stack_json(tree: &Tree, stack: usize) -> Value {
    Value::Array(tree.stacks[stack].iter().map(|&token| token_json(tree, token)).collect())
}

fn container_json(tree: &Tree, container: &Container, map: &mut Map<String, Value>) {
    if let Some(stack) = container.stack {
        map.insert("stack".into(), stack_json(tree, stack));
    }
    if let Some(options) = &container.options {
        map.insert("options".into(), Value::Array(options.iter().map(|&stack| stack_json(tree, stack)).collect()));
    }
}

fn token_json(tree: &Tree, token: usize) -> Value {
    match &tree.tokens[token] {
        Token::Root(container) => {
            let mut map = Map::new();
            map.insert("type".into(), json!(types::ROOT));
            container_json(tree, container, &mut map);
            Value::Object(map)
        }
        Token::Group { container, remember, followed_by, not_followed_by, name } => {
            let mut map = Map::new();
            map.insert("type".into(), json!(types::GROUP));
            map.insert("remember".into(), json!(remember));
            if *followed_by {
                map.insert("followedBy".into(), json!(true));
            }
            if *not_followed_by {
                map.insert("notFollowedBy".into(), json!(true));
            }
            if let Some(name) = name {
                map.insert("name".into(), json!(name));
            }
            container_json(tree, container, &mut map);
            Value::Object(map)
        }
        Token::Position(value) => json!({ "type": types::POSITION, "value": (*value as char).to_string() }),
        Token::Set { set, not } => {
            json!({ "type": types::SET, "set": set.iter().map(set_json).collect::<Vec<_>>(), "not": not })
        }
        Token::Repetition { min, max, value } => {
            json!({ "type": types::REPETITION, "min": number(*min), "max": number(*max), "value": token_json(tree, *value) })
        }
        Token::Reference(value) => json!({ "type": types::REFERENCE, "value": number(*value) }),
        Token::Char(value) => json!({ "type": types::CHAR, "value": number(*value) }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_safe_regex2_decisions() {
        let cases = [
            ("^/pricing", true),
            ("foo|bar", true),
            ("[a-z]+\\d{2}", true),
            ("(a+)+$", false),
            ("^(x+x+)+y$", false),
            ("(a{2,3}){2,3}", false),
            ("(a|a)*$", true),
            ("(a+|b)*", true),
            ("(?<=a)b", false),
            ("(?i:a)", false),
            ("(?<name>a)", true),
            ("(?<na-me>a)", false),
            ("a+?", true),
            ("(a+)+?", true),
        ];
        for (pattern, safe) in cases {
            assert_eq!(is_safe(pattern, 25), safe, "{pattern:?}");
        }
        assert!(is_safe(&"a*".repeat(25), 25));
        assert!(!is_safe(&"a*".repeat(26), 25));
    }

    #[test]
    fn rewrites_unresolved_references_like_ret() {
        assert_eq!(
            tokens_json("\\18*").expect("tokenizes"),
            json!({"type": 0, "stack": [
                {"type": 5, "min": 0, "max": null, "value": {"type": 7, "value": 1}},
                {"type": 7, "value": 56}
            ]})
        );
    }
}
