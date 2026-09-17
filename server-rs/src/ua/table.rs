//! The shapes ua-parser-js tables are written in (`[regexes], [props]` pairs) and the
//! property semantics of `rgxMapper` and `strMapper`, with the string operations its
//! tuple properties use implemented to match JS exactly.

/// A property a rule can set. ua-parser-js keeps one bag of these per item
/// (`browser`, `cpu`, `device`, `engine`, `os`); `major` is derived, never matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Field {
    Name,
    Version,
    Type,
    Model,
    Vendor,
    Architecture,
}

/// One entry of a rule's property list. The n-th entry reads capture group n+1,
/// whether or not it uses it (rgxMapper advances its group index for every entry).
#[derive(Debug)]
pub(super) enum Prop {
    /// `FIELD`: the capture, with `""` and a non-participating group both undefined.
    Capture(Field),
    /// `[FIELD, 'value']`: the constant, whatever matched.
    Const(Field, &'static str),
    /// `[FIELD, lowerize]`: called even without a capture, so `""` stays `""`.
    Lower(Field),
    /// `[FIELD, trim]`: leading JS whitespace stripped; `""` stays `""`.
    Trim(Field),
    /// `[FIELD, /re/, 'replacement']`: only applied to a non-empty capture.
    Replace(Field, Rep),
    /// `[FIELD, /re/, 'replacement', lowerize]`.
    ReplaceLower(Field, Rep),
    /// `[FIELD, strMapper, map]`: only applied to a non-empty capture.
    Map(Field, &'static StrMap),
}

/// The `String.prototype.replace` calls the tables make, one variant per distinct
/// regex. tools/generate.cjs refuses any regex/replacement pair not listed here.
#[derive(Debug)]
pub(super) enum Rep {
    /// `/(.+)/` or `/(.+)/g` with `prefix$1suffix`: wraps the first (or every) run of
    /// characters that are not JS line terminators.
    WrapLines { prefix: &'static str, suffix: &'static str, global: bool },
    /// `/_/g` and `/\./g`.
    ReplaceAll { from: char, to: &'static str },
    /// `/^/`: inserts at the start.
    Prepend(&'static str),
    /// `/[^\d\.]+./` replaced with nothing (Cobalt's version clean-up).
    StripFirstNonVersionRun,
    /// A case-sensitive literal (`/ower/`) removed once.
    RemoveFirst(&'static str),
}

/// One `[regexes], [props]` pair of a table, as written in ua-parser.js.
#[derive(Debug)]
pub(super) struct RuleSrc {
    pub patterns: &'static [&'static str],
    pub props: &'static [Prop],
}

/// A `strMapper` map. `entries` are in JS `for...in` order (integer-like keys
/// first), each with the needles its value lists; `fallback` is `map['*']` when
/// the map has that key (`Some(None)` for an explicit undefined).
#[derive(Debug)]
pub(super) struct StrMap {
    pub entries: &'static [(&'static str, &'static [&'static str])],
    pub fallback: Option<Option<&'static str>>,
}

impl StrMap {
    /// `strMapper(str, map)`: the first key whose needle occurs in `str`
    /// (case-insensitively), `undefined` for the `'?'` key, else `map['*']` or `str`.
    /// A `'*'` key with a string value is also an ordinary entry, so an input that
    /// contains that value maps to the literal key `"*"`, exactly as in JS.
    pub fn apply(&self, input: &str) -> Option<String> {
        let haystack = input.to_lowercase();
        for (key, needles) in self.entries {
            if needles.iter().any(|needle| haystack.contains(&needle.to_lowercase())) {
                return (*key != "?").then(|| (*key).to_string());
            }
        }
        match self.fallback {
            Some(value) => value.map(str::to_string),
            None => Some(input.to_string()),
        }
    }
}

/// The per-item property bag rgxMapper writes into (`this` in ua-parser-js).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Fields {
    pub name: Option<String>,
    pub version: Option<String>,
    pub r#type: Option<String>,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub architecture: Option<String>,
}

impl Fields {
    fn slot(&mut self, field: Field) -> &mut Option<String> {
        match field {
            Field::Name => &mut self.name,
            Field::Version => &mut self.version,
            Field::Type => &mut self.r#type,
            Field::Model => &mut self.model,
            Field::Vendor => &mut self.vendor,
            Field::Architecture => &mut self.architecture,
        }
    }

    /// Applies one property given its capture group (`None` when the group did not
    /// participate or does not exist), mirroring the branches of `rgxMapper`.
    pub fn apply(&mut self, prop: &Prop, capture: Option<&str>) {
        // `match ? f(match) : undefined`: JS treats "" as falsy
        let non_empty = capture.filter(|text| !text.is_empty());
        let (field, value) = match prop {
            Prop::Capture(field) => (*field, non_empty.map(str::to_string)),
            Prop::Const(field, value) => (*field, Some((*value).to_string())),
            Prop::Lower(field) => (*field, capture.map(str::to_lowercase)),
            Prop::Trim(field) => (*field, capture.map(|text| trim_start_js(text).to_string())),
            Prop::Replace(field, rep) => (*field, non_empty.map(|text| rep.apply(text))),
            Prop::ReplaceLower(field, rep) => (*field, non_empty.map(|text| rep.apply(text).to_lowercase())),
            Prop::Map(field, map) => (*field, non_empty.and_then(|text| map.apply(text))),
        };
        *self.slot(field) = value;
    }
}

impl Rep {
    pub fn apply(&self, input: &str) -> String {
        match self {
            Rep::WrapLines { prefix, suffix, global } => wrap_lines(input, prefix, suffix, *global),
            Rep::ReplaceAll { from, to } => input.replace(*from, to),
            Rep::Prepend(prefix) => format!("{prefix}{input}"),
            Rep::StripFirstNonVersionRun => strip_first_non_version_run(input),
            Rep::RemoveFirst(needle) => input.replacen(needle, "", 1),
        }
    }
}

/// JS `LineTerminator`: what `.` refuses to match.
pub(super) fn is_js_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// JS `\s`: WhiteSpace (including the BOM and every `Zs` space) plus LineTerminator.
/// Unlike Rust's `char::is_whitespace` it excludes U+0085 and includes U+FEFF.
pub(super) fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{0B}'
            | '\u{0C}'
            | '\r'
            | ' '
            | '\u{A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// `str.replace(/^\s\s*/, '')`, the whitespace half of ua-parser's `trim`.
pub(super) fn trim_start_js(input: &str) -> &str {
    input.trim_start_matches(is_js_whitespace)
}

/// `input.replace(/(.+)/, prefix + '$1' + suffix)` (or `/g`).
fn wrap_lines(input: &str, prefix: &str, suffix: &str, global: bool) -> String {
    let mut out = String::with_capacity(input.len() + prefix.len() + suffix.len());
    let mut in_run = false;
    let mut done = false;
    for c in input.chars() {
        let terminator = is_js_line_terminator(c);
        if in_run && terminator {
            out.push_str(suffix);
            in_run = false;
            done = !global;
        } else if !in_run && !terminator && !done {
            out.push_str(prefix);
            in_run = true;
        }
        out.push(c);
    }
    if in_run {
        out.push_str(suffix);
    }
    out
}

/// `input.replace(/[^\d\.]+./, '')`: the leftmost match, with the greedy run
/// backtracking until `.` finds a non-terminator after it.
fn strip_first_non_version_run(input: &str) -> String {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let in_class = |c: char| !(c.is_ascii_digit() || c == '.');
    for start in 0..chars.len() {
        if !in_class(chars[start].1) {
            continue;
        }
        let mut run_end = start;
        while run_end < chars.len() && in_class(chars[run_end].1) {
            run_end += 1;
        }
        for dot in (start + 1..=run_end).rev() {
            if dot < chars.len() && !is_js_line_terminator(chars[dot].1) {
                let from = chars[start].0;
                let to = chars.get(dot + 1).map_or(input.len(), |(offset, _)| *offset);
                return format!("{}{}", &input[..from], &input[to..]);
            }
        }
    }
    input.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_lines_matches_js_replace() {
        // "a\nb".replace(/(.+)/, '$1 X') === "a X\nb"; with /g: "a X\nb X"
        assert_eq!(wrap_lines("avast", "", " Secure Browser", false), "avast Secure Browser");
        assert_eq!(wrap_lines("a\nb", "", " X", false), "a X\nb");
        assert_eq!(wrap_lines("a\nb", "P ", "", true), "P a\nP b");
        assert_eq!(wrap_lines("\n\n", "P ", "", true), "\n\n");
        assert_eq!(wrap_lines("", "P ", "", true), "");
    }

    #[test]
    fn strip_first_non_version_run_matches_js_replace() {
        // "22.lts.4.306044-gold".replace(/[^\d\.]+./, '') === "22.4.306044-gold"
        assert_eq!(strip_first_non_version_run("22.lts.4.306044-gold"), "22.4.306044-gold");
        // run at the end backtracks one character: "9a".replace(...) === "9a" (no match)
        assert_eq!(strip_first_non_version_run("9a"), "9a");
        // "abc".replace(/[^\d\.]+./, '') === ""
        assert_eq!(strip_first_non_version_run("abc"), "");
        // "1ab".replace(/[^\d\.]+./, '') === "1"
        assert_eq!(strip_first_non_version_run("1ab"), "1");
        assert_eq!(strip_first_non_version_run("123"), "123");
    }

    #[test]
    fn str_map_follows_js_key_order_and_star_quirk() {
        static MAP: StrMap = StrMap { entries: &[("tablet", &["p10001l"]), ("*", &["mobile"])], fallback: Some(Some("mobile")) };
        assert_eq!(MAP.apply("P10001L").as_deref(), Some("tablet"));
        assert_eq!(MAP.apply("x123").as_deref(), Some("mobile"));
        // strMapper returns the key, and '*' is a key like any other
        assert_eq!(MAP.apply("mobile1").as_deref(), Some("*"));
        static NO_FALLBACK: StrMap = StrMap { entries: &[("?", &["unknown"])], fallback: None };
        assert_eq!(NO_FALLBACK.apply("Unknown"), None);
        assert_eq!(NO_FALLBACK.apply("NT 9.9").as_deref(), Some("NT 9.9"));
    }

    #[test]
    fn js_whitespace_differs_from_rust() {
        assert!(is_js_whitespace('\u{FEFF}'));
        assert!(!is_js_whitespace('\u{85}'));
        assert_eq!(trim_start_js("\u{FEFF}\u{3000} \tabc "), "abc ");
    }
}
