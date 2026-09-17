//! Request body validation, ported from server/src/api/featureFlags/schemas.ts.
//!
//! The routes answer `400 {"error":"Validation error","details": error.errors}`, so
//! zod's issues are part of the API. This module is a small interpreter for the zod
//! 3.25.76 schema types those schemas use, following each type's `_parse`: the same
//! checks in the same order, the same valid/dirty/aborted statuses (which decide
//! whether refinements run and what unions report), issue members in zod's order
//! (`makeIssue` spreads the issue data, then sets `path` and `message`), English
//! messages, and the parsed output (trimmed strings, defaults, stripped keys).

use std::sync::LazyLock;

use serde_json::{Map, Value};

use super::{
    js::{self, order_map_keys_like_js},
    regex,
};
use crate::js_json::utf16_len;

/// One step of an issue path: an object key or an array index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathItem {
    Key(String),
    Index(usize),
}

fn path_json(path: &[PathItem]) -> Value {
    Value::Array(
        path.iter()
            .map(|item| match item {
                PathItem::Key(key) => Value::String(key.clone()),
                PathItem::Index(index) => Value::from(*index),
            })
            .collect(),
    )
}

fn child(path: &[PathItem], item: PathItem) -> Vec<PathItem> {
    let mut child = path.to_vec();
    child.push(item);
    child
}

/// The issues collected while parsing (`ctx.common.issues`).
#[derive(Clone, Debug, Default)]
pub struct Issues(Vec<Value>);

/// Where `message` lands among an issue's members.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MessageSlot {
    /// The issue data had no `message` member: `path`, then `message`
    Last,
    /// The issue data carried `message` (undefined or custom) before `path` was added
    BeforePath,
}

impl Issues {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn into_json(self) -> Value {
        Value::Array(self.0)
    }

    fn push(&mut self, members: Vec<(&str, Value)>, path: &[PathItem], message: String, slot: MessageSlot) {
        let mut issue = Map::new();
        for (name, value) in members {
            issue.insert(name.to_string(), value);
        }
        match slot {
            MessageSlot::BeforePath => {
                issue.insert("message".into(), Value::String(message));
                issue.insert("path".into(), path_json(path));
            }
            MessageSlot::Last => {
                issue.insert("path".into(), path_json(path));
                issue.insert("message".into(), Value::String(message));
            }
        }
        self.0.push(Value::Object(issue));
    }

    /// `invalid_type` for a value of the wrong type.
    pub fn invalid_type(&mut self, expected: &str, received: &str, path: &[PathItem]) {
        let message = type_message(expected, received);
        self.push(
            vec![("code", "invalid_type".into()), ("expected", expected.into()), ("received", received.into())],
            path,
            message,
            MessageSlot::Last,
        );
    }

    /// `.int()` on a number with a fraction (or a non-finite number).
    pub fn not_integer(&mut self, path: &[PathItem]) {
        self.push(
            vec![("code", "invalid_type".into()), ("expected", "integer".into()), ("received", "float".into())],
            path,
            "Expected integer, received float".to_string(),
            MessageSlot::BeforePath,
        );
    }

    /// `too_small` from a `min` check on a string, number or array.
    pub fn too_small(&mut self, kind: &str, minimum: f64, path: &[PathItem]) {
        let minimum_text = js::number_to_string(minimum);
        let message = match kind {
            "string" => format!("String must contain at least {minimum_text} character(s)"),
            "array" => format!("Array must contain at least {minimum_text} element(s)"),
            _ => format!("Number must be greater than or equal to {minimum_text}"),
        };
        self.push(
            vec![
                ("code", "too_small".into()),
                ("minimum", js::number_json(minimum)),
                ("type", kind.into()),
                ("inclusive", true.into()),
                ("exact", false.into()),
            ],
            path,
            message,
            MessageSlot::BeforePath,
        );
    }

    /// `too_big` from a `max` check on a string, number or array.
    pub fn too_big(&mut self, kind: &str, maximum: f64, path: &[PathItem]) {
        let maximum_text = js::number_to_string(maximum);
        let message = match kind {
            "string" => format!("String must contain at most {maximum_text} character(s)"),
            "array" => format!("Array must contain at most {maximum_text} element(s)"),
            _ => format!("Number must be less than or equal to {maximum_text}"),
        };
        self.push(
            vec![
                ("code", "too_big".into()),
                ("maximum", js::number_json(maximum)),
                ("type", kind.into()),
                ("inclusive", true.into()),
                ("exact", false.into()),
            ],
            path,
            message,
            MessageSlot::BeforePath,
        );
    }

    /// `.regex(pattern, message)` failing.
    fn invalid_regex(&mut self, message: &str, path: &[PathItem]) {
        self.push(
            vec![("validation", "regex".into()), ("code", "invalid_string".into())],
            path,
            message.to_string(),
            MessageSlot::BeforePath,
        );
    }

    /// `z.enum` given a non-string.
    fn invalid_enum_type(&mut self, options: &[&str], received: &str, path: &[PathItem]) {
        let expected = join_values(options);
        let message = type_message(&expected, received);
        self.push(
            vec![("expected", expected.into()), ("received", received.into()), ("code", "invalid_type".into())],
            path,
            message,
            MessageSlot::Last,
        );
    }

    /// `z.enum` given a string that is not an option.
    fn invalid_enum_value(&mut self, options: &[&str], received: &str, path: &[PathItem]) {
        let message = format!("Invalid enum value. Expected {}, received '{received}'", join_values(options));
        self.push(
            vec![
                ("received", received.into()),
                ("code", "invalid_enum_value".into()),
                ("options", Value::Array(options.iter().map(|option| Value::from(*option)).collect())),
            ],
            path,
            message,
            MessageSlot::Last,
        );
    }

    /// A union where no option parsed; `unionErrors` serialise as ZodError objects.
    fn invalid_union(&mut self, option_issues: Vec<Issues>, path: &[PathItem]) {
        let union_errors = option_issues
            .into_iter()
            .map(|issues| {
                let mut error = Map::new();
                error.insert("issues".into(), issues.into_json());
                error.insert("name".into(), "ZodError".into());
                Value::Object(error)
            })
            .collect();
        self.push(
            vec![("code", "invalid_union".into()), ("unionErrors", Value::Array(union_errors))],
            path,
            "Invalid input".to_string(),
            MessageSlot::Last,
        );
    }

    /// `ctx.addIssue({ code: "custom", message, path })` from a refinement.
    pub fn custom(&mut self, message: &str, path: &[PathItem]) {
        self.push(vec![("code", "custom".into())], path, message.to_string(), MessageSlot::BeforePath);
    }

    fn extend(&mut self, other: Issues) {
        self.0.extend(other.0);
    }
}

fn type_message(expected: &str, received: &str) -> String {
    if received == "undefined" { "Required".to_string() } else { format!("Expected {expected}, received {received}") }
}

/// `util.joinValues`.
fn join_values(options: &[&str]) -> String {
    options.iter().map(|option| format!("'{option}'")).collect::<Vec<_>>().join(" | ")
}

/// zod's `getParsedType` for a JSON value (`None` is `undefined`).
pub fn parsed_type(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(number)) if js::number_value(number).is_nan() => "nan",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

enum StringCheck {
    Min(usize),
    Max(usize),
    /// A predicate standing in for the RegExp, and the custom message
    Regex(fn(&str) -> bool, &'static str),
}

enum NumberCheck {
    Int,
    Min(f64),
    Max(f64),
}

type Refinement = fn(&Value, &[PathItem], &mut Issues);

/// The zod schema types these schemas are built from.
enum Schema {
    /// `z.string()`, optionally `.trim()` (always the first check here), then checks
    String {
        trim: bool,
        checks: Vec<StringCheck>,
    },
    Number(Vec<NumberCheck>),
    Boolean,
    Null,
    Enum(&'static [&'static str]),
    Array {
        element: Box<Schema>,
        max: Option<usize>,
    },
    Record(Box<Schema>),
    Object(Vec<(&'static str, Schema)>),
    Union(Vec<Schema>),
    Optional(Box<Schema>),
    Nullable(Box<Schema>),
    Default(Box<Schema>, fn() -> Value),
    Lazy(&'static LazyLock<Schema>),
    /// `.refine` / `.superRefine`
    Effect(Box<Schema>, Refinement),
}

/// A parse result: `OK`, `DIRTY` (issues, value still produced) or `INVALID`.
enum Parsed {
    Valid(Option<Value>),
    Dirty(Option<Value>),
    Aborted,
}

impl Parsed {
    fn with_status(dirty: bool, value: Option<Value>) -> Self {
        if dirty { Parsed::Dirty(value) } else { Parsed::Valid(value) }
    }
}

fn parse(schema: &Schema, data: Option<&Value>, path: &[PathItem], issues: &mut Issues) -> Parsed {
    match schema {
        Schema::String { trim, checks } => {
            let Some(Value::String(text)) = data else {
                issues.invalid_type("string", parsed_type(data), path);
                return Parsed::Aborted;
            };
            let text = if *trim { js::trim(text) } else { text.as_str() };
            let mut dirty = false;
            for check in checks {
                match check {
                    StringCheck::Min(min) if utf16_len(text) < *min => {
                        issues.too_small("string", *min as f64, path);
                        dirty = true;
                    }
                    StringCheck::Max(max) if utf16_len(text) > *max => {
                        issues.too_big("string", *max as f64, path);
                        dirty = true;
                    }
                    StringCheck::Regex(matches, message) if !matches(text) => {
                        issues.invalid_regex(message, path);
                        dirty = true;
                    }
                    _ => {}
                }
            }
            Parsed::with_status(dirty, Some(Value::String(text.to_string())))
        }
        Schema::Number(checks) => {
            let Some(Value::Number(number)) = data else {
                issues.invalid_type("number", parsed_type(data), path);
                return Parsed::Aborted;
            };
            let value = js::number_value(number);
            let mut dirty = false;
            for check in checks {
                match check {
                    NumberCheck::Int if !(value.is_finite() && value.fract() == 0.0) => {
                        issues.not_integer(path);
                        dirty = true;
                    }
                    NumberCheck::Min(min) if value < *min => {
                        issues.too_small("number", *min, path);
                        dirty = true;
                    }
                    NumberCheck::Max(max) if value > *max => {
                        issues.too_big("number", *max, path);
                        dirty = true;
                    }
                    _ => {}
                }
            }
            Parsed::with_status(dirty, data.cloned())
        }
        Schema::Boolean => match data {
            Some(Value::Bool(_)) => Parsed::Valid(data.cloned()),
            _ => {
                issues.invalid_type("boolean", parsed_type(data), path);
                Parsed::Aborted
            }
        },
        Schema::Null => match data {
            Some(Value::Null) => Parsed::Valid(data.cloned()),
            _ => {
                issues.invalid_type("null", parsed_type(data), path);
                Parsed::Aborted
            }
        },
        Schema::Enum(options) => match data {
            Some(Value::String(text)) if options.contains(&text.as_str()) => Parsed::Valid(data.cloned()),
            Some(Value::String(text)) => {
                issues.invalid_enum_value(options, text, path);
                Parsed::Aborted
            }
            _ => {
                issues.invalid_enum_type(options, parsed_type(data), path);
                Parsed::Aborted
            }
        },
        Schema::Array { element, max } => {
            let Some(Value::Array(items)) = data else {
                issues.invalid_type("array", parsed_type(data), path);
                return Parsed::Aborted;
            };
            let mut dirty = false;
            if let Some(max) = max
                && items.len() > *max
            {
                issues.too_big("array", *max as f64, path);
                dirty = true;
            }
            let results: Vec<Parsed> = items
                .iter()
                .enumerate()
                .map(|(index, item)| parse(element, Some(item), &child(path, PathItem::Index(index)), issues))
                .collect();
            let mut values = Vec::with_capacity(results.len());
            for result in results {
                match result {
                    Parsed::Aborted => return Parsed::Aborted,
                    Parsed::Dirty(value) => {
                        dirty = true;
                        values.push(value.unwrap_or(Value::Null));
                    }
                    Parsed::Valid(value) => values.push(value.unwrap_or(Value::Null)),
                }
            }
            Parsed::with_status(dirty, Some(Value::Array(values)))
        }
        Schema::Record(element) => {
            let Some(Value::Object(members)) = data else {
                issues.invalid_type("object", parsed_type(data), path);
                return Parsed::Aborted;
            };
            let mut ordered = members.clone();
            order_map_keys_like_js(&mut ordered);
            let pairs: Vec<(String, Parsed)> = ordered
                .iter()
                .map(|(key, member)| {
                    (key.clone(), parse(element, Some(member), &child(path, PathItem::Key(key.clone())), issues))
                })
                .collect();
            merge_object(pairs, false)
        }
        Schema::Object(shape) => {
            let Some(Value::Object(members)) = data else {
                issues.invalid_type("object", parsed_type(data), path);
                return Parsed::Aborted;
            };
            let pairs: Vec<(String, Parsed)> = shape
                .iter()
                .map(|(key, field)| {
                    let value = members.get(*key);
                    ((*key).to_string(), parse(field, value, &child(path, PathItem::Key((*key).to_string())), issues))
                })
                .collect();
            // `alwaysSet`: a member present in the input is kept even when undefined
            let present: Vec<bool> = shape.iter().map(|(key, _)| members.contains_key(*key)).collect();
            merge_object_fields(pairs, &present)
        }
        Schema::Union(options) => {
            let mut dirty: Option<(Option<Value>, Issues)> = None;
            let mut option_issues = Vec::new();
            for option in options {
                let mut child_issues = Issues::default();
                match parse(option, data, path, &mut child_issues) {
                    Parsed::Valid(value) => return Parsed::Valid(value),
                    Parsed::Dirty(value) if dirty.is_none() => dirty = Some((value, child_issues.clone())),
                    _ => {}
                }
                if !child_issues.is_empty() {
                    option_issues.push(child_issues);
                }
            }
            if let Some((value, child_issues)) = dirty {
                issues.extend(child_issues);
                return Parsed::Dirty(value);
            }
            issues.invalid_union(option_issues, path);
            Parsed::Aborted
        }
        Schema::Optional(inner) => match data {
            None => Parsed::Valid(None),
            _ => parse(inner, data, path, issues),
        },
        Schema::Nullable(inner) => match data {
            Some(Value::Null) => Parsed::Valid(Some(Value::Null)),
            _ => parse(inner, data, path, issues),
        },
        Schema::Default(inner, default) => match data {
            None => parse(inner, Some(&default()), path, issues),
            _ => parse(inner, data, path, issues),
        },
        Schema::Lazy(schema) => parse(schema, data, path, issues),
        Schema::Effect(inner, refinement) => {
            let (dirty, value) = match parse(inner, data, path, issues) {
                Parsed::Aborted => return Parsed::Aborted,
                Parsed::Dirty(value) => (true, value),
                Parsed::Valid(value) => (false, value),
            };
            let before = issues.len();
            refinement(value.as_ref().unwrap_or(&Value::Null), path, issues);
            Parsed::with_status(dirty || issues.len() > before, value)
        }
    }
}

/// `ParseStatus.mergeObjectSync` for records: any aborted member aborts, `__proto__`
/// is never copied, and keys take JavaScript's order.
fn merge_object(pairs: Vec<(String, Parsed)>, _always_set: bool) -> Parsed {
    let mut dirty = false;
    let mut object = Map::new();
    for (key, result) in pairs {
        let value = match result {
            Parsed::Aborted => return Parsed::Aborted,
            Parsed::Dirty(value) => {
                dirty = true;
                value
            }
            Parsed::Valid(value) => value,
        };
        if key != "__proto__"
            && let Some(value) = value
        {
            object.insert(key, value);
        }
    }
    order_map_keys_like_js(&mut object);
    Parsed::with_status(dirty, Some(Value::Object(object)))
}

/// `ParseStatus.mergeObjectSync` for object shapes.
fn merge_object_fields(pairs: Vec<(String, Parsed)>, present: &[bool]) -> Parsed {
    let mut dirty = false;
    let mut object = Map::new();
    for ((key, result), &present) in pairs.into_iter().zip(present) {
        let value = match result {
            Parsed::Aborted => return Parsed::Aborted,
            Parsed::Dirty(value) => {
                dirty = true;
                value
            }
            Parsed::Valid(value) => value,
        };
        // A member present in the input but parsed to undefined would be set to
        // undefined, which JSON leaves out; JSON input never produces one
        let _ = present;
        if let Some(value) = value {
            object.insert(key, value);
        }
    }
    Parsed::with_status(dirty, Some(Value::Object(object)))
}

/// `schema.safeParse(data)`: the output, or every issue.
fn safe_parse(schema: &Schema, data: Option<&Value>) -> Result<Value, Issues> {
    let mut issues = Issues::default();
    match parse(schema, data, &[], &mut issues) {
        Parsed::Valid(value) => Ok(value.unwrap_or(Value::Null)),
        Parsed::Dirty(_) | Parsed::Aborted => Err(issues),
    }
}

fn string(trim: bool, checks: Vec<StringCheck>) -> Schema {
    Schema::String { trim, checks }
}

fn optional(schema: Schema) -> Schema {
    Schema::Optional(Box::new(schema))
}

fn nullable(schema: Schema) -> Schema {
    Schema::Nullable(Box::new(schema))
}

fn defaulted(schema: Schema, default: fn() -> Value) -> Schema {
    Schema::Default(Box::new(schema), default)
}

fn array(element: Schema, max: usize) -> Schema {
    Schema::Array { element: Box::new(element), max: Some(max) }
}

fn percentage() -> Schema {
    Schema::Number(vec![NumberCheck::Int, NumberCheck::Min(0.0), NumberCheck::Max(100.0)])
}

// ---------------------------------------------------------------------------------
// evaluateFeatureFlagsSchema
// ---------------------------------------------------------------------------------

static EVALUATE_SCHEMA: LazyLock<Schema> = LazyLock::new(|| {
    let bounded = |max| optional(string(false, vec![StringCheck::Max(max)]));
    let count = || optional(Schema::Number(vec![NumberCheck::Int, NumberCheck::Min(0.0)]));
    Schema::Object(vec![
        ("anonymousId", string(true, vec![StringCheck::Min(1), StringCheck::Max(128)])),
        ("identifiedUserId", optional(string(true, vec![StringCheck::Max(255)]))),
        ("hostname", bounded(253)),
        ("pathname", bounded(2048)),
        ("querystring", bounded(2048)),
        ("query", optional(Schema::Record(Box::new(string(false, vec![StringCheck::Max(2048)]))))),
        ("referrer", bounded(2048)),
        ("language", bounded(35)),
        ("screenWidth", count()),
        ("screenHeight", count()),
    ])
});

/// `evaluateFeatureFlagsSchema`'s output.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EvaluateFeatureFlagsBody {
    pub anonymous_id: String,
    pub identified_user_id: Option<String>,
    pub hostname: Option<String>,
    pub pathname: Option<String>,
    pub querystring: Option<String>,
    /// The parsed record: a JSON object of strings in JavaScript key order, without a
    /// `__proto__` member (zod's object merge skips that key)
    pub query: Option<Value>,
    pub referrer: Option<String>,
    pub language: Option<String>,
    pub screen_width: Option<f64>,
    pub screen_height: Option<f64>,
}

/// `evaluateFeatureFlagsSchema.parse(body)`. `None` is an absent body (`undefined`).
pub fn parse_evaluate_body(body: Option<&Value>) -> Result<EvaluateFeatureFlagsBody, Issues> {
    let output = safe_parse(&EVALUATE_SCHEMA, body)?;
    let text = |name: &str| output.get(name).and_then(Value::as_str).map(str::to_string);
    let number = |name: &str| output.get(name).and_then(Value::as_f64);
    Ok(EvaluateFeatureFlagsBody {
        anonymous_id: text("anonymousId").unwrap_or_default(),
        identified_user_id: text("identifiedUserId"),
        hostname: text("hostname"),
        pathname: text("pathname"),
        querystring: text("querystring"),
        query: output.get("query").cloned(),
        referrer: text("referrer"),
        language: text("language"),
        screen_width: number("screenWidth"),
        screen_height: number("screenHeight"),
    })
}

/// The zod output object for a parsed evaluate body, members in schema order.
pub fn evaluate_body_json(body: &EvaluateFeatureFlagsBody) -> Value {
    let mut map = Map::new();
    map.insert("anonymousId".into(), Value::String(body.anonymous_id.clone()));
    let mut optional = |name: &str, value: Option<Value>| {
        if let Some(value) = value {
            map.insert(name.to_string(), value);
        }
    };
    optional("identifiedUserId", body.identified_user_id.clone().map(Value::String));
    optional("hostname", body.hostname.clone().map(Value::String));
    optional("pathname", body.pathname.clone().map(Value::String));
    optional("querystring", body.querystring.clone().map(Value::String));
    optional("query", body.query.clone());
    optional("referrer", body.referrer.clone().map(Value::String));
    optional("language", body.language.clone().map(Value::String));
    optional("screenWidth", body.screen_width.map(js::number_json));
    optional("screenHeight", body.screen_height.map(js::number_json));
    Value::Object(map)
}

// ---------------------------------------------------------------------------------
// featureFlagBodySchema and featureFlagUpdateSchema
// ---------------------------------------------------------------------------------

/// `/^[A-Za-z][A-Za-z0-9_.:-]*$/`
fn is_flag_key(text: &str) -> bool {
    let mut characters = text.chars();
    characters.next().is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':' | '-'))
}

const KEY_MESSAGE: &str = "Key must start with a letter and contain only letters, numbers, _, ., :, or -";
const VARIANT_KEY_MESSAGE: &str =
    "Variant key must start with a letter and contain only letters, numbers, _, ., :, or -";
const FLAG_TYPES: &[&str] = &["boolean", "multivariate", "remote_config"];
const RUNTIMES: &[&str] = &["client", "server", "both"];
const RULE_FIELDS: &[&str] = &[
    "hostname",
    "pathname",
    "query",
    "referrer",
    "language",
    "country",
    "region",
    "city",
    "device_type",
    "user_id",
    "trait",
];
const RULE_OPERATORS: &[&str] = &["equals", "not_equals", "contains", "starts_with", "ends_with", "regex"];

/// `payloadValueSchema`: any JSON, with strings up to 4096 units and arrays up to 100.
static PAYLOAD: LazyLock<Schema> = LazyLock::new(|| {
    Schema::Union(vec![
        string(false, vec![StringCheck::Max(4096)]),
        Schema::Number(vec![]),
        Schema::Boolean,
        Schema::Null,
        array(Schema::Lazy(&PAYLOAD), 100),
        Schema::Record(Box::new(Schema::Lazy(&PAYLOAD))),
    ])
});

fn payload() -> Schema {
    Schema::Lazy(&PAYLOAD)
}

fn flag_key() -> Schema {
    string(true, vec![StringCheck::Min(1), StringCheck::Max(100), StringCheck::Regex(is_flag_key, KEY_MESSAGE)])
}

fn rule_value() -> Schema {
    let scalar = || vec![string(false, vec![StringCheck::Max(512)]), Schema::Number(vec![]), Schema::Boolean];
    let mut options = scalar();
    options.push(array(Schema::Union(scalar()), 50));
    Schema::Union(options)
}

/// `featureFlagRuleSchema`'s superRefine: regex rule values must be strings that pass
/// validation (valid ones are precompiled into the shared cache, as in Node).
fn refine_regex_rule(rule: &Value, path: &[PathItem], issues: &mut Issues) {
    if rule.get("operator").and_then(Value::as_str) != Some("regex") {
        return;
    }
    let value = rule.get("value");
    let (values, indexed): (Vec<Option<&Value>>, bool) = match value {
        Some(Value::Array(items)) => (items.iter().map(Some).collect(), true),
        other => (vec![other], false),
    };
    for (index, value) in values.into_iter().enumerate() {
        let value_path = if indexed {
            child(&child(path, PathItem::Key("value".into())), PathItem::Index(index))
        } else {
            child(path, PathItem::Key("value".into()))
        };
        let Some(Value::String(pattern)) = value else {
            issues.custom("Regex rule values must be strings", &value_path);
            continue;
        };
        if let Some(error) = regex::validate_feature_flag_regex_pattern(pattern) {
            issues.custom(&error, &value_path);
            continue;
        }
        regex::precompile_feature_flag_regex_pattern(pattern);
    }
}

/// `featureFlagRuleSchema`'s refine: query and trait rules need a key.
fn refine_rule_key(rule: &Value, path: &[PathItem], issues: &mut Issues) {
    let field = rule.get("field").and_then(Value::as_str);
    if matches!(field, Some("query" | "trait")) && !js::truthy(rule.get("key")) {
        issues.custom("key is required for query and trait rules", &child(path, PathItem::Key("key".into())));
    }
}

fn rule() -> Schema {
    let object = Schema::Object(vec![
        ("field", Schema::Enum(RULE_FIELDS)),
        ("key", optional(string(true, vec![StringCheck::Min(1), StringCheck::Max(128)]))),
        ("operator", Schema::Enum(RULE_OPERATORS)),
        ("value", rule_value()),
    ]);
    Schema::Effect(Box::new(Schema::Effect(Box::new(object), refine_regex_rule)), refine_rule_key)
}

fn variant() -> Schema {
    Schema::Object(vec![
        (
            "key",
            string(
                true,
                vec![StringCheck::Min(1), StringCheck::Max(100), StringCheck::Regex(is_flag_key, VARIANT_KEY_MESSAGE)],
            ),
        ),
        ("name", optional(string(true, vec![StringCheck::Max(120)]))),
        ("rolloutPercentage", percentage()),
        ("payload", optional(payload())),
    ])
}

fn condition_set() -> Schema {
    Schema::Object(vec![
        ("name", optional(string(true, vec![StringCheck::Max(120)]))),
        ("rules", defaulted(array(rule(), 25), || Value::Array(vec![]))),
        ("rolloutPercentage", optional(percentage())),
        ("variants", optional(array(variant(), 20))),
        ("payload", nullable(optional(payload()))),
    ])
}

/// `validateFeatureFlagShape`: flag type, variants and condition sets must agree.
fn validate_feature_flag_shape(data: &Value, path: &[PathItem], issues: &mut Issues) {
    let empty = Vec::new();
    let list = |value: Option<&Value>| match value {
        Some(Value::Array(items)) => items.clone(),
        _ => empty.clone(),
    };
    let variants = list(data.get("variants"));
    let condition_sets = list(data.get("conditionSets"));
    let flag_type = data.get("flagType").and_then(Value::as_str);
    let at = |items: &[&str]| {
        let mut full = path.to_vec();
        full.extend(items.iter().map(|item| PathItem::Key((*item).to_string())));
        full
    };
    let unique_keys = |variants: &[Value]| {
        let mut keys: Vec<String> = variants
            .iter()
            .map(|variant| js::to_string(variant.get("key")).map(|key| key.into_owned()).unwrap_or_default())
            .collect();
        keys.sort();
        keys.dedup();
        keys.len() == variants.len()
    };
    let total_rollout = |variants: &[Value]| {
        variants.iter().fold(0.0, |sum, variant| {
            sum + variant.get("rolloutPercentage").and_then(Value::as_f64).unwrap_or(f64::NAN)
        })
    };

    if flag_type == Some("remote_config") && !variants.is_empty() {
        issues.custom("Remote config flags cannot have variants", &at(&["variants"]));
    }
    if flag_type == Some("boolean") && !variants.is_empty() {
        issues.custom("Boolean flags cannot have variants", &at(&["variants"]));
    }
    if flag_type == Some("multivariate") {
        let has_condition_set_variants = condition_sets
            .iter()
            .any(|set| set.get("variants").and_then(Value::as_array).is_some_and(|variants| !variants.is_empty()));
        if !has_condition_set_variants && variants.len() < 2 {
            issues.custom("Multivariate flags require at least two variants", &at(&["variants"]));
        }
        if !unique_keys(&variants) {
            issues.custom("Variant keys must be unique", &at(&["variants"]));
        }
        if total_rollout(&variants) > 100.0 {
            issues.custom("Variant rollout percentages cannot exceed 100", &at(&["variants"]));
        }
    }

    for (index, set) in condition_sets.iter().enumerate() {
        let set_variants = list(set.get("variants"));
        let mut set_path = path.to_vec();
        set_path.push(PathItem::Key("conditionSets".into()));
        set_path.push(PathItem::Index(index));
        let variants_path = child(&set_path, PathItem::Key("variants".into()));

        if flag_type == Some("boolean") && !set_variants.is_empty() {
            issues.custom("Boolean condition sets cannot have variants", &variants_path);
        }
        if flag_type == Some("remote_config") && !set_variants.is_empty() {
            issues.custom("Remote config condition sets cannot have variants", &variants_path);
        }
        if flag_type == Some("multivariate") && !set_variants.is_empty() {
            if set_variants.len() < 2 {
                issues.custom("Multivariate condition sets require at least two variants", &variants_path);
            }
            if !unique_keys(&set_variants) {
                issues.custom("Variant keys must be unique", &variants_path);
            }
            if total_rollout(&set_variants) > 100.0 {
                issues.custom("Variant rollout percentages cannot exceed 100", &variants_path);
            }
        }
        if set.get("rolloutPercentage").is_some() && flag_type == Some("multivariate") && !set_variants.is_empty() {
            issues.custom(
                "Multivariate condition sets use variant rollout percentages",
                &child(&set_path, PathItem::Key("rolloutPercentage".into())),
            );
        }
    }
}

static FLAG_BODY_SCHEMA: LazyLock<Schema> = LazyLock::new(|| {
    let base = Schema::Object(vec![
        ("key", flag_key()),
        ("description", nullable(optional(string(true, vec![StringCheck::Max(1000)])))),
        ("enabled", defaulted(Schema::Boolean, || Value::Bool(false))),
        ("runtime", defaulted(Schema::Enum(RUNTIMES), || Value::from("client"))),
        ("flagType", defaulted(Schema::Enum(FLAG_TYPES), || Value::from("boolean"))),
        ("payload", nullable(optional(payload()))),
        ("variants", defaulted(array(variant(), 20), || Value::Array(vec![]))),
        ("rolloutPercentage", defaulted(percentage(), || Value::from(100))),
        ("rules", defaulted(array(rule(), 25), || Value::Array(vec![]))),
        ("conditionSets", defaulted(array(condition_set(), 20), || Value::Array(vec![]))),
    ]);
    Schema::Effect(Box::new(base), validate_feature_flag_shape)
});

/// The update schema's refine: some field must be present.
fn refine_not_empty(data: &Value, path: &[PathItem], issues: &mut Issues) {
    if data.as_object().is_none_or(Map::is_empty) {
        issues.custom("At least one field must be provided", path);
    }
}

static FLAG_UPDATE_SCHEMA: LazyLock<Schema> = LazyLock::new(|| {
    let base = Schema::Object(vec![
        ("key", optional(flag_key())),
        ("description", nullable(optional(string(true, vec![StringCheck::Max(1000)])))),
        ("enabled", optional(Schema::Boolean)),
        ("runtime", optional(Schema::Enum(RUNTIMES))),
        ("flagType", optional(Schema::Enum(FLAG_TYPES))),
        ("payload", nullable(optional(payload()))),
        ("variants", optional(array(variant(), 20))),
        ("rolloutPercentage", optional(percentage())),
        ("rules", optional(array(rule(), 25))),
        ("conditionSets", optional(array(condition_set(), 20))),
    ]);
    Schema::Effect(Box::new(Schema::Effect(Box::new(base), refine_not_empty)), validate_feature_flag_shape)
});

/// `featureFlagBodySchema.safeParse(body)`: the parsed flag (defaults applied, strings
/// trimmed, unknown members dropped) or zod's issues.
pub fn parse_feature_flag_body(body: Option<&Value>) -> Result<Value, Issues> {
    safe_parse(&FLAG_BODY_SCHEMA, body)
}

/// `featureFlagUpdateSchema.safeParse(body)`.
pub fn parse_feature_flag_update(body: Option<&Value>) -> Result<Value, Issues> {
    safe_parse(&FLAG_UPDATE_SCHEMA, body)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn issues(body: Value) -> String {
        parse_evaluate_body(Some(&body)).unwrap_err().into_json().to_string()
    }

    #[test]
    fn missing_body_and_fields() {
        assert_eq!(
            parse_evaluate_body(None).unwrap_err().into_json().to_string(),
            r#"[{"code":"invalid_type","expected":"object","received":"undefined","path":[],"message":"Required"}]"#
        );
        assert_eq!(
            issues(json!({})),
            r#"[{"code":"invalid_type","expected":"string","received":"undefined","path":["anonymousId"],"message":"Required"}]"#
        );
    }

    #[test]
    fn check_issues_keep_the_message_before_the_path() {
        assert_eq!(
            issues(json!({ "anonymousId": "   ", "screenWidth": -1.5 })),
            concat!(
                r#"[{"code":"too_small","minimum":1,"type":"string","inclusive":true,"exact":false,"message":"String must contain at least 1 character(s)","path":["anonymousId"]},"#,
                r#"{"code":"invalid_type","expected":"integer","received":"float","message":"Expected integer, received float","path":["screenWidth"]},"#,
                r#"{"code":"too_small","minimum":0,"type":"number","inclusive":true,"exact":false,"message":"Number must be greater than or equal to 0","path":["screenWidth"]}]"#
            )
        );
    }

    #[test]
    fn query_members_are_checked_in_javascript_key_order() {
        assert_eq!(
            issues(json!({ "anonymousId": "a", "query": { "b": 1, "2": null } })),
            concat!(
                r#"[{"code":"invalid_type","expected":"string","received":"null","path":["query","2"],"message":"Expected string, received null"},"#,
                r#"{"code":"invalid_type","expected":"string","received":"number","path":["query","b"],"message":"Expected string, received number"}]"#
            )
        );
    }

    #[test]
    fn trims_ids_and_keeps_other_strings() {
        let body = parse_evaluate_body(Some(&json!({
            "anonymousId": " \u{feff}visitor\n",
            "identifiedUserId": " user ",
            "hostname": " host ",
            "query": { "__proto__": "x", "a": "b" },
            "screenWidth": 1024,
        })))
        .unwrap();
        assert_eq!(body.anonymous_id, "visitor");
        assert_eq!(body.identified_user_id.as_deref(), Some("user"));
        assert_eq!(body.hostname.as_deref(), Some(" host "));
        assert_eq!(body.query, Some(json!({ "a": "b" })));
        assert_eq!(body.screen_width, Some(1024.0));
    }

    // Ported from server/src/api/featureFlags/schemas.test.ts
    fn base_flag(rules: Value) -> Value {
        json!({ "key": "new_checkout", "enabled": true, "runtime": "client", "flagType": "boolean", "rolloutPercentage": 100, "rules": rules })
    }

    #[test]
    fn accepts_safe_regex_targeting_rules() {
        let result = parse_feature_flag_body(Some(&base_flag(
            json!([{ "field": "pathname", "operator": "regex", "value": "^/pricing(/|$)" }]),
        )));
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_unsafe_regex_targeting_rules() {
        let result = parse_feature_flag_body(Some(&base_flag(
            json!([{ "field": "pathname", "operator": "regex", "value": "(a+)+$" }]),
        )));
        assert!(result.is_err());
    }

    #[test]
    fn body_output_applies_defaults_and_trims() {
        let parsed = parse_feature_flag_body(Some(&json!({ "key": " beta ", "extra": 1 }))).unwrap();
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            r#"{"key":"beta","enabled":false,"runtime":"client","flagType":"boolean","variants":[],"rolloutPercentage":100,"rules":[],"conditionSets":[]}"#
        );
        assert_eq!(
            parse_feature_flag_update(Some(&json!({ "extra": 1 }))).unwrap_err().into_json().to_string(),
            r#"[{"code":"custom","message":"At least one field must be provided","path":[]}]"#
        );
    }
}
