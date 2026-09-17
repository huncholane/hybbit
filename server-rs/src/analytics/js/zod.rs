//! zod 3.25 (`zod/v3`) issue objects, built field by field in the order zod's
//! `makeIssue` spreads them, with the default English error map's messages.
//!
//! Only the schema kinds the analytics layer uses are modelled. Parsing follows
//! zod's statuses: a check failure makes a value *dirty* (parsing continues and
//! refinements still run), a type failure *aborts* it.

use super::{
    json,
    number::number_to_string,
    value::{JsObject, JsValue},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathSegment {
    Key(String),
    Index(usize),
}

pub type Path = Vec<PathSegment>;

pub fn child(path: &Path, segment: PathSegment) -> Path {
    let mut next = path.clone();
    next.push(segment);
    next
}

pub fn key(path: &Path, name: &str) -> Path {
    child(path, PathSegment::Key(name.to_string()))
}

pub fn index(path: &Path, position: usize) -> Path {
    child(path, PathSegment::Index(position))
}

fn path_value(path: &Path) -> JsValue {
    JsValue::Array(
        path.iter()
            .map(|segment| match segment {
                PathSegment::Key(name) => JsValue::String(name.clone()),
                PathSegment::Index(position) => JsValue::Number(*position as f64),
            })
            .collect(),
    )
}

/// `ParseStatus` of a value that did not abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Valid,
    Dirty,
}

impl Status {
    pub fn merge(self, other: Status) -> Status {
        if self == Status::Dirty || other == Status::Dirty { Status::Dirty } else { Status::Valid }
    }
}

/// `None` is zod's `INVALID` (aborted).
pub type Parsed<T> = Option<(Status, T)>;

#[derive(Clone, Debug, PartialEq)]
pub struct ZodIssue(JsObject);

impl ZodIssue {
    pub fn message(&self) -> String {
        self.0.get("message").map(JsValue::to_js_string).unwrap_or_default()
    }

    pub fn to_js(&self) -> JsValue {
        JsValue::Object(self.0.clone())
    }

    pub fn code(&self) -> &str {
        self.0.get("code").and_then(JsValue::as_str).unwrap_or_default()
    }

    fn build(fields: Vec<(&str, JsValue)>) -> ZodIssue {
        ZodIssue(fields.into_iter().map(|(name, value)| (name.to_string(), value)).collect())
    }
}

/// `ZodError.message`: `JSON.stringify(issues, replacer, 2)`.
pub fn error_message(issues: &[ZodIssue]) -> String {
    json::stringify_pretty(&issues_value(issues), 2).unwrap_or_default()
}

pub fn issues_value(issues: &[ZodIssue]) -> JsValue {
    JsValue::Array(issues.iter().map(ZodIssue::to_js).collect())
}

/// `getParsedType` for JSON-shaped values.
pub fn parsed_type(value: &JsValue) -> &'static str {
    match value {
        JsValue::Undefined => "undefined",
        JsValue::String(_) => "string",
        JsValue::Number(number) if number.is_nan() => "nan",
        JsValue::Number(_) => "number",
        JsValue::Bool(_) => "boolean",
        JsValue::Null => "null",
        JsValue::Array(_) => "array",
        JsValue::Object(_) => "object",
    }
}

/// `util.joinValues`.
pub fn join_values(values: &[&str], separator: &str) -> String {
    values.iter().map(|value| format!("'{value}'")).collect::<Vec<_>>().join(separator)
}

fn invalid_type_message(expected: &str, received: &str) -> String {
    if received == "undefined" { "Required".to_string() } else { format!("Expected {expected}, received {received}") }
}

/// Type mismatch reported by string, number, boolean, array and object schemas.
pub fn invalid_type(path: &Path, expected: &str, received: &JsValue) -> ZodIssue {
    let received = parsed_type(received);
    ZodIssue::build(vec![
        ("code", "invalid_type".into()),
        ("expected", expected.into()),
        ("received", received.into()),
        ("path", path_value(path)),
        ("message", invalid_type_message(expected, received).into()),
    ])
}

/// Type mismatch reported by `z.enum` (fields in a different order, options joined).
pub fn enum_invalid_type(path: &Path, options: &[&str], received: &JsValue) -> ZodIssue {
    let expected = join_values(options, " | ");
    let received = parsed_type(received);
    let message = invalid_type_message(&expected, received);
    ZodIssue::build(vec![
        ("expected", expected.into()),
        ("received", received.into()),
        ("code", "invalid_type".into()),
        ("path", path_value(path)),
        ("message", message.into()),
    ])
}

pub fn invalid_enum_value(path: &Path, options: &[&str], received: &str) -> ZodIssue {
    ZodIssue::build(vec![
        ("received", received.into()),
        ("code", "invalid_enum_value".into()),
        ("options", JsValue::Array(options.iter().map(|&option| option.into()).collect())),
        ("path", path_value(path)),
        (
            "message",
            format!("Invalid enum value. Expected {}, received '{received}'", join_values(options, " | ")).into(),
        ),
    ])
}

/// A failed `.regex()` check, with the schema's message or the default "Invalid".
pub fn invalid_string_regex(path: &Path, message: Option<&str>) -> ZodIssue {
    ZodIssue::build(vec![
        ("validation", "regex".into()),
        ("code", "invalid_string".into()),
        ("message", message.unwrap_or("Invalid").into()),
        ("path", path_value(path)),
    ])
}

/// A `.refine()` or `ctx.addIssue({ code: custom, message, path })` failure.
pub fn custom(path: &Path, message: &str) -> ZodIssue {
    ZodIssue::build(vec![
        ("code", "custom".into()),
        ("message", message.into()),
        ("path", path_value(path)),
    ])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizedKind {
    String,
    Array,
}

pub fn too_small(path: &Path, kind: SizedKind, minimum: usize, message: Option<&str>) -> ZodIssue {
    let default = match kind {
        SizedKind::String => format!("String must contain at least {} character(s)", number_to_string(minimum as f64)),
        SizedKind::Array => format!("Array must contain at least {} element(s)", number_to_string(minimum as f64)),
    };
    ZodIssue::build(vec![
        ("code", "too_small".into()),
        ("minimum", JsValue::Number(minimum as f64)),
        ("type", if kind == SizedKind::String { "string" } else { "array" }.into()),
        ("inclusive", true.into()),
        ("exact", false.into()),
        ("message", message.map(str::to_string).unwrap_or(default).into()),
        ("path", path_value(path)),
    ])
}

pub fn too_big(path: &Path, kind: SizedKind, maximum: usize, message: Option<&str>) -> ZodIssue {
    let default = match kind {
        SizedKind::String => format!("String must contain at most {} character(s)", number_to_string(maximum as f64)),
        SizedKind::Array => format!("Array must contain at most {} element(s)", number_to_string(maximum as f64)),
    };
    ZodIssue::build(vec![
        ("code", "too_big".into()),
        ("maximum", JsValue::Number(maximum as f64)),
        ("type", if kind == SizedKind::String { "string" } else { "array" }.into()),
        ("inclusive", true.into()),
        ("exact", false.into()),
        ("message", message.map(str::to_string).unwrap_or(default).into()),
        ("path", path_value(path)),
    ])
}

pub fn unrecognized_keys(path: &Path, keys: &[&str]) -> ZodIssue {
    ZodIssue::build(vec![
        ("code", "unrecognized_keys".into()),
        ("keys", JsValue::Array(keys.iter().map(|&name| name.into()).collect())),
        ("path", path_value(path)),
        ("message", format!("Unrecognized key(s) in object: {}", join_values(keys, ", ")).into()),
    ])
}

/// A union whose options all aborted; each option's issues become a serialized
/// `ZodError` (`{"issues":[...],"name":"ZodError"}`).
pub fn invalid_union(path: &Path, union_errors: Vec<Vec<ZodIssue>>) -> ZodIssue {
    let errors = union_errors
        .into_iter()
        .map(|issues| {
            let mut error = JsObject::new();
            error.insert("issues", issues_value(&issues));
            error.insert("name", "ZodError".into());
            JsValue::Object(error)
        })
        .collect();
    ZodIssue::build(vec![
        ("code", "invalid_union".into()),
        ("unionErrors", JsValue::Array(errors)),
        ("path", path_value(path)),
        ("message", "Invalid input".into()),
    ])
}

/// `z.string()` with no checks.
pub fn string(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<String> {
    match value {
        JsValue::String(text) => Some((Status::Valid, text.clone())),
        other => {
            issues.push(invalid_type(path, "string", other));
            None
        }
    }
}

/// `z.enum(options)`.
pub fn enumeration(value: &JsValue, options: &[&str], path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<String> {
    let JsValue::String(text) = value else {
        issues.push(enum_invalid_type(path, options, value));
        return None;
    };
    if !options.contains(&text.as_str()) {
        issues.push(invalid_enum_value(path, options, text));
        return None;
    }
    Some((Status::Valid, text.clone()))
}

/// A two-option `z.union` (sync `ZodUnion._parse`): the first valid option wins,
/// else the first dirty one (its issues kept), else `invalid_union`.
pub fn union2<T>(
    path: &Path,
    issues: &mut Vec<ZodIssue>,
    first: impl FnOnce(&mut Vec<ZodIssue>) -> Parsed<T>,
    second: impl FnOnce(&mut Vec<ZodIssue>) -> Parsed<T>,
) -> Parsed<T> {
    let mut first_issues = Vec::new();
    let first_result = first(&mut first_issues);
    if let Some((Status::Valid, value)) = first_result {
        return Some((Status::Valid, value));
    }
    let mut second_issues = Vec::new();
    let second_result = second(&mut second_issues);
    if let Some((Status::Valid, value)) = second_result {
        return Some((Status::Valid, value));
    }
    if let Some((Status::Dirty, value)) = first_result {
        issues.extend(first_issues);
        return Some((Status::Dirty, value));
    }
    if let Some((Status::Dirty, value)) = second_result {
        issues.extend(second_issues);
        return Some((Status::Dirty, value));
    }
    let union_errors = [first_issues, second_issues].into_iter().filter(|list| !list.is_empty()).collect();
    issues.push(invalid_union(path, union_errors));
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_shapes() {
        let path = vec![PathSegment::Index(0), PathSegment::Key("value".into())];
        let issue = too_small(&path, SizedKind::Array, 1, Some("needs one"));
        assert_eq!(
            json::stringify(&issue.to_js()).unwrap(),
            r#"{"code":"too_small","minimum":1,"type":"array","inclusive":true,"exact":false,"message":"needs one","path":[0,"value"]}"#
        );
        assert_eq!(invalid_type(&vec![], "string", &JsValue::Undefined).message(), "Required");
    }
}
