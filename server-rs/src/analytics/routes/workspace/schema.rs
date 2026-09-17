//! The zod 3.25 building blocks the workspace schemas are made of, on top of
//! `analytics::js::zod` (which owns the issue objects): strings with `trim`,
//! `min` and `max` checks, numbers with `int` and `positive`, booleans, arrays
//! with a `max`, optional and nullable wrappers, and the object merge that strips
//! unknown keys.
//!
//! Statuses follow zod: a failed check makes a value dirty and parsing goes on,
//! a type mismatch aborts it (`None`). `.safeParse` fails whenever any issue was
//! recorded, which is how Node's handlers see it.

use crate::analytics::js::{
    JsObject, JsValue,
    number::number_to_string,
    string::{trim, utf16_len},
    zod::{self, Parsed, Path, SizedKind, Status, ZodIssue},
};

/// One `z.string()` check, in declaration order.
#[derive(Clone, Copy, Debug)]
pub enum StringCheck<'a> {
    /// `.trim()`
    Trim,
    /// `.min(n, message?)`
    Min(usize, Option<&'a str>),
    /// `.max(n, message?)`
    Max(usize, Option<&'a str>),
}

/// `z.string()` with its checks. Lengths are UTF-16 code units, as `String.length`.
pub fn string(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>, checks: &[StringCheck]) -> Parsed<String> {
    let JsValue::String(text) = value else {
        issues.push(zod::invalid_type(path, "string", value));
        return None;
    };
    let mut text = text.clone();
    let mut status = Status::Valid;
    for check in checks {
        match *check {
            StringCheck::Trim => text = trim(&text).to_string(),
            StringCheck::Min(minimum, message) => {
                if utf16_len(&text) < minimum {
                    issues.push(zod::too_small(path, SizedKind::String, minimum, message));
                    status = Status::Dirty;
                }
            }
            StringCheck::Max(maximum, message) => {
                if utf16_len(&text) > maximum {
                    issues.push(zod::too_big(path, SizedKind::String, maximum, message));
                    status = Status::Dirty;
                }
            }
        }
    }
    Some((status, text))
}

/// `z.number()`, optionally `.int()` and then `.positive()`.
pub fn number(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>, int: bool, positive: bool) -> Parsed<f64> {
    let number = match value {
        JsValue::Number(number) if !number.is_nan() => *number,
        other => {
            issues.push(zod::invalid_type(path, "number", other));
            return None;
        }
    };
    let mut status = Status::Valid;
    if int && !(number.is_finite() && number.trunc() == number) {
        issues.push(not_integer(path));
        status = Status::Dirty;
    }
    if positive && number <= 0.0 {
        issues.push(not_positive(path));
        status = Status::Dirty;
    }
    Some((status, number))
}

/// The `.int()` failure. Only its message is ever observable (the two schemas
/// with integer fields answer `errors[0].message`), so it is built as a custom
/// issue carrying zod's `invalid_type` message rather than the full field set.
fn not_integer(path: &Path) -> ZodIssue {
    zod::custom(path, "Expected integer, received float")
}

/// The `.positive()` failure (`min(0, exclusive)`), message only as above.
fn not_positive(path: &Path) -> ZodIssue {
    zod::custom(path, &format!("Number must be greater than {}", number_to_string(0.0)))
}

/// `z.boolean()`.
pub fn boolean(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<bool> {
    match value {
        JsValue::Bool(flag) => Some((Status::Valid, *flag)),
        other => {
            issues.push(zod::invalid_type(path, "boolean", other));
            None
        }
    }
}

/// A value that may be absent (`.optional()`) or also null (`.nullable()`).
#[derive(Clone, Debug, PartialEq)]
pub enum Field<T> {
    Absent,
    Null,
    Value(T),
}

impl<T> Field<T> {
    pub fn is_absent(&self) -> bool {
        matches!(self, Field::Absent)
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Field::Value(value) => Some(value),
            _ => None,
        }
    }
}

/// `.optional()` around `inner`.
pub fn optional<T>(value: &JsValue, inner: impl FnOnce(&JsValue) -> Parsed<T>) -> Parsed<Field<T>> {
    if value.is_undefined() {
        return Some((Status::Valid, Field::Absent));
    }
    inner(value).map(|(status, parsed)| (status, Field::Value(parsed)))
}

/// `.nullable().optional()` around `inner`.
pub fn nullable_optional<T>(value: &JsValue, inner: impl FnOnce(&JsValue) -> Parsed<T>) -> Parsed<Field<T>> {
    match value {
        JsValue::Undefined => Some((Status::Valid, Field::Absent)),
        JsValue::Null => Some((Status::Valid, Field::Null)),
        other => inner(other).map(|(status, parsed)| (status, Field::Value(parsed))),
    }
}

/// `z.array(item)` with an optional `.max(n, message)`: the length issue comes
/// first, then every item is parsed; one aborted item aborts the array.
pub fn array<T>(
    value: &JsValue,
    path: &Path,
    issues: &mut Vec<ZodIssue>,
    max: Option<(usize, Option<&str>)>,
    mut item: impl FnMut(&JsValue, &Path, &mut Vec<ZodIssue>) -> Parsed<T>,
) -> Parsed<Vec<T>> {
    let JsValue::Array(items) = value else {
        issues.push(zod::invalid_type(path, "array", value));
        return None;
    };
    let mut status = Status::Valid;
    if let Some((maximum, message)) = max
        && items.len() > maximum
    {
        issues.push(zod::too_big(path, SizedKind::Array, maximum, message));
        status = Status::Dirty;
    }
    let parsed: Vec<Parsed<T>> =
        items.iter().enumerate().map(|(position, entry)| item(entry, &zod::index(path, position), issues)).collect();
    let mut values = Vec::with_capacity(parsed.len());
    for entry in parsed {
        let (entry_status, entry_value) = entry?;
        status = status.merge(entry_status);
        values.push(entry_value);
    }
    Some((status, values))
}

/// The object being parsed: `z.object(shape)` rejects anything but a plain
/// object before looking at a single key.
pub fn object<'a>(value: &'a JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Option<&'a JsObject> {
    match value {
        JsValue::Object(object) => Some(object),
        other => {
            issues.push(zod::invalid_type(path, "object", other));
            None
        }
    }
}

/// `ParseStatus.mergeObjectSync` over the shape's fields, in shape order: any
/// aborted field aborts the object, any dirty one dirties it.
#[derive(Default)]
pub struct ObjectStatus {
    status: Option<Status>,
    aborted: bool,
}

impl ObjectStatus {
    pub fn new() -> Self {
        Self { status: Some(Status::Valid), aborted: false }
    }

    /// Record a field's result and hand its value on (None when aborted).
    pub fn field<T>(&mut self, parsed: Parsed<T>) -> Option<T> {
        match parsed {
            Some((status, value)) => {
                self.status = self.status.map(|current| current.merge(status));
                Some(value)
            }
            None => {
                self.aborted = true;
                None
            }
        }
    }

    pub fn dirty(&mut self) {
        self.status = Some(Status::Dirty);
    }

    /// The object's own result: None when a field aborted.
    pub fn finish(&self) -> Option<Status> {
        if self.aborted { None } else { self.status }
    }
}

/// `path` extended by a key.
pub fn key(path: &Path, name: &str) -> Path {
    zod::key(path, name)
}

/// The shared tail of `.parse()`/`.safeParse()`: success only when the value is
/// valid and nothing was reported.
pub fn finish<T>(result: Option<(Status, T)>, issues: Vec<ZodIssue>) -> Result<T, Vec<ZodIssue>> {
    match result {
        Some((Status::Valid, value)) if issues.is_empty() => Ok(value),
        _ => Err(issues),
    }
}

/// `error.errors[0]?.message ?? "Invalid request body"`, how the SQL routes
/// report a failed body parse.
pub fn first_message(issues: &[ZodIssue]) -> String {
    issues.first().map(ZodIssue::message).unwrap_or_else(|| "Invalid request body".to_string())
}

/// The 400 body the write handlers send for a `ZodError`.
pub fn validation_error_body(issues: &[ZodIssue]) -> JsValue {
    let mut body = JsObject::new();
    body.insert("error", "Validation error".into());
    body.insert("details", zod::issues_value(issues));
    JsValue::Object(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::{json, zod::PathSegment};

    fn stringify(issues: &[ZodIssue]) -> String {
        json::stringify(&zod::issues_value(issues)).unwrap()
    }

    #[test]
    fn number_checks_report_like_zod() {
        // z.object({ siteId: z.number().int().positive() }).safeParse({ siteId: -1.5 }).error.issues.map(i => i.message)
        let mut issues = Vec::new();
        let path = vec![PathSegment::Key("siteId".into())];
        assert!(matches!(number(&JsValue::Number(-1.5), &path, &mut issues, true, true), Some((Status::Dirty, _))));
        assert_eq!(
            issues.iter().map(ZodIssue::message).collect::<Vec<_>>(),
            ["Expected integer, received float", "Number must be greater than 0"]
        );
        let mut issues = Vec::new();
        assert!(number(&"1".into(), &path, &mut issues, true, true).is_none());
        assert_eq!(
            stringify(&issues),
            r#"[{"code":"invalid_type","expected":"number","received":"string","path":["siteId"],"message":"Expected number, received string"}]"#
        );
    }

    #[test]
    fn string_checks_run_in_order_after_trim() {
        let mut issues = Vec::new();
        let parsed = string(&"   ".into(), &vec![], &mut issues, &[StringCheck::Trim, StringCheck::Min(1, Some("Title is required"))]);
        assert_eq!(parsed, Some((Status::Dirty, String::new())));
        assert_eq!(issues[0].message(), "Title is required");
    }

    #[test]
    fn array_max_comes_before_item_issues() {
        let mut issues = Vec::new();
        let value = JsValue::Array(vec![1.0.into(), "x".into(), 2.0.into()]);
        let parsed = array(&value, &vec![], &mut issues, Some((2, Some("too many"))), |item, path, issues| {
            string(item, path, issues, &[])
        });
        assert!(parsed.is_none());
        assert_eq!(issues.iter().map(ZodIssue::message).collect::<Vec<_>>(), ["too many", "Expected string, received number", "Expected string, received number"]);
    }
}
