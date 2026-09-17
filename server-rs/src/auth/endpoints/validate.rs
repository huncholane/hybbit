//! The zod v4 schemas Better Auth attaches to endpoints, reduced to the checks they
//! perform and the messages they produce. better-call joins issues as
//! `[body.field] message; [body.other] message` inside a 400
//! `{"message", "code":"VALIDATION_ERROR"}`.

use std::sync::LazyLock;

use axum::http::StatusCode;
use regex::Regex;
use serde_json::{Map, Value};

use super::context::ApiError;

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_'+\-.]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$").expect("valid regex")
});

/// zod v4 `z.email()`
pub fn is_email(text: &str) -> bool {
    !text.starts_with('.') && !text.contains("..") && !text.contains('\n') && EMAIL.is_match(text)
}

/// The type names zod reports as `received`
pub fn type_name(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Ty {
    String,
    /// `z.string().min(1)`
    NonEmptyString,
    Boolean,
    Number,
    Email,
    Enum(&'static [&'static str]),
    /// `z.record(z.string(), z.any())`
    Record,
    /// `z.record(z.string(), z.array(z.string()))`
    RecordOfStringArrays,
    ArrayOfStrings,
    /// `z.array(z.number())`
    ArrayOfNumbers,
    /// `z.union([z.string(), z.array(z.string())])`
    StringOrStringArray,
    /// `z.coerce.string()`: anything goes
    CoerceString,
    /// A string inside a union (`z.enum([...]).or(z.string())`): "Invalid input"
    UnionString,
    /// `z.any()`
    Any,
}

#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub name: &'static str,
    pub ty: Ty,
    /// `.optional()`: undefined is fine
    pub optional: bool,
    /// `.nullable()` / `.nullish()`: null is fine
    pub nullable: bool,
}

pub const fn required(name: &'static str, ty: Ty) -> Field {
    Field { name, ty, optional: false, nullable: false }
}

pub const fn optional(name: &'static str, ty: Ty) -> Field {
    Field { name, ty, optional: true, nullable: false }
}

pub const fn nullish(name: &'static str, ty: Ty) -> Field {
    Field { name, ty, optional: true, nullable: true }
}

fn check(ty: Ty, value: Option<&Value>, path: &str, issues: &mut Vec<String>) {
    let invalid = |expected: &str, issues: &mut Vec<String>| {
        issues.push(format!("[{path}] Invalid input: expected {expected}, received {}", type_name(value)));
    };
    match ty {
        Ty::Any | Ty::CoerceString => {}
        Ty::UnionString => {
            if !matches!(value, Some(Value::String(_))) {
                issues.push(format!("[{path}] Invalid input"));
            }
        }
        Ty::String => {
            if !matches!(value, Some(Value::String(_))) {
                invalid("string", issues);
            }
        }
        Ty::NonEmptyString => match value {
            Some(Value::String(text)) if text.is_empty() => {
                issues.push(format!("[{path}] Too small: expected string to have >=1 characters"));
            }
            Some(Value::String(_)) => {}
            _ => invalid("string", issues),
        },
        Ty::Boolean => {
            if !matches!(value, Some(Value::Bool(_))) {
                invalid("boolean", issues);
            }
        }
        Ty::Number => {
            if !matches!(value, Some(Value::Number(_))) {
                invalid("number", issues);
            }
        }
        Ty::Email => match value {
            Some(Value::String(text)) if !is_email(text) => issues.push(format!("[{path}] Invalid email address")),
            Some(Value::String(_)) => {}
            _ => invalid("string", issues),
        },
        Ty::Enum(options) => {
            let ok = value.and_then(Value::as_str).is_some_and(|text| options.contains(&text));
            if !ok {
                let listed: Vec<String> = options.iter().map(|option| format!("\"{option}\"")).collect();
                issues.push(format!("[{path}] Invalid option: expected one of {}", listed.join("|")));
            }
        }
        Ty::Record => {
            if !matches!(value, Some(Value::Object(_))) {
                invalid("record", issues);
            }
        }
        Ty::RecordOfStringArrays => match value {
            Some(Value::Object(map)) => {
                for (key, item) in map {
                    check(Ty::ArrayOfStrings, Some(item), &format!("{path}.{key}"), issues);
                }
            }
            _ => invalid("record", issues),
        },
        Ty::ArrayOfStrings => match value {
            Some(Value::Array(items)) => {
                for (index, item) in items.iter().enumerate() {
                    check(Ty::String, Some(item), &format!("{path}.{index}"), issues);
                }
            }
            _ => invalid("array", issues),
        },
        Ty::ArrayOfNumbers => match value {
            Some(Value::Array(items)) => {
                for (index, item) in items.iter().enumerate() {
                    check(Ty::Number, Some(item), &format!("{path}.{index}"), issues);
                }
            }
            _ => invalid("array", issues),
        },
        Ty::StringOrStringArray => {
            let ok = match value {
                Some(Value::String(_)) => true,
                Some(Value::Array(items)) => items.iter().all(Value::is_string),
                _ => false,
            };
            if !ok {
                issues.push(format!("[{path}] Invalid input"));
            }
        }
    }
}

fn issues_for_fields(object: &Map<String, Value>, fields: &[Field], location: &str, issues: &mut Vec<String>) {
    for field in fields {
        let value = object.get(field.name);
        if value.is_none() && field.optional {
            continue;
        }
        if matches!(value, Some(Value::Null)) && field.nullable {
            continue;
        }
        check(field.ty, value, &format!("{location}.{}", field.name), issues);
    }
}

fn failure(issues: Vec<String>) -> ApiError {
    ApiError::code(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", &issues.join("; "))
}

/// `z.object({...})` over the body (or `.optional()` when `optional_object`)
pub fn object(value: Option<&Value>, fields: &[Field], location: &str, optional_object: bool) -> Result<(), ApiError> {
    match value {
        None if optional_object => Ok(()),
        Some(Value::Object(object)) => {
            let mut issues = Vec::new();
            issues_for_fields(object, fields, location, &mut issues);
            if issues.is_empty() { Ok(()) } else { Err(failure(issues)) }
        }
        other => Err(failure(vec![format!(
            "[{location}] Invalid input: expected object, received {}",
            type_name(other)
        )])),
    }
}

/// `z.record(z.string(), z.any())` at the top level
pub fn record(value: Option<&Value>, location: &str) -> Result<(), ApiError> {
    match value {
        Some(Value::Object(_)) => Ok(()),
        other => Err(failure(vec![format!("[{location}] Invalid input: expected record, received {}", type_name(other))])),
    }
}

/// `z.object({...}).and(z.xor([z.object({ permission }), z.object({ permissions })]))`
/// as used by both has-permission endpoints
pub fn object_and_permission_xor(value: Option<&Value>, fields: &[Field]) -> Result<(), ApiError> {
    object(value, fields, "body", false)?;
    let object = value.and_then(Value::as_object).expect("checked above");
    let matches = |key: &str| {
        let mut issues = Vec::new();
        check(Ty::RecordOfStringArrays, object.get(key), key, &mut issues);
        issues.is_empty()
    };
    if matches("permission") ^ matches("permissions") {
        Ok(())
    } else {
        Err(failure(vec!["[body] Invalid input".to_string()]))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn message(result: Result<(), ApiError>) -> String {
        result.unwrap_err().body.unwrap()["message"].as_str().unwrap().to_string()
    }

    #[test]
    fn messages_match_zod() {
        let fields = [required("email", Ty::String), required("password", Ty::String), optional("rememberMe", Ty::Boolean)];
        assert_eq!(
            message(object(Some(&json!({})), &fields, "body", false)),
            "[body.email] Invalid input: expected string, received undefined; [body.password] Invalid input: expected string, received undefined"
        );
        assert_eq!(message(object(None, &fields, "body", false)), "[body] Invalid input: expected object, received undefined");
        assert_eq!(
            message(object(Some(&json!({"email": "a", "password": 1, "rememberMe": "x"})), &fields, "body", false)),
            "[body.password] Invalid input: expected string, received number; [body.rememberMe] Invalid input: expected boolean, received string"
        );
        assert_eq!(
            message(object(Some(&json!({"type": "q"})), &[required("type", Ty::Enum(&["x", "y"]))], "body", false)),
            "[body.type] Invalid option: expected one of \"x\"|\"y\""
        );
        assert_eq!(message(object(Some(&json!({"e": "nope"})), &[required("e", Ty::Email)], "body", false)), "[body.e] Invalid email address");
        assert_eq!(message(record(Some(&json!("x")), "body")), "[body] Invalid input: expected record, received string");
        assert_eq!(message(object_and_permission_xor(Some(&json!({})), &[])), "[body] Invalid input");
        assert!(object_and_permission_xor(Some(&json!({"permissions": {"user": ["list"]}})), &[]).is_ok());
    }

    #[test]
    fn emails_follow_zod() {
        assert!(is_email("a.b+c@example.co"));
        assert!(!is_email(".a@example.com"));
        assert!(!is_email("a..b@example.com"));
        assert!(!is_email("a@example"));
        assert!(!is_email("a.@example.com"));
    }
}
