//! The zod 3.25 schemas these routes validate bodies with, on top of
//! `analytics::js::zod` (which owns the issue objects):
//!
//! - `updateAccountSettingsSchema` (api/user/updateAccountSettings.ts)
//! - `updateOrganizationExcludedIPsSchema` (api/organizationExclusions/organizationExcludedIPs.ts)
//!   with `ZodError.flatten()`
//! - `createApiKeyBodySchema` / `createOrgApiKeyBodySchema` (api/user/createApiKey.ts,
//!   createOrgApiKey.ts) around `apiKeyPermissionsSchema` (lib/scopes.ts)
//!
//! Statuses follow zod: a failed check makes the value dirty and parsing goes on, a
//! type mismatch aborts it. `.safeParse` fails whenever any issue was recorded.

use crate::{
    analytics::js::{
        JsObject, JsValue,
        number::number_to_string,
        string::{trim, utf16_len},
        zod::{self, Path, PathSegment, SizedKind, ZodIssue},
    },
    auth::scopes::SCOPE_MATRIX,
};

/// One recorded issue with the path it was recorded at, which `flatten()` needs.
pub struct Issue {
    pub path: Path,
    pub issue: ZodIssue,
}

fn at(path: &[&str]) -> Path {
    path.iter().map(|segment| PathSegment::Key((*segment).to_string())).collect()
}

fn indexed(path: &[&str], position: usize) -> Path {
    let mut full = at(path);
    full.push(PathSegment::Index(position));
    full
}

/// `{ ...error }` as `JSON.stringify` writes a `ZodError`: only `issues` and `name`
/// are own enumerable properties.
pub fn zod_error_value(issues: &[Issue]) -> JsValue {
    let mut error = JsObject::new();
    error.insert("issues", zod::issues_value(&issues.iter().map(|entry| entry.issue.clone()).collect::<Vec<_>>()));
    error.insert("name", "ZodError".into());
    JsValue::Object(error)
}

/// `ZodError.flatten()`: `{ formErrors, fieldErrors }`, each issue reduced to its
/// message and filed under the first segment of its path.
pub fn flatten(issues: &[Issue]) -> JsValue {
    let mut form_errors = Vec::new();
    let mut field_errors = JsObject::new();
    for entry in issues {
        let message = JsValue::String(entry.issue.message());
        match entry.path.first() {
            None => form_errors.push(message),
            Some(segment) => {
                let key = match segment {
                    PathSegment::Key(name) => name.clone(),
                    PathSegment::Index(position) => number_to_string(*position as f64),
                };
                let mut existing = match field_errors.get(&key) {
                    Some(JsValue::Array(items)) => items.clone(),
                    _ => Vec::new(),
                };
                existing.push(message);
                field_errors.insert(key, JsValue::Array(existing));
            }
        }
    }
    let mut flat = JsObject::new();
    flat.insert("formErrors", JsValue::Array(form_errors));
    flat.insert("fieldErrors", JsValue::Object(field_errors));
    JsValue::Object(flat)
}

/// `z.object(shape)` rejects anything but a plain object before looking at a key.
fn object_or_issue<'a>(value: &'a JsValue, issues: &mut Vec<Issue>) -> Option<&'a JsObject> {
    match value {
        JsValue::Object(object) => Some(object),
        other => {
            issues.push(Issue { path: Vec::new(), issue: zod::invalid_type(&Vec::new(), "object", other) });
            None
        }
    }
}

// ---------------------------------------------------------------------------
// updateAccountSettingsSchema

/// `z.object({ sendAutoEmailReports: z.boolean().optional() })`
pub fn account_settings(body: &JsValue) -> Result<Option<bool>, Vec<Issue>> {
    let mut issues = Vec::new();
    let Some(object) = object_or_issue(body, &mut issues) else { return Err(issues) };
    let value = object.get_or_undefined("sendAutoEmailReports");
    let parsed = match value {
        JsValue::Undefined => None,
        JsValue::Bool(flag) => Some(*flag),
        other => {
            issues.push(Issue {
                path: at(&["sendAutoEmailReports"]),
                issue: zod::invalid_type(&at(&["sendAutoEmailReports"]), "boolean", other),
            });
            None
        }
    };
    if issues.is_empty() { Ok(parsed) } else { Err(issues) }
}

// ---------------------------------------------------------------------------
// updateOrganizationExcludedIPsSchema

/// `z.object({ excludedIPs: z.array(z.string().trim().min(1)).max(100) })`
pub fn excluded_ips(body: &JsValue) -> Result<Vec<String>, Vec<Issue>> {
    let mut issues = Vec::new();
    let Some(object) = object_or_issue(body, &mut issues) else { return Err(issues) };
    let field = at(&["excludedIPs"]);
    let value = object.get_or_undefined("excludedIPs");
    let JsValue::Array(items) = value else {
        issues.push(Issue { path: field.clone(), issue: zod::invalid_type(&field, "array", value) });
        return Err(issues);
    };
    // ZodArray checks its own length before parsing any element
    if items.len() > 100 {
        issues.push(Issue { path: field.clone(), issue: zod::too_big(&field, SizedKind::Array, 100, None) });
    }
    let mut parsed = Vec::with_capacity(items.len());
    let mut aborted = false;
    for (position, item) in items.iter().enumerate() {
        let item_path = indexed(&["excludedIPs"], position);
        match item {
            JsValue::String(raw) => {
                let trimmed = trim(raw).to_string();
                if utf16_len(&trimmed) < 1 {
                    issues.push(Issue {
                        path: item_path.clone(),
                        issue: zod::too_small(&item_path, SizedKind::String, 1, None),
                    });
                }
                parsed.push(trimmed);
            }
            other => {
                issues.push(Issue { path: item_path.clone(), issue: zod::invalid_type(&item_path, "string", other) });
                aborted = true;
            }
        }
    }
    if issues.is_empty() && !aborted { Ok(parsed) } else { Err(issues) }
}

// ---------------------------------------------------------------------------
// createApiKeyBodySchema / createOrgApiKeyBodySchema

/// The parsed body of both API key routes.
pub struct ApiKeyBody {
    pub name: String,
    pub expires_in: Option<f64>,
    /// `undefined` means a full-access key
    pub permissions: Option<JsObject>,
}

/// `z.object({ name, expiresIn, permissions })`. Only `error.errors[0].message` is
/// ever shown, but the issues are collected in zod's order so that message is right.
pub fn api_key_body(body: &JsValue) -> Result<ApiKeyBody, Vec<Issue>> {
    let mut issues = Vec::new();
    let Some(object) = object_or_issue(body, &mut issues) else { return Err(issues) };

    // name: z.string().trim().min(1, "Name is required")
    let name_path = at(&["name"]);
    let name = match object.get_or_undefined("name") {
        JsValue::String(raw) => {
            let trimmed = trim(raw).to_string();
            if utf16_len(&trimmed) < 1 {
                issues.push(Issue {
                    path: name_path.clone(),
                    issue: zod::too_small(&name_path, SizedKind::String, 1, Some("Name is required")),
                });
            }
            Some(trimmed)
        }
        other => {
            issues.push(Issue { path: name_path.clone(), issue: zod::invalid_type(&name_path, "string", other) });
            None
        }
    };

    // expiresIn: z.number().int().positive().optional()
    let expires_path = at(&["expiresIn"]);
    let expires_in = match object.get_or_undefined("expiresIn") {
        JsValue::Undefined => None,
        JsValue::Number(number) if !number.is_nan() => {
            let number = *number;
            if !(number.is_finite() && number.trunc() == number) {
                issues.push(Issue {
                    path: expires_path.clone(),
                    issue: not_integer(&expires_path, number),
                });
            }
            if number <= 0.0 {
                issues.push(Issue { path: expires_path.clone(), issue: not_positive(&expires_path) });
            }
            Some(number)
        }
        other => {
            issues.push(Issue {
                path: expires_path.clone(),
                issue: zod::invalid_type(&expires_path, "number", other),
            });
            None
        }
    };

    // permissions: apiKeyPermissionsSchema.optional()
    let permissions = match object.get_or_undefined("permissions") {
        JsValue::Undefined => None,
        other => permissions_schema(other, &mut issues),
    };

    match (issues.is_empty(), name) {
        (true, Some(name)) => Ok(ApiKeyBody { name, expires_in, permissions }),
        _ => Err(issues),
    }
}

/// `z.number().int()`: an `invalid_type` issue with `expected: "integer"`.
fn not_integer(path: &Path, _value: f64) -> ZodIssue {
    zod::custom(path, "Expected integer, received float")
}

/// `.positive()` is `min(0, exclusive)`; only its message is ever read.
fn not_positive(path: &Path) -> ZodIssue {
    zod::custom(path, &format!("Number must be greater than {}", number_to_string(0.0)))
}

/// `apiKeyPermissionsSchema`: a record of resource to actions, then a superRefine
/// that names unknown resources and invalid actions.
fn permissions_schema(value: &JsValue, issues: &mut Vec<Issue>) -> Option<JsObject> {
    let path = at(&["permissions"]);
    let JsValue::Object(record) = value else {
        issues.push(Issue { path: path.clone(), issue: zod::invalid_type(&path, "object", value) });
        return None;
    };

    let mut parsed = JsObject::new();
    let mut aborted = false;
    for (key, actions) in record.iter() {
        let entry_path = at(&["permissions", key]);
        let JsValue::Array(items) = actions else {
            issues.push(Issue { path: entry_path.clone(), issue: zod::invalid_type(&entry_path, "array", actions) });
            aborted = true;
            continue;
        };
        if items.is_empty() {
            issues.push(Issue {
                path: entry_path.clone(),
                issue: zod::too_small(&entry_path, SizedKind::Array, 1, Some("Each resource needs at least one action")),
            });
        }
        let mut values = Vec::with_capacity(items.len());
        let mut entry_aborted = false;
        for (position, item) in items.iter().enumerate() {
            match item {
                JsValue::String(text) => values.push(JsValue::String(text.clone())),
                other => {
                    let mut item_path = entry_path.clone();
                    item_path.push(PathSegment::Index(position));
                    issues.push(Issue { path: item_path.clone(), issue: zod::invalid_type(&item_path, "string", other) });
                    entry_aborted = true;
                }
            }
        }
        if entry_aborted {
            aborted = true;
            continue;
        }
        parsed.insert(key.to_string(), JsValue::Array(values));
    }
    if aborted {
        // ZodEffects skips the refinement when the inner schema aborted
        return None;
    }

    // superRefine over the parsed record
    if parsed.is_empty() {
        issues.push(Issue {
            path: path.clone(),
            issue: zod::custom(
                &path,
                "Omit permissions entirely for full access; an empty permissions object would deny everything",
            ),
        });
        return Some(parsed);
    }
    let resources: Vec<&str> = SCOPE_MATRIX.iter().map(|(name, _)| *name).collect();
    for (resource, actions) in parsed.iter() {
        let Some((_, allowed)) = SCOPE_MATRIX.iter().find(|(name, _)| *name == resource) else {
            issues.push(Issue {
                path: path.clone(),
                issue: zod::custom(
                    &path,
                    &format!("Unknown resource \"{resource}\". Valid resources: {}", resources.join(", ")),
                ),
            });
            continue;
        };
        let JsValue::Array(items) = actions else { continue };
        for item in items {
            let Some(action) = item.as_str() else { continue };
            if !allowed.contains(&action) {
                issues.push(Issue {
                    path: path.clone(),
                    issue: zod::custom(
                        &path,
                        &format!(
                            "Invalid action \"{action}\" for resource \"{resource}\". Valid: {}",
                            allowed.join(", ")
                        ),
                    ),
                });
            }
        }
    }
    Some(parsed)
}

/// `parsed.error.errors[0]?.message ?? "Invalid request body"`
pub fn first_message(issues: &[Issue]) -> String {
    issues.first().map(|entry| entry.issue.message()).unwrap_or_else(|| "Invalid request body".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json;

    fn parse(text: &str) -> JsValue {
        json::parse(text).unwrap()
    }

    #[test]
    fn account_settings_reports_like_zod() {
        assert_eq!(account_settings(&parse(r#"{"sendAutoEmailReports":true}"#)).unwrap(), Some(true));
        assert_eq!(account_settings(&parse("{}")).unwrap(), None);
        let issues = account_settings(&parse(r#"{"sendAutoEmailReports":"yes"}"#)).unwrap_err();
        assert_eq!(
            json::stringify(&zod_error_value(&issues)).unwrap(),
            r#"{"issues":[{"code":"invalid_type","expected":"boolean","received":"string","path":["sendAutoEmailReports"],"message":"Expected boolean, received string"}],"name":"ZodError"}"#
        );
        let issues = account_settings(&parse("null")).unwrap_err();
        assert_eq!(issues[0].issue.message(), "Expected object, received null");
    }

    #[test]
    fn excluded_ips_flattens_like_zod() {
        assert_eq!(excluded_ips(&parse(r#"{"excludedIPs":[" 1.2.3.4 "]}"#)).unwrap(), vec!["1.2.3.4".to_string()]);
        let issues = excluded_ips(&parse("{}")).unwrap_err();
        assert_eq!(
            json::stringify(&flatten(&issues)).unwrap(),
            r#"{"formErrors":[],"fieldErrors":{"excludedIPs":["Required"]}}"#
        );
        let issues = excluded_ips(&parse(r#"{"excludedIPs":[""]}"#)).unwrap_err();
        assert_eq!(
            json::stringify(&flatten(&issues)).unwrap(),
            r#"{"formErrors":[],"fieldErrors":{"excludedIPs":["String must contain at least 1 character(s)"]}}"#
        );
        let issues = excluded_ips(&parse("null")).unwrap_err();
        assert_eq!(
            json::stringify(&flatten(&issues)).unwrap(),
            r#"{"formErrors":["Expected object, received null"],"fieldErrors":{}}"#
        );
    }

    #[test]
    fn api_key_body_reports_the_first_message() {
        let body = api_key_body(&parse(r#"{"name":"  key  "}"#)).unwrap();
        assert_eq!(body.name, "key");
        assert!(body.permissions.is_none());
        assert_eq!(first_message(&api_key_body(&parse("{}")).unwrap_err()), "Required");
        assert_eq!(first_message(&api_key_body(&parse(r#"{"name":"  "}"#)).unwrap_err()), "Name is required");
        assert_eq!(
            first_message(&api_key_body(&parse(r#"{"name":"k","expiresIn":1.5}"#)).unwrap_err()),
            "Expected integer, received float"
        );
        assert_eq!(
            first_message(&api_key_body(&parse(r#"{"name":"k","expiresIn":0}"#)).unwrap_err()),
            "Number must be greater than 0"
        );
        assert_eq!(
            first_message(&api_key_body(&parse(r#"{"name":"k","permissions":{}}"#)).unwrap_err()),
            "Omit permissions entirely for full access; an empty permissions object would deny everything"
        );
        assert_eq!(
            first_message(&api_key_body(&parse(r#"{"name":"k","permissions":{"nope":["read"]}}"#)).unwrap_err()),
            "Unknown resource \"nope\". Valid resources: analytics, sessions, events, users, goals, funnels, dashboards, annotations, segments, flags, experiments, sites, gsc, org, replay, sql, ingest"
        );
        assert_eq!(
            first_message(&api_key_body(&parse(r#"{"name":"k","permissions":{"sql":["write"]}}"#)).unwrap_err()),
            "Invalid action \"write\" for resource \"sql\". Valid: read"
        );
        assert_eq!(
            first_message(&api_key_body(&parse(r#"{"name":"k","permissions":{"sql":[]}}"#)).unwrap_err()),
            "Each resource needs at least one action"
        );
    }
}
