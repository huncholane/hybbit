//! The zod 3.25 schemas the admin panel and the experiment routes validate with:
//! `organizationOptionsQuerySchema`, `subscriptionOverrideSchema` and
//! `updateMemberSchema` from server/src/api/admin/adminOrganizationManagement.ts,
//! and `experimentBodySchema` / `experimentUpdateSchema` from
//! server/src/api/experiments/schemas.ts.
//!
//! Issues are built member by member in the order zod's `makeIssue` spreads them,
//! because two routes hand `error.errors` straight to the client. `makeIssue`
//! returns `{ ...issueData, path, message }`: a `message` member already present in
//! the issue data (even as `undefined`) keeps its slot, so `path` lands last for
//! those issues and second to last for the rest. The same rule is implemented for
//! feature flags in `crate::feature_flags::schemas`; this copy keeps the admin
//! group free to add schema kinds (a discriminated union, `flatten`) without
//! touching the shared one.
//!
//! Parsing follows zod's statuses: a failed check makes a value *dirty* and
//! parsing continues, a type mismatch *aborts* it. `.safeParse` and `.parse`
//! both fail as soon as any issue was recorded.

use serde_json::{Map, Value, json};

use crate::analytics::js::{
    JsObject, JsValue,
    number::number_to_string,
    string::{trim, utf16_len},
};

// ---------------------------------------------------------------------------------
// Issues
// ---------------------------------------------------------------------------------

/// One step of an issue path: an object key or an array index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathItem {
    Key(&'static str),
    Index(usize),
}

fn path_json(path: &[PathItem]) -> Value {
    Value::Array(
        path.iter()
            .map(|item| match item {
                PathItem::Key(key) => Value::String((*key).to_string()),
                PathItem::Index(index) => Value::from(*index),
            })
            .collect(),
    )
}

fn child(path: &[PathItem], item: PathItem) -> Vec<PathItem> {
    let mut next = path.to_vec();
    next.push(item);
    next
}

/// Where `message` lands among an issue's members.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// The issue data had no `message` member: `path`, then `message`
    Last,
    /// The issue data carried `message` (undefined or custom) before `path` arrived
    BeforePath,
}

/// `ctx.common.issues`, the array `ZodError.errors` exposes.
#[derive(Clone, Debug, Default)]
pub struct Issues(Vec<Value>);

impl Issues {
    /// `error.errors`
    pub fn into_json(self) -> Value {
        Value::Array(self.0)
    }

    /// `error.flatten()`: every issue's message, grouped by the first path step.
    pub fn flatten(&self) -> Value {
        let mut form_errors = Vec::new();
        let mut field_errors: Map<String, Value> = Map::new();
        for issue in &self.0 {
            let message = issue.get("message").cloned().unwrap_or(Value::Null);
            let first = issue.get("path").and_then(Value::as_array).and_then(|path| path.first());
            match first {
                None => form_errors.push(message),
                Some(step) => {
                    let key = match step {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    match field_errors.get_mut(&key) {
                        Some(Value::Array(list)) => list.push(message),
                        _ => {
                            field_errors.insert(key, Value::Array(vec![message]));
                        }
                    }
                }
            }
        }
        json!({ "formErrors": form_errors, "fieldErrors": Value::Object(field_errors) })
    }

    fn push(&mut self, members: Vec<(&str, Value)>, path: &[PathItem], message: String, slot: Slot) {
        let mut issue = Map::new();
        for (name, value) in members {
            issue.insert(name.to_string(), value);
        }
        match slot {
            Slot::BeforePath => {
                issue.insert("message".into(), Value::String(message));
                issue.insert("path".into(), path_json(path));
            }
            Slot::Last => {
                issue.insert("path".into(), path_json(path));
                issue.insert("message".into(), Value::String(message));
            }
        }
        self.0.push(Value::Object(issue));
    }

    /// A value of the wrong type, reported by string, number, boolean, array and
    /// object schemas.
    fn invalid_type(&mut self, expected: &str, received: &str, path: &[PathItem]) {
        let message = type_message(expected, received);
        self.push(
            vec![("code", "invalid_type".into()), ("expected", expected.into()), ("received", received.into())],
            path,
            message,
            Slot::Last,
        );
    }

    /// `.int()` on a number with a fraction (or a non-finite one).
    fn not_integer(&mut self, path: &[PathItem]) {
        self.push(
            vec![("code", "invalid_type".into()), ("expected", "integer".into()), ("received", "float".into())],
            path,
            "Expected integer, received float".to_string(),
            Slot::BeforePath,
        );
    }

    /// `too_small` from a `min` check. `inclusive` is false only for `.positive()`.
    fn too_small(&mut self, kind: &str, minimum: f64, inclusive: bool, path: &[PathItem]) {
        let minimum_text = number_to_string(minimum);
        let message = match kind {
            "string" => format!("String must contain at least {minimum_text} character(s)"),
            "array" => format!("Array must contain at least {minimum_text} element(s)"),
            _ if inclusive => format!("Number must be greater than or equal to {minimum_text}"),
            _ => format!("Number must be greater than {minimum_text}"),
        };
        self.push(
            vec![
                ("code", "too_small".into()),
                ("minimum", number_json(minimum)),
                ("type", kind.into()),
                ("inclusive", inclusive.into()),
                ("exact", false.into()),
            ],
            path,
            message,
            Slot::BeforePath,
        );
    }

    /// `too_big` from a `max` check (always inclusive in these schemas).
    fn too_big(&mut self, kind: &str, maximum: f64, path: &[PathItem]) {
        let maximum_text = number_to_string(maximum);
        let message = match kind {
            "string" => format!("String must contain at most {maximum_text} character(s)"),
            "array" => format!("Array must contain at most {maximum_text} element(s)"),
            _ => format!("Number must be less than or equal to {maximum_text}"),
        };
        self.push(
            vec![
                ("code", "too_big".into()),
                ("maximum", number_json(maximum)),
                ("type", kind.into()),
                ("inclusive", true.into()),
                ("exact", false.into()),
            ],
            path,
            message,
            Slot::BeforePath,
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
            Slot::Last,
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
            Slot::Last,
        );
    }

    /// `z.discriminatedUnion` given a discriminator no option declares.
    fn invalid_union_discriminator(&mut self, options: &[&str], path: &[PathItem]) {
        let message = format!("Invalid discriminator value. Expected {}", join_values(options));
        self.push(
            vec![
                ("code", "invalid_union_discriminator".into()),
                ("options", Value::Array(options.iter().map(|option| Value::from(*option)).collect())),
            ],
            path,
            message,
            Slot::Last,
        );
    }

    /// `.refine(check, { message })`: the issue data carries `message` but no path.
    fn refine(&mut self, message: &str, path: &[PathItem]) {
        self.push(vec![("code", "custom".into())], path, message.to_string(), Slot::BeforePath);
    }

    /// `ctx.addIssue({ code: "custom", path, message })` from a `superRefine`:
    /// the issue data names `path` before `message`, so both land after `code`.
    fn super_refine(&mut self, message: &str, path: &[PathItem]) {
        self.push(vec![("code", "custom".into())], path, message.to_string(), Slot::Last);
    }
}

fn type_message(expected: &str, received: &str) -> String {
    if received == "undefined" { "Required".to_string() } else { format!("Expected {expected}, received {received}") }
}

/// `util.joinValues`.
fn join_values(options: &[&str]) -> String {
    options.iter().map(|option| format!("'{option}'")).collect::<Vec<_>>().join(" | ")
}

/// A number as `JSON.stringify` spells it (the issue members are printed).
fn number_json(number: f64) -> Value {
    serde_json::from_str(&number_to_string(number)).unwrap_or(Value::Null)
}

/// zod's `getParsedType`.
fn parsed_type(value: &JsValue) -> &'static str {
    match value {
        JsValue::Undefined => "undefined",
        JsValue::Null => "null",
        JsValue::Bool(_) => "boolean",
        JsValue::Number(number) if number.is_nan() => "nan",
        JsValue::Number(_) => "number",
        JsValue::String(_) => "string",
        JsValue::Array(_) => "array",
        JsValue::Object(_) => "object",
    }
}

/// zod's `ParseStatus`: `None` is `INVALID` (aborted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Valid,
    Dirty,
}

type Parsed<T> = Option<(Status, T)>;

fn merge<T>(status: &mut Status, parsed: Parsed<T>) -> Option<T> {
    match parsed {
        None => None,
        Some((Status::Dirty, value)) => {
            *status = Status::Dirty;
            Some(value)
        }
        Some((Status::Valid, value)) => Some(value),
    }
}

// ---------------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------------

/// One `z.string()` check, in declaration order.
#[derive(Clone, Copy, Debug)]
enum StringCheck {
    /// `.trim()`
    Trim,
    /// `.min(n)`
    Min(usize),
    /// `.max(n)`
    Max(usize),
}

/// `z.string()` with its checks. Lengths are UTF-16 code units, as `String.length`.
fn string(value: &JsValue, path: &[PathItem], issues: &mut Issues, checks: &[StringCheck]) -> Parsed<String> {
    let JsValue::String(text) = value else {
        issues.invalid_type("string", parsed_type(value), path);
        return None;
    };
    let mut text = text.clone();
    let mut status = Status::Valid;
    for check in checks {
        match *check {
            StringCheck::Trim => text = trim(&text).to_string(),
            StringCheck::Min(minimum) => {
                if utf16_len(&text) < minimum {
                    issues.too_small("string", minimum as f64, true, path);
                    status = Status::Dirty;
                }
            }
            StringCheck::Max(maximum) => {
                if utf16_len(&text) > maximum {
                    issues.too_big("string", maximum as f64, path);
                    status = Status::Dirty;
                }
            }
        }
    }
    Some((status, text))
}

/// `z.number()` with `.int()`, `.positive()`, `.min(n)` and `.max(n)` in that order.
#[derive(Clone, Copy, Debug, Default)]
struct NumberChecks {
    int: bool,
    positive: bool,
    min: Option<f64>,
    max: Option<f64>,
}

fn number(value: &JsValue, path: &[PathItem], issues: &mut Issues, checks: NumberChecks) -> Parsed<f64> {
    let number = match value {
        JsValue::Number(number) if !number.is_nan() => *number,
        other => {
            issues.invalid_type("number", parsed_type(other), path);
            return None;
        }
    };
    let mut status = Status::Valid;
    if checks.int && !(number.is_finite() && number.trunc() == number) {
        issues.not_integer(path);
        status = Status::Dirty;
    }
    if checks.positive && number <= 0.0 {
        issues.too_small("number", 0.0, false, path);
        status = Status::Dirty;
    }
    if let Some(minimum) = checks.min
        && number < minimum
    {
        issues.too_small("number", minimum, true, path);
        status = Status::Dirty;
    }
    if let Some(maximum) = checks.max
        && number > maximum
    {
        issues.too_big("number", maximum, path);
        status = Status::Dirty;
    }
    Some((status, number))
}

/// `z.boolean()`.
fn boolean(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<bool> {
    match value {
        JsValue::Bool(flag) => Some((Status::Valid, *flag)),
        other => {
            issues.invalid_type("boolean", parsed_type(other), path);
            None
        }
    }
}

/// `z.enum(options)`.
fn enumeration(value: &JsValue, options: &[&str], path: &[PathItem], issues: &mut Issues) -> Parsed<String> {
    let JsValue::String(text) = value else {
        issues.invalid_enum_type(options, parsed_type(value), path);
        return None;
    };
    if !options.contains(&text.as_str()) {
        issues.invalid_enum_value(options, text, path);
        return None;
    }
    Some((Status::Valid, text.clone()))
}

/// `z.coerce.number()`: `Number(value)` before the type check.
fn coerce_number(value: &JsValue) -> JsValue {
    JsValue::Number(value.to_number())
}

/// `.optional()`: `undefined` passes straight through.
fn optional<T>(value: &JsValue, parse: impl FnOnce(&JsValue) -> Parsed<T>) -> Parsed<Option<T>> {
    if value.is_undefined() {
        return Some((Status::Valid, None));
    }
    parse(value).map(|(status, parsed)| (status, Some(parsed)))
}

/// `.nullable()`: `null` passes straight through.
fn nullable<T>(value: &JsValue, parse: impl FnOnce(&JsValue) -> Parsed<Option<T>>) -> Parsed<Option<T>> {
    if matches!(value, JsValue::Null) {
        return Some((Status::Valid, None));
    }
    parse(value)
}

/// `object[key]` for a value zod already decided is an object.
fn member<'a>(value: &'a JsValue, key: &str) -> &'a JsValue {
    match value {
        JsValue::Object(object) => object.get_or_undefined(key),
        _ => &JsValue::Undefined,
    }
}

/// `key in data`, which decides whether an `undefined` member is kept.
fn has_member(value: &JsValue, key: &str) -> bool {
    matches!(value, JsValue::Object(object) if object.contains_key(key))
}

// ---------------------------------------------------------------------------------
// organizationOptionsQuerySchema
// ---------------------------------------------------------------------------------

/// The parsed `/api/admin/organization-options` query.
#[derive(Clone, Debug, PartialEq)]
pub struct OrganizationOptionsQuery {
    pub search: String,
    pub limit: f64,
}

/// `organizationOptionsQuerySchema.safeParse(request.query)`.
pub fn parse_organization_options_query(query: &JsObject) -> Result<OrganizationOptionsQuery, Issues> {
    let data = JsValue::Object(query.clone());
    let mut issues = Issues::default();
    let mut status = Status::Valid;

    // search: z.string().trim().max(200).optional().default("")
    let raw_search = member(&data, "search");
    let defaulted_search =
        if raw_search.is_undefined() { JsValue::String(String::new()) } else { raw_search.clone() };
    let search = merge(
        &mut status,
        optional(&defaulted_search, |value| {
            string(value, &[PathItem::Key("search")], &mut issues, &[StringCheck::Trim, StringCheck::Max(200)])
        }),
    );

    // limit: z.coerce.number().int().min(1).max(50).optional().default(25)
    let raw_limit = member(&data, "limit");
    let defaulted_limit = if raw_limit.is_undefined() { JsValue::Number(25.0) } else { raw_limit.clone() };
    let limit = merge(
        &mut status,
        optional(&defaulted_limit, |value| {
            number(
                &coerce_number(value),
                &[PathItem::Key("limit")],
                &mut issues,
                NumberChecks { int: true, positive: false, min: Some(1.0), max: Some(50.0) },
            )
        }),
    );

    match (search, limit, status) {
        (Some(Some(search)), Some(Some(limit)), Status::Valid) => Ok(OrganizationOptionsQuery { search, limit }),
        _ => Err(issues),
    }
}

// ---------------------------------------------------------------------------------
// subscriptionOverrideSchema
// ---------------------------------------------------------------------------------

/// The three arms of `subscriptionOverrideSchema`.
#[derive(Clone, Debug, PartialEq)]
pub enum SubscriptionOverride {
    None,
    Preset { plan_override: String },
    Custom { events: f64, members: Option<f64>, websites: Option<f64> },
}

const OVERRIDE_MODES: &[&str] = &["none", "preset", "custom"];

/// `z.number().int().positive().nullable()`
fn nullable_positive_integer(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<Option<f64>> {
    nullable(value, |value| {
        number(value, path, issues, NumberChecks { int: true, positive: true, ..NumberChecks::default() })
            .map(|(status, number)| (status, Some(number)))
    })
}

/// `subscriptionOverrideSchema.safeParse(request.body)`.
pub fn parse_subscription_override(body: &JsValue) -> Result<SubscriptionOverride, Issues> {
    let mut issues = Issues::default();
    if !matches!(body, JsValue::Object(_)) {
        issues.invalid_type("object", parsed_type(body), &[]);
        return Err(issues);
    }
    let mode = member(body, "mode");
    let Some(mode) = mode.as_str().filter(|mode| OVERRIDE_MODES.contains(mode)) else {
        issues.invalid_union_discriminator(OVERRIDE_MODES, &[PathItem::Key("mode")]);
        return Err(issues);
    };

    let mut status = Status::Valid;
    let parsed = match mode {
        "none" => Some(SubscriptionOverride::None),
        "preset" => {
            // planOverride: z.string().min(1)
            let value = member(body, "planOverride");
            merge(
                &mut status,
                string(value, &[PathItem::Key("planOverride")], &mut issues, &[StringCheck::Min(1)]),
            )
            .map(|plan_override| SubscriptionOverride::Preset { plan_override })
        }
        _ => {
            let plan_path = [PathItem::Key("customPlan")];
            let plan = member(body, "customPlan");
            if !matches!(plan, JsValue::Object(_)) {
                issues.invalid_type("object", parsed_type(plan), &plan_path);
                None
            } else {
                let events = merge(
                    &mut status,
                    number(
                        member(plan, "events"),
                        &child(&plan_path, PathItem::Key("events")),
                        &mut issues,
                        NumberChecks { int: true, positive: true, ..NumberChecks::default() },
                    ),
                );
                let members = merge(
                    &mut status,
                    nullable_positive_integer(
                        member(plan, "members"),
                        &child(&plan_path, PathItem::Key("members")),
                        &mut issues,
                    ),
                );
                let websites = merge(
                    &mut status,
                    nullable_positive_integer(
                        member(plan, "websites"),
                        &child(&plan_path, PathItem::Key("websites")),
                        &mut issues,
                    ),
                );
                match (events, members, websites) {
                    (Some(events), Some(members), Some(websites)) => {
                        Some(SubscriptionOverride::Custom { events, members, websites })
                    }
                    _ => None,
                }
            }
        }
    };

    match (parsed, status) {
        (Some(value), Status::Valid) => Ok(value),
        _ => Err(issues),
    }
}

// ---------------------------------------------------------------------------------
// adminMoveSiteSchema
// ---------------------------------------------------------------------------------

/// `adminMoveSiteSchema.safeParse(request.body)`:
/// `z.object({ organizationId: z.string().min(1) })`.
pub fn parse_move_site_body(body: &JsValue) -> Result<String, Issues> {
    let mut issues = Issues::default();
    if !matches!(body, JsValue::Object(_)) {
        issues.invalid_type("object", parsed_type(body), &[]);
        return Err(issues);
    }
    let mut status = Status::Valid;
    let organization_id = merge(
        &mut status,
        string(member(body, "organizationId"), &[PathItem::Key("organizationId")], &mut issues, &[StringCheck::Min(1)]),
    );
    match (organization_id, status) {
        (Some(organization_id), Status::Valid) => Ok(organization_id),
        _ => Err(issues),
    }
}

// ---------------------------------------------------------------------------------
// updateMemberSchema
// ---------------------------------------------------------------------------------

/// The parsed PATCH body for an organization member.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateMember {
    pub role: String,
    pub has_restricted_site_access: bool,
    pub site_ids: Vec<f64>,
}

const MEMBER_ROLES: &[&str] = &["owner", "admin", "member"];

/// `updateMemberSchema.safeParse(request.body)`, including its `superRefine`.
pub fn parse_update_member(body: &JsValue) -> Result<UpdateMember, Issues> {
    let mut issues = Issues::default();
    if !matches!(body, JsValue::Object(_)) {
        issues.invalid_type("object", parsed_type(body), &[]);
        return Err(issues);
    }
    let mut status = Status::Valid;

    let role = merge(&mut status, enumeration(member(body, "role"), MEMBER_ROLES, &[PathItem::Key("role")], &mut issues));
    let restricted = merge(
        &mut status,
        boolean(member(body, "hasRestrictedSiteAccess"), &[PathItem::Key("hasRestrictedSiteAccess")], &mut issues),
    );

    // siteIds: z.array(z.number().int().positive()).max(500)
    let site_ids_path = [PathItem::Key("siteIds")];
    let raw_site_ids = member(body, "siteIds");
    let site_ids = match raw_site_ids {
        JsValue::Array(items) => {
            // The length check runs before the elements, as in ZodArray._parse
            if items.len() > 500 {
                issues.too_big("array", 500.0, &site_ids_path);
                status = Status::Dirty;
            }
            let mut parsed = Vec::with_capacity(items.len());
            let mut aborted = false;
            for (index, item) in items.iter().enumerate() {
                let element = number(
                    item,
                    &child(&site_ids_path, PathItem::Index(index)),
                    &mut issues,
                    NumberChecks { int: true, positive: true, ..NumberChecks::default() },
                );
                match merge(&mut status, element) {
                    Some(value) => parsed.push(value),
                    None => aborted = true,
                }
            }
            if aborted { None } else { Some(parsed) }
        }
        other => {
            issues.invalid_type("array", parsed_type(other), &site_ids_path);
            None
        }
    };

    let (Some(role), Some(restricted), Some(site_ids)) = (role, restricted, site_ids) else {
        return Err(issues);
    };

    // superRefine runs on a dirty value too, only an aborted one skips it
    if role == "member" && restricted && site_ids.is_empty() {
        issues.super_refine("Select at least one site", &site_ids_path);
        status = Status::Dirty;
    }

    match status {
        Status::Valid => Ok(UpdateMember { role, has_restricted_site_access: restricted, site_ids }),
        Status::Dirty => Err(issues),
    }
}

// ---------------------------------------------------------------------------------
// experimentBodySchema and experimentUpdateSchema
// ---------------------------------------------------------------------------------

pub const EXPERIMENT_STATUSES: &[&str] = &["draft", "running", "paused", "completed"];

/// One field of the experiment schemas, so the body and its `.partial()` form
/// share a single description.
struct ExperimentField {
    name: &'static str,
    parse: fn(&JsValue, &[PathItem], &mut Issues) -> Parsed<JsValue>,
    /// `.default(...)` applies before the field parses (only `status` has one)
    default: Option<fn() -> JsValue>,
}

/// `z.string().trim().max(n).optional().nullable()`: `null` and `undefined` both
/// pass through, and each keeps its own spelling so the output object can tell
/// "cleared" from "not sent".
fn optional_trimmed_string(
    value: &JsValue,
    path: &[PathItem],
    issues: &mut Issues,
    max: usize,
) -> Parsed<JsValue> {
    if matches!(value, JsValue::Null) {
        return Some((Status::Valid, JsValue::Null));
    }
    if value.is_undefined() {
        return Some((Status::Valid, JsValue::Undefined));
    }
    string(value, path, issues, &[StringCheck::Trim, StringCheck::Max(max)])
        .map(|(status, text)| (status, JsValue::String(text)))
}

fn experiment_name(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<JsValue> {
    string(value, path, issues, &[StringCheck::Trim, StringCheck::Min(1), StringCheck::Max(160)])
        .map(|(status, text)| (status, JsValue::String(text)))
}

fn experiment_description(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<JsValue> {
    optional_trimmed_string(value, path, issues, 1000)
}

fn experiment_hypothesis(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<JsValue> {
    optional_trimmed_string(value, path, issues, 1000)
}

fn experiment_winning_variant(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<JsValue> {
    optional_trimmed_string(value, path, issues, 100)
}

fn positive_integer(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<JsValue> {
    number(value, path, issues, NumberChecks { int: true, positive: true, ..NumberChecks::default() })
        .map(|(status, number)| (status, JsValue::Number(number)))
}

fn optional_nullable_positive_integer(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<JsValue> {
    if matches!(value, JsValue::Null) {
        return Some((Status::Valid, JsValue::Null));
    }
    if value.is_undefined() {
        return Some((Status::Valid, JsValue::Undefined));
    }
    positive_integer(value, path, issues)
}

fn experiment_status(value: &JsValue, path: &[PathItem], issues: &mut Issues) -> Parsed<JsValue> {
    enumeration(value, EXPERIMENT_STATUSES, path, issues).map(|(status, text)| (status, JsValue::String(text)))
}

fn experiment_fields() -> Vec<ExperimentField> {
    vec![
        ExperimentField { name: "name", parse: experiment_name, default: None },
        ExperimentField { name: "description", parse: experiment_description, default: None },
        ExperimentField { name: "hypothesis", parse: experiment_hypothesis, default: None },
        ExperimentField { name: "featureFlagId", parse: positive_integer, default: None },
        ExperimentField { name: "primaryGoalId", parse: optional_nullable_positive_integer, default: None },
        ExperimentField { name: "status", parse: experiment_status, default: Some(|| JsValue::String("draft".into())) },
        ExperimentField { name: "winningVariant", parse: experiment_winning_variant, default: None },
    ]
}

/// The shared object parse: every field in shape order, unknown members stripped,
/// and a member kept in the output when its value is defined or the key was sent.
fn parse_experiment_object(body: &JsValue, partial: bool) -> Result<JsObject, Issues> {
    let mut issues = Issues::default();
    if !matches!(body, JsValue::Object(_)) {
        issues.invalid_type("object", parsed_type(body), &[]);
        return Err(issues);
    }
    let mut status = Status::Valid;
    let mut aborted = false;
    let mut output = JsObject::new();

    for field in experiment_fields() {
        let path = [PathItem::Key(field.name)];
        let raw = member(body, field.name);
        // `.partial()` wraps the field (its default included) in `.optional()`
        let value = match (&field.default, partial, raw.is_undefined()) {
            (Some(default), false, true) => default(),
            _ => raw.clone(),
        };
        let parsed = if partial && value.is_undefined() {
            Some((Status::Valid, JsValue::Undefined))
        } else {
            (field.parse)(&value, &path, &mut issues)
        };
        match parsed {
            None => aborted = true,
            Some((field_status, parsed)) => {
                if field_status == Status::Dirty {
                    status = Status::Dirty;
                }
                if !parsed.is_undefined() || has_member(body, field.name) {
                    output.insert(field.name, parsed);
                }
            }
        }
    }

    if aborted {
        return Err(issues);
    }
    if partial && output.is_empty() {
        // .refine(data => Object.keys(data).length > 0, { message })
        issues.refine("At least one field must be provided", &[]);
        status = Status::Dirty;
    }
    match status {
        Status::Valid => Ok(output),
        Status::Dirty => Err(issues),
    }
}

/// `experimentBodySchema.parse(request.body)`.
pub fn parse_experiment_body(body: &JsValue) -> Result<JsObject, Issues> {
    parse_experiment_object(body, false)
}

/// `experimentUpdateSchema.parse(request.body)`.
pub fn parse_experiment_update(body: &JsValue) -> Result<JsObject, Issues> {
    parse_experiment_object(body, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json::parse;

    fn value(text: &str) -> JsValue {
        parse(text).expect("valid JSON")
    }

    fn query(pairs: &[(&str, JsValue)]) -> JsObject {
        pairs.iter().map(|(key, value)| ((*key).to_string(), value.clone())).collect()
    }

    #[test]
    fn organization_options_defaults() {
        let parsed = parse_organization_options_query(&query(&[])).unwrap();
        assert_eq!(parsed, OrganizationOptionsQuery { search: String::new(), limit: 25.0 });
        let trimmed = parse_organization_options_query(&query(&[("search", "  hi  ".into()), ("limit", "3".into())]))
            .unwrap();
        assert_eq!(trimmed, OrganizationOptionsQuery { search: "hi".into(), limit: 3.0 });
    }

    #[test]
    fn organization_options_errors_match_zod() {
        let issues = parse_organization_options_query(&query(&[("limit", "abc".into())])).unwrap_err();
        assert_eq!(
            issues.flatten().to_string(),
            r#"{"formErrors":[],"fieldErrors":{"limit":["Expected number, received nan"]}}"#
        );
        let zero = parse_organization_options_query(&query(&[("limit", "0".into())])).unwrap_err();
        assert_eq!(
            zero.flatten().to_string(),
            r#"{"formErrors":[],"fieldErrors":{"limit":["Number must be greater than or equal to 1"]}}"#
        );
        let array = parse_organization_options_query(&query(&[(
            "search",
            JsValue::Array(vec!["a".into(), "b".into()]),
        )]))
        .unwrap_err();
        assert_eq!(
            array.flatten().to_string(),
            r#"{"formErrors":[],"fieldErrors":{"search":["Expected string, received array"]}}"#
        );
    }

    #[test]
    fn subscription_override_arms() {
        assert_eq!(parse_subscription_override(&value(r#"{"mode":"none"}"#)).unwrap(), SubscriptionOverride::None);
        assert_eq!(
            parse_subscription_override(&value(r#"{"mode":"preset","planOverride":"pro1m"}"#)).unwrap(),
            SubscriptionOverride::Preset { plan_override: "pro1m".into() }
        );
        assert_eq!(
            parse_subscription_override(&value(r#"{"mode":"custom","customPlan":{"events":5,"members":null,"websites":2}}"#))
                .unwrap(),
            SubscriptionOverride::Custom { events: 5.0, members: None, websites: Some(2.0) }
        );
        let bad = parse_subscription_override(&value(r#"{"mode":"nope"}"#)).unwrap_err();
        assert_eq!(
            bad.flatten().to_string(),
            r#"{"formErrors":[],"fieldErrors":{"mode":["Invalid discriminator value. Expected 'none' | 'preset' | 'custom'"]}}"#
        );
        let missing = parse_subscription_override(&value(r#"{"mode":"custom"}"#)).unwrap_err();
        assert_eq!(
            missing.flatten().to_string(),
            r#"{"formErrors":[],"fieldErrors":{"customPlan":["Required"]}}"#
        );
    }

    #[test]
    fn update_member_refinement() {
        let ok = parse_update_member(&value(r#"{"role":"admin","hasRestrictedSiteAccess":true,"siteIds":[1,2]}"#)).unwrap();
        assert_eq!(ok.role, "admin");
        let refined =
            parse_update_member(&value(r#"{"role":"member","hasRestrictedSiteAccess":true,"siteIds":[]}"#)).unwrap_err();
        assert_eq!(
            refined.flatten().to_string(),
            r#"{"formErrors":[],"fieldErrors":{"siteIds":["Select at least one site"]}}"#
        );
        let typed = parse_update_member(&value(r#"{"role":"root","hasRestrictedSiteAccess":1,"siteIds":[1.5]}"#))
            .unwrap_err();
        assert_eq!(
            typed.flatten().to_string(),
            concat!(
                r#"{"formErrors":[],"fieldErrors":{"role":["Invalid enum value. Expected 'owner' | 'admin' | 'member', received 'root'"],"#,
                r#""hasRestrictedSiteAccess":["Expected boolean, received number"],"#,
                r#""siteIds":["Expected integer, received float"]}}"#
            )
        );
    }

    #[test]
    fn experiment_body_defaults_and_issues() {
        let parsed = parse_experiment_body(&value(r#"{"name":" A ","featureFlagId":7,"extra":1}"#)).unwrap();
        assert_eq!(
            crate::analytics::js::json::stringify(&JsValue::Object(parsed)).unwrap(),
            r#"{"name":"A","featureFlagId":7,"status":"draft"}"#
        );
        let empty = parse_experiment_update(&value("{}")).unwrap_err();
        assert_eq!(
            empty.into_json().to_string(),
            r#"[{"code":"custom","message":"At least one field must be provided","path":[]}]"#
        );
        let bad = parse_experiment_body(&value(r#"{"name":"","featureFlagId":-1}"#)).unwrap_err();
        assert_eq!(
            bad.into_json().to_string(),
            concat!(
                r#"[{"code":"too_small","minimum":1,"type":"string","inclusive":true,"exact":false,"message":"String must contain at least 1 character(s)","path":["name"]},"#,
                r#"{"code":"too_small","minimum":0,"type":"number","inclusive":false,"exact":false,"message":"Number must be greater than 0","path":["featureFlagId"]}]"#
            )
        );
    }

    #[test]
    fn experiment_update_keeps_sent_keys() {
        let parsed = parse_experiment_update(&value(r#"{"description":null,"status":"running"}"#)).unwrap();
        assert_eq!(
            crate::analytics::js::json::stringify(&JsValue::Object(parsed)).unwrap(),
            r#"{"description":null,"status":"running"}"#
        );
    }
}
