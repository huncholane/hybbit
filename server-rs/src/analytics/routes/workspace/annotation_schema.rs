//! Port of server/src/api/analytics/annotations/annotationSchema.ts: the body
//! schemas for creating and updating annotations and the GET query schema, with
//! zod's issue objects, since a failed parse is answered with
//! `{ error: "Validation error", details: error.errors }`.

use std::{cmp::Ordering, sync::LazyLock};

use regex::Regex;
use unicode_segmentation::UnicodeSegmentation;

use super::schema::{self, Field, ObjectStatus, StringCheck};
use crate::analytics::js::{
    JsObject, JsValue, date,
    zod::{self, Parsed, Path, PathSegment, Status, ZodIssue},
};

/// `ANNOTATION_COLORS`
pub const ANNOTATION_COLORS: [&str; 5] = ["amber", "rose", "sky", "violet", "lime"];
/// `annotationScopeSchema`
const SCOPES: [&str; 2] = ["site", "organization"];

const DATE_MESSAGE: &str = "Expected an ISO 8601 timestamp with offset (e.g. 2026-08-18T14:10:00Z) or a YYYY-MM-DD date";
const ICON_MESSAGE: &str = "icon must be a single emoji or character";

/// `DATE_ONLY`: `^(\d{4})-(\d{2})-(\d{2})$` (ASCII digits, as `\d` without the u flag)
static DATE_ONLY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})$").expect("static regex"));

/// `ISO_WITH_OFFSET`
static ISO_WITH_OFFSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,3})?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})$")
        .expect("static regex")
});

/// Days from 1970-01-01 to a proleptic Gregorian date (month 1-12).
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date of a day count from 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    (if month <= 2 { year_of_era + era * 400 + 1 } else { year_of_era + era * 400 }, month, day)
}

/// `isCalendarDate(value)`: `Date.UTC(year, month - 1, day)` must round-trip.
/// `Date.UTC` reads years 0 to 99 as 1900 to 1999, so those never do.
pub fn is_calendar_date(value: &str) -> bool {
    let Some(captures) = DATE_ONLY.captures(value) else { return false };
    let number = |index: usize| captures[index].parse::<i64>().unwrap_or_default();
    let (year, month, day) = (number(1), number(2), number(3));
    let utc_year = if (0..=99).contains(&year) { 1900 + year } else { year };
    // MakeDay: month overflow carries into the year, day overflow into the month
    let month_zero = month - 1;
    let carried_year = utc_year + month_zero.div_euclid(12);
    let carried_month = month_zero.rem_euclid(12) + 1;
    let days = days_from_civil(carried_year, carried_month, 1) + day - 1;
    civil_from_days(days) == (year, month, day)
}

/// `dateInput`: trim, accept a calendar date or an ISO timestamp with an offset,
/// then normalise with `new Date(...).toISOString()`. A failed refinement makes
/// the transform return INVALID, so the field aborts.
fn date_input(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<String> {
    let (_, text) = schema::string(value, path, issues, &[StringCheck::Trim])?;
    let accepted = is_calendar_date(&text) || (ISO_WITH_OFFSET.is_match(&text) && !date::parse(&text).is_nan());
    if !accepted {
        issues.push(zod::custom(path, DATE_MESSAGE));
        return None;
    }
    let source = if DATE_ONLY.is_match(&text) { format!("{text}T00:00:00.000Z") } else { text };
    // Both accepted shapes parse, so toISOString cannot throw here
    date::to_iso_string(date::parse(&source)).map(|iso| (Status::Valid, iso))
}

/// `iconInput`: at most 16 UTF-16 units and a single grapheme (or empty).
fn icon_input(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<String> {
    let (mut status, text) = schema::string(value, path, issues, &[StringCheck::Trim, StringCheck::Max(16, None)])?;
    if !(text.is_empty() || text.graphemes(true).count() == 1) {
        issues.push(zod::custom(path, ICON_MESSAGE));
        status = Status::Dirty;
    }
    Some((status, text))
}

/// `annotationScopeSchema`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnotationScope {
    Site,
    Organization,
}

fn scope(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<AnnotationScope> {
    zod::enumeration(value, &SCOPES, path, issues).map(|(status, text)| {
        (status, if text == "organization" { AnnotationScope::Organization } else { AnnotationScope::Site })
    })
}

fn color(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<String> {
    zod::enumeration(value, &ANNOTATION_COLORS, path, issues)
}

fn field_path(name: &str) -> Path {
    vec![PathSegment::Key(name.to_string())]
}

/// `CreateAnnotationInput`
#[derive(Clone, Debug, PartialEq)]
pub struct CreateAnnotation {
    pub title: String,
    pub description: Field<String>,
    pub date: String,
    pub end_date: Field<String>,
    pub color: Field<String>,
    pub icon: Field<String>,
    pub is_public: bool,
    pub scope: AnnotationScope,
}

/// `UpdateAnnotationInput`: `None`/`Absent` for keys the body left out.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateAnnotation {
    pub title: Option<String>,
    pub description: Field<String>,
    pub date: Option<String>,
    pub end_date: Field<String>,
    pub color: Field<String>,
    pub icon: Field<String>,
    pub is_public: Option<bool>,
    pub scope: Option<AnnotationScope>,
}

fn title(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<String> {
    schema::string(
        value,
        path,
        issues,
        &[StringCheck::Trim, StringCheck::Min(1, Some("Title is required")), StringCheck::Max(120, None)],
    )
}

fn description(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<Field<String>> {
    schema::nullable_optional(value, |inner| {
        schema::string(inner, path, issues, &[StringCheck::Trim, StringCheck::Max(2000, None)])
    })
}

/// `createAnnotationSchema.parse(body)`
pub fn parse_create(body: &JsValue) -> Result<CreateAnnotation, Vec<ZodIssue>> {
    let root: Path = Vec::new();
    let mut issues = Vec::new();
    let Some(object) = schema::object(body, &root, &mut issues) else { return Err(issues) };
    let field = |name: &str| object.get_or_undefined(name);
    let mut status = ObjectStatus::new();

    let title = status.field(title(field("title"), &field_path("title"), &mut issues));
    let description = status.field(description(field("description"), &field_path("description"), &mut issues));
    let date = status.field(date_input(field("date"), &field_path("date"), &mut issues));
    let end_date = status.field(schema::nullable_optional(field("endDate"), |inner| {
        date_input(inner, &field_path("endDate"), &mut issues)
    }));
    let color = status.field(schema::nullable_optional(field("color"), |inner| color(inner, &field_path("color"), &mut issues)));
    let icon = status.field(schema::nullable_optional(field("icon"), |inner| icon_input(inner, &field_path("icon"), &mut issues)));
    let is_public = status.field(match field("isPublic") {
        JsValue::Undefined => Some((Status::Valid, false)),
        other => schema::boolean(other, &field_path("isPublic"), &mut issues),
    });
    let scope = status.field(match field("scope") {
        JsValue::Undefined => Some((Status::Valid, AnnotationScope::Site)),
        other => scope(other, &field_path("scope"), &mut issues),
    });

    let Some(mut object_status) = status.finish() else { return Err(issues) };
    let (Some(title), Some(description), Some(date), Some(end_date), Some(color), Some(icon), Some(is_public), Some(scope)) =
        (title, description, date, end_date, color, icon, is_public, scope)
    else {
        return Err(issues);
    };

    // endAfterStart, refined over the (possibly dirty) object
    if let Field::Value(end) = &end_date
        && !date.is_empty()
        && !end.is_empty()
        && date::parse(end).partial_cmp(&date::parse(&date)) != Some(Ordering::Greater)
    {
        issues.push(zod::custom(&field_path("endDate"), "endDate must be after date"));
        object_status = Status::Dirty;
    }
    schema::finish(
        Some((object_status, CreateAnnotation { title, description, date, end_date, color, icon, is_public, scope })),
        issues,
    )
}

/// `updateAnnotationSchema.parse(body)`
pub fn parse_update(body: &JsValue) -> Result<UpdateAnnotation, Vec<ZodIssue>> {
    let root: Path = Vec::new();
    let mut issues = Vec::new();
    let Some(object) = schema::object(body, &root, &mut issues) else { return Err(issues) };
    let field = |name: &str| object.get_or_undefined(name);
    let mut status = ObjectStatus::new();

    let title = status.field(schema::optional(field("title"), |inner| title(inner, &field_path("title"), &mut issues)));
    let description = status.field(description(field("description"), &field_path("description"), &mut issues));
    let date = status.field(schema::optional(field("date"), |inner| date_input(inner, &field_path("date"), &mut issues)));
    let end_date = status.field(schema::nullable_optional(field("endDate"), |inner| {
        date_input(inner, &field_path("endDate"), &mut issues)
    }));
    let color = status.field(schema::nullable_optional(field("color"), |inner| color(inner, &field_path("color"), &mut issues)));
    let icon = status.field(schema::nullable_optional(field("icon"), |inner| icon_input(inner, &field_path("icon"), &mut issues)));
    let is_public = status.field(schema::optional(field("isPublic"), |inner| {
        schema::boolean(inner, &field_path("isPublic"), &mut issues)
    }));
    let scope = status.field(schema::optional(field("scope"), |inner| scope(inner, &field_path("scope"), &mut issues)));

    let Some(mut object_status) = status.finish() else { return Err(issues) };
    let (Some(title), Some(description), Some(date), Some(end_date), Some(color), Some(icon), Some(is_public), Some(scope)) =
        (title, description, date, end_date, color, icon, is_public, scope)
    else {
        return Err(issues);
    };

    // Object.keys(data).length > 0: the shape keys the body actually carried
    const SHAPE: [&str; 8] = ["title", "description", "date", "endDate", "color", "icon", "isPublic", "scope"];
    if !SHAPE.iter().any(|name| object.contains_key(name)) {
        issues.push(zod::custom(&root, "No fields to update"));
        object_status = Status::Dirty;
    }
    let is_public = match is_public {
        Field::Value(flag) => Some(flag),
        _ => None,
    };
    let scope = match scope {
        Field::Value(scope) => Some(scope),
        _ => None,
    };
    let title = match title {
        Field::Value(text) => Some(text),
        _ => None,
    };
    let date = match date {
        Field::Value(text) => Some(text),
        _ => None,
    };
    schema::finish(
        Some((object_status, UpdateAnnotation { title, description, date, end_date, color, icon, is_public, scope })),
        issues,
    )
}

/// The GET query after `listAnnotationsQuerySchema`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ListQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub time_zone: Option<String>,
}

/// JavaScript `<=` on strings: UTF-16 code unit order.
fn utf16_less_or_equal(left: &str, right: &str) -> bool {
    left.encode_utf16().cmp(right.encode_utf16()) != Ordering::Greater
}

/// `listAnnotationsQuerySchema.parse(request.query ?? {})`
pub fn parse_list_query(query: &JsObject) -> Result<ListQuery, Vec<ZodIssue>> {
    let mut issues = Vec::new();
    let mut status = ObjectStatus::new();
    let calendar = |name: &'static str, message: &'static str, issues: &mut Vec<ZodIssue>| {
        let value = query.get_or_undefined(name);
        schema::optional(value, |inner| {
            let (status, text) = schema::string(inner, &field_path(name), issues, &[])?;
            if is_calendar_date(&text) {
                Some((status, text))
            } else {
                issues.push(zod::custom(&field_path(name), message));
                Some((Status::Dirty, text))
            }
        })
    };
    let start_date = status.field(calendar("start_date", "start_date must be a valid YYYY-MM-DD date", &mut issues));
    let end_date = status.field(calendar("end_date", "end_date must be a valid YYYY-MM-DD date", &mut issues));
    let time_zone = status.field(schema::optional(query.get_or_undefined("time_zone"), |inner| {
        schema::string(inner, &field_path("time_zone"), &mut issues, &[])
    }));
    let Some(mut object_status) = status.finish() else { return Err(issues) };
    let (Some(start_date), Some(end_date), Some(time_zone)) = (start_date, end_date, time_zone) else {
        return Err(issues);
    };
    let start_date = start_date.value().cloned();
    let end_date = end_date.value().cloned();
    if let (Some(start), Some(end)) = (&start_date, &end_date)
        && !start.is_empty()
        && !end.is_empty()
        && !utf16_less_or_equal(start, end)
    {
        issues.push(zod::custom(&field_path("start_date"), "start_date must be on or before end_date"));
        object_status = Status::Dirty;
    }
    schema::finish(Some((object_status, ListQuery { start_date, end_date, time_zone: time_zone.value().cloned() })), issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json;

    fn body(text: &str) -> JsValue {
        json::parse(text).unwrap()
    }

    fn create_ok(text: &str) -> bool {
        parse_create(&body(text)).is_ok()
    }

    // Ported from annotationSchema.test.ts
    #[test]
    fn create_schema_normalizes_and_defaults() {
        let parsed = parse_create(&body(r#"{"title":"  Launch ","date":"2026-08-18"}"#)).unwrap();
        assert_eq!(parsed.date, "2026-08-18T00:00:00.000Z");
        assert_eq!(parsed.title, "Launch");
        assert_eq!(parsed.scope, AnnotationScope::Site);
        assert!(!parsed.is_public);

        let parsed = parse_create(&body(r#"{"title":"Deploy","date":"2026-08-24T16:10:00+02:00"}"#)).unwrap();
        assert_eq!(parsed.date, "2026-08-24T14:10:00.000Z");

        assert!(!create_ok(r#"{"title":"Test","date":"2026-08-14","endDate":"2026-08-11"}"#));
        assert!(!create_ok(r#"{"title":"x","date":"2026-08-18","color":"emerald"}"#));
        assert!(!create_ok(r#"{"title":"   ","date":"2026-08-18"}"#));
        assert!(!create_ok(r#"{"title":"x","date":"yesterday"}"#));
    }

    #[test]
    fn update_schema_rejects_empty_and_clears_nullable_fields() {
        assert!(parse_update(&body("{}")).is_err());
        let parsed = parse_update(&body(r#"{"endDate":null,"description":null,"color":null}"#)).unwrap();
        assert_eq!(parsed.end_date, Field::Null);
        assert_eq!(parsed.description, Field::Null);
        assert_eq!(parsed.color, Field::Null);
        assert_eq!(parsed.title, None);
    }

    #[test]
    fn date_strictness() {
        assert!(!create_ok(r#"{"title":"x","date":"2026-02-30"}"#));
        assert!(!create_ok(r#"{"title":"x","date":"2026-08-18T14:10:00"}"#));
        assert!(!create_ok(r#"{"title":"x","date":"08/18/2026"}"#));
        assert!(create_ok(r#"{"title":"x","date":"2026-08-18T14:10:00Z"}"#));
        assert!(create_ok(r#"{"title":"x","date":"2026-08-18T14:10:00.5+0200"}"#));
        // Date.UTC maps years 0-99 onto 1900-1999
        assert!(!is_calendar_date("0050-01-01"));
        assert!(is_calendar_date("0100-01-01"));
        assert!(is_calendar_date("2024-02-29"));
        assert!(!is_calendar_date("2025-02-29"));
    }

    #[test]
    fn list_query_schema() {
        let query = |pairs: &[(&str, &str)]| -> JsObject {
            pairs.iter().map(|(key, value)| (key.to_string(), JsValue::String(value.to_string()))).collect()
        };
        assert!(parse_list_query(&query(&[("start_date", "2026-08-01")])).is_ok());
        assert!(parse_list_query(&query(&[("end_date", "2026-08-31")])).is_ok());
        assert!(parse_list_query(&query(&[("start_date", "2026-08-31"), ("end_date", "2026-08-01")])).is_err());
        assert!(parse_list_query(&query(&[("start_date", "2026-13-01")])).is_err());
    }

    #[test]
    fn icon_is_one_grapheme() {
        assert!(create_ok(r#"{"title":"x","date":"2026-08-18","icon":"🚀"}"#));
        assert!(create_ok(r#"{"title":"x","date":"2026-08-18","icon":"👨‍👩‍👧"}"#));
        assert!(create_ok(r#"{"title":"x","date":"2026-08-18","icon":"🏷️"}"#));
        assert!(!create_ok(r#"{"title":"x","date":"2026-08-18","icon":"ab"}"#));
        assert!(!create_ok(r#"{"title":"x","date":"2026-08-18","icon":"🚀🔥"}"#));
    }

    #[test]
    fn issues_serialize_like_zod() {
        // createAnnotationSchema.safeParse({ title: "", date: "nope", icon: "abcdefghijklmnopq", scope: 1 }).error.errors
        let issues = parse_create(&body(r#"{"title":"","date":"nope","icon":"abcdefghijklmnopq","scope":1}"#)).unwrap_err();
        assert_eq!(
            json::stringify(&zod::issues_value(&issues)).unwrap(),
            concat!(
                r#"[{"code":"too_small","minimum":1,"type":"string","inclusive":true,"exact":false,"message":"Title is required","path":["title"]},"#,
                r#"{"code":"custom","message":"Expected an ISO 8601 timestamp with offset (e.g. 2026-08-18T14:10:00Z) or a YYYY-MM-DD date","path":["date"]},"#,
                r#"{"code":"too_big","maximum":16,"type":"string","inclusive":true,"exact":false,"message":"String must contain at most 16 character(s)","path":["icon"]},"#,
                r#"{"code":"custom","message":"icon must be a single emoji or character","path":["icon"]},"#,
                r#"{"expected":"'site' | 'organization'","received":"number","code":"invalid_type","path":["scope"],"message":"Expected 'site' | 'organization', received number"}]"#
            )
        );
    }

    #[test]
    fn postgres_timestamps_parse_like_v8() {
        // node -e 'for (const s of [...]) console.log(Date.parse(s))'
        for (text, expected) in [
            ("2026-08-18 07:00:00+00", 1_787_036_400_000.0),
            ("2026-08-24 12:10:00.5+00", 1_787_573_400_500.0),
            ("2026-08-24 12:10:00.123456+00", 1_787_573_400_123.0),
            ("2026-08-24 12:10:00+05:30", 1_787_553_600_000.0),
            ("2026-08-24 12:10:00-03", 1_787_584_200_000.0),
            ("0999-01-01 00:00:00+00", -30_641_760_000_000.0),
            ("2026-08-18T14:10:00.5+0200", 1_787_055_000_500.0),
            ("2026-08-18T14:10+02:00", 1_787_055_000_000.0),
            ("2026-08-18T14:10:00.1234Z", 1_787_062_200_123.0),
            ("+010000-01-01 00:00:00+00", 253_402_300_800_000.0),
            ("2026-08-18T24:00:00Z", 1_787_097_600_000.0),
        ] {
            assert_eq!(date::parse(text), expected, "{text}");
        }
        for text in ["2026-08-18T14:10:00+2400", "2026-08-18T14:10:00+24:00", "2026-08-18T14:10:00+99:99"] {
            assert!(date::parse(text).is_nan(), "{text}");
        }
    }
}
