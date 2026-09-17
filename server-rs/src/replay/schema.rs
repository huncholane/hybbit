//! `recordSessionReplaySchema` from server/src/api/sessionReplay/recordSessionReplay.ts
//! (zod 3.25.76), checked over the parsed body tape.
//!
//! zod reports every failure in shape order (userId, then each event's type, data
//! and timestamp, then the metadata fields), a wrong type aborts only that field,
//! and unknown keys are stripped. The handler answers `{ error: error.errors }`,
//! which the API error rewrite then replaces with its default message, so the
//! issue objects are kept faithful mostly for logs.
//!
//! Event data stays on the tape until the whole body has validated, and is then
//! serialised once, as `JSON.stringify(event.data)` would.

use super::json::{JsString, Kind, Node, Tape};
use crate::analytics::js::{
    JsObject, JsValue,
    zod::{self, Path, PathSegment, ZodIssue},
};

/// `z.union([z.string(), z.number()])` output.
#[derive(Clone, Debug, PartialEq)]
pub enum EventType {
    Text(JsString),
    Number(f64),
}

/// One validated event.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayEvent {
    pub event_type: EventType,
    /// `JSON.stringify(event.data)`; None when the key was absent (`undefined`)
    pub data: Option<String>,
    pub timestamp: f64,
}

/// The validated `metadata` object.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayMetadata {
    pub page_url: JsString,
    pub viewport_width: Option<f64>,
    pub viewport_height: Option<f64>,
    pub language: Option<JsString>,
}

/// `RecordSessionReplayRequest` after `recordSessionReplaySchema.parse`.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayBatch {
    pub user_id: JsString,
    pub events: Vec<ReplayEvent>,
    pub metadata: Option<ReplayMetadata>,
}

/// A value of the kind zod reports, for the shared issue builders.
fn stand_in(kind: Option<Kind>) -> JsValue {
    match kind {
        None => JsValue::Undefined,
        Some(Kind::Null) => JsValue::Null,
        Some(Kind::Boolean) => JsValue::Bool(false),
        Some(Kind::Number) => JsValue::Number(0.0),
        Some(Kind::String) => JsValue::String(String::new()),
        Some(Kind::Array) => JsValue::Array(Vec::new()),
        Some(Kind::Object) => JsValue::Object(JsObject::new()),
    }
}

fn key(path: &Path, name: &str) -> Path {
    zod::key(path, name)
}

/// The issue for a body that is not an object at all (`received` is zod's type
/// name, "undefined" for a request without a body).
pub fn non_object_body_issues(received: &str) -> Vec<ZodIssue> {
    let value = match received {
        "undefined" => JsValue::Undefined,
        "null" => JsValue::Null,
        "boolean" => JsValue::Bool(false),
        "number" => JsValue::Number(0.0),
        "string" => JsValue::String(String::new()),
        "array" => JsValue::Array(Vec::new()),
        _ => JsValue::Object(JsObject::new()),
    };
    vec![zod::invalid_type(&Vec::new(), "object", &value)]
}

/// `z.string()`
fn string(node: Option<Node<'_>>, path: &Path, issues: &mut Vec<ZodIssue>) -> Option<JsString> {
    match node.and_then(|node| node.as_js_string()) {
        Some(text) => Some(text),
        None => {
            issues.push(zod::invalid_type(path, "string", &stand_in(node.map(|node| node.kind()))));
            None
        }
    }
}

/// `z.number()`: any JSON number, overflowed ones (±Infinity) included.
fn number(node: Option<Node<'_>>, path: &Path, issues: &mut Vec<ZodIssue>) -> Option<f64> {
    match node.and_then(|node| node.as_number()) {
        Some(value) => Some(value),
        None => {
            issues.push(zod::invalid_type(path, "number", &stand_in(node.map(|node| node.kind()))));
            None
        }
    }
}

/// `.optional()`: absent is fine, anything present must pass.
fn optional<T>(
    node: Option<Node<'_>>,
    path: &Path,
    issues: &mut Vec<ZodIssue>,
    inner: impl FnOnce(Option<Node<'_>>, &Path, &mut Vec<ZodIssue>) -> Option<T>,
) -> Result<Option<T>, ()> {
    match node {
        None => Ok(None),
        Some(node) => inner(Some(node), path, issues).map(Some).ok_or(()),
    }
}

/// An event before its data is serialised.
struct PendingEvent<'a> {
    event_type: EventType,
    data: Option<Node<'a>>,
    timestamp: f64,
}

fn event<'a>(node: Node<'a>, path: &Path, issues: &mut Vec<ZodIssue>) -> Option<PendingEvent<'a>> {
    if node.kind() != Kind::Object {
        issues.push(zod::invalid_type(path, "object", &stand_in(Some(node.kind()))));
        return None;
    }

    // z.union([z.string(), z.number()]): both options abort on a type mismatch, so
    // a failure is always an invalid_union carrying both option errors
    let type_path = key(path, "type");
    let type_node = node.member("type");
    let event_type = match type_node {
        Some(value) if value.kind() == Kind::String => value.as_js_string().map(EventType::Text),
        Some(value) if value.kind() == Kind::Number => value.as_number().map(EventType::Number),
        other => {
            let received = stand_in(other.map(|value| value.kind()));
            issues.push(zod::invalid_union(
                &type_path,
                vec![
                    vec![zod::invalid_type(&type_path, "string", &received)],
                    vec![zod::invalid_type(&type_path, "number", &received)],
                ],
            ));
            None
        }
    };
    // data: z.any() accepts everything, absence included
    let data = node.member("data");
    let timestamp = number(node.member("timestamp"), &key(path, "timestamp"), issues);

    Some(PendingEvent { event_type: event_type?, data, timestamp: timestamp? })
}

fn metadata(node: Node<'_>, path: &Path, issues: &mut Vec<ZodIssue>) -> Option<ReplayMetadata> {
    if node.kind() != Kind::Object {
        issues.push(zod::invalid_type(path, "object", &stand_in(Some(node.kind()))));
        return None;
    }
    let page_url = string(node.member("pageUrl"), &key(path, "pageUrl"), issues);
    let viewport_width = optional(node.member("viewportWidth"), &key(path, "viewportWidth"), issues, number);
    let viewport_height = optional(node.member("viewportHeight"), &key(path, "viewportHeight"), issues, number);
    let language = optional(node.member("language"), &key(path, "language"), issues, string);
    Some(ReplayMetadata {
        page_url: page_url?,
        viewport_width: viewport_width.ok()?,
        viewport_height: viewport_height.ok()?,
        language: language.ok()?,
    })
}

/// `recordSessionReplaySchema.parse(body)` for an object body.
pub fn validate(tape: &Tape) -> Result<ReplayBatch, Vec<ZodIssue>> {
    let root = tape.root();
    let mut issues = Vec::new();
    let path: Path = Vec::new();
    if root.kind() != Kind::Object {
        return Err(vec![zod::invalid_type(&path, "object", &stand_in(Some(root.kind())))]);
    }

    let user_id = string(root.member("userId"), &key(&path, "userId"), &mut issues);

    let events_path = key(&path, "events");
    let events = match root.member("events") {
        Some(node) if node.kind() == Kind::Array => {
            let mut pending = Some(Vec::new());
            for (index, element) in node.elements().into_iter().enumerate() {
                let element_path = zod::child(&events_path, PathSegment::Index(index));
                match event(element, &element_path, &mut issues) {
                    Some(parsed) => {
                        if let Some(list) = pending.as_mut() {
                            list.push(parsed);
                        }
                    }
                    None => pending = None,
                }
            }
            pending
        }
        other => {
            issues.push(zod::invalid_type(&events_path, "array", &stand_in(other.map(|node| node.kind()))));
            None
        }
    };

    let metadata = match root.member("metadata") {
        None => Some(None),
        Some(node) => metadata(node, &key(&path, "metadata"), &mut issues).map(Some),
    };

    match (user_id, events, metadata) {
        (Some(user_id), Some(events), Some(metadata)) if issues.is_empty() => Ok(ReplayBatch {
            user_id,
            events: events
                .into_iter()
                .map(|pending| ReplayEvent {
                    event_type: pending.event_type,
                    data: pending.data.map(|data| data.stringify()),
                    timestamp: pending.timestamp,
                })
                .collect(),
            metadata,
        }),
        _ => Err(issues),
    }
}

/// `{ error: error.errors }` as the handler sends it.
pub fn error_body(issues: &[ZodIssue]) -> String {
    let mut body = JsObject::new();
    body.insert("error", zod::issues_value(issues));
    crate::analytics::js::json::stringify(&JsValue::Object(body)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::json::parse;

    fn check(body: &str) -> Result<ReplayBatch, String> {
        validate(&parse(body).unwrap()).map_err(|issues| {
            crate::analytics::js::json::stringify(&zod::issues_value(&issues)).unwrap()
        })
    }

    #[test]
    fn accepts_a_recorder_batch() {
        let batch = check(
            r#"{"userId":" u1 ","events":[{"type":2,"data":{"node":{"id":1,"childNodes":[]}},"timestamp":1700000000000,"extra":1},{"type":"custom","timestamp":1.5}],"metadata":{"pageUrl":"https://a.example/x","viewportWidth":1280,"language":"en-US","other":true},"apiKey":"x"}"#,
        )
        .unwrap();
        assert_eq!(batch.user_id, JsString::from(" u1 "));
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.events[0].event_type, EventType::Number(2.0));
        assert_eq!(batch.events[0].data.as_deref(), Some(r#"{"node":{"id":1,"childNodes":[]}}"#));
        assert_eq!(batch.events[1].event_type, EventType::Text(JsString::from("custom")));
        assert_eq!(batch.events[1].data, None);
        let metadata = batch.metadata.unwrap();
        assert_eq!(metadata.viewport_width, Some(1280.0));
        assert_eq!(metadata.viewport_height, None);
        assert_eq!(metadata.language, Some(JsString::from("en-US")));
    }

    // Issue lists as zod 3.25.76 reports them (recordSessionReplaySchema.safeParse in Node)
    #[test]
    fn reports_every_issue_in_shape_order() {
        assert_eq!(
            check(r#"{"events":[{"type":null,"data":1},5],"metadata":{"pageUrl":1,"viewportWidth":"1","language":null}}"#).unwrap_err(),
            concat!(
                r#"[{"code":"invalid_type","expected":"string","received":"undefined","path":["userId"],"message":"Required"},"#,
                r#"{"code":"invalid_union","unionErrors":[{"issues":[{"code":"invalid_type","expected":"string","received":"null","path":["events",0,"type"],"message":"Expected string, received null"}],"name":"ZodError"},{"issues":[{"code":"invalid_type","expected":"number","received":"null","path":["events",0,"type"],"message":"Expected number, received null"}],"name":"ZodError"}],"path":["events",0,"type"],"message":"Invalid input"},"#,
                r#"{"code":"invalid_type","expected":"number","received":"undefined","path":["events",0,"timestamp"],"message":"Required"},"#,
                r#"{"code":"invalid_type","expected":"object","received":"number","path":["events",1],"message":"Expected object, received number"},"#,
                r#"{"code":"invalid_type","expected":"string","received":"number","path":["metadata","pageUrl"],"message":"Expected string, received number"},"#,
                r#"{"code":"invalid_type","expected":"number","received":"string","path":["metadata","viewportWidth"],"message":"Expected number, received string"},"#,
                r#"{"code":"invalid_type","expected":"string","received":"null","path":["metadata","language"],"message":"Expected string, received null"}]"#,
            )
        );
        assert_eq!(
            check(r#"{"userId":"u","events":{},"metadata":null}"#).unwrap_err(),
            concat!(
                r#"[{"code":"invalid_type","expected":"array","received":"object","path":["events"],"message":"Expected array, received object"},"#,
                r#"{"code":"invalid_type","expected":"object","received":"null","path":["metadata"],"message":"Expected object, received null"}]"#
            )
        );
        assert_eq!(
            crate::analytics::js::json::stringify(&zod::issues_value(&non_object_body_issues("undefined"))).unwrap(),
            r#"[{"code":"invalid_type","expected":"object","received":"undefined","path":[],"message":"Required"}]"#
        );
    }

    #[test]
    fn keeps_infinite_timestamps_zod_accepts() {
        let batch = check(r#"{"userId":"","events":[{"type":3,"data":null,"timestamp":1e400},{"type":3,"data":"x","timestamp":-1e400}]}"#).unwrap();
        assert_eq!(batch.events[0].timestamp, f64::INFINITY);
        assert_eq!(batch.events[0].data.as_deref(), Some("null"));
        assert_eq!(batch.events[1].timestamp, f64::NEG_INFINITY);
        assert_eq!(batch.events[1].data.as_deref(), Some(r#""x""#));
    }
}
