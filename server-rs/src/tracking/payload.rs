//! Tracking payload validation, ported from server/src/services/tracker/trackingPayload.ts
//! (a zod 3.25.76 discriminated union of strict objects).
//!
//! The port follows zod's evaluation order rather than just its accept/reject verdict,
//! because `trackEvent` sends `error.flatten()` back to the client: every field of the
//! selected schema is checked in shape order, each check that fails adds its message
//! (a too-long string whose refinement also fails reports both), a wrong type stops
//! that field's remaining checks, and unknown keys are reported last as a form error.

use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::{
    js::utf16_len,
    json::{JsValue, parse_json},
};

/// `MAX_CLIENT_BOT_SCORE` from shared/src/botSignalContract.ts
pub const MAX_CLIENT_BOT_SCORE: u32 = 10;
/// `ALL_CLIENT_BOT_SIGNAL_BITS` from shared/src/botSignalContract.ts: the 13 signal bits
/// the contract defines (automationApi = 1 through missingScreenDimensions = 4096)
pub const ALL_CLIENT_BOT_SIGNAL_BITS: u32 = (1 << 13) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrackingEventType {
    Pageview,
    CustomEvent,
    Performance,
    Outbound,
    Error,
    ButtonClick,
    Copy,
    FormSubmit,
    InputChange,
    Heartbeat,
}

impl TrackingEventType {
    /// In schema order, which is the order zod lists them in the discriminator error
    pub const ALL: [TrackingEventType; 10] = [
        TrackingEventType::Pageview,
        TrackingEventType::CustomEvent,
        TrackingEventType::Performance,
        TrackingEventType::Outbound,
        TrackingEventType::Error,
        TrackingEventType::ButtonClick,
        TrackingEventType::Copy,
        TrackingEventType::FormSubmit,
        TrackingEventType::InputChange,
        TrackingEventType::Heartbeat,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            TrackingEventType::Pageview => "pageview",
            TrackingEventType::CustomEvent => "custom_event",
            TrackingEventType::Performance => "performance",
            TrackingEventType::Outbound => "outbound",
            TrackingEventType::Error => "error",
            TrackingEventType::ButtonClick => "button_click",
            TrackingEventType::Copy => "copy",
            TrackingEventType::FormSubmit => "form_submit",
            TrackingEventType::InputChange => "input_change",
            TrackingEventType::Heartbeat => "heartbeat",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// The object keys this variant's strict schema allows, in shape order.
    fn shape_keys(self) -> &'static [&'static str] {
        match self {
            TrackingEventType::Performance => PERFORMANCE_KEYS,
            TrackingEventType::Heartbeat => HEARTBEAT_KEYS,
            _ => EVENT_KEYS,
        }
    }
}

const BASE_KEYS: [&str; 18] = [
    "type",
    "site_id",
    "hostname",
    "pathname",
    "querystring",
    "screenWidth",
    "screenHeight",
    "language",
    "page_title",
    "referrer",
    "anonymous_id",
    "user_id",
    "tag",
    "feature_flags",
    "ip_address",
    "user_agent",
    "_bs",
    "_bsm",
];
const EVENT_KEYS: &[&str] = &concat_keys::<20>(&BASE_KEYS, &["event_name", "properties"]);
const PERFORMANCE_KEYS: &[&str] =
    &concat_keys::<25>(&BASE_KEYS, &["event_name", "properties", "lcp", "cls", "inp", "fcp", "ttfb"]);
const HEARTBEAT_KEYS: &[&str] = &concat_keys::<19>(&BASE_KEYS, &["event_name"]);

const fn concat_keys<const N: usize>(base: &[&'static str], extra: &[&'static str]) -> [&'static str; N] {
    let mut keys = [""; N];
    let mut i = 0;
    while i < base.len() {
        keys[i] = base[i];
        i += 1;
    }
    let mut j = 0;
    while j < extra.len() {
        keys[i + j] = extra[j];
        j += 1;
    }
    keys
}

/// The event body after validation: the only shape ingestion ever sees.
/// Absent optional fields are `None`; numbers stay doubles because zod bounds only
/// what the schema says (a non-negative integer screen width may still be 1e300).
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedTrackingPayload {
    pub event_type: TrackingEventType,
    pub site_id: String,
    pub hostname: Option<String>,
    pub pathname: Option<String>,
    pub querystring: Option<String>,
    pub screen_width: Option<f64>,
    pub screen_height: Option<f64>,
    pub language: Option<String>,
    pub page_title: Option<String>,
    pub referrer: Option<String>,
    pub anonymous_id: Option<String>,
    pub user_id: Option<String>,
    pub tag: Option<String>,
    /// JavaScript key order (integer-like keys first)
    pub feature_flags: Option<IndexMap<String, String>>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// `_bs`: an integer in 0..=MAX_CLIENT_BOT_SCORE
    pub bot_score: Option<u32>,
    /// `_bsm`: an integer in 0..=ALL_CLIENT_BOT_SIGNAL_BITS
    pub bot_signal_mask: Option<u32>,
    pub event_name: Option<String>,
    pub properties: Option<String>,
    /// Performance metrics: `None` absent, `Some(None)` sent as null. Non-negative,
    /// possibly `Infinity` (zod does not require finite numbers here)
    pub lcp: Option<Option<f64>>,
    pub cls: Option<Option<f64>>,
    pub inp: Option<Option<f64>>,
    pub fcp: Option<Option<f64>>,
    pub ttfb: Option<Option<f64>>,
}

/// zod's `error.flatten()`
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PayloadErrors {
    pub form_errors: Vec<String>,
    /// Keyed by the first path element, in the order issues were raised
    pub field_errors: IndexMap<String, Vec<String>>,
}

impl PayloadErrors {
    fn field(&mut self, name: &str, message: String) {
        self.field_errors.entry(name.to_string()).or_default().push(message);
    }

    fn is_empty(&self) -> bool {
        self.form_errors.is_empty() && self.field_errors.is_empty()
    }

    /// `{ formErrors, fieldErrors }`
    pub fn flatten(&self) -> Value {
        let fields: Map<String, Value> =
            self.field_errors.iter().map(|(name, messages)| (name.clone(), json!(messages))).collect();
        json!({ "formErrors": self.form_errors, "fieldErrors": fields })
    }

    /// The 400 body `trackEvent` sends, before the `/api` error rewrite.
    pub fn response_body(&self) -> Value {
        json!({ "success": false, "error": "Invalid payload", "details": self.flatten() })
    }
}

/// `trackingPayloadSchema.safeParse(request.body)`; `None` is an `undefined` body.
pub fn validate_tracking_payload(body: Option<&JsValue>) -> Result<ValidatedTrackingPayload, PayloadErrors> {
    let mut errors = PayloadErrors::default();

    let object = match body {
        None => {
            errors.form_errors.push("Required".into());
            return Err(errors);
        }
        Some(JsValue::Object(object)) => object,
        Some(other) => {
            errors.form_errors.push(format!("Expected object, received {}", other.zod_type_name()));
            return Err(errors);
        }
    };

    let Some(event_type) = object.get("type").and_then(JsValue::as_str).and_then(TrackingEventType::parse) else {
        let options: Vec<String> = TrackingEventType::ALL.iter().map(|kind| format!("'{}'", kind.as_str())).collect();
        errors.field("type", format!("Invalid discriminator value. Expected {}", options.join(" | ")));
        return Err(errors);
    };

    let mut fields = Fields { object, errors: &mut errors };
    let site_id = fields.string("site_id", Presence::Required, Some(1), None);
    let hostname = fields.string("hostname", Presence::Optional, None, Some(253));
    let pathname = fields.string("pathname", Presence::Optional, None, Some(2048));
    let querystring = fields.string("querystring", Presence::Optional, None, Some(2048));
    let screen_width = fields.number("screenWidth", true, Some(0.0), None);
    let screen_height = fields.number("screenHeight", true, Some(0.0), None);
    let language = fields.string("language", Presence::Optional, None, Some(35));
    let page_title = fields.string("page_title", Presence::Optional, None, Some(512));
    let referrer = fields.string("referrer", Presence::Optional, None, Some(2048));
    let anonymous_id = fields.string("anonymous_id", Presence::Optional, Some(1), Some(255));
    let user_id = fields.string("user_id", Presence::Optional, None, Some(255));
    let tag = fields.string("tag", Presence::Optional, None, Some(256));
    let feature_flags = fields.feature_flags();
    let ip_address = fields.ip("ip_address");
    let user_agent = fields.string("user_agent", Presence::Optional, None, Some(512));
    let bot_score = fields.number("_bs", true, Some(0.0), Some(MAX_CLIENT_BOT_SCORE as f64));
    let bot_signal_mask = fields.number("_bsm", true, Some(0.0), Some(ALL_CLIENT_BOT_SIGNAL_BITS as f64));

    let optional_name = |fields: &mut Fields| fields.string("event_name", Presence::Optional, None, Some(256));
    let required_name = |fields: &mut Fields| fields.string("event_name", Presence::Required, Some(1), Some(256));
    let mut metrics = [None, None, None, None, None];

    let (event_name, properties) = match event_type {
        TrackingEventType::Pageview => {
            (optional_name(&mut fields), fields.string("properties", Presence::Optional, None, Some(2048)))
        }
        TrackingEventType::Performance => {
            let names = (optional_name(&mut fields), fields.string("properties", Presence::Optional, None, Some(2048)));
            for (slot, metric) in metrics.iter_mut().zip(["lcp", "cls", "inp", "fcp", "ttfb"]) {
                *slot = fields.nullable_metric(metric);
            }
            names
        }
        TrackingEventType::CustomEvent => (
            required_name(&mut fields),
            fields.refined("properties", Presence::Optional, 2048, is_json, "Properties must be a valid JSON string"),
        ),
        TrackingEventType::Outbound => (
            optional_name(&mut fields),
            fields.refined(
                "properties",
                Presence::Required,
                2048,
                is_outbound_properties,
                "Properties must be valid JSON with outbound link fields (url required, text and target optional)",
            ),
        ),
        TrackingEventType::Error => (
            required_name(&mut fields),
            fields.refined(
                "properties",
                Presence::Required,
                4096,
                is_error_properties,
                "Properties must be valid JSON with error fields (message, stack, fileName, lineNumber, columnNumber)",
            ),
        ),
        TrackingEventType::ButtonClick => (
            optional_name(&mut fields),
            fields.refined("properties", Presence::Optional, 2048, is_json, "Properties must be valid JSON"),
        ),
        TrackingEventType::Copy => (
            optional_name(&mut fields),
            fields.refined(
                "properties",
                Presence::Required,
                2048,
                is_copy_properties,
                "Properties must be valid JSON with copy fields (sourceElement required, text and textLength optional)",
            ),
        ),
        TrackingEventType::FormSubmit => (
            optional_name(&mut fields),
            fields.refined(
                "properties",
                Presence::Required,
                2048,
                is_form_submit_properties,
                "Properties must be valid JSON with form_submit fields (formId, formName, formAction, method, fieldCount required)",
            ),
        ),
        TrackingEventType::InputChange => (
            optional_name(&mut fields),
            fields.refined(
                "properties",
                Presence::Required,
                2048,
                is_input_change_properties,
                "Properties must be valid JSON with input_change fields (element, inputName required)",
            ),
        ),
        TrackingEventType::Heartbeat => (fields.empty_literal("event_name"), None),
    };

    let shape = event_type.shape_keys();
    let unknown: Vec<String> =
        object.keys().filter(|key| !shape.contains(&key.as_str())).map(|key| format!("'{key}'")).collect();
    if !unknown.is_empty() {
        errors.form_errors.push(format!("Unrecognized key(s) in object: {}", unknown.join(", ")));
    }

    if !errors.is_empty() {
        tracing::debug!(
            event_type = event_type.as_str(),
            form_errors = ?errors.form_errors,
            fields = ?errors.field_errors.keys().collect::<Vec<_>>(),
            "Tracking payload failed validation"
        );
        return Err(errors);
    }

    let [lcp, cls, inp, fcp, ttfb] = metrics;
    Ok(ValidatedTrackingPayload {
        event_type,
        site_id: site_id.unwrap_or_default(),
        hostname,
        pathname,
        querystring,
        screen_width,
        screen_height,
        language,
        page_title,
        referrer,
        anonymous_id,
        user_id,
        tag,
        feature_flags,
        ip_address,
        user_agent,
        // Validated integers in range; `as` maps -0 to 0, which no consumer can tell apart
        bot_score: bot_score.map(|score| score as u32),
        bot_signal_mask: bot_signal_mask.map(|mask| mask as u32),
        event_name,
        properties,
        lcp,
        cls,
        inp,
        fcp,
        ttfb,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Presence {
    Required,
    Optional,
}

struct Fields<'a> {
    object: &'a IndexMap<String, JsValue>,
    errors: &'a mut PayloadErrors,
}

impl Fields<'_> {
    /// Returns the value if its type is right; failed checks are recorded either way.
    fn typed<'v>(
        &mut self,
        name: &str,
        presence: Presence,
        expected: &str,
        value: Option<&'v JsValue>,
    ) -> Option<&'v JsValue> {
        match value {
            None => {
                if presence == Presence::Required {
                    self.errors.field(name, "Required".into());
                }
                None
            }
            Some(value) if value.zod_type_name() == expected => Some(value),
            Some(other) => {
                self.errors.field(name, format!("Expected {expected}, received {}", other.zod_type_name()));
                None
            }
        }
    }

    fn string_checks(&mut self, name: &str, text: &str, min: Option<usize>, max: Option<usize>) {
        let length = utf16_len(text);
        if let Some(min) = min
            && length < min
        {
            self.errors.field(name, format!("String must contain at least {min} character(s)"));
        }
        if let Some(max) = max
            && length > max
        {
            self.errors.field(name, format!("String must contain at most {max} character(s)"));
        }
    }

    fn string(&mut self, name: &str, presence: Presence, min: Option<usize>, max: Option<usize>) -> Option<String> {
        let text = self.typed(name, presence, "string", self.object.get(name))?.as_str()?;
        self.string_checks(name, text, min, max);
        Some(text.to_string())
    }

    /// `z.string().ip().optional()`
    fn ip(&mut self, name: &str) -> Option<String> {
        let text = self.typed(name, Presence::Optional, "string", self.object.get(name))?.as_str()?;
        if !is_valid_ip(text) {
            self.errors.field(name, "Invalid ip".into());
        }
        Some(text.to_string())
    }

    /// `z.number()` with optional `.int()`, `.min()` and `.max()`, all optional fields
    fn number(&mut self, name: &str, integer: bool, min: Option<f64>, max: Option<f64>) -> Option<f64> {
        let JsValue::Number(number) = self.typed(name, Presence::Optional, "number", self.object.get(name))? else {
            return None;
        };
        self.number_checks(name, *number, integer, min, max);
        Some(*number)
    }

    fn number_checks(&mut self, name: &str, number: f64, integer: bool, min: Option<f64>, max: Option<f64>) {
        if integer && !(number.is_finite() && number.floor() == number) {
            self.errors.field(name, "Expected integer, received float".into());
        }
        if let Some(min) = min
            && number < min
        {
            self.errors.field(name, format!("Number must be greater than or equal to {}", min as i64));
        }
        if let Some(max) = max
            && number > max
        {
            self.errors.field(name, format!("Number must be less than or equal to {}", max as i64));
        }
    }

    /// `z.number().min(0).nullable().optional()`
    fn nullable_metric(&mut self, name: &str) -> Option<Option<f64>> {
        match self.object.get(name) {
            None => None,
            Some(JsValue::Null) => Some(None),
            value => {
                let JsValue::Number(number) = self.typed(name, Presence::Optional, "number", value)? else {
                    return None;
                };
                self.number_checks(name, *number, false, Some(0.0), None);
                Some(Some(*number))
            }
        }
    }

    /// `z.record(z.string().max(100), z.string().max(2048)).optional()`
    fn feature_flags(&mut self) -> Option<IndexMap<String, String>> {
        let JsValue::Object(entries) =
            self.typed("feature_flags", Presence::Optional, "object", self.object.get("feature_flags"))?
        else {
            return None;
        };
        let mut flags = IndexMap::new();
        for (key, value) in entries {
            self.string_checks("feature_flags", key, None, Some(100));
            match value {
                JsValue::String(text) => {
                    self.string_checks("feature_flags", text, None, Some(2048));
                    flags.insert(key.clone(), text.clone());
                }
                other => {
                    self.errors.field("feature_flags", format!("Expected string, received {}", other.zod_type_name()));
                }
            }
        }
        Some(flags)
    }

    /// `z.string().max(max).refine(check, { message })`: the refinement still runs
    /// when the length check failed, but not when the value is not a string.
    fn refined(
        &mut self,
        name: &str,
        presence: Presence,
        max: usize,
        check: fn(&str) -> bool,
        message: &str,
    ) -> Option<String> {
        let text = self.typed(name, presence, "string", self.object.get(name))?.as_str()?;
        self.string_checks(name, text, None, Some(max));
        if !check(text) {
            self.errors.field(name, message.to_string());
        }
        Some(text.to_string())
    }

    /// `z.literal("").optional()`
    fn empty_literal(&mut self, name: &str) -> Option<String> {
        match self.object.get(name) {
            None => None,
            Some(JsValue::String(text)) if text.is_empty() => Some(String::new()),
            Some(_) => {
                self.errors.field(name, "Invalid literal value, expected \"\"".into());
                None
            }
        }
    }
}

/// zod 3's `isValidIP` with no version: its IPv4 or IPv6 regex.
fn is_valid_ip(text: &str) -> bool {
    static IPV4: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$")
            .expect("zod IPv4 pattern")
    });
    static IPV6: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(concat!(
            r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}",
            r"|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}",
            r"|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}",
            r"|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}",
            r"|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])",
            r"|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
        ))
        .expect("zod IPv6 pattern")
    });
    IPV4.is_match(text) || IPV6.is_match(text)
}

/// `JSON.parse(val)` succeeds, and the object it gives when it gives one.
fn parse_properties(text: &str) -> Option<JsValue> {
    parse_json(text, 1).ok().map(|parsed| parsed.value)
}

fn is_json(text: &str) -> bool {
    parse_json(text, 0).is_ok()
}

/// `value && typeof value !== expected` fails the refinement.
fn truthy_but_not(value: Option<&JsValue>, expected: &str) -> bool {
    value.is_some_and(|value| value.is_truthy() && value.type_of() != expected)
}

fn is_outbound_properties(text: &str) -> bool {
    // A non-object gives `undefined` for `parsed.url` (or throws, for null)
    let Some(JsValue::Object(parsed)) = parse_properties(text) else { return false };
    let Some(JsValue::String(url)) = parsed.get("url") else { return false };
    if url.is_empty() || truthy_but_not(parsed.get("text"), "string") || truthy_but_not(parsed.get("target"), "string")
    {
        return false;
    }
    url::Url::parse(url).is_ok()
}

fn is_error_properties(text: &str) -> bool {
    let Some(JsValue::Object(parsed)) = parse_properties(text) else { return false };
    matches!(parsed.get("message"), Some(JsValue::String(_)))
        && !truthy_but_not(parsed.get("stack"), "string")
        && !truthy_but_not(parsed.get("fileName"), "string")
        && !truthy_but_not(parsed.get("lineNumber"), "number")
        && !truthy_but_not(parsed.get("columnNumber"), "number")
}

/// Node rejects `typeof n !== "number" || n < 0`; parsed JSON numbers are never NaN,
/// so `n >= 0` is the same test.
fn is_copy_properties(text: &str) -> bool {
    let Some(JsValue::Object(parsed)) = parse_properties(text) else { return false };
    matches!(parsed.get("sourceElement"), Some(JsValue::String(_)))
        && parsed.get("text").is_none_or(|text| matches!(text, JsValue::String(_)))
        && parsed.get("textLength").is_none_or(|length| matches!(length, JsValue::Number(length) if *length >= 0.0))
}

fn is_form_submit_properties(text: &str) -> bool {
    let Some(JsValue::Object(parsed)) = parse_properties(text) else { return false };
    ["formId", "formName", "formAction", "method"]
        .iter()
        .all(|field| matches!(parsed.get(*field), Some(JsValue::String(_))))
        && matches!(parsed.get("fieldCount"), Some(JsValue::Number(count)) if *count >= 0.0)
}

fn is_input_change_properties(text: &str) -> bool {
    let Some(JsValue::Object(parsed)) = parse_properties(text) else { return false };
    matches!(parsed.get("element"), Some(JsValue::String(_)))
        && matches!(parsed.get("inputName"), Some(JsValue::String(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracking::json::parse_json;

    fn validate(text: &str) -> Result<ValidatedTrackingPayload, PayloadErrors> {
        let body = parse_json(text, 2).expect("test payloads are valid JSON").value;
        validate_tracking_payload(Some(&body))
    }

    fn pageview(extra: &str) -> Result<ValidatedTrackingPayload, PayloadErrors> {
        let separator = if extra.is_empty() { "" } else { "," };
        validate(&format!(r#"{{"type":"pageview","site_id":"site_abc"{separator}{extra}}}"#))
    }

    // Ported from trackingPayload.test.ts
    #[test]
    fn accepts_a_mask_carrying_every_bit_the_contract_defines() {
        assert!(pageview(&format!(r#""_bsm":{ALL_CLIENT_BOT_SIGNAL_BITS},"_bs":{MAX_CLIENT_BOT_SCORE}"#)).is_ok());
        assert!(pageview(r#""_bsm":2048"#).is_ok());
    }

    #[test]
    fn rejects_a_mask_carrying_bits_the_contract_does_not_define() {
        assert!(pageview(&format!(r#""_bsm":{}"#, ALL_CLIENT_BOT_SIGNAL_BITS + 1)).is_err());
    }

    #[test]
    fn rejects_a_score_above_the_contracts_ceiling() {
        assert!(pageview(&format!(r#""_bs":{MAX_CLIENT_BOT_SCORE}"#)).is_ok());
        assert!(pageview(&format!(r#""_bs":{}"#, MAX_CLIENT_BOT_SCORE + 1)).is_err());
    }

    #[test]
    fn treats_both_bot_fields_as_optional() {
        assert!(pageview("").is_ok());
    }

    #[test]
    fn heartbeat_accepts_page_context_but_not_a_name_or_properties() {
        let heartbeat = |extra: &str| validate(&format!(r#"{{"type":"heartbeat","site_id":"site_abc",{extra}}}"#));
        assert!(
            heartbeat(r#""pathname":"/pricing","hostname":"example.com","referrer":"https://google.com/""#).is_ok()
        );
        assert!(heartbeat(r#""event_name":"signup""#).is_err());
        assert!(heartbeat(r#""properties":"{}""#).is_err());
    }

    #[test]
    fn flattens_errors_in_zod_order() {
        let errors = validate(
            r#"{"type":"custom_event","site_id":"","screenWidth":-1.5,"properties":"{","zzz":1,"1":2,"feature_flags":{"k":5}}"#,
        )
        .unwrap_err();
        assert_eq!(
            errors.flatten(),
            json!({
                "formErrors": ["Unrecognized key(s) in object: '1', 'zzz'"],
                "fieldErrors": {
                    "site_id": ["String must contain at least 1 character(s)"],
                    "screenWidth": ["Expected integer, received float", "Number must be greater than or equal to 0"],
                    "feature_flags": ["Expected string, received number"],
                    "event_name": ["Required"],
                    "properties": ["Properties must be a valid JSON string"],
                }
            })
        );
    }

    #[test]
    fn rejects_non_objects_and_unknown_types() {
        assert_eq!(validate_tracking_payload(None).unwrap_err().form_errors, ["Required"]);
        assert_eq!(validate("[]").unwrap_err().form_errors, ["Expected object, received array"]);
        let errors = validate(r#"{"type":"nope"}"#).unwrap_err();
        assert_eq!(
            errors.field_errors["type"],
            [
                "Invalid discriminator value. Expected 'pageview' | 'custom_event' | 'performance' | 'outbound' | 'error' | 'button_click' | 'copy' | 'form_submit' | 'input_change' | 'heartbeat'"
            ]
        );
    }

    #[test]
    fn keeps_infinite_metrics_zod_accepts() {
        let payload = validate(r#"{"type":"performance","site_id":"1","lcp":1e400,"cls":null}"#).unwrap();
        assert_eq!(payload.lcp, Some(Some(f64::INFINITY)));
        assert_eq!(payload.cls, Some(None));
        assert_eq!(payload.inp, None);
    }
}
