//! `POST /api/identify`, ported from server/src/services/tracker/identifyService.ts.
//!
//! Links an anonymous device fingerprint to a Site's own user id: a
//! `user_profiles` shell, a `user_aliases` row (plus a queued ClickHouse backfill
//! of `identified_user_id`), and a traits merge. The route itself is wired by the
//! HTTP layer; `handle_identify` returns exactly the status and JSON body Node's
//! handler sends, including zod's flattened validation errors.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use sqlx::{
    Encode, PgPool, Postgres, Type,
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo, types::Oid},
};

use super::{
    backfill::{BACKFILL_DAYS, BackfillSink, IdentityAssignment, IdentityBackfillQueue},
    sticky::StickyStore,
    user_id::{UserIdDeps, UserIdOptions, UserIdService},
};
use crate::{
    geo::AsnLookup,
    site_config::{SiteConfigCache, SiteConfigData, SiteRef},
};

/// `MAX_TRAITS_SIZE`: 2KB of `JSON.stringify(traits)` as UTF-8.
pub const MAX_TRAITS_SIZE: usize = 2048;

/// `backfillIdentifiedUserId`: queue the assignment instead of mutating now.
/// `days: None` backfills the device's full history; only the dashboard's
/// explicit identify does that.
pub fn backfill_identified_user_id<S: BackfillSink>(
    queue: &IdentityBackfillQueue<S>,
    site_id: i32,
    anonymous_id: &str,
    user_id: &str,
    days: Option<u32>,
) {
    queue.enqueue(
        IdentityAssignment { site_id, anonymous_id: anonymous_id.to_string(), user_id: user_id.to_string() },
        days,
    );
}

// ---------------------------------------------------------------------------
// Validation: `identifyPayloadSchema` with zod 3.25's messages and flatten()

/// The validated body (`validationResult.data`).
#[derive(Clone, Debug, PartialEq)]
pub struct IdentifyPayload {
    pub site_id: String,
    pub anonymous_id: Option<String>,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// The record zod rebuilt: own keys in order, `__proto__` dropped.
    pub traits: Option<Map<String, Value>>,
    pub is_new_identify: bool,
}

/// zod's `ZodParsedType` name for a JSON value.
fn parsed_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// zod's default `invalid_type` message.
fn invalid_type_message(expected: &str, received: Option<&Value>) -> String {
    match received {
        None => "Required".to_string(),
        Some(value) => format!("Expected {expected}, received {}", parsed_type(value)),
    }
}

/// JavaScript `string.length`: UTF-16 code units, which zod's min/max compare.
fn js_length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// zod 3.25 `ipv4Regex` / `ipv6Regex`, verbatim.
static IPV4: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$")
        .expect("ipv4Regex compiles")
});
static IPV6: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$")
        .expect("ipv6Regex compiles")
});

/// zod `isValidIP(ip)` with no version.
pub fn zod_is_valid_ip(ip: &str) -> bool {
    IPV4.is_match(ip) || IPV6.is_match(ip)
}

#[derive(Default)]
struct Issues {
    form_errors: Vec<String>,
    field_errors: IndexMap<&'static str, Vec<String>>,
}

impl Issues {
    fn field(&mut self, name: &'static str, message: String) {
        self.field_errors.entry(name).or_default().push(message);
    }

    fn is_empty(&self) -> bool {
        self.form_errors.is_empty() && self.field_errors.is_empty()
    }

    /// `error.flatten()`
    fn flatten(self) -> Value {
        let field_errors: Map<String, Value> =
            self.field_errors.into_iter().map(|(name, messages)| (name.to_string(), json!(messages))).collect();
        json!({ "formErrors": self.form_errors, "fieldErrors": field_errors })
    }
}

/// `z.string()` with optional `.min()`, `.max()` and `.ip()` checks, in that order.
struct StringRules {
    optional: bool,
    min: Option<usize>,
    max: Option<usize>,
    ip: bool,
}

fn parse_string(issues: &mut Issues, name: &'static str, value: Option<&Value>, rules: StringRules) -> Option<String> {
    let text = match value {
        None if rules.optional => return None,
        Some(Value::String(text)) => text,
        other => {
            issues.field(name, invalid_type_message("string", other));
            return None;
        }
    };

    let length = js_length(text);
    if let Some(min) = rules.min
        && length < min
    {
        issues.field(name, format!("String must contain at least {min} character(s)"));
    }
    if let Some(max) = rules.max
        && length > max
    {
        issues.field(name, format!("String must contain at most {max} character(s)"));
    }
    if rules.ip && !zod_is_valid_ip(text) {
        issues.field(name, "Invalid ip".to_string());
    }
    Some(text.clone())
}

/// `identifyPayloadSchema.safeParse(request.body)`: the payload, or the
/// `details` object (`error.flatten()`) of the 400 response.
///
/// `body` is Fastify's `request.body`: None when there was none (zod sees
/// `undefined`), a `Value::String` for a text body.
pub fn validate_identify_payload(body: Option<&Value>) -> Result<IdentifyPayload, Value> {
    let mut issues = Issues::default();
    let Some(Value::Object(object)) = body else {
        issues.form_errors.push(invalid_type_message("object", body));
        return Err(issues.flatten());
    };

    let site_id = parse_string(
        &mut issues,
        "site_id",
        object.get("site_id"),
        StringRules { optional: false, min: Some(1), max: None, ip: false },
    );
    let anonymous_id = parse_string(
        &mut issues,
        "anonymous_id",
        object.get("anonymous_id"),
        StringRules { optional: true, min: Some(1), max: Some(255), ip: false },
    );
    let user_id = parse_string(
        &mut issues,
        "user_id",
        object.get("user_id"),
        StringRules { optional: false, min: Some(1), max: Some(255), ip: false },
    );
    let ip_address = parse_string(
        &mut issues,
        "ip_address",
        object.get("ip_address"),
        StringRules { optional: true, min: None, max: None, ip: true },
    );
    let user_agent = parse_string(
        &mut issues,
        "user_agent",
        object.get("user_agent"),
        StringRules { optional: true, min: None, max: Some(512), ip: false },
    );

    let traits = match object.get("traits") {
        None => None,
        Some(Value::Object(record)) => {
            // ZodRecord rebuilds the object and never assigns `__proto__`
            let record: Map<String, Value> = record
                .iter()
                .filter(|(key, _)| key.as_str() != "__proto__")
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let size = js_json_stringify_object(&record).len();
            if size > MAX_TRAITS_SIZE {
                issues.field("traits", format!("Traits must be less than {MAX_TRAITS_SIZE} bytes (2KB)"));
            }
            Some(record)
        }
        Some(other) => {
            issues.field("traits", invalid_type_message("object", Some(other)));
            None
        }
    };

    let is_new_identify = match object.get("is_new_identify") {
        None => true,
        Some(Value::Bool(flag)) => *flag,
        Some(other) => {
            issues.field("is_new_identify", invalid_type_message("boolean", Some(other)));
            true
        }
    };

    if !issues.is_empty() {
        return Err(issues.flatten());
    }

    Ok(IdentifyPayload {
        site_id: site_id.unwrap_or_default(),
        anonymous_id,
        user_id: user_id.unwrap_or_default(),
        ip_address,
        user_agent,
        traits,
        is_new_identify,
    })
}

// ---------------------------------------------------------------------------
// JSON.stringify

/// Whether a key is an ECMAScript array index ("0" to "4294967294", canonical),
/// which objects enumerate first, in ascending order.
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_digit()) || (key.len() > 1 && key.starts_with('0')) {
        return None;
    }
    key.parse::<u64>().ok().filter(|&index| index < u64::from(u32::MAX)).map(|index| index as u32)
}

/// `JSON.stringify(object)` for a parsed JSON object: array-index keys first in
/// ascending order, then the rest in insertion order; numbers printed the way
/// JavaScript prints doubles (`1e+21`, `1` for `1.0`).
pub fn js_json_stringify_object(object: &Map<String, Value>) -> String {
    let mut output = String::new();
    write_object(object, &mut output);
    output
}

/// An object's own entries in ECMAScript property order (`Object.entries`).
fn js_entries(object: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut indices: BTreeMap<u32, (&String, &Value)> = BTreeMap::new();
    let mut named: Vec<(&String, &Value)> = Vec::new();
    for (key, value) in object {
        match array_index(key) {
            Some(index) => {
                indices.insert(index, (key, value));
            }
            None => named.push((key, value)),
        }
    }
    indices.into_values().chain(named).collect()
}

fn write_object(object: &Map<String, Value>, output: &mut String) {
    output.push('{');
    for (position, (key, value)) in js_entries(object).into_iter().enumerate() {
        if position > 0 {
            output.push(',');
        }
        write_string(key, output);
        output.push(':');
        write_value(value, output);
    }
    output.push('}');
}

fn write_value(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(flag) => output.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => match number.as_f64() {
            Some(double) if double.is_finite() => output.push_str(ryu_js::Buffer::new().format(double)),
            _ => output.push_str("null"),
        },
        Value::String(text) => write_string(text, output),
        Value::Array(items) => {
            output.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    output.push(',');
                }
                write_value(item, output);
            }
            output.push(']');
        }
        Value::Object(object) => write_object(object, output),
    }
}

/// `QuoteJSONString`
fn write_string(text: &str, output: &mut String) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if (control as u32) < 0x20 => output.push_str(&format!("\\u{:04x}", control as u32)),
            other => output.push(other),
        }
    }
    output.push('"');
}

// ---------------------------------------------------------------------------
// Postgres

/// A jsonb parameter holding already-serialised JSON text, bound the way
/// postgres.js binds `JSON.stringify(traits)` into the jsonb column.
struct JsonbText<'a>(&'a str);

impl Type<Postgres> for JsonbText<'_> {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_oid(Oid(3802))
    }
}

impl Encode<'_, Postgres> for JsonbText<'_> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        // jsonb binary format: version 1, then the text
        buf.push(1);
        buf.extend_from_slice(self.0.as_bytes());
        Ok(IsNull::No)
    }
}

/// `db.insert(userProfiles).values({ siteId, userId }).onConflictDoNothing()`
async fn insert_profile_shell(pg: &PgPool, site_id: i32, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"insert into "user_profiles" ("site_id", "user_id", "traits", "created_at", "updated_at") values ($1, $2, default, default, default) on conflict do nothing"#,
    )
    .bind(site_id)
    .bind(user_id)
    .execute(pg)
    .await
    .map(|_| ())
}

/// The alias step: create the alias (and queue the backfill) when the device has
/// none, repoint it when it names another user, leave it otherwise.
async fn upsert_alias<S: BackfillSink>(
    pg: &PgPool,
    backfill: &IdentityBackfillQueue<S>,
    site_id: i32,
    anonymous_id: &str,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    let existing: Option<String> = sqlx::query_scalar(
        r#"select "user_id" from "user_aliases" where ("user_aliases"."site_id" = $1 and "user_aliases"."anonymous_id" = $2) limit 1"#,
    )
    .bind(site_id)
    .bind(anonymous_id)
    .fetch_optional(pg)
    .await?;

    match existing {
        None => {
            sqlx::query(
                r#"insert into "user_aliases" ("id", "site_id", "anonymous_id", "user_id", "created_at") values (default, $1, $2, $3, default)"#,
            )
            .bind(site_id)
            .bind(anonymous_id)
            .bind(user_id)
            .execute(pg)
            .await?;
            tracing::info!(site_id, anonymous_id, "Created identity alias; backfill queued");
            // Fire-and-forget: backfill identified_user_id on past anonymous events
            backfill_identified_user_id(backfill, site_id, anonymous_id, user_id, Some(BACKFILL_DAYS));
        }
        Some(existing_user_id) if existing_user_id != user_id => {
            sqlx::query(
                r#"update "user_aliases" set "user_id" = $1 where ("user_aliases"."site_id" = $2 and "user_aliases"."anonymous_id" = $3)"#,
            )
            .bind(user_id)
            .bind(site_id)
            .bind(anonymous_id)
            .execute(pg)
            .await?;
            tracing::info!(site_id, anonymous_id, "Repointed identity alias to a new user");
        }
        Some(_) => tracing::debug!(site_id, anonymous_id, "Identity alias unchanged"),
    }
    Ok(())
}

/// The traits merge, with Node's exact SQL shape. Keys set to null are meant to
/// be removed, but drizzle expands the key array into a parenthesised list, so
/// `("traits" - ($4)::text[])` only succeeds when the single null key is itself a
/// Postgres array literal (`{a,b}` removes `a` and `b`), and two or more null keys
/// always fail (`cannot cast type record to text[]`). Node logs the error and
/// writes nothing; this does the same, so both backends leave the same rows
/// behind during the cutover. A known Node bug, reported rather than fixed here.
async fn upsert_traits(
    pg: &PgPool,
    site_id: i32,
    user_id: &str,
    traits: &Map<String, Value>,
) -> Result<(), sqlx::Error> {
    let filtered: Map<String, Value> =
        traits.iter().filter(|(_, value)| !value.is_null()).map(|(key, value)| (key.clone(), value.clone())).collect();
    let null_keys: Vec<&String> =
        js_entries(traits).into_iter().filter(|(_, value)| value.is_null()).map(|(key, _)| key).collect();
    let serialized = js_json_stringify_object(&filtered);

    let traits_expr = if null_keys.is_empty() {
        r#""user_profiles"."traits" || $4::jsonb"#.to_string()
    } else {
        let placeholders: Vec<String> = (0..null_keys.len()).map(|index| format!("${}", index + 4)).collect();
        format!(
            r#"("user_profiles"."traits" - ({})::text[]) || ${}::jsonb"#,
            placeholders.join(", "),
            null_keys.len() + 4
        )
    };
    let statement = format!(
        r#"insert into "user_profiles" ("site_id", "user_id", "traits", "created_at", "updated_at") values ($1, $2, $3, default, default) on conflict ("site_id","user_id") do update set "traits" = {traits_expr}, "updated_at" = now()"#
    );

    let mut query = sqlx::query(&statement).bind(site_id).bind(user_id).bind(JsonbText(&serialized));
    for key in &null_keys {
        query = query.bind(key.as_str());
    }
    query.bind(serialized.as_str()).execute(pg).await.map(|_| ())
}

// ---------------------------------------------------------------------------
// Handler

/// Shared handles `handle_identify` needs (all from AppState).
pub struct IdentifyDeps<'a, R, B: BackfillSink> {
    pub pg: &'a PgPool,
    /// Sticky identity store: `AppState::redis` in production.
    pub redis: &'a R,
    pub site_config: &'a SiteConfigCache,
    /// The request's memoised ASN resolver (`state.geo.asn_lookup()`).
    pub asn_lookup: &'a AsnLookup<'a>,
    /// `Config::better_auth_secret`
    pub secret: Option<&'a str>,
    /// The process-wide `UserIdService`.
    pub user_ids: &'a UserIdService,
    /// The process-wide backfill queue.
    pub backfill: &'a IdentityBackfillQueue<B>,
}

/// What the route passes in from the HTTP request.
pub struct IdentifyRequest<'a> {
    /// `request.body` after Fastify's content-type parsing: None when the request
    /// had no body, `Value::String` for a text/plain body, the parsed JSON otherwise.
    pub body: Option<&'a Value>,
    /// `request.headers["user-agent"]`
    pub user_agent_header: Option<&'a str>,
    /// `resolveClientIp(request, { firstPartyProxy: site.firstPartyProxy })`.
    /// Called only when the payload carries no `ip_address`, after the Site is known.
    pub resolve_client_ip: &'a (dyn Fn(&SiteConfigData) -> String + Sync),
}

fn internal_error() -> (StatusCode, Value) {
    (StatusCode::INTERNAL_SERVER_ERROR, json!({ "success": false, "error": "Failed to process identify" }))
}

/// `handleIdentify`: validate, resolve the Site and the device fingerprint, write
/// the profile shell and alias (new identifies only), merge traits, and answer
/// `200 {success:true}`; `400` with zod details, `404` for an unknown Site, `500`
/// when the fingerprint cannot be computed (a salted Site without a secret).
/// Database failures are logged and do not change the response, as in Node.
pub async fn handle_identify<R: StickyStore, B: BackfillSink>(
    deps: &IdentifyDeps<'_, R, B>,
    request: IdentifyRequest<'_>,
) -> (StatusCode, Value) {
    let payload = match validate_identify_payload(request.body) {
        Ok(payload) => payload,
        Err(details) => {
            tracing::debug!(details = %details, "Identify payload rejected");
            return (
                StatusCode::BAD_REQUEST,
                json!({ "success": false, "error": "Invalid payload", "details": details }),
            );
        }
    };

    let Some(site) = deps.site_config.get_config(&SiteRef::Text(payload.site_id.clone())).await else {
        tracing::debug!(site = %payload.site_id, "Identify for unknown site");
        return (StatusCode::NOT_FOUND, json!({ "success": false, "error": "Site not found" }));
    };
    let site_id = site.site_id;

    let anonymous_id = match &payload.anonymous_id {
        Some(client_id) => {
            deps.user_ids
                .generate_user_id_from_client_id(
                    deps.site_config,
                    deps.secret,
                    client_id,
                    site_id,
                    UserIdOptions::default(),
                )
                .await
        }
        None => {
            let ip = match &payload.ip_address {
                Some(ip) => ip.clone(),
                None => (request.resolve_client_ip)(&site),
            };
            let user_agent = payload
                .user_agent
                .as_deref()
                .filter(|user_agent| !user_agent.is_empty())
                .or(request.user_agent_header)
                .unwrap_or("");
            let user_id_deps = UserIdDeps { redis: deps.redis, salt_source: deps.site_config, secret: deps.secret };
            deps.user_ids
                .generate_user_id(&user_id_deps, deps.asn_lookup, &ip, user_agent, site_id, UserIdOptions::default())
                .await
        }
    };
    let anonymous_id = match anonymous_id {
        Ok(anonymous_id) => anonymous_id,
        Err(error) => {
            tracing::error!(error = %error, site_id, "Error handling identify");
            return internal_error();
        }
    };

    let user_id = payload.user_id.as_str();

    if payload.is_new_identify {
        // A profile row at identify time keeps the user discoverable without traits
        if let Err(error) = insert_profile_shell(deps.pg, site_id, user_id).await {
            tracing::error!(site_id, error = %error, "Error creating user profile shell");
        }

        if let Err(error) = upsert_alias(deps.pg, deps.backfill, site_id, &anonymous_id, user_id).await {
            // Unique violations from a concurrent identify land here, as in Node
            tracing::debug!(site_id, anonymous_id = %anonymous_id, error = %error, "Alias may already exist");
        }
    }

    if let Some(traits) = payload.traits.as_ref().filter(|traits| !traits.is_empty())
        && let Err(error) = upsert_traits(deps.pg, site_id, user_id, traits).await
    {
        tracing::error!(site_id, error = %error, "Error updating user profile");
    }

    tracing::debug!(site_id, is_new_identify = payload.is_new_identify, "Identify processed");
    (StatusCode::OK, json!({ "success": true }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn details(body: Value) -> Value {
        validate_identify_payload(Some(&body)).unwrap_err()
    }

    #[test]
    fn accepts_a_minimal_payload_and_defaults_is_new_identify() {
        let payload = validate_identify_payload(Some(&json!({ "site_id": "abc", "user_id": "u1" }))).unwrap();
        assert_eq!(payload.site_id, "abc");
        assert!(payload.is_new_identify);
        assert_eq!(payload.traits, None);
    }

    #[test]
    fn reports_missing_and_mistyped_fields_like_zod() {
        assert_eq!(
            details(
                json!({ "site_id": 5, "anonymous_id": "", "ip_address": "1.2.3", "traits": [], "is_new_identify": "yes" })
            ),
            json!({
                "formErrors": [],
                "fieldErrors": {
                    "site_id": ["Expected string, received number"],
                    "anonymous_id": ["String must contain at least 1 character(s)"],
                    "user_id": ["Required"],
                    "ip_address": ["Invalid ip"],
                    "traits": ["Expected object, received array"],
                    "is_new_identify": ["Expected boolean, received string"],
                }
            })
        );
    }

    #[test]
    fn rejects_non_object_bodies_at_the_form_level() {
        assert_eq!(
            validate_identify_payload(None).unwrap_err(),
            json!({ "formErrors": ["Required"], "fieldErrors": {} })
        );
        assert_eq!(
            details(json!(null)),
            json!({ "formErrors": ["Expected object, received null"], "fieldErrors": {} })
        );
        assert_eq!(
            details(json!("text")),
            json!({ "formErrors": ["Expected object, received string"], "fieldErrors": {} })
        );
    }

    #[test]
    fn counts_lengths_in_utf16_code_units() {
        // 128 astral characters are 256 UTF-16 units: over 255
        let long = "\u{1F600}".repeat(128);
        assert_eq!(
            details(json!({ "site_id": "a", "user_id": long })),
            json!({ "formErrors": [], "fieldErrors": { "user_id": ["String must contain at most 255 character(s)"] } })
        );
    }

    #[test]
    fn measures_traits_as_javascript_serialises_them() {
        let mut traits = Map::new();
        traits.insert("k".to_string(), json!("x".repeat(2048 - 8)));
        // {"k":"…"} is 8 bytes of framing: exactly the limit
        assert!(
            validate_identify_payload(Some(&json!({ "site_id": "a", "user_id": "u", "traits": traits.clone() })))
                .is_ok()
        );
        traits.insert("k".to_string(), json!("x".repeat(2048 - 7)));
        assert_eq!(
            details(json!({ "site_id": "a", "user_id": "u", "traits": traits })),
            json!({ "formErrors": [], "fieldErrors": { "traits": ["Traits must be less than 2048 bytes (2KB)"] } })
        );
    }

    #[test]
    fn stringifies_like_javascript() {
        let value: Value =
            serde_json::from_str(r#"{"b":1.0,"2":[1e21,-0,0.1,"a\u0001\"é"],"1":null,"01":true,"4294967295":{}}"#)
                .unwrap();
        let Value::Object(object) = value else { unreachable!() };
        assert_eq!(
            js_json_stringify_object(&object),
            r#"{"1":null,"2":[1e+21,0,0.1,"a\u0001\"é"],"b":1,"01":true,"4294967295":{}}"#
        );
    }

    #[test]
    fn zod_ip_accepts_what_zod_accepts() {
        for ip in ["1.2.3.4", "::1", "::", "2001:db8::1", "::ffff:1.2.3.4", "fe80::1%eth0", "1:2:3:4:5:6:7:8"] {
            assert!(zod_is_valid_ip(ip), "{ip}");
        }
        for ip in ["01.2.3.4", "1.2.3.4 ", "1:2:3:4:5:6:7:8:9", "2001:db8::1%eth0", "", "1.2.3.4\n"] {
            assert!(!zod_is_valid_ip(ip), "{ip}");
        }
    }
}
