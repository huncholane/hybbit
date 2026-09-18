//! Feature flag CRUD, ported from server/src/api/featureFlags/index.ts:
//! `getFeatureFlags`, `createFeatureFlag`, `updateFeatureFlag` and
//! `deleteFeatureFlag`. The evaluate routes live in `crate::routes::feature_flags`
//! and the body schemas in `crate::feature_flags::schemas`, which the write
//! handlers call so Node and Rust reject the same bodies with the same issues.

use axum::{
    body::Body,
    extract::{RawPathParams, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use sqlx::{Row, postgres::PgRow};
use tracing::{debug, error, info, warn};

use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::{JsObject, JsValue, json as js_json, number::parse_int_10},
        sql_string::{escape_number, escape_string},
        utils::analytics_query::QuerySpec,
    },
    feature_flags::{
        definitions::invalidate_feature_flag_definitions,
        schemas::{parse_feature_flag_body, parse_feature_flag_update},
    },
    state::AppState,
};

use super::support::{
    admin_clickhouse, object, param, path_params, pg_int4, read_body, send_error, send_error_details, send_js,
};

/// `parseSiteId`: `parseInt(raw, 10)`, positive or a 400.
fn parse_site_id(raw: &str) -> Result<f64, Response> {
    let site_id = parse_int_10(raw);
    if site_id.is_nan() || site_id <= 0.0 {
        return Err(send_error(StatusCode::BAD_REQUEST, "Invalid site ID"));
    }
    Ok(site_id)
}

/// The flag id check the write handlers run after the site id.
fn parse_flag_id(raw: &str) -> Result<f64, Response> {
    let flag_id = parse_int_10(raw);
    if flag_id.is_nan() || flag_id <= 0.0 {
        return Err(send_error(StatusCode::BAD_REQUEST, "Invalid feature flag ID"));
    }
    Ok(flag_id)
}

/// Postgres' unique-violation code, which both write handlers translate.
const UNIQUE_VIOLATION: &str = "23505";

fn is_duplicate_key(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some(UNIQUE_VIOLATION))
}

/// Every column of `feature_flags`, named so a row reads back in schema order.
const FLAG_COLUMNS: &str = r#""flag_id", "site_id", "key", "description", "enabled", "runtime", "flag_type",
       "payload"::text as "payload", "variants"::text as "variants", "rollout_percentage",
       "rules"::text as "rules", "condition_sets"::text as "condition_sets", "salt", "version",
       "created_at"::text as "created_at", "updated_at"::text as "updated_at""#;

fn json_column(row: &PgRow, name: &str) -> JsValue {
    match row.try_get::<Option<String>, _>(name) {
        Ok(Some(text)) => js_json::parse(&text).unwrap_or(JsValue::Null),
        _ => JsValue::Null,
    }
}

/// A `feature_flags` row as drizzle hands it to `JSON.stringify`.
fn flag_row(row: &PgRow) -> JsObject {
    let mut flag = JsObject::new();
    flag.insert("flagId", JsValue::Number(f64::from(row.try_get::<i32, _>("flag_id").unwrap_or_default())));
    flag.insert("siteId", JsValue::Number(f64::from(row.try_get::<i32, _>("site_id").unwrap_or_default())));
    flag.insert("key", JsValue::String(row.try_get::<String, _>("key").unwrap_or_default()));
    flag.insert(
        "description",
        row.try_get::<Option<String>, _>("description").ok().flatten().map_or(JsValue::Null, JsValue::String),
    );
    flag.insert("enabled", JsValue::Bool(row.try_get::<bool, _>("enabled").unwrap_or_default()));
    flag.insert("runtime", JsValue::String(row.try_get::<String, _>("runtime").unwrap_or_default()));
    flag.insert("flagType", JsValue::String(row.try_get::<String, _>("flag_type").unwrap_or_default()));
    flag.insert("payload", json_column(row, "payload"));
    flag.insert("variants", json_column(row, "variants"));
    flag.insert(
        "rolloutPercentage",
        JsValue::Number(f64::from(row.try_get::<i32, _>("rollout_percentage").unwrap_or_default())),
    );
    flag.insert("rules", json_column(row, "rules"));
    flag.insert("conditionSets", json_column(row, "condition_sets"));
    flag.insert("salt", JsValue::String(row.try_get::<String, _>("salt").unwrap_or_default()));
    flag.insert("version", JsValue::Number(f64::from(row.try_get::<i32, _>("version").unwrap_or_default())));
    flag.insert(
        "createdAt",
        row.try_get::<Option<String>, _>("created_at").ok().flatten().map_or(JsValue::Null, JsValue::String),
    );
    flag.insert(
        "updatedAt",
        row.try_get::<Option<String>, _>("updated_at").ok().flatten().map_or(JsValue::Null, JsValue::String),
    );
    flag
}

// ---------------------------------------------------------------------------------
// GET /api/sites/:siteId/feature-flags
// ---------------------------------------------------------------------------------

/// `getFeatureFlagStats`: per flag key, the sessions, events and exposures seen
/// for each assigned value. Any failure answers with no statistics at all.
async fn feature_flag_stats(state: &AppState, site_id: f64, keys: &[String]) -> Vec<(String, Vec<JsValue>)> {
    if keys.is_empty() {
        return Vec::new();
    }
    let escaped_keys = keys.iter().map(|key| escape_string(key)).collect::<Vec<_>>().join(", ");
    let sql = format!(
        "
        SELECT
          flag_key,
          flag_value,
          uniq(session_id) AS sessions,
          count() AS events,
          countIf(type = 'custom_event' AND event_name = 'feature_flag_exposure') AS exposures
        FROM (
          SELECT
            session_id,
            type,
            event_name,
            arrayJoin(mapKeys(feature_flags)) AS flag_key,
            feature_flags[flag_key] AS flag_value
          FROM events
          WHERE site_id = {}
            AND length(mapKeys(feature_flags)) > 0
        )
        WHERE flag_key IN ({escaped_keys})
        GROUP BY flag_key, flag_value
        ORDER BY flag_key ASC, sessions DESC
      ",
        escape_number(site_id)
    );

    let client = match admin_clickhouse(state) {
        Ok(client) => client,
        Err(err) => {
            warn!(error = %err, "Feature flag statistics unavailable; answering without them");
            return Vec::new();
        }
    };
    let mut rows = match client.query_rows(&QuerySpec::new(&sql), &[]).await {
        Ok(rows) => rows,
        Err(err) => {
            warn!(error = %err, "Feature flag statistics query failed; answering without them");
            return Vec::new();
        }
    };
    crate::analytics::utils::utils::process_results(&mut rows);

    let mut stats: Vec<(String, Vec<JsValue>)> = Vec::new();
    for row in rows {
        let key = row.get("flag_key").and_then(Value::as_str).unwrap_or_default().to_string();
        let value = JsValue::from_serde(&Value::Object(row));
        match stats.iter_mut().find(|(name, _)| *name == key) {
            Some((_, list)) => list.push(value),
            None => stats.push((key, vec![value])),
        }
    }
    stats
}

/// `stats[flag.key] ?? []` on a plain object: a key that names an
/// `Object.prototype` method reads back that method, and `JSON.stringify` then
/// drops the whole `stats` member.
fn stats_for(stats: &[(String, Vec<JsValue>)], key: &str) -> JsValue {
    if let Some((_, rows)) = stats.iter().find(|(name, _)| name == key) {
        return JsValue::Array(rows.clone());
    }
    const PROTOTYPE_METHODS: &[&str] =
        &["constructor", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString", "toString", "valueOf"];
    if PROTOTYPE_METHODS.contains(&key) {
        debug!(key, "Flag key shadows an Object.prototype method; its stats member is dropped");
        return JsValue::Undefined;
    }
    JsValue::Array(Vec::new())
}

/// `getFeatureFlags` behind `authFlagsRead`
pub async fn list(
    State(state): State<AppState>,
    raw_params: RawPathParams,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let request = match site_scoped(
        &state,
        &headers,
        &uri,
        &param(&params, "siteId"),
        SiteGuard::Member,
        route_scope("flags", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };
    let site_id = match parse_site_id(&request.site_id) {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };
    let Some(bound_site_id) = pg_int4(site_id) else {
        return super::support::uncaught_exception("feature-flags", None, "value out of range for type integer");
    };

    let rows = sqlx::query(&format!(
        r#"select {FLAG_COLUMNS} from "feature_flags" where "feature_flags"."site_id" = $1 order by "feature_flags"."key" asc"#
    ))
    .bind(bound_site_id)
    .fetch_all(&state.pg)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(err) => return super::support::uncaught_exception("feature-flags", None, &err.to_string()),
    };

    let keys: Vec<String> = rows.iter().filter_map(|row| row.try_get::<String, _>("key").ok()).collect();
    let stats = feature_flag_stats(&state, site_id, &keys).await;

    let data = rows
        .iter()
        .map(|row| {
            let mut flag = flag_row(row);
            let key = row.try_get::<String, _>("key").unwrap_or_default();
            flag.insert("stats", stats_for(&stats, &key));
            JsValue::Object(flag)
        })
        .collect();

    debug!(site_id, flags = rows.len(), "Listed feature flags");
    send_js(StatusCode::OK, &object(vec![("data", JsValue::Array(data))]))
}

// ---------------------------------------------------------------------------------
// POST /api/sites/:siteId/feature-flags
// ---------------------------------------------------------------------------------

/// The chain the three write routes share: `adminFlagsWrite`.
async fn write_chain(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    site_param: &str,
) -> Result<String, Response> {
    let request = site_scoped(
        state,
        headers,
        uri,
        site_param,
        SiteGuard::Admin,
        route_scope("flags", "write"),
        ChainSteps::TIME_ONLY,
    )
    .await?;
    Ok(request.site_id)
}

/// `createFeatureFlag`
pub async fn create(
    State(state): State<AppState>,
    raw_params: RawPathParams,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let resolved = match write_chain(&state, &headers, &uri, &param(&params, "siteId")).await {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };
    let site_id = match parse_site_id(&resolved) {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };

    let parsed = match parse_feature_flag_body(Some(&body.to_serde())) {
        Ok(parsed) => parsed,
        Err(issues) => {
            debug!("Feature flag create body failed validation");
            return send_error_details(StatusCode::BAD_REQUEST, "Validation error", issues.into_json());
        }
    };

    let failed = |message: &str| {
        error!(message, "Failed to create feature flag");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create feature flag")
    };
    let Some(bound_site_id) = pg_int4(site_id) else {
        return failed("site id out of range for type integer");
    };

    let field = |name: &str| parsed.get(name);
    let json_text = |name: &str| field(name).map(|value| serde_json::to_string(value).unwrap_or_default());
    // `description: body.description || null`
    let description = field("description").and_then(Value::as_str).filter(|text| !text.is_empty());
    let rollout = field("rolloutPercentage").and_then(Value::as_f64).unwrap_or(100.0);

    let inserted = sqlx::query(&format!(
        r#"insert into "feature_flags" ("site_id", "key", "description", "enabled", "runtime", "flag_type",
               "payload", "variants", "rollout_percentage", "rules", "condition_sets")
           values ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10::jsonb, $11::jsonb)
           returning {FLAG_COLUMNS}"#
    ))
    .bind(bound_site_id)
    .bind(field("key").and_then(Value::as_str).unwrap_or_default())
    .bind(description)
    .bind(field("enabled").and_then(Value::as_bool).unwrap_or(false))
    .bind(field("runtime").and_then(Value::as_str).unwrap_or("client"))
    .bind(field("flagType").and_then(Value::as_str).unwrap_or("boolean"))
    .bind(json_text("payload"))
    .bind(json_text("variants"))
    .bind(pg_int4(rollout))
    .bind(json_text("rules"))
    .bind(json_text("conditionSets"))
    .fetch_one(&state.pg)
    .await;

    let created = match inserted {
        Ok(row) => row,
        Err(err) if is_duplicate_key(&err) => {
            debug!("Rejected a duplicate feature flag key");
            return send_error(StatusCode::CONFLICT, "A feature flag with this key already exists");
        }
        Err(err) => return failed(&err.to_string()),
    };

    invalidate_feature_flag_definitions(&state, bound_site_id).await;
    let created_key = field("key").and_then(Value::as_str).unwrap_or_default().to_string();
    info!(site_id, flag = created_key, "Created a feature flag");
    send_js(
        StatusCode::CREATED,
        &object(vec![("success", JsValue::Bool(true)), ("data", JsValue::Object(flag_row(&created)))]),
    )
}

// ---------------------------------------------------------------------------------
// PUT /api/sites/:siteId/feature-flags/:flagId
// ---------------------------------------------------------------------------------

/// `updateFeatureFlag`
pub async fn update(
    State(state): State<AppState>,
    raw_params: RawPathParams,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let resolved = match write_chain(&state, &headers, &uri, &param(&params, "siteId")).await {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };
    let site_id = match parse_site_id(&resolved) {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };
    let flag_id = match parse_flag_id(&param(&params, "flagId")) {
        Ok(flag_id) => flag_id,
        Err(response) => return response,
    };

    let parsed = match parse_feature_flag_update(Some(&body.to_serde())) {
        Ok(parsed) => parsed,
        Err(issues) => {
            debug!("Feature flag update body failed validation");
            return send_error_details(StatusCode::BAD_REQUEST, "Validation error", issues.into_json());
        }
    };

    let failed = |message: &str| {
        error!(message, "Failed to update feature flag");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update feature flag")
    };
    let (Some(bound_site_id), Some(bound_flag_id)) = (pg_int4(site_id), pg_int4(flag_id)) else {
        return failed("site or flag id out of range for type integer");
    };

    // The version is read first; a missing row is the 404 before any write
    let version: Result<Option<i32>, sqlx::Error> = sqlx::query_scalar(
        r#"select "version" from "feature_flags"
           where "feature_flags"."site_id" = $1 and "feature_flags"."flag_id" = $2 limit 1"#,
    )
    .bind(bound_site_id)
    .bind(bound_flag_id)
    .fetch_optional(&state.pg)
    .await
    .map(Option::flatten);
    let version = match version {
        Ok(Some(version)) => version + 1,
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Feature flag not found"),
        Err(err) => return failed(&err.to_string()),
    };

    // `set()` drops undefined members, so only the sent fields are written
    let mut assignments: Vec<String> = Vec::new();
    let mut strings: Vec<Option<String>> = Vec::new();
    let mut bools: Vec<bool> = Vec::new();
    let mut ints: Vec<i32> = Vec::new();
    let mut binder = 0;
    let mut next = || {
        binder += 1;
        binder
    };

    // Ordered so the parameter list can be bound in one pass below
    let mut plan: Vec<(&str, Slot)> = Vec::new();
    let field = |name: &str| parsed.get(name);
    if field("key").is_some() {
        plan.push(("key", Slot::Text));
    }
    if parsed.get("description").is_some() {
        plan.push(("description", Slot::Text));
    }
    if field("enabled").is_some() {
        plan.push(("enabled", Slot::Bool));
    }
    if field("runtime").is_some() {
        plan.push(("runtime", Slot::Text));
    }
    if field("flagType").is_some() {
        plan.push(("flagType", Slot::Text));
    }
    if field("payload").is_some() {
        plan.push(("payload", Slot::Json));
    }
    if field("variants").is_some() {
        plan.push(("variants", Slot::Json));
    }
    if field("rolloutPercentage").is_some() {
        plan.push(("rolloutPercentage", Slot::Int));
    }
    if field("rules").is_some() {
        plan.push(("rules", Slot::Json));
    }
    if field("conditionSets").is_some() {
        plan.push(("conditionSets", Slot::Json));
    }

    for (name, slot) in &plan {
        let column = column_for(name);
        let placeholder = next();
        match slot {
            Slot::Text => {
                assignments.push(format!("\"{column}\" = ${placeholder}"));
                let value = match *name {
                    // `description: body.description || null`
                    "description" => field("description")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(str::to_string),
                    other => field(other).and_then(Value::as_str).map(str::to_string),
                };
                strings.push(value);
            }
            Slot::Bool => {
                assignments.push(format!("\"{column}\" = ${placeholder}"));
                bools.push(field(name).and_then(Value::as_bool).unwrap_or(false));
            }
            Slot::Int => {
                assignments.push(format!("\"{column}\" = ${placeholder}"));
                ints.push(field(name).and_then(Value::as_f64).and_then(pg_int4).unwrap_or(0));
            }
            Slot::Json => {
                assignments.push(format!("\"{column}\" = ${placeholder}::jsonb"));
                strings.push(field(name).map(|value| serde_json::to_string(value).unwrap_or_default()));
            }
        }
    }

    let updated_at_slot = next();
    assignments.push(format!("\"updated_at\" = ${updated_at_slot}::timestamp"));
    let version_slot = next();
    assignments.push(format!("\"version\" = ${version_slot}"));
    let site_slot = next();
    let flag_slot = next();

    let sql = format!(
        r#"update "feature_flags" set {} where "feature_flags"."site_id" = ${site_slot} and "feature_flags"."flag_id" = ${flag_slot} returning {FLAG_COLUMNS}"#,
        assignments.join(", ")
    );
    let mut query = sqlx::query(&sql);
    let mut string_index = 0;
    let mut bool_index = 0;
    let mut int_index = 0;
    for (_, slot) in &plan {
        query = match slot {
            Slot::Text | Slot::Json => {
                let value = strings[string_index].clone();
                string_index += 1;
                query.bind(value)
            }
            Slot::Bool => {
                let value = bools[bool_index];
                bool_index += 1;
                query.bind(value)
            }
            Slot::Int => {
                let value = ints[int_index];
                int_index += 1;
                query.bind(value)
            }
        };
    }
    query = query
        .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true))
        .bind(version)
        .bind(bound_site_id)
        .bind(bound_flag_id);

    let updated = match query.fetch_optional(&state.pg).await {
        Ok(Some(row)) => row,
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Feature flag not found"),
        Err(err) if is_duplicate_key(&err) => {
            return send_error(StatusCode::CONFLICT, "A feature flag with this key already exists");
        }
        Err(err) => return failed(&err.to_string()),
    };

    invalidate_feature_flag_definitions(&state, bound_site_id).await;
    info!(site_id, flag_id, version, "Updated a feature flag");
    send_js(
        StatusCode::OK,
        &object(vec![("success", JsValue::Bool(true)), ("data", JsValue::Object(flag_row(&updated)))]),
    )
}

/// How one updated member is bound.
enum Slot {
    Text,
    Bool,
    Int,
    Json,
}

fn column_for(field: &str) -> &'static str {
    match field {
        "key" => "key",
        "description" => "description",
        "enabled" => "enabled",
        "runtime" => "runtime",
        "flagType" => "flag_type",
        "payload" => "payload",
        "variants" => "variants",
        "rolloutPercentage" => "rollout_percentage",
        "rules" => "rules",
        "conditionSets" => "condition_sets",
        other => unreachable!("unknown feature flag column {other}"),
    }
}

// ---------------------------------------------------------------------------------
// DELETE /api/sites/:siteId/feature-flags/:flagId
// ---------------------------------------------------------------------------------

/// `deleteFeatureFlag`
pub async fn delete(
    State(state): State<AppState>,
    raw_params: RawPathParams,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let resolved = match write_chain(&state, &headers, &uri, &param(&params, "siteId")).await {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };
    let site_id = match parse_site_id(&resolved) {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };
    let flag_id = match parse_flag_id(&param(&params, "flagId")) {
        Ok(flag_id) => flag_id,
        Err(response) => return response,
    };
    let (Some(bound_site_id), Some(bound_flag_id)) = (pg_int4(site_id), pg_int4(flag_id)) else {
        // No catch block here, so the statement failure escapes to Fastify
        return super::support::uncaught_exception("feature-flags", None, "value out of range for type integer");
    };

    let deleted: Result<Option<i32>, sqlx::Error> = sqlx::query_scalar(
        r#"delete from "feature_flags"
           where "feature_flags"."site_id" = $1 and "feature_flags"."flag_id" = $2 returning "flag_id""#,
    )
    .bind(bound_site_id)
    .bind(bound_flag_id)
    .fetch_optional(&state.pg)
    .await;
    match deleted {
        Err(err) => super::support::uncaught_exception("feature-flags", None, &err.to_string()),
        Ok(None) => send_error(StatusCode::NOT_FOUND, "Feature flag not found"),
        Ok(Some(_)) => {
            invalidate_feature_flag_definitions(&state, bound_site_id).await;
            info!(site_id, flag_id, "Deleted a feature flag");
            send_js(StatusCode::OK, &object(vec![("success", JsValue::Bool(true))]))
        }
    }
}
