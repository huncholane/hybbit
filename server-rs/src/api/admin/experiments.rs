//! Experiment CRUD, ported from server/src/api/experiments/: `getExperiments`,
//! `createExperiment`, `updateExperiment`, `deleteExperiment` and the helpers in
//! utils.ts they share. The results endpoint lives next door in
//! `super::experiment_results`.

use axum::{
    body::Body,
    extract::{RawPathParams, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use chrono::{SecondsFormat, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};
use tracing::{debug, error, info};

use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::{JsObject, JsValue, json as js_json, number::{number_to_string, parse_int_10}},
    },
    state::AppState,
};

use super::{
    support::{
        drizzle_query_error, object, param, path_params, pg_int4, read_body, send_error, send_error_details, send_js,
    },
    zod::{parse_experiment_body, parse_experiment_update},
};

/// `parseSiteId`
pub(super) fn parse_site_id(raw: &str) -> Result<f64, Response> {
    let site_id = parse_int_10(raw);
    if site_id.is_nan() || site_id <= 0.0 {
        return Err(send_error(StatusCode::BAD_REQUEST, "Invalid site ID"));
    }
    Ok(site_id)
}

/// `parseExperimentId`
pub(super) fn parse_experiment_id(raw: &str) -> Result<f64, Response> {
    let experiment_id = parse_int_10(raw);
    if experiment_id.is_nan() || experiment_id <= 0.0 {
        return Err(send_error(StatusCode::BAD_REQUEST, "Invalid experiment ID"));
    }
    Ok(experiment_id)
}

/// `getDuplicateExperimentMessage(error)` reads `error.code === "23505"`, but
/// drizzle 0.45.2 wraps every driver failure in a `DrizzleQueryError` that carries
/// the `PostgresError` as `cause` and has no `code`. The check never matches, so a
/// second experiment for the same flag answers 500 rather than 409, in Node too.
const DUPLICATE_KEY_IS_UNREACHABLE: &str =
    "drizzle wraps the PostgresError, so error.code is undefined and the 409 branch never runs";

const EXPERIMENT_COLUMNS: &str = r#""e"."experiment_id", "e"."site_id", "e"."feature_flag_id", "e"."primary_goal_id",
       "e"."name", "e"."description", "e"."hypothesis", "e"."status", "e"."winning_variant",
       "e"."started_at"::text as "started_at", "e"."ended_at"::text as "ended_at",
       "e"."created_at"::text as "e_created_at", "e"."updated_at"::text as "e_updated_at""#;

const FLAG_COLUMNS: &str = r#""f"."flag_id", "f"."site_id" as "f_site_id", "f"."key", "f"."description" as "f_description",
       "f"."enabled", "f"."runtime", "f"."flag_type", "f"."payload"::text as "payload",
       "f"."variants"::text as "variants", "f"."rollout_percentage", "f"."rules"::text as "rules",
       "f"."condition_sets"::text as "condition_sets", "f"."salt", "f"."version",
       "f"."created_at"::text as "f_created_at", "f"."updated_at"::text as "f_updated_at""#;

const GOAL_COLUMNS: &str = r#""g"."goal_id", "g"."site_id" as "g_site_id", "g"."name" as "g_name", "g"."goal_type",
       "g"."config"::text as "config", "g"."created_at"::text as "g_created_at""#;

/// `getExperimentWithRelations`'s select, reused by the list route.
fn relations_sql(filter: &str) -> String {
    format!(
        r#"select {EXPERIMENT_COLUMNS}, {FLAG_COLUMNS}, {GOAL_COLUMNS}
           from "experiments" "e"
           inner join "feature_flags" "f" on "e"."feature_flag_id" = "f"."flag_id"
           left join "goals" "g" on "e"."primary_goal_id" = "g"."goal_id"
           {filter}"#
    )
}

fn text(row: &PgRow, name: &str) -> JsValue {
    row.try_get::<Option<String>, _>(name).ok().flatten().map_or(JsValue::Null, JsValue::String)
}

fn json_text(row: &PgRow, name: &str) -> JsValue {
    match row.try_get::<Option<String>, _>(name) {
        Ok(Some(value)) => js_json::parse(&value).unwrap_or(JsValue::Null),
        _ => JsValue::Null,
    }
}

fn int(row: &PgRow, name: &str) -> JsValue {
    row.try_get::<Option<i32>, _>(name).ok().flatten().map_or(JsValue::Null, |value| JsValue::Number(f64::from(value)))
}

/// The joined `feature_flags` row, in schema order.
pub(super) fn feature_flag_value(row: &PgRow) -> JsValue {
    object(vec![
        ("flagId", int(row, "flag_id")),
        ("siteId", int(row, "f_site_id")),
        ("key", text(row, "key")),
        ("description", text(row, "f_description")),
        ("enabled", row.try_get::<bool, _>("enabled").map_or(JsValue::Null, JsValue::Bool)),
        ("runtime", text(row, "runtime")),
        ("flagType", text(row, "flag_type")),
        ("payload", json_text(row, "payload")),
        ("variants", json_text(row, "variants")),
        ("rolloutPercentage", int(row, "rollout_percentage")),
        ("rules", json_text(row, "rules")),
        ("conditionSets", json_text(row, "condition_sets")),
        ("salt", text(row, "salt")),
        ("version", int(row, "version")),
        ("createdAt", text(row, "f_created_at")),
        ("updatedAt", text(row, "f_updated_at")),
    ])
}

/// The joined `goals` row, or null when the left join matched nothing.
fn primary_goal_value(row: &PgRow) -> JsValue {
    if row.try_get::<Option<i32>, _>("goal_id").ok().flatten().is_none() {
        return JsValue::Null;
    }
    object(vec![
        ("goalId", int(row, "goal_id")),
        ("siteId", int(row, "g_site_id")),
        ("name", text(row, "g_name")),
        ("goalType", text(row, "goal_type")),
        ("config", json_text(row, "config")),
        ("createdAt", text(row, "g_created_at")),
    ])
}

/// `serializeExperiment(record)`: the experiment's own members, then the relations.
pub(super) fn serialize_experiment(row: &PgRow) -> JsValue {
    let mut experiment = JsObject::new();
    experiment.insert("experimentId", int(row, "experiment_id"));
    experiment.insert("siteId", int(row, "site_id"));
    experiment.insert("featureFlagId", int(row, "feature_flag_id"));
    experiment.insert("primaryGoalId", int(row, "primary_goal_id"));
    experiment.insert("name", text(row, "name"));
    experiment.insert("description", text(row, "description"));
    experiment.insert("hypothesis", text(row, "hypothesis"));
    experiment.insert("status", text(row, "status"));
    experiment.insert("winningVariant", text(row, "winning_variant"));
    experiment.insert("startedAt", text(row, "started_at"));
    experiment.insert("endedAt", text(row, "ended_at"));
    experiment.insert("createdAt", text(row, "e_created_at"));
    experiment.insert("updatedAt", text(row, "e_updated_at"));
    experiment.insert("featureFlag", feature_flag_value(row));
    experiment.insert("primaryGoal", primary_goal_value(row));
    JsValue::Object(experiment)
}

/// `getExperimentWithRelations(siteId, experimentId)`
pub(super) async fn experiment_with_relations(
    pg: &PgPool,
    site_id: i32,
    experiment_id: i32,
) -> Result<Option<PgRow>, sqlx::Error> {
    sqlx::query(&relations_sql(r#"where "e"."site_id" = $1 and "e"."experiment_id" = $2"#))
        .bind(site_id)
        .bind(experiment_id)
        .fetch_optional(pg)
        .await
}

/// `authExperimentsRead`
pub(super) async fn read_chain(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    site_param: &str,
) -> Result<crate::analytics::chain::SiteRequest, Response> {
    site_scoped(state, headers, uri, site_param, SiteGuard::Member, route_scope("experiments", "read"), ChainSteps::FULL)
        .await
}

/// `adminExperimentsWrite`
async fn write_chain(state: &AppState, headers: &HeaderMap, uri: &Uri, site_param: &str) -> Result<String, Response> {
    let request = site_scoped(
        state,
        headers,
        uri,
        site_param,
        SiteGuard::Admin,
        route_scope("experiments", "write"),
        ChainSteps::TIME_ONLY,
    )
    .await?;
    Ok(request.site_id)
}

// ---------------------------------------------------------------------------------
// GET /api/sites/:siteId/experiments
// ---------------------------------------------------------------------------------

/// `getExperiments`
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
    let request = match read_chain(&state, &headers, &uri, &param(&params, "siteId")).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let site_id = match parse_site_id(&request.site_id) {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };
    let Some(bound_site_id) = pg_int4(site_id) else {
        return super::support::uncaught_exception("experiments", None, "value out of range for type integer");
    };

    let rows = sqlx::query(&relations_sql(r#"where "e"."site_id" = $1 order by "e"."updated_at" desc"#))
        .bind(bound_site_id)
        .fetch_all(&state.pg)
        .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(err) => return super::support::uncaught_exception("experiments", None, &err.to_string()),
    };

    debug!(site_id, experiments = rows.len(), "Listed experiments");
    send_js(
        StatusCode::OK,
        &object(vec![("data", JsValue::Array(rows.iter().map(serialize_experiment).collect()))]),
    )
}

// ---------------------------------------------------------------------------------
// The reference checks both write routes run
// ---------------------------------------------------------------------------------

/// `validateExperimentReferences`: the flag must exist on this Site and be
/// multivariate, and a named goal must exist on it too.
async fn validate_references(
    pg: &PgPool,
    site_id: i32,
    feature_flag_id: f64,
    primary_goal_id: Option<f64>,
) -> Result<Option<&'static str>, sqlx::Error> {
    let flag_type: Option<String> = match pg_int4(feature_flag_id) {
        Some(flag_id) => sqlx::query_scalar(
            r#"select "flag_type" from "feature_flags"
               where "feature_flags"."site_id" = $1 and "feature_flags"."flag_id" = $2 limit 1"#,
        )
        .bind(site_id)
        .bind(flag_id)
        .fetch_optional(pg)
        .await?,
        // An id Postgres cannot bind makes the lookup fail in Node
        None => return Err(sqlx::Error::Protocol("feature flag id out of range for type integer".into())),
    };
    // `body.primaryGoalId ? ... : Promise.resolve(undefined)` is a truthiness test,
    // so null and 0 skip the lookup entirely
    let goal_id = primary_goal_id.filter(|id| *id != 0.0 && !id.is_nan());
    let goal: Option<i32> = match goal_id {
        None => None,
        Some(id) => match pg_int4(id) {
            Some(bound) => sqlx::query_scalar(
                r#"select "goal_id" from "goals" where "goals"."site_id" = $1 and "goals"."goal_id" = $2 limit 1"#,
            )
            .bind(site_id)
            .bind(bound)
            .fetch_optional(pg)
            .await?,
            None => return Err(sqlx::Error::Protocol("goal id out of range for type integer".into())),
        },
    };

    if flag_type.is_none() {
        return Ok(Some("Feature flag not found"));
    }
    if flag_type.as_deref() != Some("multivariate") {
        return Ok(Some("Experiments require a multivariate feature flag"));
    }
    if goal_id.is_some() && goal.is_none() {
        return Ok(Some("Goal not found"));
    }
    Ok(None)
}

/// `timestampsForStatus(status, existing)`
fn timestamps_for_status(status: &str, existing_started: bool, existing_ended: bool) -> (Option<String>, Option<String>) {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    (
        (status == "running" && !existing_started).then(|| now.clone()),
        (status == "completed" && !existing_ended).then_some(now),
    )
}

// ---------------------------------------------------------------------------------
// POST /api/sites/:siteId/experiments
// ---------------------------------------------------------------------------------

/// `createExperiment`
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

    let parsed = match parse_experiment_body(&body) {
        Ok(parsed) => parsed,
        Err(issues) => {
            debug!("Experiment create body failed validation");
            return send_error_details(StatusCode::BAD_REQUEST, "Validation error", issues.into_json());
        }
    };

    let failed = |message: &str| {
        error!(message, "Failed to create experiment");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create experiment")
    };
    let Some(bound_site_id) = pg_int4(site_id) else {
        return failed("site id out of range for type integer");
    };

    let feature_flag_id = parsed.get_or_undefined("featureFlagId").to_number();
    let primary_goal_id = match parsed.get_or_undefined("primaryGoalId") {
        JsValue::Number(number) => Some(*number),
        _ => None,
    };
    match validate_references(&state.pg, bound_site_id, feature_flag_id, primary_goal_id).await {
        Err(err) => return failed(&err.to_string()),
        Ok(Some(message)) => return send_error(StatusCode::BAD_REQUEST, message),
        Ok(None) => {}
    }

    let status = parsed.get_or_undefined("status").to_js_string();
    let (started_at, ended_at) = timestamps_for_status(&status, false, false);
    // `body.description || null` and friends
    let truthy_text = |name: &str| {
        let value = parsed.get_or_undefined(name);
        value.is_truthy().then(|| value.to_js_string())
    };

    let created: Result<i32, sqlx::Error> = sqlx::query_scalar(
        r#"insert into "experiments" ("site_id", "feature_flag_id", "primary_goal_id", "name", "description",
               "hypothesis", "status", "winning_variant", "started_at", "ended_at")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamp, $10::timestamp)
           returning "experiment_id""#,
    )
    .bind(bound_site_id)
    .bind(pg_int4(feature_flag_id))
    .bind(primary_goal_id.and_then(pg_int4))
    .bind(parsed.get_or_undefined("name").to_js_string())
    .bind(truthy_text("description"))
    .bind(truthy_text("hypothesis"))
    .bind(&status)
    .bind(truthy_text("winningVariant"))
    .bind(started_at)
    .bind(ended_at)
    .fetch_one(&state.pg)
    .await;

    let experiment_id = match created {
        Ok(id) => id,
        Err(err) => {
            debug!(reason = DUPLICATE_KEY_IS_UNREACHABLE, "Experiment insert failed");
            return failed(&err.to_string());
        }
    };

    let record = match experiment_with_relations(&state.pg, bound_site_id, experiment_id).await {
        Ok(record) => record,
        Err(err) => return failed(&err.to_string()),
    };
    info!(site_id, experiment_id, "Created an experiment");
    // `record ? serializeExperiment(record) : created`, `created` being the id alone
    let data = match &record {
        Some(row) => serialize_experiment(row),
        None => object(vec![("experimentId", JsValue::Number(f64::from(experiment_id)))]),
    };
    send_js(StatusCode::CREATED, &object(vec![("success", JsValue::Bool(true)), ("data", data)]))
}

// ---------------------------------------------------------------------------------
// PUT /api/sites/:siteId/experiments/:experimentId
// ---------------------------------------------------------------------------------

/// `updateExperiment`
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
    let experiment_id = match parse_experiment_id(&param(&params, "experimentId")) {
        Ok(experiment_id) => experiment_id,
        Err(response) => return response,
    };

    let failed = |message: &str| {
        error!(message, "Failed to update experiment");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update experiment")
    };
    let (Some(bound_site_id), Some(bound_experiment_id)) = (pg_int4(site_id), pg_int4(experiment_id)) else {
        return failed("site or experiment id out of range for type integer");
    };

    // The existence check runs before the body is validated
    let existing = sqlx::query(
        r#"select "feature_flag_id", "primary_goal_id", "started_at"::text as "started_at",
                  "ended_at"::text as "ended_at" from "experiments"
           where "experiments"."site_id" = $1 and "experiments"."experiment_id" = $2 limit 1"#,
    )
    .bind(bound_site_id)
    .bind(bound_experiment_id)
    .fetch_optional(&state.pg)
    .await;
    let existing = match existing {
        Ok(Some(row)) => row,
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Experiment not found"),
        Err(err) => return failed(&err.to_string()),
    };

    let parsed = match parse_experiment_update(&body) {
        Ok(parsed) => parsed,
        Err(issues) => {
            debug!("Experiment update body failed validation");
            return send_error_details(StatusCode::BAD_REQUEST, "Validation error", issues.into_json());
        }
    };

    let existing_flag_id: i32 = existing.try_get("feature_flag_id").unwrap_or_default();
    let existing_goal_id: Option<i32> = existing.try_get("primary_goal_id").unwrap_or_default();
    let existing_started: Option<String> = existing.try_get("started_at").unwrap_or_default();
    let existing_ended: Option<String> = existing.try_get("ended_at").unwrap_or_default();

    let sent = |name: &str| parsed.contains_key(name);
    if sent("featureFlagId") || sent("primaryGoalId") {
        let feature_flag_id = match parsed.get("featureFlagId") {
            Some(JsValue::Number(number)) => *number,
            _ => f64::from(existing_flag_id),
        };
        let primary_goal_id = match parsed.get("primaryGoalId") {
            Some(JsValue::Number(number)) => Some(*number),
            Some(JsValue::Null) => None,
            _ => existing_goal_id.map(f64::from),
        };
        match validate_references(&state.pg, bound_site_id, feature_flag_id, primary_goal_id).await {
            Err(err) => return failed(&err.to_string()),
            Ok(Some(message)) => return send_error(StatusCode::BAD_REQUEST, message),
            Ok(None) => {}
        }
    }

    let mut assignments: Vec<String> = Vec::new();
    let mut texts: Vec<Option<String>> = Vec::new();
    let mut ints: Vec<Option<i32>> = Vec::new();
    let mut slot = 0;
    let mut placeholder = || {
        slot += 1;
        slot
    };

    let mut text_plan: Vec<&str> = Vec::new();
    let mut int_plan: Vec<&str> = Vec::new();
    // Column order follows `{...body}` with the overrides applied on top
    for (field, column) in
        [("name", "name"), ("description", "description"), ("hypothesis", "hypothesis"), ("status", "status"), ("winningVariant", "winning_variant")]
    {
        if sent(field) {
            assignments.push(format!("\"{column}\" = ${}", placeholder()));
            let value = parsed.get_or_undefined(field);
            // `body.x || null` for the nullable text members; `name` is required text
            let stored = if field == "name" {
                Some(value.to_js_string())
            } else {
                value.is_truthy().then(|| value.to_js_string())
            };
            texts.push(stored);
            text_plan.push(field);
        }
    }
    for (field, column) in [("featureFlagId", "feature_flag_id"), ("primaryGoalId", "primary_goal_id")] {
        if sent(field) {
            assignments.push(format!("\"{column}\" = ${}", placeholder()));
            ints.push(match parsed.get_or_undefined(field) {
                JsValue::Number(number) => pg_int4(*number),
                _ => None,
            });
            int_plan.push(field);
        }
    }

    let mut timestamps: Vec<Option<String>> = Vec::new();
    if sent("status") {
        let status = parsed.get_or_undefined("status").to_js_string();
        let (started_at, ended_at) =
            timestamps_for_status(&status, existing_started.is_some(), existing_ended.is_some());
        if let Some(started_at) = started_at {
            assignments.push(format!("\"started_at\" = ${}::timestamp", placeholder()));
            timestamps.push(Some(started_at));
        }
        if let Some(ended_at) = ended_at {
            assignments.push(format!("\"ended_at\" = ${}::timestamp", placeholder()));
            timestamps.push(Some(ended_at));
        }
    }
    let updated_at_slot = placeholder();
    assignments.push(format!("\"updated_at\" = ${updated_at_slot}::timestamp"));
    let site_slot = placeholder();
    let experiment_slot = placeholder();

    let sql = format!(
        r#"update "experiments" set {} where "experiments"."site_id" = ${site_slot} and "experiments"."experiment_id" = ${experiment_slot} returning "experiment_id""#,
        assignments.join(", ")
    );
    let mut query = sqlx::query_scalar::<_, i32>(&sql);
    for value in &texts {
        query = query.bind(value.clone());
    }
    for value in &ints {
        query = query.bind(*value);
    }
    for value in &timestamps {
        query = query.bind(value.clone());
    }
    query = query
        .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true))
        .bind(bound_site_id)
        .bind(bound_experiment_id);

    let updated = match query.fetch_optional(&state.pg).await {
        Ok(Some(id)) => id,
        // `updated.experimentId` on an undefined row throws, and the catch answers
        Ok(None) => return failed("the experiment disappeared between the read and the write"),
        Err(err) => {
            debug!(reason = DUPLICATE_KEY_IS_UNREACHABLE, "Experiment update failed");
            return failed(&err.to_string());
        }
    };

    let record = match experiment_with_relations(&state.pg, bound_site_id, updated).await {
        Ok(record) => record,
        Err(err) => return failed(&err.to_string()),
    };
    info!(site_id, experiment_id, "Updated an experiment");
    let data = match &record {
        Some(row) => serialize_experiment(row),
        None => object(vec![("experimentId", JsValue::Number(f64::from(updated)))]),
    };
    send_js(StatusCode::OK, &object(vec![("success", JsValue::Bool(true)), ("data", data)]))
}

// ---------------------------------------------------------------------------------
// DELETE /api/sites/:siteId/experiments/:experimentId
// ---------------------------------------------------------------------------------

/// The statement drizzle renders for the delete, which its error message quotes.
const DELETE_EXPERIMENT_SQL: &str = concat!(
    r#"delete from "experiments" where ("experiments"."site_id" = $1 and "#,
    r#""experiments"."experiment_id" = $2) returning "experiment_id""#
);

/// `deleteExperiment`
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
    let experiment_id = match parse_experiment_id(&param(&params, "experimentId")) {
        Ok(experiment_id) => experiment_id,
        Err(response) => return response,
    };
    let (Some(bound_site_id), Some(bound_experiment_id)) = (pg_int4(site_id), pg_int4(experiment_id)) else {
        // No catch block here, so drizzle's wrapper escapes to Fastify verbatim
        return super::support::uncaught_exception(
            "experiments",
            None,
            &drizzle_query_error(
                DELETE_EXPERIMENT_SQL,
                &[number_to_string(site_id), number_to_string(experiment_id)],
            ),
        );
    };

    let deleted: Result<Option<i32>, sqlx::Error> = sqlx::query_scalar(
        r#"delete from "experiments"
           where "experiments"."site_id" = $1 and "experiments"."experiment_id" = $2 returning "experiment_id""#,
    )
    .bind(bound_site_id)
    .bind(bound_experiment_id)
    .fetch_optional(&state.pg)
    .await;
    match deleted {
        Err(err) => super::support::uncaught_exception("experiments", None, &err.to_string()),
        Ok(None) => send_error(StatusCode::NOT_FOUND, "Experiment not found"),
        Ok(Some(_)) => {
            info!(site_id, experiment_id, "Deleted an experiment");
            send_js(StatusCode::OK, &object(vec![("success", JsValue::Bool(true))]))
        }
    }
}
