//! GET /api/sites/:siteId/experiments/:experimentId/results, ported from
//! server/src/api/experiments/getExperimentResults.ts and the
//! `getExperimentVariantKeys` / `buildExperimentResults` helpers in utils.ts.
//!
//! Two ClickHouse queries: sessions are attributed to the variant of their first
//! `feature_flag_exposure` event, and when nothing recorded an exposure the
//! handler falls back to the `feature_flags` map every event carries. Both are
//! scoped to the same filtered-session cohort, so a filter qualifies a session
//! once rather than being re-applied to the exposure and goal rows.

use axum::{
    extract::{RawPathParams, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::{Map, Value};
use sqlx::Row;
use tracing::{debug, error, warn};

use crate::{
    analytics::{
        js::{JsValue, zod::ZodIssue},
        segments::segment_schema::validation_error_body,
        sql_string::{escape_number, escape_string},
        utils::{
            analytics_query::QuerySpec,
            get_filter_statement::FilterStatementError,
            query_validation::FiltersError,
            session_filters::build_filtered_sessions_cte,
            time_window::{TimeWindowParams, get_time_statement},
            utils::process_results,
        },
    },
    state::AppState,
};

use super::{
    experiments::{experiment_with_relations, parse_experiment_id, parse_site_id, read_chain, serialize_experiment},
    support::{admin_clickhouse, object, param, path_params, pg_int4, send_error, send_js},
};

/// The two queries `buildExperimentResultQueries` returns.
pub struct ResultQueries {
    pub exposure_query: String,
    pub assignment_query: String,
}

/// `buildExperimentResultQueries({ query, siteId, flagKey, goalCondition })`
pub fn build_experiment_result_queries(
    filters: &JsValue,
    time_statement: &str,
    filtered_sessions_cte: Option<&str>,
    site_id: f64,
    flag_key: &str,
    goal_condition: &str,
) -> ResultQueries {
    let _ = filters;
    let filtered_sessions_join =
        if filtered_sessions_cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    let filtered_sessions_prefix = filtered_sessions_cte.map(|cte| format!("{cte},")).unwrap_or_default();
    let escaped_site_id = escape_number(site_id);
    let escaped_flag_key = escape_string(flag_key);

    // A session qualifies once, independently of which event carried the filter
    // value. Goal, exposure, and assignment rows are then scoped to that cohort.
    let goal_sessions_cte = format!(
        "
      goal_sessions AS (
        SELECT
          session_id,
          max(timestamp) AS last_goal_at
        FROM events
        {filtered_sessions_join}
        WHERE site_id = {escaped_site_id}
          AND ({goal_condition})
          {time_statement}
        GROUP BY session_id
      )"
    );

    let exposure_query = format!(
        "
      WITH
        {filtered_sessions_prefix}
        exposure_sessions AS (
          SELECT
            session_id,
            argMin(JSONExtractString(toString(props), 'value'), timestamp) AS variant,
            min(timestamp) AS exposed_at,
            count() AS exposures
          FROM events
          {filtered_sessions_join}
          WHERE site_id = {escaped_site_id}
            AND type = 'custom_event'
            AND event_name = 'feature_flag_exposure'
            AND JSONExtractString(toString(props), 'key') = {escaped_flag_key}
            AND JSONExtractString(toString(props), 'value') != ''
            {time_statement}
          GROUP BY session_id
        ),
        {goal_sessions_cte}
      SELECT
        e.variant AS variant,
        uniqExact(e.session_id) AS sessions,
        sum(e.exposures) AS exposures,
        uniqExactIf(e.session_id, g.last_goal_at >= e.exposed_at) AS conversions
      FROM exposure_sessions e
      LEFT JOIN goal_sessions g ON g.session_id = e.session_id
      GROUP BY e.variant
      ORDER BY e.variant ASC
    "
    );

    // Assignment fallback follows the same one-arm-per-session rule, using the
    // first event that carried an assignment for the flag.
    let assignment_query = format!(
        "
      WITH
        {filtered_sessions_prefix}
        assignment_sessions AS (
          SELECT
            session_id,
            argMin(feature_flags[{escaped_flag_key}], timestamp) AS variant,
            min(timestamp) AS assigned_at
          FROM events
          {filtered_sessions_join}
          WHERE site_id = {escaped_site_id}
            AND feature_flags[{escaped_flag_key}] != ''
            {time_statement}
          GROUP BY session_id
        ),
        {goal_sessions_cte}
      SELECT
        a.variant AS variant,
        uniqExact(a.session_id) AS sessions,
        uniqExact(a.session_id) AS exposures,
        uniqExactIf(a.session_id, g.last_goal_at >= a.assigned_at) AS conversions
      FROM assignment_sessions a
      LEFT JOIN goal_sessions g ON g.session_id = a.session_id
      GROUP BY a.variant
      ORDER BY a.variant ASC
    "
    );

    ResultQueries { exposure_query, assignment_query }
}

/// A `TypeError` from reading a member off null or undefined.
struct TypeErr;

fn member(value: &JsValue, key: &str) -> Result<JsValue, TypeErr> {
    match value {
        JsValue::Undefined | JsValue::Null => Err(TypeErr),
        JsValue::Object(object) => Ok(object.get_or_undefined(key).clone()),
        _ => Ok(JsValue::Undefined),
    }
}

/// `===` for the values a variant key can hold.
fn strict_equals(left: &JsValue, right: &JsValue) -> bool {
    match (left, right) {
        (JsValue::Number(a), JsValue::Number(b)) => a == b,
        (JsValue::String(a), JsValue::String(b)) => a == b,
        (JsValue::Bool(a), JsValue::Bool(b)) => a == b,
        (JsValue::Null, JsValue::Null) => true,
        (JsValue::Undefined, JsValue::Undefined) => true,
        // Objects and arrays compare by identity; two reads of the same stored
        // value are distinct objects, so they never match here either
        _ => false,
    }
}

/// `getExperimentVariantKeys(flag)`: condition set variants first, then the
/// flag's own, each key kept once.
fn experiment_variant_keys(flag: &JsValue) -> Result<Vec<JsValue>, TypeErr> {
    let mut keys: Vec<JsValue> = Vec::new();
    let list = |value: JsValue| match value {
        JsValue::Array(items) => items,
        // `|| []` for null, undefined and anything else falsy; a truthy non-array
        // makes `for...of` throw, which the handler's catch turns into a 500
        _ => Vec::new(),
    };
    for condition_set in list(member(flag, "conditionSets")?) {
        for variant in list(member(&condition_set, "variants")?) {
            let key = member(&variant, "key")?;
            if !keys.iter().any(|existing| strict_equals(existing, &key)) {
                keys.push(key);
            }
        }
    }
    for variant in list(member(flag, "variants")?) {
        let key = member(&variant, "key")?;
        if !keys.iter().any(|existing| strict_equals(existing, &key)) {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// `value > 0` with JavaScript's coercion.
fn greater_than_zero(value: &JsValue) -> bool {
    let number = value.to_number();
    !number.is_nan() && number > 0.0
}

/// `left + right` where either side may still be a string from ClickHouse.
fn js_add(left: &JsValue, right: &JsValue) -> JsValue {
    match (left, right) {
        (JsValue::String(_), _) | (_, JsValue::String(_)) => {
            JsValue::String(format!("{}{}", left.to_js_string(), right.to_js_string()))
        }
        _ => JsValue::Number(left.to_number() + right.to_number()),
    }
}

/// `buildExperimentResults(variants, rows)`
fn build_experiment_results(variants: &[JsValue], rows: &[Map<String, Value>]) -> Vec<JsValue> {
    let row_variant = |row: &Map<String, Value>| JsValue::from_serde(row.get("variant").unwrap_or(&Value::Null));
    // `new Map(rows.map(...))`: a later row replaces an earlier one with the same key
    let find_row = |key: &JsValue| {
        rows.iter().rev().find(|row| strict_equals(&row_variant(row), key)).map(|row| {
            let read = |name: &str| JsValue::from_serde(row.get(name).unwrap_or(&Value::Null));
            (read("sessions"), read("exposures"), read("conversions"))
        })
    };

    let mut all_variants: Vec<JsValue> = variants.to_vec();
    for row in rows {
        let variant = row_variant(row);
        if !all_variants.iter().any(|existing| strict_equals(existing, &variant)) {
            all_variants.push(variant);
        }
    }

    // `variants.find(v => v === "control") || variants[0] || rows[0]?.variant || null`
    let control = all_variants
        .iter()
        .find(|variant| strict_equals(variant, &JsValue::String("control".into())))
        .cloned()
        .filter(JsValue::is_truthy)
        .or_else(|| all_variants.first().cloned().filter(JsValue::is_truthy))
        .or_else(|| rows.first().map(row_variant).filter(JsValue::is_truthy));
    let control_rate = control.as_ref().and_then(find_row).and_then(|(sessions, _, conversions)| {
        greater_than_zero(&sessions).then(|| conversions.to_number() / sessions.to_number())
    });

    all_variants
        .iter()
        .map(|variant| {
            let (sessions, exposures, conversions) =
                find_row(variant).unwrap_or((JsValue::Number(0.0), JsValue::Number(0.0), JsValue::Number(0.0)));
            let conversion_rate = if greater_than_zero(&sessions) {
                conversions.to_number() / sessions.to_number()
            } else {
                0.0
            };
            // `controlRate && controlRate > 0` is falsy for null, 0 and NaN alike
            let lift = match control_rate {
                Some(rate) if rate > 0.0 => JsValue::Number((conversion_rate - rate) / rate),
                _ => JsValue::Null,
            };
            object(vec![
                ("variant", variant.clone()),
                ("sessions", sessions),
                ("exposures", exposures),
                ("conversions", conversions),
                ("conversionRate", JsValue::Number(conversion_rate)),
                ("lift", lift),
                (
                    "isControl",
                    JsValue::Bool(control.as_ref().is_some_and(|control| strict_equals(variant, control))),
                ),
            ])
        })
        .collect()
}

/// A failure inside the handler's try block.
enum Failure {
    /// A `ZodError`, answered with its issues
    Zod(Vec<ZodIssue>),
    Other(String),
}

fn zod_issues(err: &FilterStatementError) -> Option<Vec<ZodIssue>> {
    match err {
        FilterStatementError::Filters(FiltersError::Schema(issues)) => Some(issues.clone()),
        _ => None,
    }
}

fn failure_from_filters(err: FilterStatementError) -> Failure {
    match zod_issues(&err) {
        Some(issues) => Failure::Zod(issues),
        None => Failure::Other(err.to_string()),
    }
}

/// `getExperimentResults`
pub async fn results(
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

    match run(&state, &request, &param(&params, "experimentId")).await {
        Ok(response) => response,
        Err(Failure::Zod(issues)) => {
            debug!("Experiment results query failed validation");
            send_js(StatusCode::BAD_REQUEST, &validation_error_body(&issues))
        }
        Err(Failure::Other(message)) => {
            error!(message, "Failed to get experiment results");
            send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get experiment results")
        }
    }
}

async fn run(
    state: &AppState,
    request: &crate::analytics::chain::SiteRequest,
    experiment_param: &str,
) -> Result<Response, Failure> {
    let site_id = match parse_site_id(&request.site_id) {
        Ok(site_id) => site_id,
        Err(response) => return Ok(response),
    };
    let experiment_id = match parse_experiment_id(experiment_param) {
        Ok(experiment_id) => experiment_id,
        Err(response) => return Ok(response),
    };
    let (Some(bound_site_id), Some(bound_experiment_id)) = (pg_int4(site_id), pg_int4(experiment_id)) else {
        return Err(Failure::Other("site or experiment id out of range for type integer".into()));
    };

    let record = experiment_with_relations(&state.pg, bound_site_id, bound_experiment_id)
        .await
        .map_err(|err| Failure::Other(err.to_string()))?;
    let Some(record) = record else {
        return Ok(send_error(StatusCode::NOT_FOUND, "Experiment not found"));
    };

    let flag = super::experiments::feature_flag_value(&record);
    let variants = experiment_variant_keys(&flag)
        .map_err(|_| Failure::Other("Cannot read properties of null".to_string()))?;

    let goal_type: Option<String> = record.try_get("goal_type").ok().flatten();
    let goal_config = match record.try_get::<Option<String>, _>("config") {
        Ok(Some(text)) => crate::analytics::js::json::parse(&text).unwrap_or(JsValue::Null),
        _ => JsValue::Null,
    };
    let goal_condition = match &goal_type {
        None => None,
        Some(goal_type) => super::goal_conditions::build_goal_condition(goal_type, &goal_config)
            .map_err(|err| Failure::Other(err.to_string()))?,
    };

    let experiment = serialize_experiment(&record);
    // `!record.primaryGoal || !goalCondition`
    let Some(goal_condition) = goal_condition.filter(|condition| !condition.is_empty()) else {
        debug!(site_id, experiment_id, "Experiment has no usable goal; answering with empty variant rows");
        return Ok(send_js(
            StatusCode::OK,
            &object(vec![(
                "data",
                object(vec![
                    ("experiment", experiment),
                    ("variants", JsValue::Array(build_experiment_results(&variants, &[]))),
                    ("totalExposureSessions", JsValue::Number(0.0)),
                    ("totalConversions", JsValue::Number(0.0)),
                    ("hasGoal", JsValue::Bool(false)),
                    ("measurement", JsValue::String("exposure".into())),
                ]),
            )]),
        ));
    };

    let window = TimeWindowParams::from_object(&request.query);
    let time_statement = get_time_statement(&window, "timestamp")
        .map_err(|_| Failure::Other("time window bound is not a valid date".into()))?;
    let filters = request.query.get_or_undefined("filters").clone();
    let filtered_sessions_cte = build_filtered_sessions_cte(&filters, site_id as i64, &time_statement, "FilteredSessions")
        .map_err(failure_from_filters)?;

    let queries = build_experiment_result_queries(
        &filters,
        &time_statement,
        filtered_sessions_cte.as_deref(),
        site_id,
        &flag.as_object().map_or(String::new(), |flag| flag.get_or_undefined("key").to_js_string()),
        &goal_condition,
    );

    let client = admin_clickhouse(state).map_err(|err| Failure::Other(err.to_string()))?;
    let mut rows = client
        .query_rows(&QuerySpec::new(&queries.exposure_query), &[])
        .await
        .map_err(|err| Failure::Other(err.message()))?;
    process_results(&mut rows);
    let mut measurement = "exposure";

    // Nothing called hygo.flag for this key, so fall back to the assignments the
    // feature_flags map carries on every event
    let has_exposures = rows.iter().any(|row| {
        let sessions = JsValue::from_serde(row.get("sessions").unwrap_or(&Value::Null));
        let number = sessions.to_number();
        !number.is_nan() && number > 0.0
    });
    if !has_exposures {
        match client.query_rows(&QuerySpec::new(&queries.assignment_query), &[]).await {
            Ok(mut assignment_rows) => {
                process_results(&mut assignment_rows);
                let has_assignments = assignment_rows.iter().any(|row| {
                    let sessions = JsValue::from_serde(row.get("sessions").unwrap_or(&Value::Null));
                    let number = sessions.to_number();
                    !number.is_nan() && number > 0.0
                });
                if has_assignments {
                    rows = assignment_rows;
                    measurement = "assignment";
                }
            }
            Err(err) => {
                warn!(error = %err, "Experiment assignment fallback query failed");
                return Err(Failure::Other(err.message()));
            }
        }
    }

    let variant_results = build_experiment_results(&variants, &rows);
    let total = |name: &str| {
        variant_results.iter().fold(JsValue::Number(0.0), |sum, variant| {
            js_add(&sum, &variant.as_object().map_or(JsValue::Undefined, |row| row.get_or_undefined(name).clone()))
        })
    };

    debug!(site_id, experiment_id, measurement, variants = variant_results.len(), "Answered experiment results");
    Ok(send_js(
        StatusCode::OK,
        &object(vec![(
            "data",
            object(vec![
                ("experiment", experiment),
                ("variants", JsValue::Array(variant_results.clone())),
                ("totalExposureSessions", total("sessions")),
                ("totalConversions", total("conversions")),
                ("hasGoal", JsValue::Bool(true)),
                ("measurement", JsValue::String(measurement.to_string())),
            ]),
        )]),
    ))
}
