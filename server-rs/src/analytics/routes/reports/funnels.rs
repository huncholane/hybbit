//! Funnels, ported from server/src/api/analytics/funnels: the saved funnel list
//! (getFunnels.ts), ad-hoc analysis (getFunnel.ts), the sessions behind a step
//! (getFunnelStepSessions.ts), and saving and deleting (createFunnel.ts,
//! deleteFunnel.ts).
//!
//! Steps come from the request body without a schema, so every handler reads them
//! with JavaScript's rules (see `conditions`) and reproduces the few places Node
//! lets an exception escape to Fastify's default error handler.

use axum::{
    body::Body,
    extract::{RawPathParams, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::{Value, json};
use sqlx::Row;
use tracing::{debug, error, info, warn};

use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::{JsObject, JsValue, json as js_json, number::{parse_int_10, string_to_number}},
        sql_string::escape,
        utils::{
            analytics_query::{QueryParam, QuerySpec},
            session_attribution::{SESSION_CHANNEL_AGG, SESSION_REFERRER_AGG},
            session_filters::build_filtered_sessions_cte,
            time_window::{TimeWindowParams, get_time_statement},
            utils::enrich_with_traits,
        },
    },
    auth::guards::Authenticated,
    state::AppState,
};

use super::{
    conditions::build_funnel_step_condition,
    support::{
        JsError, analytics_clickhouse, analytics_failure, caught, length, postgres_js_text, less_than, path_params, pg_int4, property, read_body, send_error,
        send_js, send_json, template, uncaught_exception,
    },
};

type BuildResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// `getUserHasAccessToSite(request, siteId)`: the principal's site list (cached for
/// 15 seconds per process, as in Node) contains `Number(siteId)`.
pub async fn user_has_access_to_site(state: &AppState, auth: &Authenticated, site_number: f64) -> bool {
    let sites = state.sites_access.sites_for(&state.pg, &auth.principal(), false).await;
    sites.iter().any(|site| f64::from(*site) == site_number)
}

/// `Number(siteId)` as the integral value SQL templates print it with.
fn site_integer(site_number: f64) -> Option<i64> {
    (site_number.is_finite() && site_number.fract() == 0.0).then_some(site_number as i64)
}

/// The steps array a query builder can `.map` over.
fn steps_array(steps: &JsValue) -> Result<&[JsValue], JsError> {
    match steps {
        JsValue::Array(items) => Ok(items),
        _ => Err(JsError::new("steps.map is not a function")),
    }
}

/// `buildFunnelQuery(query, siteId, steps)` (getFunnel.ts).
pub fn build_funnel_query(query: &JsObject, site_id: f64, steps: &JsValue) -> BuildResult<String> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let site = site_integer(site_id).ok_or_else(|| JsError::new("site id is not an integer"))?;
    let filtered_sessions_cte =
        build_filtered_sessions_cte(query.get_or_undefined("filters"), site, &time_statement, "FilteredSessions")?;

    let steps = steps_array(steps)?;
    let step_conditions = steps.iter().map(build_funnel_step_condition).collect::<Result<Vec<_>, _>>()?;

    let later_steps: String = step_conditions
        .iter()
        .enumerate()
        .skip(1)
        .map(|(position, condition)| {
            let previous = position.to_string();
            template(
                r#"
    , Step${current} AS (
      SELECT DISTINCT
        s${previous}.session_id,
        min(sa.timestamp) as step_time
      FROM Step${previous} s${previous}
      JOIN SessionActions sa ON s${previous}.session_id = sa.session_id
      WHERE
        sa.timestamp > s${previous}.step_time
        AND ${condition}
      GROUP BY s${previous}.session_id
    )
    "#,
                &[("current", &(position + 1).to_string()), ("previous", &previous), ("condition", condition)],
            )
        })
        .collect();

    let mut step_counts = Vec::with_capacity(steps.len());
    for (position, step) in steps.iter().enumerate() {
        let name = property(step, "name")?;
        let label = if name.is_truthy() { name } else { property(step, "value")? };
        step_counts.push(template(
            r#"
          SELECT
            ${number} as step_number,
            ${label} as step_name,
            count(DISTINCT session_id) as sessions
          FROM Step${number}
        "#,
            &[("number", &(position + 1).to_string()), ("label", &escape(&label))],
        ));
    }

    let cte_prefix = filtered_sessions_cte.as_ref().map(|cte| format!("{cte},")).unwrap_or_default();
    let session_join = if filtered_sessions_cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    Ok(template(
        r#"
    WITH
    ${cte_prefix}
    -- Get all session actions in the time period
    SessionActions AS (
      SELECT
        session_id,
        timestamp_ms AS timestamp,
        pathname,
        event_name,
        type,
        props,
        hostname,
        url_parameters
      FROM events
      ${session_join}
      WHERE
        site_id = {siteId:Int32}
        ${time_statement}
    ),
    -- Initial step (all sessions who completed step 1)
    Step1 AS (
      SELECT DISTINCT
        session_id,
        min(timestamp) as step_time
      FROM SessionActions
      WHERE ${first_condition}
      GROUP BY session_id
    )

    -- Calculate each funnel step
    ${later_steps}

    -- Calculate visitor count for each step
    , StepCounts AS (
      ${step_counts}
    )

    -- Final results with calculated conversion and dropoff rates
    SELECT
      s1.step_number,
      s1.step_name,
      s1.sessions as sessions,
      round(s1.sessions * 100.0 / first_step.sessions, 2) as conversion_rate,
      CASE
        WHEN s1.step_number = 1 THEN 0
        ELSE round((1 - (s1.sessions / prev_step.sessions)) * 100.0, 2)
      END as dropoff_rate
    FROM StepCounts s1
    CROSS JOIN (SELECT sessions FROM StepCounts WHERE step_number = 1) as first_step
    LEFT JOIN (
      SELECT step_number + 1 as next_step_number, sessions
      FROM StepCounts
      WHERE step_number < {stepNumber:Int32}
    ) as prev_step ON s1.step_number = prev_step.next_step_number
    ORDER BY s1.step_number
    "#,
        &[
            ("cte_prefix", &cte_prefix),
            ("session_join", session_join),
            ("time_statement", &time_statement),
            // `stepConditions[0]` of an empty list prints as "undefined"
            ("first_condition", step_conditions.first().map_or("undefined", String::as_str)),
            ("later_steps", &later_steps),
            ("step_counts", &step_counts.join("\nUNION ALL\n")),
        ],
    ))
}

/// `buildFunnelStepSessionsQuery(query, siteId, steps, stepNumber)`
/// (getFunnelStepSessions.ts).
pub fn build_funnel_step_sessions_query(
    query: &JsObject,
    site_id: f64,
    steps: &JsValue,
    step_number: usize,
) -> BuildResult<String> {
    let reached = query.get_or_undefined("mode").as_str() == Some("reached");
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let site = site_integer(site_id).ok_or_else(|| JsError::new("site id is not an integer"))?;
    let filtered_sessions_cte =
        build_filtered_sessions_cte(query.get_or_undefined("filters"), site, &time_statement, "FilteredSessions")?;

    let steps = match steps {
        JsValue::Array(items) => items,
        _ => return Err(JsError::new("steps.slice(...).map is not a function").into()),
    };
    // stepNumber never exceeds steps.length once steps is an array
    let steps_to_check = if reached { step_number } else { step_number.saturating_add(1) };
    let step_conditions = steps
        .iter()
        .take(steps_to_check)
        .map(build_funnel_step_condition)
        .collect::<Result<Vec<_>, _>>()?;

    let cte_prefix = filtered_sessions_cte.as_ref().map(|cte| format!("{cte},")).unwrap_or_default();
    let session_join = if filtered_sessions_cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    let mut step_ctes = vec![template(
        r#"
    ${cte_prefix}
    SessionActions AS (
      SELECT
        session_id,
        timestamp,
        pathname,
        event_name,
        type,
        props,
        hostname,
        url_parameters,
        tag
      FROM events
      ${session_join}
      WHERE
        site_id = {siteId:Int32}
        ${time_statement}
    ),
    Step1 AS (
      SELECT DISTINCT
        session_id,
        min(timestamp) as step_time
      FROM SessionActions
      WHERE ${first_condition}
      GROUP BY session_id
    )"#,
        &[
            ("cte_prefix", &cte_prefix),
            ("session_join", session_join),
            ("time_statement", &time_statement),
            ("first_condition", step_conditions.first().map_or("undefined", String::as_str)),
        ],
    )];

    for position in 1..steps_to_check {
        let previous = position.to_string();
        step_ctes.push(template(
            r#"
    Step${current} AS (
      SELECT DISTINCT
        s${previous}.session_id,
        min(sa.timestamp) as step_time
      FROM Step${previous} s${previous}
      JOIN SessionActions sa ON s${previous}.session_id = sa.session_id
      WHERE
        sa.timestamp > s${previous}.step_time
        AND ${condition}
      GROUP BY s${previous}.session_id
    )"#,
            &[
                ("current", &(position + 1).to_string()),
                ("previous", &previous),
                ("condition", step_conditions.get(position).map_or("undefined", String::as_str)),
            ],
        ));
    }

    let target_sessions = if reached {
        template(
            r#"
    TargetSessions AS (
      SELECT session_id
      FROM Step${step}
    )"#,
            &[("step", &step_number.to_string())],
        )
    } else {
        template(
            r#"
    TargetSessions AS (
      SELECT session_id
      FROM Step${step}
      WHERE session_id NOT IN (
        SELECT session_id
        FROM Step${next}
      )
    )"#,
            &[("step", &step_number.to_string()), ("next", &step_number.saturating_add(1).to_string())],
        )
    };

    Ok(template(
        r#"
    WITH
    ${step_ctes}
    ,
    ${target_sessions}
    ,
    AggregatedSessions AS (
      SELECT
        e.session_id,
        e.user_id,
        argMax(e.identified_user_id, e.timestamp) AS identified_user_id,
        argMax(e.country, e.timestamp) AS country,
        argMax(e.region, e.timestamp) AS region,
        argMax(e.city, e.timestamp) AS city,
        argMax(e.language, e.timestamp) AS language,
        argMax(e.device_type, e.timestamp) AS device_type,
        argMax(e.browser, e.timestamp) AS browser,
        argMax(e.browser_version, e.timestamp) AS browser_version,
        argMax(e.operating_system, e.timestamp) AS operating_system,
        argMax(e.operating_system_version, e.timestamp) AS operating_system_version,
        argMax(e.screen_width, e.timestamp) AS screen_width,
        argMax(e.screen_height, e.timestamp) AS screen_height,
        ${referrer_agg} AS referrer,
        ${channel_agg} AS channel,
        argMin(e.hostname, e.timestamp) AS hostname,
        argMin(e.page_title, e.timestamp) AS page_title,
        argMin(e.querystring, e.timestamp) AS querystring,
        argMin(e.url_parameters, e.timestamp)['utm_source'] AS utm_source,
        argMin(e.url_parameters, e.timestamp)['utm_medium'] AS utm_medium,
        argMin(e.url_parameters, e.timestamp)['utm_campaign'] AS utm_campaign,
        argMin(e.url_parameters, e.timestamp)['utm_term'] AS utm_term,
        argMin(e.url_parameters, e.timestamp)['utm_content'] AS utm_content,
        MAX(e.timestamp) AS session_end,
        MIN(e.timestamp) AS session_start,
        dateDiff('second', MIN(e.timestamp), MAX(e.timestamp)) AS session_duration,
        argMinIf(e.pathname, e.timestamp_ms, e.type = 'pageview') AS entry_page,
        argMaxIf(e.pathname, e.timestamp_ms, e.type = 'pageview') AS exit_page,
        countIf(e.type = 'pageview') AS pageviews,
        countIf(e.type = 'custom_event') AS events,
        countIf(e.type = 'error') AS errors,
        countIf(e.type = 'outbound') AS outbound,
        argMax(e.ip, e.timestamp) AS ip,
        argMax(e.lat, e.timestamp) AS lat,
        argMax(e.lon, e.timestamp) AS lon,
        argMax(e.tag, e.timestamp) AS tag
      FROM events e
      INNER JOIN TargetSessions ts ON e.session_id = ts.session_id
      WHERE
        e.site_id = {siteId:Int32}
        ${time_statement}
      GROUP BY
        e.session_id,
        e.user_id
      ORDER BY session_end DESC
    )
    SELECT *
    FROM AggregatedSessions
    LIMIT {limit:Int32} OFFSET {offset:Int32}
    "#,
        &[
            ("step_ctes", &step_ctes.join(",\n")),
            ("target_sessions", &target_sessions),
            ("referrer_agg", SESSION_REFERRER_AGG),
            ("channel_agg", SESSION_CHANNEL_AGG),
            ("time_statement", &time_statement),
        ],
    ))
}

/// The request's `siteId` after the chain, and the handler's `Number(siteId)`.
fn site_number(site_id: &str) -> f64 {
    string_to_number(site_id)
}

/// GET /api/sites/:siteId/funnels (`getFunnels`).
pub async fn get_funnels(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_params: RawPathParams,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Public, route_scope("funnels", "read"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let failed = |err: &dyn std::fmt::Display| {
        error!(err = %err, site_id = %request.site_id, "Error fetching funnels");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch funnels")
    };
    let Some(site_id) = pg_int4(site_number(&request.site_id)) else {
        return failed(&"site id is not a valid integer parameter");
    };
    let rows = match sqlx::query(
        "SELECT report_id, data::text AS data, created_at::text AS created_at, updated_at::text AS updated_at \
         FROM funnels WHERE site_id = $1 ORDER BY created_at",
    )
    .bind(site_id)
    .fetch_all(&state.pg)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return failed(&err),
    };

    let mut funnels = Vec::with_capacity(rows.len());
    for row in rows {
        let report_id: i32 = row.get("report_id");
        let data_text: Option<String> = row.get("data");
        let data = match data_text.as_deref().map(js_json::parse) {
            Some(Ok(value)) => value,
            Some(Err(_)) => return failed(&"stored funnel data is not JSON"),
            None => JsValue::Null,
        };
        let field = |name: &str| property(&data, name);
        let (name, steps, configuration, last_result) =
            match (field("name"), field("steps"), field("configuration"), field("lastResult")) {
                (Ok(name), Ok(steps), Ok(configuration), Ok(last_result)) => (name, steps, configuration, last_result),
                _ => return failed(&format!("Cannot read properties of null (reading 'name') for funnel {report_id}")),
            };
        // `data.lastResult?.conversionRate || null`
        let from_last_result = |name: &str| match &last_result {
            JsValue::Undefined | JsValue::Null => JsValue::Null,
            other => property(other, name).ok().filter(JsValue::is_truthy).unwrap_or(JsValue::Null),
        };
        let or = |value: JsValue, fallback: JsValue| if value.is_truthy() { value } else { fallback };
        let text_or_null = |value: Option<String>| value.map_or(JsValue::Null, JsValue::String);

        let mut funnel = JsObject::new();
        funnel.insert("id", JsValue::Number(f64::from(report_id)));
        funnel.insert("name", or(name, JsValue::from("Unnamed Funnel")));
        funnel.insert("steps", or(steps, JsValue::Array(Vec::new())));
        funnel.insert("configuration", or(configuration, JsValue::Object(JsObject::new())));
        funnel.insert("createdAt", text_or_null(row.get("created_at")));
        funnel.insert("updatedAt", text_or_null(row.get("updated_at")));
        funnel.insert("conversionRate", from_last_result("conversionRate"));
        funnel.insert("totalVisitors", from_last_result("totalVisitors"));
        funnels.push(JsValue::Object(funnel));
    }
    debug!(site_id, count = funnels.len(), "Fetched funnels");
    let mut body = JsObject::new();
    body.insert("data", JsValue::Array(funnels));
    send_js(StatusCode::OK, &JsValue::Object(body))
}

/// `const { steps } = request.body` (and the other destructured names).
fn destructure(body: &JsValue, names: &[&str]) -> Result<Vec<JsValue>, JsError> {
    match body {
        JsValue::Undefined | JsValue::Null => Err(JsError::new(format!(
            "Cannot destructure property '{}' of 'request.body' as it is {}.",
            names[0],
            if body.is_undefined() { "undefined" } else { "null" }
        ))),
        other => names.iter().map(|name| property(other, name)).collect(),
    }
}

/// `!steps || steps.length < 2`
fn too_few_steps(steps: &JsValue) -> Result<bool, JsError> {
    Ok(!steps.is_truthy() || less_than(&length(steps)?, &JsValue::Number(2.0)))
}

/// POST /api/sites/:siteId/funnels/analyze (`getFunnel`).
pub async fn analyze_funnel(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_params: RawPathParams,
    body: Body,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Public, route_scope("funnels", "read"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let steps = match destructure(&body, &["steps"]) {
        Ok(mut values) => values.remove(0),
        Err(exception) => return uncaught_exception("POST /api/sites/:siteId/funnels/analyze", &exception),
    };
    match too_few_steps(&steps) {
        Ok(true) => return send_error(StatusCode::BAD_REQUEST, "At least 2 steps are required for a funnel"),
        Ok(false) => {}
        Err(exception) => return uncaught_exception("POST /api/sites/:siteId/funnels/analyze", &exception),
    }

    let site = site_number(&request.site_id);
    let failed = |err: &(dyn std::error::Error + 'static)| {
        caught("POST /api/sites/:siteId/funnels/analyze", err, || {
            error!(err = %err, site_id = %request.site_id, "Error executing funnel query");
            send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to execute funnel analysis")
        })
    };
    let query = match build_funnel_query(&request.query, site, &steps) {
        Ok(query) => query,
        Err(err) => return failed(err.as_ref()),
    };
    let step_count = length(&steps).map(|value| value.to_number()).unwrap_or(f64::NAN);
    let spec = QuerySpec::new(query).param("siteId", site).param("stepNumber", step_count);
    let clickhouse = match analytics_clickhouse(&state) {
        Ok(client) => client,
        Err(err) => return failed(&err),
    };
    let rows = match clickhouse.run_analytics_query(&spec).await {
        Ok(rows) => rows,
        Err(err) => {
            for query in &err.queries {
                debug!(query = %query, "Failed funnel query");
            }
            return failed(&err.original);
        }
    };

    // `visitors` is the deprecated name of `sessions`, kept for API consumers
    let data: Vec<Value> = rows
        .into_iter()
        .map(|mut row| {
            let sessions = row.get("sessions").cloned();
            match sessions {
                Some(value) => {
                    row.insert("visitors".to_string(), value);
                }
                None => {
                    row.remove("visitors");
                }
            }
            Value::Object(row)
        })
        .collect();
    info!(site_id = %request.site_id, steps = data.len(), "Funnel analyzed");
    send_json(StatusCode::OK, &json!({ "data": data }))
}

/// POST /api/sites/:siteId/funnels/:stepNumber/sessions (`getFunnelStepSessions`).
pub async fn get_funnel_step_sessions(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_params: RawPathParams,
    body: Body,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Public, route_scope("funnels", "read"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    // Registered as {funnelId}: axum needs one parameter name per position
    let step_param = params.get("funnelId").cloned().unwrap_or_default();
    match funnel_step_sessions(&state, &request.site_id, &request.query, &body, &step_param).await {
        Ok(response) => response,
        Err(err) => analytics_failure("funnel step sessions", err.as_ref()),
    }
}

async fn funnel_step_sessions(
    state: &AppState,
    site_id: &str,
    query: &JsObject,
    body: &JsValue,
    step_param: &str,
) -> BuildResult<Response> {
    let steps = destructure(body, &["steps"])?.remove(0);
    let step_number = parse_int_10(step_param);
    let mode = query.get_or_undefined("mode");

    if too_few_steps(&steps)? {
        return Ok(send_error(StatusCode::BAD_REQUEST, "At least 2 steps are required for a funnel"));
    }
    let steps_length = length(&steps)?;
    if step_number.is_nan() || step_number < 1.0 || less_than(&steps_length, &JsValue::Number(step_number)) {
        return Ok(send_error(StatusCode::BAD_REQUEST, "Invalid step number"));
    }
    let mode_text = mode.as_str();
    if mode_text != Some("reached") && mode_text != Some("dropped") {
        return Ok(send_error(StatusCode::BAD_REQUEST, "Mode must be 'reached' or 'dropped'"));
    }
    // The last step has no drop-off
    if mode_text == Some("dropped") && steps_length == JsValue::Number(step_number) {
        return Ok(send_json(StatusCode::OK, &json!({ "data": [] })));
    }

    let site = site_number(site_id);
    // A step number past every array index cannot reach here (it exceeds steps.length)
    let step_index = step_number as usize;
    let sql = build_funnel_step_sessions_query(query, site, &steps, step_index)?;

    // limit: limit || 25, offset: ((page || 1) - 1) * (limit || 25)
    let limit = query.get_or_undefined("limit");
    let page = query.get_or_undefined("page");
    let limit_value = if limit.is_truthy() { limit.clone() } else { JsValue::Number(25.0) };
    let page_value = if page.is_truthy() { page.clone() } else { JsValue::Number(1.0) };
    let offset = (page_value.to_number() - 1.0) * limit_value.to_number();
    let spec = QuerySpec::new(sql)
        .param("siteId", site)
        .param("limit", QueryParam::from(&limit_value))
        .param("offset", offset);

    let rows = analytics_clickhouse(state)?.run_analytics_query(&spec).await?;
    let site_i32 = pg_int4(site).ok_or_else(|| JsError::new("site id out of range"))?;
    let rows = enrich_with_traits(&state.pg, rows, site_i32).await?;
    debug!(site_id, step = step_index, rows = rows.len(), "Funnel step sessions fetched");
    Ok(send_json(StatusCode::OK, &json!({ "data": rows })))
}

/// POST /api/sites/:siteId/funnels (`createFunnel`).
pub async fn create_funnel(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_params: RawPathParams,
    body: Body,
) -> Response {
    const ROUTE: &str = "POST /api/sites/:siteId/funnels";
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Member, route_scope("funnels", "write"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let (steps, name, report_id) = match destructure(&body, &["steps", "name", "reportId"]) {
        Ok(values) => (values[0].clone(), values[1].clone(), values[2].clone()),
        Err(exception) => return uncaught_exception(ROUTE, &exception),
    };

    match validate_funnel_body(&steps, &name) {
        Ok(Some(message)) => return send_error(StatusCode::BAD_REQUEST, message),
        Ok(None) => {}
        Err(exception) => return uncaught_exception(ROUTE, &exception),
    }

    let site = site_number(&request.site_id);
    if !user_has_access_to_site(&state, &request.auth, site).await {
        return send_error(StatusCode::FORBIDDEN, "Forbidden");
    }

    let failed = |err: &dyn std::fmt::Display| {
        error!(err = %err, site_id = %request.site_id, "Error creating funnel");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create funnel")
    };

    let mut data = JsObject::new();
    data.insert("name", name);
    data.insert("steps", steps);
    let data_text = js_json::stringify(&JsValue::Object(data)).unwrap_or_default();

    if report_id.is_truthy() {
        // postgres.js sends the value's text untyped and Postgres parses it as an integer
        let Some(report_id_text) = postgres_js_text(&report_id) else {
            return failed(&format!("reportId of type {} binds as a boolean", report_id.type_of()));
        };
        let existing = sqlx::query("SELECT report_id, site_id FROM funnels WHERE report_id = $1::text::int4 LIMIT 1")
            .bind(&report_id_text)
            .fetch_optional(&state.pg)
            .await;
        let existing = match existing {
            Ok(existing) => existing,
            Err(err) => return failed(&err),
        };
        let Some(existing) = existing else {
            return send_error(StatusCode::NOT_FOUND, "Funnel not found");
        };
        let existing_site: Option<i32> = existing.get("site_id");
        if existing_site.map(f64::from) != Some(site) {
            warn!(report_id = %report_id_text, site_id = %request.site_id, "Funnel belongs to another site");
            return send_error(StatusCode::FORBIDDEN, "Funnel does not belong to this site");
        }
        let updated_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let updated = sqlx::query(
            "UPDATE funnels SET data = $1::text::jsonb, updated_at = $2::text::timestamp \
             WHERE report_id = $3::text::int4 RETURNING report_id",
        )
        .bind(&data_text)
        .bind(&updated_at)
        .bind(&report_id_text)
        .fetch_all(&state.pg)
        .await;
        return match updated {
            Ok(rows) if rows.is_empty() => send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update funnel"),
            Ok(rows) => {
                let funnel_id: i32 = rows[0].get("report_id");
                info!(funnel_id, site_id = %request.site_id, "Funnel updated");
                send_json(StatusCode::CREATED, &json!({ "success": true, "funnelId": funnel_id }))
            }
            Err(err) => failed(&err),
        };
    }

    let Some(site_id) = pg_int4(site) else {
        return failed(&"site id is not a valid integer parameter");
    };
    let inserted = sqlx::query(
        "INSERT INTO funnels (site_id, user_id, data) VALUES ($1, $2, $3::text::jsonb) RETURNING report_id",
    )
    .bind(site_id)
    .bind(request.auth.user_id.as_deref())
    .bind(&data_text)
    .fetch_one(&state.pg)
    .await;
    match inserted {
        Ok(row) => {
            let funnel_id: i32 = row.get("report_id");
            info!(funnel_id, site_id, "Funnel created");
            send_json(StatusCode::CREATED, &json!({ "success": true, "funnelId": funnel_id }))
        }
        Err(err) => failed(&err),
    }
}

/// createFunnel's checks before the access check: `Some(message)` is a 400.
fn validate_funnel_body(steps: &JsValue, name: &JsValue) -> Result<Option<&'static str>, JsError> {
    if too_few_steps(steps)? {
        return Ok(Some("At least 2 steps are required for a funnel"));
    }
    let JsValue::Array(items) = steps else {
        return Err(JsError::new("steps.some is not a function"));
    };
    for step in items {
        let step_type = property(step, "type")?;
        let known = matches!(step_type.as_str(), Some("page" | "event"))
            || step_type.as_str().and_then(crate::analytics::utils::event_conditions::is_autocapture_target_type).is_some();
        if !known {
            return Ok(Some("Invalid step type"));
        }
    }
    for step in items {
        let step_type = property(step, "type")?;
        if matches!(step_type.as_str(), Some("page" | "event")) && !property(step, "value")?.is_truthy() {
            return Ok(Some("Page and event steps require a value"));
        }
    }
    if !name.is_truthy() {
        return Ok(Some("Funnel name is required"));
    }
    Ok(None)
}

/// DELETE /api/sites/:siteId/funnels/:funnelId (`deleteFunnel`).
pub async fn delete_funnel(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_params: RawPathParams,
    body: Body,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    // Fastify parses a DELETE body too, before any preHandler
    if let Err(response) = read_body(&headers, body).await {
        return response;
    }
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Member, route_scope("funnels", "write"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let funnel_param = params.get("funnelId").cloned().unwrap_or_default();
    delete_funnel_by_param(&state, &request.auth, &request.site_id, &funnel_param).await
}

/// deleteFunnel's body, shared with the literal `/funnels/analyze` path Fastify
/// also routes to it for DELETE.
pub async fn delete_funnel_by_param(state: &AppState, auth: &Authenticated, site_id: &str, funnel_param: &str) -> Response {
    let parsed_site_id = parse_int_10(site_id);
    let parsed_funnel_id = parse_int_10(funnel_param);
    if parsed_site_id.is_nan() || parsed_site_id <= 0.0 {
        return send_error(StatusCode::BAD_REQUEST, "Invalid site ID");
    }
    if parsed_funnel_id.is_nan() || parsed_funnel_id <= 0.0 {
        return send_error(StatusCode::BAD_REQUEST, "Invalid funnel ID");
    }

    let failed = |err: &dyn std::fmt::Display| {
        error!(err = %err, site_id, funnel = funnel_param, "Error deleting funnel");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete funnel")
    };
    let Some(funnel_id) = pg_int4(parsed_funnel_id) else {
        return failed(&"funnel id out of integer range");
    };
    let funnel = match sqlx::query("SELECT site_id FROM funnels WHERE report_id = $1 LIMIT 1")
        .bind(funnel_id)
        .fetch_optional(&state.pg)
        .await
    {
        Ok(funnel) => funnel,
        Err(err) => return failed(&err),
    };
    let Some(funnel) = funnel else {
        return send_error(StatusCode::NOT_FOUND, "Funnel not found");
    };
    let funnel_site: Option<i32> = funnel.get("site_id");
    let Some(funnel_site) = funnel_site.filter(|site| *site != 0) else {
        return send_error(StatusCode::BAD_REQUEST, "Invalid funnel: missing site ID");
    };
    if f64::from(funnel_site) != parsed_site_id {
        return send_error(StatusCode::FORBIDDEN, "Funnel does not belong to the specified site");
    }
    if !user_has_access_to_site(state, auth, parsed_site_id).await {
        return send_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    match sqlx::query("DELETE FROM funnels WHERE report_id = $1").bind(funnel_id).execute(&state.pg).await {
        Ok(_) => {
            info!(funnel_id, site_id, "Funnel deleted");
            send_json(StatusCode::OK, &json!({ "success": true }))
        }
        Err(err) => failed(&err),
    }
}

#[cfg(test)]
mod tests {
    use crate::analytics::js::json::parse;

    use super::*;

    fn query(pairs: &[(&str, &str)]) -> JsObject {
        pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
    }

    const CAMPAIGN_FILTER: &str = r#"[{"parameter":"utm_campaign","type":"equals","value":["launch"]}]"#;

    fn session_actions(sql: &str) -> String {
        let start = sql.find("SessionActions AS (").expect("SessionActions CTE") + "SessionActions AS (".len();
        let end = sql[start..].find("\n    ),").expect("end of SessionActions") + start;
        sql[start..end].to_string()
    }

    fn steps() -> JsValue {
        parse(r#"[{"type":"page","value":"/pricing"},{"type":"event","value":"signup"}]"#).unwrap()
    }

    // Ported from funnelQueries.test.ts
    #[test]
    fn funnel_queries_qualify_sessions_by_landing_campaign() {
        let base = query(&[("filters", CAMPAIGN_FILTER), ("start_date", ""), ("end_date", ""), ("time_zone", "UTC")]);
        let sql = build_funnel_query(&base, 1.0, &steps()).unwrap();
        let actions = session_actions(&sql);
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("argMin(url_parameters, timestamp)['utm_campaign'] AS utm_campaign"));
        assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'launch'"));
        assert!(actions.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(!actions.contains("url_parameters['utm_campaign'] = 'launch'"));
        assert!(actions.contains("pathname") && actions.contains("event_name"));

        let mut reached = base.clone();
        reached.insert("mode", "reached".into());
        let sql = build_funnel_step_sessions_query(&reached, 1.0, &steps(), 2).unwrap();
        let actions = session_actions(&sql);
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'launch'"));
        assert!(actions.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(!actions.contains("url_parameters['utm_campaign'] = 'launch'"));
        assert!(sql.contains("FROM Step2"));
        assert!(sql.contains("argMinIf(referrer, timestamp, referrer != '') AS referrer"));
        assert!(sql.contains("channel NOT IN ('Direct', 'Internal', '')"));
        assert!(!sql.contains("argMin(e.referrer, e.timestamp) AS referrer"));
        assert!(!sql.contains("argMin(e.channel, e.timestamp) AS channel"));

        let mut dropped = base;
        dropped.insert("mode", "dropped".into());
        let sql = build_funnel_step_sessions_query(&dropped, 1.0, &steps(), 1).unwrap();
        assert!(session_actions(&sql).contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(sql.contains("FROM Step1") && sql.contains("FROM Step2"));
    }

    // Ported from getFunnel.test.ts
    #[test]
    fn funnel_steps_order_by_millisecond_timestamps() {
        let steps = parse(r#"[{"type":"page","value":"/cart","name":"Cart"},{"type":"page","value":"/checkout","name":"Checkout"}]"#).unwrap();
        let sql = build_funnel_query(&query(&[("start_date", ""), ("end_date", ""), ("time_zone", ""), ("filters", "")]), 1.0, &steps).unwrap();
        assert!(sql.contains("timestamp_ms AS timestamp"));
        assert!(sql.contains("sa.timestamp > s1.step_time"));
    }

    #[test]
    fn create_funnel_body_checks() {
        let check = |steps: &str, name: &str| validate_funnel_body(&parse(steps).unwrap(), &parse(name).unwrap());
        assert_eq!(check("[]", r#""x""#), Ok(Some("At least 2 steps are required for a funnel")));
        assert_eq!(check("5", r#""x""#), Err(JsError::new("steps.some is not a function")));
        assert_eq!(check(r#"[{"type":"page","value":"/"},{"type":"nope"}]"#, r#""x""#), Ok(Some("Invalid step type")));
        assert_eq!(
            check(r#"[{"type":"page","value":"/"},null]"#, r#""x""#),
            Err(JsError::new("Cannot read properties of null (reading 'type')"))
        );
        assert_eq!(check(r#"[{"type":"page","value":"/"},{"type":"event"}]"#, r#""x""#), Ok(Some("Page and event steps require a value")));
        assert_eq!(check(r#"[{"type":"page","value":"/"},{"type":"copy"}]"#, r#""""#), Ok(Some("Funnel name is required")));
        assert_eq!(check(r#"[{"type":"page","value":"/"},{"type":"copy"}]"#, "1"), Ok(None));
        assert_eq!(
            destructure(&JsValue::Undefined, &["steps", "name"]).unwrap_err().0,
            "Cannot destructure property 'steps' of 'request.body' as it is undefined."
        );
    }
}
