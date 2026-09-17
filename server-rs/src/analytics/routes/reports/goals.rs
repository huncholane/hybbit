//! Goals, ported from server/src/api/analytics/goals: the paginated list with
//! conversion counts (getGoals.ts), conversions over time (getGoalTimeSeries.ts),
//! the sessions that converted (getGoalSessions.ts), and create, update and delete
//! with `goalBodySchema` (goalSchema.ts).

use axum::{
    body::Body,
    extract::{RawPathParams, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::json;
use sqlx::{Row, postgres::PgRow};
use tracing::{debug, error, info, warn};

use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::{
            JsObject, JsValue, json as js_json,
            number::{parse_int_10, string_to_number},
            string::utf16_len,
            zod::{self, Parsed, Path, PathSegment, Status, ZodIssue},
        },
        segments::segment_schema::validation_error_body,
        sql_string::escape,
        types::TimeBucket,
        utils::{
            analytics_query::QuerySpec,
            event_conditions::AutocaptureTargetType,
            session_filters::build_filtered_sessions_cte,
            time_window::{TimeWindowParams, get_time_statement, time_bucket_fn},
        },
    },
    auth::guards::Authenticated,
    state::AppState,
};

use super::{
    conditions::build_goal_condition,
    funnels::user_has_access_to_site,
    support::{
        JsError, ZOD_ERROR_LOG_EXCEPTION, analytics_clickhouse, analytics_failure, object_prototype_text, path_params, pg_int4, pg_int8, read_body, send_error,
        send_js, send_json, template, uncaught_exception,
    },
};

type BuildResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// A `goals` row as drizzle's `select()` returns it.
#[derive(Clone, Debug, PartialEq)]
pub struct GoalRow {
    pub goal_id: i32,
    pub site_id: i32,
    pub name: Option<String>,
    pub goal_type: String,
    /// `config`, parsed from jsonb the way postgres.js does (`JSON.parse`)
    pub config: JsValue,
    /// `created_at` as Postgres prints it (drizzle's string mode)
    pub created_at: Option<String>,
}

impl GoalRow {
    const COLUMNS: &'static str = "goal_id, site_id, name, goal_type, config::text AS config, created_at::text AS created_at";

    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let config_text: String = row.try_get("config")?;
        let config = js_json::parse(&config_text).map_err(|err| sqlx::Error::Decode(Box::new(JsError::new(format!("{err:?}")))))?;
        Ok(Self {
            goal_id: row.try_get("goal_id")?,
            site_id: row.try_get("site_id")?,
            name: row.try_get("name")?,
            goal_type: row.try_get("goal_type")?,
            config,
            created_at: row.try_get("created_at")?,
        })
    }

    /// `{ ...goal }`, keys in schema order.
    fn to_js(&self) -> JsObject {
        let mut object = JsObject::new();
        object.insert("goalId", JsValue::Number(f64::from(self.goal_id)));
        object.insert("siteId", JsValue::Number(f64::from(self.site_id)));
        object.insert("name", self.name.clone().map_or(JsValue::Null, JsValue::String));
        object.insert("goalType", JsValue::String(self.goal_type.clone()));
        object.insert("config", self.config.clone());
        object.insert("createdAt", self.created_at.clone().map_or(JsValue::Null, JsValue::String));
        object
    }

    fn condition(&self) -> Result<Option<String>, JsError> {
        build_goal_condition(&self.goal_type, &self.config)
    }
}

// ---------------------------------------------------------------------------
// goalBodySchema
// ---------------------------------------------------------------------------

/// `GOAL_TYPES`.
const GOAL_TYPES: [&str; 6] = ["path", "event", "outbound", "button_click", "form_submit", "copy"];

/// A body that passed `goalBodySchema`.
#[derive(Clone, Debug, PartialEq)]
pub struct GoalBody {
    pub name: Option<String>,
    pub goal_type: String,
    /// The parsed config: known keys only, in schema order
    pub config: JsObject,
}

fn key_path(path: &Path, name: &str) -> Path {
    zod::key(path, name)
}

/// `z.string().optional()` (with `.max(512)` for `valuePattern`).
fn optional_string(value: &JsValue, path: &Path, max: Option<usize>, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    match value {
        JsValue::Undefined => Some((Status::Valid, JsValue::Undefined)),
        JsValue::String(text) => {
            if let Some(maximum) = max
                && utf16_len(text) > maximum
            {
                issues.push(zod::too_big(path, zod::SizedKind::String, maximum, None));
                return Some((Status::Dirty, value.clone()));
            }
            Some((Status::Valid, value.clone()))
        }
        other => {
            issues.push(zod::invalid_type(path, "string", other));
            None
        }
    }
}

/// `z.union([z.string(), z.number(), z.boolean()])`: each option either accepts the
/// value or aborts with a type issue, so the union is valid or `invalid_union`.
fn string_number_boolean(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    match value {
        JsValue::String(_) | JsValue::Bool(_) => Some((Status::Valid, value.clone())),
        JsValue::Number(number) if !number.is_nan() => Some((Status::Valid, value.clone())),
        other => {
            let union_errors = ["string", "number", "boolean"]
                .into_iter()
                .map(|expected| vec![zod::invalid_type(path, expected, other)])
                .collect();
            issues.push(zod::invalid_union(path, union_errors));
            None
        }
    }
}

/// Folds field results the way `ParseStatus.mergeObjectSync` does.
struct ObjectParse {
    status: Status,
    aborted: bool,
    output: JsObject,
}

impl ObjectParse {
    fn new() -> Self {
        Self { status: Status::Valid, aborted: false, output: JsObject::new() }
    }

    fn field(&mut self, key: &str, parsed: Parsed<JsValue>) {
        match parsed {
            None => self.aborted = true,
            Some((status, value)) => {
                self.status = self.status.merge(status);
                if !value.is_undefined() {
                    self.output.insert(key, value);
                }
            }
        }
    }

    fn finish(self) -> Parsed<JsValue> {
        if self.aborted { None } else { Some((self.status, JsValue::Object(self.output))) }
    }
}

/// `z.object({ key: z.string(), value: union })`.
fn property_filter(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    let JsValue::Object(object) = value else {
        issues.push(zod::invalid_type(path, "object", value));
        return None;
    };
    let mut parse = ObjectParse::new();
    let key = zod::string(object.get_or_undefined("key"), &key_path(path, "key"), issues).map(|(status, text)| (status, JsValue::String(text)));
    parse.field("key", key);
    parse.field("value", string_number_boolean(object.get_or_undefined("value"), &key_path(path, "value"), issues));
    parse.finish()
}

/// The `config` object schema.
fn goal_config(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<JsValue> {
    let JsValue::Object(object) = value else {
        issues.push(zod::invalid_type(path, "object", value));
        return None;
    };
    let mut parse = ObjectParse::new();
    for name in ["pathPattern", "eventName"] {
        parse.field(name, optional_string(object.get_or_undefined(name), &key_path(path, name), None, issues));
    }
    parse.field("valuePattern", optional_string(object.get_or_undefined("valuePattern"), &key_path(path, "valuePattern"), Some(512), issues));
    parse.field(
        "eventPropertyKey",
        optional_string(object.get_or_undefined("eventPropertyKey"), &key_path(path, "eventPropertyKey"), None, issues),
    );
    let property_value = object.get_or_undefined("eventPropertyValue");
    parse.field(
        "eventPropertyValue",
        if property_value.is_undefined() {
            Some((Status::Valid, JsValue::Undefined))
        } else {
            string_number_boolean(property_value, &key_path(path, "eventPropertyValue"), issues)
        },
    );
    let filters_path = key_path(path, "propertyFilters");
    let filters = match object.get_or_undefined("propertyFilters") {
        JsValue::Undefined => Some((Status::Valid, JsValue::Undefined)),
        JsValue::Array(items) => {
            let mut status = Status::Valid;
            let mut aborted = false;
            let mut output = Vec::with_capacity(items.len());
            for (position, item) in items.iter().enumerate() {
                match property_filter(item, &zod::child(&filters_path, PathSegment::Index(position)), issues) {
                    None => aborted = true,
                    Some((item_status, parsed)) => {
                        status = status.merge(item_status);
                        output.push(parsed);
                    }
                }
            }
            if aborted { None } else { Some((status, JsValue::Array(output))) }
        }
        other => {
            issues.push(zod::invalid_type(&filters_path, "array", other));
            None
        }
    };
    parse.field("propertyFilters", filters);
    parse.finish()
}

/// `goalBodySchema.parse(body)`: the object schema, then both `.refine` checks
/// (which run whenever the object did not abort).
pub fn parse_goal_body(body: &JsValue) -> Result<GoalBody, Vec<ZodIssue>> {
    let root: Path = Vec::new();
    let JsValue::Object(object) = body else {
        return Err(vec![zod::invalid_type(&root, "object", body)]);
    };
    let mut issues = Vec::new();
    let mut parse = ObjectParse::new();
    parse.field("name", optional_string(object.get_or_undefined("name"), &key_path(&root, "name"), None, &mut issues));
    let goal_type = zod::enumeration(object.get_or_undefined("goalType"), &GOAL_TYPES, &key_path(&root, "goalType"), &mut issues)
        .map(|(status, text)| (status, JsValue::String(text)));
    parse.field("goalType", goal_type);
    parse.field("config", goal_config(object.get_or_undefined("config"), &key_path(&root, "config"), &mut issues));

    let Some((status, JsValue::Object(parsed))) = parse.finish() else {
        return Err(issues);
    };
    let goal_type = parsed.get("goalType").and_then(JsValue::as_str).unwrap_or_default().to_string();
    let config = match parsed.get("config") {
        Some(JsValue::Object(config)) => config.clone(),
        _ => JsObject::new(),
    };
    let config_field = |name: &str| config.get_or_undefined(name).clone();

    let matches_type = match goal_type.as_str() {
        "path" => config_field("pathPattern").is_truthy(),
        "event" => config_field("eventName").is_truthy(),
        // An empty valuePattern matches any event of the autocapture type
        _ => true,
    };
    let mut status = status;
    if !matches_type {
        issues.push(zod::custom(&vec![PathSegment::Key("config".into())], "Configuration must match goal type"));
        status = Status::Dirty;
    }
    // Legacy property matching needs both fields or neither
    let key_given = config_field("eventPropertyKey").is_truthy();
    let value_given = !config_field("eventPropertyValue").is_undefined();
    let legacy_pair_ok = goal_type != "event" || key_given == value_given;
    if !legacy_pair_ok {
        issues.push(zod::custom(
            &vec![PathSegment::Key("config".into())],
            "Both eventPropertyKey and eventPropertyValue must be provided together or omitted together",
        ));
        status = Status::Dirty;
    }
    if status == Status::Dirty || !issues.is_empty() {
        return Err(issues);
    }
    Ok(GoalBody { name: parsed.get("name").and_then(JsValue::as_str).map(str::to_string), goal_type, config })
}

// ---------------------------------------------------------------------------
// Query builders
// ---------------------------------------------------------------------------

fn filtered_sessions(query: &JsObject, site_id: f64) -> BuildResult<(String, Option<String>)> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let site = (site_id.is_finite() && site_id.fract() == 0.0)
        .then_some(site_id as i64)
        .ok_or_else(|| JsError::new("site id is not an integer"))?;
    let cte = build_filtered_sessions_cte(query.get_or_undefined("filters"), site, &time_statement, "FilteredSessions")?;
    Ok((time_statement, cte))
}

/// `buildGoalsTotalSessionsQuery(query, siteId)`.
pub fn build_goals_total_sessions_query(query: &JsObject, site_id: f64) -> BuildResult<String> {
    let (time_statement, cte) = filtered_sessions(query, site_id)?;
    if let Some(cte) = cte {
        return Ok(template(
            r#"
      WITH ${cte}
      SELECT COUNT(*) AS total_sessions
      FROM FilteredSessions
    "#,
            &[("cte", &cte)],
        ));
    }
    Ok(template(
        r#"
      SELECT COUNT(DISTINCT session_id) AS total_sessions
      FROM events
      WHERE site_id = ${site}
      ${time_statement}
    "#,
        &[("site", &escape(&JsValue::Number(site_id))), ("time_statement", &time_statement)],
    ))
}

/// `buildGoalsConversionsQuery(query, siteId, goals)`: `None` when no goal yields a
/// condition.
pub fn build_goals_conversions_query(query: &JsObject, site_id: f64, goals: &[GoalRow]) -> BuildResult<Option<String>> {
    let (time_statement, cte) = filtered_sessions(query, site_id)?;
    let mut clauses = Vec::new();
    for goal in goals {
        let Some(condition) = goal.condition()? else { continue };
        clauses.push(template(
            r#"
        COUNT(DISTINCT IF(
          ${condition},
          session_id,
          NULL
        )) AS goal_${goal_id}_conversions
      "#,
            &[("condition", &condition), ("goal_id", &goal.goal_id.to_string())],
        ));
    }
    if clauses.is_empty() {
        return Ok(None);
    }
    Ok(Some(template(
        r#"
      ${with_cte}
      SELECT
        ${clauses}
      FROM events
      ${session_join}
      WHERE site_id = ${site}
      ${time_statement}
    "#,
        &[
            ("with_cte", &cte.as_ref().map(|cte| format!("WITH {cte}")).unwrap_or_default()),
            ("clauses", &clauses.join(", ")),
            ("session_join", if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" }),
            ("site", &escape(&JsValue::Number(site_id))),
            ("time_statement", &time_statement),
        ],
    )))
}

/// `TimeBucketToFn[bucket]` as the template literal prints it: the function name
/// for a bucket, a native function's source for an `Object.prototype` key, `None`
/// (falsy, undefined) for anything else.
fn bucket_function_text(bucket_key: &str) -> Option<String> {
    TimeBucket::parse(bucket_key)
        .map(|bucket| time_bucket_fn(bucket).to_string())
        .or_else(|| object_prototype_text(bucket_key).map(str::to_string))
}

/// `buildGoalTimeSeriesQuery(query, siteId, goals)`: `None` when no goal yields a
/// condition.
pub fn build_goal_time_series_query(query: &JsObject, site_id: f64, goals: &[GoalRow]) -> BuildResult<Option<String>> {
    let bucket = match query.get_or_undefined("bucket") {
        JsValue::Undefined => "hour".to_string(),
        other => other.to_js_string(),
    };
    let (time_statement, cte) = filtered_sessions(query, site_id)?;
    let session_join = if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    let bucket_fn = bucket_function_text(&bucket).unwrap_or_else(|| "undefined".to_string());

    let mut conversion_queries = Vec::new();
    for goal in goals {
        let Some(condition) = goal.condition()? else { continue };
        conversion_queries.push(template(
            r#"
          SELECT
            toDateTime(${bucket_fn}(toTimeZone(timestamp, {timeZone:String}))) AS time,
            ${goal_id} AS goal_id,
            COUNT(DISTINCT session_id) AS conversions
          FROM events
          ${session_join}
          WHERE
            site_id = {siteId:Int32}
            AND (${condition})
            ${time_statement}
          GROUP BY time, goal_id
        "#,
            &[
                ("bucket_fn", &bucket_fn),
                ("goal_id", &goal.goal_id.to_string()),
                ("session_join", session_join),
                ("condition", &condition),
                ("time_statement", &time_statement),
            ],
        ));
    }
    if conversion_queries.is_empty() {
        return Ok(None);
    }
    let goal_ids = goals.iter().map(|goal| goal.goal_id.to_string()).collect::<Vec<_>>().join(", ");
    Ok(Some(template(
        r#"
      WITH
        ${cte_prefix}
        sessions_by_bucket AS (
          SELECT
            toDateTime(${bucket_fn}(toTimeZone(timestamp, {timeZone:String}))) AS time,
            COUNT(DISTINCT session_id) AS total_sessions
          FROM events
          ${session_join}
          WHERE
            site_id = {siteId:Int32}
            ${time_statement}
          GROUP BY time
        ),
        goal_ids AS (
          SELECT arrayJoin([${goal_ids}]) AS goal_id
        ),
        conversions_by_goal AS (
          ${conversion_queries}
        )
      SELECT
        s.time AS time,
        g.goal_id AS goal_id,
        ifNull(c.conversions, 0) AS conversions,
        s.total_sessions AS total_sessions,
        if(s.total_sessions > 0, ifNull(c.conversions, 0) / s.total_sessions, 0) AS conversion_rate
      FROM sessions_by_bucket s
      CROSS JOIN goal_ids g
      LEFT JOIN conversions_by_goal c ON c.time = s.time AND c.goal_id = g.goal_id
      ORDER BY s.time ASC, g.goal_id ASC
    "#,
        &[
            ("cte_prefix", &cte.as_ref().map(|cte| format!("{cte},")).unwrap_or_default()),
            ("bucket_fn", &bucket_fn),
            ("session_join", session_join),
            ("time_statement", &time_statement),
            ("goal_ids", &goal_ids),
            ("conversion_queries", &conversion_queries.join("\nUNION ALL\n")),
        ],
    )))
}

/// `buildGoalSessionsQuery(query, siteId, goalCondition)`.
pub fn build_goal_sessions_query(query: &JsObject, site_id: f64, goal_condition: &str) -> BuildResult<String> {
    let (time_statement, cte) = filtered_sessions(query, site_id)?;
    Ok(template(
        r#"
    WITH ${cte_prefix}
    GoalSessions AS (
      SELECT DISTINCT session_id
      FROM events
      ${session_join}
      WHERE
        site_id = {siteId:Int32}
        AND (${goal_condition})
        ${time_statement}
    ),
    AggregatedSessions AS (
      SELECT
        e.session_id,
        e.user_id,
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
        argMin(e.referrer, e.timestamp) AS referrer,
        argMin(e.channel, e.timestamp) AS channel,
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
      INNER JOIN GoalSessions gs ON e.session_id = gs.session_id
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
            ("cte_prefix", &cte.as_ref().map(|cte| format!("{cte},")).unwrap_or_default()),
            ("session_join", if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" }),
            ("goal_condition", goal_condition),
            ("time_statement", &time_statement),
        ],
    ))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `parseGoalIds(req.query.goal_ids)`, deduplicated like `new Set`.
pub fn parse_goal_ids(value: &JsValue) -> Vec<f64> {
    fn finite_numbers(items: impl Iterator<Item = f64>) -> Vec<f64> {
        items.filter(|number| number.is_finite()).collect()
    }
    let ids = if !value.is_truthy() {
        Vec::new()
    } else if let JsValue::Array(items) = value {
        finite_numbers(items.iter().map(JsValue::to_number))
    } else {
        let text = value.to_js_string();
        match js_json::parse(&text) {
            Ok(JsValue::Array(items)) => finite_numbers(items.iter().map(JsValue::to_number)),
            _ => finite_numbers(text.split(',').map(string_to_number)),
        }
    };
    // SameValueZero: 0 and -0 are one entry, the first spelling kept
    let mut unique: Vec<f64> = Vec::with_capacity(ids.len());
    for id in ids {
        if !unique.contains(&id) {
            unique.push(id);
        }
    }
    unique
}

/// The site id handlers use (`Number(siteId)`).
fn site_number(site_id: &str) -> f64 {
    string_to_number(site_id)
}

/// GET /api/sites/:siteId/goals (`getGoals`).
pub async fn get_goals(
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
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Public, route_scope("goals", "read"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match goals_data(&state, &request.site_id, &request.query).await {
        Ok(response) => response,
        Err(err) => analytics_failure("goals data", err.as_ref()),
    }
}

async fn goals_data(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let with_default = |name: &str, fallback: &str| match query.get_or_undefined(name) {
        JsValue::Undefined => JsValue::from(fallback),
        other => other.clone(),
    };
    let page = with_default("page", "1");
    let page_size = with_default("page_size", "10");
    let sort = with_default("sort", "createdAt");
    let order = with_default("order", "desc");

    let page_number = parse_int_10(&page.to_js_string());
    let page_size_number = parse_int_10(&page_size.to_js_string());
    if page_number.is_nan() || page_number < 1.0 {
        return Ok(send_error(StatusCode::BAD_REQUEST, "Invalid page number"));
    }
    if page_size_number.is_nan() || !(1.0..=100.0).contains(&page_size_number) {
        return Ok(send_error(StatusCode::BAD_REQUEST, "Invalid page size, must be between 1 and 100"));
    }

    let site = site_number(site_id);
    let site_param = pg_int4(site).ok_or_else(|| JsError::new("site id is not a valid integer parameter"))?;
    // count(*) is a bigint, which postgres.js hands over as a string
    let total_goals: String = sqlx::query_scalar("SELECT count(*)::text FROM goals WHERE site_id = $1")
        .bind(site_param)
        .fetch_one(&state.pg)
        .await?;
    let total_pages = (string_to_number(&total_goals) / page_size_number).ceil();
    let meta = |total: JsValue, total_pages: f64| {
        let mut meta = JsObject::new();
        meta.insert("total", total);
        meta.insert("page", JsValue::Number(page_number));
        meta.insert("pageSize", JsValue::Number(page_size_number));
        meta.insert("totalPages", JsValue::Number(total_pages));
        JsValue::Object(meta)
    };
    let respond = |data: Vec<JsValue>, total: JsValue, total_pages: f64| {
        let mut body = JsObject::new();
        body.insert("data", JsValue::Array(data));
        body.insert("meta", meta(total, total_pages));
        send_js(StatusCode::OK, &JsValue::Object(body))
    };

    let sort_column = match sort.as_str() {
        Some("goalId") => "goal_id",
        Some("name") => "name",
        Some("goalType") => "goal_type",
        _ => "created_at",
    };
    let direction = if order.as_str() == Some("asc") { "asc" } else { "desc" };
    let offset = (page_number - 1.0) * page_size_number;
    let offset = pg_int8(offset).ok_or_else(|| JsError::new("offset is not a valid bigint parameter"))?;
    let limit = pg_int8(page_size_number).ok_or_else(|| JsError::new("limit is not a valid bigint parameter"))?;
    let sql = format!("SELECT {} FROM goals WHERE site_id = $1 ORDER BY {sort_column} {direction} LIMIT $2 OFFSET $3", GoalRow::COLUMNS);
    let rows = sqlx::query(&sql).bind(site_param).bind(limit).bind(offset).fetch_all(&state.pg).await?;
    let goals = rows.iter().map(GoalRow::from_row).collect::<Result<Vec<_>, _>>()?;

    if goals.is_empty() {
        debug!(site_id, page = page_number, "No goals on this page");
        return Ok(respond(Vec::new(), JsValue::String(total_goals), total_pages));
    }

    let clickhouse = analytics_clickhouse(state)?;
    let total_sessions_rows = clickhouse.run_analytics_query(&QuerySpec::new(build_goals_total_sessions_query(query, site)?)).await?;
    let total_sessions = total_sessions_rows
        .first()
        .and_then(|row| row.get("total_sessions"))
        .map(JsValue::from_serde)
        .filter(JsValue::is_truthy)
        .unwrap_or(JsValue::Number(0.0));

    let with_conversions = |goal: &GoalRow, conversions: JsValue| {
        let rate = if total_sessions.to_number() > 0.0 { conversions.to_number() / total_sessions.to_number() } else { 0.0 };
        let mut object = goal.to_js();
        object.insert("total_conversions", conversions);
        object.insert("total_sessions", total_sessions.clone());
        object.insert("conversion_rate", JsValue::Number(rate));
        JsValue::Object(object)
    };

    let Some(conversion_query) = build_goals_conversions_query(query, site, &goals)? else {
        let data = goals
            .iter()
            .map(|goal| {
                let mut object = goal.to_js();
                object.insert("total_conversions", JsValue::Number(0.0));
                object.insert("total_sessions", total_sessions.clone());
                object.insert("conversion_rate", JsValue::Number(0.0));
                JsValue::Object(object)
            })
            .collect();
        return Ok(respond(data, JsValue::String(total_goals), total_pages));
    };
    let conversion_rows = clickhouse.run_analytics_query(&QuerySpec::new(conversion_query)).await?;
    let conversions = conversion_rows.into_iter().next().unwrap_or_default();
    let data = goals
        .iter()
        .map(|goal| {
            let count = conversions
                .get(&format!("goal_{}_conversions", goal.goal_id))
                .map(JsValue::from_serde)
                .filter(JsValue::is_truthy)
                .unwrap_or(JsValue::Number(0.0));
            with_conversions(goal, count)
        })
        .collect();
    debug!(site_id, goals = goals.len(), "Goals with conversions");
    Ok(respond(data, JsValue::String(total_goals), total_pages))
}

/// GET /api/sites/:siteId/goals/time-series (`getGoalTimeSeries`).
pub async fn get_goal_time_series(
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
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Public, route_scope("goals", "read"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match goal_time_series(&state, &request.site_id, &request.query).await {
        Ok(response) => response,
        Err(err) => analytics_failure("goal time series", err.as_ref()),
    }
}

async fn goal_time_series(state: &AppState, site_id: &str, query: &JsObject) -> BuildResult<Response> {
    let site = site_number(site_id);
    let bucket = match query.get_or_undefined("bucket") {
        JsValue::Undefined => "hour".to_string(),
        other => other.to_js_string(),
    };
    let time_zone = query.get_or_undefined("time_zone");
    let time_zone = if time_zone.is_truthy() { time_zone.clone() } else { JsValue::from("UTC") };

    if bucket_function_text(&bucket).is_none() {
        return Ok(send_error(StatusCode::BAD_REQUEST, &format!("Invalid bucket value: {bucket}")));
    }
    let goal_ids = parse_goal_ids(query.get_or_undefined("goal_ids"));
    if goal_ids.is_empty() {
        return Ok(send_json(StatusCode::OK, &json!({ "data": [] })));
    }

    let site_param = pg_int4(site).ok_or_else(|| JsError::new("site id is not a valid integer parameter"))?;
    let id_params = goal_ids
        .iter()
        .map(|id| pg_int4(*id))
        .collect::<Option<Vec<i32>>>()
        .ok_or_else(|| JsError::new("a goal id is not a valid integer parameter"))?;
    let sql = format!("SELECT {} FROM goals WHERE site_id = $1 AND goal_id = ANY($2)", GoalRow::COLUMNS);
    let rows = sqlx::query(&sql).bind(site_param).bind(&id_params).fetch_all(&state.pg).await?;
    let goals = rows.iter().map(GoalRow::from_row).collect::<Result<Vec<_>, _>>()?;
    if goals.is_empty() {
        return Ok(send_json(StatusCode::OK, &json!({ "data": [] })));
    }

    let Some(sql) = build_goal_time_series_query(query, site, &goals)? else {
        return Ok(send_json(StatusCode::OK, &json!({ "data": [] })));
    };
    let spec = QuerySpec::new(sql).param("siteId", site).param("timeZone", &time_zone);
    let rows = analytics_clickhouse(state)?.run_analytics_query(&spec).await?;
    debug!(site_id, goals = goals.len(), rows = rows.len(), "Goal time series fetched");
    Ok(send_json(StatusCode::OK, &json!({ "data": rows })))
}

/// GET /api/sites/:siteId/goals/:goalId/sessions (`getGoalSessions`).
pub async fn get_goal_sessions(
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
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Public, route_scope("goals", "read"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let goal_param = params.get("goalId").cloned().unwrap_or_default();
    match goal_sessions(&state, &request.site_id, &request.query, &goal_param).await {
        Ok(response) => response,
        Err(err) => analytics_failure("goal sessions", err.as_ref()),
    }
}

async fn goal_sessions(state: &AppState, site_id: &str, query: &JsObject, goal_param: &str) -> BuildResult<Response> {
    let goal_id = pg_int4(string_to_number(goal_param)).ok_or_else(|| JsError::new("goal id is not a valid integer parameter"))?;
    let sql = format!("SELECT {} FROM goals WHERE goal_id = $1 LIMIT 1", GoalRow::COLUMNS);
    let Some(row) = sqlx::query(&sql).bind(goal_id).fetch_optional(&state.pg).await? else {
        return Ok(send_error(StatusCode::NOT_FOUND, "Goal not found"));
    };
    let goal = GoalRow::from_row(&row)?;
    let site = site_number(site_id);
    if f64::from(goal.site_id) != site {
        return Ok(send_error(StatusCode::FORBIDDEN, "Goal does not belong to this site"));
    }
    let Some(condition) = goal.condition()? else {
        return Ok(send_error(StatusCode::BAD_REQUEST, "Invalid goal configuration"));
    };

    let limit = query.get_or_undefined("limit");
    let page = query.get_or_undefined("page");
    let limit_value = if limit.is_truthy() { limit.clone() } else { JsValue::Number(25.0) };
    let page_value = if page.is_truthy() { page.clone() } else { JsValue::Number(1.0) };
    let offset = (page_value.to_number() - 1.0) * limit_value.to_number();
    let spec = QuerySpec::new(build_goal_sessions_query(query, site, &condition)?)
        .param("siteId", site)
        .param("limit", &limit_value)
        .param("offset", offset);
    let rows = analytics_clickhouse(state)?.run_analytics_query(&spec).await?;
    debug!(site_id, goal_id, rows = rows.len(), "Goal sessions fetched");
    Ok(send_json(StatusCode::OK, &json!({ "data": rows })))
}

/// A body `goalBodySchema` rejects. Both write handlers would answer 400
/// `{error: "Validation error", details}`, but their catch block logs the
/// `ZodError` first and Node's logger throws on it, so Fastify's default error
/// handler answers 500 instead (see `support::ZOD_ERROR_LOG_EXCEPTION`).
fn validation_failed(issues: &[ZodIssue], route: &str) -> Response {
    let details = js_json::stringify(&validation_error_body(issues)).unwrap_or_default();
    warn!(route, issue_count = issues.len(), details = %details, "Goal body failed validation");
    uncaught_exception(route, &JsError::new(ZOD_ERROR_LOG_EXCEPTION))
}

fn goal_config_text(body: &GoalBody) -> String {
    js_json::stringify(&JsValue::Object(body.config.clone())).unwrap_or_default()
}

/// `name || null`
fn goal_name(body: &GoalBody) -> Option<&str> {
    body.name.as_deref().filter(|name| !name.is_empty())
}

/// POST /api/sites/:siteId/goals (`createGoal`).
pub async fn create_goal(
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
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Member, route_scope("goals", "write"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let site_id = parse_int_10(&request.site_id);
    if site_id.is_nan() || site_id <= 0.0 {
        return send_error(StatusCode::BAD_REQUEST, "Invalid site ID");
    }
    let goal = match parse_goal_body(&body) {
        Ok(goal) => goal,
        Err(issues) => return validation_failed(&issues, "POST /api/sites/:siteId/goals"),
    };
    if !user_has_access_to_site(&state, &request.auth, site_id).await {
        return send_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    let failed = |err: &dyn std::fmt::Display| {
        error!(err = %err, site_id, "Error creating goal");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create goal")
    };
    let Some(site_param) = pg_int4(site_id) else {
        return failed(&"site id out of integer range");
    };
    let inserted = sqlx::query(
        "INSERT INTO goals (site_id, name, goal_type, config) VALUES ($1, $2, $3, $4::text::jsonb) RETURNING goal_id",
    )
    .bind(site_param)
    .bind(goal_name(&goal))
    .bind(&goal.goal_type)
    .bind(goal_config_text(&goal))
    .fetch_one(&state.pg)
    .await;
    match inserted {
        Ok(row) => {
            let goal_id: i32 = row.get("goal_id");
            info!(goal_id, site_id, goal_type = %goal.goal_type, "Goal created");
            send_json(StatusCode::CREATED, &json!({ "success": true, "goalId": goal_id }))
        }
        Err(err) => failed(&err),
    }
}

/// PUT /api/sites/:siteId/goals/:goalId (`updateGoal`).
pub async fn update_goal(
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
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Member, route_scope("goals", "write"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let goal_param = params.get("goalId").cloned().unwrap_or_default();
    update_goal_by_param(&state, &request.auth, &request.site_id, &goal_param, &body).await
}

/// updateGoal's body, shared with the literal `/goals/time-series` path Fastify
/// also routes to it for PUT.
pub async fn update_goal_by_param(
    state: &AppState,
    auth: &Authenticated,
    site_param: &str,
    goal_param: &str,
    body: &JsValue,
) -> Response {
    let site_id = parse_int_10(site_param);
    let goal_id = parse_int_10(goal_param);
    if site_id.is_nan() || site_id <= 0.0 {
        return send_error(StatusCode::BAD_REQUEST, "Invalid site ID");
    }
    if goal_id.is_nan() || goal_id <= 0.0 {
        return send_error(StatusCode::BAD_REQUEST, "Invalid goal ID");
    }
    let goal = match parse_goal_body(body) {
        Ok(goal) => goal,
        Err(issues) => return validation_failed(&issues, "PUT /api/sites/:siteId/goals/:goalId"),
    };
    let failed = |err: &dyn std::fmt::Display| {
        error!(err = %err, site_id, goal = goal_param, "Error updating goal");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update goal")
    };
    let Some(goal_param_id) = pg_int4(goal_id) else {
        return failed(&"goal id out of integer range");
    };
    let existing: Option<i32> = match sqlx::query_scalar("SELECT site_id FROM goals WHERE goal_id = $1 LIMIT 1")
        .bind(goal_param_id)
        .fetch_optional(&state.pg)
        .await
    {
        Ok(existing) => existing,
        Err(err) => return failed(&err),
    };
    let Some(existing_site) = existing else {
        return send_error(StatusCode::NOT_FOUND, "Goal not found");
    };
    if f64::from(existing_site) != site_id {
        return send_error(StatusCode::FORBIDDEN, "Goal does not belong to the specified site");
    }
    if !user_has_access_to_site(state, auth, site_id).await {
        return send_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    let updated = sqlx::query(
        "UPDATE goals SET name = $1, goal_type = $2, config = $3::text::jsonb WHERE goal_id = $4 RETURNING goal_id",
    )
    .bind(goal_name(&goal))
    .bind(&goal.goal_type)
    .bind(goal_config_text(&goal))
    .bind(goal_param_id)
    .fetch_all(&state.pg)
    .await;
    match updated {
        Ok(rows) if rows.is_empty() => send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update goal"),
        Ok(rows) => {
            let updated_id: i32 = rows[0].get("goal_id");
            info!(goal_id = updated_id, site_id, "Goal updated");
            send_json(StatusCode::OK, &json!({ "success": true, "goalId": updated_id }))
        }
        Err(err) => failed(&err),
    }
}

/// DELETE /api/sites/:siteId/goals/:goalId (`deleteGoal`).
pub async fn delete_goal(
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
    if let Err(response) = read_body(&headers, body).await {
        return response;
    }
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Member, route_scope("goals", "write"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let goal_param = params.get("goalId").cloned().unwrap_or_default();
    delete_goal_by_param(&state, &request.auth, &request.site_id, &goal_param).await
}

/// deleteGoal's body, shared with the literal `/goals/time-series` path.
pub async fn delete_goal_by_param(state: &AppState, auth: &Authenticated, site_param: &str, goal_param: &str) -> Response {
    let site_id = parse_int_10(site_param);
    let goal_id = parse_int_10(goal_param);
    if site_id.is_nan() || site_id <= 0.0 {
        return send_error(StatusCode::BAD_REQUEST, "Invalid site ID");
    }
    if goal_id.is_nan() || goal_id <= 0.0 {
        return send_error(StatusCode::BAD_REQUEST, "Invalid goal ID");
    }
    let failed = |err: &dyn std::fmt::Display| {
        error!(err = %err, site_id, goal = goal_param, "Error deleting goal");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete goal")
    };
    let Some(goal_param_id) = pg_int4(goal_id) else {
        return failed(&"goal id out of integer range");
    };
    let existing: Option<i32> = match sqlx::query_scalar("SELECT site_id FROM goals WHERE goal_id = $1 LIMIT 1")
        .bind(goal_param_id)
        .fetch_optional(&state.pg)
        .await
    {
        Ok(existing) => existing,
        Err(err) => return failed(&err),
    };
    let Some(existing_site) = existing else {
        return send_error(StatusCode::NOT_FOUND, "Goal not found");
    };
    if f64::from(existing_site) != site_id {
        return send_error(StatusCode::FORBIDDEN, "Goal does not belong to the specified site");
    }
    if !user_has_access_to_site(state, auth, site_id).await {
        return send_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    match sqlx::query("DELETE FROM goals WHERE goal_id = $1 RETURNING goal_id").bind(goal_param_id).fetch_all(&state.pg).await {
        Ok(rows) if rows.is_empty() => send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete goal"),
        Ok(_) => {
            info!(goal_id = goal_param_id, site_id, "Goal deleted");
            send_json(StatusCode::OK, &json!({ "success": true }))
        }
        Err(err) => failed(&err),
    }
}

/// Every autocapture type is also a goal type.
const _: () = assert!(AutocaptureTargetType::ALL.len() + 2 == GOAL_TYPES.len());

#[cfg(test)]
mod tests {
    use crate::analytics::js::json::parse;

    use super::*;

    fn issues_json(body: &str) -> String {
        match parse_goal_body(&parse(body).unwrap()) {
            Ok(_) => "ok".into(),
            Err(issues) => js_json::stringify(&zod::issues_value(&issues)).unwrap(),
        }
    }

    #[test]
    fn goal_body_schema() {
        assert_eq!(issues_json(r#"{"goalType":"path","config":{"pathPattern":"/x"}}"#), "ok");
        assert_eq!(issues_json(r#"{"goalType":"copy","config":{}}"#), "ok");
        assert_eq!(
            issues_json(r#"{"goalType":"path","config":{}}"#),
            r#"[{"code":"custom","message":"Configuration must match goal type","path":["config"]}]"#
        );
        assert_eq!(
            issues_json(r#"{"goalType":"event","config":{"eventName":"x","eventPropertyKey":"k"}}"#),
            r#"[{"code":"custom","message":"Both eventPropertyKey and eventPropertyValue must be provided together or omitted together","path":["config"]}]"#
        );
        assert_eq!(
            issues_json(r#"{"config":{}}"#),
            r#"[{"expected":"'path' | 'event' | 'outbound' | 'button_click' | 'form_submit' | 'copy'","received":"undefined","code":"invalid_type","path":["goalType"],"message":"Required"}]"#
        );
        assert_eq!(
            issues_json(r#"{"goalType":"path","config":{"pathPattern":1,"propertyFilters":[{"key":"a","value":null}]}}"#),
            r#"[{"code":"invalid_type","expected":"string","received":"number","path":["config","pathPattern"],"message":"Expected string, received number"},{"code":"invalid_union","unionErrors":[{"issues":[{"code":"invalid_type","expected":"string","received":"null","path":["config","propertyFilters",0,"value"],"message":"Expected string, received null"}],"name":"ZodError"},{"issues":[{"code":"invalid_type","expected":"number","received":"null","path":["config","propertyFilters",0,"value"],"message":"Expected number, received null"}],"name":"ZodError"},{"issues":[{"code":"invalid_type","expected":"boolean","received":"null","path":["config","propertyFilters",0,"value"],"message":"Expected boolean, received null"}],"name":"ZodError"}],"path":["config","propertyFilters",0,"value"],"message":"Invalid input"}]"#
        );
        let long = "x".repeat(513);
        assert!(issues_json(&format!(r#"{{"goalType":"copy","config":{{"valuePattern":"{long}"}}}}"#)).contains("too_big"));
        let parsed = parse_goal_body(&parse(r#"{"name":"n","goalType":"event","config":{"extra":1,"eventName":"e","pathPattern":"/"}}"#).unwrap()).unwrap();
        assert_eq!(js_json::stringify(&JsValue::Object(parsed.config)).unwrap(), r#"{"pathPattern":"/","eventName":"e"}"#);
    }

    #[test]
    fn goal_id_parsing() {
        assert_eq!(parse_goal_ids(&JsValue::from("1,2,2,x")), vec![1.0, 2.0]);
        assert_eq!(parse_goal_ids(&JsValue::from("[3, \"4\", null, true]")), vec![3.0, 4.0, 0.0, 1.0]);
        assert_eq!(parse_goal_ids(&JsValue::from("")), Vec::<f64>::new());
        assert_eq!(parse_goal_ids(&JsValue::Array(vec!["5".into(), "5".into()])), vec![5.0]);
        assert_eq!(parse_goal_ids(&JsValue::from("7")), vec![7.0]);
    }

    fn form_goal() -> GoalRow {
        GoalRow {
            goal_id: 115,
            site_id: 1,
            name: Some("Recipe book form".into()),
            goal_type: "form_submit".into(),
            config: parse(r#"{"valuePattern":"gform_115"}"#).unwrap(),
            created_at: None,
        }
    }

    // Ported from goalQueries.test.ts
    #[test]
    fn goal_queries_with_session_filters() {
        let query: JsObject = [
            ("filters", r#"[{"parameter":"utm_campaign","type":"equals","value":["recipe_book_2026"]}]"#),
            ("start_date", ""),
            ("end_date", ""),
            ("time_zone", "UTC"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), JsValue::from(value)))
        .collect();

        let sql = build_goals_conversions_query(&query, 1.0, &[form_goal()]).unwrap().unwrap();
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("argMin(url_parameters, timestamp)['utm_campaign'] AS utm_campaign"));
        assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
        assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(sql.contains("type = 'form_submit'"));

        let sql = build_goals_total_sessions_query(&query, 1.0).unwrap();
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
        assert!(sql.contains("FROM FilteredSessions"));

        let mut bucketed = query.clone();
        bucketed.insert("bucket", "hour".into());
        let sql = build_goal_time_series_query(&bucketed, 1.0, &[form_goal()]).unwrap().unwrap();
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(sql.contains("type = 'form_submit'"));

        let sql = build_goal_sessions_query(&query, 1.0, "type = 'form_submit' AND JSONExtractString(toString(props), 'formId') = 'gform_115'").unwrap();
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
        assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
    }

    #[test]
    fn bucket_lookups() {
        assert_eq!(bucket_function_text("day").as_deref(), Some("toStartOfDay"));
        assert_eq!(bucket_function_text("toString").as_deref(), Some("function toString() { [native code] }"));
        assert_eq!(bucket_function_text("hour,day"), None);
    }
}
