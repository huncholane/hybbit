//! User-authored SQL, ported from server/src/api/analytics/runCustomQuery.ts
//! (POST /api/organizations/:organizationId/analytics/query) and
//! runDashboardCardQuery.ts (POST /api/sites/:siteId/dashboards/run-card).
//!
//! Both wrap the validated query in a `scoped_events` CTE pinned to the caller's
//! sites and run it as the least-privileged `hygo_query` ClickHouse user
//! (`clickhouseQuery` in server/src/db/clickhouse/client.ts), whose settings
//! profile carries the execution limits.

use std::{net::SocketAddr, sync::OnceLock, time::Duration};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::json;
use tracing::{debug, error, info, warn};

use super::{
    access::RequestAccess,
    rate_limit::{self, CUSTOM_QUERY, RUN_CARD},
    request::{self, object},
    schema::{self, ObjectStatus, StringCheck, first_message},
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, org_scoped, route_scope, site_scoped},
        js::{
            JsObject, JsValue,
            number::parse_int_10,
            string::is_js_space_char,
            zod::{self, Path, PathSegment, Status, ZodIssue},
        },
        sql_string::escape_string,
        types::TimeBucket,
        utils::{
            analytics_query::{AnalyticsClickHouse, QueryParam, QuerySpec},
            custom_query_validation::{MAX_CUSTOM_QUERY_LENGTH, normalize_custom_query, sanitize_clickhouse_error, validate_scoped_query},
            query_validation::validate_http_time_params,
            time_window::{TimeWindowParams, bucket_interval, get_time_statement},
        },
    },
    http,
    state::AppState,
};

/// Mirrors the hygo_query ClickHouse profile
const MAX_EXECUTION_TIME_SECONDS: f64 = 10.0;
const MAX_RESULT_ROWS: f64 = 1000.0;
/// `request_timeout` of the `clickhouseQuery` client
const QUERY_CLIENT_TIMEOUT: Duration = Duration::from_millis(30_000);

static QUERY_CLIENT: OnceLock<Option<AnalyticsClickHouse>> = OnceLock::new();

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// `clickhouseQuery`: `CLICKHOUSE_QUERY_USER || "hygo_query"`, with
/// `CLICKHOUSE_QUERY_PASSWORD || CLICKHOUSE_PASSWORD`.
fn query_client(state: &AppState) -> Option<&'static AnalyticsClickHouse> {
    QUERY_CLIENT
        .get_or_init(|| {
            let config = &state.config.clickhouse;
            let user = env_nonempty("CLICKHOUSE_QUERY_USER").unwrap_or_else(|| "hygo_query".to_string());
            let password = env_nonempty("CLICKHOUSE_QUERY_PASSWORD").unwrap_or_else(|| config.password.clone());
            match AnalyticsClickHouse::from_parts_with_timeout(&config.url, &config.database, &user, &password, QUERY_CLIENT_TIMEOUT) {
                Ok(client) => {
                    info!(user = %user, "Custom query ClickHouse client ready");
                    Some(client)
                }
                Err(err) => {
                    error!(error = %err, "Could not build the custom query ClickHouse client");
                    None
                }
            }
        })
        .as_ref()
}

/// Run a wrapped query and shape Node's reply: `{ data, meta }`, or 400 with the
/// sanitised ClickHouse error.
async fn execute(state: &AppState, spec: QuerySpec, label: &str) -> Response {
    let Some(client) = query_client(state) else {
        return request::error(StatusCode::BAD_REQUEST, "Failed to run query");
    };
    match client.query_json_each_row(&spec).await {
        Ok((query_id, rows)) => {
            let row_count = rows.len();
            info!(query_id = %query_id, rows = row_count, "{label} finished");
            request::send(
                StatusCode::OK,
                &object(vec![
                    ("data", JsValue::Array(rows)),
                    (
                        "meta",
                        object(vec![
                            ("queryId", JsValue::String(query_id)),
                            ("rowCount", JsValue::Number(row_count as f64)),
                            ("maxExecutionTimeSeconds", JsValue::Number(MAX_EXECUTION_TIME_SECONDS)),
                            ("maxRows", JsValue::Number(MAX_RESULT_ROWS)),
                        ]),
                    ),
                ]),
            )
        }
        Err(failure) => {
            let message = failure.message();
            error!(error = %message, "Failed to run {label}");
            request::error(StatusCode::BAD_REQUEST, &sanitize_clickhouse_error(Some(&message)))
        }
    }
}

fn key_path(name: &str) -> Path {
    vec![PathSegment::Key(name.to_string())]
}

/// `z.string().trim().min(1).max(MAX_CUSTOM_QUERY_LENGTH)`
fn query_field(object: &JsObject, issues: &mut Vec<ZodIssue>) -> Option<(Status, String)> {
    schema::string(
        object.get_or_undefined("query"),
        &key_path("query"),
        issues,
        &[StringCheck::Trim, StringCheck::Min(1, None), StringCheck::Max(MAX_CUSTOM_QUERY_LENGTH, None)],
    )
}

/// runCustomQuery's `requestBodySchema`
fn parse_query_body(body: &JsValue) -> Result<(String, Option<f64>), String> {
    let mut issues = Vec::new();
    let Some(object) = schema::object(body, &Vec::new(), &mut issues) else { return Err(first_message(&issues)) };
    let mut status = ObjectStatus::new();
    let query = status.field(query_field(object, &mut issues));
    let site_id = status.field(schema::optional(object.get_or_undefined("siteId"), |inner| {
        schema::number(inner, &key_path("siteId"), &mut issues, true, true)
    }));
    let result = match (status.finish(), query, site_id) {
        (Some(object_status), Some(query), Some(site_id)) => Some((object_status, (query, site_id.value().copied()))),
        _ => None,
    };
    schema::finish(result, issues).map_err(|issues| first_message(&issues))
}

/// The organization routes' chain (`orgSqlRead`) and the query limiter they share.
pub(super) async fn org_chain(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    organization_id: &str,
    peer: ConnectInfo<SocketAddr>,
) -> Result<(crate::auth::guards::Authenticated, rate_limit::LimitHeaders), Response> {
    let scoped = org_scoped(state, headers, uri, organization_id, false, route_scope("sql", "read")).await?;
    let peer = peer.0.ip();
    let key = scoped.auth.user_id.clone().unwrap_or_else(|| request::request_ip(headers, peer));
    let limit_headers = rate_limit::check(state, CUSTOM_QUERY, &key).await?;
    Ok((scoped.auth, limit_headers))
}

/// `getSitesUserHasAccessTo(request)` narrowed to one organization, in access order.
pub(super) async fn organization_site_ids(access: &RequestAccess<'_>, organization_id: &str) -> Vec<i32> {
    let accessible = access.site_ids(false).await;
    if accessible.is_empty() {
        return accessible;
    }
    let owned: Result<Vec<i32>, sqlx::Error> =
        sqlx::query_scalar("SELECT site_id FROM sites WHERE site_id = ANY($1) AND organization_id = $2")
            .bind(&accessible)
            .bind(organization_id)
            .fetch_all(access.pg())
            .await;
    match owned {
        Ok(owned) => accessible.into_iter().filter(|site_id| owned.contains(site_id)).collect(),
        Err(err) => {
            error!(error = %err, "Error reading site organizations");
            Vec::new()
        }
    }
}

/// POST /api/organizations/:organizationId/analytics/query
pub async fn run_custom_query(
    State(state): State<AppState>,
    peer: ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (auth, limit_headers) = match org_chain(&state, &uri, &headers, &params[0], peer).await {
        Ok(chain) => chain,
        Err(response) => return response,
    };
    let organization_id = &params[0];

    let response = async {
        let (query, requested_site) = match parse_query_body(&body) {
            Ok(parsed) => parsed,
            Err(message) => return request::error(StatusCode::BAD_REQUEST, &message),
        };
        if let Some(reason) = validate_scoped_query(&query) {
            return request::error(StatusCode::BAD_REQUEST, &reason);
        }
        let access = RequestAccess::new(&state, &headers, &auth);
        let accessible = organization_site_ids(&access, organization_id).await;
        if accessible.is_empty() {
            return request::error(StatusCode::FORBIDDEN, "No access to organization or no sites found");
        }
        let site_ids: Vec<i32> = match requested_site {
            None => accessible,
            Some(site_id) => {
                if !accessible.iter().any(|id| f64::from(*id) == site_id) {
                    return request::error(StatusCode::FORBIDDEN, "No access to the requested site");
                }
                vec![site_id as i32]
            }
        };
        debug!(organization_id = %organization_id, sites = site_ids.len(), "Running custom analytics query");
        let sql = format!(
            "\n    WITH scoped_events AS (\n      SELECT *\n      FROM events\n      PREWHERE site_id IN {{siteIds:Array(UInt16)}}\n    )\n    SELECT *\n    FROM (\n      {}\n    )\n    LIMIT {{limit:UInt32}}\n  ",
            normalize_custom_query(&query)
        );
        let spec = QuerySpec::new(sql)
            .param("siteIds", QueryParam::Array(site_ids.iter().map(|id| QueryParam::from(*id)).collect()))
            .param("limit", MAX_RESULT_ROWS);
        execute(&state, spec, "custom analytics query").await
    }
    .await;
    rate_limit::with_headers(response, limit_headers)
}

/// runDashboardCardQuery's body after `requestBodySchema`
struct CardBody {
    query: String,
    time: JsObject,
    time_zone: Option<String>,
    bucket: Option<TimeBucket>,
}

const BUCKETS: [&str; 9] = ["minute", "five_minutes", "ten_minutes", "fifteen_minutes", "hour", "day", "week", "month", "year"];

fn parse_card_body(body: &JsValue) -> Result<CardBody, String> {
    let mut issues = Vec::new();
    let Some(object) = schema::object(body, &Vec::new(), &mut issues) else { return Err(first_message(&issues)) };
    let mut status = ObjectStatus::new();
    let query = status.field(query_field(object, &mut issues));
    let mut strings = Vec::new();
    for name in ["startDate", "endDate", "timeZone", "startDateTime", "endDateTime"] {
        let parsed = status.field(schema::optional(object.get_or_undefined(name), |inner| {
            schema::string(inner, &key_path(name), &mut issues, &[])
        }));
        strings.push(parsed.map(|field| field.value().cloned()));
    }
    let mut numbers = Vec::new();
    for name in ["pastMinutesStart", "pastMinutesEnd"] {
        let parsed = status.field(schema::optional(object.get_or_undefined(name), |inner| {
            schema::number(inner, &key_path(name), &mut issues, false, false)
        }));
        numbers.push(parsed.map(|field| field.value().copied()));
    }
    let bucket = status.field(schema::optional(object.get_or_undefined("bucket"), |inner| {
        zod::enumeration(inner, &BUCKETS, &key_path("bucket"), &mut issues)
    }));
    let finished = status.finish();
    let (Some(object_status), Some(query), Some(bucket)) = (finished, query, bucket) else {
        return Err(first_message(&issues));
    };
    if strings.iter().any(Option::is_none) || numbers.iter().any(Option::is_none) {
        return Err(first_message(&issues));
    }
    let strings: Vec<Option<String>> = strings.into_iter().flatten().collect();
    let numbers: Vec<Option<f64>> = numbers.into_iter().flatten().collect();
    if object_status != Status::Valid || !issues.is_empty() {
        return Err(first_message(&issues));
    }
    let text = |value: &Option<String>| value.clone().map_or(JsValue::Undefined, JsValue::String);
    let number = |value: &Option<f64>| value.map_or(JsValue::Undefined, JsValue::Number);
    // The time params in validateHttpTimeParams' names, absent ones undefined
    let time: JsObject = [
        ("start_date", text(&strings[0])),
        ("end_date", text(&strings[1])),
        ("time_zone", text(&strings[2])),
        ("start_datetime", text(&strings[3])),
        ("end_datetime", text(&strings[4])),
        ("past_minutes_start", number(&numbers[0])),
        ("past_minutes_end", number(&numbers[1])),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value))
    .collect();
    Ok(CardBody {
        query,
        time,
        time_zone: strings[2].clone(),
        bucket: bucket.value().and_then(|name| TimeBucket::parse(name)),
    })
}

/// `text.replace(/\{\{\s*<word>\s*\}\}/gi, replacement)` for an ASCII word and a
/// replacement without `$` patterns.
fn replace_token(text: &str, word: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if text[index..].starts_with("{{")
            && let Some(end) = token_end(&text[index + 2..], word)
        {
            out.push_str(replacement);
            index += 2 + end;
            continue;
        }
        let character = text[index..].chars().next().expect("index is on a char boundary");
        out.push(character);
        index += character.len_utf8();
    }
    out
}

/// The length of `\s*word\s*}}` at the start of `rest`, if it matches.
fn token_end(rest: &str, word: &str) -> Option<usize> {
    let after_space = rest.len() - rest.trim_start_matches(is_js_space_char).len();
    let candidate = rest.get(after_space..after_space + word.len())?;
    if !candidate.eq_ignore_ascii_case(word) {
        return None;
    }
    let tail = &rest[after_space + word.len()..];
    let trailing = tail.len() - tail.trim_start_matches(is_js_space_char).len();
    tail[trailing..].starts_with("}}").then_some(after_space + word.len() + trailing + 2)
}

/// POST /api/sites/:siteId/dashboards/run-card (`authDashboardsRead` + the run-card limiter)
pub async fn run_card(
    State(state): State<AppState>,
    peer: ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Member,
        route_scope("dashboards", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };
    let peer = peer.0.ip();
    let key = site.auth.user_id.clone().unwrap_or_else(|| request::request_ip(&headers, peer));
    let limit_headers = match rate_limit::check(&state, RUN_CARD, &key).await {
        Ok(headers) => headers,
        Err(response) => return response,
    };

    let response = async {
        let site_id = parse_int_10(&site.site_id);
        if site_id.is_nan() || site_id <= 0.0 {
            return request::error(StatusCode::BAD_REQUEST, "Invalid site ID");
        }
        let card = match parse_card_body(&body) {
            Ok(card) => card,
            Err(message) => return request::error(StatusCode::BAD_REQUEST, &message),
        };
        if let Some(message) = validate_http_time_params(&JsValue::Object(card.time.clone())) {
            return request::error(StatusCode::BAD_REQUEST, &message);
        }

        let interval = bucket_interval(card.bucket.unwrap_or(TimeBucket::Hour));
        let zone = card.time_zone.as_deref().filter(|zone| !zone.is_empty()).unwrap_or("UTC");
        let substituted = replace_token(&replace_token(&card.query, "bucket", interval), "tz", &escape_string(zone));
        if let Some(reason) = validate_scoped_query(&substituted) {
            return request::error(StatusCode::BAD_REQUEST, &reason);
        }

        let time_statement = match get_time_statement(&TimeWindowParams::from_object(&card.time), "timestamp") {
            Ok(statement) => statement,
            Err(err) => {
                // Thrown outside the handler's try: Fastify's default error reply
                error!(error = %err, "Dashboard card time window failed");
                return http::json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({ "statusCode": 500, "error": "Internal Server Error", "message": err.to_string() }),
                );
            }
        };
        let sql = format!(
            "\n    WITH scoped_events AS (\n      SELECT *\n      FROM events\n      PREWHERE site_id IN {{siteIds:Array(UInt16)}}\n      WHERE 1=1 {time_statement}\n    )\n    SELECT *\n    FROM (\n      {}\n    )\n    LIMIT {{limit:UInt32}}\n  ",
            normalize_custom_query(&substituted)
        );
        let spec = QuerySpec::new(sql).param("siteIds", QueryParam::Array(vec![QueryParam::Number(site_id)])).param("limit", MAX_RESULT_ROWS);
        if site_id > f64::from(u16::MAX) {
            warn!(site_id, "Dashboard card site id exceeds UInt16");
        }
        execute(&state, spec, "dashboard card query").await
    }
    .await;
    rate_limit::with_headers(response, limit_headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json;

    #[test]
    fn replaces_template_tokens_like_the_regexes() {
        assert_eq!(replace_token("a {{bucket}} b {{ BUCKET\t}} {{{bucket}}}", "bucket", "1 HOUR"), "a 1 HOUR b 1 HOUR {1 HOUR}");
        assert_eq!(replace_token("{{ bucketx }} {{tz}}", "bucket", "X"), "{{ bucketx }} {{tz}}");
        assert_eq!(replace_token("toTimeZone(t, {{ tz }})", "tz", "'UTC'"), "toTimeZone(t, 'UTC')");
    }

    #[test]
    fn body_errors_report_the_first_zod_message() {
        let parse = |text: &str| parse_query_body(&json::parse(text).unwrap());
        assert_eq!(parse(r#"{"query":"  "}"#).unwrap_err(), "String must contain at least 1 character(s)");
        assert_eq!(parse(r#"{"query":"SELECT 1","siteId":1.5}"#).unwrap_err(), "Expected integer, received float");
        assert_eq!(parse(r#"{"siteId":0}"#).unwrap_err(), "Required");
        assert_eq!(parse("[]").unwrap_err(), "Expected object, received array");
        assert_eq!(parse(r#"{"query":" SELECT 1 ","siteId":3}"#).unwrap(), ("SELECT 1".to_string(), Some(3.0)));
        let card = |text: &str| parse_card_body(&json::parse(text).unwrap()).err();
        assert_eq!(card(r#"{"query":"x","bucket":"decade"}"#).unwrap(), "Invalid enum value. Expected 'minute' | 'five_minutes' | 'ten_minutes' | 'fifteen_minutes' | 'hour' | 'day' | 'week' | 'month' | 'year', received 'decade'");
        assert_eq!(card(r#"{"query":"x","pastMinutesStart":"5"}"#).unwrap(), "Expected number, received string");
        assert!(card(r#"{"query":"x","startDate":"2026-01-01","endDate":"2026-01-02","timeZone":"UTC","bucket":"day"}"#).is_none());
    }

    // Ported from runCustomQuery.test.ts
    #[test]
    fn validate_scoped_query_cases() {
        assert_eq!(validate_scoped_query("SELECT event_name, count() FROM scoped_events GROUP BY event_name"), None);
        assert_eq!(validate_scoped_query("SELECT event_name, count() AS events FROM scoped_events GROUP BY event_name"), None);
        assert_eq!(validate_scoped_query("\n        WITH event_name AS name\n        SELECT name, count()\n        FROM scoped_events\n        GROUP BY name\n      "), None);
        assert_eq!(
            validate_scoped_query("\n        WITH top_events AS (\n          SELECT event_name, count() AS event_count\n          FROM scoped_events\n          GROUP BY event_name\n        )\n        SELECT *\n        FROM top_events\n      "),
            None
        );
        assert_eq!(validate_scoped_query("SELECT count() FROM events").as_deref(), Some("Queries can only read from scoped_events"));
        assert_eq!(
            validate_scoped_query("SELECT count() FROM scoped_events, hourly_events_by_site_mv_target").as_deref(),
            Some("Queries can only read from scoped_events")
        );
        assert_eq!(
            validate_scoped_query("SELECT count() FROM scoped_events; SELECT count() FROM scoped_events").as_deref(),
            Some("Only one SQL statement is allowed")
        );
        assert_eq!(validate_scoped_query("SELECT 'DROP TABLE events' AS label FROM scoped_events LIMIT 1"), None);
        assert_eq!(
            validate_scoped_query("WITH scoped_events AS (SELECT * FROM events) SELECT * FROM scoped_events").as_deref(),
            Some("scoped_events is reserved and cannot be redefined")
        );
        assert_eq!(
            validate_scoped_query("SELECT * FROM scoped_events UNION ALL SELECT * FROM s3('https://example.com')").as_deref(),
            Some("s3() is not allowed in custom analytics queries")
        );
    }
}
