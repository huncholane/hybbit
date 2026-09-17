//! Port of server/src/api/analytics/utils/analyticsQuery.ts: the query spec
//! handlers build, the executor that runs it the way `@clickhouse/client` 1.11.1
//! does, pagination clauses and the standard analytics error response.
//!
//! The executor is separate from `crate::clickhouse::ClickHouse` because Node
//! sends `max_execution_time` as a setting and formats parameters and the
//! trailing `FORMAT` clause in its own way; keeping the request byte-identical
//! keeps ClickHouse's behaviour (and its query log) identical.

use std::time::{Duration, Instant};

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use fancy_regex::Regex as FancyRegex;
use serde_json::{Map, Value, json};
use std::sync::LazyLock;
use tracing::{debug, error, warn};

use crate::{
    analytics::js::{JsValue, json as js_json_parse, number::{number_to_string, parse_int_10}, string::trim},
    config::ClickHouseConfig,
};

use super::utils::process_results;

/// `MAX_EXECUTION_TIME_SECONDS` for first-party analytics queries.
pub const MAX_EXECUTION_TIME_SECONDS: u32 = 60;
/// `CLICKHOUSE_REQUEST_TIMEOUT_MS`.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(300_000);

/// A value in `query_params`, as `formatQueryParams` understands it.
#[derive(Clone, Debug, PartialEq)]
pub enum QueryParam {
    Undefined,
    Null,
    Number(f64),
    Bool(bool),
    String(String),
    Array(Vec<QueryParam>),
    /// A JavaScript `Date`, as milliseconds since the epoch
    Date(f64),
    /// `TupleParam`
    Tuple(Vec<QueryParam>),
    /// A `Map` or plain object: entries in order
    Map(Vec<(QueryParam, QueryParam)>),
}

impl From<&str> for QueryParam {
    fn from(value: &str) -> Self {
        QueryParam::String(value.to_string())
    }
}

impl From<String> for QueryParam {
    fn from(value: String) -> Self {
        QueryParam::String(value)
    }
}

impl From<i64> for QueryParam {
    fn from(value: i64) -> Self {
        QueryParam::Number(value as f64)
    }
}

impl From<i32> for QueryParam {
    fn from(value: i32) -> Self {
        QueryParam::Number(f64::from(value))
    }
}

impl From<f64> for QueryParam {
    fn from(value: f64) -> Self {
        QueryParam::Number(value)
    }
}

impl From<bool> for QueryParam {
    fn from(value: bool) -> Self {
        QueryParam::Bool(value)
    }
}

impl From<&JsValue> for QueryParam {
    /// A raw request value used as a parameter (Node passes `req.query.x` through).
    fn from(value: &JsValue) -> Self {
        match value {
            JsValue::Undefined => QueryParam::Undefined,
            JsValue::Null => QueryParam::Null,
            JsValue::Bool(flag) => QueryParam::Bool(*flag),
            JsValue::Number(number) => QueryParam::Number(*number),
            JsValue::String(text) => QueryParam::String(text.clone()),
            JsValue::Array(items) => QueryParam::Array(items.iter().map(QueryParam::from).collect()),
            JsValue::Object(object) => QueryParam::Map(
                object.iter().map(|(key, item)| (QueryParam::String(key.to_string()), QueryParam::from(item))).collect(),
            ),
        }
    }
}

/// `formatQueryParams({ value, wrapStringInQuotes, printNullAsKeyword })`.
pub fn format_query_param(value: &QueryParam, wrap_string_in_quotes: bool, print_null_as_keyword: bool) -> String {
    let nested = |item: &QueryParam| format_query_param(item, true, true);
    match value {
        QueryParam::Undefined | QueryParam::Null => {
            if print_null_as_keyword {
                "NULL".to_string()
            } else {
                "\\N".to_string()
            }
        }
        QueryParam::Number(number) if number.is_nan() => "nan".to_string(),
        QueryParam::Number(number) if *number == f64::INFINITY => "+inf".to_string(),
        QueryParam::Number(number) if *number == f64::NEG_INFINITY => "-inf".to_string(),
        QueryParam::Number(number) => number_to_string(*number),
        QueryParam::Bool(flag) => if *flag { "1" } else { "0" }.to_string(),
        QueryParam::String(text) => {
            let mut result = String::with_capacity(text.len());
            for character in text.chars() {
                match character {
                    '\t' => result.push_str("\\t"),
                    '\n' => result.push_str("\\n"),
                    '\r' => result.push_str("\\r"),
                    '\'' => result.push_str("\\'"),
                    '\\' => result.push_str("\\\\"),
                    other => result.push(other),
                }
            }
            if wrap_string_in_quotes { format!("'{result}'") } else { result }
        }
        QueryParam::Array(items) => format!("[{}]", items.iter().map(nested).collect::<Vec<_>>().join(",")),
        QueryParam::Date(ms) => {
            // An invalid Date is not a number to `Number.isNaN`, so it formats as NaN text
            let seconds = number_to_string((ms / 1000.0).floor());
            let unix_timestamp = format!("{seconds:0>10}");
            if ms.is_nan() {
                return format!("{unix_timestamp}.NaN");
            }
            let milliseconds = ms.rem_euclid(1000.0) as i64;
            if milliseconds == 0 { unix_timestamp } else { format!("{unix_timestamp}.{milliseconds:03}") }
        }
        QueryParam::Tuple(items) => format!("({})", items.iter().map(nested).collect::<Vec<_>>().join(",")),
        QueryParam::Map(entries) => format!(
            "{{{}}}",
            entries.iter().map(|(key, item)| format!("{}:{}", nested(key), nested(item))).collect::<Vec<_>>().join(",")
        ),
    }
}

/// `QuerySpec`: a fully built query plus its bound parameters, in insertion order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuerySpec {
    pub query: String,
    pub params: Vec<(String, QueryParam)>,
}

impl QuerySpec {
    pub fn new(query: impl Into<String>) -> Self {
        Self { query: query.into(), params: Vec::new() }
    }

    pub fn param(mut self, name: &str, value: impl Into<QueryParam>) -> Self {
        self.params.push((name.to_string(), value.into()));
        self
    }
}

/// `removeTrailingSemi` then the client's ` \nFORMAT <format>` suffix, after `trim()`.
pub fn format_query(query: &str, format: &str) -> String {
    let trimmed = trim(query);
    // removeTrailingSemi leaves a query made only of semicolons untouched
    let without_semicolons = match trimmed.trim_end_matches(';') {
        "" => trimmed,
        rest => rest,
    };
    format!("{without_semicolons} \nFORMAT {format}")
}

/// What `@clickhouse/client`'s `parseError` makes of an error response body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClickHouseErrorInfo {
    /// `error.message`: the text after `Exception: ` when the body parses,
    /// else the whole body
    pub message: String,
    pub code: Option<String>,
    pub kind: Option<String>,
}

static CLICKHOUSE_ERROR: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(r"(?s)(Code|Error): (?P<code>[0-9]+).*Exception: (?P<message>.+)\((?P<type>(?=.+[A-Z]{3})[A-Z0-9_]+?)\)")
        .expect("static regex")
});

/// Port of `parseError` from `@clickhouse/client-common`.
pub fn parse_clickhouse_error(body: &str) -> ClickHouseErrorInfo {
    match CLICKHOUSE_ERROR.captures(body) {
        Ok(Some(captures)) => ClickHouseErrorInfo {
            message: captures.name("message").map(|m| m.as_str().to_string()).unwrap_or_default(),
            code: captures.name("code").map(|m| m.as_str().to_string()),
            kind: captures.name("type").map(|m| m.as_str().to_string()),
        },
        _ => ClickHouseErrorInfo { message: body.to_string(), code: None, kind: None },
    }
}

/// A failed ClickHouse call, carrying what Node's `error.message` would be.
#[derive(Debug, thiserror::Error)]
pub enum ClickHouseFailure {
    #[error("{0}")]
    Transport(#[from] reqwest::Error),
    #[error("{}", .info.message)]
    Server { status: u16, info: ClickHouseErrorInfo },
    /// A response line `JSON.parse` rejects (e.g. an exception streamed after a 200)
    #[error("Unexpected token in JSON at position {position}")]
    Decode { position: usize },
}

impl ClickHouseFailure {
    /// `error.message` as the Node client would report it.
    pub fn message(&self) -> String {
        self.to_string()
    }
}

/// `AnalyticsQueryError`: the failure plus the SQL that caused it.
#[derive(Debug, thiserror::Error)]
#[error("ClickHouse query failed")]
pub struct AnalyticsQueryError {
    #[source]
    pub original: ClickHouseFailure,
    pub queries: Vec<String>,
}

/// `runPaginatedQuery`'s result.
#[derive(Clone, Debug, PartialEq)]
pub struct PaginatedRows {
    pub data: Vec<Map<String, Value>>,
    /// `countRows[0]?.totalCount ?? 0`
    pub total_count: Value,
}

/// The analytics ClickHouse client (`clickhouse` in server/src/db/clickhouse/client.ts).
#[derive(Clone)]
pub struct AnalyticsClickHouse {
    http: reqwest::Client,
    url: String,
    database: String,
    user: String,
    password: String,
}

fn random_query_id() -> String {
    let bits: u128 = rand::random();
    let bits = (bits & !(0xF << 76) & !(0x3 << 62)) | (0x4 << 76) | (0x2 << 62);
    let hex = format!("{bits:032x}");
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

impl AnalyticsClickHouse {
    pub fn new(config: &ClickHouseConfig) -> Result<Self, reqwest::Error> {
        Self::from_parts(&config.url, &config.database, &config.user, &config.password)
    }

    pub fn from_parts(url: &str, database: &str, user: &str, password: &str) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build()?;
        Ok(Self {
            http,
            url: url.trim_end_matches('/').to_string(),
            database: database.to_string(),
            user: user.to_string(),
            password: password.to_string(),
        })
    }

    /// POST the query the way the Node client does and return the raw body.
    async fn send(
        &self,
        query: &str,
        params: &[(String, QueryParam)],
        settings: &[(&str, String)],
    ) -> Result<String, ClickHouseFailure> {
        let mut search: Vec<(String, String)> = vec![("query_id".to_string(), random_query_id())];
        for (name, value) in params {
            search.push((format!("param_{name}"), format_query_param(value, false, false)));
        }
        for (name, value) in settings {
            search.push((name.to_string(), value.clone()));
        }
        if self.database != "default" {
            search.push(("database".to_string(), self.database.clone()));
        }
        let response = self
            .http
            .post(format!("{}/", self.url))
            .query(&search)
            .header("X-ClickHouse-User", &self.user)
            .header("X-ClickHouse-Key", &self.password)
            .body(format_query(query, "JSONEachRow"))
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        if status.is_success() {
            Ok(text)
        } else {
            Err(ClickHouseFailure::Server { status: status.as_u16(), info: parse_clickhouse_error(&text) })
        }
    }

    /// JSONEachRow rows, each parsed as `JSON.parse` would (key order included).
    pub async fn query_rows(
        &self,
        spec: &QuerySpec,
        settings: &[(&str, String)],
    ) -> Result<Vec<Map<String, Value>>, ClickHouseFailure> {
        let body = self.send(&spec.query, &spec.params, settings).await?;
        let mut rows = Vec::new();
        for line in body.split('\n').filter(|line| !line.is_empty()) {
            let parsed = js_json_parse::parse(line).map_err(|error| ClickHouseFailure::Decode { position: error.position })?;
            match parsed.to_serde() {
                Value::Object(map) => rows.push(map),
                _ => return Err(ClickHouseFailure::Decode { position: 0 }),
            }
        }
        Ok(rows)
    }

    /// `runAnalyticsQuery(spec)`: run with a 60 second cap and `processResults`.
    pub async fn run_analytics_query(&self, spec: &QuerySpec) -> Result<Vec<Map<String, Value>>, AnalyticsQueryError> {
        let started = Instant::now();
        let settings = [("max_execution_time", MAX_EXECUTION_TIME_SECONDS.to_string())];
        match self.query_rows(spec, &settings).await {
            Ok(mut rows) => {
                process_results(&mut rows);
                debug!(rows = rows.len(), elapsed_ms = started.elapsed().as_millis() as u64, "analytics query finished");
                Ok(rows)
            }
            Err(original) => {
                warn!(error = %original, elapsed_ms = started.elapsed().as_millis() as u64, "analytics query failed");
                Err(AnalyticsQueryError { original, queries: vec![spec.query.clone()] })
            }
        }
    }

    /// `runPaginatedQuery(dataSpec, countSpec)`: both queries concurrently.
    pub async fn run_paginated_query(&self, data: &QuerySpec, count: &QuerySpec) -> Result<PaginatedRows, AnalyticsQueryError> {
        let (data_rows, count_rows) = tokio::join!(self.run_analytics_query(data), self.run_analytics_query(count));
        let data_rows = data_rows?;
        let count_rows = count_rows?;
        let total_count = match count_rows.first().and_then(|row| row.get("totalCount")) {
            None | Some(Value::Null) => json!(0),
            Some(value) => value.clone(),
        };
        Ok(PaginatedRows { data: data_rows, total_count })
    }
}

/// `getPaginationStatements`'s result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaginationStatements {
    pub limit_statement: String,
    pub offset_statement: String,
}

/// `getPaginationStatements({ limit, page }, defaultLimit, isCountQuery)` for raw
/// request values (`Undefined` when absent).
pub fn get_pagination_statements(
    limit: &JsValue,
    page: &JsValue,
    default_limit: f64,
    is_count_query: bool,
) -> PaginationStatements {
    if is_count_query {
        return PaginationStatements { limit_statement: String::new(), offset_statement: String::new() };
    }
    let mut validated_limit = None;
    if !limit.is_undefined() {
        let parsed = parse_int_10(&limit.to_js_string());
        if !parsed.is_nan() && parsed > 0.0 {
            validated_limit = Some(parsed);
        }
    }
    let effective_limit = validated_limit.unwrap_or(default_limit);
    let limit_statement = format!("LIMIT {}", number_to_string(effective_limit));

    let mut offset_statement = String::new();
    if !page.is_undefined() {
        let parsed_page = parse_int_10(&page.to_js_string());
        if !parsed_page.is_nan() && parsed_page >= 1.0 {
            let offset = (parsed_page - 1.0) * effective_limit;
            if offset > 0.0 {
                offset_statement = format!("OFFSET {}", number_to_string(offset));
            }
        }
    }
    PaginationStatements { limit_statement, offset_statement }
}

/// `analyticsRoute`'s failure path: log the label (and the failed SQL at debug)
/// and answer 500 `{ "error": "Failed to fetch <label>" }`.
pub fn analytics_route_failure(label: &str, failure: &(dyn std::error::Error + 'static)) -> Response {
    match failure.downcast_ref::<AnalyticsQueryError>() {
        Some(query_error) => {
            error!(err = %query_error.original, label, "Analytics query failed");
            for query in &query_error.queries {
                debug!(query = %query, "Failed analytics query");
            }
        }
        None => error!(err = %failure, label, "Analytics query failed"),
    }
    let body = crate::js_json::to_string(&json!({ "error": format!("Failed to fetch {label}") })).unwrap_or_default();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pagination(limit: JsValue, page: JsValue, default_limit: f64) -> (String, String) {
        let statements = get_pagination_statements(&limit, &page, default_limit, false);
        (statements.limit_statement, statements.offset_statement)
    }

    // Ported from analyticsQuery.test.ts (the executor tests run against the parity ClickHouse instead)
    #[test]
    fn pagination_statements() {
        use JsValue::Undefined;
        assert_eq!(pagination(Undefined, Undefined, 100.0), ("LIMIT 100".into(), String::new()));
        assert_eq!(pagination(JsValue::Number(25.0), Undefined, 100.0).0, "LIMIT 25");
        assert_eq!(pagination("25".into(), Undefined, 100.0).0, "LIMIT 25");
        assert_eq!(pagination("abc".into(), Undefined, 100.0).0, "LIMIT 100");
        assert_eq!(pagination(JsValue::Number(-5.0), Undefined, 100.0).0, "LIMIT 100");
        assert_eq!(pagination(JsValue::Number(0.0), Undefined, 100.0).0, "LIMIT 100");
        assert_eq!(pagination(JsValue::Number(25.0), JsValue::Number(3.0), 100.0).1, "OFFSET 50");
        assert_eq!(pagination(Undefined, JsValue::Number(2.0), 10.0).1, "OFFSET 10");
        assert_eq!(pagination(Undefined, JsValue::Number(1.0), 100.0).1, "");
        assert_eq!(pagination(Undefined, JsValue::Number(0.0), 100.0).1, "");
        assert_eq!(pagination(Undefined, "abc".into(), 100.0).1, "");
        let count = get_pagination_statements(&JsValue::Number(25.0), &JsValue::Number(3.0), 100.0, true);
        assert_eq!((count.limit_statement.as_str(), count.offset_statement.as_str()), ("", ""));
    }

    #[test]
    fn query_params_format_like_the_node_client() {
        assert_eq!(format_query_param(&QueryParam::Undefined, false, false), "\\N");
        assert_eq!(format_query_param(&QueryParam::Number(1.0), false, false), "1");
        assert_eq!(format_query_param(&QueryParam::Number(f64::NAN), false, false), "nan");
        assert_eq!(format_query_param(&QueryParam::Bool(true), false, false), "1");
        assert_eq!(format_query_param(&"a'b\\c\td".into(), false, false), "a\\'b\\\\c\\td");
        assert_eq!(
            format_query_param(&QueryParam::Array(vec![1.into(), "x".into(), QueryParam::Null]), false, false),
            "[1,'x',NULL]"
        );
        assert_eq!(format_query_param(&QueryParam::Date(1_700_000_000_123.0), false, false), "1700000000.123");
        assert_eq!(format_query(" SELECT 1;;\n", "JSONEachRow"), "SELECT 1 \nFORMAT JSONEachRow");
    }

    #[test]
    fn parse_error_like_the_node_client() {
        let body = "Code: 62. DB::Exception: Syntax error: failed at position 5 (end of query). (SYNTAX_ERROR) (version 26.3.17.4 (official build))\n";
        let info = parse_clickhouse_error(body);
        assert_eq!(info.code.as_deref(), Some("62"));
        assert_eq!(info.kind.as_deref(), Some("SYNTAX_ERROR"));
        assert_eq!(info.message, "Syntax error: failed at position 5 (end of query). ");
        assert_eq!(parse_clickhouse_error("socket hang up").message, "socket hang up");
    }

    // Ported from analyticsQuery.test.ts: analyticsRoute maps failures to a labelled 500
    #[tokio::test]
    async fn route_failure_response() {
        let failure = AnalyticsQueryError {
            original: ClickHouseFailure::Decode { position: 3 },
            queries: vec!["SELECT bad".to_string()],
        };
        let response = analytics_route_failure("browser", &failure);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"Failed to fetch browser"}"#);

        let plain = std::io::Error::other("boom");
        let response = analytics_route_failure("things", &plain);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"Failed to fetch things"}"#);
    }

    #[test]
    fn query_ids_are_v4_uuids() {
        let id = random_query_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
    }
}
