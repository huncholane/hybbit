//! ClickHouse calls the replay code makes, sent the way `@clickhouse/client` 1.11.1
//! sends `clickhouse.query`, `clickhouse.insert` and `clickhouse.command` (search
//! parameters `query_id`, `param_*`, `database`, `query`; no compression).
//!
//! Queries reuse the analytics executor, which already parses rows like
//! `JSON.parse`. Inserts carry pre-serialised JSONEachRow text rather than serde
//! values because replay rows hold strings with lone surrogates, which only the
//! replay JSON writer can spell the way `JSON.stringify` does. Deletes are commands.

use std::{sync::OnceLock, time::Duration};

use serde_json::{Map, Value};
use tracing::{debug, warn};

use crate::{
    analytics::utils::analytics_query::{
        AnalyticsClickHouse, ClickHouseFailure, QueryParam, QuerySpec, format_query_param, parse_clickhouse_error,
    },
    config::ClickHouseConfig,
};

/// `CLICKHOUSE_REQUEST_TIMEOUT_MS`
const REQUEST_TIMEOUT: Duration = Duration::from_millis(300_000);

pub struct ReplayClickHouse {
    analytics: AnalyticsClickHouse,
    http: reqwest::Client,
    url: String,
    database: String,
    user: String,
    password: String,
}

static STORE: OnceLock<ReplayClickHouse> = OnceLock::new();

/// A random v4 UUID, the client's default `query_id`.
fn query_id() -> String {
    let bits: u128 = rand::random();
    let bits = (bits & !(0xF << 76) & !(0x3 << 62)) | (0x4 << 76) | (0x2 << 62);
    let hex = format!("{bits:032x}");
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// `removeTrailingSemi(query.trim())`
fn command_text(query: &str) -> String {
    let trimmed = crate::analytics::js::string::trim(query);
    match trimmed.trim_end_matches(';') {
        "" => trimmed.to_string(),
        rest => rest.to_string(),
    }
}

impl ReplayClickHouse {
    /// The process-wide client (Node's module singleton `clickhouse`).
    pub fn shared(config: &ClickHouseConfig) -> &'static ReplayClickHouse {
        STORE.get_or_init(|| {
            ReplayClickHouse::new(config).unwrap_or_else(|error| panic!("building the replay ClickHouse client: {error}"))
        })
    }

    fn new(config: &ClickHouseConfig) -> Result<Self, reqwest::Error> {
        Ok(Self {
            analytics: AnalyticsClickHouse::new(config)?,
            http: reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build()?,
            url: config.url.trim_end_matches('/').to_string(),
            database: config.database.clone(),
            user: config.user.clone(),
            password: config.password.clone(),
        })
    }

    /// `clickhouse.query({ query, query_params, format: "JSONEachRow" })` then
    /// `processResults`.
    pub async fn query(&self, spec: &QuerySpec) -> Result<Vec<Map<String, Value>>, ClickHouseFailure> {
        let mut rows = self.analytics.query_rows(spec, &[]).await?;
        crate::analytics::utils::utils::process_results(&mut rows);
        debug!(rows = rows.len(), "replay query finished");
        Ok(rows)
    }

    async fn post(&self, search: Vec<(String, String)>, body: String, operation: &str) -> Result<(), ClickHouseFailure> {
        let response = self
            .http
            .post(format!("{}/", self.url))
            .query(&search)
            .header("X-ClickHouse-User", &self.user)
            .header("X-ClickHouse-Key", &self.password)
            .body(body)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        if status.is_success() {
            return Ok(());
        }
        let info = parse_clickhouse_error(&text);
        warn!(status = status.as_u16(), code = info.code.as_deref().unwrap_or(""), kind = info.kind.as_deref().unwrap_or(""), operation, "ClickHouse rejected a replay request");
        Err(ClickHouseFailure::Server { status: status.as_u16(), info })
    }

    fn search(&self, params: &[(String, QueryParam)]) -> Vec<(String, String)> {
        let mut search = vec![("query_id".to_string(), query_id())];
        for (name, value) in params {
            search.push((format!("param_{name}"), format_query_param(value, false, false)));
        }
        if self.database != "default" {
            search.push(("database".to_string(), self.database.clone()));
        }
        search
    }

    /// `clickhouse.insert({ table, values, format: "JSONEachRow" })` for rows already
    /// serialised one per line. `table` is a fixed name from this module.
    pub async fn insert_json_each_row(&self, table: &str, body: String, rows: usize) -> Result<(), ClickHouseFailure> {
        if rows == 0 {
            return Ok(());
        }
        let bytes = body.len();
        let mut search = self.search(&[]);
        search.push(("query".to_string(), format!("INSERT INTO {table} FORMAT JSONEachRow")));
        self.post(search, body, "insert").await?;
        debug!(table, rows, bytes, "replay rows inserted");
        Ok(())
    }

    /// `clickhouse.command({ query, query_params })`
    pub async fn command(&self, spec: &QuerySpec) -> Result<(), ClickHouseFailure> {
        let search = self.search(&spec.params);
        self.post(search, command_text(&spec.query), "command").await
    }
}

/// `JSON.stringify(error)` for what a failed ClickHouse call throws: the client's
/// `ClickHouseError` has enumerable `code` and `type`; transport failures are plain
/// `Error`s with nothing enumerable.
pub fn serialized_error(failure: &ClickHouseFailure) -> Value {
    match failure {
        ClickHouseFailure::Server { info, .. } if info.code.is_some() => {
            let mut error = Map::new();
            error.insert("code".into(), info.code.clone().map_or(Value::Null, Value::String));
            error.insert("type".into(), info.kind.clone().map_or(Value::Null, Value::String));
            Value::Object(error)
        }
        _ => Value::Object(Map::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_trimmed_like_the_client() {
        assert_eq!(command_text("\n  DELETE FROM t WHERE x = 1;;\n "), "DELETE FROM t WHERE x = 1");
        assert_eq!(command_text(";"), ";");
    }

    #[test]
    fn query_ids_are_v4_uuids() {
        let id = query_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
    }
}
