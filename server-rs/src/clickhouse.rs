use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};

/// Minimal ClickHouse HTTP client. Queries keep the Node backend's SQL verbatim,
/// `{name:Type}` placeholders included: ClickHouse binds those from `param_name`
/// query-string values, so request input never gets spliced into SQL here.
#[derive(Clone)]
pub struct ClickHouse {
    http: reqwest::Client,
    base_url: String,
    database: String,
    user: String,
    password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ClickHouseError {
    #[error("ClickHouse request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("ClickHouse returned {status}: {body}")]
    Server { status: u16, body: String },
    #[error("unexpected ClickHouse row: {0}")]
    Decode(#[from] serde_json::Error),
}

impl ClickHouse {
    pub fn new(base_url: &str, database: &str, user: &str, password: &str) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(300)).build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            database: database.to_string(),
            user: user.to_string(),
            password: password.to_string(),
        })
    }

    /// Run a query and decode each JSONEachRow line into `T`.
    pub async fn query<T: DeserializeOwned>(
        &self,
        sql: &str,
        params: &[(&str, String)],
    ) -> Result<Vec<T>, ClickHouseError> {
        let mut query = vec![
            ("database".to_string(), self.database.clone()),
            ("default_format".to_string(), "JSONEachRow".to_string()),
        ];
        query.extend(params.iter().map(|(name, value)| (format!("param_{name}"), value.clone())));

        let body = self.send(&query, sql.to_string()).await?;
        body.lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).map_err(ClickHouseError::from))
            .collect()
    }

    /// Run a statement that returns no rows (`clickhouse.command` in Node, which
    /// sends `wait_end_of_query=1` so the server buffers the whole response before
    /// answering). `{name:Type}` placeholders bind from `params`, so request input
    /// is never spliced into SQL.
    pub async fn command(&self, sql: &str, params: &[(&str, String)]) -> Result<(), ClickHouseError> {
        let mut query = vec![
            ("database".to_string(), self.database.clone()),
            ("wait_end_of_query".to_string(), "1".to_string()),
        ];
        query.extend(params.iter().map(|(name, value)| (format!("param_{name}"), value.clone())));
        self.send(&query, sql.to_string()).await.map(|_| ())
    }

    /// Insert rows as JSONEachRow, each line spelled the way `JSON.stringify` spells
    /// it (as @clickhouse/client sends it). `table` must be a fixed table name from
    /// this codebase, never request input.
    pub async fn insert<T: Serialize>(&self, table: &str, rows: &[T]) -> Result<(), ClickHouseError> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut body = String::new();
        for row in rows {
            body.push_str(&crate::js_json::to_string(row)?);
            body.push('\n');
        }

        let query = vec![
            ("database".to_string(), self.database.clone()),
            ("query".to_string(), format!("INSERT INTO {table} FORMAT JSONEachRow")),
        ];
        self.send(&query, body).await.map(|_| ())
    }

    pub async fn ping(&self) -> Result<(), ClickHouseError> {
        let response = self.http.get(format!("{}/ping", self.base_url)).send().await?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(ClickHouseError::Server { status: status.as_u16(), body: response.text().await? })
        }
    }

    async fn send(&self, query: &[(String, String)], body: String) -> Result<String, ClickHouseError> {
        let response = self
            .http
            .post(&self.base_url)
            .query(query)
            .header("X-ClickHouse-User", &self.user)
            .header("X-ClickHouse-Key", &self.password)
            .body(body)
            .send()
            .await?;

        let status = response.status();
        let text = response.text().await?;
        if status.is_success() {
            Ok(text)
        } else {
            Err(ClickHouseError::Server { status: status.as_u16(), body: text })
        }
    }
}
