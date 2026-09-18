//! `provisionQueryUser`, ported from server/src/db/clickhouse/queryUser.ts.
//!
//! Least-privilege ClickHouse user for user-authored SQL (custom query page and
//! dashboard cards). Provisioned with SQL at startup so every deployment type
//! (compose, Kubernetes, managed ClickHouse) gets it without hand-editing
//! users.d, and so the limits below are re-applied on upgrade. Requires the main
//! connection to have access_management (the bundled compose sets
//! CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1); otherwise the steps fail, the error
//! is logged, and custom queries fail closed until the user is created by hand.
//!
//! The SQL validator is defense-in-depth on top of this user: a validator bypass
//! must still land inside SELECT-on-events, with no table functions
//! (url/s3/file/remote…), no system tables, and the pinned resource limits.

use serde_json::Value;
use tracing::{error, info};

use crate::{clickhouse::ClickHouse, config::ClickHouseConfig};

struct QueryUserLimits {
    max_execution_time_seconds: u32,
    max_memory_usage_bytes: u64,
    max_threads: u32,
    max_result_rows: u32,
    max_concurrent_queries_for_user: u32,
    max_bytes_before_external_bytes: u64,
}

const QUERY_USER_LIMITS: QueryUserLimits = QueryUserLimits {
    max_execution_time_seconds: 10,
    max_memory_usage_bytes: 4_000_000_000,
    max_threads: 4,
    max_result_rows: 1000,
    max_concurrent_queries_for_user: 8,
    max_bytes_before_external_bytes: 2_000_000_000,
};

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|char| char.is_ascii_alphanumeric() || char == '_')
}

/// `SqlString.escape` from the `sqlstring` package (MySQL flavoured, and accepted by
/// ClickHouse): single quotes around the value with backslash escapes for the control
/// characters and quote characters below. Reproduced rather than swapped for a
/// Postgres-style `''` doubling so a password containing a backslash or a quote
/// produces the same literal Node produces.
fn escape_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('\'');
    for char in value.chars() {
        match char {
            '\0' => escaped.push_str("\\0"),
            '\u{8}' => escaped.push_str("\\b"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\u{1a}' => escaped.push_str("\\Z"),
            '"' => escaped.push_str("\\\""),
            '\'' => escaped.push_str("\\'"),
            '\\' => escaped.push_str("\\\\"),
            other => escaped.push(other),
        }
    }
    escaped.push('\'');
    escaped
}

pub fn build_query_user_statements(database: &str, user: &str, password: &str) -> Result<Vec<String>, &'static str> {
    if !is_identifier(database) || !is_identifier(user) {
        return Err("ClickHouse database and query user names must be plain identifiers");
    }
    let profile = user;
    let secret = escape_string(password);
    let l = &QUERY_USER_LIMITS;
    // readonly=2 lets a query's SETTINGS clause change settings, and for most
    // limits 0 means "unlimited", so each guardrail is marked READONLY (a settings
    // constraint) rather than merely bounded.
    let profile_settings = [
        "readonly = 2 READONLY".to_string(),
        format!("max_execution_time = {} READONLY", l.max_execution_time_seconds),
        format!("max_memory_usage = {} READONLY", l.max_memory_usage_bytes),
        format!("max_threads = {} READONLY", l.max_threads),
        format!("max_result_rows = {} READONLY", l.max_result_rows),
        "result_overflow_mode = 'break' READONLY".to_string(),
        format!("max_concurrent_queries_for_user = {} READONLY", l.max_concurrent_queries_for_user),
        format!("max_bytes_before_external_group_by = {} READONLY", l.max_bytes_before_external_bytes),
        format!("max_bytes_before_external_sort = {} READONLY", l.max_bytes_before_external_bytes),
        "enable_json_type = 1".to_string(),
        "log_queries = 0".to_string(),
    ]
    .join(", ");

    Ok(vec![
        format!("CREATE SETTINGS PROFILE IF NOT EXISTS {profile}"),
        format!("ALTER SETTINGS PROFILE {profile} SETTINGS {profile_settings}"),
        format!("CREATE USER IF NOT EXISTS {user} IDENTIFIED WITH sha256_password BY {secret}"),
        // Re-assert the password and profile so an env change or a drifted user is corrected.
        format!(
            "ALTER USER {user} IDENTIFIED WITH sha256_password BY {secret} SETTINGS PROFILE {}",
            escape_string(profile)
        ),
        // Reset grants to exactly SELECT on the events table.
        format!("REVOKE ALL ON *.* FROM {user}"),
        format!("GRANT SELECT ON {database}.events TO {user}"),
    ])
}

pub async fn provision_query_user(clickhouse: &ClickHouse, config: &ClickHouseConfig) {
    let database = &config.query_grant_database;
    let user = &config.query_user;

    match build_query_user_statements(database, user, &config.query_password) {
        Ok(statements) => {
            let mut failure = None;
            for statement in &statements {
                if let Err(error) = clickhouse.exec(statement, &[]).await {
                    failure = Some(error.to_string());
                    break;
                }
            }
            match failure {
                None => info!(user, database, "ClickHouse query user provisioned"),
                Some(error) => error!(
                    %error,
                    user,
                    "Could not provision ClickHouse user \"{user}\" (the main ClickHouse user needs access_management). \
                     Custom SQL queries and dashboards will fail until it exists with SELECT on {database}.events. \
                     See docs: self-hosting-advanced, Custom SQL queries"
                ),
            }
        }
        Err(error) => error!(%error, user, "Could not provision the ClickHouse query user"),
    }

    // Node builds a second client for this user at import time and pings it here, so a
    // password mismatch is visible at boot rather than on the first dashboard card.
    let probe = ClickHouse::new(&config.url, &config.database, user, &config.query_password);
    let reachable = match probe {
        Ok(client) => client.query::<Value>("SELECT 1", &[]).await.map(|_| ()).map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    if let Err(error) = reachable {
        error!(
            %error,
            user,
            "ClickHouse user \"{user}\" cannot connect; custom SQL queries and dashboards are unavailable \
             (check CLICKHOUSE_QUERY_PASSWORD)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned against the statements Node builds for the same inputs; the whole point
    /// of the port is that the two backends provision the identical profile and grant.
    #[test]
    fn statements_match_node() {
        let statements = build_query_user_statements("analytics", "hygo_query", "hygo").unwrap();
        assert_eq!(
            statements,
            vec![
                "CREATE SETTINGS PROFILE IF NOT EXISTS hygo_query",
                "ALTER SETTINGS PROFILE hygo_query SETTINGS readonly = 2 READONLY, max_execution_time = 10 READONLY, \
                 max_memory_usage = 4000000000 READONLY, max_threads = 4 READONLY, max_result_rows = 1000 READONLY, \
                 result_overflow_mode = 'break' READONLY, max_concurrent_queries_for_user = 8 READONLY, \
                 max_bytes_before_external_group_by = 2000000000 READONLY, \
                 max_bytes_before_external_sort = 2000000000 READONLY, enable_json_type = 1, log_queries = 0",
                "CREATE USER IF NOT EXISTS hygo_query IDENTIFIED WITH sha256_password BY 'hygo'",
                "ALTER USER hygo_query IDENTIFIED WITH sha256_password BY 'hygo' SETTINGS PROFILE 'hygo_query'",
                "REVOKE ALL ON *.* FROM hygo_query",
                "GRANT SELECT ON analytics.events TO hygo_query",
            ]
        );
    }

    #[test]
    fn rejects_non_identifiers() {
        assert!(build_query_user_statements("analytics; DROP", "hygo_query", "x").is_err());
        assert!(build_query_user_statements("analytics", "1bad", "x").is_err());
        assert!(build_query_user_statements("analytics", "hygo_query", "x").is_ok());
    }

    #[test]
    fn escapes_like_sqlstring() {
        assert_eq!(escape_string("plain"), "'plain'");
        assert_eq!(escape_string("it's"), r"'it\'s'");
        assert_eq!(escape_string("a\\b"), r"'a\\b'");
        assert_eq!(escape_string("line\nbreak\ttab\r"), r"'line\nbreak\ttab\r'");
        assert_eq!(escape_string("quote\"d"), "'quote\\\"d'");
        assert_eq!(escape_string("\0\u{8}\u{1a}"), r"'\0\b\Z'");
    }
}
