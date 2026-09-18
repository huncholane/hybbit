//! GET /api/admin/clickhouse-stats and GET /api/admin/clickhouse-query-log,
//! ported from server/src/api/admin/getClickhouseStats.ts and
//! getClickhouseQueryLog.ts.
//!
//! Both read ClickHouse system tables and build their SQL with template
//! literals, so the query text is reproduced character for character: it is what
//! lands in `system.query_log`, and for a malformed value it is what ClickHouse
//! echoes back inside the error the handler then inspects.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use tracing::{debug, error, warn};

use crate::{
    analytics::js::{JsValue, number::number_to_string, number::parse_int_10},
    state::AppState,
};

use super::support::{clickhouse_rows, object, row_number, row_value, send_error, send_js};

/// `${value}` for a number in a template literal.
fn number_text(value: f64) -> String {
    number_to_string(value)
}

/// `Math.max` and `Math.min` propagate NaN, and the SQL then carries the text "NaN".
fn js_max(left: f64, right: f64) -> f64 {
    if left.is_nan() || right.is_nan() { f64::NAN } else { left.max(right) }
}

fn js_min(left: f64, right: f64) -> f64 {
    if left.is_nan() || right.is_nan() { f64::NAN } else { left.min(right) }
}

/// A value read off `Object.prototype` by a lookup keyed with request input
/// (`allowedSortColumns[sortBy]`), as a template literal prints it. Such a lookup
/// is truthy, so Node goes on to build SQL around it.
fn object_prototype_text(key: &str) -> Option<&'static str> {
    Some(match key {
        "constructor" => "function Object() { [native code] }",
        "__defineGetter__" => "function __defineGetter__() { [native code] }",
        "__defineSetter__" => "function __defineSetter__() { [native code] }",
        "hasOwnProperty" => "function hasOwnProperty() { [native code] }",
        "__lookupGetter__" => "function __lookupGetter__() { [native code] }",
        "__lookupSetter__" => "function __lookupSetter__() { [native code] }",
        "isPrototypeOf" => "function isPrototypeOf() { [native code] }",
        "propertyIsEnumerable" => "function propertyIsEnumerable() { [native code] }",
        "toString" => "function toString() { [native code] }",
        "valueOf" => "function valueOf() { [native code] }",
        "__proto__" => "[object Object]",
        "toLocaleString" => "function toLocaleString() { [native code] }",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------
// GET /api/admin/clickhouse-stats
// ---------------------------------------------------------------------------------

const TABLE_STATS_QUERY: &str = "
        SELECT
          table,
          sum(rows) as total_rows,
          formatReadableSize(sum(data_compressed_bytes)) as compressed_size,
          sum(data_compressed_bytes) as compressed_bytes,
          formatReadableSize(sum(data_uncompressed_bytes)) as uncompressed_size,
          sum(data_uncompressed_bytes) as uncompressed_bytes,
          count() as parts_count
        FROM system.parts
        WHERE database = currentDatabase() AND active = 1
          AND table IN ('events', 'session_replay_events', 'session_replay_metadata_v2')
        GROUP BY table
        ORDER BY total_rows DESC
      ";

const INSERT_RATE_QUERY: &str = "
          SELECT
            toStartOfHour(event_time) as hour,
            count() as insert_count,
            sum(written_rows) as total_rows_inserted
          FROM system.query_log
          WHERE type = 'QueryFinish'
            AND query_kind = 'Insert'
            AND event_time >= now() - INTERVAL 24 HOUR
          GROUP BY hour
          ORDER BY hour
        ";

const QUERY_ERRORS_QUERY: &str = "
          SELECT
            event_time,
            query_id,
            exception_code,
            exception,
            substring(query, 1, 500) as query
          FROM system.query_log
          WHERE type = 'ExceptionWhileProcessing'
            AND event_time >= now() - INTERVAL 24 HOUR
          ORDER BY event_time DESC
          LIMIT 50
        ";

fn rows_by_date_query(date_filter: &str, date_filter_start_time: &str) -> String {
    format!(
        "
        SELECT date, table, rows_inserted FROM (
          SELECT toDate(timestamp) as date, 'events' as table, count() as rows_inserted
          FROM events
          {date_filter}
          GROUP BY date
          UNION ALL
          SELECT toDate(timestamp) as date, 'session_replay_events' as table, count() as rows_inserted
          FROM session_replay_events
          {date_filter}
          GROUP BY date
          UNION ALL
          SELECT toDate(start_time) as date, 'session_replay_metadata' as table, count() as rows_inserted
          FROM session_replay_metadata_v2
          {date_filter_start_time}
          GROUP BY date
        )
        ORDER BY date, table
      "
    )
}

/// `getClickhouseStats`
pub async fn stats(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let request = match super::admin_chain(&state, &headers, &uri).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    // `request.query.days ? parseInt(request.query.days, 10) : 30`
    let raw_days = request.query.get_or_undefined("days");
    let days = if raw_days.is_truthy() { parse_int_10(&raw_days.to_js_string()) } else { 30.0 };
    let days_interval = if days > 0.0 { days } else { 30.0 };

    let date_filter = if days == 0.0 {
        String::new()
    } else {
        format!("WHERE timestamp >= now() - INTERVAL {} DAY", number_text(days_interval))
    };
    let date_filter_start_time = if days == 0.0 {
        String::new()
    } else {
        format!("WHERE start_time >= now() - INTERVAL {} DAY", number_text(days_interval))
    };

    let mut unavailable_features: Vec<JsValue> = Vec::new();

    let table_stats = match clickhouse_rows(&state, TABLE_STATS_QUERY).await {
        Ok(rows) => rows,
        Err(err) => {
            error!(error = %err, "Failed to get ClickHouse stats");
            return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get ClickHouse stats");
        }
    };
    let rows_by_date = match clickhouse_rows(&state, &rows_by_date_query(&date_filter, &date_filter_start_time)).await {
        Ok(rows) => rows,
        Err(err) => {
            error!(error = %err, "Failed to get ClickHouse stats");
            return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get ClickHouse stats");
        }
    };

    // system.query_log may be disabled to save disk space
    let insert_rate = match clickhouse_rows(&state, INSERT_RATE_QUERY).await {
        Ok(rows) => rows,
        Err(err) => {
            debug!(error = %err, "system.query_log not available - insert rate feature disabled");
            unavailable_features.push(JsValue::String("insertRate".into()));
            Vec::new()
        }
    };
    let query_errors = match clickhouse_rows(&state, QUERY_ERRORS_QUERY).await {
        Ok(rows) => rows,
        Err(err) => {
            debug!(error = %err, "system.query_log not available - query errors feature disabled");
            // The guard only adds "queryErrors" when insertRate is not already listed
            if !unavailable_features.iter().any(|value| value.as_str() == Some("insertRate")) {
                unavailable_features.push(JsValue::String("queryErrors".into()));
            }
            Vec::new()
        }
    };

    let body = object(vec![
        (
            "tableStats",
            JsValue::Array(
                table_stats
                    .iter()
                    .map(|row| {
                        object(vec![
                            ("table", row_value(row, "table")),
                            ("totalRows", JsValue::Number(row_number(row, "total_rows"))),
                            ("compressedSize", row_value(row, "compressed_size")),
                            ("compressedBytes", JsValue::Number(row_number(row, "compressed_bytes"))),
                            ("uncompressedSize", row_value(row, "uncompressed_size")),
                            ("uncompressedBytes", JsValue::Number(row_number(row, "uncompressed_bytes"))),
                            ("partsCount", JsValue::Number(row_number(row, "parts_count"))),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "rowsByDate",
            JsValue::Array(
                rows_by_date
                    .iter()
                    .map(|row| {
                        object(vec![
                            ("date", row_value(row, "date")),
                            ("table", row_value(row, "table")),
                            ("rowsInserted", JsValue::Number(row_number(row, "rows_inserted"))),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "insertRate",
            JsValue::Array(
                insert_rate
                    .iter()
                    .map(|row| {
                        object(vec![
                            ("hour", row_value(row, "hour")),
                            ("insertCount", JsValue::Number(row_number(row, "insert_count"))),
                            ("totalRowsInserted", JsValue::Number(row_number(row, "total_rows_inserted"))),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "queryErrors",
            JsValue::Array(
                query_errors
                    .iter()
                    .map(|row| {
                        object(vec![
                            ("eventTime", row_value(row, "event_time")),
                            ("queryId", row_value(row, "query_id")),
                            // The only member the handler does not convert
                            ("exceptionCode", row_value(row, "exception_code")),
                            ("exception", row_value(row, "exception")),
                            ("query", row_value(row, "query")),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("unavailableFeatures", JsValue::Array(unavailable_features)),
    ]);
    debug!(days = %number_text(days), "Answered the admin ClickHouse stats");
    send_js(StatusCode::OK, &body)
}

// ---------------------------------------------------------------------------------
// GET /api/admin/clickhouse-query-log
// ---------------------------------------------------------------------------------

/// `allowedSortColumns`, plus the `Object.prototype` members a request can reach
/// through the same lookup.
fn sort_column(sort_by: &str) -> String {
    const ALLOWED: &[&str] = &[
        "event_time",
        "query_duration_ms",
        "read_rows",
        "read_bytes",
        "written_rows",
        "written_bytes",
        "memory_usage",
        "type",
        "query_kind",
    ];
    if ALLOWED.contains(&sort_by) {
        return sort_by.to_string();
    }
    // `allowedSortColumns[sortBy] || "event_time"`: an inherited member is truthy
    match object_prototype_text(sort_by) {
        Some(text) => text.to_string(),
        None => "event_time".to_string(),
    }
}

/// `getClickhouseQueryLog`
pub async fn query_log(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let request = match super::admin_chain(&state, &headers, &uri).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let query = &request.query;
    let text = |name: &str| {
        let value = query.get_or_undefined(name);
        if value.is_truthy() { Some(value.to_js_string()) } else { None }
    };

    let page = js_max(1.0, parse_int_10(&text("page").unwrap_or_else(|| "1".into())));
    let page_size = js_min(100.0, js_max(1.0, parse_int_10(&text("pageSize").unwrap_or_else(|| "25".into()))));
    let sort_by = text("sortBy").unwrap_or_else(|| "event_time".into());
    // `request.query.sortOrder === "asc"`: an array never compares equal
    let sort_order = if query.get_or_undefined("sortOrder").as_str() == Some("asc") { "ASC" } else { "DESC" };
    let sort_column = sort_column(&sort_by);
    let offset = (page - 1.0) * page_size;

    let mut conditions = vec![
        "event_time >= now() - INTERVAL 24 HOUR".to_string(),
        "type != 'QueryStart'".to_string(),
        "query NOT LIKE '%system.query_log%'".to_string(),
        "query NOT LIKE '%system.processes%'".to_string(),
    ];
    if let Some(kind) = query.get_or_undefined("queryKind").as_str()
        && ["Select", "Insert", "Other"].contains(&kind)
    {
        conditions.push(format!("query_kind = '{kind}'"));
    }
    if let Some(kind) = query.get_or_undefined("type").as_str()
        && ["QueryFinish", "ExceptionWhileProcessing"].contains(&kind)
    {
        conditions.push(format!("type = '{kind}'"));
    }
    let where_clause = conditions.join(" AND ");

    let count_query = format!(
        "
        SELECT count() as total
        FROM system.query_log
        WHERE {where_clause}
      "
    );
    let rows_query = format!(
        "
        SELECT
          event_time,
          query_id,
          query_kind,
          query_duration_ms,
          read_rows,
          read_bytes,
          written_rows,
          written_bytes,
          memory_usage,
          type,
          exception_code,
          substring(query, 1, 500) as query,
          user,
          databases,
          tables
        FROM system.query_log
        WHERE {where_clause}
        ORDER BY {sort_column} {sort_order}
        LIMIT {}
        OFFSET {}
      ",
        number_text(page_size),
        number_text(offset)
    );

    let unavailable = |message: &str| {
        // `error?.message?.includes("query_log") || error?.message?.includes("UNKNOWN_TABLE")`
        message.contains("query_log") || message.contains("UNKNOWN_TABLE")
    };

    let count_rows = match clickhouse_rows(&state, &count_query).await {
        Ok(rows) => rows,
        Err(err) => return query_log_failure(&err.message(), unavailable(&err.message())),
    };
    let total = count_rows.first().map_or(0.0, |row| {
        let raw = row_value(row, "total");
        // `Number(countRows[0]?.total || 0)`
        if raw.is_truthy() { raw.to_number() } else { 0.0 }
    });

    let rows = match clickhouse_rows(&state, &rows_query).await {
        Ok(rows) => rows,
        Err(err) => return query_log_failure(&err.message(), unavailable(&err.message())),
    };

    let items = rows
        .iter()
        .map(|row| {
            object(vec![
                ("eventTime", row_value(row, "event_time")),
                ("queryId", row_value(row, "query_id")),
                ("queryKind", row_value(row, "query_kind")),
                ("queryDurationMs", JsValue::Number(row_number(row, "query_duration_ms"))),
                ("readRows", JsValue::Number(row_number(row, "read_rows"))),
                ("readBytes", JsValue::Number(row_number(row, "read_bytes"))),
                ("writtenRows", JsValue::Number(row_number(row, "written_rows"))),
                ("writtenBytes", JsValue::Number(row_number(row, "written_bytes"))),
                ("memoryUsage", JsValue::Number(row_number(row, "memory_usage"))),
                ("type", row_value(row, "type")),
                ("exceptionCode", JsValue::Number(row_number(row, "exception_code"))),
                ("query", row_value(row, "query")),
                ("user", row_value(row, "user")),
                ("databases", row_value(row, "databases")),
                ("tables", row_value(row, "tables")),
            ])
        })
        .collect();

    debug!(rows = rows.len(), total, "Answered the admin ClickHouse query log");
    send_js(
        StatusCode::OK,
        &object(vec![
            ("items", JsValue::Array(items)),
            ("total", JsValue::Number(total)),
            ("page", JsValue::Number(page)),
            ("pageSize", JsValue::Number(page_size)),
        ]),
    )
}

/// The catch block: a failure that names the query log answers 200 with
/// `unavailable: true`, anything else is a 500.
fn query_log_failure(message: &str, unavailable: bool) -> Response {
    if unavailable {
        debug!(message, "system.query_log unavailable; answering with an empty page");
        return send_js(
            StatusCode::OK,
            &object(vec![
                ("items", JsValue::Array(Vec::new())),
                ("total", JsValue::Number(0.0)),
                ("page", JsValue::Number(1.0)),
                ("pageSize", JsValue::Number(25.0)),
                ("unavailable", JsValue::Bool(true)),
            ]),
        );
    }
    warn!(message, "Failed to get ClickHouse query log");
    send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get ClickHouse query log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_columns_follow_the_lookup_table() {
        assert_eq!(sort_column("read_rows"), "read_rows");
        assert_eq!(sort_column("bogus"), "event_time");
        assert_eq!(sort_column("constructor"), "function Object() { [native code] }");
        assert_eq!(sort_column("__proto__"), "[object Object]");
    }

    #[test]
    fn pagination_keeps_javascript_nan() {
        assert!(js_max(1.0, parse_int_10("abc")).is_nan());
        assert!(js_min(100.0, f64::NAN).is_nan());
        assert_eq!(number_text(js_min(100.0, js_max(1.0, parse_int_10("500")))), "100");
    }
}
