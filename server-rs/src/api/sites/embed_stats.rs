//! `GET /api/sites/:siteId/embed-stats`, ported from
//! server/src/api/sites/getEmbedStats.ts. This is the only route in the group with
//! no access guard: it is registered with `resolveSiteId` alone and the handler
//! decides for itself, by requiring `embedEnabled` on the Site.
//!
//! The per-process 60 second cache is kept, and so is its quirk that the
//! `Cache-Control: public, max-age=60` header only rides on the success answers.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use serde_json::Value;
use tracing::{debug, error};

use super::request::{self, object};
use crate::{
    analytics::{
        chain::fastify_query,
        js::JsValue,
        routes::people::common::{clickhouse, path_params},
        utils::{
            analytics_query::{QueryParam, QuerySpec},
            utils::process_results,
        },
    },
    auth::guards::resolve_site_id,
    site_config::SiteRef,
    state::AppState,
};

/// `CACHE_TTL_MS`
const CACHE_TTL: Duration = Duration::from_secs(60);
/// `ALLOWED_MINUTES`
const ALLOWED_MINUTES: [f64; 3] = [30.0, 1440.0, 10080.0];

/// The module-level `cache` in getEmbedStats.ts. Keys are attacker-shaped (the
/// identifier spelling is part of them), so the map is swept on write.
static CACHE: LazyLock<Mutex<HashMap<String, (Instant, Value)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// `bucketExpr`
fn bucket_expr(minutes: f64) -> &'static str {
    if minutes == 30.0 {
        "toStartOfMinute(timestamp)"
    } else if minutes == 1440.0 {
        "toStartOfHour(timestamp)"
    } else {
        "toStartOfDay(timestamp)"
    }
}

const COUNT_QUERY: &str = r#"SELECT COUNT(DISTINCT(session_id)) AS count FROM events
            WHERE timestamp > now() - interval {minutes:Int32} minute
              AND site_id = {siteId:Int32}"#;

const COUNTRIES_QUERY: &str = r#"SELECT country,
                     COUNT(DISTINCT session_id) AS users
              FROM events
              WHERE timestamp > now() - interval {minutes:Int32} minute
                AND site_id = {siteId:Int32}
                AND country != ''
              GROUP BY country
              ORDER BY users DESC
              LIMIT 5"#;

fn series_query(minutes: f64) -> String {
    format!(
        r#"SELECT toString({}) AS time,
                     COUNT(DISTINCT session_id) AS users
              FROM events
              WHERE timestamp > now() - interval {{minutes:Int32}} minute
                AND site_id = {{siteId:Int32}}
              GROUP BY time
              ORDER BY time"#,
        bucket_expr(minutes)
    )
}

fn with_cache_header(mut response: Response) -> Response {
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=60"));
    response
}

/// `Number(value)` where `value` may be the array Fastify builds for a repeated
/// query parameter: `Number(["30"])` is 30, `Number(["30","30"])` is NaN.
fn query_number(value: &JsValue) -> f64 {
    request::js_number(&value.to_js_string())
}

pub async fn get_embed_stats(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    _headers: HeaderMap,
) -> Response {
    let params = match path_params(&method, &uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    // The route's only preHandler
    let site_id = match resolve_site_id(&state, &params[0]).await {
        Ok(site_id) => site_id,
        Err(response) => return response,
    };
    let query = fastify_query(&uri);

    // `Number(req.query.minutes ?? 30)`
    let minutes = match query.get("minutes") {
        None | Some(JsValue::Undefined) => 30.0,
        Some(value) => query_number(value),
    };
    if !ALLOWED_MINUTES.contains(&minutes) {
        return request::error(StatusCode::BAD_REQUEST, "Invalid minutes. Allowed: 30, 1440, 10080");
    }
    let include_chart = query.get("chart").and_then(JsValue::as_str) == Some("true");
    let include_countries = query.get("countries").and_then(JsValue::as_str) == Some("true");

    let Some(config) = state.site_config.get_config(&SiteRef::Text(site_id.clone())).await else {
        return request::error(StatusCode::NOT_FOUND, "Site not found");
    };
    if !config.embed_enabled {
        return request::error(StatusCode::FORBIDDEN, "Embed widget is not enabled for this site");
    }

    let cache_key = format!(
        "{site_id}:{}:{include_chart}:{include_countries}",
        crate::js_json::number_to_string(minutes)
    );
    if let Some(cached) = cached(&cache_key) {
        debug!(site_id = %site_id, minutes, "Embed stats served from cache");
        return with_cache_header(request::send(StatusCode::OK, &cached));
    }

    let numeric = request::js_number(&site_id);
    let Some(numeric) = request::pg_int(numeric) else {
        error!(site_id = %site_id, "Site id is not a ClickHouse Int32");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    };
    let bind = |spec: QuerySpec| {
        spec.param("siteId", QueryParam::Number(f64::from(numeric))).param("minutes", QueryParam::Number(minutes))
    };

    let count_rows = match run(&state, bind(QuerySpec::new(COUNT_QUERY))).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    // `Number(countRows[0]?.count ?? 0)`
    let count = count_rows
        .first()
        .and_then(|row| row.get("count"))
        .map_or(0.0, |value| request::js_number(&value_to_string(value)));

    let mut series: Vec<Value> = Vec::new();
    if include_chart {
        let rows = match run(&state, bind(QuerySpec::new(series_query(minutes)))).await {
            Ok(rows) => rows,
            Err(response) => return response,
        };
        for row in &rows {
            series.push(object(vec![
                ("time", row.get("time").cloned().unwrap_or(Value::Null)),
                ("users", Value::from(request::js_number(&value_to_string(row.get("users").unwrap_or(&Value::Null))))),
            ]));
        }
    }

    let mut top_countries: Vec<Value> = Vec::new();
    if include_countries {
        let rows = match run(&state, bind(QuerySpec::new(COUNTRIES_QUERY))).await {
            Ok(rows) => rows,
            Err(response) => return response,
        };
        for row in &rows {
            top_countries.push(object(vec![
                ("country", row.get("country").cloned().unwrap_or(Value::Null)),
                ("users", Value::from(request::js_number(&value_to_string(row.get("users").unwrap_or(&Value::Null))))),
            ]));
        }
    }

    let data = object(vec![
        ("count", Value::from(count)),
        ("series", Value::Array(series)),
        ("topCountries", Value::Array(top_countries)),
    ]);
    store(cache_key, data.clone());
    debug!(site_id = %site_id, minutes, include_chart, include_countries, "Embed stats computed");
    with_cache_header(request::send(StatusCode::OK, &data))
}

/// A ClickHouse read with the plain client's settings (no `max_execution_time`),
/// then `processResults`. A failure escapes the handler, which has no try/catch,
/// so Fastify's default error handler answers with the thrown message.
async fn run(state: &AppState, spec: QuerySpec) -> Result<Vec<serde_json::Map<String, Value>>, Response> {
    match clickhouse(state).query_rows(&spec, &[]).await {
        Ok(mut rows) => {
            process_results(&mut rows);
            Ok(rows)
        }
        Err(err) => {
            let message = err.message();
            error!(error = %message, "Embed stats query failed");
            Err(crate::analytics::routes::people::common::uncaught_error(&message))
        }
    }
}

/// `String(value)` for `Number(value)` on a value processResults may have left as
/// a string.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => crate::js_json::number_to_string(number.as_f64().unwrap_or(f64::NAN)),
        Value::Null => "null".to_string(),
        other => crate::js_json::stringify(other),
    }
}

fn cached(key: &str) -> Option<Value> {
    let cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.get(key).filter(|(expires, _)| *expires > Instant::now()).map(|(_, data)| data.clone())
}

fn store(key: String, data: Value) {
    let mut cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    // Node never sweeps this map; Rust drops expired entries so an attacker-chosen
    // key space cannot grow without bound. Answers are unchanged either way.
    if cache.len() > 10_000 {
        cache.retain(|_, (expires, _)| *expires > now);
    }
    cache.insert(key, (now + CACHE_TTL, data));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_follow_the_window() {
        assert_eq!(bucket_expr(30.0), "toStartOfMinute(timestamp)");
        assert_eq!(bucket_expr(1440.0), "toStartOfHour(timestamp)");
        assert_eq!(bucket_expr(10080.0), "toStartOfDay(timestamp)");
    }

    #[test]
    fn only_the_three_windows_are_allowed() {
        assert!(ALLOWED_MINUTES.contains(&30.0));
        assert!(!ALLOWED_MINUTES.contains(&31.0));
        assert!(!ALLOWED_MINUTES.contains(&f64::NAN));
    }
}
