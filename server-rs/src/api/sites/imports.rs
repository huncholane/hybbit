//! The four import routes, ported from server/src/api/sites/getSiteImports.ts,
//! createSiteImport.ts, batchImportEvents.ts and deleteSiteImport.ts, with the
//! `importStatusManager`, `importQuotaManager` and `importQuotaTracker` services
//! behind them.
//!
//! Quotas are the self-hosted answer throughout. `ImportQuotaTracker.create`
//! short-circuits to `(no usage, Infinity, "190001")` without CLOUD, and
//! `startImport` always allows, so the concurrency 429 and the monthly ceiling
//! cannot fire; what the tracker still does is drop events whose timestamp is
//! malformed or in the future, and that is reproduced. The free-plan 403 on every
//! one of these routes is likewise CLOUD-only and not ported.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::{Value, json};
use sqlx::Row;
use tracing::{debug, error, info, warn};

use super::{
    import_mappers::{self, Platform},
    request::{self, object},
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, SiteRequest, route_scope, site_scoped},
        routes::people::common::path_params,
        utils::analytics_query::parse_clickhouse_error,
    },
    clickhouse::ClickHouseError,
    state::AppState,
};

/// `importPlatforms`, the values `z.enum(importPlatforms)` accepts.
const PLATFORMS: [&str; 3] = ["umami", "simple_analytics", "plausible"];

/// `ImportQuotaTracker`'s self-hosted `oldestAllowedMonth`.
const OLDEST_ALLOWED_MONTH: &str = "190001";

/// `getImportsForSite`'s limit.
const IMPORT_LIST_LIMIT: i64 = 10;

/// The message `@clickhouse/client` puts on the error it throws, which
/// `batchImportEvents` interpolates into its 500. The client parses the server's
/// body down to the text after `Exception:`, so the raw response would not match.
fn clickhouse_message(error: &ClickHouseError) -> String {
    match error {
        ClickHouseError::Server { body, .. } => parse_clickhouse_error(body).message,
        other => other.to_string(),
    }
}

/// `{ error: "Validation error" }`, the one body every schema failure here sends.
fn validation_error() -> Response {
    request::error(StatusCode::BAD_REQUEST, "Validation error")
}

/// `z.string().uuid()` over the `:importId` parameter, and the text Postgres binds.
fn parse_uuid(raw: &str) -> Option<&str> {
    let bytes = raw.as_bytes();
    let groups = [8usize, 4, 4, 4, 12];
    let mut index = 0;
    for (position, size) in groups.iter().enumerate() {
        if position > 0 {
            if bytes.get(index) != Some(&b'-') {
                return None;
            }
            index += 1;
        }
        for _ in 0..*size {
            match bytes.get(index) {
                Some(byte) if byte.is_ascii_hexdigit() => index += 1,
                _ => return None,
            }
        }
    }
    (index == bytes.len()).then_some(raw)
}

/// The `adminSitesRead` or `adminSitesWrite` chain plus the `z.coerce.number()`
/// the import schemas apply to `:siteId`.
async fn import_site(
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    write: bool,
) -> Result<(SiteRequest, f64), Response> {
    let params = path_params(method, uri, &[3]).await?;
    let site = site_scoped(
        state,
        headers,
        uri,
        &params[0],
        SiteGuard::Admin,
        route_scope("sites", if write { "write" } else { "read" }),
        ChainSteps::TIME_ONLY,
    )
    .await?;
    let Some(site_id) = request::coerce_positive_int(&site.site_id) else {
        return Err(validation_error());
    };
    Ok((site, site_id))
}

/// The site's organization, or the 404 `createSiteImport` and `batchImportEvents`
/// send when the Site has none. `Err(None)` is a Postgres failure.
async fn site_organization(state: &AppState, site_id: i32) -> Result<String, Option<Response>> {
    let organization_id: Result<Option<Option<String>>, sqlx::Error> = sqlx::query_scalar(
        r#"SELECT s.organization_id FROM sites s LEFT JOIN organization o ON s.organization_id = o.id
           WHERE s.site_id = $1 LIMIT 1"#,
    )
    .bind(site_id)
    .fetch_optional(&state.pg)
    .await;
    match organization_id {
        Ok(value) => match value.flatten().filter(|id| !id.is_empty()) {
            Some(organization_id) => Ok(organization_id),
            None => Err(Some(request::error(StatusCode::NOT_FOUND, "Site not found"))),
        },
        Err(err) => {
            error!(error = %err, site_id, "Import route could not read the site");
            Err(None)
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/sites/:siteId/imports

pub async fn list(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let (_, site_id) = match import_site(&state, &method, &uri, &headers, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(numeric) = request::pg_int(site_id) else {
        error!(site_id, "Site id is not a Postgres integer; Node's query throws here");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    };

    let rows = sqlx::query(
        r#"SELECT import_id::text AS import_id, platform::text AS platform, imported_events, skipped_events,
                  invalid_events, started_at::text AS started_at, completed_at::text AS completed_at
           FROM import_status WHERE site_id = $1 ORDER BY started_at DESC LIMIT $2"#,
    )
    .bind(numeric)
    .bind(IMPORT_LIST_LIMIT)
    .fetch_all(&state.pg)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(err) => {
            error!(error = %err, site_id = numeric, "Error fetching imports");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };

    let mut data = Vec::with_capacity(rows.len());
    for row in &rows {
        let entry = || -> Result<Value, sqlx::Error> {
            Ok(object(vec![
                ("importId", Value::String(row.try_get("import_id")?)),
                ("platform", Value::String(row.try_get("platform")?)),
                ("importedEvents", Value::from(row.try_get::<i32, _>("imported_events")?)),
                ("skippedEvents", Value::from(row.try_get::<i32, _>("skipped_events")?)),
                ("invalidEvents", Value::from(row.try_get::<i32, _>("invalid_events")?)),
                ("startedAt", Value::String(row.try_get("started_at")?)),
                (
                    "completedAt",
                    row.try_get::<Option<String>, _>("completed_at")?.map_or(Value::Null, Value::String),
                ),
            ]))
        }();
        match entry {
            Ok(entry) => data.push(entry),
            Err(err) => {
                error!(error = %err, site_id = numeric, "Error fetching imports");
                return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
            }
        }
    }
    debug!(site_id = numeric, imports = data.len(), "Imports listed");
    request::send(StatusCode::OK, &json!({ "data": data }))
}

// ---------------------------------------------------------------------------
// POST /api/sites/:siteId/imports

pub async fn create(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (_, site_id) = match import_site(&state, &method, &uri, &headers, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    // `body: z.object({ platform: z.enum(importPlatforms) })`
    let platform = match body.as_ref().and_then(|body| body.get("platform")) {
        Some(Value::String(platform)) if PLATFORMS.contains(&platform.as_str()) => platform.clone(),
        _ => return validation_error(),
    };
    let Some(numeric) = request::pg_int(site_id) else {
        error!(site_id, "Site id is not a Postgres integer; Node's query throws here");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    };
    let organization_id = match site_organization(&state, numeric).await {
        Ok(organization_id) => organization_id,
        Err(Some(response)) => return response,
        Err(None) => return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
    };

    // `createImport`
    let import_id: Result<Option<String>, sqlx::Error> = sqlx::query_scalar(
        r#"INSERT INTO import_status (site_id, organization_id, platform)
           VALUES ($1, $2, $3::import_platform_enum) RETURNING import_id::text"#,
    )
    .bind(numeric)
    .bind(&organization_id)
    .bind(&platform)
    .fetch_optional(&state.pg)
    .await;
    let import_id = match import_id {
        Ok(Some(import_id)) => import_id,
        Ok(None) | Err(_) => {
            error!(site_id = numeric, "Error creating import");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };

    // `DateTime.fromFormat(oldestAllowedMonth + "01", "yyyyMMdd", { zone: "utc" })`
    // with the self-hosted month, and today in UTC
    let earliest = format!("{}-{}-01", &OLDEST_ALLOWED_MONTH[..4], &OLDEST_ALLOWED_MONTH[4..6]);
    let latest = chrono::Utc::now().format("%Y-%m-%d").to_string();
    info!(site_id = numeric, %platform, %import_id, "Import created");
    request::send(
        StatusCode::OK,
        &object(vec![(
            "data",
            object(vec![
                ("importId", Value::String(import_id)),
                (
                    "allowedDateRange",
                    object(vec![
                        ("earliestAllowedDate", Value::String(earliest)),
                        ("latestAllowedDate", Value::String(latest)),
                    ]),
                ),
            ]),
        )]),
    )
}

// ---------------------------------------------------------------------------
// POST /api/sites/:siteId/imports/:importId/events

/// `canImportBatch` with an unlimited quota: the indices whose timestamp parses
/// and is not in the future.
fn allowed_indices(timestamps: &[String]) -> Vec<usize> {
    allowed_indices_at(timestamps, chrono::Utc::now().naive_utc())
}

/// [`allowed_indices`] against a fixed instant, so the rules are testable without
/// a clock. `DateTime.fromFormat(timestamp, "yyyy-MM-dd HH:mm:ss", { zone: "utc" })`
/// is invalid for anything the format does not describe exactly (an ISO `T`
/// separator, an out-of-range month, hour or day-of-month), and `dt > now` is
/// false when the two are equal, so a timestamp at the current instant passes.
fn allowed_indices_at(timestamps: &[String], now: chrono::NaiveDateTime) -> Vec<usize> {
    timestamps
        .iter()
        .enumerate()
        .filter(|(_, timestamp)| {
            match chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S") {
                Ok(parsed) => parsed <= now,
                Err(_) => false,
            }
        })
        .map(|(index, _)| index)
        .collect()
}

/// One `import_status` row as the batch and delete routes read it.
struct ImportRow {
    site_id: i32,
    organization_id: String,
    platform: String,
    completed: bool,
}

/// `getImportById`
async fn import_by_id(state: &AppState, import_id: &str) -> Result<Option<ImportRow>, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT site_id, organization_id, platform::text AS platform, completed_at IS NOT NULL AS completed
           FROM import_status WHERE import_id = $1::uuid LIMIT 1"#,
    )
    .bind(import_id)
    .fetch_optional(&state.pg)
    .await?;
    row.map(|row| {
        Ok(ImportRow {
            site_id: row.try_get("site_id")?,
            organization_id: row.try_get("organization_id")?,
            platform: row.try_get("platform")?,
            completed: row.try_get::<Option<bool>, _>("completed")?.unwrap_or(false),
        })
    })
    .transpose()
}

/// `completeImport`: `DateTime.utc().toISO()` into the `completed_at` column.
async fn complete_import(state: &AppState, import_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE import_status SET completed_at = $1::timestamp WHERE import_id = $2::uuid")
        .bind(super::lifecycle::now_iso())
        .bind(import_id)
        .execute(&state.pg)
        .await
        .map(|_| ())
}

pub async fn batch_events(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match path_params(&method, &uri, &[3, 5]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    // `bodyLimit: 50 * 1024 * 1024` on this route only
    let body = match request::read_body_limited(&headers, body, request::IMPORT_BODY_LIMIT).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Admin,
        route_scope("sites", "write"),
        ChainSteps::TIME_ONLY,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };

    let Some(site_id) = request::coerce_positive_int(&site.site_id) else { return validation_error() };
    let Some(import_id) = parse_uuid(&params[1]) else { return validation_error() };
    let Some(Value::Object(fields)) = body.as_ref() else { return validation_error() };
    let Some(Value::Array(events)) = fields.get("events") else { return validation_error() };
    if !import_mappers::events_union_accepts(events) {
        return validation_error();
    }
    let is_last_batch = match fields.get("isLastBatch") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return validation_error(),
    };

    let Some(numeric) = request::pg_int(site_id) else {
        error!(site_id, "Site id is not a Postgres integer; Node's query throws here");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    };

    let import = match import_by_id(&state, import_id).await {
        Ok(Some(import)) => import,
        Ok(None) => return request::error(StatusCode::NOT_FOUND, "Import not found"),
        Err(err) => {
            error!(error = %err, "Error importing events");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };
    if f64::from(import.site_id) != site_id {
        return request::error(StatusCode::BAD_REQUEST, "Import does not belong to this site");
    }
    // Node reads the Site's organization only to gate on the plan and to release
    // the concurrency slot, neither of which exists here; the 404 it answers when
    // the Site has none is still observable, so the read stays.
    if let Err(response) = site_organization(&state, numeric).await {
        return response
            .unwrap_or_else(|| request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"));
    }

    let Some(platform) = Platform::from_str(&import.platform) else {
        return request::error(StatusCode::BAD_REQUEST, "Unsupported platform");
    };

    let transformed = import_mappers::transform(platform, events, i64::from(numeric), import_id);
    let invalid_events = events.len() - transformed.len();
    let timestamps: Vec<String> = transformed.iter().map(import_mappers::row_timestamp).collect();
    let allowed = allowed_indices(&timestamps);
    let within_quota: Vec<&Value> = allowed.iter().map(|index| &transformed[*index]).collect();
    let skipped = transformed.len() - within_quota.len();

    // Everything from here is inside Node's inner try: a failure completes the
    // import when this is the last batch, then answers 500 with the message
    let outcome: Result<(), String> = async {
        if !within_quota.is_empty() {
            state.clickhouse.insert("events", &within_quota).await.map_err(|error| clickhouse_message(&error))?;
        }
        sqlx::query(
            r#"UPDATE import_status SET imported_events = imported_events + $1,
                   skipped_events = skipped_events + $2, invalid_events = invalid_events + $3
               WHERE import_id = $4::uuid"#,
        )
        .bind(within_quota.len() as i32)
        .bind(skipped as i32)
        .bind(invalid_events as i32)
        .bind(import_id)
        .execute(&state.pg)
        .await
        .map_err(|error| error.to_string())?;
        if is_last_batch {
            complete_import(&state, import_id).await.map_err(|error| error.to_string())?;
        }
        Ok(())
    }
    .await;

    match outcome {
        Ok(()) => {
            info!(
                site_id = numeric,
                import_id,
                imported = within_quota.len(),
                skipped,
                invalid_events,
                is_last_batch,
                "Import batch stored"
            );
            request::empty_ok()
        }
        Err(message) => {
            error!(error = %message, import_id, "Failed to insert imported events");
            if is_last_batch {
                let _ = complete_import(&state, import_id).await;
            }
            request::error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to insert events: {message}"))
        }
    }
}

// ---------------------------------------------------------------------------
// DELETE /api/sites/:siteId/imports/:importId

pub async fn delete_import(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match path_params(&method, &uri, &[3, 5]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    if let Err(response) = request::read_body(&headers, body).await {
        return response;
    }
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Admin,
        route_scope("sites", "write"),
        ChainSteps::TIME_ONLY,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };

    let Some(site_id) = request::coerce_positive_int(&site.site_id) else { return validation_error() };
    let Some(import_id) = parse_uuid(&params[1]) else { return validation_error() };

    let import = match import_by_id(&state, import_id).await {
        Ok(Some(import)) => import,
        Ok(None) => return request::error(StatusCode::NOT_FOUND, "Import not found"),
        Err(err) => {
            error!(error = %err, "Error deleting import");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };
    if f64::from(import.site_id) != site_id {
        return request::error(StatusCode::FORBIDDEN, "Import does not belong to this site");
    }
    if !import.completed {
        return request::error(StatusCode::BAD_REQUEST, "Cannot delete active import");
    }

    let Some(numeric) = request::pg_int(site_id) else {
        error!(site_id, "Site id is not a ClickHouse UInt16");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    };
    if let Err(err) = state
        .clickhouse
        .command(
            "DELETE FROM events WHERE import_id = {importId:UUID} AND site_id = {siteId:UInt16}",
            &[("importId", import_id.to_string()), ("siteId", i64::from(numeric).to_string())],
        )
        .await
    {
        warn!(error = %err, import_id, "Failed to delete imported events");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete imported events");
    }
    if let Err(err) = sqlx::query("DELETE FROM import_status WHERE import_id = $1::uuid")
        .bind(import_id)
        .execute(&state.pg)
        .await
    {
        warn!(error = %err, import_id, "Failed to delete import record");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete import record");
    }
    info!(site_id = numeric, import_id, organization = %import.organization_id, "Import deleted");
    request::empty_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parameters_follow_zod() {
        assert!(parse_uuid("0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001").is_some());
        assert!(parse_uuid("0195F4D5-0F3C-7A5C-8F2A-7F0D2F9F0001").is_some());
        assert!(parse_uuid("0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f000").is_none());
        assert!(parse_uuid("0195f4d50f3c7a5c8f2a7f0d2f9f0001").is_none());
        assert!(parse_uuid("").is_none());
        assert!(parse_uuid("0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001x").is_none());
    }

    #[test]
    fn future_and_malformed_timestamps_are_dropped() {
        let future = (chrono::Utc::now() + chrono::Duration::days(2)).format("%Y-%m-%d %H:%M:%S").to_string();
        let timestamps = vec![
            "2026-05-04 12:30:45".to_string(),
            future,
            "2026-02-31 00:00:00".to_string(),
            "not a timestamp".to_string(),
            "2024-02-29 23:59:59".to_string(),
        ];
        assert_eq!(allowed_indices(&timestamps), vec![0, 4]);
    }

    /// The `canImportBatch` half of
    /// server/src/services/import/importQuotaTracker.test.ts, for the tracker
    /// `create` builds without CLOUD: no usage, an unlimited monthly limit and the
    /// `190001` window. The quota and historical-window cases from that suite have
    /// no self-hosted equivalent (an unlimited limit skips both), so what remains
    /// is the timestamp validation, which the suite asserts still applies.
    mod import_quota_tracker {
        use super::*;

        fn at(text: &str) -> chrono::NaiveDateTime {
            chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S").expect("parses")
        }

        fn batch(timestamps: &[&str]) -> Vec<usize> {
            let owned: Vec<String> = timestamps.iter().map(|value| (*value).to_string()).collect();
            // The suite's fake clock
            allowed_indices_at(&owned, at("2024-06-15 12:00:00"))
        }

        #[test]
        fn allows_every_timestamp_when_unlimited() {
            assert_eq!(batch(&["2024-06-01 10:00:00", "2024-06-02 10:00:00"]), vec![0, 1]);
        }

        #[test]
        fn returns_an_empty_array_for_an_empty_batch() {
            assert_eq!(batch(&[]), Vec::<usize>::new());
        }

        #[test]
        fn rejects_future_timestamps() {
            assert_eq!(batch(&["2024-06-15 12:00:01", "2025-01-01 00:00:00"]), Vec::<usize>::new());
        }

        #[test]
        fn allows_a_timestamp_exactly_at_the_current_time() {
            // `dt > now` is false when equal, so it is not treated as future
            assert_eq!(batch(&["2024-06-15 12:00:00"]), vec![0]);
        }

        #[test]
        fn rejects_invalid_timestamp_strings() {
            assert_eq!(
                batch(&["not-a-date", "2024-06-15T10:00:00", "", "2024-13-01 10:00:00"]),
                Vec::<usize>::new()
            );
        }

        #[test]
        fn keeps_valid_events_interleaved_with_rejected_ones() {
            assert_eq!(batch(&["2024-06-01 10:00:00", "garbage", "2024-06-02 10:00:00"]), vec![0, 2]);
        }

        #[test]
        fn still_rejects_malformed_and_future_timestamps_when_unlimited() {
            assert_eq!(batch(&["not-a-date", "2099-01-01 00:00:00", "2024-06-01 10:00:00"]), vec![2]);
        }

        #[test]
        fn ignores_the_historical_window_when_unlimited() {
            // The window is tier derived, so self-hosted imports reach as far back
            // as the data goes
            assert_eq!(batch(&["2020-01-01 00:00:00"]), vec![0]);
        }
    }
}
