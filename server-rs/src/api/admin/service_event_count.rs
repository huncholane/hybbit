//! GET /api/admin/service-event-count, ported from
//! server/src/api/admin/getAdminServiceEventCount.ts: daily counts per event type
//! across every Site, over a window that defaults to the last 30 days in the
//! requested zone.
//!
//! The defaults come from Luxon (`DateTime.now().setZone(time_zone)` then
//! `minus({ days: 30 })` and `toFormat("yyyy-MM-dd")`), so they are calendar
//! dates in that zone. An unusable zone leaves Luxon with an invalid DateTime
//! whose `toFormat` prints "Invalid DateTime"; `resolveTimeWindow` then sees two
//! bounds no date schema accepts and answers over all time, exactly as Node does.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use chrono::{Datelike, Days, TimeZone, Utc};
use chrono_tz::Tz;
use tracing::{debug, error, warn};

use crate::{
    analytics::{
        js::JsValue,
        types::TimeBucket,
        utils::{
            analytics_query::QuerySpec,
            time_window::{TimeWindowParams, resolve_time_window},
            utils::process_results,
        },
    },
    state::AppState,
};

use super::support::{admin_clickhouse, object, send_error, send_js};

/// Luxon's `normalizeZone` for the zone names that reach this handler.
enum Zone {
    /// `FixedOffsetZone`: "utc"/"gmt" in any case
    Utc,
    Iana(Tz),
    /// `setZone` produced an invalid DateTime
    Invalid,
}

fn resolve_zone(time_zone: &str) -> Zone {
    let lowered = time_zone.to_lowercase();
    if lowered == "utc" || lowered == "gmt" {
        return Zone::Utc;
    }
    if time_zone.is_empty() {
        return Zone::Invalid;
    }
    match Tz::from_str_insensitive(time_zone) {
        Ok(tz) => Zone::Iana(tz),
        Err(_) => {
            // `validateTimeParams` already proved Intl accepts the name, so this is
            // an alias chrono-tz does not carry rather than a bad request
            warn!(time_zone, "Time zone unknown to chrono-tz; using UTC for the service event count defaults");
            Zone::Utc
        }
    }
}

/// `DateTime.now().setZone(zone)` then `toFormat("yyyy-MM-dd")`, optionally after
/// `minus({ days })`.
fn today_minus_days(zone: &Zone, days: u64) -> String {
    let now = Utc::now();
    let date = match zone {
        Zone::Invalid => return "Invalid DateTime".to_string(),
        Zone::Utc => now.date_naive(),
        Zone::Iana(tz) => tz.from_utc_datetime(&now.naive_utc()).date_naive(),
    };
    let shifted = if days == 0 { Some(date) } else { date.checked_sub_days(Days::new(days)) };
    match shifted {
        Some(date) => format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day()),
        None => "Invalid DateTime".to_string(),
    }
}

/// `getAdminServiceEventCount`
pub async fn service_event_count(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let request = match super::admin_chain(&state, &headers, &uri).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let query = &request.query;

    // `const { time_zone = "UTC" } = req.query`: only an absent member takes the default
    let raw_time_zone = query.get_or_undefined("time_zone");
    let time_zone =
        if raw_time_zone.is_undefined() { JsValue::String("UTC".into()) } else { raw_time_zone.clone() };
    let zone = resolve_zone(time_zone.as_str().unwrap_or_default());

    let raw_start = query.get_or_undefined("start_date");
    let raw_end = query.get_or_undefined("end_date");
    let start_date =
        if raw_start.is_truthy() { raw_start.clone() } else { JsValue::String(today_minus_days(&zone, 30)) };
    let end_date = if raw_end.is_truthy() { raw_end.clone() } else { JsValue::String(today_minus_days(&zone, 0)) };

    let params = TimeWindowParams {
        start_date,
        end_date,
        time_zone: time_zone.clone(),
        ..TimeWindowParams::default()
    };
    let window = match resolve_time_window(&params) {
        Ok(window) => window,
        Err(_) => {
            // A RangeError from the window builder lands in the handler's catch
            error!("Error fetching service event count: the time window could not be resolved");
            return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch service event count");
        }
    };

    let sql = format!(
        "
      SELECT
        {} as event_date,
        countIf(type = 'pageview') as pageview_count,
        countIf(type = 'custom_event') as custom_event_count,
        countIf(type = 'performance') as performance_count,
        countIf(type = 'outbound') as outbound_count,
        countIf(type = 'error') as error_count,
        countIf(type = 'button_click') as button_click_count,
        countIf(type = 'copy') as copy_count,
        countIf(type = 'form_submit') as form_submit_count,
        countIf(type = 'input_change') as input_change_count,
        count() as event_count
      FROM events
      WHERE type IN ('pageview', 'custom_event', 'performance', 'outbound', 'error', 'button_click', 'copy', 'form_submit', 'input_change')
        {}
      GROUP BY event_date
      ORDER BY event_date
      {}
    ",
        window.bucketed("timestamp", TimeBucket::Day),
        window.where_timestamp(),
        window.fill(TimeBucket::Day)
    );

    let client = match admin_clickhouse(&state) {
        Ok(client) => client,
        Err(err) => {
            error!(error = %err, "Error fetching service event count");
            return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch service event count");
        }
    };
    let mut rows = match client.query_rows(&QuerySpec::new(&sql), &[]).await {
        Ok(rows) => rows,
        Err(err) => {
            error!(error = %err, "Error fetching service event count");
            return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch service event count");
        }
    };
    process_results(&mut rows);

    debug!(days = rows.len(), "Answered the admin service event count");
    send_js(
        StatusCode::OK,
        &object(vec![(
            "data",
            JsValue::Array(rows.iter().map(|row| JsValue::from_serde(&serde_json::Value::Object(row.clone()))).collect()),
        )]),
    )
}
