//! `GET /api/sites/:siteId/usage`, ported from server/src/api/sites/getSiteUsage.ts
//! on the `authSitesRead` chain.
//!
//! Counts the organization's events for the calendar month live from ClickHouse,
//! so the site's share of organization usage is exact. `orgEventLimit` is always
//! `null` here: the limit came from a Stripe subscription, and this deployment has
//! no billing, which is what Node answers with CLOUD unset.
//!
//! `daysElapsed` is Luxon's `now.diff(now.startOf("month"), "days").days`, which
//! for a single unit is the whole calendar days plus the remaining milliseconds
//! over the length of the following day. That is reproduced step for step (rather
//! than as one division) so the double comes out bit for bit the same.

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use chrono::{Datelike, Local, NaiveDate, NaiveDateTime, TimeZone};
use serde_json::Value;
use tracing::{debug, error};

use super::request::{self, object};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        routes::people::common::{clickhouse, path_params},
        utils::{
            analytics_query::{QueryParam, QuerySpec},
            utils::process_results,
        },
    },
    state::AppState,
};

/// `USAGE_COUNTED_EVENT_TYPES` in server/src/lib/const.ts.
const USAGE_COUNTED_EVENT_TYPES: [&str; 8] = [
    "pageview",
    "custom_event",
    "performance",
    "outbound",
    "button_click",
    "copy",
    "form_submit",
    "input_change",
];

const USAGE_QUERY: &str = r#"
        SELECT
          site_id,
          COUNT(*) as count
        FROM events
        WHERE site_id IN {siteIds:Array(UInt16)}
          AND type IN {types:Array(String)}
          AND timestamp >= toDate({periodStart:String})
        GROUP BY site_id
      "#;

/// The month arithmetic `getSiteUsage` does with Luxon in the process's own zone
/// (production and the parity stack both run UTC).
pub struct MonthWindow {
    /// `now.startOf("month").toISODate()`
    pub period_start: String,
    /// `now.daysInMonth ?? 30`
    pub days_in_month: f64,
    /// `now.diff(now.startOf("month"), "days").days`
    pub days_elapsed: f64,
}

fn local_ms(naive: &NaiveDateTime) -> i64 {
    // Luxon resolves an ambiguous local time to the earlier offset
    Local
        .from_local_datetime(naive)
        .earliest()
        .or_else(|| Local.from_local_datetime(naive).latest())
        .map_or(0, |value| value.timestamp_millis())
}

fn days_in_month(date: NaiveDate) -> u32 {
    let (year, month) = (date.year(), date.month());
    let next = if month == 12 { NaiveDate::from_ymd_opt(year + 1, 1, 1) } else { NaiveDate::from_ymd_opt(year, month + 1, 1) };
    match (next, NaiveDate::from_ymd_opt(year, month, 1)) {
        (Some(next), Some(first)) => (next - first).num_days() as u32,
        _ => 30,
    }
}

/// The window for one instant, split out so the arithmetic is testable without a clock.
pub fn month_window_at(now: chrono::DateTime<Local>) -> MonthWindow {
    let naive = now.naive_local();
    let start_date = NaiveDate::from_ymd_opt(naive.year(), naive.month(), 1).unwrap_or(naive.date());
    let start = start_date.and_hms_opt(0, 0, 0).unwrap_or(naive);
    let now_ms = now.timestamp_millis();

    // `dayDiff`: whole calendar days between the two local dates
    let whole_days = (naive.date() - start_date).num_days();
    let cursor = start + chrono::Duration::days(whole_days);
    let cursor_ms = local_ms(&cursor);
    let mut days_elapsed = whole_days as f64;
    if cursor_ms < now_ms {
        let high_water_ms = local_ms(&(cursor + chrono::Duration::days(1)));
        let span = (high_water_ms - cursor_ms) as f64;
        if span != 0.0 {
            days_elapsed += (now_ms - cursor_ms) as f64 / span;
        }
    }

    MonthWindow {
        period_start: start_date.format("%Y-%m-%d").to_string(),
        days_in_month: f64::from(days_in_month(start_date)),
        days_elapsed,
    }
}

pub async fn get_site_usage(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let params = match path_params(&method, &uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Member,
        route_scope("sites", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };

    // `z.coerce.number().int().positive()` over the route parameter
    let Some(site_id) = request::coerce_positive_int(&site.site_id) else {
        return request::error(StatusCode::BAD_REQUEST, "Validation error");
    };
    let Some(numeric) = request::pg_int(site_id) else {
        error!(site_id, "Site id is not a Postgres integer; Node's query throws here");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    };

    let organization_id: Result<Option<Option<String>>, sqlx::Error> =
        sqlx::query_scalar("SELECT organization_id FROM sites WHERE site_id = $1 LIMIT 1")
            .bind(numeric)
            .fetch_optional(&state.pg)
            .await;
    let organization_id = match organization_id {
        Ok(value) => value.flatten().filter(|id| !id.is_empty()),
        Err(err) => {
            error!(error = %err, site_id = numeric, "Error fetching site usage");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };
    // `!site?.organizationId` also covers the empty string
    let Some(organization_id) = organization_id else {
        return request::error(StatusCode::NOT_FOUND, "Site not found");
    };

    let org_site_ids: Result<Vec<i32>, sqlx::Error> =
        sqlx::query_scalar("SELECT site_id FROM sites WHERE organization_id = $1")
            .bind(&organization_id)
            .fetch_all(&state.pg)
            .await;
    let org_site_ids = match org_site_ids {
        Ok(ids) => ids,
        Err(err) => {
            error!(error = %err, site_id = numeric, "Error fetching site usage");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };

    let window = month_window_at(Local::now());
    let spec = QuerySpec::new(USAGE_QUERY)
        .param("siteIds", QueryParam::Array(org_site_ids.iter().map(|id| QueryParam::Number(f64::from(*id))).collect()))
        .param(
            "types",
            QueryParam::Array(USAGE_COUNTED_EVENT_TYPES.iter().map(|kind| QueryParam::String((*kind).to_string())).collect()),
        )
        .param("periodStart", window.period_start.clone());

    let rows = match clickhouse(&state).query_rows(&spec, &[]).await {
        Ok(mut rows) => {
            process_results(&mut rows);
            rows
        }
        Err(err) => {
            error!(error = %err, site_id = numeric, "Error fetching site usage");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };

    let mut site_events = 0f64;
    let mut org_events = 0f64;
    for row in &rows {
        // `parseInt(String(row.count), 10)`
        let count = crate::analytics::js::number::parse_int_10(&js_string(row.get("count")));
        let count = if count.is_nan() { 0.0 } else { count };
        org_events += count;
        if request::js_number(&js_string(row.get("site_id"))) == site_id {
            site_events = count;
        }
    }

    // Too little data in the first day of a month to extrapolate meaningfully
    let projection = (window.days_elapsed >= 1.0).then(|| window.days_in_month / window.days_elapsed);
    let project = |events: f64| match projection {
        None => Value::Null,
        Some(factor) => Value::from(js_round(events * factor)),
    };

    debug!(site_id = numeric, site_events, org_events, "Site usage read");
    request::send(
        StatusCode::OK,
        &object(vec![
            ("periodStart", Value::String(window.period_start)),
            ("daysInMonth", Value::from(window.days_in_month)),
            ("daysElapsed", Value::from(window.days_elapsed)),
            ("siteEventsThisMonth", Value::from(site_events)),
            ("orgEventsThisMonth", Value::from(org_events)),
            // null when self-hosted: the limit came from a subscription
            ("orgEventLimit", Value::Null),
            ("projectedSiteEvents", project(site_events)),
            ("projectedOrgEvents", project(org_events)),
        ]),
    )
}

/// `String(value)` for a value processResults may have left as a string or turned
/// into a number.
fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => {
            crate::js_json::number_to_string(number.as_f64().unwrap_or(f64::NAN))
        }
        Some(other) => crate::js_json::stringify(other),
    }
}

/// `Math.round`: halves go toward positive infinity.
fn js_round(value: f64) -> f64 {
    if value.is_nan() || value.is_infinite() { value } else { (value + 0.5).floor() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> chrono::DateTime<Local> {
        let naive = NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.3f").expect("parses");
        Local.from_local_datetime(&naive).earliest().expect("unambiguous")
    }

    #[test]
    fn month_window_matches_luxon() {
        let window = month_window_at(at("2026-09-18 08:14:22.000"));
        assert_eq!(window.period_start, "2026-09-01");
        assert_eq!(window.days_in_month, 30.0);
        // 17 whole days plus 8h14m22s of the eighteenth
        assert!((window.days_elapsed - (17.0 + (8.0 * 3600.0 + 14.0 * 60.0 + 22.0) * 1000.0 / 86_400_000.0)).abs() < 1e-12);

        let start = month_window_at(at("2026-02-01 00:00:00.000"));
        assert_eq!(start.period_start, "2026-02-01");
        assert_eq!(start.days_in_month, 28.0);
        assert_eq!(start.days_elapsed, 0.0);

        assert_eq!(month_window_at(at("2024-02-10 00:00:00.000")).days_in_month, 29.0);
        assert_eq!(month_window_at(at("2026-12-31 12:00:00.000")).days_elapsed, 30.5);
    }

    #[test]
    fn rounding_matches_math_round() {
        assert_eq!(js_round(0.5), 1.0);
        assert_eq!(js_round(1.4), 1.0);
        assert_eq!(js_round(2.5), 3.0);
        assert_eq!(js_round(0.0), 0.0);
    }

    #[test]
    fn counts_read_like_parse_int() {
        assert_eq!(js_string(Some(&Value::from(42))), "42");
        assert_eq!(js_string(Some(&Value::String("18446744073709551615".into()))), "18446744073709551615");
    }
}
