//! The 24 hour and 30 day per-Site event counts that `getAdminSites.ts` and
//! `getAdminOrganizations.ts` both read from `hourly_events_by_site_mv_target`.
//!
//! That table is created by `initializeCloudTables`, which only runs with
//! `CLOUD=true`, so it does not exist in this deployment: the query fails with
//! `UNKNOWN_TABLE`. `getAdminOrganizations` catches that and keeps going with
//! empty maps, `getAdminSites` does not and answers 500 - both are ported as
//! they are, so the endpoints behave identically before and after the cutover.
//!
//! `sum(event_count)` comes back as a JSON string (a UInt64), and Node stores it
//! in the map without converting it, so the counts it prints are strings wherever
//! the table does exist. The values are kept as they arrived here for the same reason.

use chrono::{Days, Local, TimeZone};
use tracing::debug;

use crate::{
    analytics::{js::JsValue, utils::analytics_query::ClickHouseFailure},
    state::AppState,
};

use super::support::{clickhouse_rows, row_number, row_value};

/// `site_id -> total_events`, in the order ClickHouse returned the rows.
#[derive(Clone, Debug, Default)]
pub struct EventCounts(Vec<(f64, JsValue)>);

impl EventCounts {
    /// `map.get(siteId) || 0`
    pub fn get_or_zero(&self, site_id: f64) -> JsValue {
        match self.0.iter().rev().find(|(id, _)| *id == site_id) {
            // Later rows overwrite earlier ones, as repeated `map.set` calls do
            Some((_, value)) if value.is_truthy() => value.clone(),
            _ => JsValue::Number(0.0),
        }
    }

    fn from_rows(rows: &[JsValue]) -> Self {
        Self(rows.iter().map(|row| (row_number(row, "site_id"), row_value(row, "total_events"))).collect())
    }
}

/// The three `DateTime.now()` derived bounds, formatted as Luxon's
/// `toFormat("yyyy-MM-dd HH:mm:ss")` in the process time zone.
pub struct Bounds {
    pub now: String,
    pub yesterday: String,
    pub thirty_days_ago: String,
}

impl Bounds {
    pub fn now() -> Self {
        let now = Local::now();
        // `minus({ hours: 24 })` shifts the instant; `minus({ days: 30 })` walks the
        // calendar and keeps the wall-clock time, which differ only across a DST
        // change (production and the parity stores both run UTC)
        let yesterday = now - chrono::Duration::hours(24);
        let thirty_days_ago = now
            .naive_local()
            .checked_sub_days(Days::new(30))
            .and_then(|naive| Local.from_local_datetime(&naive).earliest())
            .unwrap_or(now - chrono::Duration::days(30));
        Self {
            now: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            yesterday: yesterday.format("%Y-%m-%d %H:%M:%S").to_string(),
            thirty_days_ago: thirty_days_ago.format("%Y-%m-%d %H:%M:%S").to_string(),
        }
    }
}

/// `getAdminSites`'s copy of the query, whitespace included: it is echoed back in
/// the ClickHouse error message that becomes the 500 body.
fn admin_sites_query(from: &str, to: &str) -> String {
    format!(
        "\n      SELECT \n        site_id,\n        sum(event_count) as total_events\n      FROM \n        hourly_events_by_site_mv_target\n      WHERE \n        event_hour >= toDateTime('{from}') AND\n        event_hour <= toDateTime('{to}')\n      GROUP BY \n        site_id\n    "
    )
}

/// `getAdminOrganizations`'s copy of the same query (indented two levels deeper,
/// with no trailing spaces).
fn admin_organizations_query(from: &str, to: &str) -> String {
    format!(
        "\n          SELECT\n            site_id,\n            sum(event_count) as total_events\n          FROM\n            hourly_events_by_site_mv_target\n          WHERE\n            event_hour >= toDateTime('{from}') AND\n            event_hour <= toDateTime('{to}')\n          GROUP BY\n            site_id\n        "
    )
}

/// The two queries `getAdminSites` runs, in order. The first failure escapes the
/// handler, which has no catch block.
pub async fn for_admin_sites(state: &AppState, bounds: &Bounds) -> Result<(EventCounts, EventCounts), ClickHouseFailure> {
    let last_24_hours = clickhouse_rows(state, &admin_sites_query(&bounds.yesterday, &bounds.now)).await?;
    let last_30_days = clickhouse_rows(state, &admin_sites_query(&bounds.thirty_days_ago, &bounds.now)).await?;
    Ok((EventCounts::from_rows(&last_24_hours), EventCounts::from_rows(&last_30_days)))
}

/// The same two queries inside `getAdminOrganizations`'s inner try/catch: a
/// failure leaves both maps empty and the request carries on.
pub async fn for_admin_organizations(state: &AppState, bounds: &Bounds) -> (EventCounts, EventCounts) {
    let mut last_24_hours = EventCounts::default();
    let mut last_30_days = EventCounts::default();
    let loaded = async {
        let first = clickhouse_rows(state, &admin_organizations_query(&bounds.yesterday, &bounds.now)).await?;
        last_24_hours = EventCounts::from_rows(&first);
        let second = clickhouse_rows(state, &admin_organizations_query(&bounds.thirty_days_ago, &bounds.now)).await?;
        last_30_days = EventCounts::from_rows(&second);
        Ok::<(), ClickHouseFailure>(())
    }
    .await;
    if let Err(err) = loaded {
        // `request.log.warn(clickhouseError, "ClickHouse query failed, continuing without event counts")`
        tracing::warn!(error = %err, "ClickHouse query failed, continuing without event counts");
        // A failure partway through leaves the earlier map filled, as in Node
        return (last_24_hours, last_30_days);
    }
    debug!("Loaded admin organization event counts");
    (last_24_hours, last_30_days)
}
