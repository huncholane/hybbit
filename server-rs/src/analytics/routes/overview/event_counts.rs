//! GET /api/sites/:siteId/events/count (server/src/api/analytics/events/getSiteEventCount.ts)
//! and GET /api/org-event-count/:organizationId (getOrgEventCount.ts): events per
//! bucket by type, for one Site or every accessible Site of an Organization.

use axum::http::StatusCode;
use tracing::{debug, warn};

use crate::analytics::{
    js::{JsObject, JsValue},
    types::TimeBucket,
    utils::{
        analytics_query::QuerySpec,
        get_filter_statement::{FilterStatementOptions, get_filter_statement},
        time_window::{resolve_time_window_with_clock, time_bucket_fn},
    },
};

use super::{Outcome, 
    BucketLookup, HandlerError, OverviewBackend, Reply, integral_site_id, is_object_prototype_key, js_number,
    overview::data_rows, route_failure, time_params,
};
use crate::analytics::types::FilterParameter;

/// `buildSiteEventCountQuery(query, siteId)` for a bucket that exists. Binds
/// `{siteId:Int32}` and `{timeZone:String}`.
pub fn build_site_event_count_query(
    query: &JsObject,
    site_id: i64,
    bucket: TimeBucket,
    now: &dyn Fn() -> f64,
) -> Result<String, super::BuildError> {
    let time_statement = resolve_time_window_with_clock(&time_params(query), now)?.where_timestamp();
    let filter_statement = get_filter_statement(
        query.get_or_undefined("filters"),
        Some(site_id),
        Some(&time_statement),
        &FilterStatementOptions::session_level(vec![FilterParameter::Channel]),
    )?;
    let bucket_fn = time_bucket_fn(bucket);
    Ok(format!(
        "
    SELECT
      toDateTime({bucket_fn}(toTimeZone(timestamp, {{timeZone:String}}))) AS time,
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
    WHERE
      site_id = {{siteId:Int32}}
      AND type IN ('pageview', 'custom_event', 'performance', 'outbound', 'error', 'button_click', 'copy', 'form_submit', 'input_change')
      {time_statement}
      {filter_statement}
    GROUP BY time
    ORDER BY time
  "
    ))
}

/// `getSiteEventCount`.
pub(crate) async fn get_site_event_count<B: OverviewBackend>(backend: &B, site_id: &str, query: &JsObject) -> Outcome {
    const LABEL: &str = "site event count";
    let site = js_number(site_id);
    let raw_bucket = match query.get_or_undefined("bucket") {
        JsValue::Undefined => JsValue::from("day"),
        other => other.clone(),
    };
    let key = raw_bucket.to_js_string();
    let lookup = BucketLookup::of(&raw_bucket);
    // `!TimeBucketToFn[bucket]`: inherited Object.prototype members are truthy
    if lookup == BucketLookup::Invalid && !is_object_prototype_key(&key) {
        debug!(site_id = site, bucket = %key, "site event count: invalid bucket");
        return Ok(Reply::error(StatusCode::BAD_REQUEST, format!("Invalid bucket value: {key}")));
    }
    let time_zone = match query.get_or_undefined("time_zone") {
        value if value.is_truthy() => value.clone(),
        _ => JsValue::from("UTC"),
    };

    let result: Result<Reply, HandlerError> = async {
        let numeric_site = integral_site_id(site)?;
        // A prototype member renders its function source into the SQL, which ClickHouse rejects
        let bucket = lookup.require(&raw_bucket);
        let sql = match bucket {
            Ok(bucket) => build_site_event_count_query(query, numeric_site, bucket, &|| backend.now_ms())?,
            Err(rejected) => {
                // Node still builds (and can fail on) the filters first
                build_site_event_count_query(query, numeric_site, TimeBucket::Day, &|| backend.now_ms())?;
                return Err(rejected.into());
            }
        };
        let spec = QuerySpec::new(sql).param("siteId", site).param("timeZone", &time_zone);
        let rows = backend.run_analytics_query(&spec).await?;
        debug!(site_id = site, bucket = %key, rows = rows.len(), "site event count fetched");
        Ok(Reply::ok(data_rows(rows)))
    }
    .await;
    result.or_else(|failure| route_failure(LABEL, &failure))
}

/// `buildOrgEventCountQuery(query, siteIds)`: days counted in the caller's zone,
/// the same one the window and its fill are bounded by.
pub fn build_org_event_count_query(
    query: &JsObject,
    site_ids: &[i64],
    now: &dyn Fn() -> f64,
) -> Result<String, super::BuildError> {
    let window = resolve_time_window_with_clock(&time_params(query), now)?;
    let event_date = window.bucketed("timestamp", TimeBucket::Day);
    let site_list = site_ids.iter().map(i64::to_string).collect::<Vec<_>>().join(", ");
    let where_clause = window.where_timestamp();
    let fill = window.fill(TimeBucket::Day);
    Ok(format!(
        "
      SELECT
        {event_date} as event_date,
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
      WHERE site_id IN ({site_list})
        AND type IN ('pageview', 'custom_event', 'performance', 'outbound', 'error', 'button_click', 'copy', 'form_submit', 'input_change')
        {where_clause}
      GROUP BY event_date
      ORDER BY event_date
      {fill}
    "
    ))
}

/// `getOrgEventCount`.
pub(crate) async fn get_org_event_count<B: OverviewBackend>(
    backend: &B,
    organization_id: &str,
    query: &JsObject,
) -> Outcome {
    const LABEL: &str = "organization event count";
    let site_ids = backend.organization_site_ids(organization_id).await;
    if site_ids.is_empty() {
        warn!(organization_id, "organization event count: no accessible sites");
        return Ok(Reply::error(StatusCode::FORBIDDEN, "No access to organization or no sites found"));
    }
    let result: Result<Reply, HandlerError> = async {
        let sql = build_org_event_count_query(query, &site_ids, &|| backend.now_ms())?;
        let rows = backend.run_analytics_query(&QuerySpec::new(sql)).await?;
        debug!(organization_id, sites = site_ids.len(), rows = rows.len(), "organization event count fetched");
        Ok(Reply::ok(data_rows(rows)))
    }
    .await;
    result.or_else(|failure| route_failure(LABEL, &failure))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> JsObject {
        pairs.iter().map(|(key, value)| (key.to_string(), JsValue::from(*value))).collect()
    }

    #[test]
    fn site_event_count_buckets_in_the_request_zone() {
        let sql = build_site_event_count_query(&query(&[]), 3, TimeBucket::Week, &|| 0.0).unwrap();
        assert!(sql.contains("toDateTime(toStartOfWeek(toTimeZone(timestamp, {timeZone:String}))) AS time"));
        let filtered = build_site_event_count_query(
            &query(&[("filters", r#"[{"parameter":"channel","type":"equals","value":["Direct"]}]"#)]),
            3,
            TimeBucket::Day,
            &|| 0.0,
        )
        .unwrap();
        assert!(filtered.contains("session_id IN ("));
    }

    #[test]
    fn org_event_count_lists_sites_and_fills_days() {
        let sql = build_org_event_count_query(
            &query(&[("start_date", "2026-09-01"), ("end_date", "2026-09-07"), ("time_zone", "America/Chicago")]),
            &[1, 2, 37],
            &|| 0.0,
        )
        .unwrap();
        assert!(sql.contains("WHERE site_id IN (1, 2, 37)"));
        assert!(sql.contains("toDateTime(toStartOfDay(toTimeZone(timestamp, 'America/Chicago'))) as event_date"));
        assert!(sql.contains("WITH FILL FROM"));
    }
}
