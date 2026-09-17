//! The pure parts of server/src/api/analytics/segments/expandSegmentParam.ts:
//! turning `segment_id` into the `filters` query param. The route layer does the
//! two database reads in between (`loadSegmentForSite`, `resolveSegmentActor`),
//! so expansion is split around them:
//!
//! 1. [`segment_param_lookup`]: parse the ids and check the bearer scope.
//! 2. [`apply_loaded_segment`]: visibility, then merge the segment's filters with
//!    the request's own and write `filters` back into the query.

use tracing::debug;

use crate::analytics::{
    js::{JsObject, JsValue, json, number::is_integer},
    utils::query_validation::validate_filters,
};

/// A response that ends the request, as the preHandler sends it.
#[derive(Clone, Debug, PartialEq)]
pub struct SegmentRejection {
    pub status: u16,
    pub body: JsValue,
}

impl SegmentRejection {
    fn error(status: u16, message: &str) -> Self {
        let mut body = JsObject::new();
        body.insert("error", message.into());
        Self { status, body: JsValue::Object(body) }
    }
}

/// Which segment to load. The ids are `Number(raw)` values that passed
/// `Number.isInteger(x) && x > 0`, so they may exceed the Postgres integer range
/// just as they can in Node.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SegmentLookup {
    pub segment_id: f64,
    pub site_id: f64,
}

/// Steps before the database. `Ok(None)` when no `segment_id` was sent.
///
/// `bearer_can_read_segments` is `None` for cookie sessions and unauthenticated
/// viewers, and `Some(hasScope(statements, segments:read))` for bearer
/// credentials.
pub fn segment_param_lookup(
    query: &JsObject,
    site_id_param: Option<&str>,
    bearer_can_read_segments: Option<bool>,
) -> Result<Option<SegmentLookup>, SegmentRejection> {
    let raw = query.get_or_undefined("segment_id");
    if matches!(raw, JsValue::Undefined | JsValue::Null) || raw == &JsValue::String(String::new()) {
        return Ok(None);
    }

    let segment_id = raw.to_number();
    if !is_integer(segment_id) || segment_id <= 0.0 {
        debug!("segment_id is not a positive integer");
        return Err(SegmentRejection::error(400, "Invalid segment_id"));
    }

    let site_id = site_id_param.map_or(f64::NAN, |text| JsValue::from(text).to_number());
    if !is_integer(site_id) || site_id <= 0.0 {
        return Err(SegmentRejection::error(400, "Site ID required"));
    }

    if bearer_can_read_segments == Some(false) {
        debug!(segment_id, "bearer credential lacks segments:read");
        let mut body = JsObject::new();
        body.insert("error", "Insufficient scope".into());
        body.insert("required", "segments:read".into());
        return Err(SegmentRejection { status: 403, body: JsValue::Object(body) });
    }

    Ok(Some(SegmentLookup { segment_id, site_id }))
}

/// What `loadSegmentForSite` found (a segment of this site, or org-wide in its org).
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedSegment {
    /// The `filters` jsonb column as `JSON.parse` returns it
    pub filters: JsValue,
    pub is_public: bool,
}

/// `JSON.stringify([filter.parameter, filter.type, filter.value])`.
fn filter_key(filter: &JsValue) -> String {
    let field = |name: &str| match filter {
        JsValue::Object(object) => object.get_or_undefined(name).clone(),
        _ => JsValue::Undefined,
    };
    json::stringify(&JsValue::Array(vec![field("parameter"), field("type"), field("value")])).unwrap_or_default()
}

/// `mergeSegmentFilters(segmentFilters, extra)`: the segment's filters, then the
/// ad-hoc ones not already in the segment.
pub fn merge_segment_filters(segment_filters: &[JsValue], extra: &[JsValue]) -> Vec<JsValue> {
    let seen: Vec<String> = segment_filters.iter().map(filter_key).collect();
    segment_filters
        .iter()
        .cloned()
        .chain(extra.iter().filter(|filter| !seen.contains(&filter_key(filter))).cloned())
        .collect()
}

/// Steps after the database. `loaded` is `None` when the segment does not exist
/// for this site; `actor_has_site_access` is `resolveSegmentActor(...).hasSiteAccess`.
/// On success `query.filters` holds the merged filters JSON.
pub fn apply_loaded_segment(
    query: &mut JsObject,
    loaded: Option<&LoadedSegment>,
    actor_has_site_access: bool,
) -> Result<(), SegmentRejection> {
    let Some(loaded) = loaded else {
        return Err(SegmentRejection::error(404, "Segment not found"));
    };
    if !(actor_has_site_access || loaded.is_public) {
        debug!("segment is private to site members");
        return Err(SegmentRejection::error(404, "Segment not found"));
    }

    let mut existing: Vec<JsValue> = Vec::new();
    if let JsValue::String(raw_filters) = query.get_or_undefined("filters")
        && !raw_filters.is_empty()
    {
        match validate_filters(raw_filters) {
            Ok(filters) => existing = filters.iter().map(|filter| filter.to_js()).collect(),
            Err(error) => {
                debug!(error = %error, "request filters failed validation during segment expansion");
                return Err(SegmentRejection::error(400, "Invalid filters"));
            }
        }
    }

    // Node calls segmentFilters.map; a non-array column would throw there (a 500)
    let JsValue::Array(segment_filters) = &loaded.filters else {
        return Err(SegmentRejection::error(500, "Internal Server Error"));
    };
    let merged = merge_segment_filters(segment_filters, &existing);
    let text = json::stringify(&JsValue::Array(merged)).unwrap_or_default();
    query.insert("filters", JsValue::String(text));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(parameter: &str, filter_type: &str, values: &[&str]) -> JsValue {
        let mut object = JsObject::new();
        object.insert("parameter", parameter.into());
        object.insert("type", filter_type.into());
        object.insert("value", JsValue::Array(values.iter().map(|&value| value.into()).collect()));
        JsValue::Object(object)
    }

    fn query(pairs: &[(&str, JsValue)]) -> JsObject {
        pairs.iter().map(|(key, value)| (key.to_string(), value.clone())).collect()
    }

    fn loaded(is_public: bool) -> LoadedSegment {
        LoadedSegment {
            filters: JsValue::Array(vec![filter("device_type", "equals", &["Mobile"]), filter("country", "equals", &["DE"])]),
            is_public,
        }
    }

    fn filters_of(query: &JsObject) -> JsValue {
        json::parse(query.get("filters").and_then(JsValue::as_str).unwrap()).unwrap()
    }

    // Ported from expandSegmentParam.test.ts
    #[test]
    fn merge_segment_filters_cases() {
        let mobile = filter("device_type", "equals", &["Mobile"]);
        let germany = filter("country", "equals", &["DE"]);
        let chrome = filter("browser", "equals", &["Chrome"]);
        assert_eq!(
            merge_segment_filters(&[mobile.clone(), germany.clone()], &[chrome.clone(), mobile.clone()]),
            vec![mobile.clone(), germany, chrome]
        );
        let mobile_tablet = filter("device_type", "equals", &["Mobile", "Tablet"]);
        assert_eq!(merge_segment_filters(std::slice::from_ref(&mobile), std::slice::from_ref(&mobile_tablet)), vec![mobile, mobile_tablet]);
    }

    #[test]
    fn expansion_flow() {
        let chrome_json = json::stringify(&JsValue::Array(vec![filter("browser", "equals", &["Chrome"])])).unwrap();

        // Absent: nothing happens
        let absent = query(&[("filters", chrome_json.clone().into())]);
        assert_eq!(segment_param_lookup(&absent, Some("1"), None), Ok(None));

        // Expands, segment first
        let mut with_filters = query(&[("segment_id", "7".into()), ("filters", chrome_json.clone().into())]);
        assert!(segment_param_lookup(&with_filters, Some("1"), None).unwrap().is_some());
        apply_loaded_segment(&mut with_filters, Some(&loaded(false)), true).unwrap();
        assert_eq!(
            filters_of(&with_filters),
            JsValue::Array(vec![
                filter("device_type", "equals", &["Mobile"]),
                filter("country", "equals", &["DE"]),
                filter("browser", "equals", &["Chrome"])
            ])
        );

        // Numeric segment id, no ad-hoc filters
        let mut numeric = query(&[("segment_id", JsValue::Number(7.0))]);
        assert!(segment_param_lookup(&numeric, Some("1"), None).unwrap().is_some());
        apply_loaded_segment(&mut numeric, Some(&loaded(false)), true).unwrap();
        assert_eq!(filters_of(&numeric), loaded(false).filters);

        // Malformed id
        let rejection = segment_param_lookup(&query(&[("segment_id", "seven".into())]), Some("1"), None).unwrap_err();
        assert_eq!(rejection.status, 400);
        assert_eq!(json::stringify(&rejection.body).unwrap(), r#"{"error":"Invalid segment_id"}"#);

        // Outside the site
        let mut outside = query(&[("segment_id", "7".into())]);
        assert_eq!(apply_loaded_segment(&mut outside, None, true).unwrap_err().status, 404);

        // Private segment hidden from public viewers, public one expands
        let mut private = query(&[("segment_id", "7".into())]);
        assert_eq!(apply_loaded_segment(&mut private, Some(&loaded(false)), false).unwrap_err().status, 404);
        let mut public = query(&[("segment_id", "7".into())]);
        apply_loaded_segment(&mut public, Some(&loaded(true)), false).unwrap();
        assert_eq!(filters_of(&public), loaded(true).filters);

        // Bearer scope
        let denied = segment_param_lookup(&query(&[("segment_id", "7".into())]), Some("1"), Some(false)).unwrap_err();
        assert_eq!(denied.status, 403);
        assert_eq!(json::stringify(&denied.body).unwrap(), r#"{"error":"Insufficient scope","required":"segments:read"}"#);
        assert!(segment_param_lookup(&query(&[("segment_id", "7".into())]), Some("1"), Some(true)).unwrap().is_some());

        // Invalid ad-hoc filters
        let mut invalid = query(&[("segment_id", "7".into()), ("filters", "not json".into())]);
        let rejection = apply_loaded_segment(&mut invalid, Some(&loaded(false)), true).unwrap_err();
        assert_eq!(rejection.status, 400);
        assert_eq!(json::stringify(&rejection.body).unwrap(), r#"{"error":"Invalid filters"}"#);
    }
}
