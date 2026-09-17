//! The queued event (`createBasePayload` in server/src/services/tracker/utils.ts)
//! and the ClickHouse rows built from it (PageviewQueue and BotEventQueue).
//!
//! Node enriches rows with GeoIP when a batch flushes; the databases are static
//! for the life of the process, so Rust enriches when the row is queued.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::{
    bot::BotEventProperties,
    datacenter_asns::is_datacenter_asn,
    geo::{AsnInfo, Geo, Location},
    tracking::{
        channel::get_channel,
        json::{JsValue, parse_json},
        payload::ValidatedTrackingPayload,
        url_params::{clear_self_referrer, get_all_url_params},
    },
    ua::{ParsedUserAgent, get_device_type},
};

/// `TotalTrackingPayload`: the validated event plus what ingestion resolved.
pub struct BasePayload {
    pub site_id: i32,
    pub hostname: String,
    pub pathname: String,
    pub querystring: String,
    pub screen_width: f64,
    pub screen_height: f64,
    pub language: String,
    pub page_title: String,
    pub referrer: String,
    pub event_type: &'static str,
    pub event_name: Option<String>,
    pub properties: Option<String>,
    pub lcp: Option<Option<f64>>,
    pub cls: Option<Option<f64>>,
    pub inp: Option<Option<f64>>,
    pub fcp: Option<Option<f64>>,
    pub ttfb: Option<Option<f64>>,
    pub tag: Option<String>,
    pub feature_flags: Option<IndexMap<String, String>>,
    pub ip_address: String,
    pub received_at: DateTime<Utc>,
    pub ua: Arc<ParsedUserAgent>,
    /// Always the device fingerprint
    pub user_id: String,
    /// The custom user id when identified, "" otherwise
    pub identified_user_id: String,
    /// The Site's `trackIp`
    pub store_ip: bool,
}

impl BasePayload {
    /// The fields of `createBasePayload` that come straight from the payload.
    pub fn new(
        payload: &ValidatedTrackingPayload,
        site_id: i32,
        ip_address: &str,
        received_at: DateTime<Utc>,
        ua: Arc<ParsedUserAgent>,
        user_id: String,
        store_ip: bool,
    ) -> Self {
        let text = |value: &Option<String>| value.clone().unwrap_or_default();
        // `payload.screenWidth || 0`
        let dimension = |value: Option<f64>| value.filter(|number| *number != 0.0 && !number.is_nan()).unwrap_or(0.0);
        Self {
            site_id,
            hostname: text(&payload.hostname),
            pathname: text(&payload.pathname),
            querystring: text(&payload.querystring),
            screen_width: dimension(payload.screen_width),
            screen_height: dimension(payload.screen_height),
            language: text(&payload.language),
            page_title: text(&payload.page_title),
            referrer: text(&payload.referrer),
            event_type: payload.event_type.as_str(),
            event_name: payload.event_name.clone(),
            properties: payload.properties.clone(),
            lcp: payload.lcp,
            cls: payload.cls,
            inp: payload.inp,
            fcp: payload.fcp,
            ttfb: payload.ttfb,
            tag: payload.tag.clone(),
            feature_flags: payload.feature_flags.clone(),
            ip_address: ip_address.to_string(),
            received_at,
            ua,
            user_id,
            // `payload.user_id ? payload.user_id.trim() : ""`
            identified_user_id: payload
                .user_id
                .as_deref()
                .map(|id| crate::tracking::js::js_trim(id).to_string())
                .unwrap_or_default(),
            store_ip,
        }
    }
}

/// `x || ""` for GeoIP strings
fn or_empty(value: &Option<String>) -> String {
    value.clone().filter(|text| !text.is_empty()).unwrap_or_default()
}

/// `x || 0` for coordinates
fn or_zero(value: Option<f64>) -> f64 {
    value.filter(|number| *number != 0.0 && !number.is_nan()).unwrap_or(0.0)
}

/// `countryCode && regionCode ? countryCode + "-" + regionCode : ""`
fn region(location: Option<&Location>) -> String {
    let country = location.map(|l| or_empty(&l.country_iso)).unwrap_or_default();
    let region = location.map(|l| or_empty(&l.region)).unwrap_or_default();
    if !country.is_empty() && !region.is_empty() { format!("{country}-{region}") } else { String::new() }
}

/// A metric as `JSON.stringify` writes `pv.lcp ?? null`: absent, null and
/// non-finite values are all null.
fn metric(value: Option<Option<f64>>) -> Value {
    match value.flatten() {
        Some(number) if number.is_finite() => json!(number),
        _ => Value::Null,
    }
}

/// `getParsedProperties`: the properties string parsed as JSON, or omitted.
///
/// Deviation, deliberately: Node writes whatever `JSON.parse` returns, and a
/// pageview's unvalidated properties such as `"5"` make ClickHouse reject the JSON
/// column, which drops the whole batch of up to 5000 events. Only objects are kept
/// here; anything else is omitted like unparseable text already is.
fn parsed_properties(properties: Option<&str>) -> Option<Value> {
    let text = properties.filter(|text| !text.is_empty())?;
    let parsed = parse_json(text, 64).ok()?.value;
    match parsed {
        JsValue::Object(_) => Some(parsed.to_serde()),
        _ => None,
    }
}

/// `new Date(receivedAt)` formatted by luxon in UTC
fn format_timestamp(received_at: DateTime<Utc>, millis: bool) -> String {
    if millis {
        received_at.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
    } else {
        received_at.format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

/// `PageviewQueue.processQueue`'s filter: a spam source on Rybbit's cloud, kept so
/// both backends store the same rows.
pub fn is_filtered_event(event: &BasePayload) -> bool {
    event.site_id == 9133 && event.screen_width == 800.0 && event.screen_height == 600.0
}

/// One `events` row.
pub fn event_row(event: &BasePayload, session_id: &str, geo: &Geo, asn: Option<AsnInfo>) -> Value {
    let location = geo.location(&event.ip_address);
    let location = location.as_ref();
    let referrer = clear_self_referrer(&event.referrer, &event.hostname).to_string();
    let url_parameters: Map<String, Value> =
        get_all_url_params(&event.querystring).into_iter().map(|(key, value)| (key, Value::String(value))).collect();
    let feature_flags: Map<String, Value> = event
        .feature_flags
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect();

    let mut row = Map::new();
    row.insert("site_id".into(), json!(event.site_id));
    row.insert("timestamp".into(), json!(format_timestamp(event.received_at, false)));
    row.insert("timestamp_ms".into(), json!(format_timestamp(event.received_at, true)));
    row.insert("session_id".into(), json!(session_id));
    row.insert("user_id".into(), json!(event.user_id));
    row.insert("identified_user_id".into(), json!(event.identified_user_id));
    row.insert("hostname".into(), json!(event.hostname));
    row.insert("pathname".into(), json!(event.pathname));
    row.insert("querystring".into(), json!(event.querystring));
    row.insert("page_title".into(), json!(event.page_title));
    row.insert("referrer".into(), json!(referrer));
    row.insert("channel".into(), json!(get_channel(&referrer, &event.querystring, &event.hostname)));
    row.insert("browser".into(), json!(or_empty(&event.ua.browser.name)));
    row.insert("browser_version".into(), json!(or_empty(&event.ua.browser.major)));
    row.insert("operating_system".into(), json!(or_empty(&event.ua.os.name)));
    row.insert("operating_system_version".into(), json!(or_empty(&event.ua.os.version)));
    row.insert("language".into(), json!(event.language));
    row.insert("screen_width".into(), json!(event.screen_width));
    row.insert("screen_height".into(), json!(event.screen_height));
    row.insert(
        "device_type".into(),
        json!(get_device_type(event.screen_width, event.screen_height, &event.ua)),
    );
    let country = location.map(|l| or_empty(&l.country_iso)).unwrap_or_default();
    row.insert("country".into(), json!(country));
    row.insert("region".into(), json!(region(location)));
    row.insert("city".into(), json!(location.map(|l| or_empty(&l.city)).unwrap_or_default()));
    row.insert("lat".into(), json!(or_zero(location.and_then(|l| l.latitude))));
    row.insert("lon".into(), json!(or_zero(location.and_then(|l| l.longitude))));
    row.insert("type".into(), json!(if event.event_type.is_empty() { "pageview" } else { event.event_type }));
    row.insert("event_name".into(), json!(event.event_name.clone().unwrap_or_default()));
    if let Some(props) = parsed_properties(event.properties.as_deref()) {
        row.insert("props".into(), props);
    }
    row.insert("url_parameters".into(), Value::Object(url_parameters));
    row.insert("lcp".into(), metric(event.lcp));
    row.insert("cls".into(), metric(event.cls));
    row.insert("inp".into(), metric(event.inp));
    row.insert("fcp".into(), metric(event.fcp));
    row.insert("ttfb".into(), metric(event.ttfb));
    row.insert("ip".into(), if event.store_ip { json!(event.ip_address) } else { Value::Null });
    row.insert("timezone".into(), json!(location.map(|l| or_empty(&l.time_zone)).unwrap_or_default()));
    row.insert("tag".into(), json!(event.tag.clone().unwrap_or_default()));
    row.insert("feature_flags".into(), Value::Object(feature_flags));
    row.insert("import_id".into(), Value::Null);
    row.insert("asn".into(), asn.as_ref().map_or(Value::Null, |info| json!(info.asn)));
    row.insert("asn_org".into(), json!(asn.as_ref().map(|info| info.organization.clone()).unwrap_or_default()));
    row.insert(
        "is_datacenter_asn".into(),
        json!(u8::from(asn.as_ref().is_some_and(|info| is_datacenter_asn(Some(info.asn))))),
    );
    Value::Object(row)
}

/// One `bot_events` / `bot_observations` row.
pub fn bot_event_row(event: &BasePayload, session_id: &str, geo: &Geo, bot: &BotEventProperties) -> Value {
    let location = geo.location(&event.ip_address);
    let location = location.as_ref();
    let referrer = clear_self_referrer(&event.referrer, &event.hostname).to_string();

    let mut row = Map::new();
    row.insert("site_id".into(), json!(event.site_id));
    row.insert("timestamp".into(), json!(format_timestamp(event.received_at, false)));
    row.insert("session_id".into(), json!(session_id));
    row.insert("user_id".into(), json!(event.user_id));
    row.insert("hostname".into(), json!(event.hostname));
    row.insert("pathname".into(), json!(event.pathname));
    row.insert("querystring".into(), json!(event.querystring));
    row.insert("referrer".into(), json!(referrer));
    row.insert("browser".into(), json!(or_empty(&event.ua.browser.name)));
    row.insert("browser_version".into(), json!(or_empty(&event.ua.browser.major)));
    row.insert("operating_system".into(), json!(or_empty(&event.ua.os.name)));
    row.insert("operating_system_version".into(), json!(or_empty(&event.ua.os.version)));
    let country = location.map(|l| or_empty(&l.country_iso)).unwrap_or_default();
    row.insert("country".into(), json!(country));
    row.insert("region".into(), json!(region(location)));
    row.insert("city".into(), json!(location.map(|l| or_empty(&l.city)).unwrap_or_default()));
    row.insert("lat".into(), json!(or_zero(location.and_then(|l| l.latitude))));
    row.insert("lon".into(), json!(or_zero(location.and_then(|l| l.longitude))));
    row.insert("screen_width".into(), json!(event.screen_width));
    row.insert("screen_height".into(), json!(event.screen_height));
    row.insert(
        "device_type".into(),
        json!(get_device_type(event.screen_width, event.screen_height, &event.ua)),
    );
    row.insert("type".into(), json!(if event.event_type.is_empty() { "pageview" } else { event.event_type }));
    row.insert("asn".into(), bot.bot_asn.map_or(Value::Null, |asn| json!(asn)));
    row.insert("asn_org".into(), json!(bot.bot_asn_org));
    row.insert("detected_ua_pattern".into(), json!(bot.detected_ua_pattern));
    row.insert("detected_header_heuristics".into(), json!(bot.detected_header_heuristics));
    row.insert("detected_client_signals".into(), json!(bot.detected_client_signals));
    row.insert("detected_bot_asn".into(), json!(bot.detected_bot_asn));
    row.insert("detected_rate_anomaly".into(), json!(bot.detected_rate_anomaly));
    row.insert("matched_ua_pattern".into(), json!(bot.matched_ua_pattern));
    row.insert("bot_category".into(), json!(bot.bot_category));
    row.insert("bot_name".into(), json!(bot.bot_name));
    row.insert("bot_operator".into(), json!(bot.bot_operator));
    row.insert("bot_purpose".into(), json!(bot.bot_purpose));
    row.insert("asn_provider".into(), json!(bot.asn_provider));
    row.insert("client_bot_score".into(), bot.client_bot_score.map_or(Value::Null, |score| json!(score)));
    row.insert("client_signal_mask".into(), json!(bot.client_signal_mask.unwrap_or(0)));
    row.insert("anomaly_reasons".into(), json!(bot.anomaly_reasons));
    row.insert("anomaly_score".into(), json!(bot.anomaly_score));
    Value::Object(row)
}
