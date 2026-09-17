//! `SessionReplayIngestService` (server/src/services/replay/sessionReplayIngestService.ts)
//! and `parseTrackingData` (trackingUtils.ts): one validated batch becomes
//! `session_replay_events` rows and, when the recorder sent metadata, one
//! append-only `session_replay_metadata_v2` row.
//!
//! Row JSON is written field by field in Node's key order with `JSON.stringify`
//! spellings (see `json`), so ClickHouse parses the same bytes from either backend.
//! R2 storage is cloud-only and disabled in this deployment, so event data always
//! goes to ClickHouse (`event_data_key` and `batch_index` null).

use std::future::Future;

use chrono::{DateTime, Local, TimeZone, Utc};
use tracing::{debug, error, warn};

use super::{
    clock_skew::correct_replay_clock_skew,
    json::{JsString, quote_str},
    page_url::whatwg_url,
    schema::{EventType, ReplayBatch, ReplayEvent, ReplayMetadata},
};
use crate::{
    analytics::utils::analytics_query::ClickHouseFailure,
    geo::Location,
    identity::UserIdError,
    tracking::{channel::get_channel, url_params::clear_self_referrer},
    ua::{self, get_device_type},
};

pub const EVENTS_TABLE: &str = "session_replay_events";
pub const METADATA_TABLE: &str = "session_replay_metadata_v2";

/// `RequestMetadata`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestMeta {
    pub user_agent: String,
    pub ip_address: String,
    pub origin: String,
    pub referrer: String,
}

/// Why `recordEvents` threw; the handler answers 500 for all of them.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error(transparent)]
    UserId(#[from] UserIdError),
    /// `JSON.stringify(undefined).length`: an event without a `data` key
    #[error("Cannot read properties of undefined (reading 'length')")]
    MissingEventData { index: usize },
    #[error("ClickHouse insert into {table} failed: {failure}")]
    Insert { table: &'static str, failure: ClickHouseFailure },
}

/// What recording needs from the outside world. Production wires Redis, the Site
/// Configuration, GeoIP and ClickHouse; tests substitute recorders.
pub trait IngestDeps: Sync {
    /// `userIdService.generateUserId(ip, userAgent, siteId)`
    fn generate_user_id(&self, ip: &str, user_agent: &str, site_id: i32) -> impl Future<Output = Result<String, UserIdError>> + Send;
    /// `sessionsService.updateSession({ userId, identifiedUserId, siteId })`
    fn update_session(&self, user_id: &str, identified_user_id: &str, site_id: i32) -> impl Future<Output = String> + Send;
    /// `clickhouse.insert` of pre-serialised JSONEachRow lines
    fn insert(&self, table: &'static str, body: String, rows: usize) -> impl Future<Output = Result<(), ClickHouseFailure>> + Send;
    /// `getLocation([ip])[ip]`
    fn location(&self, ip: &str) -> Option<Location>;
    /// `Date.now()`
    fn now_ms(&self) -> f64;
    /// A metadata bound as luxon formats it, in the process's local zone
    fn format_time(&self, ms: f64) -> String {
        format_datetime_ms(ms, &Local)
    }
}

/// A JSON object written key by key.
struct RowWriter {
    out: String,
    first: bool,
}

impl RowWriter {
    fn new(out: String) -> Self {
        let mut out = out;
        out.push('{');
        Self { out, first: true }
    }

    fn key(&mut self, name: &str) -> &mut String {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        quote_str(&mut self.out, name);
        self.out.push(':');
        &mut self.out
    }

    fn str(&mut self, name: &str, value: &str) {
        quote_str(self.key(name), value);
    }

    fn js_str(&mut self, name: &str, value: &JsString) {
        value.write_quoted(self.key(name));
    }

    /// A JavaScript number: non-finite values serialise as null
    fn number(&mut self, name: &str, value: f64) {
        let out = self.key(name);
        if value.is_finite() {
            out.push_str(ryu_js::Buffer::new().format(value));
        } else {
            out.push_str("null");
        }
    }

    fn null(&mut self, name: &str) {
        self.key(name).push_str("null");
    }

    /// `value || null` for an optional number
    fn number_or_null(&mut self, name: &str, value: Option<f64>) {
        match value.filter(|number| is_truthy(*number)) {
            Some(number) => self.number(name, number),
            None => self.null(name),
        }
    }

    fn finish(mut self) -> String {
        self.out.push_str("}\n");
        self.out
    }
}

fn is_truthy(number: f64) -> bool {
    number != 0.0 && !number.is_nan()
}

/// `value || 0`
fn or_zero(value: Option<f64>) -> f64 {
    value.filter(|number| is_truthy(*number)).unwrap_or(0.0)
}

/// `TrackingData`; `Default` is Node's `{}` when parsing was skipped or failed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrackingData {
    pub browser: String,
    pub browser_version: String,
    pub operating_system: String,
    pub operating_system_version: String,
    pub device_type: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub lat: f64,
    pub lon: f64,
    pub channel: String,
    pub language: Option<JsString>,
    pub hostname: String,
    pub referrer: String,
}

/// `parseTrackingData(userAgent, ipAddress, referrer, querystring, hostname,
/// language, screenWidth, screenHeight)`
#[allow(clippy::too_many_arguments)]
pub fn parse_tracking_data(
    location: Option<Location>,
    user_agent: &str,
    referrer: &str,
    querystring: &str,
    hostname: &str,
    language: Option<&JsString>,
    screen_width: f64,
    screen_height: f64,
) -> TrackingData {
    // UAParser(userAgent), uncached like the Node call
    let parsed = ua::parse(user_agent);
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    let location = location.unwrap_or_default();
    let country = text(&location.country_iso);
    let region_code = text(&location.region);
    // Clear self-referrer if it's from the same domain
    let referrer = clear_self_referrer(referrer, hostname);

    TrackingData {
        browser: text(&parsed.browser.name),
        browser_version: text(&parsed.browser.major),
        operating_system: text(&parsed.os.name),
        operating_system_version: text(&parsed.os.version),
        device_type: get_device_type(screen_width, screen_height, &parsed).to_string(),
        region: if !country.is_empty() && !region_code.is_empty() { format!("{country}-{region_code}") } else { String::new() },
        country,
        city: text(&location.city),
        lat: or_zero(location.latitude),
        lon: or_zero(location.longitude),
        channel: get_channel(referrer, querystring, hostname).to_string(),
        language: language.filter(|language| !language.is_empty()).cloned(),
        hostname: hostname.to_string(),
        referrer: referrer.to_string(),
    }
}

/// `DateTime.fromJSDate(new Date(ms)).toFormat("yyyy-MM-dd HH:mm:ss.SSS")`: luxon
/// formats in the process's zone (UTC in the containers, where TZ is unset), and
/// `new Date` truncates fractional milliseconds.
pub fn format_datetime_ms<Tz: TimeZone>(ms: f64, zone: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    DateTime::<Utc>::from_timestamp_millis(ms.trunc() as i64)
        .map(|instant| instant.with_timezone(zone).format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_else(|| "Invalid DateTime".to_string())
}

/// `SessionReplayIngestService.recordEvents(siteId, request, requestMeta)`
pub async fn record_events<D: IngestDeps>(
    deps: &D,
    site_id: i32,
    batch: ReplayBatch,
    meta: &RequestMeta,
) -> Result<(), RecordError> {
    let ReplayBatch { user_id: client_user_id, events: raw_events, metadata } = batch;

    // Device clocks, not ours: correct the whole batch onto server time before
    // anything downstream partitions or TTLs on these values
    let timestamps: Vec<f64> = raw_events.iter().map(|event| event.timestamp).collect();
    let (corrected, skew_ms) = correct_replay_clock_skew(&timestamps, deps.now_ms());
    if skew_ms != 0.0 {
        warn!(site_id, skew_ms, event_count = raw_events.len(), "Corrected replay clock skew");
    }
    let events: Vec<ReplayEvent> = match corrected {
        None => raw_events,
        Some(corrected) => raw_events
            .into_iter()
            .zip(corrected)
            .map(|(event, timestamp)| ReplayEvent { timestamp, ..event })
            .collect(),
    };

    // Always generate the device fingerprint (anonymous user id) server-side
    let device_fingerprint = deps.generate_user_id(&meta.ip_address, &meta.user_agent, site_id).await?;

    // An identified user id is the client's id when it differs from the fingerprint
    let trimmed_client_user_id = client_user_id.trim();
    let identified_user_id = if !trimmed_client_user_id.is_empty() && trimmed_client_user_id.to_lossy() != device_fingerprint {
        trimmed_client_user_id
    } else {
        JsString::default()
    };
    let identified_lossy = identified_user_id.to_lossy();

    // The stored user_id stays the fingerprint; the identified id only scopes the session
    let user_id = device_fingerprint;
    let session_id = deps.update_session(&user_id, &identified_lossy, site_id).await;
    debug!(site_id, session_id = %session_id, identified = !identified_user_id.is_empty(), events = events.len(), "Recording replay batch");

    // Prepare events for the batch insert (R2 is disabled: everything in ClickHouse)
    let viewport_width = metadata.as_ref().and_then(|metadata| metadata.viewport_width);
    let viewport_height = metadata.as_ref().and_then(|metadata| metadata.viewport_height);
    let mut body = String::new();
    let mut sizes: Vec<usize> = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let Some(serialized) = event.data.as_deref() else {
            error!(site_id, index, "Replay event has no data; JSON.stringify(undefined) has no length");
            return Err(RecordError::MissingEventData { index });
        };
        let size = crate::js_json::utf16_len(serialized);
        sizes.push(size);

        let mut row = RowWriter::new(std::mem::take(&mut body));
        row.number("site_id", f64::from(site_id));
        row.str("session_id", &session_id);
        row.str("user_id", &user_id);
        row.js_str("identified_user_id", &identified_user_id);
        row.number("timestamp", event.timestamp);
        match &event.event_type {
            EventType::Text(text) => row.js_str("event_type", text),
            EventType::Number(number) => row.number("event_type", *number),
        }
        row.str("event_data", serialized);
        row.null("event_data_key");
        row.null("batch_index");
        row.number("sequence_number", index as f64);
        row.number("event_size_bytes", size as f64);
        row.number_or_null("viewport_width", viewport_width);
        row.number_or_null("viewport_height", viewport_height);
        row.number("is_complete", 0.0);
        body = row.finish();
    }

    if !events.is_empty() {
        let rows = events.len();
        deps.insert(EVENTS_TABLE, body, rows)
            .await
            .map_err(|failure| RecordError::Insert { table: EVENTS_TABLE, failure })?;
    }

    if let Some(metadata) = metadata {
        // A batch without events still records metadata, anchored on server time
        let timestamps: Vec<f64> = if events.is_empty() {
            vec![deps.now_ms()]
        } else {
            events.iter().map(|event| event.timestamp).collect()
        };
        let stats = BatchStats {
            start_time: timestamps.iter().copied().fold(f64::INFINITY, f64::min),
            end_time: timestamps.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            event_count: events.len(),
            compressed_size_bytes: sizes.iter().sum(),
            screen_width: or_zero(metadata.viewport_width),
            screen_height: or_zero(metadata.viewport_height),
        };
        update_session_metadata(deps, site_id, &session_id, &user_id, &identified_user_id, &metadata, &stats, meta).await?;
    }
    Ok(())
}

/// `BatchStats`: what one batch observed about its session.
struct BatchStats {
    start_time: f64,
    end_time: f64,
    event_count: usize,
    compressed_size_bytes: usize,
    screen_width: f64,
    screen_height: f64,
}

/// `updateSessionMetadata`: append-only; the aggregating table combines batches.
#[allow(clippy::too_many_arguments)]
async fn update_session_metadata<D: IngestDeps>(
    deps: &D,
    site_id: i32,
    session_id: &str,
    user_id: &str,
    identified_user_id: &JsString,
    metadata: &ReplayMetadata,
    stats: &BatchStats,
    meta: &RequestMeta,
) -> Result<(), RecordError> {
    let page_url = metadata.page_url.to_lossy();
    let screen_width = if is_truthy(stats.screen_width) { stats.screen_width } else { or_zero(metadata.viewport_width) };
    let screen_height = if is_truthy(stats.screen_height) { stats.screen_height } else { or_zero(metadata.viewport_height) };

    let tracking = if meta.user_agent.is_empty() {
        TrackingData::default()
    } else {
        match whatwg_url(&page_url) {
            Some(url) => parse_tracking_data(
                deps.location(&meta.ip_address),
                &meta.user_agent,
                &meta.referrer,
                &url.search,
                &url.hostname,
                metadata.language.as_ref(),
                screen_width,
                screen_height,
            ),
            None => {
                // `new URL(metadata.pageUrl)` threw: Node logs and records empty tracking data
                error!(site_id, session_id, "Error parsing tracking data for session replay: Invalid URL");
                TrackingData::default()
            }
        }
    };

    let mut row = RowWriter::new(String::new());
    row.number("site_id", f64::from(site_id));
    row.str("session_id", session_id);
    row.str("user_id", user_id);
    row.js_str("identified_user_id", identified_user_id);
    row.str("start_time", &deps.format_time(stats.start_time));
    row.str("end_time", &deps.format_time(stats.end_time));
    row.number("event_count", stats.event_count as f64);
    row.number("compressed_size_bytes", stats.compressed_size_bytes as f64);
    row.js_str("page_url", &metadata.page_url);
    row.str("country", &tracking.country);
    row.str("region", &tracking.region);
    row.str("city", &tracking.city);
    row.number("lat", tracking.lat);
    row.number("lon", tracking.lon);
    row.str("browser", &tracking.browser);
    row.str("browser_version", &tracking.browser_version);
    row.str("operating_system", &tracking.operating_system);
    row.str("operating_system_version", &tracking.operating_system_version);
    match &tracking.language {
        Some(language) => row.js_str("language", language),
        None => row.str("language", ""),
    }
    row.number("screen_width", screen_width);
    row.number("screen_height", screen_height);
    row.str("device_type", &tracking.device_type);
    row.str("channel", &tracking.channel);
    row.str("hostname", &tracking.hostname);
    row.str("referrer", &tracking.referrer);
    row.number("has_replay_data", 1.0);

    deps.insert(METADATA_TABLE, row.finish(), 1)
        .await
        .map_err(|failure| RecordError::Insert { table: METADATA_TABLE, failure })
}

#[cfg(test)]
mod tests {
    //! Port of server/src/services/replay/sessionReplayIngestService.test.ts, plus
    //! row-shape checks against rows Node wrote for the same batches.

    use std::sync::Mutex;

    use serde_json::Value;

    use super::*;

    #[derive(Default)]
    struct Recorder {
        generate_calls: Mutex<Vec<(String, String, i32)>>,
        session_calls: Mutex<Vec<(String, String, i32)>>,
        inserts: Mutex<Vec<(&'static str, String)>>,
    }

    impl IngestDeps for Recorder {
        async fn generate_user_id(&self, ip: &str, user_agent: &str, site_id: i32) -> Result<String, UserIdError> {
            self.generate_calls.lock().unwrap().push((ip.into(), user_agent.into(), site_id));
            Ok("shared-fingerprint".into())
        }

        async fn update_session(&self, user_id: &str, identified_user_id: &str, site_id: i32) -> String {
            self.session_calls.lock().unwrap().push((user_id.into(), identified_user_id.into(), site_id));
            let identified = if identified_user_id.is_empty() { "anonymous" } else { identified_user_id };
            format!("session-{user_id}-{identified}")
        }

        async fn insert(&self, table: &'static str, body: String, _rows: usize) -> Result<(), ClickHouseFailure> {
            self.inserts.lock().unwrap().push((table, body));
            Ok(())
        }

        fn location(&self, _ip: &str) -> Option<Location> {
            None
        }

        fn now_ms(&self) -> f64 {
            1_700_000_100_000.0
        }

        fn format_time(&self, ms: f64) -> String {
            format_datetime_ms(ms, &Utc)
        }
    }

    impl Recorder {
        fn rows(&self) -> Vec<(&'static str, Value)> {
            self.inserts
                .lock()
                .unwrap()
                .iter()
                .flat_map(|(table, body)| body.lines().map(|line| (*table, serde_json::from_str(line).unwrap())).collect::<Vec<_>>())
                .collect()
        }
    }

    fn request_meta() -> RequestMeta {
        RequestMeta {
            ip_address: "198.51.100.10".into(),
            user_agent: "Standardized Corporate Browser/1.0".into(),
            origin: "https://internal.example".into(),
            referrer: String::new(),
        }
    }

    fn replay_request(identified_user_id: &str) -> ReplayBatch {
        ReplayBatch {
            user_id: JsString::from(identified_user_id),
            events: vec![ReplayEvent {
                event_type: EventType::Number(2.0),
                data: Some(format!("{{\"user\":\"{identified_user_id}\"}}")),
                timestamp: 1_700_000_000_000.0,
            }],
            metadata: None,
        }
    }

    #[tokio::test]
    async fn separates_identified_replay_users_behind_a_shared_proxy() {
        let deps = Recorder::default();
        record_events(&deps, 42, replay_request("employee-alice"), &request_meta()).await.unwrap();
        record_events(&deps, 42, replay_request("employee-bob"), &request_meta()).await.unwrap();

        assert_eq!(
            *deps.session_calls.lock().unwrap(),
            vec![
                ("shared-fingerprint".into(), "employee-alice".into(), 42),
                ("shared-fingerprint".into(), "employee-bob".into(), 42),
            ]
        );
        let rows = deps.rows();
        let distinct = |field: &str| rows.iter().map(|(_, row)| row[field].as_str().unwrap().to_string()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(distinct("user_id"), ["shared-fingerprint".to_string()].into());
        assert_eq!(distinct("identified_user_id"), ["employee-alice".to_string(), "employee-bob".to_string()].into());
        assert_eq!(distinct("session_id").len(), 2);
    }

    #[tokio::test]
    async fn retains_the_existing_anonymous_replay_session_key() {
        let deps = Recorder::default();
        record_events(&deps, 42, replay_request(""), &request_meta()).await.unwrap();
        assert_eq!(*deps.generate_calls.lock().unwrap(), vec![("198.51.100.10".into(), "Standardized Corporate Browser/1.0".into(), 42)]);
        assert_eq!(*deps.session_calls.lock().unwrap(), vec![("shared-fingerprint".into(), String::new(), 42)]);
    }

    #[tokio::test]
    async fn writes_rows_in_node_key_order_and_spelling() {
        let deps = Recorder::default();
        let batch = ReplayBatch {
            user_id: JsString::from_units(vec![0x20, 0xD800, 0x20]),
            events: vec![
                ReplayEvent { event_type: EventType::Number(2.0), data: Some("{\"a\":\"\\ud800é\"}".into()), timestamp: 1_700_000_000_000.5 },
                ReplayEvent { event_type: EventType::Text(JsString::from("x\"y")), data: Some("null".into()), timestamp: 1_700_000_001_000.0 },
            ],
            metadata: Some(ReplayMetadata {
                page_url: JsString::from("https://www.example.com/p?utm_source=google&utm_medium=cpc"),
                viewport_width: Some(1280.0),
                viewport_height: Some(0.0),
                language: Some(JsString::from("en-US")),
            }),
        };
        let meta = RequestMeta {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36".into(),
            referrer: "https://www.example.com/".into(),
            ..request_meta()
        };
        record_events(&deps, 42, batch, &meta).await.unwrap();
        let inserts = deps.inserts.lock().unwrap();
        assert_eq!(
            inserts[0].1,
            concat!(
                r#"{"site_id":42,"session_id":"session-shared-fingerprint-�","user_id":"shared-fingerprint","identified_user_id":"\ud800","timestamp":1700000000000.5,"event_type":2,"event_data":"{\"a\":\"\\ud800é\"}","event_data_key":null,"batch_index":null,"sequence_number":0,"event_size_bytes":15,"viewport_width":1280,"viewport_height":null,"is_complete":0}"#,
                "\n",
                r#"{"site_id":42,"session_id":"session-shared-fingerprint-�","user_id":"shared-fingerprint","identified_user_id":"\ud800","timestamp":1700000001000,"event_type":"x\"y","event_data":"null","event_data_key":null,"batch_index":null,"sequence_number":1,"event_size_bytes":4,"viewport_width":1280,"viewport_height":null,"is_complete":0}"#,
                "\n"
            )
        );
        assert_eq!(
            inserts[1].1,
            concat!(
                r#"{"site_id":42,"session_id":"session-shared-fingerprint-�","user_id":"shared-fingerprint","identified_user_id":"\ud800","start_time":"2023-11-14 22:13:20.000","end_time":"2023-11-14 22:13:21.000","event_count":2,"compressed_size_bytes":19,"page_url":"https://www.example.com/p?utm_source=google&utm_medium=cpc","country":"","region":"","city":"","lat":0,"lon":0,"browser":"Chrome","browser_version":"138","operating_system":"Windows","operating_system_version":"10","language":"en-US","screen_width":1280,"screen_height":0,"device_type":"Desktop","channel":"Paid Search","hostname":"www.example.com","referrer":"","has_replay_data":1}"#,
                "\n"
            )
        );
    }

    #[tokio::test]
    async fn an_event_without_data_fails_before_any_insert() {
        let deps = Recorder::default();
        let mut batch = replay_request("u");
        batch.events.push(ReplayEvent { event_type: EventType::Number(3.0), data: None, timestamp: 1_700_000_000_500.0 });
        let error = record_events(&deps, 42, batch, &request_meta()).await.unwrap_err();
        assert!(matches!(error, RecordError::MissingEventData { index: 1 }));
        assert_eq!(deps.session_calls.lock().unwrap().len(), 1);
        assert!(deps.inserts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn metadata_without_events_is_anchored_on_server_time() {
        let deps = Recorder::default();
        let batch = ReplayBatch {
            user_id: JsString::default(),
            events: Vec::new(),
            metadata: Some(ReplayMetadata { page_url: JsString::from("/relative"), viewport_width: None, viewport_height: None, language: None }),
        };
        record_events(&deps, 7, batch, &request_meta()).await.unwrap();
        let rows = deps.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, METADATA_TABLE);
        assert_eq!(rows[0].1["start_time"], "2023-11-14 22:15:00.000");
        assert_eq!(rows[0].1["end_time"], "2023-11-14 22:15:00.000");
        // An unparseable page URL leaves every tracking field empty, browser included
        assert_eq!(rows[0].1["browser"], "");
        assert_eq!(rows[0].1["hostname"], "");
        assert_eq!(rows[0].1["event_count"], 0);
    }

    #[test]
    fn formats_bounds_like_luxon_in_the_process_zone() {
        assert_eq!(format_datetime_ms(1_700_000_000_999.9, &Utc), "2023-11-14 22:13:20.999");
        let pacific = chrono::FixedOffset::west_opt(7 * 3600).unwrap();
        assert_eq!(format_datetime_ms(1_700_000_000_000.0, &pacific), "2023-11-14 15:13:20.000");
    }

    #[tokio::test]
    async fn shifts_skewed_batches_onto_server_time() {
        let deps = Recorder::default();
        let mut batch = replay_request("");
        batch.events[0].timestamp = 3_600_000_000_000.0;
        batch.events.push(ReplayEvent { event_type: EventType::Number(3.0), data: Some("{}".into()), timestamp: 3_600_000_000_250.0 });
        record_events(&deps, 1, batch, &request_meta()).await.unwrap();
        let rows = deps.rows();
        assert_eq!(rows[0].1["timestamp"], 1_700_000_099_875.0);
        assert_eq!(rows[1].1["timestamp"], 1_700_000_100_125.0);
    }
}
