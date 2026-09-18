//! The three import mappers, ported from server/src/services/import/mappers
//! (umami.ts, simpleAnalytics.ts, plausible.ts and the `HygoEvent` shape in
//! hygo.ts), plus the key-only schemas `batchImportEvents` validates the request
//! body against.
//!
//! Two zod behaviours decide what a mapper keeps. First, a `safeParse` that ends
//! *dirty* (any failed check) is a failure, so an event is either fully valid or
//! dropped, which is why these return `Option`. Second, a `.transform()` runs only
//! on a clean value, so the transformed spellings below are reached only by events
//! that passed every check.
//!
//! The row is built in the same key order as the object literal in each mapper,
//! because `clickhouse.insert` writes `JSON.stringify(row)` per line.

use std::sync::LazyLock;

use regress::{Flags, Regex};
use serde_json::{Map, Value};

use crate::{
    js_json,
    tracking::{channel::get_channel, url_params::{clear_self_referrer, get_all_url_params}},
    ua,
};

fn regex(source: &str) -> Regex {
    Regex::new(source).expect("import mapper pattern compiles")
}

fn regex_i(source: &str) -> Regex {
    Regex::with_flags(source, Flags::from("i")).expect("import mapper pattern compiles")
}

/// zod 3.25's `uuidRegex`.
static UUID: LazyLock<Regex> = LazyLock::new(|| {
    regex_i(r"^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$")
});
/// zod 3.25's `datetimeRegex({})`: a leap-year-aware date, a time with optional
/// fractional seconds, and a mandatory `Z`.
static DATETIME: LazyLock<Regex> = LazyLock::new(|| {
    regex(concat!(
        r"^((\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29",
        r"|\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\d|3[01])|(0[469]|11)-(0[1-9]|[12]\d|30)|(02)-(0[1-9]|1\d|2[0-8])))",
        r"T([01]\d|2[0-3]):[0-5]\d(:[0-5]\d(\.\d+)?)?(Z)$"
    ))
});
static COUNTRY: LazyLock<Regex> = LazyLock::new(|| regex("^[A-Z]{2}$"));
static REGION: LazyLock<Regex> = LazyLock::new(|| regex("^[A-Z]{2}-[A-Z0-9]{1,3}$"));
static SCREEN: LazyLock<Regex> = LazyLock::new(|| regex(r"^\d{1,5}x\d{1,5}$"));
static DIGITS: LazyLock<Regex> = LazyLock::new(|| regex(r"^\d+$"));
static TIMESTAMP: LazyLock<Regex> =
    LazyLock::new(|| regex(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$"));
static WWW_PREFIX: LazyLock<Regex> = LazyLock::new(|| regex(r"^www\."));

fn matches(pattern: &LazyLock<Regex>, text: &str) -> bool {
    pattern.find(text).is_some()
}

/// `z.string().max(n)` counted in UTF-16 code units, as `String.length` counts.
fn within(text: &str, maximum: usize) -> bool {
    js_json::utf16_len(text) <= maximum
}

/// The key-only schema `deriveKeyOnlySchema` builds: every key of the real schema,
/// each `z.string()`. The object is not strict, so extra keys are ignored.
fn all_string_keys(event: &Value, keys: &[&str]) -> bool {
    let Value::Object(fields) = event else { return false };
    keys.iter().all(|key| matches!(fields.get(*key), Some(Value::String(_))))
}

/// The platform an import runs as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Umami,
    SimpleAnalytics,
    Plausible,
}

impl Platform {
    /// `importPlatforms`, the values the `import_platform_enum` column takes.
    pub fn from_str(value: &str) -> Option<Platform> {
        match value {
            "umami" => Some(Platform::Umami),
            "simple_analytics" => Some(Platform::SimpleAnalytics),
            "plausible" => Some(Platform::Plausible),
            _ => None,
        }
    }

    #[allow(dead_code)] // the column value, kept next to `from_str`
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Umami => "umami",
            Platform::SimpleAnalytics => "simple_analytics",
            Platform::Plausible => "plausible",
        }
    }
}

const UMAMI_KEYS: [&str; 19] = [
    "session_id", "hostname", "browser", "os", "device", "screen", "language", "country", "region", "city",
    "url_path", "url_query", "referrer_path", "referrer_domain", "page_title", "event_type", "event_name",
    "distinct_id", "created_at",
];

const SIMPLE_ANALYTICS_KEYS: [&str; 14] = [
    "added_iso", "country_code", "datapoint", "document_referrer", "hostname", "lang_language", "lang_region",
    "path", "query", "screen_height", "screen_width", "session_id", "user_agent", "uuid",
];

const PLAUSIBLE_KEYS: [&str; 18] = [
    "timestamp", "session_id", "user_id", "hostname", "pathname", "querystring", "referrer", "browser",
    "browser_version", "operating_system", "operating_system_version", "device_type", "country", "region", "city",
    "type", "event_name", "props",
];

/// `z.union([array(umami), array(simpleAnalytics), array(plausible)])`: the first
/// option every element satisfies wins. Only whether one does matters, because
/// the handler transforms by the import's recorded platform, not by the branch.
pub fn events_union_accepts(events: &[Value]) -> bool {
    [&UMAMI_KEYS[..], &SIMPLE_ANALYTICS_KEYS[..], &PLAUSIBLE_KEYS[..]]
        .iter()
        .any(|keys| events.iter().all(|event| all_string_keys(event, keys)))
}

fn field<'a>(event: &'a Value, key: &str) -> &'a str {
    match event {
        Value::Object(fields) => match fields.get(key) {
            Some(Value::String(text)) => text,
            _ => "",
        },
        _ => "",
    }
}

/// The `HygoEvent` object literal, in the order every mapper writes it.
#[allow(clippy::too_many_arguments)]
struct HygoEvent {
    site_id: i64,
    timestamp: String,
    session_id: String,
    user_id: String,
    hostname: String,
    pathname: String,
    querystring: String,
    url_parameters: Map<String, Value>,
    page_title: String,
    referrer: String,
    channel: String,
    browser: String,
    browser_version: String,
    operating_system: String,
    operating_system_version: String,
    language: String,
    country: String,
    region: String,
    city: String,
    screen_width: f64,
    screen_height: f64,
    device_type: String,
    event_type: String,
    event_name: String,
    props: Value,
    import_id: String,
}

impl HygoEvent {
    fn into_row(self) -> Value {
        let mut row = Map::new();
        row.insert("site_id".into(), Value::from(self.site_id));
        row.insert("timestamp".into(), Value::String(self.timestamp));
        row.insert("session_id".into(), Value::String(self.session_id));
        row.insert("user_id".into(), Value::String(self.user_id));
        row.insert("hostname".into(), Value::String(self.hostname));
        row.insert("pathname".into(), Value::String(self.pathname));
        row.insert("querystring".into(), Value::String(self.querystring));
        row.insert("url_parameters".into(), Value::Object(self.url_parameters));
        row.insert("page_title".into(), Value::String(self.page_title));
        row.insert("referrer".into(), Value::String(self.referrer));
        row.insert("channel".into(), Value::String(self.channel));
        row.insert("browser".into(), Value::String(self.browser));
        row.insert("browser_version".into(), Value::String(self.browser_version));
        row.insert("operating_system".into(), Value::String(self.operating_system));
        row.insert("operating_system_version".into(), Value::String(self.operating_system_version));
        row.insert("language".into(), Value::String(self.language));
        row.insert("country".into(), Value::String(self.country));
        row.insert("region".into(), Value::String(self.region));
        row.insert("city".into(), Value::String(self.city));
        row.insert("lat".into(), Value::from(0));
        row.insert("lon".into(), Value::from(0));
        row.insert("screen_width".into(), Value::from(self.screen_width));
        row.insert("screen_height".into(), Value::from(self.screen_height));
        row.insert("device_type".into(), Value::String(self.device_type));
        row.insert("type".into(), Value::String(self.event_type));
        row.insert("event_name".into(), Value::String(self.event_name));
        row.insert("props".into(), self.props);
        row.insert("import_id".into(), Value::String(self.import_id));
        Value::Object(row)
    }
}

fn url_parameter_map(querystring: &str) -> Map<String, Value> {
    get_all_url_params(querystring).into_iter().map(|(key, value)| (key, Value::String(value))).collect()
}

/// `transform(events, site, importId)` for one platform: every event that parses,
/// in order, as the rows `clickhouse.insert` receives.
pub fn transform(platform: Platform, events: &[Value], site_id: i64, import_id: &str) -> Vec<Value> {
    events
        .iter()
        .filter_map(|event| match platform {
            Platform::Umami => umami_event(event, site_id, import_id),
            Platform::SimpleAnalytics => simple_analytics_event(event, site_id, import_id),
            Platform::Plausible => plausible_event(event, site_id, import_id),
        })
        .map(HygoEvent::into_row)
        .collect()
}

/// The timestamp every row carries, which the quota tracker reads back.
pub fn row_timestamp(row: &Value) -> String {
    row.get("timestamp").and_then(Value::as_str).unwrap_or_default().to_string()
}

// ---------------------------------------------------------------------------
// umami

fn umami_browser(browser: &str) -> String {
    let mapped = match browser.to_lowercase().as_str() {
        "chrome" => Some("Chrome"),
        "opera" => Some("Opera"),
        "crios" => Some("Mobile Chrome"),
        "firefox" => Some("Firefox"),
        "facebook" => Some("Facebook"),
        "safari" => Some("Safari"),
        "ios" => Some("Mobile Safari"),
        "ios-webview" => Some("Mobile Safari"),
        "edge-chromium" => Some("Edge"),
        "samsung" => Some("Samsung Internet"),
        "yandexbrowser" => Some("Yandex"),
        "edge-ios" => Some("Edge"),
        "chromium-webview" => Some("Chrome WebView"),
        "fxios" => Some("Mobile Firefox"),
        "edge" => Some("Edge"),
        _ => None,
    };
    mapped.map_or_else(|| browser.to_string(), str::to_string)
}

fn umami_os(os: &str) -> String {
    let mapped = match os.to_lowercase().as_str() {
        "windows 10" | "windows 7" | "windows server 2003" => Some("Windows"),
        "mac os" => Some("macOS"),
        "ios" => Some("iOS"),
        "android os" => Some("Android"),
        "linux" => Some("Linux"),
        "chrome os" => Some("Chrome OS"),
        _ => None,
    };
    mapped.map_or_else(|| os.to_string(), str::to_string)
}

fn umami_device(device: &str) -> String {
    let mapped = match device.to_lowercase().as_str() {
        "laptop" | "desktop" => Some("Desktop"),
        "mobile" | "tablet" => Some("Mobile"),
        _ => None,
    };
    mapped.map_or_else(|| device.to_string(), str::to_string)
}

/// `deriveOsVersion`, which reads the *raw* `event.os`, not the mapped one.
fn umami_os_version(raw_os: &str) -> &'static str {
    match raw_os.to_lowercase().as_str() {
        "windows 10" => "10",
        "windows 7" => "7",
        _ => "",
    }
}

fn umami_event(event: &Value, site_id: i64, import_id: &str) -> Option<HygoEvent> {
    if !all_string_keys(event, &UMAMI_KEYS) {
        return None;
    }
    let get = |key: &str| field(event, key);
    let (session_id, hostname, browser, os, device) =
        (get("session_id"), get("hostname"), get("browser"), get("os"), get("device"));
    let (screen, language, country, region, city) =
        (get("screen"), get("language"), get("country"), get("region"), get("city"));
    let (url_path, url_query, referrer_path, referrer_domain, page_title) =
        (get("url_path"), get("url_query"), get("referrer_path"), get("referrer_domain"), get("page_title"));
    let (event_type, event_name, distinct_id, created_at) =
        (get("event_type"), get("event_name"), get("distinct_id"), get("created_at"));

    if !matches(&UUID, session_id)
        || !within(hostname, 253)
        || !within(browser, 30)
        || !within(os, 25)
        || !within(device, 20)
        || !(matches(&SCREEN, screen) || screen.is_empty())
        || !within(language, 35)
        || !(matches(&COUNTRY, country) || country.is_empty())
        || !(matches(&REGION, region) || region.is_empty())
        || !within(city, 60)
        || !within(url_path, 2048)
        || !within(url_query, 2048)
        || !within(referrer_path, 2048)
        || !within(referrer_domain, 253)
        || !within(page_title, 512)
        || !(event_type == "1" || event_type == "2")
        || !within(event_name, 256)
        || !within(distinct_id, 64)
        || !matches(&TIMESTAMP, created_at)
    {
        return None;
    }

    // The transforms, which only a clean value reaches
    let browser = umami_browser(browser);
    let os_name = umami_os(os);
    let device = umami_device(device);
    let query = if url_query.is_empty() { String::new() } else { format!("?{url_query}") };
    let domain = if referrer_domain.is_empty() { String::new() } else { format!("https://{referrer_domain}") };

    let combined = format!("{domain}{referrer_path}");
    let bare_host = match WWW_PREFIX.find(hostname) {
        Some(found) => &hostname[found.range().end..],
        None => hostname,
    };
    let referrer = clear_self_referrer(&combined, bare_host).to_string();
    let (width, height) = match screen.split_once('x') {
        Some((width, height)) if !screen.is_empty() => (width, height),
        _ => ("0", "0"),
    };

    Some(HygoEvent {
        site_id,
        timestamp: created_at.to_string(),
        session_id: session_id.to_string(),
        user_id: distinct_id.to_string(),
        hostname: hostname.to_string(),
        pathname: url_path.to_string(),
        querystring: query.clone(),
        url_parameters: url_parameter_map(&query),
        page_title: page_title.to_string(),
        channel: get_channel(&referrer, &query, hostname).to_string(),
        referrer,
        browser,
        browser_version: String::new(),
        operating_system: os_name,
        operating_system_version: umami_os_version(os).to_string(),
        language: language.to_string(),
        country: country.to_string(),
        region: region.to_string(),
        city: city.to_string(),
        screen_width: crate::analytics::js::number::parse_int_10(width),
        screen_height: crate::analytics::js::number::parse_int_10(height),
        device_type: device,
        event_type: if event_type == "1" { "pageview".into() } else { "custom_event".into() },
        event_name: if event_type == "1" { String::new() } else { event_name.to_string() },
        props: Value::Object(Map::new()),
        import_id: import_id.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Simple Analytics

/// `DateTime.fromISO(added_iso).toFormat("yyyy-MM-dd HH:mm:ss")`. The zod check
/// requires a `Z`, so the instant is UTC; Luxon then renders it in the process's
/// zone, which is UTC in production and in the parity stack.
fn simple_analytics_timestamp(added_iso: &str) -> Option<String> {
    let parsed = chrono::DateTime::parse_from_rfc3339(added_iso).ok()?;
    Some(parsed.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
}

fn simple_analytics_event(event: &Value, site_id: i64, import_id: &str) -> Option<HygoEvent> {
    if !all_string_keys(event, &SIMPLE_ANALYTICS_KEYS) {
        return None;
    }
    let get = |key: &str| field(event, key);
    let (added_iso, country_code, datapoint, document_referrer, hostname) =
        (get("added_iso"), get("country_code"), get("datapoint"), get("document_referrer"), get("hostname"));
    let (lang_language, lang_region, path, query) =
        (get("lang_language"), get("lang_region"), get("path"), get("query"));
    let (screen_height, screen_width, session_id, user_agent, uuid) =
        (get("screen_height"), get("screen_width"), get("session_id"), get("user_agent"), get("uuid"));

    if !matches(&DATETIME, added_iso)
        || !(matches(&COUNTRY, country_code) || country_code.is_empty())
        || !within(datapoint, 256)
        || !within(document_referrer, 253 + 2048)
        || !within(hostname, 253)
        || !within(lang_language, 35)
        || !within(lang_region, 35)
        || !within(path, 2048)
        || !within(query, 2048)
        || !matches(&DIGITS, screen_height)
        || !matches(&DIGITS, screen_width)
        || !matches(&UUID, session_id)
        || !within(user_agent, 1024)
        || !matches(&UUID, uuid)
    {
        return None;
    }

    let query = if query.is_empty() { String::new() } else { format!("?{query}") };
    let parsed_ua = ua::parse(user_agent);
    let referrer = clear_self_referrer(document_referrer, hostname).to_string();
    let width = crate::analytics::js::number::parse_int_10(screen_width);
    let height = crate::analytics::js::number::parse_int_10(screen_height);

    Some(HygoEvent {
        site_id,
        timestamp: simple_analytics_timestamp(added_iso)?,
        session_id: session_id.to_string(),
        user_id: uuid.to_string(),
        hostname: hostname.to_string(),
        pathname: path.to_string(),
        querystring: query.clone(),
        url_parameters: url_parameter_map(&query),
        page_title: String::new(),
        channel: get_channel(&referrer, &query, hostname).to_string(),
        referrer,
        browser: parsed_ua.browser.name.clone().unwrap_or_default(),
        browser_version: parsed_ua.browser.major.clone().unwrap_or_default(),
        operating_system: parsed_ua.os.name.clone().unwrap_or_default(),
        operating_system_version: parsed_ua.os.version.clone().unwrap_or_default(),
        language: if lang_region.is_empty() {
            lang_language.to_string()
        } else {
            format!("{lang_language}-{}", lang_region.to_uppercase())
        },
        country: country_code.to_string(),
        region: String::new(),
        city: String::new(),
        screen_width: width,
        screen_height: height,
        device_type: ua::get_device_type(width, height, &parsed_ua).to_string(),
        event_type: if datapoint == "pageview" { "pageview".into() } else { "custom_event".into() },
        event_name: if datapoint == "pageview" { String::new() } else { datapoint.to_string() },
        props: Value::Object(Map::new()),
        import_id: import_id.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Plausible

fn plausible_event(event: &Value, site_id: i64, import_id: &str) -> Option<HygoEvent> {
    if !all_string_keys(event, &PLAUSIBLE_KEYS) {
        return None;
    }
    let get = |key: &str| field(event, key);
    let (timestamp, session_id, user_id, hostname, pathname) =
        (get("timestamp"), get("session_id"), get("user_id"), get("hostname"), get("pathname"));
    let (querystring, referrer, browser, browser_version) =
        (get("querystring"), get("referrer"), get("browser"), get("browser_version"));
    let (operating_system, operating_system_version, device_type) =
        (get("operating_system"), get("operating_system_version"), get("device_type"));
    let (country, region, city, event_type, event_name, props) =
        (get("country"), get("region"), get("city"), get("type"), get("event_name"), get("props"));

    if !matches(&TIMESTAMP, timestamp)
        || !matches(&UUID, session_id)
        || !matches(&UUID, user_id)
        || !within(hostname, 253)
        || !within(pathname, 2048)
        || !within(querystring, 2048)
        || !within(referrer, 2048)
        || !within(browser, 30)
        || !within(browser_version, 20)
        || !within(operating_system, 25)
        || !within(operating_system_version, 20)
        || !within(device_type, 20)
        || !(matches(&COUNTRY, country) || country.is_empty())
        || !(matches(&REGION, region) || region.is_empty())
        || !within(city, 60)
        || !(event_type == "pageview" || event_type == "custom_event")
        || !within(event_name, 256)
        || !within(props, 4096)
    {
        return None;
    }

    // `JSON.parse(data.props || "{}")`, invalid JSON ignored
    let source = if props.is_empty() { "{}" } else { props };
    let parsed_props = crate::analytics::js::json::parse(source)
        .map(|value| value.to_serde())
        .unwrap_or_else(|_| Value::Object(Map::new()));

    let bare_host = match WWW_PREFIX.find(hostname) {
        Some(found) => &hostname[found.range().end..],
        None => hostname,
    };
    let cleared = clear_self_referrer(referrer, bare_host).to_string();

    Some(HygoEvent {
        site_id,
        timestamp: timestamp.to_string(),
        session_id: session_id.to_string(),
        user_id: user_id.to_string(),
        hostname: hostname.to_string(),
        pathname: pathname.to_string(),
        querystring: querystring.to_string(),
        url_parameters: url_parameter_map(querystring),
        page_title: String::new(),
        channel: get_channel(&cleared, querystring, hostname).to_string(),
        referrer: cleared,
        browser: browser.to_string(),
        browser_version: browser_version.to_string(),
        operating_system: operating_system.to_string(),
        operating_system_version: operating_system_version.to_string(),
        language: String::new(),
        country: country.to_string(),
        region: region.to_string(),
        city: city.to_string(),
        screen_width: 0.0,
        screen_height: 0.0,
        device_type: device_type.to_string(),
        event_type: event_type.to_string(),
        event_name: event_name.to_string(),
        props: parsed_props,
        import_id: import_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn umami(overrides: Value) -> Value {
        let mut event = json!({
            "session_id": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001",
            "hostname": "www.example.com", "browser": "crios", "os": "Windows 10", "device": "laptop",
            "screen": "1920x1080", "language": "en-US", "country": "US", "region": "US-CA", "city": "Oakland",
            "url_path": "/pricing", "url_query": "utm_source=news&a=1", "referrer_path": "/blog",
            "referrer_domain": "news.example.org", "page_title": "Pricing", "event_type": "1",
            "event_name": "signup", "distinct_id": "device-1", "created_at": "2026-05-04 12:30:45"
        });
        if let (Value::Object(base), Value::Object(extra)) = (&mut event, overrides) {
            base.extend(extra);
        }
        event
    }

    #[test]
    fn umami_rows_carry_the_mapped_values() {
        let rows = transform(Platform::Umami, &[umami(json!({}))], 65200, "11111111-1111-4111-8111-111111111111");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["browser"], json!("Mobile Chrome"));
        assert_eq!(row["operating_system"], json!("Windows"));
        assert_eq!(row["operating_system_version"], json!("10"));
        assert_eq!(row["device_type"], json!("Desktop"));
        assert_eq!(row["querystring"], json!("?utm_source=news&a=1"));
        assert_eq!(row["referrer"], json!("https://news.example.org/blog"));
        assert_eq!(row["screen_width"], json!(1920.0));
        assert_eq!(row["type"], json!("pageview"));
        assert_eq!(row["event_name"], json!(""));
        assert_eq!(row["timestamp"], json!("2026-05-04 12:30:45"));
        // key order is the object literal's
        let keys: Vec<&str> = row.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys[0], "site_id");
        assert_eq!(keys[1], "timestamp");
        assert_eq!(*keys.last().unwrap(), "import_id");
    }

    #[test]
    fn umami_drops_events_that_fail_any_check() {
        for bad in [
            json!({ "session_id": "not-a-uuid" }),
            json!({ "created_at": "2026-13-04 12:30:45" }),
            json!({ "event_type": "3" }),
            json!({ "country": "usa" }),
            json!({ "screen": "1920X1080" }),
            json!({ "city": "x".repeat(61) }),
        ] {
            assert!(transform(Platform::Umami, &[umami(bad.clone())], 1, "i").is_empty(), "{bad}");
        }
        // an empty screen is allowed and means 0x0
        let rows = transform(Platform::Umami, &[umami(json!({ "screen": "" }))], 1, "i");
        assert_eq!(rows[0]["screen_width"], json!(0.0));
    }

    #[test]
    fn umami_clears_a_self_referrer_by_the_bare_hostname() {
        // `clearSelfReferrer` compares the referrer's hostname with the site's
        // hostname *after* `replace(/^www\./, "")`, so only a bare-host referrer
        // is cleared. Both spellings are checked because the asymmetry is Node's.
        let cleared = transform(
            Platform::Umami,
            &[umami(json!({ "referrer_domain": "example.com", "referrer_path": "/x" }))],
            1,
            "i",
        );
        assert_eq!(cleared[0]["referrer"], json!(""));
        let kept = transform(
            Platform::Umami,
            &[umami(json!({ "referrer_domain": "www.example.com", "referrer_path": "/x" }))],
            1,
            "i",
        );
        assert_eq!(kept[0]["referrer"], json!("https://www.example.com/x"));
    }

    #[test]
    fn plausible_props_fall_back_to_an_object() {
        let event = json!({
            "timestamp": "2026-05-04 12:30:45", "session_id": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001",
            "user_id": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0002", "hostname": "example.com", "pathname": "/",
            "querystring": "", "referrer": "", "browser": "Chrome", "browser_version": "120",
            "operating_system": "macOS", "operating_system_version": "14", "device_type": "Desktop",
            "country": "US", "region": "", "city": "", "type": "custom_event", "event_name": "signup",
            "props": "{not json"
        });
        let rows = transform(Platform::Plausible, &[event], 1, "i");
        assert_eq!(rows[0]["props"], json!({}));
    }

    #[test]
    fn simple_analytics_reads_the_user_agent() {
        let event = json!({
            "added_iso": "2026-05-04T12:30:45.123Z", "country_code": "US", "datapoint": "pageview",
            "document_referrer": "https://news.example.org/x", "hostname": "example.com",
            "lang_language": "en", "lang_region": "us", "path": "/", "query": "a=1",
            "screen_height": "1080", "screen_width": "1920",
            "session_id": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "uuid": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0002"
        });
        let rows = transform(Platform::SimpleAnalytics, &[event], 1, "i");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["language"], json!("en-US"));
        assert_eq!(rows[0]["browser"], json!("Chrome"));
        assert_eq!(rows[0]["device_type"], json!("Desktop"));
        // Luxon renders the instant in the process's zone; production runs UTC
        let expected = chrono::DateTime::parse_from_rfc3339("2026-05-04T12:30:45.123Z")
            .unwrap()
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        assert_eq!(rows[0]["timestamp"], json!(expected));
    }

    #[test]
    fn the_union_accepts_any_one_platform() {
        assert!(events_union_accepts(&[]));
        assert!(events_union_accepts(&[umami(json!({}))]));
        assert!(!events_union_accepts(&[json!({ "session_id": "x" })]));
        assert!(!events_union_accepts(&[json!("text")]));
        // a numeric value fails the key-only z.string()
        assert!(!events_union_accepts(&[umami(json!({ "event_type": 1 }))]));
    }

    // ----------------------------------------------------------------------
    // The three vitest suites, ported case for case from
    // server/src/services/import/mappers/{umami,plausible,simpleAnalytics}.test.ts.

    /// The fixture event each suite builds, with the overrides a case applies.
    fn event(base: &Value, overrides: Value) -> Value {
        let mut merged = base.clone();
        if let (Value::Object(target), Value::Object(extra)) = (&mut merged, overrides) {
            target.extend(extra);
        }
        merged
    }

    mod umami_suite {
        use super::*;

        // A valid RFC4122 v4 UUID, as the suite notes
        const SESSION: &str = "9e3779b1-3c6e-4362-8a4f-81b88c81f013";

        fn base() -> Value {
            json!({
                "session_id": SESSION, "hostname": "example.com", "browser": "chrome", "os": "Windows 10",
                "device": "desktop", "screen": "1920x1080", "language": "en-US", "country": "US",
                "region": "US-CA", "city": "San Francisco", "url_path": "/blog/post-1",
                "url_query": "utm_source=google", "referrer_path": "/search", "referrer_domain": "google.com",
                "page_title": "Post 1", "event_type": "1", "event_name": "", "distinct_id": "visitor-1",
                "created_at": "2024-06-15 14:30:00"
            })
        }

        fn rows(overrides: Value, site: i64, import_id: &str) -> Vec<Value> {
            transform(Platform::Umami, &[event(&base(), overrides)], site, import_id)
        }

        fn one(overrides: Value) -> Value {
            let rows = rows(overrides, 1, "i");
            assert_eq!(rows.len(), 1, "event should have been kept");
            rows[0].clone()
        }

        #[test]
        fn transforms_a_valid_pageview_event() {
            let rows = rows(json!({}), 1, "import-1");
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row["site_id"], json!(1));
            assert_eq!(row["timestamp"], json!("2024-06-15 14:30:00"));
            assert_eq!(row["session_id"], json!(SESSION));
            assert_eq!(row["user_id"], json!("visitor-1"));
            assert_eq!(row["hostname"], json!("example.com"));
            assert_eq!(row["pathname"], json!("/blog/post-1"));
            assert_eq!(row["querystring"], json!("?utm_source=google"));
            assert_eq!(row["url_parameters"], json!({ "utm_source": "google" }));
            assert_eq!(row["page_title"], json!("Post 1"));
            assert_eq!(row["referrer"], json!("https://google.com/search"));
            assert_eq!(row["browser"], json!("Chrome"));
            assert_eq!(row["browser_version"], json!(""));
            assert_eq!(row["operating_system"], json!("Windows"));
            assert_eq!(row["operating_system_version"], json!("10"));
            assert_eq!(row["language"], json!("en-US"));
            assert_eq!(row["country"], json!("US"));
            assert_eq!(row["region"], json!("US-CA"));
            assert_eq!(row["city"], json!("San Francisco"));
            assert_eq!(row["lat"], json!(0));
            assert_eq!(row["lon"], json!(0));
            assert_eq!(row["screen_width"], json!(1920.0));
            assert_eq!(row["screen_height"], json!(1080.0));
            assert_eq!(row["device_type"], json!("Desktop"));
            assert_eq!(row["type"], json!("pageview"));
            assert_eq!(row["event_name"], json!(""));
            assert_eq!(row["props"], json!({}));
            assert_eq!(row["import_id"], json!("import-1"));
            assert_ne!(row["channel"], json!(""), "channel is truthy");
        }

        #[test]
        fn transforms_a_custom_event() {
            let rows = rows(json!({ "event_type": "2", "event_name": "SignUp" }), 2, "import-2");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["type"], json!("custom_event"));
            assert_eq!(rows[0]["event_name"], json!("SignUp"));
        }

        #[test]
        fn clears_the_event_name_for_pageviews() {
            assert_eq!(one(json!({ "event_type": "1", "event_name": "ShouldBeDropped" }))["event_name"], json!(""));
        }

        #[test]
        fn maps_known_browser_keys_case_insensitively() {
            for (input, expected) in [("chrome", "Chrome"), ("Chrome", "Chrome"), ("crios", "Mobile Chrome"),
                                      ("edge-chromium", "Edge"), ("ios", "Mobile Safari"),
                                      ("samsung", "Samsung Internet")] {
                assert_eq!(one(json!({ "browser": input }))["browser"], json!(expected), "{input}");
            }
            assert_eq!(one(json!({ "browser": "brave" }))["browser"], json!("brave"));
        }

        #[test]
        fn maps_known_operating_systems() {
            for (input, expected) in [("Windows 10", "Windows"), ("Mac OS", "macOS"), ("iOS", "iOS"),
                                      ("Android OS", "Android"), ("Linux", "Linux"), ("Chrome OS", "Chrome OS")] {
                assert_eq!(one(json!({ "os": input }))["operating_system"], json!(expected), "{input}");
            }
        }

        #[test]
        fn maps_device_types() {
            for (input, expected) in [("desktop", "Desktop"), ("laptop", "Desktop"), ("mobile", "Mobile"),
                                      ("tablet", "Mobile")] {
                assert_eq!(one(json!({ "device": input }))["device_type"], json!(expected), "{input}");
            }
        }

        #[test]
        fn derives_the_operating_system_version_case_insensitively() {
            for os in ["Windows 10", "windows 10", "WINDOWS 10"] {
                let row = one(json!({ "os": os }));
                assert_eq!(row["operating_system_version"], json!("10"), "{os}");
                assert_eq!(row["operating_system"], json!("Windows"));
            }
            for os in ["Windows 7", "windows 7", "wInDoWs 7"] {
                assert_eq!(one(json!({ "os": os }))["operating_system_version"], json!("7"), "{os}");
            }
            for os in ["Mac OS", "Linux", "Android OS", "Windows Server 2003", "iOS"] {
                assert_eq!(one(json!({ "os": os }))["operating_system_version"], json!(""), "{os}");
            }
        }

        #[test]
        fn parses_the_screen_dimensions() {
            let row = one(json!({ "screen": "390x844" }));
            assert_eq!(row["screen_width"], json!(390.0));
            assert_eq!(row["screen_height"], json!(844.0));
            let empty = one(json!({ "screen": "" }));
            assert_eq!(empty["screen_width"], json!(0.0));
            assert_eq!(empty["screen_height"], json!(0.0));
        }

        #[test]
        fn handles_the_querystring() {
            let row = one(json!({ "url_query": "a=1&b=2" }));
            assert_eq!(row["querystring"], json!("?a=1&b=2"));
            assert_eq!(row["url_parameters"], json!({ "a": "1", "b": "2" }));
            let empty = one(json!({ "url_query": "" }));
            assert_eq!(empty["querystring"], json!(""));
            assert_eq!(empty["url_parameters"], json!({}));
        }

        #[test]
        fn handles_the_referrer() {
            assert_eq!(
                one(json!({ "referrer_domain": "news.ycombinator.com", "referrer_path": "/item" }))["referrer"],
                json!("https://news.ycombinator.com/item")
            );
            assert_eq!(
                one(json!({ "referrer_domain": "example.com", "referrer_path": "/previous" }))["referrer"],
                json!("")
            );
            // the site hostname loses its www prefix before the comparison
            assert_eq!(
                one(json!({ "hostname": "www.example.com", "referrer_domain": "example.com",
                            "referrer_path": "/previous" }))["referrer"],
                json!("")
            );
            assert_eq!(one(json!({ "referrer_domain": "", "referrer_path": "" }))["referrer"], json!(""));
        }

        #[test]
        fn drops_invalid_rows() {
            assert!(rows(json!({ "session_id": "not-a-uuid" }), 1, "i").is_empty());
            for country in ["USA", "us", "1A"] {
                assert!(rows(json!({ "country": country }), 1, "i").is_empty(), "{country}");
            }
            assert_eq!(one(json!({ "country": "" }))["country"], json!(""));
            for created_at in ["2024-06-15T14:30:00", "2024-13-01 10:00:00", "2024-06-15 24:30:00",
                               "not-a-date", ""] {
                assert!(rows(json!({ "created_at": created_at }), 1, "i").is_empty(), "{created_at}");
            }
            assert!(rows(json!({ "screen": "1920*1080" }), 1, "i").is_empty());
        }

        #[test]
        fn keeps_valid_rows_mixed_with_invalid_ones() {
            let events = [
                event(&base(), json!({ "url_path": "/valid" })),
                event(&base(), json!({ "session_id": "bad" })),
                event(&base(), json!({ "url_path": "/also-valid" })),
            ];
            let rows = transform(Platform::Umami, &events, 1, "i");
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["pathname"], json!("/valid"));
            assert_eq!(rows[1]["pathname"], json!("/also-valid"));
        }
    }

    mod plausible_suite {
        use super::*;

        const SESSION: &str = "9e3779b1-3c6e-4362-da4f-81b88c81f013";
        const USER: &str = "12345678-90ab-cdef-1234-567890abcdef";

        fn base() -> Value {
            json!({
                "timestamp": "2024-06-15 14:30:00", "session_id": SESSION, "user_id": USER,
                "hostname": "example.com", "pathname": "/blog/post-1", "querystring": "?utm_source=google",
                "referrer": "https://google.com", "browser": "Chrome", "browser_version": "125",
                "operating_system": "Windows", "operating_system_version": "10", "device_type": "Desktop",
                "country": "US", "region": "US-CA", "city": "San Francisco", "type": "pageview",
                "event_name": "", "props": "{}"
            })
        }

        fn rows(overrides: Value) -> Vec<Value> {
            transform(Platform::Plausible, &[event(&base(), overrides)], 1, "import-1")
        }

        #[test]
        fn transforms_a_valid_pageview_event() {
            let rows = rows(json!({}));
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row["site_id"], json!(1));
            assert_eq!(row["timestamp"], json!("2024-06-15 14:30:00"));
            assert_eq!(row["session_id"], json!(SESSION));
            assert_eq!(row["user_id"], json!(USER));
            assert_eq!(row["pathname"], json!("/blog/post-1"));
            assert_eq!(row["querystring"], json!("?utm_source=google"));
            assert_eq!(row["referrer"], json!("https://google.com"));
            assert_eq!(row["browser_version"], json!("125"));
            assert_eq!(row["operating_system_version"], json!("10"));
            assert_eq!(row["language"], json!(""));
            assert_eq!(row["screen_width"], json!(0.0));
            assert_eq!(row["import_id"], json!("import-1"));
        }

        #[test]
        fn transforms_a_custom_event() {
            let rows = rows(json!({ "type": "custom_event", "event_name": "Signup",
                                    "props": r#"{"plan":"pro"}"# }));
            assert_eq!(rows[0]["type"], json!("custom_event"));
            assert_eq!(rows[0]["event_name"], json!("Signup"));
            assert_eq!(rows[0]["props"], json!({ "plan": "pro" }));
        }

        #[test]
        fn skips_events_with_an_invalid_timestamp_or_type() {
            assert!(rows(json!({ "timestamp": "2024-06-15T14:30:00" })).is_empty());
            assert!(rows(json!({ "timestamp": "not-a-date" })).is_empty());
            assert!(rows(json!({ "type": "click" })).is_empty());
        }

        #[test]
        fn handles_empty_and_invalid_props() {
            assert_eq!(rows(json!({ "props": "" }))[0]["props"], json!({}));
            assert_eq!(rows(json!({ "props": "{invalid" }))[0]["props"], json!({}));
        }

        #[test]
        fn skips_a_hostname_over_the_maximum_length() {
            assert!(rows(json!({ "hostname": "x".repeat(254) })).is_empty());
            assert_eq!(rows(json!({ "hostname": "x".repeat(253) })).len(), 1);
        }

        #[test]
        fn handles_empty_optional_fields() {
            let rows = rows(json!({ "querystring": "", "referrer": "", "region": "", "city": "",
                                    "country": "", "browser_version": "", "operating_system_version": "" }));
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["querystring"], json!(""));
            assert_eq!(rows[0]["referrer"], json!(""));
            assert_eq!(rows[0]["url_parameters"], json!({}));
        }

        #[test]
        fn computes_the_channel_from_the_referrer() {
            assert_eq!(rows(json!({ "referrer": "https://google.com", "querystring": "" }))[0]["channel"],
                       json!("Organic Search"));
            assert_eq!(rows(json!({ "referrer": "", "querystring": "" }))[0]["channel"], json!("Direct"));
        }

        #[test]
        fn returns_nothing_for_an_empty_input_and_filters_invalid_events() {
            assert!(transform(Platform::Plausible, &[], 1, "i").is_empty());
            let events = [event(&base(), json!({ "pathname": "/a" })),
                          event(&base(), json!({ "session_id": "bad" })),
                          event(&base(), json!({ "pathname": "/b" }))];
            let rows = transform(Platform::Plausible, &events, 1, "i");
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["pathname"], json!("/a"));
            assert_eq!(rows[1]["pathname"], json!("/b"));
        }
    }

    mod simple_analytics_suite {
        use super::*;

        const SESSION: &str = "9e3779b1-3c6e-4362-8a4f-81b88c81f013";
        const USER: &str = "12345678-90ab-4def-9234-567890abcdef";
        const CHROME_WINDOWS_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
        const IPHONE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

        fn base() -> Value {
            json!({
                "added_iso": "2024-06-15T14:30:00Z", "country_code": "US", "datapoint": "pageview",
                "document_referrer": "https://google.com/search", "hostname": "example.com",
                "lang_language": "en", "lang_region": "us", "path": "/blog/post-1", "query": "utm_source=google",
                "screen_height": "1080", "screen_width": "1920", "session_id": SESSION,
                "user_agent": CHROME_WINDOWS_UA, "uuid": USER
            })
        }

        fn rows(overrides: Value) -> Vec<Value> {
            transform(Platform::SimpleAnalytics, &[event(&base(), overrides)], 1, "import-1")
        }

        /// The suite pins Luxon's zone to UTC; the port renders in the process's
        /// zone, so the expectation is converted the same way.
        fn expected_timestamp(iso: &str) -> String {
            chrono::DateTime::parse_from_rfc3339(iso)
                .expect("parses")
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        }

        #[test]
        fn transforms_a_valid_pageview_event() {
            let rows = rows(json!({}));
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row["site_id"], json!(1));
            assert_eq!(row["timestamp"], json!(expected_timestamp("2024-06-15T14:30:00Z")));
            assert_eq!(row["session_id"], json!(SESSION));
            assert_eq!(row["user_id"], json!(USER));
            assert_eq!(row["hostname"], json!("example.com"));
            assert_eq!(row["page_title"], json!(""));
            assert_eq!(row["region"], json!(""));
            assert_eq!(row["city"], json!(""));
            assert_eq!(row["browser"], json!("Chrome"));
            assert_eq!(row["operating_system"], json!("Windows"));
            assert_eq!(row["device_type"], json!("Desktop"));
        }

        #[test]
        fn turns_a_non_pageview_datapoint_into_a_custom_event() {
            let rows = rows(json!({ "datapoint": "signup" }));
            assert_eq!(rows[0]["type"], json!("custom_event"));
            assert_eq!(rows[0]["event_name"], json!("signup"));
        }

        #[test]
        fn reformats_the_timestamp_and_drops_fractional_seconds() {
            assert_eq!(rows(json!({ "added_iso": "2023-01-05T09:07:03Z" }))[0]["timestamp"],
                       json!(expected_timestamp("2023-01-05T09:07:03Z")));
            assert_eq!(rows(json!({ "added_iso": "2024-06-15T14:30:00.123Z" }))[0]["timestamp"],
                       json!(expected_timestamp("2024-06-15T14:30:00Z")));
        }

        #[test]
        fn drops_rows_with_non_iso_timestamps() {
            for added_iso in ["2024-06-15 14:30:00", "2024-06-15T14:30:00", "2024-06-15T14:30:00+02:00",
                              "not-a-date", ""] {
                assert!(rows(json!({ "added_iso": added_iso })).is_empty(), "{added_iso}");
            }
        }

        #[test]
        fn reads_the_user_agent() {
            let iphone = rows(json!({ "user_agent": IPHONE_UA, "screen_width": "390", "screen_height": "844" }));
            assert_eq!(iphone.len(), 1);
            assert_eq!(iphone[0]["operating_system"], json!("iOS"));
            assert_eq!(iphone[0]["device_type"], json!("Mobile"));

            let empty = rows(json!({ "user_agent": "" }));
            assert_eq!(empty.len(), 1);
            assert_eq!(empty[0]["browser"], json!(""));
            assert_eq!(empty[0]["browser_version"], json!(""));
            assert_eq!(empty[0]["operating_system"], json!(""));
            assert_eq!(empty[0]["operating_system_version"], json!(""));
            // 1920x1080, so the larger dimension puts it on Desktop
            assert_eq!(empty[0]["device_type"], json!("Desktop"));
        }

        #[test]
        fn combines_the_language_and_region() {
            assert_eq!(rows(json!({ "lang_language": "pt", "lang_region": "br" }))[0]["language"], json!("pt-BR"));
            assert_eq!(rows(json!({ "lang_language": "de", "lang_region": "" }))[0]["language"], json!("de"));
        }

        #[test]
        fn handles_the_querystring_and_referrer() {
            assert_eq!(rows(json!({ "query": "a=1" }))[0]["querystring"], json!("?a=1"));
            assert_eq!(rows(json!({ "query": "" }))[0]["querystring"], json!(""));
            assert_eq!(rows(json!({ "document_referrer": "https://example.com/previous" }))[0]["referrer"], json!(""));
            assert_eq!(rows(json!({ "document_referrer": "https://news.ycombinator.com/item" }))[0]["referrer"],
                       json!("https://news.ycombinator.com/item"));
            assert_eq!(rows(json!({ "document_referrer": "" }))[0]["referrer"], json!(""));
        }

        #[test]
        fn drops_rows_that_fail_the_schema() {
            for overrides in [json!({ "screen_width": "abc" }), json!({ "screen_width": "" }),
                              json!({ "screen_height": "1080.5" }), json!({ "screen_height": "" })] {
                assert!(rows(overrides.clone()).is_empty(), "{overrides}");
            }
            for country in ["USA", "us", "1A"] {
                assert!(rows(json!({ "country_code": country })).is_empty(), "{country}");
            }
            assert_eq!(rows(json!({ "country_code": "" }))[0]["country"], json!(""));
            assert!(rows(json!({ "session_id": "not-a-uuid" })).is_empty());
            assert!(rows(json!({ "uuid": "not-a-uuid" })).is_empty());
        }

        #[test]
        fn keeps_valid_rows_mixed_with_invalid_ones() {
            let events = [event(&base(), json!({ "path": "/valid" })),
                          event(&base(), json!({ "added_iso": "bad" })),
                          event(&base(), json!({ "path": "/also-valid" }))];
            let rows = transform(Platform::SimpleAnalytics, &events, 1, "i");
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["pathname"], json!("/valid"));
            assert_eq!(rows[1]["pathname"], json!("/also-valid"));
            assert!(transform(Platform::SimpleAnalytics, &[], 1, "i").is_empty());
        }
    }
}
