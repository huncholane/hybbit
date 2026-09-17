//! User agent parsing: a port of ua-parser-js 2.0.3 (browser, OS, device, engine,
//! CPU) as the Node server calls it, plus `getDeviceType` from server/src/utils.ts.
//!
//! Node calls `UAParser(ua)` with a plain string everywhere (tracking through the
//! cached `parseUserAgent`, and directly in session replay, feature flags and the
//! Simple Analytics importer), so no client hints or extensions are involved. What
//! reaches ClickHouse is `browser.name`, `browser.major`, `os.name`, `os.version`
//! and the `getDeviceType` result; those are computed eagerly. Device, engine and
//! CPU are ported with the same parity but parsed lazily on first access, because
//! the device table is the most expensive one and nothing downstream reads it yet.
//!
//! Layout:
//! - `regexes.rs`: the ua-parser-js tables, generated from the JS by `tools/generate.cjs`;
//! - `translate.rs`: JS regex syntax to `regex` / `fancy-regex` syntax;
//! - `parser.rs`: truncation, the ASCII haystack, compiled tables, `rgxMapper`;
//! - `table.rs`: property semantics, `strMapper` and the replace helpers;
//! - `cache.rs`: the LRU in front of it all; `device_type.rs`: `getDeviceType`.
//!
//! The caller must hand over the UA string Node would see. For request headers
//! Node decodes the raw bytes as latin1, so the tracking port has to do the same
//! before calling in.
#![allow(dead_code)] // consumed by the tracking pipeline as it is ported

mod cache;
mod device_type;
mod parser;
#[cfg(test)]
mod parity;
mod regexes;
mod table;
mod translate;

use std::{
    sync::{Arc, LazyLock, Mutex, OnceLock},
    time::Instant,
};

#[allow(unused_imports)] // re-exported for the tracking port
pub use device_type::get_device_type;
use parser::{Haystack, TABLES, majorize, rgx_mapper, truncate};

/// `UA_CACHE_MAX` in server/src/services/tracker/utils.ts.
pub const UA_CACHE_MAX: usize = 10_000;

/// `IBrowser`. Every field is `undefined` in JS when absent; an empty string is
/// possible only for `major` (e.g. version "v.1").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Browser {
    pub name: Option<String>,
    pub version: Option<String>,
    pub major: Option<String>,
    /// "inapp" for in-app browsers.
    pub r#type: Option<String>,
}

/// `IOS`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Os {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// `IDevice`. `type` is one of console, mobile, tablet, smarttv, wearable, xr,
/// embedded (or, through a strMapper quirk for "itel" UAs, "*").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Device {
    pub r#type: Option<String>,
    pub model: Option<String>,
    pub vendor: Option<String>,
}

/// `IEngine`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Engine {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// `ICPU`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cpu {
    pub architecture: Option<String>,
}

/// `IResult` of `UAParser(ua)`.
#[derive(Debug)]
pub struct ParsedUserAgent {
    /// `result.ua`: the input after UA_MAX_LENGTH truncation.
    pub ua: String,
    pub browser: Browser,
    pub os: Os,
    /// The truncation split a surrogate pair; JS kept half of it (see parser.rs).
    dangling_high_surrogate: bool,
    device: OnceLock<Device>,
    engine: OnceLock<Engine>,
    cpu: OnceLock<Cpu>,
}

impl ParsedUserAgent {
    fn haystack(&self) -> Haystack<'_> {
        Haystack::new(&self.ua, self.dangling_high_surrogate)
    }

    /// `result.device`, parsed on first access.
    pub fn device(&self) -> &Device {
        self.device.get_or_init(|| {
            let fields = rgx_mapper(&self.haystack(), &TABLES.device);
            Device { r#type: fields.r#type, model: fields.model, vendor: fields.vendor }
        })
    }

    /// `result.engine`, parsed on first access.
    pub fn engine(&self) -> &Engine {
        self.engine.get_or_init(|| {
            let fields = rgx_mapper(&self.haystack(), &TABLES.engine);
            Engine { name: fields.name, version: fields.version }
        })
    }

    /// `result.cpu`, parsed on first access.
    pub fn cpu(&self) -> &Cpu {
        self.cpu.get_or_init(|| Cpu { architecture: rgx_mapper(&self.haystack(), &TABLES.cpu).architecture })
    }
}

/// `UAParser(ua)` without the cache: what session replay, feature flag evaluation
/// and the Simple Analytics importer call.
pub fn parse(ua: &str) -> ParsedUserAgent {
    let (truncated, dangling_high_surrogate) = truncate(ua);
    if truncated.len() != ua.len() {
        tracing::debug!(
            original_bytes = ua.len(),
            truncated_bytes = truncated.len(),
            "user agent longer than UA_MAX_LENGTH, truncated like ua-parser-js"
        );
    }
    let haystack = Haystack::new(truncated, dangling_high_surrogate);

    let browser_fields = rgx_mapper(&haystack, &TABLES.browser);
    let major = majorize(browser_fields.version.as_deref());
    let browser = Browser { name: browser_fields.name, version: browser_fields.version, major, r#type: browser_fields.r#type };

    let os_fields = rgx_mapper(&haystack, &TABLES.os);
    let os = Os { name: os_fields.name, version: os_fields.version };

    ParsedUserAgent {
        ua: truncated.to_string(),
        browser,
        os,
        dangling_high_surrogate,
        device: OnceLock::new(),
        engine: OnceLock::new(),
        cpu: OnceLock::new(),
    }
}

static CACHE: LazyLock<Mutex<cache::Lru<Arc<ParsedUserAgent>>>> = LazyLock::new(|| Mutex::new(cache::Lru::new(UA_CACHE_MAX)));

/// `parseUserAgent` from server/src/services/tracker/utils.ts: `UAParser(ua)`
/// memoised in a 10,000-entry LRU keyed by the raw (untruncated) UA.
pub fn parse_user_agent(user_agent: &str) -> Arc<ParsedUserAgent> {
    if let Some(hit) = lock_cache().get(user_agent) {
        tracing::trace!(ua_bytes = user_agent.len(), "user agent cache hit");
        return hit;
    }

    // parse outside the lock; two threads racing on the same new UA both parse it
    // and the later insert wins, which is invisible to callers
    let started = Instant::now();
    let parsed = Arc::new(parse(user_agent));
    let elapsed_us = started.elapsed().as_secs_f64() * 1e6;

    let (evicted, size) = {
        let mut cache = lock_cache();
        let evicted = cache.insert(user_agent, parsed.clone());
        (evicted, cache.len())
    };
    tracing::debug!(
        ua_bytes = user_agent.len(),
        browser = parsed.browser.name.as_deref().unwrap_or(""),
        os = parsed.os.name.as_deref().unwrap_or(""),
        elapsed_us,
        cache_size = size,
        evicted = evicted.is_some(),
        "user agent cache miss, parsed"
    );
    parsed
}

fn lock_cache() -> std::sync::MutexGuard<'static, cache::Lru<Arc<ParsedUserAgent>>> {
    // nothing inside the critical sections can panic short of allocation failure,
    // so a poisoned lock still guards a consistent list: keep serving from it
    CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Compiles every table now instead of on the first tracked event.
pub fn warm_up() {
    LazyLock::force(&TABLES);
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_WINDOWS_UA: &str =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
    const IPHONE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

    /// The pageview row fields Node derives from a parse (pageviewQueue.ts).
    fn row(ua: &ParsedUserAgent, width: f64, height: f64) -> [String; 5] {
        [
            ua.browser.name.clone().unwrap_or_default(),
            ua.browser.major.clone().unwrap_or_default(),
            ua.os.name.clone().unwrap_or_default(),
            ua.os.version.clone().unwrap_or_default(),
            get_device_type(width, height, ua).to_string(),
        ]
    }

    // ported from server/src/services/import/mappers/simpleAnalytics.test.ts
    #[test]
    fn simple_analytics_transform_valid_pageview() {
        let parsed = parse(CHROME_WINDOWS_UA);
        assert_eq!(row(&parsed, 1920.0, 1080.0), ["Chrome", "125", "Windows", "10", "Desktop"]);
    }

    #[test]
    fn simple_analytics_iphone_is_mobile_ios() {
        let parsed = parse(IPHONE_UA);
        assert_eq!(parsed.os.name.as_deref(), Some("iOS"));
        assert_eq!(get_device_type(390.0, 844.0, &parsed), "Mobile");
    }

    #[test]
    fn simple_analytics_empty_ua_falls_back_to_screen() {
        let parsed = parse("");
        assert_eq!(row(&parsed, 1920.0, 1080.0), ["", "", "", "", "Desktop"]);
    }

    #[test]
    fn full_result_for_common_browsers() {
        let parsed = parse(IPHONE_UA);
        assert_eq!(
            parsed.browser,
            Browser { name: Some("Mobile Safari".into()), version: Some("17.5".into()), major: Some("17".into()), r#type: None }
        );
        assert_eq!(parsed.os, Os { name: Some("iOS".into()), version: Some("17.5".into()) });
        assert_eq!(
            parsed.device(),
            &Device { r#type: Some("mobile".into()), model: Some("iPhone".into()), vendor: Some("Apple".into()) }
        );
        assert_eq!(parsed.engine(), &Engine { name: Some("WebKit".into()), version: Some("605.1.15".into()) });
        assert_eq!(parsed.cpu(), &Cpu { architecture: None });

        let chrome = parse(CHROME_WINDOWS_UA);
        assert_eq!(chrome.engine().name.as_deref(), Some("Blink"));
        assert_eq!(chrome.cpu().architecture.as_deref(), Some("amd64"));
        assert_eq!(chrome.device(), &Device::default());
    }

    #[test]
    fn cached_parse_returns_the_same_result() {
        let first = parse_user_agent(CHROME_WINDOWS_UA);
        let second = parse_user_agent(CHROME_WINDOWS_UA);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.browser.name.as_deref(), Some("Chrome"));
    }

    #[test]
    fn long_user_agents_are_truncated_like_js() {
        let ua = format!("   {CHROME_WINDOWS_UA}{}", " x".repeat(300));
        let parsed = parse(&ua);
        assert_eq!(parsed.ua.len(), 500);
        assert!(parsed.ua.starts_with("Mozilla/5.0"));
        assert_eq!(parsed.browser.name.as_deref(), Some("Chrome"));
    }
}
