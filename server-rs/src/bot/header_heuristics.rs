//! Header heuristic scoring, ported from
//! server/src/services/tracker/botBlocking/headerHeuristics.ts (`detectBot`).
//!
//! The heuristics read Node's `IncomingHttpHeaders`, not the raw header list, so
//! the port reads headers through [`node_header`], which rebuilds the value Node
//! would have handed them: a duplicated `Accept-Language` is one comma-joined
//! string, an empty one is present-but-falsy, and bytes outside ASCII decode as
//! latin1.

use std::sync::LazyLock;

use axum::http::HeaderMap;

use super::{
    config::BOT_SCORE_THRESHOLD,
    js::{JsRegex, JsText, js_string_to_number},
};

/// `BotDetectionResult` (header heuristics): the score and the reasons it was
/// made of, comma-joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderDetection {
    pub is_bot: bool,
    pub score: i64,
    pub reason: Option<String>,
}

/// `BOT_FRAMEWORK_PATTERNS`: scripting framework signatures, matched as
/// substrings of the lowercased user agent.
const BOT_FRAMEWORK_PATTERNS: [&str; 25] = [
    "python-requests",
    "python-urllib",
    "go-http-client",
    "java/",
    "okhttp",
    "node-fetch",
    "undici",
    "curl/",
    "wget",
    "httpie",
    "scrapy",
    "phantomjs",
    "selenium",
    "puppeteer",
    "playwright",
    "headlesschrome",
    "apache-httpclient",
    "libwww-perl",
    "mechanize",
    "aiohttp",
    "httpx",
    "got/",
    "superagent",
    "postman",
    "insomnia",
];

/// `HEADLESS_PATTERNS`.
const HEADLESS_PATTERNS: [&str; 3] = ["headlesschrome", "headless", "phantomjs"];

/// Headers whose duplicates Node discards, keeping the first value
/// (`matchKnownFields` in node/lib/_http_incoming.js, as documented for
/// `message.headers`).
const NODE_FIRST_VALUE_HEADERS: [&str; 18] = [
    "age",
    "authorization",
    "content-length",
    "content-type",
    "etag",
    "expires",
    "from",
    "host",
    "if-modified-since",
    "if-unmodified-since",
    "last-modified",
    "location",
    "max-forwards",
    "proxy-authorization",
    "referer",
    "retry-after",
    "server",
    "user-agent",
];

/// The string Node's `request.headers[name]` holds for a lowercase header name:
/// the first value for the single-valued headers above, duplicate `cookie` values
/// joined with "; ", every other duplicate joined with ", ". Values are decoded
/// byte-for-byte as latin1, which is what Node's HTTP parser does. `set-cookie`
/// is an array in Node and is not supported here.
pub fn node_header(headers: &HeaderMap, name: &str) -> Option<String> {
    debug_assert!(name != "set-cookie", "set-cookie is an array in Node");
    let mut values = headers.get_all(name).iter();
    let first = latin1(values.next()?.as_bytes());
    if NODE_FIRST_VALUE_HEADERS.contains(&name) {
        return Some(first);
    }
    let separator = if name == "cookie" { "; " } else { ", " };
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(separator);
        joined.push_str(&latin1(value.as_bytes()));
        joined
    }))
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| char::from(byte)).collect()
}

/// JavaScript truthiness of an optional header string.
fn truthy(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|text| !text.is_empty())
}

static CHROME_VERSION: LazyLock<JsRegex> = LazyLock::new(|| JsRegex::new(r"Chrome\/(\d+)"));
static WINDOWS_MODERN: LazyLock<JsRegex> = LazyLock::new(|| JsRegex::new("Windows NT (1[0-9]|[2-9][0-9])"));
static MAC_VERSION: LazyLock<JsRegex> = LazyLock::new(|| JsRegex::new(r"Mac OS X (\d+)[_.](\d+)"));

/// `getChromeVersion`: `parseInt` of the digits after `Chrome/`. The number can
/// exceed any integer type, so it stays a double like Node's.
fn get_chrome_version(text: &JsText) -> Option<f64> {
    let found = CHROME_VERSION.exec(text)?;
    text.group(&found, 1).map(|digits| js_string_to_number(&digits))
}

/// `claimsModernOS`: Windows 10+ or macOS 10.15+.
fn claims_modern_os(text: &JsText) -> bool {
    if WINDOWS_MODERN.test(text) {
        return true;
    }
    if let Some(found) = MAC_VERSION.exec(text) {
        let major = text.group(&found, 1).map(|digits| js_string_to_number(&digits)).unwrap_or(f64::NAN);
        if major >= 11.0 {
            return true;
        }
        let minor = text.group(&found, 2).map(|digits| js_string_to_number(&digits)).unwrap_or(f64::NAN);
        if major == 10.0 && minor >= 15.0 {
            return true;
        }
    }
    false
}

/// `detectBot`: score-based detection from headers real browsers always send
/// and scripting clients typically miss.
pub fn detect_bot(headers: &HeaderMap, user_agent: &str) -> HeaderDetection {
    let mut score = 0;
    let mut reasons: Vec<&str> = Vec::new();
    let lower_ua = user_agent.to_lowercase();

    // 1. Known bot framework signatures (instant kill)
    for pattern in BOT_FRAMEWORK_PATTERNS {
        if lower_ua.contains(pattern) {
            return HeaderDetection { is_bot: true, score: 5, reason: Some(format!("bot_framework:{pattern}")) };
        }
    }

    // 2. Headless browser patterns
    if let Some(pattern) = HEADLESS_PATTERNS.iter().find(|pattern| lower_ua.contains(*pattern)) {
        score += 3;
        reasons.push(match *pattern {
            "headlesschrome" => "headless:headlesschrome",
            "headless" => "headless:headless",
            _ => "headless:phantomjs",
        });
    }

    // 3. Missing Accept-Language: every real browser sends it
    if !truthy(&node_header(headers, "accept-language")) {
        score += 3;
        reasons.push("missing_accept_language");
    }

    // 4. Missing Accept
    if !truthy(&node_header(headers, "accept")) {
        score += 2;
        reasons.push("missing_accept");
    }

    // 5. Missing Accept-Encoding, or no gzip support
    let accept_encoding = node_header(headers, "accept-encoding");
    match accept_encoding.as_deref() {
        None | Some("") => {
            score += 2;
            reasons.push("missing_accept_encoding");
        }
        Some(encoding) if !encoding.contains("gzip") => {
            score += 2;
            reasons.push("no_gzip_support");
        }
        Some(_) => {}
    }

    // 6. Missing sec-fetch-site when the UA claims Chrome 76+, which always sends
    // fetch metadata. `chromeVersion &&` skips version 0 and NaN.
    let text = JsText::new(user_agent);
    let chrome_version = get_chrome_version(&text).filter(|version| *version != 0.0 && !version.is_nan());
    if let Some(version) = chrome_version
        && version >= 76.0
    {
        if !truthy(&node_header(headers, "sec-fetch-site")) {
            score += 2;
            reasons.push("missing_sec_fetch_site");
        }

        // 7. The tracker's fetch() uses "cors" mode, never "navigate"
        if node_header(headers, "sec-fetch-mode").as_deref() == Some("navigate") {
            score += 2;
            reasons.push("sec_fetch_mode_navigate");
        }
    }

    // 8. Stale Chrome (< 80) claiming a modern OS
    if let Some(version) = chrome_version
        && version < 80.0
        && claims_modern_os(&text)
    {
        score += 2;
        reasons.push("stale_chrome_version");
    }

    HeaderDetection {
        is_bot: score >= BOT_SCORE_THRESHOLD,
        score,
        reason: (!reasons.is_empty()).then(|| reasons.join(",")),
    }
}

#[cfg(test)]
pub(crate) fn header_map(pairs: &[(&str, &[u8])]) -> HeaderMap {
    use axum::http::{HeaderName, HeaderValue};
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_bytes(value).expect("header value"),
        );
    }
    map
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/tracker/botBlocking/headerHeuristics.test.ts.
    use super::*;

    const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    #[test]
    fn detects_scripting_framework_user_agents() {
        assert_eq!(
            detect_bot(&HeaderMap::new(), "python-requests/2.31.0"),
            HeaderDetection { is_bot: true, score: 5, reason: Some("bot_framework:python-requests".into()) }
        );
    }

    #[test]
    fn detects_default_okhttp_react_native_requests() {
        assert_eq!(
            detect_bot(&HeaderMap::new(), "okhttp/4.12.0"),
            HeaderDetection { is_bot: true, score: 5, reason: Some("bot_framework:okhttp".into()) }
        );
    }

    #[test]
    fn does_not_block_react_native_sdk_requests_that_send_sdk_headers() {
        let headers = header_map(&[("accept", b"application/json"), ("accept-language", b"en-US,en;q=0.9")]);
        assert_eq!(
            detect_bot(
                &headers,
                "Mozilla/5.0 (Linux; Android 36) AppleWebKit/537.36 (KHTML, like Gecko) HygoReactNative/0.1.1"
            ),
            HeaderDetection { is_bot: false, score: 2, reason: Some("missing_accept_encoding".into()) }
        );
    }

    #[test]
    fn scores_missing_browser_headers() {
        let result = detect_bot(&HeaderMap::new(), BROWSER_USER_AGENT);
        assert!(result.is_bot);
        assert_eq!(result.score, 9);
        let reason = result.reason.unwrap();
        for expected in
            ["missing_accept_language", "missing_accept", "missing_accept_encoding", "missing_sec_fetch_site"]
        {
            assert!(reason.contains(expected), "{reason}");
        }
    }

    #[test]
    fn does_not_score_complete_browser_fetch_headers() {
        let headers = header_map(&[
            ("accept", b"*/*"),
            ("accept-encoding", b"gzip, br"),
            ("accept-language", b"en-US,en;q=0.9"),
            ("sec-fetch-site", b"cross-site"),
        ]);
        assert_eq!(detect_bot(&headers, BROWSER_USER_AGENT), HeaderDetection { is_bot: false, score: 0, reason: None });
    }

    #[test]
    fn reads_headers_the_way_node_builds_them() {
        let headers = header_map(&[
            ("accept-language", b""),
            ("accept-language", b"en"),
            ("user-agent", b"first"),
            ("user-agent", b"second"),
            ("cookie", b"a=1"),
            ("cookie", b"b=2"),
            ("sec-fetch-mode", b"navigate"),
            ("sec-fetch-mode", b"navigate"),
            ("accept", b"caf\xe9"),
        ]);
        assert_eq!(node_header(&headers, "accept-language").as_deref(), Some(", en"));
        assert_eq!(node_header(&headers, "user-agent").as_deref(), Some("first"));
        assert_eq!(node_header(&headers, "cookie").as_deref(), Some("a=1; b=2"));
        assert_eq!(node_header(&headers, "sec-fetch-mode").as_deref(), Some("navigate, navigate"));
        assert_eq!(node_header(&headers, "accept").as_deref(), Some("caf\u{e9}"));
        assert_eq!(node_header(&headers, "sec-fetch-site"), None);
    }

    #[test]
    fn treats_an_empty_header_as_missing() {
        let headers = header_map(&[("accept", b"*/*"), ("accept-encoding", b""), ("accept-language", b"")]);
        let result = detect_bot(&headers, "Mozilla/5.0");
        assert_eq!(result.reason.as_deref(), Some("missing_accept_language,missing_accept_encoding"));
    }
}
