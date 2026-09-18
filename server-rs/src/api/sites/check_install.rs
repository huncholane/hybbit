//! `GET /api/site/check-install`, ported from server/src/api/sites/checkInstall.ts
//! together with the pieces it uses: `signedToken.ts`'s expiring HMAC and the
//! `fetchHomepage` / `hasHygoScript` half of
//! server/src/services/lifecycleEmails/platformDetect.ts.
//!
//! The route is registered with no preHandler at all: the signed, expiring
//! `(siteId, domain)` pair is what keeps it from being an open fetch proxy, and a
//! per-IP limiter (5 a minute, in process) keeps a leaked link from being a probe
//! loop. Both the 400 and the 429 are HTML bodies, which the `/api` error rewrite
//! then replaces with JSON, exactly as in Node.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{LazyLock, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use hmac::{Hmac, KeyInit, Mac};
use regress::{Flags, Regex};
use sha2::Sha256;
use tracing::{debug, info, warn};

use super::request;
use crate::{
    analytics::{
        chain::fastify_query,
        js::JsValue,
        routes::{people::common::path_params, workspace::request::request_ip},
    },
    state::AppState,
};

/// `RATE_LIMIT_WINDOW_MS`
const RATE_LIMIT_WINDOW_MS: u64 = 60_000;
/// `RATE_LIMIT_MAX`
const RATE_LIMIT_MAX: u64 = 5;
/// `MAX_BODY_BYTES`
const MAX_BODY_BYTES: usize = 512 * 1024;
/// `FETCH_TIMEOUT_MS`
const FETCH_TIMEOUT: Duration = Duration::from_millis(8000);
/// `MAX_REDIRECTS`
const MAX_REDIRECTS: usize = 3;

const USER_AGENT: &str = "Mozilla/5.0 (compatible; HygoSetupCheck/1.0; +https://hygo.ai)";

/// `rateBuckets`: (count, resetAt in epoch milliseconds).
static RATE_BUCKETS: LazyLock<Mutex<HashMap<String, (u64, u64)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// `isRateLimited`
fn is_rate_limited(ip: &str) -> bool {
    let now = now_ms();
    let mut buckets = RATE_BUCKETS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match buckets.get_mut(ip) {
        Some(bucket) if bucket.1 >= now => {
            bucket.0 += 1;
            bucket.0 > RATE_LIMIT_MAX
        }
        _ => {
            // Opportunistic cleanup so the map does not grow unbounded
            if buckets.len() > 10_000 {
                buckets.retain(|_, (_, reset_at)| *reset_at >= now);
            }
            buckets.insert(ip.to_string(), (1, now + RATE_LIMIT_WINDOW_MS));
            false
        }
    }
}

/// `signPayload`: HMAC-SHA256 with `SECRET || ""`, base64url without padding.
pub fn sign_payload(secret: &str, payload: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key length");
    mac.update(payload.as_bytes());
    let digest = mac.finalize().into_bytes();
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// `verifySignedPayload`: equal byte lengths, then a constant-time comparison.
fn verify_signed_payload(secret: &str, payload: &str, provided: &[u8]) -> bool {
    let expected = sign_payload(secret, payload);
    let expected = expected.as_bytes();
    if expected.len() != provided.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(provided) {
        difference |= left ^ right;
    }
    difference == 0
}

/// `verifyExpiringPayload`
fn verify_expiring_payload(secret: &str, payload: &str, exp: &JsValue, signature: &[u8]) -> bool {
    let exp_number = request::js_number(&exp.to_js_string());
    if !exp_number.is_finite() || exp_number < now_ms() as f64 / 1000.0 {
        return false;
    }
    // `Math.floor` of the expiry, so the signed text is the integer form
    let floored = crate::js_json::number_to_string(exp_number.floor());
    verify_signed_payload(secret, &format!("{payload}:{floored}"), signature)
}

/// `Buffer.from(value)` for a query value: a string's UTF-8 bytes, or an array
/// read as bytes (`ToNumber(element) & 255`, NaN becoming 0).
fn buffer_from(value: &JsValue) -> Vec<u8> {
    match value {
        JsValue::String(text) => text.as_bytes().to_vec(),
        JsValue::Array(items) => items
            .iter()
            .map(|item| {
                let number = request::js_number(&item.to_js_string());
                if number.is_finite() { (number.trunc() as i64 & 0xFF) as u8 } else { 0 }
            })
            .collect(),
        other => other.to_js_string().as_bytes().to_vec(),
    }
}

/// `escapeHtml`
fn escape_html(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The `page` template literal.
fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} - Hygo</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0e1013; color: #e5e7eb; display: flex; justify-content: center; padding: 80px 24px; margin: 0; }}
    main {{ max-width: 480px; }}
    h1 {{ font-size: 20px; color: #fff; }}
    p {{ line-height: 1.6; color: #9ca3af; }}
    a {{ color: #10b981; }}
  </style>
</head>
<body><main><h1>{title}</h1><p>{body}</p></main></body>
</html>"#
    )
}

/// `reply.status(status).type("text/html").send(html)`
fn html(status: StatusCode, body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    response
}

// ---------------------------------------------------------------------------
// The homepage fetch (platformDetect.ts)

/// The bare-hostname test `fetchHomepage` applies before anything else.
static HOSTNAME_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::with_flags(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", Flags::from("i"))
        .expect("hostname pattern compiles")
});

/// `isPublicV4`
fn is_public_v4(address: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = address.octets();
    if a == 0 || a == 10 || a == 127 {
        return false;
    }
    if a == 100 && (64..=127).contains(&b) {
        return false; // CGNAT 100.64/10
    }
    if a == 169 && b == 254 {
        return false; // link-local / metadata
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    if a == 192 && b == 0 {
        return false; // 192.0.0/24 + 192.0.2/24 (docs)
    }
    if a == 198 && (b == 18 || b == 19) {
        return false; // benchmarking
    }
    if a == 198 && b == 51 {
        return false; // 198.51.100/24 docs
    }
    if a == 203 && b == 113 {
        return false; // 203.0.113/24 docs
    }
    a < 224 // multicast + reserved + broadcast
}

/// `isPublicUnicastAddress`
pub fn is_public_unicast_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            // v4-mapped / v4-translated: judge the embedded v4
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let segments = v6.segments();
            if v6.is_unspecified() || v6.is_loopback() {
                return false;
            }
            let first = segments[0];
            if (0xfc00..0xfe00).contains(&first) {
                return false; // unique local fc00::/7
            }
            if (0xfe80..0xfec0).contains(&first) {
                return false; // link-local fe80::/10
            }
            if first & 0xff00 == 0xff00 {
                return false; // multicast
            }
            true
        }
    }
}

/// `isSafeTarget`: only http/https on default ports, no credentials, and every
/// address the hostname resolves to must be publicly routable.
async fn is_safe_target(url: &url::Url) -> bool {
    if url.scheme() != "https" && url.scheme() != "http" {
        return false;
    }
    if url.port().is_some_and(|port| port != 80 && port != 443) {
        return false;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else { return false };
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    if let Ok(address) = host.parse::<IpAddr>() {
        return is_public_unicast_address(address);
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") || lower.ends_with(".internal") {
        return false;
    }
    let resolved = tokio::task::spawn_blocking(move || {
        (host.as_str(), 0u16).to_socket_addrs().map(|addresses| addresses.collect::<Vec<SocketAddr>>())
    })
    .await;
    match resolved {
        Ok(Ok(addresses)) => {
            !addresses.is_empty() && addresses.iter().all(|address| is_public_unicast_address(address.ip()))
        }
        _ => false,
    }
}

/// `fetchHomepage`: the site's homepage HTML, or None when it is unreachable.
pub async fn fetch_homepage(domain: &str) -> Option<String> {
    if HOSTNAME_PATTERN.find(domain).is_none() {
        return None;
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(FETCH_TIMEOUT)
        .build()
        .ok()?;

    for scheme in ["https", "http"] {
        let Ok(mut url) = url::Url::parse(&format!("{scheme}://{domain}/")) else { return None };
        for _ in 0..=MAX_REDIRECTS {
            if !is_safe_target(&url).await {
                debug!(domain, target = %url, "Blocked non-public fetch target");
                break;
            }
            let response = client
                .get(url.clone())
                .header(header::USER_AGENT, USER_AGENT)
                .header(header::ACCEPT, "text/html")
                .send()
                .await;
            let Ok(response) = response else {
                debug!(domain, scheme, "Homepage fetch failed");
                break;
            };
            let status = response.status();
            if status.is_redirection() {
                let location = response.headers().get(header::LOCATION).and_then(|value| value.to_str().ok());
                let Some(location) = location else { break };
                match url.join(location) {
                    Ok(next) => url = next,
                    Err(_) => break,
                }
                continue;
            }
            if !status.is_success() {
                break;
            }
            return Some(read_body(response).await);
        }
    }
    None
}

/// `readBody`: chunks until the cap is reached, then the bytes as UTF-8.
async fn read_body(mut response: reqwest::Response) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    while bytes.len() < MAX_BODY_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            _ => break,
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `hasHygoScript`: a script reference plus a matching `data-site-id`, so a
/// leftover snippet for a different site does not report success.
pub fn has_hygo_script(html: &str, site_id: f64) -> bool {
    static SCRIPT: LazyLock<Regex> =
        LazyLock::new(|| Regex::with_flags(r"api/script\.js|hygo\.js", Flags::from("i")).expect("script pattern compiles"));
    if SCRIPT.find(html).is_none() {
        return false;
    }
    let id = crate::js_json::number_to_string(site_id);
    let Ok(pattern) = Regex::with_flags(&format!(r#"data-site-id=["']?{id}["'\s>]"#), Flags::from("i")) else {
        return false;
    };
    pattern.find(html).is_some()
}

// ---------------------------------------------------------------------------

pub async fn check_install(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    // The route has no parameters, but a path find-my-way cannot decode is still
    // Fastify's bad-URL answer
    if let Err(response) = path_params(&method, &uri, &[]).await {
        return response;
    }
    let query = fastify_query(&uri);
    let site_id_raw = query.get_or_undefined("siteId").clone();
    let domain = query.get_or_undefined("domain").clone();
    let exp = query.get_or_undefined("exp").clone();
    let sig = query.get_or_undefined("sig").clone();

    let site_id = request::js_number(&site_id_raw.to_js_string());
    let secret = state.config.better_auth_secret.clone().unwrap_or_default();
    let integer_id = site_id.is_finite() && site_id.fract() == 0.0;
    let signed = integer_id
        && verify_expiring_payload(
            &secret,
            &format!("check-install:{}:{}", crate::js_json::number_to_string(site_id), domain.to_js_string()),
            &exp,
            &buffer_from(&sig),
        );

    if !truthy(&domain) || !truthy(&sig) || !truthy(&exp) || !integer_id || !signed {
        debug!("Install-check link rejected");
        return html(
            StatusCode::BAD_REQUEST,
            page("Invalid link", "This install-check link is invalid or expired."),
        );
    }

    let ip = request_ip(&headers, peer.ip());
    if is_rate_limited(&ip) {
        warn!(ip = %ip, "Install check rate limited");
        return html(
            StatusCode::TOO_MANY_REQUESTS,
            page("Slow down", "Too many checks in a row - wait a minute and try again."),
        );
    }

    let domain_text = domain.to_js_string();
    let Some(page_html) = fetch_homepage(&domain_text).await else {
        info!(domain = %domain_text, site_id, "Install check could not reach the homepage");
        return html(
            StatusCode::OK,
            page(
                &format!("Couldn't reach {}", escape_html(&domain_text)),
                "We couldn't fetch your homepage just now. If the site is up, it may be blocking automated requests - check the page source manually for the Hygo snippet, or reply to the email and we'll help.",
            ),
        );
    };

    if has_hygo_script(&page_html, site_id) {
        info!(domain = %domain_text, site_id, "Install check found the snippet");
        return html(
            StatusCode::OK,
            page(
                &format!("The snippet is installed on {}", escape_html(&domain_text)),
                "We found the Hygo script with your site ID on your homepage. If data still isn't showing up after a few minutes, an adblocker may be blocking your own test visits - try a private window, or see <a href=\"https://hygo.ai/docs/script-troubleshooting\">the troubleshooting guide</a>.",
            ),
        );
    }

    info!(domain = %domain_text, site_id, "Install check did not find the snippet");
    html(
        StatusCode::OK,
        page(
            &format!("The snippet isn't on {} yet", escape_html(&domain_text)),
            "We fetched your homepage and couldn't find the Hygo script with your site ID in it. Add the snippet to the &lt;head&gt; of every page and redeploy - see <a href=\"https://hygo.ai/docs/script\">the install guide</a>. If a snippet is there but for a different site ID, data is being sent to the wrong site.",
        ),
    )
}

/// JavaScript truthiness for a query value: `undefined` and `""` are falsy, an
/// array (even an empty one) is not.
fn truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Undefined | JsValue::Null => false,
        JsValue::String(text) => !text.is_empty(),
        JsValue::Bool(flag) => *flag,
        JsValue::Number(number) => *number != 0.0 && !number.is_nan(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "parity-local-secret-not-for-production";

    #[test]
    fn signature_matches_the_node_helper() {
        // signPayload("check-install:1:example.com") from server/src/lib/signedToken.ts
        let signature = sign_payload(SECRET, "check-install:1:example.com:1789700000");
        assert_eq!(signature.len(), 43, "base64url sha256 without padding");
        assert!(verify_signed_payload(SECRET, "check-install:1:example.com:1789700000", signature.as_bytes()));
        assert!(!verify_signed_payload(SECRET, "check-install:1:example.com:1789700001", signature.as_bytes()));
        assert!(!verify_signed_payload(SECRET, "check-install:1:example.com:1789700000", b"short"));
    }

    #[test]
    fn expiry_is_part_of_the_signature() {
        let future = (now_ms() / 1000 + 3600) as f64;
        let payload = "check-install:1:example.com";
        let signature = sign_payload(SECRET, &format!("{payload}:{future}"));
        assert!(verify_expiring_payload(SECRET, payload, &JsValue::Number(future), signature.as_bytes()));
        let past = (now_ms() / 1000 - 10) as f64;
        let stale = sign_payload(SECRET, &format!("{payload}:{past}"));
        assert!(!verify_expiring_payload(SECRET, payload, &JsValue::Number(past), stale.as_bytes()));
        assert!(!verify_expiring_payload(SECRET, payload, &JsValue::String("nope".into()), signature.as_bytes()));
    }

    #[test]
    fn script_detection_needs_both_markers() {
        assert!(has_hygo_script(r#"<script src="/api/script.js" data-site-id="7"></script>"#, 7.0));
        assert!(has_hygo_script(r#"<script src="https://x/hygo.js" data-site-id=7 ></script>"#, 7.0));
        assert!(!has_hygo_script(r#"<script src="/api/script.js" data-site-id="8"></script>"#, 7.0));
        assert!(!has_hygo_script(r#"<script data-site-id="7"></script>"#, 7.0));
        // a longer id must not match on its prefix
        assert!(!has_hygo_script(r#"<script src="/api/script.js" data-site-id="70"></script>"#, 7.0));
    }

    #[test]
    fn private_addresses_are_refused() {
        for address in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(!is_public_unicast_address(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
            assert!(is_public_unicast_address(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn html_is_escaped_in_the_page() {
        assert_eq!(escape_html("<a href=\"x\">&"), "&lt;a href=&quot;x&quot;&gt;&amp;");
        assert!(page("t", "b").starts_with("<!doctype html>"));
    }
}
