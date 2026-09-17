//! Better Auth's request rate limiter (better-auth/dist/api/rate-limiter) with the
//! memory store, and the client IP resolution it and session creation share
//! (@better-auth/core/utils/ip `getIp`).
//!
//! Like Node the buckets live in this process only: with both backends serving
//! /api/auth during cutover, each keeps its own counts.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use axum::http::HeaderMap;
use tracing::warn;

const MEMORY_STORE_MAX_ENTRIES: usize = 100_000;

/// `z.ipv4()`
fn is_ipv4(text: &str) -> bool {
    text.parse::<Ipv4Addr>().is_ok()
}

/// `z.ipv6()`
fn is_ipv6(text: &str) -> bool {
    text.parse::<Ipv6Addr>().is_ok()
}

/// `expandIPv6`: four hex digits per group, zero groups filled in for `::`
fn expand_ipv6(ip: &str) -> Vec<String> {
    let pad = |group: &str| format!("{group:0>4}");
    if let Some((left, right)) = ip.split_once("::") {
        let left: Vec<&str> = if left.is_empty() { Vec::new() } else { left.split(':').collect() };
        let right: Vec<&str> = if right.is_empty() { Vec::new() } else { right.split(':').collect() };
        let missing = 8usize.saturating_sub(left.len() + right.len());
        let mut groups: Vec<String> = left.iter().map(|g| pad(g)).collect();
        groups.extend(std::iter::repeat_n("0000".to_string(), missing));
        groups.extend(right.iter().map(|g| pad(g)));
        return groups;
    }
    ip.split(':').map(pad).collect()
}

/// `extractIPv4FromMapped`
fn extract_ipv4_from_mapped(ip: &str) -> Option<String> {
    let lower = ip.to_lowercase();
    if let Some(rest) = lower.strip_prefix("::ffff:")
        && is_ipv4(rest)
    {
        return Some(rest.to_string());
    }
    let parts: Vec<&str> = ip.split(':').collect();
    if parts.len() == 7 && parts[5].to_lowercase() == "ffff" && is_ipv4(parts[6]) {
        return Some(parts[6].to_string());
    }
    if lower.contains("::ffff:") || lower.contains(":ffff:") {
        let groups = expand_ipv6(ip);
        if groups.len() == 8 && groups[..5].iter().all(|g| g == "0000") && groups[5] == "ffff" && !groups[6].is_empty() && !groups[7].is_empty() {
            let byte = |group: &str, range: std::ops::Range<usize>| group.get(range).and_then(|h| u8::from_str_radix(h, 16).ok()).unwrap_or(0);
            return Some(format!(
                "{}.{}.{}.{}",
                byte(&groups[6], 0..2),
                byte(&groups[6], 2..4),
                byte(&groups[7], 0..2),
                byte(&groups[7], 2..4)
            ));
        }
    }
    None
}

/// `normalizeIP(ip, { ipv6Subnet: 64 })`
pub fn normalize_ip(ip: &str) -> String {
    if is_ipv4(ip) || !is_ipv6(ip) {
        return ip.to_lowercase();
    }
    if let Some(v4) = extract_ipv4_from_mapped(ip) {
        return v4.to_lowercase();
    }
    let groups = expand_ipv6(ip);
    let mut bits_remaining = 64i32;
    groups
        .iter()
        .map(|group| {
            if bits_remaining <= 0 {
                return "0000".to_string();
            }
            if bits_remaining >= 16 {
                bits_remaining -= 16;
                return group.clone();
            }
            let value = u16::from_str_radix(group, 16).unwrap_or(0);
            let masked = value & (0xffffu16 << (16 - bits_remaining));
            bits_remaining = 0;
            format!("{masked:04x}")
        })
        .collect::<Vec<_>>()
        .join(":")
        .to_lowercase()
}

/// `getIp(request, options)`: only a single-valued, valid `x-forwarded-for` is
/// trusted. Development and test fall back to 127.0.0.1.
pub fn client_ip(headers: &HeaderMap, development_or_test: bool) -> Option<String> {
    if let Some(value) = headers.get("x-forwarded-for").and_then(|value| value.to_str().ok()) {
        let forwarded: Vec<&str> = value.split(',').map(str::trim).filter(|ip| !ip.is_empty()).collect();
        if forwarded.len() == 1 && (is_ipv4(forwarded[0]) || is_ipv6(forwarded[0])) {
            return Some(normalize_ip(forwarded[0]));
        }
    }
    development_or_test.then(|| "127.0.0.1".to_string())
}

/// `normalizePathname(url, "/api/auth")`
pub fn normalize_pathname(pathname: &str) -> String {
    let trimmed = pathname.trim_end_matches('/');
    let pathname = if trimmed.is_empty() { "/" } else { trimmed };
    if pathname == "/api/auth" {
        return "/".to_string();
    }
    if let Some(rest) = pathname.strip_prefix("/api/auth/") {
        let rest = format!("/{rest}");
        let rest = rest.trim_end_matches('/');
        return if rest.is_empty() { "/".to_string() } else { rest.to_string() };
    }
    pathname.to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub window_seconds: u64,
    pub max: u32,
}

/// The default 100 per 10 s, the built-in special rules, then the email-otp
/// plugin's rules (the first plugin rule that matches wins).
pub fn rule_for(path: &str) -> Rule {
    let mut rule = Rule { window_seconds: 10, max: 100 };
    if path.starts_with("/sign-in") || path.starts_with("/sign-up") || path.starts_with("/change-password") || path.starts_with("/change-email") {
        rule = Rule { window_seconds: 10, max: 3 };
    } else if path == "/request-password-reset"
        || path == "/send-verification-email"
        || path.starts_with("/forget-password")
        || path == "/email-otp/send-verification-otp"
        || path == "/email-otp/request-password-reset"
    {
        rule = Rule { window_seconds: 60, max: 3 };
    }
    const EMAIL_OTP_PATHS: [&str; 9] = [
        "/email-otp/send-verification-otp",
        "/email-otp/check-verification-otp",
        "/email-otp/verify-email",
        "/sign-in/email-otp",
        "/email-otp/request-password-reset",
        "/email-otp/reset-password",
        "/forget-password/email-otp",
        "/email-otp/request-email-change",
        "/email-otp/change-email",
    ];
    if EMAIL_OTP_PATHS.contains(&path) {
        rule = Rule { window_seconds: 60, max: 3 };
    }
    rule
}

#[derive(Clone, Copy)]
struct Entry {
    count: u32,
    last_request: Instant,
    expires_at: Instant,
}

static MEMORY: LazyLock<Mutex<HashMap<String, Entry>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// `onRequestRateLimit` with the memory store: `Some(retry_after_seconds)` when the
/// request is refused.
pub fn consume(ip: Option<&str>, path: &str) -> Option<u64> {
    let key = format!("{}|{path}", ip.unwrap_or("no-trusted-ip"));
    let rule = rule_for(path);
    let now = Instant::now();
    let window = Duration::from_secs(rule.window_seconds);
    let mut memory = MEMORY.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    // pruneMemoryStore
    memory.retain(|_, entry| now < entry.expires_at);
    if memory.len() > MEMORY_STORE_MAX_ENTRIES {
        let overflow = memory.len() - MEMORY_STORE_MAX_ENTRIES;
        let victims: Vec<String> = memory.keys().take(overflow).cloned().collect();
        for victim in victims {
            memory.remove(&victim);
        }
    }

    let current = memory.get(&key).copied().filter(|entry| now < entry.expires_at);
    let next_count = match current {
        None => 1,
        Some(entry) if now.duration_since(entry.last_request) > window => 1,
        Some(entry) if entry.count >= rule.max => {
            // getRetryAfter: ceil((lastRequest + window - now) / 1000)
            let remaining = (entry.last_request + window).saturating_duration_since(now);
            let retry = remaining.as_millis().div_ceil(1000) as u64;
            warn!(path, "Better Auth rate limit reached");
            return Some(retry);
        }
        Some(entry) => entry.count + 1,
    };
    memory.insert(key, Entry { count: next_count, last_request: now, expires_at: now + window });
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ips_normalise_like_better_auth() {
        assert_eq!(normalize_ip("10.0.0.1"), "10.0.0.1");
        assert_eq!(normalize_ip("2001:DB8::1"), "2001:0db8:0000:0000:0000:0000:0000:0000");
        assert_eq!(normalize_ip("::ffff:192.0.2.1"), "192.0.2.1");
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        assert_eq!(client_ip(&headers, false), None);
        assert_eq!(client_ip(&headers, true).as_deref(), Some("127.0.0.1"));
        headers.insert("x-forwarded-for", " 1.2.3.4 ".parse().unwrap());
        assert_eq!(client_ip(&headers, false).as_deref(), Some("1.2.3.4"));
        headers.insert("x-forwarded-for", "01.2.3.4".parse().unwrap());
        assert_eq!(client_ip(&headers, false), None);
    }

    #[test]
    fn rules_and_paths() {
        assert_eq!(normalize_pathname("/api/auth/sign-in/email/"), "/sign-in/email");
        assert_eq!(normalize_pathname("/api/auth"), "/");
        assert_eq!(rule_for("/sign-in/email").max, 3);
        assert_eq!(rule_for("/sign-in/email-otp").window_seconds, 60);
        assert_eq!(rule_for("/email-otp/reset-password"), Rule { window_seconds: 60, max: 3 });
        assert_eq!(rule_for("/get-session"), Rule { window_seconds: 10, max: 100 });
    }

    #[test]
    fn memory_store_refuses_the_fourth_sign_in() {
        let ip = "203.0.113.77";
        for _ in 0..3 {
            assert_eq!(consume(Some(ip), "/sign-in/email"), None);
        }
        let retry = consume(Some(ip), "/sign-in/email").unwrap();
        assert!((1..=10).contains(&retry));
        assert_eq!(consume(Some(ip), "/get-session"), None);
    }
}
