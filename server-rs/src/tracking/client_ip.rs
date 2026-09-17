//! Client IP and user agent, ported from `getIpAddress` and `getRequestUserAgent` in
//! server/src/utils.ts and from server/src/services/tracker/resolveClientIp.ts.
//!
//! Node reads headers after its HTTP parser has merged duplicates: most headers (the
//! forwarding ones included) are joined with ", ", while User-Agent keeps the first
//! value. Values are latin1 strings. Fastify runs with `trustProxy: true`, so the
//! final fallback, `request.ip`, is the leftmost X-Forwarded-For entry (as
//! @fastify/forwarded splits it) or the socket address when there is none.
//!
//! In production the chain is Cloudflare, then Caddy (which sets X-Forwarded-For and
//! X-Real-IP to its `{client_ip}`), then this service; the resolution below does not
//! assume that topology, it reproduces what Node computes from the same headers.

use std::net::IpAddr;

use axum::http::{HeaderMap, header};

use super::{
    AsnSource,
    js::{js_to_lower, js_trim, latin1},
};
use crate::datacenter_asns::is_datacenter_asn;

/// Cloudflare's documented `CF-Connecting-IP` on cross-zone Worker subrequests, the
/// first-party Worker proxy topology; recognised without consulting the ASN database.
pub const CF_WORKER_SUBREQUEST_IP: &str = "2a06:98c0:3600::103";

/// `request.headers[name]` for a header Node joins with ", " when repeated.
fn joined_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let mut joined = latin1(values.next()?.as_bytes());
    for value in values {
        joined.push_str(", ");
        joined.push_str(&latin1(value.as_bytes()));
    }
    Some(joined)
}

/// A header's value when it is a non-empty string, trimmed (possibly to "").
fn trimmed_header(headers: &HeaderMap, name: &str) -> Option<String> {
    joined_header(headers, name).filter(|value| !value.is_empty()).map(|value| js_trim(&value).to_string())
}

/// Every non-empty, trimmed `X-Forwarded-For` entry in order.
fn forwarded_for_entries(headers: &HeaderMap) -> Vec<String> {
    joined_header(headers, "x-forwarded-for")
        .filter(|value| !value.is_empty())
        .map(|value| value.split(',').map(js_trim).filter(|entry| !entry.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

/// Fastify's `request.ip` with `trustProxy: true`: the last address `@fastify/forwarded`
/// returns, i.e. the leftmost X-Forwarded-For token, else the socket address.
pub fn fastify_request_ip(headers: &HeaderMap, peer: IpAddr) -> String {
    let socket = peer.to_string();
    let Some(header) = joined_header(headers, "x-forwarded-for").filter(|value| !value.is_empty()) else {
        return socket;
    };

    if !header.contains(',') {
        let remote = js_trim(&header);
        return if remote.is_empty() { socket } else { remote.to_string() };
    }

    // @fastify/forwarded `parse`: scan from the end, splitting on commas and dropping
    // spaces (only U+0020) around each token; the last token found is the leftmost
    let bytes = header.as_bytes();
    let mut end = bytes.len();
    let mut start = end;
    let mut leftmost = None;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b' ' => {
                if start == end {
                    start = i;
                    end = i;
                }
            }
            b',' => {
                if start != end {
                    leftmost = Some((start, end));
                }
                start = i;
                end = i;
            }
            _ => start = i,
        }
    }
    if start != end {
        leftmost = Some((start, end));
    }
    leftmost.map_or(socket, |(start, end)| header[start..end].to_string())
}

/// `getIpAddress`: X-Real-IP, then the first X-Forwarded-For entry, then
/// CF-Connecting-IP, then `request.ip`.
pub fn get_ip_address(headers: &HeaderMap, peer: IpAddr) -> String {
    if let Some(real_ip) = trimmed_header(headers, "x-real-ip") {
        return real_ip;
    }
    if let Some(first) = forwarded_for_entries(headers).into_iter().next() {
        return first;
    }
    if let Some(cf_ip) = trimmed_header(headers, "cf-connecting-ip") {
        return cf_ip;
    }
    fastify_request_ip(headers, peer)
}

/// `getRequestUserAgent`: the first User-Agent value, or "".
pub fn get_request_user_agent(headers: &HeaderMap) -> String {
    headers.get(header::USER_AGENT).map(|value| latin1(value.as_bytes())).unwrap_or_default()
}

/// `isProxiedEdge`: the edge IP belongs to hosting infrastructure, so a first-party
/// proxy sits in front of Cloudflare. A missing ASN database answers false (direct).
pub fn is_proxied_edge(ip: &str, asn: &impl AsnSource) -> bool {
    js_to_lower(ip) == CF_WORKER_SUBREQUEST_IP || is_datacenter_asn(asn.asn_number(ip))
}

/// `resolveClientIp(request, { firstPartyProxy, lookupAsn })`
pub fn resolve_client_ip(headers: &HeaderMap, peer: IpAddr, first_party_proxy: bool, asn: &impl AsnSource) -> String {
    resolve_client_ip_with_edge(headers, peer, first_party_proxy, |ip| is_proxied_edge(ip, asn))
}

/// `resolveClientIp` with the edge classification injected (Node's `proxiedEdge` option).
pub fn resolve_client_ip_with_edge(
    headers: &HeaderMap,
    peer: IpAddr,
    first_party_proxy: bool,
    proxied_edge: impl Fn(&str) -> bool,
) -> String {
    let real_ip = trimmed_header(headers, "x-real-ip");
    let forwarded_first = forwarded_for_entries(headers).into_iter().next();
    let cf_ip = trimmed_header(headers, "cf-connecting-ip");

    if first_party_proxy {
        let resolved = real_ip.or(forwarded_first).or(cf_ip).unwrap_or_else(|| get_ip_address(headers, peer));
        tracing::debug!(ip = %resolved, topology = "first_party_proxy", "Resolved client IP");
        return resolved;
    }

    if let Some(cf_ip) = cf_ip.filter(|ip| !ip.is_empty()) {
        if proxied_edge(&cf_ip) {
            // A proxy in front: trust what it forwarded, else the edge itself
            let resolved = real_ip.or(forwarded_first).unwrap_or(cf_ip);
            tracing::debug!(ip = %resolved, topology = "proxied_edge", "Resolved client IP");
            return resolved;
        }
        // A direct visitor: the edge IP is authoritative, forwarded headers are noise
        tracing::debug!(ip = %cf_ip, topology = "direct_edge", "Resolved client IP");
        return cf_ip;
    }

    let resolved = get_ip_address(headers, peer);
    tracing::debug!(ip = %resolved, topology = "no_edge", "Resolved client IP");
    resolved
}

/// `collectCandidateClientIps(request, extra)`: every IP the request could belong to,
/// for exclusion matching only (over-matching is the safe failure there).
pub fn collect_candidate_client_ips(headers: &HeaderMap, peer: IpAddr, extra: &[&str]) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    let mut add = |ip: &str| {
        if !ip.is_empty() && !candidates.iter().any(|existing| existing == ip) {
            candidates.push(ip.to_string());
        }
    };

    for ip in extra {
        add(ip);
    }
    if let Some(cf_ip) = trimmed_header(headers, "cf-connecting-ip") {
        add(&cf_ip);
    }
    if let Some(real_ip) = trimmed_header(headers, "x-real-ip") {
        add(&real_ip);
    }
    for entry in forwarded_for_entries(headers) {
        add(&entry);
    }
    add(&fastify_request_ip(headers, peer));
    candidates
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;
    use crate::geo::AsnInfo;

    const SOCKET: &str = "198.51.100.10";

    fn request(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn peer() -> IpAddr {
        SOCKET.parse().unwrap()
    }

    const PROXIED: fn(&str) -> bool = |_| true;
    const DIRECT: fn(&str) -> bool = |_| false;

    struct NoAsn;
    impl AsnSource for NoAsn {
        fn asn_info(&self, _ip: &str) -> Option<AsnInfo> {
            None
        }
    }

    // Ported from resolveClientIp.test.ts

    #[test]
    fn trusts_the_forwarded_visitor_ip_when_the_edge_is_a_datacenter() {
        let headers = request(&[("cf-connecting-ip", "13.224.0.1"), ("x-forwarded-for", "203.0.113.10, 13.224.0.1")]);
        assert_eq!(resolve_client_ip_with_edge(&headers, peer(), false, PROXIED), "203.0.113.10");
    }

    #[test]
    fn prefers_x_real_ip_over_x_forwarded_for_on_the_proxied_path() {
        let headers = request(&[
            ("cf-connecting-ip", "13.224.0.1"),
            ("x-forwarded-for", "203.0.113.10"),
            ("x-real-ip", "192.0.2.10"),
        ]);
        assert_eq!(resolve_client_ip_with_edge(&headers, peer(), false, PROXIED), "192.0.2.10");
    }

    #[test]
    fn falls_back_to_the_edge_ip_if_a_proxy_forwarded_nothing() {
        let headers = request(&[("cf-connecting-ip", "13.224.0.1")]);
        assert_eq!(resolve_client_ip_with_edge(&headers, peer(), false, PROXIED), "13.224.0.1");
    }

    #[test]
    fn trusts_the_edge_ip_and_ignores_spoofable_headers_on_the_direct_path() {
        let headers =
            request(&[("cf-connecting-ip", "203.0.113.55"), ("x-forwarded-for", "8.8.8.8"), ("x-real-ip", "1.1.1.1")]);
        assert_eq!(resolve_client_ip_with_edge(&headers, peer(), false, DIRECT), "203.0.113.55");
    }

    #[test]
    fn uses_forwarded_headers_when_there_is_no_cloudflare_edge() {
        assert_eq!(
            resolve_client_ip_with_edge(&request(&[("x-real-ip", "192.0.2.10")]), peer(), false, DIRECT),
            "192.0.2.10"
        );
        assert_eq!(
            resolve_client_ip_with_edge(
                &request(&[("x-forwarded-for", "203.0.113.10, 10.0.0.1")]),
                peer(),
                false,
                DIRECT
            ),
            "203.0.113.10"
        );
    }

    #[test]
    fn falls_back_to_the_socket_ip_when_no_usable_headers_are_present() {
        assert_eq!(resolve_client_ip_with_edge(&request(&[]), peer(), false, DIRECT), SOCKET);
    }

    #[test]
    fn first_party_proxy_trusts_forwarded_headers_even_when_the_edge_looks_direct() {
        let headers = request(&[("cf-connecting-ip", "70.132.5.9"), ("x-forwarded-for", "203.0.113.10, 70.132.5.9")]);
        assert_eq!(resolve_client_ip_with_edge(&headers, peer(), true, DIRECT), "203.0.113.10");
    }

    #[test]
    fn first_party_proxy_prefers_x_real_ip_then_xff_then_the_edge() {
        let headers = request(&[("x-real-ip", "192.0.2.10"), ("cf-connecting-ip", "70.132.5.9")]);
        assert_eq!(resolve_client_ip(&headers, peer(), true, &NoAsn), "192.0.2.10");
        assert_eq!(
            resolve_client_ip(&request(&[("cf-connecting-ip", "70.132.5.9")]), peer(), true, &NoAsn),
            "70.132.5.9"
        );
        assert_eq!(resolve_client_ip(&request(&[]), peer(), true, &NoAsn), SOCKET);
    }

    #[test]
    fn trusts_forwarded_headers_behind_the_cloudflare_worker_subrequest_ip() {
        let headers = request(&[
            ("cf-connecting-ip", "2a06:98c0:3600::103"),
            ("x-forwarded-for", "203.0.113.10, 2a06:98c0:3600::103"),
            ("x-real-ip", "203.0.113.10"),
        ]);
        assert_eq!(resolve_client_ip(&headers, peer(), false, &NoAsn), "203.0.113.10");
        let upper = request(&[("cf-connecting-ip", "2A06:98C0:3600::103"), ("x-forwarded-for", "203.0.113.10")]);
        assert_eq!(resolve_client_ip(&upper, peer(), false, &NoAsn), "203.0.113.10");
    }

    #[test]
    fn collects_every_candidate_ip_deduplicated() {
        let headers = request(&[
            ("cf-connecting-ip", "13.224.0.1"),
            ("x-forwarded-for", "203.0.113.10, 13.224.0.1"),
            ("x-real-ip", "192.0.2.10"),
        ]);
        // With trustProxy, request.ip is the leftmost forwarded address, not the socket
        assert_eq!(
            collect_candidate_client_ips(&headers, peer(), &["203.0.113.10", ""]),
            ["203.0.113.10", "13.224.0.1", "192.0.2.10"]
        );
        assert_eq!(collect_candidate_client_ips(&request(&[]), peer(), &[]), [SOCKET]);
    }

    #[test]
    fn mirrors_nodes_header_merging_and_forwarded_parsing() {
        let repeated = request(&[("x-forwarded-for", "203.0.113.10"), ("x-forwarded-for", "198.51.100.7")]);
        assert_eq!(get_ip_address(&repeated, peer()), "203.0.113.10");
        assert_eq!(fastify_request_ip(&request(&[("x-forwarded-for", " a b ,c")]), peer()), "a b");
        assert_eq!(fastify_request_ip(&request(&[("x-forwarded-for", ",\t,")]), peer()), "\t");
        let agents = request(&[("user-agent", "first"), ("user-agent", "second")]);
        assert_eq!(get_request_user_agent(&agents), "first");
    }
}
