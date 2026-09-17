//! Differential tests against Node.
//!
//! Each fixture holds inputs and the outputs the real TypeScript produced for them
//! (Node 24, the production major). `testdata/` carries synthetic cases so these run
//! everywhere; set `TRACKING_PARITY_DIR` to a directory of full dumps (which include
//! parity-snapshot data and so stay out of git) to replay those too:
//!
//! ```text
//! TRACKING_PARITY_DIR=/path/to/out GEOIP_DIR=../server cargo test tracking::parity_tests -- --nocapture
//! ```
//!
//! The dumps come from `parity/tracking/`, whose scripts import the TypeScript modules
//! directly. Run them with Node 24 from `server/` (which has the node_modules), e.g.
//! `npx tsx ../server-rs/parity/tracking/dump_payload.ts <out> 8000`, likewise
//! `dump_channel.ts <out>`, `dump_ip.ts <out>`, `dump_exclusion.ts <out>`,
//! `dump_urlfuzz.ts <out> [seed size name]`; for request bodies start
//! `harness_server.ts 38101` and record with `node http_cases.mjs 38101 <out>/http_cases.json`.
//! `make_testdata.mjs <out>` refreshes `testdata/`. ASN and country cases need GeoLite2
//! (`GEOIP_DIR`) and are skipped without it.

use std::{net::IpAddr, path::PathBuf};

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use super::{
    body::{
        BodyHeaders, BodyRejection, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_track_body, reject_before_reading,
    },
    channel::{get_channel, get_medium_type, get_source_type, is_paid_traffic},
    client_ip::{
        collect_candidate_client_ips, fastify_request_ip, get_ip_address, get_request_user_agent, resolve_client_ip,
        resolve_client_ip_with_edge,
    },
    exclusions::{SiteExclusionDecision, SiteExclusionRequest, SiteExclusionRules, decide_site_exclusion},
    ip_utils::{matches_cidr, matches_range, validate_ip_pattern},
    json::parse_json,
    payload::{ValidatedTrackingPayload, validate_tracking_payload},
    url_params::{clear_self_referrer, get_all_url_params, get_utm_params, url_hostname, url_search_params},
};
use crate::{geo::Geo, http::errors::normalize_api_error};

/// Every fixture directory that has `name`, with its parsed contents.
fn fixtures(name: &str) -> Vec<(PathBuf, Value)> {
    let mut dirs = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/tracking/testdata")];
    if let Ok(dir) = std::env::var("TRACKING_PARITY_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    dirs.into_iter()
        .map(|dir| dir.join(name))
        .filter(|path| path.exists())
        .map(|path| {
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            let value =
                serde_json::from_str(&text).unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()));
            (path, value)
        })
        .collect()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_else(|| panic!("expected a string, got {value}"))
}

fn pairs(value: &Value) -> Vec<(String, String)> {
    value
        .as_array()
        .expect("entries array")
        .iter()
        .map(|pair| (text(&pair[0]).to_string(), text(&pair[1]).to_string()))
        .collect()
}

fn to_pairs(map: indexmap::IndexMap<String, String>) -> Vec<(String, String)> {
    map.into_iter().collect()
}

/// Counts agreement and keeps the first few disagreements for the failure message.
#[derive(Default)]
struct Tally {
    checked: usize,
    mismatches: Vec<String>,
}

impl Tally {
    fn check<T: PartialEq + std::fmt::Debug>(&mut self, what: &str, input: impl std::fmt::Debug, node: T, rust: T) {
        self.checked += 1;
        if node != rust {
            self.mismatches.push(format!("{what} {input:?}\n    node: {node:?}\n    rust: {rust:?}"));
        }
    }

    fn finish(self, label: &str) {
        eprintln!(
            "{label}: {} checks, {} agree, {} differ",
            self.checked,
            self.checked - self.mismatches.len(),
            self.mismatches.len()
        );
        assert!(
            self.mismatches.is_empty(),
            "{label}: {} mismatches, first ones:\n{}",
            self.mismatches.len(),
            self.mismatches.iter().take(25).cloned().collect::<Vec<_>>().join("\n")
        );
    }
}

#[test]
fn channel_and_url_helpers_match_node() {
    for (path, corpus) in fixtures("channel_corpus.json") {
        let mut tally = Tally::default();
        let rows = corpus["rows"].as_array().expect("rows");
        for row in rows {
            let (referrer, querystring, hostname) =
                (text(&row["referrer"]), text(&row["querystring"]), text(&row["hostname"]));
            let input = (referrer, querystring, hostname);
            tally.check("getChannel", input, text(&row["channel"]), get_channel(referrer, querystring, hostname));
            tally.check("getUTMParams", querystring, pairs(&row["utm"]), to_pairs(get_utm_params(querystring)));
            tally.check("getAllUrlParams", querystring, pairs(&row["all"]), to_pairs(get_all_url_params(querystring)));
            tally.check(
                "clearSelfReferrer",
                (referrer, hostname),
                text(&row["cleared"]),
                clear_self_referrer(referrer, hostname),
            );
            tally.check("URLSearchParams", querystring, pairs(&row["searchParams"]), url_search_params(querystring));
            tally.check(
                "URL.hostname",
                referrer,
                row["referrerHost"].as_str().map(str::to_string),
                url_hostname(referrer),
            );
        }

        for classifier in corpus["classifiers"].as_array().expect("classifiers") {
            let value = text(&classifier["value"]);
            tally.check("getSourceType", value, text(&classifier["sourceType"]), get_source_type(value));
            tally.check("getMediumType", value, text(&classifier["mediumType"]), get_medium_type(value));
            tally.check(
                "isPaidTraffic(medium)",
                value,
                classifier["paidAsMedium"].as_bool(),
                Some(is_paid_traffic(value, "")),
            );
            tally.check(
                "isPaidTraffic(source)",
                value,
                classifier["paidAsSource"].as_bool(),
                Some(is_paid_traffic("", value)),
            );
        }

        eprintln!("{}: {} tuples", path.display(), rows.len());
        tally.finish("channel corpus");
    }
}

#[test]
fn url_parsing_and_query_decoding_fuzz_match_node() {
    let corpora = [fixtures("url_fuzz.json"), fixtures("url_fuzz_2.json"), fixtures("url_fuzz_3.json")];
    for (path, corpus) in corpora.into_iter().flatten() {
        let mut tally = Tally::default();
        for case in corpus["urlCases"].as_array().expect("urlCases") {
            let input = text(&case["input"]);
            tally.check("URL.hostname", input, case["host"].as_str().map(str::to_string), url_hostname(input));
        }
        for case in corpus["queryCases"].as_array().expect("queryCases") {
            let input = text(&case["input"]);
            tally.check("URLSearchParams", input, pairs(&case["searchParams"]), url_search_params(input));
            tally.check("getUTMParams", input, pairs(&case["utm"]), to_pairs(get_utm_params(input)));
            tally.check("getAllUrlParams", input, pairs(&case["all"]), to_pairs(get_all_url_params(input)));
        }
        eprintln!("{}", path.display());
        tally.finish("url fuzz");
    }
}

/// A number as the dump prints it: `String(value)`, with -0 kept apart.
fn js_number(value: f64) -> Value {
    if value == 0.0 && value.is_sign_negative() {
        return Value::from("num:-0");
    }
    Value::from(format!("num:{}", ryu_js::Buffer::new().format(value)))
}

/// The zod output object in shape order, encoded like the Node dump.
fn encode_payload(payload: &ValidatedTrackingPayload) -> String {
    let mut out = serde_json::Map::new();
    let mut put = |key: &str, value: Option<Value>| {
        if let Some(value) = value {
            out.insert(key.to_string(), value);
        }
    };
    let string = |value: &Option<String>| value.clone().map(Value::from);
    let number = |value: Option<f64>| value.map(js_number);
    let metric = |value: Option<Option<f64>>| value.map(|metric| metric.map_or(Value::Null, js_number));

    put("type", Some(Value::from(payload.event_type.as_str())));
    put("site_id", Some(Value::from(payload.site_id.clone())));
    put("hostname", string(&payload.hostname));
    put("pathname", string(&payload.pathname));
    put("querystring", string(&payload.querystring));
    put("screenWidth", number(payload.screen_width));
    put("screenHeight", number(payload.screen_height));
    put("language", string(&payload.language));
    put("page_title", string(&payload.page_title));
    put("referrer", string(&payload.referrer));
    put("anonymous_id", string(&payload.anonymous_id));
    put("user_id", string(&payload.user_id));
    put("tag", string(&payload.tag));
    put(
        "feature_flags",
        payload.feature_flags.as_ref().map(|flags| {
            Value::Object(flags.iter().map(|(key, value)| (key.clone(), Value::from(value.clone()))).collect())
        }),
    );
    put("ip_address", string(&payload.ip_address));
    put("user_agent", string(&payload.user_agent));
    put("_bs", payload.bot_score.map(|score| js_number(score.into())));
    put("_bsm", payload.bot_signal_mask.map(|mask| js_number(mask.into())));
    put("event_name", string(&payload.event_name));
    put("properties", string(&payload.properties));
    put("lcp", metric(payload.lcp));
    put("cls", metric(payload.cls));
    put("inp", metric(payload.inp));
    put("fcp", metric(payload.fcp));
    put("ttfb", metric(payload.ttfb));
    serde_json::to_string(&out).expect("encoding a payload")
}

#[test]
fn payload_validation_matches_zod() {
    let corpora = [fixtures("payload_corpus.json"), fixtures("payload_corpus_valid.json")];
    for (path, corpus) in corpora.into_iter().flatten() {
        let mut tally = Tally::default();
        let cases = corpus.as_array().expect("cases");
        for case in cases {
            let input = text(&case["text"]);
            let body = parse_json(input, 2).unwrap_or_else(|_| panic!("corpus text must be valid JSON: {input}")).value;
            let result = validate_tracking_payload(Some(&body));
            let node = if case["success"].as_bool() == Some(true) {
                format!("ok {}", text(&case["data"]))
            } else {
                format!("err {}", text(&case["errors"]))
            };
            let rust = match &result {
                Ok(payload) => format!("ok {}", encode_payload(payload)),
                Err(errors) => format!("err {}", serde_json::to_string(&errors.flatten()).expect("encoding errors")),
            };
            tally.check("safeParse", input, node, rust);
        }
        eprintln!(
            "{}: {} payloads, {} accepted by Node",
            path.display(),
            cases.len(),
            cases.iter().filter(|case| case["success"].as_bool() == Some(true)).count()
        );
        tally.finish("payload corpus");
    }
}

/// The recorded request body: hex bytes, or `[text, repeat]` parts for large ones.
fn recorded_body(case: &Value) -> Vec<u8> {
    if let Some(hex_body) = case["bodyHex"].as_str() {
        return hex::decode(hex_body).expect("hex body");
    }
    case["parts"]
        .as_array()
        .expect("body parts")
        .iter()
        .flat_map(|part| text(&part[0]).repeat(part[1].as_u64().expect("repeat count") as usize).into_bytes())
        .collect()
}

/// What this module plus the `/api` error rewrite answer for one POST /api/track, as
/// (status, body, connection closed) the way the Node harness reports it.
fn replay_track(headers: &HeaderMap, raw: &[u8]) -> (u16, String, bool) {
    let rejected = |rejection: BodyRejection| {
        let status = rejection.status.as_u16();
        let body = Value::Object(normalize_api_error(status, rejection.body));
        (status, body.to_string(), rejection.close_connection)
    };

    let body_headers = BodyHeaders::from_headers(headers);
    if let Some(rejection) = reject_before_reading(&body_headers) {
        return rejected(rejection);
    }
    if raw.len() > TRACK_BODY_LIMIT_BYTES {
        return rejected(body_too_large());
    }
    let body = match parse_track_body(&body_headers, raw) {
        Ok(body) => body,
        Err(rejection) => return rejected(rejection),
    };
    match validate_tracking_payload(body.as_ref()) {
        Ok(payload) => {
            (200, serde_json::json!({ "success": true, "harness": encode_payload(&payload) }).to_string(), false)
        }
        Err(errors) => (400, Value::Object(normalize_api_error(400, errors.response_body())).to_string(), false),
    }
}

#[test]
fn track_request_bodies_match_fastify() {
    let loopback: IpAddr = "127.0.0.1".parse().expect("loopback");
    for (path, cases) in fixtures("http_cases.json") {
        let mut tally = Tally::default();
        for case in cases.as_array().expect("cases") {
            let name = text(&case["name"]);
            let headers = header_map_from_list(&case["requestHeaders"]);

            if text(&case["path"]) == "/api/ipecho" {
                let node: Value = serde_json::from_str(text(&case["response"])).expect("echo body");
                let resolved_direct = resolve_client_ip_with_edge(&headers, loopback, false, |_| false);
                let rust = serde_json::json!({
                    "requestIp": fastify_request_ip(&headers, loopback),
                    "getIpAddress": get_ip_address(&headers, loopback),
                    "userAgent": get_request_user_agent(&headers),
                    "resolvedDirect": resolved_direct,
                    "resolvedProxied": resolve_client_ip_with_edge(&headers, loopback, false, |_| true),
                    "resolvedFirstParty": resolve_client_ip_with_edge(&headers, loopback, true, |_| false),
                    "candidates": collect_candidate_client_ips(&headers, loopback, &[&resolved_direct]),
                });
                tally.check("ipecho", name, node.to_string(), rust.to_string());
                continue;
            }

            let node = (
                case["status"].as_u64().expect("status") as u16,
                text(&case["response"]).to_string(),
                case["connection"].as_str() == Some("close"),
            );
            tally.check("POST /api/track", name, node, replay_track(&headers, &recorded_body(case)));
        }
        eprintln!("{}", path.display());
        tally.finish("http cases");
    }
}

/// Headers in the order they were sent, duplicates kept, values as latin1 text.
fn header_map_from_list(list: &Value) -> HeaderMap {
    let mut map = HeaderMap::new();
    for pair in list.as_array().expect("header list") {
        let bytes: Vec<u8> =
            text(&pair[1]).chars().map(|c| u8::try_from(u32::from(c)).expect("latin1 header value")).collect();
        map.append(
            HeaderName::from_bytes(text(&pair[0]).as_bytes()).expect("header name"),
            HeaderValue::from_bytes(&bytes).expect("header value"),
        );
    }
    map
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().expect("string array").iter().map(|item| text(item).to_string()).collect()
}

#[test]
fn site_exclusion_decisions_match_node() {
    let Some(geo) = geo_databases() else {
        eprintln!("exclusion corpus skipped: GeoLite2 not found (set GEOIP_DIR)");
        return;
    };
    for (path, cases) in fixtures("exclusion_corpus.json") {
        let mut tally = Tally::default();
        for case in cases.as_array().expect("cases") {
            let (config, request) = (&case["configuration"], &case["request"]);
            let lists = [
                "excludedIPs",
                "organizationExcludedIPs",
                "excludedCountries",
                "excludedPaths",
                "excludedHostnames",
                "excludedUserAgents",
                "excludedASNs",
                "excludedQueryParams",
            ]
            .map(|name| strings(&config[name]));
            let rules = SiteExclusionRules {
                excluded_ips: &lists[0],
                use_organization_excluded_ips: config["useOrganizationExcludedIPs"].as_bool().expect("flag"),
                organization_excluded_ips: &lists[1],
                excluded_countries: &lists[2],
                excluded_paths: &lists[3],
                excluded_hostnames: &lists[4],
                excluded_user_agents: &lists[5],
                excluded_asns: &lists[6],
                excluded_query_params: &lists[7],
            };
            let candidates = strings(&request["candidateIps"]);
            let exclusion_request = SiteExclusionRequest {
                ip_address: text(&request["ipAddress"]),
                candidate_ips: &candidates,
                pathname: request["pathname"].as_str(),
                querystring: request["querystring"].as_str(),
                hostname: request["hostname"].as_str(),
                user_agent: request["userAgent"].as_str(),
            };

            let decision = decide_site_exclusion(&rules, &exclusion_request, &geo, &geo.asn_lookup());
            let rust = match &decision {
                SiteExclusionDecision::Accepted => serde_json::json!({ "excluded": false }),
                SiteExclusionDecision::Excluded { reason, value } => serde_json::json!({
                    "excluded": true,
                    "reason": reason.as_str(),
                    "label": reason.label(),
                    "value": value,
                }),
            };
            tally.check("decideSiteExclusion", case, case["decision"].to_string(), rust.to_string());
        }
        eprintln!("{}", path.display());
        tally.finish("exclusion corpus");
    }
}

/// GeoLite2 databases from `GEOIP_DIR` or next to the Node server, when present.
fn geo_databases() -> Option<Geo> {
    let dirs = [
        std::env::var("GEOIP_DIR").ok().map(PathBuf::from),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../server")),
    ];
    dirs.into_iter()
        .flatten()
        .find(|dir| dir.join("GeoLite2-City.mmdb").exists() && dir.join("GeoLite2-ASN.mmdb").exists())
        .map(|dir| Geo::load(&dir).expect("loading GeoLite2"))
}

fn header_map(headers: &Value) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers.as_object().expect("headers object") {
        let bytes: Vec<u8> =
            text(value).chars().map(|c| u8::try_from(u32::from(c)).expect("latin1 header value")).collect();
        map.append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_bytes(&bytes).unwrap_or_else(|_| panic!("header value {value}")),
        );
    }
    map
}

#[test]
fn ip_matching_and_client_ip_resolution_match_node() {
    let geo = geo_databases();
    for (path, corpus) in fixtures("ip_corpus.json") {
        let mut tally = Tally::default();

        for case in corpus["validations"].as_array().expect("validations") {
            let pattern = text(&case["pattern"]);
            let node = (case["result"]["valid"].as_bool(), case["result"]["error"].as_str().map(str::to_string));
            let rust = validate_ip_pattern(pattern);
            tally.check("validateIPPattern", pattern, node, (Some(rust.valid), rust.error.map(str::to_string)));
        }
        for case in corpus["cidr"].as_array().expect("cidr") {
            let (ip, cidr) = (text(&case["ip"]), text(&case["cidr"]));
            tally.check("matchesCIDR", (ip, cidr), case["result"].as_bool(), Some(matches_cidr(ip, cidr)));
        }
        for case in corpus["range"].as_array().expect("range") {
            let (ip, range) = (text(&case["ip"]), text(&case["range"]));
            tally.check("matchesRange", (ip, range), case["result"].as_bool(), Some(matches_range(ip, range)));
        }

        let mut skipped = 0;
        for case in corpus["clientCases"].as_array().expect("clientCases") {
            let headers = header_map(&case["headers"]);
            let peer: IpAddr = text(&case["socket"]).parse().expect("socket address");
            let first_party_proxy = case["firstPartyProxy"].as_bool().expect("flag");
            let input = (&case["headers"], text(&case["socket"]), first_party_proxy, text(&case["mode"]));

            let resolved = match text(&case["mode"]) {
                "direct" => resolve_client_ip_with_edge(&headers, peer, first_party_proxy, |_| false),
                "proxied" => resolve_client_ip_with_edge(&headers, peer, first_party_proxy, |_| true),
                _ => match &geo {
                    Some(geo) => resolve_client_ip(&headers, peer, first_party_proxy, &geo.asn_lookup()),
                    None => {
                        skipped += 1;
                        continue;
                    }
                },
            };
            tally.check("resolveClientIp", input, text(&case["resolved"]), resolved.as_str());
            tally.check("request.ip", input, text(&case["requestIp"]), fastify_request_ip(&headers, peer).as_str());
            tally.check("getIpAddress", input, text(&case["getIpAddress"]), get_ip_address(&headers, peer).as_str());
            tally.check(
                "getRequestUserAgent",
                input,
                text(&case["userAgent"]),
                get_request_user_agent(&headers).as_str(),
            );

            let mut extra: Vec<&str> = case["extra"].as_array().expect("extra").iter().map(text).collect();
            extra.push(&resolved);
            let node_candidates: Vec<&str> =
                case["candidates"].as_array().expect("candidates").iter().map(text).collect();
            tally.check(
                "collectCandidateClientIps",
                input,
                node_candidates,
                collect_candidate_client_ips(&headers, peer, &extra).iter().map(String::as_str).collect(),
            );
        }
        if skipped > 0 {
            eprintln!("{}: {skipped} ASN-mode cases skipped, GeoLite2 not found (set GEOIP_DIR)", path.display());
        }
        tally.finish("ip corpus");
    }
}
