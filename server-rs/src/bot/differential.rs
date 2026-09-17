//! Differential tests against dumps of the Node implementation.
//!
//! The dumps are written by the scripts in `parity/bot/` (run them all with
//! `parity/bot/run.sh`, which needs `server/node_modules`, the GeoLite2 databases
//! and the parity stores) and are too large to commit, so these tests only run
//! when `BOT_DIFF_DUMPS` names the directory holding them:
//!
//! ```sh
//! BOT_DIFF_DUMPS=/path/to/dumps cargo test --release bot::differential -- --nocapture --test-threads 1
//! ```
//!
//! - `ua.jsonl`: `classifyUA`, `classifyStaleBrowserVersion`, `isDesktopUserAgent`
//!   and `getScreenDimensionSignals` over ~52k user agents (ua-parser-js 2.0.3
//!   fixtures, isbot fixtures, crawler-user-agents, test literals, synthetic traps).
//! - `headers.jsonl`: `detectBot` over raw header lists turned into Node's
//!   `IncomingHttpHeaders`, and those headers themselves.
//! - `asn.json`: `classifyBotAsn` for every ASN below 500,000 plus edge values.
//! - `anomaly.json`: observation sequences through `observeTrackingAnomaly`, via
//!   the parity Redis and in-process, with the Redis state each one left.
//! - `e2e.json`: `checkBotBlocking` with real GeoLite2 ASN lookups, plus the
//!   detection stats at the end.
//! - `baseline.json`: `computeSiteBaselines` against the parity ClickHouse.
//!
//! Every case must agree; a failure prints the first disagreements by JSON path.

use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use serde_json::{Value, json};

use super::{
    bot_provider_asns::classify_bot_asn,
    header_heuristics::{detect_bot, node_header},
    signal_contract::{get_screen_dimension_signals, is_desktop_user_agent},
    stale_browser_version::classify_stale_browser_version,
    ua_bots::classify_ua_uncached,
};

fn dumps_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("BOT_DIFF_DUMPS").map(PathBuf::from);
    if dir.is_none() {
        eprintln!("BOT_DIFF_DUMPS not set; skipping the Node differential test");
    }
    dir
}

fn lines(path: PathBuf) -> impl Iterator<Item = Value> {
    let file = fs::File::open(&path).unwrap_or_else(|error| panic!("opening {}: {error}", path.display()));
    BufReader::new(file)
        .lines()
        .map(|line| line.expect("reading dump line"))
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(&line).expect("parsing dump line"))
}

/// The leaf paths at which two JSON values differ, for readable failures.
fn json_differences(path: &str, expected: &Value, actual: &Value, out: &mut Vec<String>) {
    match (expected, actual) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys: Vec<&String> = left.keys().chain(right.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let (left, right) = (left.get(key).unwrap_or(&Value::Null), right.get(key).unwrap_or(&Value::Null));
                json_differences(&format!("{path}.{key}"), left, right, out);
            }
        }
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
            for (index, (left, right)) in left.iter().zip(right).enumerate() {
                json_differences(&format!("{path}[{index}]"), left, right, out);
            }
        }
        _ if expected != actual => out.push(format!("  {path}: node {expected} rust {actual}")),
        _ => {}
    }
}

struct Tally {
    name: &'static str,
    cases: usize,
    mismatches: Vec<String>,
}

impl Tally {
    fn new(name: &'static str) -> Self {
        Self { name, cases: 0, mismatches: Vec::new() }
    }

    fn check(&mut self, expected: &Value, actual: &Value, context: impl FnOnce() -> String) {
        self.cases += 1;
        if expected != actual {
            let mut differences = Vec::new();
            json_differences("", expected, actual, &mut differences);
            self.mismatches.push(format!("{}\n{}", context(), differences.join("\n")));
        }
    }

    fn finish(self) {
        eprintln!(
            "{}: {} cases, {} agree, {} disagree",
            self.name,
            self.cases,
            self.cases - self.mismatches.len(),
            self.mismatches.len()
        );
        assert!(
            self.mismatches.is_empty(),
            "{} disagreements in {}:\n{}",
            self.mismatches.len(),
            self.name,
            self.mismatches.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
        );
    }
}

#[test]
fn ua_classification_and_stale_versions_match_node() {
    let Some(dir) = dumps_dir() else { return };
    let mut classify = Tally::new("classifyUA");
    let mut stale = Tally::new("classifyStaleBrowserVersion");
    let mut desktop = Tally::new("isDesktopUserAgent");

    for case in lines(dir.join("ua.jsonl")) {
        let ua = case["ua"].as_str().expect("ua");

        let c = classify_ua_uncached(ua);
        let actual = json!([
            c.is_bot,
            c.category.map(|category| category.as_str()),
            c.matched_pattern,
            c.name,
            c.operator,
            c.purpose.map(|purpose| purpose.as_str())
        ]);
        classify.check(&case["classify"], &actual, || format!("classifyUA({ua:?})"));

        let s = classify_stale_browser_version(ua);
        let actual = json!([s.is_stale, s.matched_version, s.major_version]);
        stale.check(&case["stale"], &actual, || format!("classifyStaleBrowserVersion({ua:?})"));

        desktop.check(&case["desktop"], &json!(is_desktop_user_agent(ua)), || format!("isDesktopUserAgent({ua:?})"));
    }

    // Throughput of the uncached classification, the cost of a user agent the
    // cache has not seen.
    let user_agents: Vec<String> =
        lines(dir.join("ua.jsonl")).map(|case| case["ua"].as_str().unwrap_or_default().to_string()).collect();
    for (label, classify_fn) in [
        ("classify_ua_uncached (literal prefilter)", classify_ua_uncached as fn(&str) -> _),
        ("classify_ua_reference (Node's combined regex, no prefilter)", super::ua_bots::classify_ua_reference),
    ] {
        let started = std::time::Instant::now();
        let bots = user_agents.iter().filter(|ua| classify_fn(ua).is_bot).count();
        let elapsed = started.elapsed();
        eprintln!(
            "{label}: {} user agents ({bots} bots) in {elapsed:?}, {:?} each",
            user_agents.len(),
            elapsed / user_agents.len().max(1) as u32
        );
    }
    let browsers: Vec<&String> = user_agents.iter().filter(|ua| !classify_ua_uncached(ua).is_bot).collect();
    let started = std::time::Instant::now();
    for ua in &browsers {
        classify_ua_uncached(ua);
    }
    eprintln!(
        "classify_ua_uncached on the {} non-bot user agents: {:?} each",
        browsers.len(),
        started.elapsed() / browsers.len().max(1) as u32
    );

    classify.finish();
    stale.finish();
    desktop.finish();
}

#[test]
fn screen_signals_match_node() {
    let Some(dir) = dumps_dir() else { return };
    let mut tally = Tally::new("getScreenDimensionSignals");
    for case in lines(dir.join("ua.jsonl")) {
        let ua = case["ua"].as_str().expect("ua");
        // null stands for NaN, which JSON cannot carry.
        let width = case["screenDims"][0].as_f64().unwrap_or(f64::NAN);
        let height = case["screenDims"][1].as_f64().unwrap_or(f64::NAN);
        let actual = json!(get_screen_dimension_signals(width, height, ua));
        tally.check(&case["screen"], &actual, || format!("getScreenDimensionSignals({width}, {height}, {ua:?})"));
    }
    tally.finish();
}

fn header_map_from_raw(raw: &[Value]) -> axum::http::HeaderMap {
    use axum::http::{HeaderName, HeaderValue};
    let mut map = axum::http::HeaderMap::new();
    for pair in raw.chunks(2) {
        let name = pair[0].as_str().expect("header name");
        // Node holds header values as latin1-decoded strings; turn them back into bytes.
        let bytes: Vec<u8> = pair[1]
            .as_str()
            .expect("header value")
            .chars()
            .map(|c| u8::try_from(u32::from(c)).expect("latin1"))
            .collect();
        map.append(
            HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
            HeaderValue::from_bytes(&bytes).expect("valid header value"),
        );
    }
    map
}

#[test]
fn header_heuristics_match_node() {
    let Some(dir) = dumps_dir() else { return };
    let mut detect = Tally::new("detectBot");
    let mut headers_tally = Tally::new("IncomingHttpHeaders");

    for case in lines(dir.join("headers.jsonl")) {
        let ua = case["ua"].as_str().expect("ua");
        let raw = case["raw"].as_array().expect("raw headers");
        let map = header_map_from_raw(raw);

        let result = detect_bot(&map, ua);
        let actual = json!([result.is_bot, result.score, result.reason]);
        detect.check(&case["detect"], &actual, || format!("detectBot({raw:?}, {ua:?})"));

        let expected_headers = case["headers"].as_object().expect("headers");
        for (name, expected) in expected_headers {
            if name == "set-cookie" {
                continue;
            }
            let actual = json!(node_header(&map, name));
            headers_tally.check(expected, &actual, || format!("headers[{name:?}] from {raw:?}"));
        }
    }

    detect.finish();
    headers_tally.finish();
}

#[test]
fn bot_asn_classification_matches_node() {
    let Some(dir) = dumps_dir() else { return };
    let dump: Value = serde_json::from_str(&fs::read_to_string(dir.join("asn.json")).expect("asn dump")).expect("json");
    let range_end = dump["rangeEnd"].as_u64().expect("rangeEnd") as u32;
    let extra: Vec<u32> = dump["extra"].as_array().expect("extra").iter().map(|v| v.as_u64().unwrap() as u32).collect();
    let hits: std::collections::HashMap<u32, Value> = dump["hits"]
        .as_array()
        .expect("hits")
        .iter()
        .map(|hit| (hit[0].as_u64().unwrap() as u32, hit.clone()))
        .collect();

    let mut tally = Tally::new("classifyBotAsn");
    for asn in (0..range_end).chain(extra) {
        let m = classify_bot_asn(Some(asn));
        let actual = if m.is_bot_infrastructure {
            json!([asn, m.source.map(|s| s.as_str()), m.provider, m.category.map(|c| c.as_str()), m.note])
        } else {
            Value::Null
        };
        let expected = hits.get(&asn).cloned().unwrap_or(Value::Null);
        tally.check(&expected, &actual, || format!("classifyBotAsn({asn})"));
    }
    tally.finish();
}

/// JSON numbers from V8 and serde differ in form (`1` against `1.0`), and
/// serde_json's default float parser is not always correctly rounded in the last
/// bit, so numbers compare as 13 significant digits.
fn normalize_numbers(value: Value) -> Value {
    match value {
        Value::Number(number) => {
            number.as_f64().map(|float| json!(format!("{float:.12e}"))).unwrap_or(Value::Number(number))
        }
        Value::Array(items) => Value::Array(items.into_iter().map(normalize_numbers).collect()),
        Value::Object(map) => {
            Value::Object(map.into_iter().map(|(key, value)| (key, normalize_numbers(value))).collect())
        }
        other => other,
    }
}

/// An `AnomalyInput` as the Node dump serialized it, with owned strings.
struct DumpedAnomalyInput {
    site_id: i32,
    ip_address: String,
    user_agent: String,
    hostname: Option<String>,
    pathname: Option<String>,
    event_type: Option<String>,
    referrer: Option<String>,
    has_client_bot_score: bool,
    screen_width: Option<f64>,
    screen_height: Option<f64>,
    language: Option<String>,
    is_hosting_asn: bool,
    asn: Option<u32>,
    site_baseline: super::anomaly_scorer::BaselineSource,
    now_ms: i64,
}

impl DumpedAnomalyInput {
    fn parse(value: &Value) -> Self {
        use super::{anomaly_scorer::BaselineSource, site_baseline::SiteBaseline};
        let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_string);
        Self {
            site_id: value["siteId"].as_i64().expect("siteId") as i32,
            ip_address: text("ipAddress").unwrap_or_default(),
            user_agent: text("userAgent").unwrap_or_default(),
            hostname: text("hostname"),
            pathname: text("pathname"),
            event_type: text("eventType"),
            referrer: text("referrer"),
            has_client_bot_score: value["hasClientBotScore"].as_bool().unwrap_or(false),
            screen_width: value.get("screenWidth").and_then(Value::as_f64),
            screen_height: value.get("screenHeight").and_then(Value::as_f64),
            language: text("language"),
            is_hosting_asn: value.get("isHostingAsn").and_then(Value::as_bool).unwrap_or(false),
            asn: value.get("asn").and_then(Value::as_u64).map(|asn| asn as u32),
            site_baseline: match value.get("siteBaseline") {
                None => BaselineSource::Lookup,
                Some(Value::Null) => BaselineSource::Absent,
                Some(baseline) => BaselineSource::Given(SiteBaseline {
                    events10m: baseline["events10m"].as_f64().expect("events10m"),
                    eligible: baseline["eligible"].as_bool().expect("eligible"),
                }),
            },
            now_ms: value["nowMs"].as_i64().expect("nowMs"),
        }
    }

    fn input(&self) -> super::anomaly_scorer::AnomalyInput<'_> {
        super::anomaly_scorer::AnomalyInput {
            site_id: self.site_id,
            ip_address: &self.ip_address,
            user_agent: &self.user_agent,
            hostname: self.hostname.as_deref(),
            pathname: self.pathname.as_deref(),
            event_type: self.event_type.as_deref(),
            referrer: self.referrer.as_deref(),
            has_client_bot_score: self.has_client_bot_score,
            screen_width: self.screen_width,
            screen_height: self.screen_height,
            language: self.language.as_deref(),
            is_hosting_asn: self.is_hosting_asn,
            asn: self.asn,
            site_baseline: self.site_baseline,
            now_ms: Some(self.now_ms),
        }
    }
}

/// The Redis state a scenario left behind, in the dump script's format: token
/// members (which carry a process id) reduced to their count and scores, value
/// members, hashes and counters verbatim, HyperLogLogs as raw bytes.
async fn redis_state(redis: &redis::aio::ConnectionManager, site_id: i32) -> serde_json::Map<String, Value> {
    let mut connection = redis.clone();
    let mut keys: Vec<String> =
        redis::cmd("KEYS").arg(format!("bot:*:{site_id}:*")).query_async(&mut connection).await.expect("KEYS");
    keys.sort();
    let token_members = regex::Regex::new(r"^bot:a:(te10|te60|ti10|ie60|sue|mcs):").unwrap();
    let hll = regex::Regex::new(r"^bot:(f:sa|f:ca|e:pa|e:ac):").unwrap();

    let mut state = serde_json::Map::new();
    for key in keys {
        let (kind, pttl): (String, i64) =
            redis::pipe().cmd("TYPE").arg(&key).cmd("PTTL").arg(&key).query_async(&mut connection).await.expect("TYPE");
        let value = match kind.as_str() {
            "zset" => {
                let mut pairs: Vec<(String, String)> = redis::cmd("ZRANGE")
                    .arg(&key)
                    .arg(0)
                    .arg(-1)
                    .arg("WITHSCORES")
                    .query_async(&mut connection)
                    .await
                    .unwrap();
                if token_members.is_match(&key) {
                    let mut scores: Vec<String> = pairs.iter().map(|(_, score)| score.clone()).collect();
                    scores.sort();
                    json!({ "count": pairs.len(), "scores": scores })
                } else {
                    pairs.sort();
                    json!({ "members": pairs })
                }
            }
            "hash" => {
                let map: std::collections::BTreeMap<String, String> =
                    redis::cmd("HGETALL").arg(&key).query_async(&mut connection).await.unwrap();
                json!(map)
            }
            "string" => {
                let raw: Vec<u8> = redis::cmd("GET").arg(&key).query_async(&mut connection).await.unwrap();
                if hll.is_match(&key) {
                    json!({ "hll": hex::encode(raw) })
                } else {
                    json!(String::from_utf8_lossy(&raw))
                }
            }
            other => json!(other),
        };
        state.insert(key, json!({ "type": kind, "pttl": pttl, "value": value }));
    }
    state
}

async fn delete_site(redis: &redis::aio::ConnectionManager, site_id: i32) {
    super::anomaly_observe::tests::delete_matching(redis, &format!("bot:*:{site_id}:*")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn anomaly_scorer_matches_node_through_redis_and_in_process() {
    use std::sync::Arc;

    use super::{anomaly_scorer::AnomalyScorer, site_baseline::SiteBaselines};

    let Some(dir) = dumps_dir() else { return };
    let Some(redis) = super::anomaly_observe::tests::parity_redis().await else { return };
    let dump: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("anomaly.json")).expect("anomaly dump")).expect("json");
    assert_eq!(
        dump["scriptSha"].as_str(),
        Some(super::anomaly_observe::ANOMALY_OBSERVE_SHA1),
        "ioredis loaded the same script"
    );

    let mut redis_results = Tally::new("observeTrackingAnomaly (Redis)");
    let mut local_results = Tally::new("observeTrackingAnomaly (in-process)");
    let mut redis_keys = Tally::new("Redis state after each scenario");

    for scenario in dump["scenarios"].as_array().expect("scenarios") {
        let name = scenario["name"].as_str().unwrap();
        let inputs: Vec<DumpedAnomalyInput> =
            scenario["inputs"].as_array().unwrap().iter().map(DumpedAnomalyInput::parse).collect();
        let site_id = inputs[0].site_id;
        delete_site(&redis, site_id).await;

        let scorer = AnomalyScorer::new(Some(redis.clone()), Arc::new(SiteBaselines::new()));
        scorer.set_redis_enabled(true);
        for (index, input) in inputs.iter().enumerate() {
            let actual =
                normalize_numbers(serde_json::to_value(scorer.observe_tracking_anomaly(&input.input()).await).unwrap());
            let expected = normalize_numbers(scenario["redis"][index].clone());
            redis_results.check(&expected, &actual, || format!("{name} event {index} (Redis)"));
        }

        let state = redis_state(&redis, site_id).await;
        let expected_state = scenario["state"].as_object().expect("state");
        let expected_keys: Vec<&String> = expected_state.keys().collect();
        let actual_keys: Vec<&String> = state.keys().collect();
        redis_keys.check(&json!(expected_keys), &json!(actual_keys), || format!("{name}: key set"));
        for (key, expected) in expected_state {
            let Some(actual) = state.get(key) else { continue };
            redis_keys.check(&expected["type"], &actual["type"], || format!("{name}: TYPE {key}"));
            redis_keys.check(&expected["value"], &actual["value"], || format!("{name}: value of {key}"));
            // TTLs are relative to the wall clock of each run, so only their size is
            // compared: both set, and within a few seconds of each other.
            let (node_ttl, rust_ttl) = (expected["pttl"].as_i64().unwrap(), actual["pttl"].as_i64().unwrap());
            let close = node_ttl > 0 && rust_ttl > 0 && (node_ttl - rust_ttl).abs() <= 15_000;
            redis_keys
                .check(&json!(true), &json!(close), || format!("{name}: PTTL {key} node {node_ttl} rust {rust_ttl}"));
        }
        delete_site(&redis, site_id).await;

        let scorer = AnomalyScorer::new(None, Arc::new(SiteBaselines::new()));
        scorer.set_redis_enabled(false);
        for (index, input) in inputs.iter().enumerate() {
            let actual =
                normalize_numbers(serde_json::to_value(scorer.observe_tracking_anomaly(&input.input()).await).unwrap());
            let expected = normalize_numbers(scenario["local"][index].clone());
            local_results.check(&expected, &actual, || format!("{name} event {index} (in-process)"));
        }
        eprintln!("{name}: {} events, {} keys", inputs.len(), expected_state.len());
    }

    redis_results.finish();
    local_results.finish();
    redis_keys.finish();
}

/// Drop null-valued object keys: Node writes `botName: null` where the port
/// leaves the field out.
fn strip_nulls(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key, strip_nulls(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(strip_nulls).collect()),
        other => other,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn check_bot_blocking_matches_node_end_to_end() {
    use super::{BotBlocking, BotBlockingInput, BotBlockingPayload};

    let Some(dir) = dumps_dir() else { return };
    let geo_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../server");
    let geo = crate::geo::Geo::load(&geo_dir).expect("GeoLite2 databases next to the Node server");
    let dump: Value = serde_json::from_str(&fs::read_to_string(dir.join("e2e.json")).expect("e2e dump")).expect("json");

    let detector = BotBlocking::new(None);
    detector.anomaly.set_redis_enabled(false);
    let mut tally = Tally::new("checkBotBlocking");
    let text = |value: &Value, name: &str| value.get(name).and_then(Value::as_str).map(str::to_string);

    let cases = dump["cases"].as_array().expect("cases");
    for (index, case) in cases.iter().enumerate() {
        let headers = header_map_from_raw(case["raw"].as_array().expect("raw"));
        let payload_json = &case["payload"];
        let (user_agent, language, hostname, pathname, event_type, referrer, ip_address) = (
            text(payload_json, "userAgent"),
            text(payload_json, "language"),
            text(payload_json, "hostname"),
            text(payload_json, "pathname"),
            text(payload_json, "eventType"),
            text(payload_json, "referrer"),
            text(payload_json, "ipAddress").unwrap_or_default(),
        );
        let payload = BotBlockingPayload {
            site_id: payload_json["siteId"].as_i64().unwrap() as i32,
            user_agent: user_agent.as_deref(),
            client_bot_score: payload_json.get("clientBotScore").and_then(Value::as_i64),
            client_bot_signal_mask: payload_json.get("clientBotSignalMask").and_then(Value::as_i64),
            screen_width: payload_json.get("screenWidth").and_then(Value::as_f64),
            screen_height: payload_json.get("screenHeight").and_then(Value::as_f64),
            language: language.as_deref(),
            hostname: hostname.as_deref(),
            pathname: pathname.as_deref(),
            event_type: event_type.as_deref(),
            referrer: referrer.as_deref(),
            ip_address: &ip_address,
        };
        let asn_lookup = geo.asn_lookup();
        let input = BotBlockingInput {
            headers: &headers,
            block_bots: case["blockBots"].as_bool().unwrap(),
            trusted_server_side_ingestion: case["trusted"].as_bool().unwrap(),
            is_mobile_site: case["mobile"].as_bool().unwrap(),
            payload,
            asn_lookup: &asn_lookup,
        };

        let mut result = None;
        for _ in 0..case["repeat"].as_u64().unwrap() {
            result = detector.check_bot_blocking(input).await;
        }

        let expected = &dump["results"][index];
        let actual = match result {
            None => Value::Null,
            Some(result) => json!({
                "isBot": true,
                "enforced": result.enforced,
                "message": result.message,
                "detections": result.detections,
                "eventProperties": result.event_properties,
            }),
        };
        let expected = normalize_numbers(strip_nulls(expected.clone()));
        let actual = normalize_numbers(strip_nulls(actual));
        tally.check(&expected, &actual, || format!("case {index}: {case}"));
    }

    let stats = detector.stats.snapshot();
    let actual_stats = normalize_numbers(json!({
        "totalRequests": stats.total_requests,
        "totalBotRequests": stats.total_bot_requests,
        "totalEnforcedBotRequests": stats.total_enforced_bot_requests,
        "botRequestPercentage": stats.bot_request_percentage,
        "totals": stats.totals.iter().map(|(key, value)| (key.to_string(), json!(value))).collect::<serde_json::Map<_, _>>(),
        "clientBotScoreHistogram": stats.client_bot_score_histogram.iter().map(|(key, value)| (key.to_string(), json!(value))).collect::<serde_json::Map<_, _>>(),
        "clientBotSignalTotals": stats.client_bot_signal_totals.iter().map(|(key, value)| (key.to_string(), json!(value))).collect::<serde_json::Map<_, _>>(),
    }));
    tally.check(&normalize_numbers(dump["stats"].clone()), &actual_stats, || "getBotDetectionStats".to_string());

    let layers: std::collections::BTreeMap<String, usize> = dump["results"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|result| result["detections"].as_array().cloned().unwrap_or_default())
        .fold(Default::default(), |mut counts, detection| {
            *counts.entry(detection["layer"].as_str().unwrap_or_default().to_string()).or_default() += 1;
            counts
        });
    eprintln!("detections by layer in the e2e corpus: {layers:?}");
    tally.finish();
}

#[tokio::test(flavor = "multi_thread")]
async fn site_baselines_match_node() {
    use super::site_baseline::{compute_site_baselines, encode};

    let Some(dir) = dumps_dir() else { return };
    let url = std::env::var("BOT_TEST_CLICKHOUSE_URL").unwrap_or_else(|_| "http://127.0.0.1:58123".to_string());
    let clickhouse = crate::clickhouse::ClickHouse::new(&url, "analytics", "default", "hygo").expect("client");
    if clickhouse.ping().await.is_err() {
        eprintln!("parity ClickHouse unreachable; skipping");
        return;
    }
    let dump: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("baseline.json")).expect("baseline dump")).expect("json");

    let computed = compute_site_baselines(&clickhouse).await.expect("computing baselines");
    let actual: serde_json::Map<String, Value> = computed
        .iter()
        .map(|(site_id, baseline)| {
            (
                site_id.to_string(),
                json!({ "events10m": baseline.events10m, "eligible": baseline.eligible, "encoded": encode(*baseline) }),
            )
        })
        .collect();

    let mut tally = Tally::new("computeSiteBaselines");
    tally.check(&normalize_numbers(dump["baselines"].clone()), &normalize_numbers(Value::Object(actual)), || {
        "baselines by site".to_string()
    });
    eprintln!("{} sites", computed.len());
    tally.finish();
}
