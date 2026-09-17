//! Differential checks against the Node implementation. parity/feature_flags/node.mts
//! generates the corpora and records Node's answers; these ignored tests replay every
//! case through the port and compare byte for byte. Run through
//! parity/feature_flags/run.sh (PARITY_FEATURE_FLAGS_DIR names the corpus directory).

use std::{path::PathBuf, sync::Mutex};

use serde_json::{Value, json};

use super::{
    definitions::{DefinitionsCache, DefinitionsError, Stores},
    evaluate::{self, EvaluateStores, RequestFacts, Runtime},
    evaluator::{self, FeatureFlagContext},
    js,
    regex::{self, RegexCache, compile::CompiledRegex, safe_regex, syntax},
    schemas,
};
use crate::{
    geo::Location,
    js_json,
    site_config::{SiteConfigData, SiteRef},
};

fn corpus(name: &str) -> Value {
    let directory = std::env::var("PARITY_FEATURE_FLAGS_DIR").expect("PARITY_FEATURE_FLAGS_DIR");
    let path = PathBuf::from(directory).join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text).expect("corpus JSON")
}

fn output_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var("PARITY_FEATURE_FLAGS_DIR").expect("PARITY_FEATURE_FLAGS_DIR")).join(name)
}

/// Prints the mismatches (40 unless PARITY_SHOW says otherwise) and fails when there
/// is any.
fn report(suite: &str, total: usize, mismatches: &[String]) {
    report_with_known(suite, total, mismatches, 0);
}

/// [`report`] for a suite with `known` accepted differences (printed as KNOWN).
fn report_with_known(suite: &str, total: usize, mismatches: &[String], known: usize) {
    let show = std::env::var("PARITY_SHOW").ok().and_then(|show| show.parse().ok()).unwrap_or(40);
    for mismatch in mismatches.iter().take(show) {
        println!("MISMATCH {suite}: {mismatch}");
    }
    println!("{suite}: {}/{total} identical, {known} known differences", total - mismatches.len() - known);
    assert!(mismatches.is_empty(), "{} {suite} mismatches", mismatches.len());
}

/// Pattern and subject pairs where the port knowingly differs. regress compares
/// case-insensitive backreferences with its own folding, which (unlike V8's
/// `Canonicalize`) lets U+017F and U+0131 match `s`/`S` and `i`/`I` and some Greek
/// titlecase letters match their lowercase forms. Characters and classes are folded
/// by the port itself and do not have this difference.
const KNOWN_REGEX_DIFFERENCES: &[(&str, &str)] = &[("(?i:(\u{17f})\\1)", "\u{17f}s")];

#[test]
#[ignore = "needs corpora from parity/feature_flags/run.sh"]
fn regex_matches_node() {
    let corpus = corpus("regex.json");
    let subjects: Vec<&str> =
        corpus["subjects"].as_array().unwrap().iter().map(|subject| subject.as_str().unwrap()).collect();
    let cases = corpus["cases"].as_array().unwrap();
    let mut mismatches = Vec::new();
    let mut checks = 0;
    for case in cases {
        let pattern = case["pattern"].as_str().unwrap();
        let units: Vec<u16> = pattern.encode_utf16().collect();

        checks += 1;
        let validate = regex::validate_feature_flag_regex_pattern(pattern);
        if validate.as_deref() != case["validate"].as_str() {
            mismatches.push(format!("validate {pattern:?}\n  node: {}\n  rust: {validate:?}", case["validate"]));
        }

        checks += 1;
        let parsed = syntax::parse(&units);
        let v8 = parsed.as_ref().err().map(|error| regex::v8_syntax_error_message(pattern, *error));
        if v8.as_deref() != case["v8"].as_str() {
            mismatches.push(format!("new RegExp {pattern:?}\n  node: {}\n  rust: {v8:?}", case["v8"]));
        }

        checks += 1;
        let tokens = safe_regex::tokens_json(pattern).ok();
        let node_tokens = (!case["ret"].is_null()).then(|| case["ret"].clone());
        if tokens != node_tokens {
            mismatches.push(format!(
                "ret {pattern:?}\n  node: {}\n  rust: {}",
                node_tokens.map_or("throws".to_string(), |tokens| tokens.to_string()),
                tokens.map_or("throws".to_string(), |tokens| tokens.to_string())
            ));
        }

        checks += 1;
        let safe = safe_regex::is_safe(pattern, regex::MAX_REGEX_REPETITIONS);
        if Some(safe) != case["safe"].as_bool() {
            mismatches.push(format!("safeRegex {pattern:?}\n  node: {}\n  rust: {safe}", case["safe"]));
        }

        if let (Some(tests), Ok(parsed)) = (case["tests"].as_array(), &parsed) {
            let compiled = match CompiledRegex::new(parsed) {
                Ok(compiled) => compiled,
                Err(error) => {
                    mismatches.push(format!(
                        "compile {pattern:?}: regress rejected {:?}: {error}",
                        syntax::parse(&units).map(|p| super::regex::compile::spell(&p))
                    ));
                    continue;
                }
            };
            for (subject, expected) in subjects.iter().zip(tests) {
                checks += 1;
                let actual = compiled.test(subject);
                if Some(actual) != expected.as_bool() {
                    mismatches.push(format!(
                        "test {pattern:?} on {subject:?} (spelled {:?})\n  node: {expected}\n  rust: {actual}",
                        compiled.spelled()
                    ));
                }
            }
        }
    }
    let semantic = corpus["semantic"].as_array().unwrap();
    let mut known = 0;
    for case in semantic {
        let pattern = case["pattern"].as_str().unwrap();
        let subject = case["subject"].as_str().unwrap();
        checks += 1;
        let units: Vec<u16> = pattern.encode_utf16().collect();
        let actual = syntax::parse(&units)
            .ok()
            .and_then(|parsed| CompiledRegex::new(&parsed).ok())
            .map(|compiled| compiled.test(subject));
        if actual != case["result"].as_bool() {
            let mismatch =
                format!("semantic {pattern:?} on {subject:?}\n  node: {}\n  rust: {actual:?}", case["result"]);
            if KNOWN_REGEX_DIFFERENCES.contains(&(pattern, subject)) {
                println!("KNOWN regex: {mismatch}");
                known += 1;
            } else {
                mismatches.push(mismatch);
            }
        }
    }
    println!("regex: {} patterns, {} semantic cases, {checks} comparisons", cases.len(), semantic.len());
    report_with_known("regex", checks, &mismatches, known);
}

fn context_from_json(context: &Value) -> FeatureFlagContext {
    let text = |name: &str| context.get(name).and_then(Value::as_str).map(str::to_string);
    FeatureFlagContext {
        anonymous_id: text("anonymousId").unwrap_or_default(),
        identified_user_id: text("identifiedUserId"),
        hostname: text("hostname"),
        pathname: text("pathname"),
        query: context.get("query").cloned(),
        referrer: text("referrer"),
        language: text("language"),
        country: text("country"),
        region: text("region"),
        city: text("city"),
        device_type: text("deviceType"),
        traits: context.get("traits").cloned(),
    }
}

#[test]
#[ignore = "needs corpora from parity/feature_flags/run.sh"]
fn evaluator_matches_node() {
    let corpus = corpus("evaluator.json");
    let cases = corpus["cases"].as_array().unwrap();
    // One cache for the whole run, like the single Node process that produced it
    let cache = Mutex::new(RegexCache::new());
    let mut mismatches = Vec::new();
    let mut flags = 0;
    for (index, case) in cases.iter().enumerate() {
        let definitions = js::parse_json(case["definitions"].as_str().unwrap()).unwrap();
        let context = context_from_json(&js::parse_json(case["context"].as_str().unwrap()).unwrap());
        let runtime = case["runtime"].as_str();
        let rows = definitions.as_array().unwrap();
        flags += rows.len();
        let result = evaluator::evaluate_feature_flag_definitions_with_cache(rows, &context, runtime, Some(&cache));
        let (rust_result, rust_error) = match &result {
            Ok(assignments) => (Some(js_json::stringify(&Value::Object(assignments.clone()))), None),
            Err(error) => (None, Some(error.0.clone())),
        };
        let node_result = case["result"].as_str().map(str::to_string);
        let node_error = case["error"].as_str();
        if rust_result != node_result || rust_error.is_some() != node_error.is_some() {
            mismatches.push(format!(
                "case {index}\n  definitions: {}\n  context: {}\n  runtime: {runtime:?}\n  node: {}\n  rust: {}",
                case["definitions"].as_str().unwrap(),
                case["context"].as_str().unwrap(),
                node_result.as_deref().or(node_error).unwrap_or_default(),
                rust_result.as_deref().or(rust_error.as_deref()).unwrap_or_default()
            ));
        }
    }
    println!("evaluator: {} cases, {flags} flags", cases.len());
    report("evaluator", cases.len(), &mismatches);
}

#[test]
#[ignore = "needs corpora from parity/feature_flags/run.sh"]
fn schemas_match_node() {
    let corpus = corpus("schemas.json");
    let cases = corpus["cases"].as_array().unwrap();
    let mut mismatches = Vec::new();
    for case in cases {
        let body = case["body"].as_str().map(|body| js::parse_json(body).unwrap());
        let (data, details) = match schemas::parse_evaluate_body(body.as_ref()) {
            Ok(parsed) => (Some(js_json::stringify(&schemas::evaluate_body_json(&parsed))), None),
            Err(issues) => (None, Some(js_json::stringify(&issues.into_json()))),
        };
        if data.as_deref() != case["data"].as_str() || details.as_deref() != case["details"].as_str() {
            mismatches.push(format!(
                "body {}\n  node: {} {}\n  rust: {data:?} {details:?}",
                case["body"], case["data"], case["details"]
            ));
        }
    }
    report("schemas", cases.len(), &mismatches);
}

#[test]
#[ignore = "needs corpora from parity/feature_flags/run.sh"]
fn flag_schemas_match_node() {
    let corpus = corpus("flag-schemas.json");
    let cases = corpus["cases"].as_array().unwrap();
    let mut mismatches = Vec::new();
    for case in cases {
        let body = case["body"].as_str().map(|body| js::parse_json(body).unwrap());
        for (name, result) in [
            ("create", schemas::parse_feature_flag_body(body.as_ref())),
            ("update", schemas::parse_feature_flag_update(body.as_ref())),
        ] {
            let (data, details) = match result {
                Ok(data) => (Some(js_json::stringify(&data)), None),
                Err(issues) => (None, Some(js_json::stringify(&issues.into_json()))),
            };
            let node = &case[name];
            if data.as_deref() != node["data"].as_str() || details.as_deref() != node["details"].as_str() {
                mismatches.push(format!(
                    "{name} body {}\n  node: {} {}\n  rust: {data:?} {details:?}",
                    case["body"], node["data"], node["details"]
                ));
            }
        }
    }
    report("flag schemas", cases.len() * 2, &mismatches);
}

#[test]
#[ignore = "needs corpora from parity/feature_flags/run.sh"]
fn query_matches_node() {
    let corpus = corpus("query.json");
    let cases = corpus["cases"].as_array().unwrap();
    let mut mismatches = Vec::new();
    for case in cases {
        let querystring = case["querystring"].as_str().unwrap();
        let result = js_json::stringify(&super::query::parse_query(Some(querystring)));
        if Some(result.as_str()) != case["result"].as_str() {
            mismatches.push(format!("parseQuery {querystring:?}\n  node: {}\n  rust: {result}", case["result"]));
        }
    }
    report("query", cases.len(), &mismatches);
}

const PARITY_SITE_ID: i32 = 65731;

/// The parity Postgres and Redis from the environment run.sh exports, with fresh
/// per-test copies of the process-wide caches.
struct ParityStores {
    pg: sqlx::PgPool,
    redis: redis::aio::ConnectionManager,
    site_config: crate::site_config::SiteConfigCache,
    definitions: DefinitionsCache,
}

impl ParityStores {
    async fn connect() -> Self {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

        let config = crate::config::Config::from_env().unwrap();
        let options = PgConnectOptions::new()
            .host(&config.postgres.host)
            .port(config.postgres.port)
            .username(&config.postgres.user)
            .password(&config.postgres.password)
            .database(&config.postgres.database);
        let pg = PgPoolOptions::new().max_connections(4).connect_with(options).await.unwrap();
        let redis_url = match &config.redis.password {
            Some(password) => format!("redis://:{password}@{}:{}/", config.redis.host, config.redis.port),
            None => format!("redis://{}:{}/", config.redis.host, config.redis.port),
        };
        let redis = redis::aio::ConnectionManager::new(redis::Client::open(redis_url).unwrap()).await.unwrap();
        let site_config = crate::site_config::SiteConfigCache::new(pg.clone());
        Self { pg, redis, site_config, definitions: DefinitionsCache::new() }
    }

    fn stores(&self) -> Stores<'_> {
        Stores { pg: &self.pg, redis: &self.redis }
    }
}

/// The same wiring as `impl EvaluateStores for AppState`, on the parity stores.
impl EvaluateStores for ParityStores {
    async fn site_config(&self, site_id_param: &str) -> Option<SiteConfigData> {
        self.site_config.get_config(&SiteRef::Text(site_id_param.to_string())).await
    }

    async fn definitions_for_runtime(&self, site_id: i32, runtime: Runtime) -> Result<Vec<Value>, DefinitionsError> {
        self.definitions.get_for_runtime(&self.stores(), site_id, runtime.as_str()).await
    }

    async fn user_traits(&self, site_id: i32, user_id: &str) -> Result<Option<Value>, String> {
        evaluate::load_user_traits(&self.pg, site_id, user_id).await
    }
}

#[tokio::test]
#[ignore = "needs the parity stores and cache-node.json from parity/feature_flags/run.sh"]
async fn cache_writes_what_node_writes() {
    use redis::AsyncCommands;

    let node = corpus("cache-node.json");
    let parity = ParityStores::connect().await;
    let key = super::definitions::cache_key(PARITY_SITE_ID);
    let mut redis = parity.redis.clone();
    let _: () = redis.del(&key).await.unwrap();

    let rows = parity.definitions.get(&parity.stores(), PARITY_SITE_ID).await.unwrap();
    let cached: Option<String> = redis.get(&key).await.unwrap();
    let ttl: i64 = redis.ttl(&key).await.unwrap();
    let _: () = redis.del(&key).await.unwrap();
    std::fs::write(output_path("cache-rust.json"), json!({ "cached": cached, "ttl": ttl }).to_string()).unwrap();

    let mut mismatches = Vec::new();
    if cached.as_deref() != node["cached"].as_str() {
        mismatches.push(format!("Redis value\n  node: {}\n  rust: {cached:?}", node["cached"]));
    }
    if (ttl - node["ttl"].as_i64().unwrap()).abs() > 2 {
        mismatches.push(format!("TTL node {} rust {ttl}", node["ttl"]));
    }
    // What Node evaluated on the Postgres path equals what Rust returns
    if Some(js_json::stringify(&rows).as_str()) != node["rows"].as_str() {
        mismatches.push(format!("rows\n  node: {}\n  rust: {}", node["rows"], js_json::stringify(&rows)));
    }

    // Rust reading Node's bytes
    let _: () = redis.set_ex(&key, node["cached"].as_str().unwrap(), 300).await.unwrap();
    let from_node = parity.definitions.get(&parity.stores(), PARITY_SITE_ID).await.unwrap();
    let _: () = redis.del(&key).await.unwrap();
    if js_json::stringify(&from_node) != js_json::stringify(&rows) {
        mismatches.push(format!(
            "reading Node's cache\n  expected: {}\n  rust: {}",
            js_json::stringify(&rows),
            js_json::stringify(&from_node)
        ));
    }
    report("cache write", 3, &mismatches);
}

#[test]
#[ignore = "needs cache-node-read.json from parity/feature_flags/run.sh"]
fn node_reads_what_rust_writes() {
    let node_read = corpus("cache-node-read.json");
    let node = corpus("cache-node.json");
    let mut mismatches = Vec::new();
    if node_read["rows"] != node["rows"] {
        mismatches
            .push(format!("Node reading Rust's cache\n  expected: {}\n  node: {}", node["rows"], node_read["rows"]));
    }
    report("cache read", 1, &mismatches);
}

/// What the Node handler computes for a request from 127.0.0.1 without a user agent.
struct ParityFacts;

impl RequestFacts for ParityFacts {
    fn location(&self, _site: &SiteConfigData) -> Option<Location> {
        // getLocation(["127.0.0.1"]) finds nothing
        None
    }

    fn device_type(&self, screen_width: f64, screen_height: f64) -> String {
        // getDeviceType with no OS name
        let larger = js::math_max(screen_width, screen_height);
        let smaller = js::math_min(screen_width, screen_height);
        if larger > 1024.0 {
            "Desktop".into()
        } else if larger > 768.0 && smaller > 1024.0 {
            "Tablet".into()
        } else {
            "Mobile".into()
        }
    }
}

#[tokio::test]
#[ignore = "needs the parity stores seeded by parity/feature_flags/run.sh"]
async fn evaluate_route_matches_node() {
    let corpus = corpus("e2e.json");
    let parity = ParityStores::connect().await;
    let cases = corpus["cases"].as_array().unwrap();
    let mut mismatches = Vec::new();
    for case in cases {
        let body = case["body"].as_str().map(|body| js::parse_json(body).unwrap());
        let runtime = if case["runtime"] == "server" { Runtime::Server } else { Runtime::Client };
        let (status, mut response) = evaluate::evaluate_with_stores(
            &parity,
            case["site"].as_str().unwrap(),
            body.as_ref(),
            runtime,
            &ParityFacts,
        )
        .await;
        if let Some(generated_at) = response.get_mut("generatedAt") {
            let text = generated_at.as_str().unwrap_or_default();
            assert!(
                chrono::DateTime::parse_from_rfc3339(text).is_ok() && text.ends_with('Z') && text.len() == 24,
                "{text}"
            );
            *generated_at = json!("<generatedAt>");
        }
        let response = js_json::stringify(&response);
        if Some(u64::from(status.as_u16())) != case["status"].as_u64()
            || Some(response.as_str()) != case["response"].as_str()
        {
            mismatches.push(format!(
                "{} {} body {}\n  node: {} {}\n  rust: {} {response}",
                case["runtime"],
                case["site"],
                case["body"],
                case["status"],
                case["response"],
                status.as_u16()
            ));
        }
    }
    report("evaluate route", cases.len(), &mismatches);
}
