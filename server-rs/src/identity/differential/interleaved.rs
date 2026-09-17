//! Node and Rust taking turns against the same parity Redis and Postgres.
//!
//! Each scenario is a fixed script of calls. It runs three times over the same
//! keys, cleaning up in between: every call on Node, every call on Rust, and each
//! call on a backend picked at random. A faithful port gives identical answers
//! and identical stored state in all three runs; a mismatch in the alternating
//! run means one backend cannot read what the other wrote.

use std::{collections::BTreeMap, sync::Arc};

use redis::{AsyncCommands, aio::ConnectionManager};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

use super::{NodeRpc, PARITY_PG, Rng, SECRET, pure::load_pure, report, server_dir};
use crate::{
    clickhouse::ClickHouse,
    geo::Geo,
    identity::{
        backfill::{BACKFILL_DAYS, IdentityAssignment, IdentityBackfillQueue, tests::RecordingSink},
        identify::{IdentifyDeps, IdentifyRequest, handle_identify},
        sessions::{SESSION_GET_OR_CREATE_LUA, SESSION_REFRESH_LUA, SessionsService, session_key},
        sticky::{
            ALIAS_TTL_MS, CANDIDATE_WINDOW_MS, MAX_CANDIDATES, SEEN_TTL_MS, STICKY_RESOLVE_LUA, StickyIdentityInput,
            StickyResolveInput, resolve_sticky_user_id_with, sticky_resolve,
        },
        user_id::{UserIdDeps, UserIdOptions, UserIdService},
    },
    site_config::SiteConfigCache,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Node,
    Rust,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    AllNode,
    AllRust,
    Alternating,
}

const MODES: [Mode; 3] = [Mode::AllNode, Mode::AllRust, Mode::Alternating];

impl Mode {
    fn backend(self, chooser: &mut Rng) -> Backend {
        match self {
            Mode::AllNode => Backend::Node,
            Mode::AllRust => Backend::Rust,
            Mode::Alternating => {
                if chooser.chance(0.5) {
                    Backend::Node
                } else {
                    Backend::Rust
                }
            }
        }
    }
}

struct Context {
    node: NodeRpc,
    redis: ConnectionManager,
    pg: PgPool,
    site_config: SiteConfigCache,
    geo: Geo,
    user_ids: UserIdService,
    sessions: SessionsService,
}

impl Context {
    async fn start() -> Option<Self> {
        let mut node = NodeRpc::start().await?;
        let shas = node.call("ready", Value::Null).await;

        let client = redis::Client::open("redis://:hygo@127.0.0.1:56379/").expect("redis url");
        let redis = ConnectionManager::new(client).await.expect("parity Redis");
        let pg = PgPoolOptions::new().max_connections(4).connect(PARITY_PG).await.expect("parity Postgres");

        // Identical Lua text means identical SHA1, so EVALSHA finds whichever backend loaded it
        assert_eq!(shas["stickyResolveSha"], json!(redis::Script::new(STICKY_RESOLVE_LUA).get_hash()));
        assert_eq!(shas["sessionGetOrCreateSha"], json!(redis::Script::new(SESSION_GET_OR_CREATE_LUA).get_hash()));
        assert_eq!(shas["sessionRefreshSha"], json!(redis::Script::new(SESSION_REFRESH_LUA).get_hash()));
        println!("Lua SHA1s match Node's: {shas}");

        Some(Self {
            node,
            redis,
            site_config: SiteConfigCache::new(pg.clone()),
            pg,
            geo: Geo::load(&server_dir()).expect("GeoLite2 next to the Node server"),
            user_ids: UserIdService::new(),
            sessions: SessionsService::new(),
        })
    }

    async fn delete_keys(&self, patterns: &[&str]) {
        let mut redis = self.redis.clone();
        for pattern in patterns {
            let keys: Vec<String> = redis.keys(*pattern).await.unwrap();
            if !keys.is_empty() {
                let _: () = redis.del(keys).await.unwrap();
            }
        }
    }

    /// Every key under the patterns: type, content and remaining TTL.
    async fn dump_redis(&self, patterns: &[&str]) -> BTreeMap<String, (Value, i64)> {
        let mut redis = self.redis.clone();
        let mut dump = BTreeMap::new();
        for pattern in patterns {
            let keys: Vec<String> = redis.keys(*pattern).await.unwrap();
            for key in keys {
                let kind: String = redis::cmd("TYPE").arg(&key).query_async(&mut redis).await.unwrap();
                let content = match kind.as_str() {
                    "string" => json!(redis.get::<_, Option<String>>(&key).await.unwrap()),
                    "zset" => json!(redis.zrange_withscores::<_, Vec<(String, f64)>>(&key, 0, -1).await.unwrap()),
                    other => json!(format!("unexpected type {other}")),
                };
                let ttl: i64 = redis::cmd("PTTL").arg(&key).query_async(&mut redis).await.unwrap();
                dump.insert(key, (content, ttl));
            }
        }
        dump
    }
}

/// Equal values, except that sorted-set scores written from the wall clock (the
/// runs happen seconds apart) only need to agree within `tolerance_ms`.
fn same_content(expected: &Value, actual: &Value, tolerance_ms: i64) -> bool {
    match (expected, actual) {
        (Value::Array(expected), Value::Array(actual)) if expected.len() == actual.len() => {
            expected.iter().zip(actual).all(|(expected, actual)| match (expected, actual) {
                (Value::Array(pair), Value::Array(other)) if pair.len() == 2 && other.len() == 2 => {
                    pair[0] == other[0]
                        && match (pair[1].as_f64(), other[1].as_f64()) {
                            (Some(score), Some(other_score)) => (score - other_score).abs() <= tolerance_ms as f64,
                            _ => pair[1] == other[1],
                        }
                }
                _ => expected == actual,
            })
        }
        _ => expected == actual,
    }
}

/// Mismatches between two Redis dumps, TTLs compared within `tolerance_ms`.
fn compare_dumps(
    name: &str,
    expected: &BTreeMap<String, (Value, i64)>,
    actual: &BTreeMap<String, (Value, i64)>,
    tolerance_ms: i64,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    for (key, (content, ttl)) in expected {
        match actual.get(key) {
            None => mismatches.push(format!("{name}: {key} missing")),
            Some((other_content, other_ttl)) => {
                if !same_content(content, other_content, tolerance_ms) {
                    mismatches.push(format!("{name}: {key} holds {other_content}, expected {content}"));
                }
                if (ttl - other_ttl).abs() > tolerance_ms {
                    mismatches.push(format!("{name}: {key} ttl {other_ttl}, expected about {ttl}"));
                }
            }
        }
    }
    for key in actual.keys().filter(|key| !expected.contains_key(*key)) {
        mismatches.push(format!("{name}: unexpected key {key}"));
    }
    mismatches
}

fn compare_outputs(name: &str, runs: &[Vec<Value>]) -> Vec<String> {
    let mut mismatches = Vec::new();
    for (mode, run) in MODES.iter().zip(runs).skip(1) {
        for (step, (expected, actual)) in runs[0].iter().zip(run).enumerate() {
            if expected != actual {
                mismatches.push(format!("{name} {mode:?} step {step}: {actual}, all-Node run gave {expected}"));
            }
        }
    }
    mismatches
}

fn ua_hash(user_agent: &str) -> String {
    hex::encode(Sha256::digest(user_agent.as_bytes()))[..16].to_string()
}

// ---------------------------------------------------------------------------
// Sticky identity with scripted clocks and eligibility

enum StickyStep {
    /// `resolveStickyUserId`
    Resolve { raw: String, ua: String, salt_scope: String, now_ms: i64, eligible: bool },
    /// `stickyResolve` directly, for the outcome
    Raw { raw: String, ua: String, salt_scope: String, now_ms: i64, eligible: bool },
    /// Let a fingerprint's seen flag lapse (same for every run), so ids that were
    /// known can re-attach and alias chains form.
    ForgetSeen { raw: String },
}

const STICKY_SITE: i32 = 65100;

fn sticky_steps() -> Vec<StickyStep> {
    let mut rng = Rng(2026_0917);
    let user_agents = ["Mozilla/5.0 Chrome/151", "Mozilla/5.0 Firefox/153", "HygoApp/1 CFNetwork"];
    let mut now_ms = 1_790_000_000_000_i64;
    let mut steps = Vec::new();
    for _ in 0..600 {
        let ua = rng.pick(&user_agents).to_string();
        let raw = format!("{}{:02}", &ua_hash(&ua)[..10], rng.below(7));
        let salt_scope = if rng.chance(0.3) { "2026-09-17".to_string() } else { String::new() };
        now_ms += rng.below(240_000) as i64;
        if rng.chance(0.03) {
            now_ms += CANDIDATE_WINDOW_MS as i64 + 1;
        }
        let eligible = rng.chance(0.8);
        let roll = rng.next();
        steps.push(if roll < 0.06 {
            StickyStep::ForgetSeen { raw }
        } else if roll < 0.5 {
            StickyStep::Resolve { raw, ua, salt_scope, now_ms, eligible }
        } else {
            StickyStep::Raw { raw, ua, salt_scope, now_ms, eligible }
        });
    }
    steps
}

#[tokio::test]
#[ignore]
async fn sticky_identity_interleaves_with_node() {
    let Some(mut ctx) = Context::start().await else { return };
    let patterns = [format!("sticky:*:{STICKY_SITE}:*")];
    let patterns: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let steps = sticky_steps();

    let mut runs = Vec::new();
    let mut dumps = Vec::new();
    let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
    let mut calls: BTreeMap<String, usize> = BTreeMap::new();
    for mode in MODES {
        ctx.delete_keys(&patterns).await;
        let mut chooser = Rng(99);
        let mut outputs = Vec::new();
        for step in &steps {
            let output =
                match step {
                    StickyStep::ForgetSeen { raw } => {
                        let _: () = ctx.redis.clone().del(format!("sticky:seen:{STICKY_SITE}:{raw}")).await.unwrap();
                        json!("forgot")
                    }
                    StickyStep::Resolve { raw, ua, salt_scope, now_ms, eligible } => {
                        let backend = mode.backend(&mut chooser);
                        *calls.entry(format!("{mode:?}/{backend:?}")).or_default() += 1;
                        match backend {
                            Backend::Node => ctx
                                .node
                                .call(
                                    "sticky",
                                    json!({ "input": {
                                        "siteId": STICKY_SITE, "rawUserId": raw, "ipAddress": "203.0.113.7",
                                        "userAgent": ua, "saltScope": salt_scope, "nowMs": now_ms, "eligible": eligible,
                                    }}),
                                )
                                .await,
                            Backend::Rust => {
                                let eligible = *eligible;
                                let predicate = move |_: &str| eligible;
                                let input = StickyIdentityInput {
                                    site_id: STICKY_SITE,
                                    raw_user_id: raw,
                                    ip_address: "203.0.113.7",
                                    user_agent: ua,
                                    salt_scope,
                                    now_ms: Some(*now_ms),
                                    is_datacenter_egress: &predicate,
                                };
                                json!(resolve_sticky_user_id_with(&ctx.redis, input, true).await)
                            }
                        }
                    }
                    StickyStep::Raw { raw, ua, salt_scope, now_ms, eligible } => {
                        let input = StickyResolveInput {
                            seen_key: format!("sticky:seen:{STICKY_SITE}:{raw}"),
                            candidates_key: format!("sticky:cand:{STICKY_SITE}:{salt_scope}:{}", ua_hash(ua)),
                            alias_key: format!("sticky:alias:{STICKY_SITE}:{raw}"),
                            raw_user_id: raw.clone(),
                            now_ms: *now_ms,
                            candidate_window_ms: CANDIDATE_WINDOW_MS,
                            seen_ttl_ms: SEEN_TTL_MS,
                            alias_ttl_ms: ALIAS_TTL_MS,
                            eligible: *eligible,
                            seen_key_prefix: format!("sticky:seen:{STICKY_SITE}:"),
                            alias_key_prefix: format!("sticky:alias:{STICKY_SITE}:"),
                            max_candidates: MAX_CANDIDATES,
                        };
                        let backend = mode.backend(&mut chooser);
                        *calls.entry(format!("{mode:?}/{backend:?}")).or_default() += 1;
                        let result = match backend {
                            Backend::Node => ctx
                                .node
                                .call(
                                    "stickyRaw",
                                    json!({ "input": {
                                        "seenKey": input.seen_key, "candidatesKey": input.candidates_key,
                                        "aliasKey": input.alias_key, "rawUserId": input.raw_user_id,
                                        "nowMs": input.now_ms, "candidateWindowMs": input.candidate_window_ms,
                                        "seenTtlMs": input.seen_ttl_ms, "aliasTtlMs": input.alias_ttl_ms,
                                        "eligible": input.eligible, "seenKeyPrefix": input.seen_key_prefix,
                                        "aliasKeyPrefix": input.alias_key_prefix, "maxCandidates": input.max_candidates,
                                    }}),
                                )
                                .await,
                            Backend::Rust => {
                                let (user_id, outcome) = sticky_resolve(&mut ctx.redis.clone(), &input).await.unwrap();
                                json!([user_id, outcome.as_str()])
                            }
                        };
                        *outcomes.entry(result[1].as_str().unwrap_or_default().to_string()).or_default() += 1;
                        result
                    }
                };
            outputs.push(output);
        }
        dumps.push(ctx.dump_redis(&patterns).await);
        runs.push(outputs);
    }
    ctx.delete_keys(&patterns).await;
    ctx.node.stop().await;

    println!(
        "sticky: {} steps per run, calls {calls:?}, stickyResolve outcomes over all runs {outcomes:?}",
        steps.len()
    );
    println!("sticky: {} keys in the final state", dumps[0].len());
    report("sticky answers", steps.len() * 2, &compare_outputs("sticky", &runs));
    let mut state = compare_dumps("all-Rust", &dumps[0], &dumps[1], 30_000);
    state.extend(compare_dumps("alternating", &dumps[0], &dumps[2], 30_000));
    report("sticky Redis state", dumps[0].len() * 2, &state);
}

// ---------------------------------------------------------------------------
// Full user ids with sticky re-attachment and real ASN lookups

#[tokio::test]
#[ignore]
async fn user_ids_with_sticky_interleave_with_node() {
    let Some(corpus) = load_pure() else { return };
    let Some(mut ctx) = Context::start().await else { return };
    let sites = [(65101, false), (65102, true)];
    let patterns = ["sticky:*:65101:*", "sticky:*:65102:*"];

    // Visitors rotating through datacenter egress of one ASN, plus residential ones
    let mut by_asn: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for case in corpus.user_ids.iter().filter(|case| case.datacenter && !case.ip.contains('%')) {
        if let Some(asn) = case.asn {
            by_asn.entry(asn).or_default().push(case.ip.clone());
        }
    }
    let mut pools: Vec<Vec<String>> =
        by_asn.into_values().filter(|ips| ips.len() >= 6).take(5).map(|ips| ips[..6].to_vec()).collect();
    pools.push(
        corpus
            .user_ids
            .iter()
            .filter(|case| !case.datacenter && case.ip.starts_with("73."))
            .take(4)
            .map(|case| case.ip.clone())
            .collect(),
    );
    assert!(pools.len() >= 4, "enough datacenter pools in the corpus");
    let user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1",
    ];

    let mut rng = Rng(424242);
    let steps: Vec<(String, String, i32, bool)> = (0..400)
        .map(|_| {
            let visitor = rng.below(pools.len());
            let ip = rng.pick(&pools[visitor]).clone();
            let ua = user_agents[visitor % user_agents.len()].to_string();
            let (site, salted) = *rng.pick(&sites);
            (ip, ua, site, salted)
        })
        .collect();

    let mut runs = Vec::new();
    let mut dumps = Vec::new();
    for mode in MODES {
        ctx.delete_keys(&patterns).await;
        let mut chooser = Rng(7);
        let mut outputs = Vec::new();
        for (ip, ua, site, salted) in &steps {
            let output = match mode.backend(&mut chooser) {
                Backend::Node => {
                    ctx.node
                        .call(
                            "userId",
                            json!({ "ip": ip, "ua": ua, "siteId": site, "salted": salted, "receivedAt": null }),
                        )
                        .await
                }
                Backend::Rust => {
                    let lookup = ctx.geo.asn_lookup();
                    let deps = UserIdDeps { redis: &ctx.redis, salt_source: &ctx.site_config, secret: Some(SECRET) };
                    let options = UserIdOptions { salt_user_ids: Some(*salted), received_at: None };
                    json!(ctx.user_ids.generate_user_id(&deps, &lookup, ip, ua, *site, options).await.unwrap())
                }
            };
            outputs.push(output);
        }
        dumps.push(ctx.dump_redis(&patterns).await);
        runs.push(outputs);
    }
    ctx.delete_keys(&patterns).await;
    ctx.node.stop().await;

    let distinct: std::collections::BTreeSet<String> = runs[0].iter().map(Value::to_string).collect();
    let aliases = dumps[0].keys().filter(|key| key.starts_with("sticky:alias:")).count();
    println!(
        "user ids: {} steps over {} visitor pools, {} distinct ids, {aliases} re-attachment aliases",
        steps.len(),
        pools.len(),
        distinct.len()
    );
    report("user ids with sticky", steps.len() * 2, &compare_outputs("userId", &runs));
    let mut state = compare_dumps("all-Rust", &dumps[0], &dumps[1], 30_000);
    state.extend(compare_dumps("alternating", &dumps[0], &dumps[2], 30_000));
    report("user id Redis state", dumps[0].len() * 2, &state);
}

// ---------------------------------------------------------------------------
// Sessions

const SESSION_SITE: i32 = 65103;

#[tokio::test]
#[ignore]
async fn sessions_interleave_with_node() {
    let Some(mut ctx) = Context::start().await else { return };
    let pattern = format!("session:{SESSION_SITE}:*");
    let patterns = [pattern.as_str()];

    let users = ["fp-one", "fp-two", "fp-three", "fp-four"];
    let identified = ["", "alice", "bob@example.com", "ü\0nicode"];
    let mut rng = Rng(31337);
    // 0 update, 1 refresh, 2 expire
    let steps: Vec<(u8, &str, &str)> = (0..500)
        .map(|_| {
            let roll = rng.next();
            let kind = if roll < 0.66 {
                0
            } else if roll < 0.94 {
                1
            } else {
                2
            };
            (kind, *rng.pick(&users), *rng.pick(&identified))
        })
        .collect();

    let mut runs = Vec::new();
    let mut dumps = Vec::new();
    let mut calls: BTreeMap<String, usize> = BTreeMap::new();
    for mode in MODES {
        ctx.delete_keys(&patterns).await;
        let mut chooser = Rng(5);
        // Session ids are random: compare them by order of first appearance
        let mut labels: BTreeMap<String, usize> = BTreeMap::new();
        let mut label = |id: Option<String>| -> Value {
            match id {
                None => Value::Null,
                Some(id) => {
                    let next = labels.len();
                    json!(format!("session-{}", labels.entry(id).or_insert(next)))
                }
            }
        };
        let mut outputs = Vec::new();
        for (kind, user, identified_user) in &steps {
            let output = match kind {
                2 => {
                    let _: () = ctx.redis.clone().del(session_key(user, SESSION_SITE, identified_user)).await.unwrap();
                    json!("expired")
                }
                kind => {
                    let backend = mode.backend(&mut chooser);
                    *calls.entry(format!("{mode:?}/{backend:?}")).or_default() += 1;
                    let input = json!({ "input": { "userId": user, "identifiedUserId": identified_user, "siteId": SESSION_SITE } });
                    let id = match (backend, kind) {
                        (Backend::Node, 0) => {
                            ctx.node.call("updateSession", input).await["sessionId"].as_str().map(str::to_string)
                        }
                        (Backend::Node, _) => {
                            ctx.node.call("refreshSession", input).await["sessionId"].as_str().map(str::to_string)
                        }
                        (Backend::Rust, 0) => {
                            Some(ctx.sessions.update_session(&ctx.redis, user, identified_user, SESSION_SITE).await)
                        }
                        (Backend::Rust, _) => {
                            ctx.sessions.refresh_session(&ctx.redis, user, identified_user, SESSION_SITE).await
                        }
                    };
                    if let Some(id) = &id {
                        assert_eq!(id.chars().count(), 14, "nanoid(14)");
                    }
                    label(id)
                }
            };
            outputs.push(output);
        }
        let dump = ctx.dump_redis(&patterns).await;
        // Values are random ids; keep the label so the comparison is structural
        let dump = dump
            .into_iter()
            .map(|(key, (value, ttl))| {
                let id = value.as_str().map(str::to_string);
                (key, (label(id), ttl))
            })
            .collect();
        dumps.push(dump);
        runs.push(outputs);
    }
    ctx.delete_keys(&patterns).await;
    ctx.node.stop().await;

    let created = runs[0]
        .iter()
        .filter_map(Value::as_str)
        .filter(|value| value.starts_with("session-"))
        .collect::<std::collections::BTreeSet<_>>();
    println!("sessions: {} steps, {} distinct sessions, calls {calls:?}", steps.len(), created.len());
    report("session answers", steps.len() * 2, &compare_outputs("session", &runs));
    let mut state = compare_dumps("all-Rust", &dumps[0], &dumps[1], 30_000);
    state.extend(compare_dumps("alternating", &dumps[0], &dumps[2], 30_000));
    report("session Redis state", dumps[0].len() * 2, &state);
}

// ---------------------------------------------------------------------------
// Identify: responses, Postgres rows and queued backfills

struct IdentifyStep {
    body: Option<Value>,
    user_agent_header: Option<String>,
    client_ip: String,
}

fn identify_steps(datacenter_ips: &[String]) -> Vec<IdentifyStep> {
    let mut rng = Rng(8675309);
    let sites = [
        json!("rs-identity-plain"),
        json!("rs-identity-salted"),
        json!("65002"),
        json!("65001"),
        json!("nope-site"),
        json!(""),
        json!(65002),
    ];
    let users = ["user-1", "user-2", "user-3"];
    let ips: Vec<String> =
        datacenter_ips.iter().take(4).cloned().chain(["73.1.2.3".to_string(), "2601:1:2::3".to_string()]).collect();
    let user_agents = ["Mozilla/5.0 Chrome/151.0.0.0", "Mozilla/5.0 Chrome/152.0.0.0", "HygoApp/2.0 CFNetwork/1"];
    let traits = [
        json!({ "plan": "pro", "seats": 1.0, "ratio": 0.1 }),
        json!({ "big": 1e21, "nested": { "a": [1, 2, { "b": null }] }, "2": "two", "1": "one" }),
        json!({ "plan": null }),
        json!({ "{plan,seats}": null, "c": 1 }),
        json!({ "x": null, "y": null, "z": true }),
        json!({}),
        json!({ "emoji": "😀", "quote": "it's \"quoted\"", "control": "\u{1}" }),
        json!({ "huge": "x".repeat(2100) }),
        // {"edge":"…"} is 11 bytes of framing: exactly 2048, then one over
        json!({ "edge": "x".repeat(2048 - 11) }),
        json!({ "edge": "x".repeat(2048 - 10) }),
        // two-byte characters and array-index keys count like JavaScript counts them
        json!({ "u": "é".repeat(1020), "10": 1 }),
        json!({ "u": "é".repeat(1016), "10": 1.5e300 }),
        json!(["not", "an", "object"]),
    ];

    (0..500)
        .map(|_| {
            let roll = rng.next();
            let body = if roll < 0.03 {
                None
            } else if roll < 0.05 {
                Some(json!(null))
            } else if roll < 0.07 {
                Some(json!("user_id=1"))
            } else {
                let mut body = serde_json::Map::new();
                body.insert("site_id".into(), rng.pick(&sites).clone());
                if rng.chance(0.95) {
                    let user = if rng.chance(0.04) { json!("u".repeat(300)) } else { json!(rng.pick(&users)) };
                    body.insert("user_id".into(), user);
                }
                if rng.chance(0.3) {
                    let anonymous =
                        if rng.chance(0.1) { json!("") } else { json!(rng.pick(&["client-a", "client-b"])) };
                    body.insert("anonymous_id".into(), anonymous);
                }
                if rng.chance(0.5) {
                    let ip = if rng.chance(0.08) { json!("1.2.3") } else { json!(rng.pick(&ips)) };
                    body.insert("ip_address".into(), ip);
                }
                if rng.chance(0.5) {
                    let ua = if rng.chance(0.1) {
                        json!("")
                    } else if rng.chance(0.03) {
                        json!("u".repeat(600))
                    } else {
                        json!(rng.pick(&user_agents))
                    };
                    body.insert("user_agent".into(), ua);
                }
                if rng.chance(0.6) {
                    body.insert("traits".into(), rng.pick(&traits).clone());
                }
                if rng.chance(0.5) {
                    let flag = if rng.chance(0.1) { json!("yes") } else { json!(rng.chance(0.7)) };
                    body.insert("is_new_identify".into(), flag);
                }
                Some(Value::Object(body))
            };
            IdentifyStep {
                body,
                user_agent_header: rng.chance(0.9).then(|| rng.pick(&user_agents).to_string()),
                client_ip: rng.pick(&ips).clone(),
            }
        })
        .collect()
}

async fn identify_rows(pg: &PgPool) -> Vec<Value> {
    let profiles = sqlx::query(
        "SELECT site_id, user_id, traits::text AS traits FROM user_profiles WHERE site_id IN (65001, 65002) ORDER BY site_id, user_id",
    )
    .fetch_all(pg)
    .await
    .unwrap();
    let aliases = sqlx::query(
        "SELECT site_id, anonymous_id, user_id FROM user_aliases WHERE site_id IN (65001, 65002) ORDER BY site_id, anonymous_id",
    )
    .fetch_all(pg)
    .await
    .unwrap();
    profiles
        .iter()
        .map(|row| {
            json!([
                "profile",
                row.get::<i32, _>("site_id"),
                row.get::<String, _>("user_id"),
                row.get::<Option<String>, _>("traits")
            ])
        })
        .chain(aliases.iter().map(|row| {
            json!([
                "alias",
                row.get::<i32, _>("site_id"),
                row.get::<String, _>("anonymous_id"),
                row.get::<String, _>("user_id")
            ])
        }))
        .collect()
}

async fn delete_identify_rows(pg: &PgPool) {
    sqlx::query("DELETE FROM user_profiles WHERE site_id IN (65001, 65002)").execute(pg).await.unwrap();
    sqlx::query("DELETE FROM user_aliases WHERE site_id IN (65001, 65002)").execute(pg).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn identify_interleaves_with_node() {
    let Some(corpus) = load_pure() else { return };
    let Some(mut ctx) = Context::start().await else { return };
    let patterns = ["sticky:*:65001:*", "sticky:*:65002:*"];
    let datacenter_ips: Vec<String> = corpus
        .user_ids
        .iter()
        .filter(|case| case.datacenter && !case.ip.contains('%'))
        .map(|case| case.ip.clone())
        .collect();
    let steps = identify_steps(&datacenter_ips);

    let mut runs = Vec::new();
    let mut rows = Vec::new();
    let mut backfills = Vec::new();
    let mut statuses: BTreeMap<String, usize> = BTreeMap::new();
    for mode in MODES {
        delete_identify_rows(&ctx.pg).await;
        ctx.delete_keys(&patterns).await;
        ctx.node.call("backfillReset", Value::Null).await;
        let queue = IdentityBackfillQueue::new(Arc::new(RecordingSink::default()));
        let mut chooser = Rng(11);
        let mut outputs = Vec::new();
        for step in &steps {
            let output = match mode.backend(&mut chooser) {
                Backend::Node => {
                    ctx.node
                        .call(
                            "identify",
                            json!({
                                "missingBody": step.body.is_none(),
                                "body": step.body.clone().unwrap_or(Value::Null),
                                "userAgentHeader": step.user_agent_header,
                                "clientIp": step.client_ip,
                            }),
                        )
                        .await
                }
                Backend::Rust => {
                    let lookup = ctx.geo.asn_lookup();
                    let deps = IdentifyDeps {
                        pg: &ctx.pg,
                        redis: &ctx.redis,
                        site_config: &ctx.site_config,
                        asn_lookup: &lookup,
                        secret: Some(SECRET),
                        user_ids: &ctx.user_ids,
                        backfill: &queue,
                    };
                    let client_ip = step.client_ip.clone();
                    let resolve = move |_: &crate::site_config::SiteConfigData| client_ip.clone();
                    let request = IdentifyRequest {
                        body: step.body.as_ref(),
                        user_agent_header: step.user_agent_header.as_deref(),
                        resolve_client_ip: &resolve,
                    };
                    let (status, body) = handle_identify(&deps, request).await;
                    json!({ "status": status.as_u16(), "body": body })
                }
            };
            *statuses.entry(format!("{mode:?} {}", output["status"])).or_default() += 1;
            outputs.push(output);
        }

        let mut pending: Vec<Value> =
            ctx.node.call("backfillPending", Value::Null).await.as_array().cloned().unwrap_or_default();
        pending.extend(queue.pending_snapshot().into_iter().map(|(days, IdentityAssignment { site_id, anonymous_id, user_id }, attempts)| {
            json!({ "days": days, "siteId": site_id, "anonymousId": anonymous_id, "userId": user_id, "attempts": attempts })
        }));
        pending.sort_by_key(|entry| entry.to_string());
        backfills.push(pending);
        rows.push(identify_rows(&ctx.pg).await);
        runs.push(outputs);
    }
    delete_identify_rows(&ctx.pg).await;
    ctx.delete_keys(&patterns).await;
    ctx.node.call("backfillReset", Value::Null).await;
    ctx.node.stop().await;

    println!("identify: {} steps, statuses {statuses:?}", steps.len());
    println!("identify: {} rows and {} queued backfills after the all-Node run", rows[0].len(), backfills[0].len());
    for row in rows[0].iter().filter(|row| row[0] == "profile") {
        let text = row.to_string();
        let shown: String = text.chars().take(160).collect();
        println!("  {shown}{}", if text.chars().count() > 160 { "…" } else { "" });
    }
    report("identify responses", steps.len() * 2, &compare_outputs("identify", &runs));

    let mut state = Vec::new();
    for (mode, (mode_rows, mode_backfills)) in MODES.iter().zip(rows.iter().zip(&backfills)).skip(1) {
        if mode_rows != &rows[0] {
            state.push(format!("{mode:?} rows {mode_rows:?}\n    all-Node rows {:?}", rows[0]));
        }
        if mode_backfills != &backfills[0] {
            state.push(format!("{mode:?} backfills {mode_backfills:?}\n    all-Node {:?}", backfills[0]));
        }
    }
    report("identify Postgres rows and backfill queue", 4, &state);
}

// ---------------------------------------------------------------------------
// Backfill mutations against the parity ClickHouse

async fn clickhouse_rows(clickhouse: &ClickHouse, site_id: i32) -> Vec<(String, String)> {
    #[derive(serde::Deserialize)]
    struct Row {
        user_id: String,
        identified_user_id: String,
    }
    clickhouse
        .query::<Row>(
            "SELECT user_id, identified_user_id FROM events WHERE site_id = {site:UInt16} ORDER BY user_id, identified_user_id",
            &[("site", site_id.to_string())],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.user_id, row.identified_user_id))
        .collect()
}

async fn wait_for_mutations(clickhouse: &ClickHouse) {
    #[derive(serde::Deserialize)]
    struct Pending {
        pending: String,
    }
    for _ in 0..300 {
        let rows: Vec<Pending> = clickhouse
            .query("SELECT toString(count()) AS pending FROM system.mutations WHERE database = currentDatabase() AND NOT is_done", &[])
            .await
            .unwrap();
        if rows.first().is_some_and(|row| row.pending == "0") {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("mutations did not finish");
}

#[tokio::test]
#[ignore]
async fn backfill_mutations_match_node_on_clickhouse() {
    let Some(mut node) = NodeRpc::start().await else { return };
    node.call("ready", Value::Null).await;
    let clickhouse = ClickHouse::new("http://127.0.0.1:58123", "analytics", "default", "hygo").unwrap();
    let (node_site, rust_site) = (65004, 65005);

    #[derive(serde::Serialize)]
    struct EventRow {
        site_id: i32,
        timestamp: String,
        session_id: String,
        user_id: String,
        identified_user_id: String,
    }
    let now = chrono::Utc::now();
    let mut seeded = Vec::new();
    for site_id in [node_site, rust_site] {
        for (index, age_days) in [0, 1, 29, 45].into_iter().enumerate() {
            for anonymous in ["anon-a", "anon-b", "it's-anon\\c"] {
                seeded.push(EventRow {
                    site_id,
                    timestamp: (now - chrono::Duration::days(age_days)).format("%Y-%m-%d %H:%M:%S").to_string(),
                    session_id: format!("s{index}"),
                    user_id: anonymous.to_string(),
                    identified_user_id: String::new(),
                });
            }
        }
    }
    clickhouse.insert("events", &seeded).await.unwrap();

    let assignments = |site_id: i32| {
        vec![
            (
                IdentityAssignment { site_id, anonymous_id: "anon-a".into(), user_id: "user-a".into() },
                Some(BACKFILL_DAYS),
            ),
            (IdentityAssignment { site_id, anonymous_id: "it's-anon\\c".into(), user_id: "user 'c'".into() }, None),
        ]
    };

    for (assignment, days) in assignments(node_site) {
        node.call(
            "backfillEnqueue",
            json!({ "assignment": { "siteId": assignment.site_id, "anonymousId": assignment.anonymous_id, "userId": assignment.user_id }, "days": days }),
        )
        .await;
    }
    node.call("backfillFlush", Value::Null).await;

    let queue = IdentityBackfillQueue::new(clickhouse.clone());
    for (assignment, days) in assignments(rust_site) {
        queue.enqueue(assignment, days);
    }
    queue.flush().await;
    wait_for_mutations(&clickhouse).await;

    let node_rows = clickhouse_rows(&clickhouse, node_site).await;
    let rust_rows = clickhouse_rows(&clickhouse, rust_site).await;
    println!("backfill rows after Node's flush: {node_rows:?}");

    // The query text ClickHouse logged for each backend's mutations
    #[derive(serde::Deserialize)]
    struct Logged {
        query: String,
    }
    let _ = clickhouse.query::<Value>("SYSTEM FLUSH LOGS", &[]).await;
    let logged: Vec<Logged> = clickhouse
        .query(
            "SELECT DISTINCT query FROM system.query_log WHERE type = 'QueryFinish' AND query LIKE 'ALTER TABLE %identified_user_id%' AND event_time > now() - INTERVAL 10 MINUTE",
            &[],
        )
        .await
        .unwrap();

    let _ = clickhouse
        .query::<Value>("ALTER TABLE events DELETE WHERE site_id IN (65004, 65005) SETTINGS mutations_sync = 1", &[])
        .await;
    node.stop().await;

    let mut mismatches = Vec::new();
    if node_rows != rust_rows {
        mismatches.push(format!("rows differ\n    node {node_rows:?}\n    rust {rust_rows:?}"));
    }
    let expected_updated = node_rows.iter().filter(|(_, identified)| !identified.is_empty()).count();
    if expected_updated != 3 + 4 {
        mismatches.push(format!(
            "expected 7 identified rows (anon-a within 30 days, anon-c all history), got {expected_updated}"
        ));
    }
    // query_log keeps the formatted statement with parameters substituted, so the
    // two backends' mutations must be identical once the site ids are aligned
    let node_texts: std::collections::BTreeSet<String> = logged
        .iter()
        .filter(|entry| entry.query.contains("[65004]"))
        .map(|entry| entry.query.replace("65004", "65005"))
        .collect();
    let rust_texts: std::collections::BTreeSet<String> =
        logged.iter().filter(|entry| entry.query.contains("[65005]")).map(|entry| entry.query.clone()).collect();
    println!("mutations logged: {} from Node, {} from Rust", node_texts.len(), rust_texts.len());
    for text in &rust_texts {
        println!("  {text}");
    }
    if node_texts.len() != 6 || node_texts != rust_texts {
        mismatches.push(format!("mutation texts differ\n    node {node_texts:?}\n    rust {rust_texts:?}"));
    }
    report("backfill mutations on ClickHouse (rows, identified count, statements)", 3, &mismatches);
}
