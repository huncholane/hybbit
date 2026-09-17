//! Differential tests against the Node server's own output.
//!
//! `testdata/node_golden.json` is a committed slice of a Node dump (the shortest
//! example of every browser, OS, vendor, engine, CPU and device-type value seen,
//! plus truncation and non-ASCII cases), so plain `cargo test` checks parity.
//! The full corpus run needs Node and a ua-parser-js 2.0.3 checkout (for its
//! fixtures), from the repository root:
//!
//! ```text
//! git clone --depth 1 --branch 2.0.3 https://github.com/faisalman/ua-parser-js.git /tmp/uap
//! node server-rs/src/ua/tools/build_corpus.mjs /tmp/uap server/src /tmp/corpus.json
//! (cd server && npx tsx ../server-rs/src/ua/tools/dump_node.mts /tmp/corpus.json /tmp/node-dump.json)
//! cd server-rs && UA_PARITY_DUMP=/tmp/node-dump.json cargo test --release ua::parity -- --ignored --nocapture
//! node src/ua/tools/select_golden.cjs /tmp/node-dump.json src/ua/testdata/node_golden.json  # refresh the golden file
//! ```

use std::time::Instant;

use serde_json::Value;

use super::{
    TABLES, UA_CACHE_MAX, get_device_type, parse, parse_user_agent,
    parser::{Haystack, truncate},
    warm_up,
};

/// One UA and what Node reported for it.
type Case = (String, Outcome);
/// Screen sizes (width, height) getDeviceType was asked about.
type Screens = Vec<(f64, f64)>;

/// Everything Node reports for one UA, flattened: result.ua, browser (name,
/// version, major, type), cpu.architecture, device (type, model, vendor), engine
/// (name, version), os (name, version), then getDeviceType per screen.
#[derive(Debug, PartialEq)]
struct Outcome {
    ua: String,
    fields: [Option<String>; 12],
    device_types: Vec<String>,
}

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

fn screens(dump: &Value) -> Screens {
    dump["screens"].as_array().unwrap().iter().map(|pair| (pair[0].as_f64().unwrap(), pair[1].as_f64().unwrap())).collect()
}

/// A case of dump_node.mts output.
fn from_dump(case: &Value) -> Case {
    let input = case["input"].as_str().unwrap().to_string();
    let outcome = Outcome {
        ua: case["ua"].as_str().unwrap().to_string(),
        fields: [
            text(&case["browser"]["name"]),
            text(&case["browser"]["version"]),
            text(&case["browser"]["major"]),
            text(&case["browser"]["type"]),
            text(&case["cpu"]["architecture"]),
            text(&case["device"]["type"]),
            text(&case["device"]["model"]),
            text(&case["device"]["vendor"]),
            text(&case["engine"]["name"]),
            text(&case["engine"]["version"]),
            text(&case["os"]["name"]),
            text(&case["os"]["version"]),
        ],
        device_types: case["deviceTypes"].as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()).collect(),
    };
    (input, outcome)
}

/// A row of the golden file: `[input, ua or null when unchanged, 12 fields, "types,..."]`.
fn from_golden(row: &Value) -> Case {
    let row = row.as_array().unwrap();
    let input = row[0].as_str().unwrap().to_string();
    let outcome = Outcome {
        ua: row[1].as_str().unwrap_or(&input).to_string(),
        fields: std::array::from_fn(|index| text(&row[index + 2])),
        device_types: row[14].as_str().unwrap().split(',').map(str::to_string).collect(),
    };
    (input, outcome)
}

fn rust_outcome(input: &str, screens: &[(f64, f64)]) -> Outcome {
    let parsed = parse(input);
    let device = parsed.device().clone();
    let engine = parsed.engine().clone();
    let cpu = parsed.cpu().clone();
    Outcome {
        ua: parsed.ua.clone(),
        fields: [
            parsed.browser.name.clone(),
            parsed.browser.version.clone(),
            parsed.browser.major.clone(),
            parsed.browser.r#type.clone(),
            cpu.architecture,
            device.r#type,
            device.model,
            device.vendor,
            engine.name,
            engine.version,
            parsed.os.name.clone(),
            parsed.os.version.clone(),
        ],
        device_types: screens.iter().map(|(width, height)| get_device_type(*width, *height, &parsed).to_string()).collect(),
    }
}

/// Compares every case, printing the first mismatches; returns how many differ.
fn compare(cases: &[Case], screens: &[(f64, f64)]) -> usize {
    let mut mismatches = 0;
    for (input, expected) in cases {
        let actual = rust_outcome(input, screens);
        if &actual != expected {
            mismatches += 1;
            if mismatches <= 40 {
                println!("MISMATCH ua={input:?}\n  node: {expected:?}\n  rust: {actual:?}");
            }
        }
    }
    println!("parity: {}/{} cases agree", cases.len() - mismatches, cases.len());
    mismatches
}

#[test]
fn node_golden_cases() {
    let dump: Value = serde_json::from_str(include_str!("testdata/node_golden.json")).unwrap();
    let screens = screens(&dump);
    let cases: Vec<Case> = dump["rows"].as_array().unwrap().iter().map(from_golden).collect();
    assert!(cases.len() > 900);
    assert_eq!(compare(&cases, &screens), 0);
}

fn load_dump() -> (Screens, Vec<Case>) {
    let path = std::env::var("UA_PARITY_DUMP").expect("UA_PARITY_DUMP must point at a dump_node.mts output");
    let dump: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("reading dump")).expect("parsing dump");
    let cases = dump["cases"].as_array().unwrap().iter().map(from_dump).collect();
    (screens(&dump), cases)
}

#[test]
#[ignore = "needs UA_PARITY_DUMP pointing at a Node dump"]
fn node_full_corpus() {
    let (screens, cases) = load_dump();

    // the fancy-regex pre-check must never rule out a real match
    let fancy: Vec<_> = [&TABLES.browser, &TABLES.cpu, &TABLES.device, &TABLES.engine, &TABLES.os]
        .into_iter()
        .flat_map(|rules| rules.iter().flat_map(|rule| rule.regexes.iter()))
        .filter(|regex| regex.is_fancy())
        .collect();
    for (input, _) in &cases {
        let (truncated, dangling) = truncate(input);
        let haystack = Haystack::new(truncated, dangling);
        for regex in &fancy {
            assert!(!regex.approximation_misses(&haystack), "approximation of /{}/ misses {input:?}", regex.source());
        }
    }

    assert_eq!(compare(&cases, &screens), 0);
}

/// Per-UA cost over the dump's corpus: uncached browser+OS (what a cache miss on
/// the tracking path pays), every field, a realistic `Mozilla/5.0 (` subset, and
/// a cache hit.
#[test]
#[ignore = "benchmark; needs UA_PARITY_DUMP"]
fn bench_corpus() {
    let (_, cases) = load_dump();
    let inputs: Vec<&str> = cases.iter().map(|(input, _)| input.as_str()).collect();
    warm_up();
    let rounds = 3;
    let per_ua = |list: &[&str], work: &dyn Fn(&str)| {
        let started = Instant::now();
        for _ in 0..rounds {
            for input in list {
                work(input);
            }
        }
        started.elapsed().as_secs_f64() * 1e6 / (rounds * list.len()) as f64
    };

    let eager = per_ua(&inputs, &|input| {
        std::hint::black_box(parse(input));
    });
    let full = per_ua(&inputs, &|input| {
        let parsed = parse(input);
        std::hint::black_box((parsed.device(), parsed.engine(), parsed.cpu()));
    });
    let modern: Vec<&str> = inputs.iter().copied().filter(|ua| ua.starts_with("Mozilla/5.0 (") && ua.len() < 300 && ua.is_ascii()).collect();
    let mozilla = per_ua(&modern, &|input| {
        std::hint::black_box(parse(input));
    });
    let hot: Vec<&str> = inputs.iter().copied().take(UA_CACHE_MAX).collect();
    for input in &hot {
        parse_user_agent(input);
    }
    let hit = per_ua(&hot, &|input| {
        std::hint::black_box(parse_user_agent(input));
    });

    println!(
        "corpus {} UAs: browser+os {eager:.2} us/UA, all fields {full:.2} us/UA, Mozilla/5.0 subset ({}) {mozilla:.2} us/UA, cache hit {hit:.2} us/UA",
        inputs.len(),
        modern.len()
    );
}
