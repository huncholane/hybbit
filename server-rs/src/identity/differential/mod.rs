//! Differential tests against the Node implementation. Ignored by default: they
//! need the parity stores (server-rs/parity) and Node's code, and are run with
//!
//! ```text
//! HYGO_SERVER_DIR=/path/to/server/with/node_modules src/identity/differential/node/run.sh
//! ```
//!
//! which creates the two test Sites, dumps Node's answers (`node/dump_pure.mts`)
//! into IDENTITY_DIFF_DIR, points NODE_IDENTITY_RPC at `node/rpc.mts`, runs
//! `cargo test identity::differential -- --ignored`, and removes its rows again.
//!
//! - `pure`: stateless functions against answers Node computed over generated
//!   corpora (user agents, IP buckets, net.isIP and mmdb-lib parsing, full user
//!   ids with real ASN lookups, client ids, session keys).
//! - `interleaved`: scripted sequences run three times against the same parity
//!   Redis and Postgres (all Node, all Rust, and alternating between the two),
//!   comparing every answer and the stored state. `NODE_IDENTITY_RPC` starts a
//!   Node process answering identity calls one JSON line at a time.
//!
//! Both BETTER_AUTH_SECRET values must be `SECRET` (server-rs/parity/env.sh).

use std::{path::PathBuf, process::Stdio};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout},
};

mod interleaved;
mod pure;

pub(crate) const SECRET: &str = "parity-local-secret-not-for-production";
pub(crate) const PARITY_PG: &str = "postgres://hygo:hygo@127.0.0.1:55432/analytics";

fn diff_dir() -> Option<PathBuf> {
    std::env::var("IDENTITY_DIFF_DIR").ok().map(PathBuf::from)
}

fn server_dir() -> PathBuf {
    std::env::var("IDENTITY_GEOIP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../server"))
}

/// Prints a summary and the first mismatches, then fails if any.
fn report(name: &str, total: usize, mismatches: &[String]) {
    println!("{name}: {} / {total} agree", total - mismatches.len());
    for mismatch in mismatches.iter().take(15) {
        println!("  MISMATCH {mismatch}");
    }
    assert!(mismatches.is_empty(), "{name}: {} mismatches", mismatches.len());
}

/// A Node process running the identity RPC script.
struct NodeRpc {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

impl NodeRpc {
    async fn start() -> Option<Self> {
        let command = std::env::var("NODE_IDENTITY_RPC").ok()?;
        let mut child = tokio::process::Command::new("bash")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("starting the Node RPC process");
        let stdin = child.stdin.take().expect("stdin");
        let lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
        Some(Self { child, stdin, lines, next_id: 0 })
    }

    async fn call(&mut self, op: &str, payload: Value) -> Value {
        self.next_id += 1;
        let mut message = match payload {
            Value::Object(object) => object,
            Value::Null => serde_json::Map::new(),
            other => panic!("payload must be an object, got {other}"),
        };
        message.insert("op".into(), json!(op));
        message.insert("id".into(), json!(self.next_id));
        let line = format!("{}\n", Value::Object(message));
        self.stdin.write_all(line.as_bytes()).await.expect("writing to Node");
        self.stdin.flush().await.expect("flushing to Node");

        loop {
            let line = tokio::time::timeout(std::time::Duration::from_secs(60), self.lines.next_line())
                .await
                .expect("Node answered within a minute")
                .expect("reading from Node")
                .expect("Node exited");
            let Some(rest) = line.strip_prefix("RPC ") else { continue };
            let response: Value = serde_json::from_str(rest).expect("RPC line is JSON");
            if response["id"] != json!(self.next_id) {
                continue;
            }
            if let Some(error) = response.get("error") {
                panic!("Node {op} failed: {}", error.as_str().unwrap_or_default());
            }
            return response["result"].clone();
        }
    }

    async fn stop(mut self) {
        let _ = self.call("exit", Value::Null).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.child.wait()).await;
    }
}

/// mulberry32, so scenarios are reproducible without a seeded RNG dependency.
struct Rng(u32);

impl Rng {
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x6d2b_79f5);
        let mut t = self.0;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() * n as f64) as usize
    }

    fn chance(&mut self, p: f64) -> bool {
        self.next() < p
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}
