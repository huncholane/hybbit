#!/usr/bin/env bash
# Feature flag parity: node.mts builds deterministic corpora and records what the
# real Node code answers (regex validation and matching, flag evaluation, body
# validation, parseQuery, the Redis definitions cache, the evaluate route); the
# ignored Rust tests in src/feature_flags/parity.rs replay them and compare.
#
# Needs the parity stores (docker-compose.yml) and a server/ with node_modules
# (HYGO_SERVER_DIR, default ../../../server). Keeps the corpora in
# PARITY_FEATURE_FLAGS_DIR when set, else in a temporary directory.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export LOG_LEVEL=silent
export HYGO_SERVER_DIR="${HYGO_SERVER_DIR:-$(cd "$here/../../../server" && pwd)}"
export PARITY_FEATURE_FLAGS_DIR="${PARITY_FEATURE_FLAGS_DIR:-$(mktemp -d)}"
crate="$(cd "$here/../.." && pwd)"

node_suite() {
  (cd "$HYGO_SERVER_DIR" && npx --no-install tsx "$here/node.mts" "$1" "$PARITY_FEATURE_FLAGS_DIR" 2>&1) | { grep -v "npm notice" || true; }
}
# Summaries, mismatches (set PARITY_SHOW for more than 40) and failures only
rust_test() {
  local filter="$1"
  shift
  (cd "$crate" && cargo test --quiet "feature_flags::parity::$filter" -- --ignored --nocapture --test-threads 1 "$@" 2>&1) |
    grep -E -A2 "identical|comparisons|cases,|MISMATCH|KNOWN|test result|panicked|^error"
}

trap 'node_suite cleanup >/dev/null 2>&1 || true' EXIT

for suite in regex evaluator schemas query; do node_suite "$suite"; done
node_suite cache-seed
rust_test cache_writes_what_node_writes
node_suite cache-node-read
node_suite e2e
rust_test "" --skip cache_writes_what_node_writes
