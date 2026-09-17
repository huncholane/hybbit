#!/usr/bin/env bash
# /api/auth differential suite. Starts the real Node backend (unmodified, TZ=UTC, on
# NODE_PORT) and the Rust auth router behind the HTTP edge layers (the ignored
# `parity_server` test, on RUST_PORT), both against the parity Postgres, then drives
# every scenario once per backend with fresh `parity-auth-` fixtures that are deleted
# after each run, and compares normalised responses and rows step by step.
#
# Usage: run.sh [scenario-name-substring ...] [--verbose] [--dump]
# HYGO_SERVER_DIR: a server/ directory with node_modules (default: this checkout's).
# Exit status is non-zero when any step differs. The known differences are listed in
# AUTH_COMPAT.md ("Rust port status").
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export NODE_PORT="${NODE_PORT:-3021}" RUST_PORT="${RUST_PORT:-3057}"
export HYGO_SERVER_DIR="${HYGO_SERVER_DIR:-$(cd "$here/../../../server" && pwd)}"
export PUBLIC_DIR="$HYGO_SERVER_DIR/public" GEOIP_DIR="$HYGO_SERVER_DIR"
logs="$(mktemp -d)"
echo "logs in $logs"

stop() {
  for pid in "${node_pid:-}" "${rust_pid:-}"; do
    [[ -n "$pid" ]] && kill -- "-$pid" 2>/dev/null || true
  done
}
trap stop EXIT

(cd "$HYGO_SERVER_DIR" && NODE_PARITY_PORT="$NODE_PORT" exec setsid npx tsx "$here/node-on-port.mts") >"$logs/node.log" 2>&1 &
node_pid=$!
(cd "$here/../.." && cargo test --release --no-run --quiet && PORT="$RUST_PORT" exec setsid cargo test --release parity_server -- --ignored --nocapture) >"$logs/rust.log" 2>&1 &
rust_pid=$!

for port in "$NODE_PORT" "$RUST_PORT"; do
  for attempt in $(seq 1 600); do
    if curl -fsS "http://127.0.0.1:$port/api/health" >/dev/null 2>&1; then
      break
    fi
    if [[ "$attempt" == 600 ]]; then
      echo "backend on :$port did not start; see $logs" >&2
      exit 1
    fi
    sleep 1
  done
done

python3 "$here/suite.py" "$@"
