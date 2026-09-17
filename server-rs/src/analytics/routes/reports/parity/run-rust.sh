#!/usr/bin/env bash
# The Rust backend on :3047 (RUST_PORT) against the parity stores, for harness.py.
# Node runs from server-rs/parity/run-node.sh on :3001.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
crate="$(cd "$here/../../../../.." && pwd)"
source "$crate/parity/env.sh"
export PORT=${RUST_PORT:-3047}
export PUBLIC_DIR="$crate/../server/public"
export GEOIP_DIR="$crate/../server"
export LOG_LEVEL=${LOG_LEVEL:-info}
cd "$crate"
exec ./target/debug/hygo-backend
