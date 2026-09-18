#!/usr/bin/env bash
# The Rust backend on :3102 against the parity stores, for the api-orgs harness.
# Stop it with the PID this prints; never pkill by name (other agents run the same
# binary).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export PORT=3102
export PUBLIC_DIR="$here/../../../server/public"
export GEOIP_DIR="$here/../../../server"
cd "$here/../.."
cargo build --quiet
exec ./target/debug/hygo-backend
