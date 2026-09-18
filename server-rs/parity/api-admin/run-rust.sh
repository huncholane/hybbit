#!/usr/bin/env bash
# The Rust backend on :3103 against the parity stores, for the api-admin harness.
# Stop it by its own PID (other agents run the same binary; never pkill by name).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export PORT=3103
export PUBLIC_DIR="$here/../../../server/public"
export GEOIP_DIR="$here/../../../server"
cd "$here/../.."
cargo build --quiet
exec ./target/debug/hygo-backend
