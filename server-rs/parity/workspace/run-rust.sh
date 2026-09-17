#!/usr/bin/env bash
# Rust backend for the workspace parity harness (default :3057) against the parity
# stores. Extra environment (OPENROUTER_API_KEY, OPENROUTER_API_URL) passes through.
# The binary runs under its own name so `pkill -x hygo-backend` elsewhere leaves it be.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export PORT="${PORT:-3057}"
export PUBLIC_DIR="$here/../../../server/public"
export GEOIP_DIR="$here/../../../server"
export LOG_LEVEL="${LOG_LEVEL:-info}"
out="${PARITY_WORKSPACE_OUT:-/tmp/parity-workspace}"
mkdir -p "$out"
cp "$here/../../target/debug/hygo-backend" "$out/hygo-ws-backend-$PORT"
exec "$out/hygo-ws-backend-$PORT"
