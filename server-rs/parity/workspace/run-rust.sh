#!/usr/bin/env bash
# Rust backend for the workspace parity harness (default :3057) against the parity
# stores. Extra environment (OPENROUTER_API_KEY, OPENROUTER_API_URL) passes through.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export PORT="${PORT:-3057}"
export PUBLIC_DIR="$here/../../../server/public"
export GEOIP_DIR="$here/../../../server"
export LOG_LEVEL="${LOG_LEVEL:-info}"
exec "$here/../../target/debug/hygo-backend"
