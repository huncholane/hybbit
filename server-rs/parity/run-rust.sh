#!/usr/bin/env bash
# Rust backend on :3011 against the parity stores. Stop it with: pkill -x hygo-backend
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/env.sh"
export PORT=3011
export PUBLIC_DIR="$here/../../server/public"
export GEOIP_DIR="$here/../../server"
cd "$here/.."
cargo build --quiet
exec ./target/debug/hygo-backend
