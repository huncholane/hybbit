#!/usr/bin/env bash
# Rust backend on :3101 for the /api/sites parity harness.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source /home/huncho/code/hygo/repo/hybbit/server-rs/parity/env.sh
export PORT=3101
export PUBLIC_DIR=/home/huncho/code/hygo/repo/hybbit/server/public
export GEOIP_DIR=/home/huncho/code/hygo/repo/hybbit/server
exec "$here/../../target/debug/hygo-backend"
