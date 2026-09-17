#!/usr/bin/env bash
# Rust backend on :3063 for the people-routes parity harness.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source /home/huncho/code/hygo/repo/hybbit/server-rs/parity/env.sh
export PORT=3063
export PUBLIC_DIR=/home/huncho/code/hygo/repo/hybbit/server/public
export GEOIP_DIR=/home/huncho/code/hygo/repo/hybbit/server
exec "$here/../../target/debug/hygo-backend"
