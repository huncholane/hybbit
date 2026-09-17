#!/usr/bin/env bash
# Differential tests of server-rs/src/bot against the Node bot detection code.
#
# 1. Clones the user-agent corpora (pinned) into $BOT_CORPUS_DIR.
# 2. Runs the Node dumps from server/ against the parity stores (needs
#    server/node_modules and the GeoLite2 databases next to server/).
# 3. Runs the Rust differential tests, which replay every case and compare.
#
# The anomaly dump writes and deletes Redis keys for site ids 65100 and up; the
# Rust replay does the same. Run the two back to back: Node's state snapshot is
# compared with Rust's, TTLs within 15 seconds.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$here/../../.."
export BOT_CORPUS_DIR="${BOT_CORPUS_DIR:-${TMPDIR:-/tmp}/hygo-bot-corpus}"
export BOT_DIFF_DUMPS="${BOT_DIFF_DUMPS:-$BOT_CORPUS_DIR/dumps}"
mkdir -p "$BOT_CORPUS_DIR" "$BOT_DIFF_DUMPS"

clone() {
  local url="$1" dir="$2" ref="$3"
  if [ ! -d "$BOT_CORPUS_DIR/$dir" ]; then
    git clone --quiet "$url" "$BOT_CORPUS_DIR/$dir"
    git -C "$BOT_CORPUS_DIR/$dir" checkout --quiet "$ref"
  fi
}
clone https://github.com/faisalman/ua-parser-js ua-parser-js 2.0.3
clone https://github.com/omrilotan/isbot isbot eff2b5a27f837832e57a9260ba2b54560562857a
clone https://github.com/monperrus/crawler-user-agents crawler-user-agents 7baee040e86208bfaf24b2815fd8f322318bd2fa

source "$here/../env.sh"
export LOG_LEVEL=warn
cd "$repo/server"
npx tsx "$here/dump_stateless.mts"
npx tsx "$here/dump_baseline.mts"
npx tsx "$here/dump_e2e.mts"
npx tsx "$here/dump_anomaly.mts"

cd "$repo/server-rs"
cargo test --release bot::differential -- --nocapture --test-threads 1
