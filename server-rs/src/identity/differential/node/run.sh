#!/usr/bin/env bash
# Runs the identity differential tests: Node's answers for the stateless
# functions are dumped first, then the Rust tests compare against them and
# alternate calls with a live Node process (rpc.mts) against the parity stores.
#
# Needs the parity stores up (server-rs/parity/docker-compose.yml) and a server
# checkout with node_modules and the GeoLite2 databases:
#   HYGO_SERVER_DIR=/path/to/hybbit/server src/identity/differential/node/run.sh
# Optional: USER_AGENTS_DATASET=<path to user-agents/dist/index.js> adds real-world
# user agents to the corpus.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_RS="$(cd "$HERE/../../../.." && pwd)"
source "$SERVER_RS/parity/env.sh"
export LOG_LEVEL="${LOG_LEVEL:-warn}"
export HYGO_SERVER_DIR="${HYGO_SERVER_DIR:-$SERVER_RS/../server}"
export IDENTITY_GEOIP_DIR="${IDENTITY_GEOIP_DIR:-$HYGO_SERVER_DIR}"
export IDENTITY_DIFF_DIR="${IDENTITY_DIFF_DIR:-$(mktemp -d)}"
mkdir -p "$IDENTITY_DIFF_DIR"
PSQL=(psql "postgres://hygo:hygo@127.0.0.1:55432/analytics" -v ON_ERROR_STOP=1 -q)

# Test sites outside the production id range: 65001 salts user ids, 65002 does not
"${PSQL[@]}" -c "INSERT INTO sites (id, site_id, name, domain, \"saltUserIds\") VALUES
  ('rs-identity-salted', 65001, 'rs identity salted', 'salted.identity.invalid', true),
  ('rs-identity-plain', 65002, 'rs identity plain', 'plain.identity.invalid', false)
  ON CONFLICT DO NOTHING"
cleanup() {
  "${PSQL[@]}" -c "DELETE FROM user_profiles WHERE site_id IN (65001, 65002)" \
    -c "DELETE FROM user_aliases WHERE site_id IN (65001, 65002)" \
    -c "DELETE FROM sites WHERE site_id IN (65001, 65002)"
}
trap cleanup EXIT

echo "Dumping Node answers into $IDENTITY_DIFF_DIR"
(cd "$HYGO_SERVER_DIR" && npx tsx "$HERE/dump_pure.mts")

export NODE_IDENTITY_RPC="cd '$HYGO_SERVER_DIR' && exec npx tsx '$HERE/rpc.mts'"
cd "$SERVER_RS"
cargo test identity::differential -- --ignored --nocapture --test-threads=1
