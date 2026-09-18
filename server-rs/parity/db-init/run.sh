#!/usr/bin/env bash
# Startup database init parity: Node's boot work against one set of throwaway stores,
# Rust's against another, then a normalised diff of both schemas.
#
#   ./run.sh            # production settings (no CLOUD, no LITE_DASHBOARD)
#   ./run.sh full       # CLOUD=true LITE_DASHBOARD=true, so every branch runs
#
# Six checks, in order (the last only with a snapshot to hand):
#   1. fresh    Node-made schema == Rust-made schema, on empty stores
#   2. twice    a second Rust boot changes nothing it made
#   3. adopted  a Rust boot against the Node-made stores changes nothing (production)
#   4. admin    both promote the same (oldest) user to admin
#   5. drift    both heal the same damage the same way (the column-healing and
#               refreshable-view paths a fresh store never reaches)
#   6. live     with PARITY_SNAPSHOT=../../../backups/<timestamp>, the same against a
#               restored copy of the production schema: the case that matters most,
#               because production's databases were made by Node and must not move
#
# Everything lives in databases named dbinit_* on the parity stores from
# parity/docker-compose.yml, which are dropped and recreated on every run, so the
# fixtures other harnesses use are untouched. Nothing here ever points at production.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
source "$here/../env.sh"

mode="${1:-default}"
case "$mode" in
  default) export CLOUD=false LITE_DASHBOARD=false ;;
  full)    export CLOUD=true  LITE_DASHBOARD=true ;;
  *) echo "usage: run.sh [default|full]" >&2; exit 2 ;;
esac

# A git worktree has no server/node_modules, so the Node side runs from the main
# checkout. Its migrations have to be the same bytes or the comparison is meaningless.
server_dir="$repo/server"
if [ ! -d "$server_dir/node_modules" ]; then
  server_dir="$(dirname "$(cd "$repo" && git rev-parse --path-format=absolute --git-common-dir)")/server"
  echo "no server/node_modules here, running Node from $server_dir"
  diff -r "$server_dir/drizzle" "$repo/server/drizzle" >/dev/null \
    || { echo "that checkout's drizzle/ differs from this one's; nothing to compare" >&2; exit 2; }
fi

NODE_PG=dbinit_node NODE_CH=dbinit_node NODE_CHUSER=dbinit_node_q
RUST_PG=dbinit_rust RUST_CH=dbinit_rust RUST_CHUSER=dbinit_rust_q
PG_CONTAINER=hygo-parity-postgres-1
RUST_PORT=3071
work="$(mktemp -d)"
trap 'rm -rf "$work"; pkill -f "[d]binit-rust" >/dev/null 2>&1 || true' EXIT

psql_admin() { docker exec -i "$PG_CONTAINER" psql -U hygo -d postgres -q -c "$1"; }
psql_db()    { docker exec -i "$PG_CONTAINER" psql -U hygo -d "$1" -q -c "$2"; }
ch() { curl -sS -f -u "default:hygo" "$CLICKHOUSE_HOST" --data-binary "$1"; }

reset_stores() { # <pg-db> <ch-db> <ch-query-user>
  psql_admin "DROP DATABASE IF EXISTS $1 WITH (FORCE)"
  psql_admin "CREATE DATABASE $1"
  ch "DROP DATABASE IF EXISTS $2"
  ch "CREATE DATABASE $2"
  ch "DROP USER IF EXISTS $3"
  ch "DROP SETTINGS PROFILE IF EXISTS $3"
}

run_node_init() { # <pg-db> <ch-db> <ch-query-user>
  # Both halves of a Node deployment's boot: the entrypoint's `drizzle-kit migrate`
  # and then index.ts's Promise.all.
  ( cd "$server_dir" \
    && export POSTGRES_DB="$1" CLICKHOUSE_DB="$2" CLICKHOUSE_QUERY_USER="$3" PARITY_SERVER="$server_dir" \
    && npx drizzle-kit migrate --config=drizzle.config.ts >>"$work/node.log" 2>&1 \
    && npx tsx "$here/node_init.mts" >>"$work/node.log" 2>&1 ) \
    || { echo "node init failed:" >&2; tail -30 "$work/node.log" >&2; return 1; }
}

run_rust_init() { # <pg-db> <ch-db> <ch-query-user>
  # The real binary, so what is verified is the startup path and not a test harness
  # reimplementation of it. It exits non-zero if init fails, which is caught below.
  POSTGRES_DB="$1" CLICKHOUSE_DB="$2" CLICKHOUSE_QUERY_USER="$3" PORT="$RUST_PORT" \
    PUBLIC_DIR="$repo/server/public" GEOIP_DIR="$repo/server" CLIENT_DIR="$work/no-client" \
    "$repo/server-rs/target/debug/dbinit-rust" >>"$work/rust.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 120); do
    if curl -sS -f -o /dev/null "http://127.0.0.1:$RUST_PORT/api/health" 2>/dev/null; then
      kill -TERM "$pid"; wait "$pid" 2>/dev/null || true
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null; echo "rust backend exited during init:" >&2; tail -20 "$work/rust.log" >&2; return 1; }
    sleep 0.5
  done
  kill -TERM "$pid" 2>/dev/null || true
  echo "rust backend never became healthy" >&2
  return 1
}

dump() { # <pg-db> <ch-db> <ch-query-user> <out>
  python3 "$here/dump.py" "$1" "$2" "$3" >"$4" 2>/dev/null
}

expect_same() { # <label> <a> <b>
  if diff -u "$2" "$3" >"$work/diff.txt"; then
    echo "PASS  $1"
  else
    echo "FAIL  $1"
    sed -n '1,120p' "$work/diff.txt"
    failures=$((failures + 1))
  fi
}

failures=0
echo "mode=$mode (CLOUD=$CLOUD LITE_DASHBOARD=$LITE_DASHBOARD)"

( cd "$repo/server-rs" && cargo build --quiet )
# A distinct name so the pkill in the EXIT trap cannot match another agent's backend
cp "$repo/server-rs/target/debug/hygo-backend" "$repo/server-rs/target/debug/dbinit-rust"

echo "step 1  fresh stores"
reset_stores "$NODE_PG" "$NODE_CH" "$NODE_CHUSER"
reset_stores "$RUST_PG" "$RUST_CH" "$RUST_CHUSER"
run_node_init "$NODE_PG" "$NODE_CH" "$NODE_CHUSER"
run_rust_init "$RUST_PG" "$RUST_CH" "$RUST_CHUSER"
dump "$NODE_PG" "$NODE_CH" "$NODE_CHUSER" "$work/node-fresh.txt"
dump "$RUST_PG" "$RUST_CH" "$RUST_CHUSER" "$work/rust-fresh.txt"
expect_same "fresh: node schema == rust schema" "$work/node-fresh.txt" "$work/rust-fresh.txt"

echo "step 2  rust twice"
run_rust_init "$RUST_PG" "$RUST_CH" "$RUST_CHUSER"
dump "$RUST_PG" "$RUST_CH" "$RUST_CHUSER" "$work/rust-again.txt"
expect_same "idempotent: second rust boot changes nothing" "$work/rust-fresh.txt" "$work/rust-again.txt"

echo "step 3  rust over a node-initialised store"
run_rust_init "$NODE_PG" "$NODE_CH" "$NODE_CHUSER"
dump "$NODE_PG" "$NODE_CH" "$NODE_CHUSER" "$work/node-after-rust.txt"
expect_same "adopted: rust changes nothing node made" "$work/node-fresh.txt" "$work/node-after-rust.txt"

echo "step 4  admin promotion"
seed_users() {
  psql_db "$1" "INSERT INTO \"user\" (\"id\",\"name\",\"email\",\"emailVerified\",\"createdAt\",\"updatedAt\",\"role\")
     VALUES ('second','Second','second@example.test',false,'2026-02-02 00:00:00','2026-02-02 00:00:00','user'),
            ('first','First','first@example.test',false,'2026-01-01 00:00:00','2026-01-01 00:00:00','user')
     ON CONFLICT (\"id\") DO NOTHING"
}
seed_users "$NODE_PG"
seed_users "$RUST_PG"
run_node_init "$NODE_PG" "$NODE_CH" "$NODE_CHUSER"
run_rust_init "$RUST_PG" "$RUST_CH" "$RUST_CHUSER"
dump "$NODE_PG" "$NODE_CH" "$NODE_CHUSER" "$work/node-users.txt"
dump "$RUST_PG" "$RUST_CH" "$RUST_CHUSER" "$work/rust-users.txt"
expect_same "admin: node and rust agree on roles and schema" "$work/node-users.txt" "$work/rust-users.txt"
grep -A3 '===== users =====' "$work/rust-users.txt"

echo "step 5  drift healing"
# The same damage to both sides. A fresh store never reaches the healing branches
# (every column is already in the CREATE), so this is the only way to see them run:
# the ALTERs that re-add columns, the migration that re-applies because its
# bookkeeping row is gone, and in `full` mode the refreshable view that is replaced
# because its stored definition no longer matches.
drift() { # <pg-db> <ch-db>
  psql_db "$1" "ALTER TABLE sites DROP COLUMN IF EXISTS bounce_threshold"
  psql_db "$1" "DELETE FROM drizzle.__drizzle_migrations WHERE created_at = 1789085773946"
  ch "ALTER TABLE $2.events DROP COLUMN tag"
  ch "ALTER TABLE $2.bot_events DROP COLUMN asn_provider"
  ch "ALTER TABLE $2.bot_observations DROP COLUMN anomaly_score"
  ch "ALTER TABLE $2.session_replay_events DROP COLUMN identified_user_id"
  ch "ALTER TABLE $2.session_replay_metadata DROP COLUMN identified_user_id"
  if [ "$LITE_DASHBOARD" = "true" ]; then
    ch "DROP VIEW IF EXISTS $2.session_hourly_mv SYNC"
    ch "CREATE MATERIALIZED VIEW $2.session_hourly_mv REFRESH EVERY 5 MINUTE TO $2.session_hourly_mv_target
        AS SELECT site_id, toStartOfHour(timestamp) AS session_hour, count() AS sessions, count() AS pageviews,
                  uniqState(user_id) AS users, toUInt64(0) AS total_session_duration_seconds,
                  toUInt64(0) AS bounced_sessions
           FROM $2.events GROUP BY site_id, session_hour"
  fi
}
drift "$NODE_PG" "$NODE_CH"
drift "$RUST_PG" "$RUST_CH"
run_node_init "$NODE_PG" "$NODE_CH" "$NODE_CHUSER"
run_rust_init "$RUST_PG" "$RUST_CH" "$RUST_CHUSER"
dump "$NODE_PG" "$NODE_CH" "$NODE_CHUSER" "$work/node-healed.txt"
dump "$RUST_PG" "$RUST_CH" "$RUST_CHUSER" "$work/rust-healed.txt"
expect_same "drift: node and rust heal identically" "$work/node-healed.txt" "$work/rust-healed.txt"
# Healing is not a restore: a re-added column lands at the end of the table, so this
# must differ from the fresh snapshot or the drift never happened.
if diff -q "$work/rust-fresh.txt" "$work/rust-healed.txt" >/dev/null; then
  echo "FAIL  drift: the damage did not take, nothing was healed"
  failures=$((failures + 1))
fi

if [ "${PARITY_SNAPSHOT:-}" != "" ]; then
  echo "step 6  production snapshot"
  snapshot="$(cd "$PARITY_SNAPSHOT" && pwd)"
  PROD_PG=dbinit_prod PROD_CH=dbinit_prod PROD_CHUSER=dbinit_prod_q
  psql_admin "DROP DATABASE IF EXISTS $PROD_PG WITH (FORCE)"
  psql_admin "CREATE DATABASE $PROD_PG"
  docker exec -i "$PG_CONTAINER" pg_restore -U hygo -d "$PROD_PG" --no-owner --no-privileges \
    <"$snapshot/analytics.dump" >>"$work/snapshot.log" 2>&1 || true   # role grants that do not exist here
  ch "DROP DATABASE IF EXISTS $PROD_CH"
  ch "CREATE DATABASE $PROD_CH"
  ch "DROP USER IF EXISTS $PROD_CHUSER"
  ch "DROP SETTINGS PROFILE IF EXISTS $PROD_CHUSER"
  # Schema only: what a boot may change is the schema, and the data would not alter it.
  # The snapshot names the production database, and it holds tables this codebase never
  # creates (monitor_events), which is deliberate: init must leave them alone too.
  for sql in "$snapshot"/clickhouse/*.sql; do
    ch "$(sed "s/\banalytics\./$PROD_CH./g" "$sql")"
  done
  dump "$PROD_PG" "$PROD_CH" "$PROD_CHUSER" "$work/prod-restored.txt"
  # One Node boot first, because that is what production is: a store Node made and
  # keeps re-asserting. The snapshot carries no ClickHouse users, so this is also what
  # brings the query user into existence for Rust to find.
  run_node_init "$PROD_PG" "$PROD_CH" "$PROD_CHUSER"
  dump "$PROD_PG" "$PROD_CH" "$PROD_CHUSER" "$work/prod-node.txt"
  run_rust_init "$PROD_PG" "$PROD_CH" "$PROD_CHUSER"
  dump "$PROD_PG" "$PROD_CH" "$PROD_CHUSER" "$work/prod-after.txt"
  expect_same "live: rust changes nothing in a Node-initialised production schema" \
    "$work/prod-node.txt" "$work/prod-after.txt"
  echo "      (what Node's own boot changed in the restored snapshot:)"
  diff "$work/prod-restored.txt" "$work/prod-node.txt" | sed -n '1,40p' | sed 's/^/      /' || true
fi

if [ "${PARITY_KEEP:-}" != "" ]; then
  mkdir -p "$PARITY_KEEP" && cp "$work"/*.txt "$work"/*.log "$PARITY_KEEP/" && echo "snapshots in $PARITY_KEEP"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "db-init parity: all checks identical"
else
  echo "db-init parity: $failures check(s) differ"
fi
exit "$failures"
