#!/usr/bin/env bash
# Load a production snapshot (made on the rybbit box by /opt/hygo/backup-pre-upgrade.sh
# and copied into ./backups) into the local parity stores. Safe to re-run: every
# database and table it loads is dropped first.
set -euo pipefail

# Resolve the snapshot path against the caller's directory before moving
SNAPSHOT=${1:?usage: restore-snapshot.sh <snapshot dir, e.g. backups/20260917-065644>}
SNAPSHOT=$(cd "$SNAPSHOT" && pwd)
cd "$(dirname "$0")"
DC=(docker compose -f docker-compose.yml)

PSQL() { "${DC[@]}" exec -T postgres psql -U hygo -v ON_ERROR_STOP=1 "$@"; }
CH() { "${DC[@]}" exec -T clickhouse clickhouse-client --password hygo "$@"; }

echo "=== Postgres: analytics from $SNAPSHOT ==="
PSQL -d postgres -qc "DROP DATABASE IF EXISTS analytics WITH (FORCE)" -c "CREATE DATABASE analytics"
# pg_restore exits non-zero on harmless warnings (roles and grants from production
# that don't exist here), so report them instead of aborting
if ! "${DC[@]}" exec -T postgres pg_restore -U hygo -d analytics --no-owner --no-privileges \
  <"$SNAPSHOT/analytics.dump" 2>/tmp/hygo-parity-pg-restore.log; then
  echo "  pg_restore reported $(grep -c 'error:' /tmp/hygo-parity-pg-restore.log || true) warnings (see /tmp/hygo-parity-pg-restore.log)"
fi

echo "=== ClickHouse: analytics ==="
for sql in "$SNAPSHOT"/clickhouse/*.sql; do
  table=$(basename "$sql" .sql)
  CH -q "DROP TABLE IF EXISTS analytics.$table"
  CH --multiquery <"$sql"
  native="$SNAPSHOT/clickhouse/$table.native"
  if [ -s "$native" ]; then
    CH -q "INSERT INTO analytics.$table FORMAT Native" <"$native"
  fi
done

echo "=== Row counts ==="
PSQL -d analytics -Atc "SELECT 'postgres users=' || (SELECT count(*) FROM \"user\") || ' sites=' || (SELECT count(*) FROM sites) || ' organizations=' || (SELECT count(*) FROM organization) || ' sessions=' || (SELECT count(*) FROM session)"
CH -q "SELECT name, total_rows FROM system.tables WHERE database = 'analytics' ORDER BY name FORMAT TSV"
