#!/usr/bin/env bash
# The whole /api/sites parity suite: fixtures, the read harness group by group,
# then the write harness, into $OUT (default: this session's scratchpad).
#
# Node must be listening on :3001 (parity/run-node.sh) and the Rust build on
# :3101 (./run-rust.sh).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${OUT:-/tmp/claude-1000/-home-huncho-code-hygo-repo-hybbit/c715b88b-ff27-4193-85dd-24c1a017449e/scratchpad/api-sites}"
mkdir -p "$out"

python3 "$here/fixtures.py" setup

for group in routing access identifiers exclusions embed headers credentials check-install rate-limit reachable; do
  echo "== reads: $group"
  python3 "$here/harness.py" --groups "$group" --out "$out/r_$group.json" | tail -1
done

for group in config private-link move delete imports; do
  echo "== writes: $group"
  python3 "$here/writes.py" --groups "$group" --out "$out/w_$group.json" | tail -1
done

python3 "$here/summarise.py" "$out"/r_*.json "$out"/w_*.json
