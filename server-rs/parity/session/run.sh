#!/usr/bin/env bash
# Cookie session parity: the same cases through Node's getSession and Rust's
# get_session against the parity Postgres, then a field-by-field comparison.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export BETTER_AUTH_SECRET="${BETTER_AUTH_SECRET:-parity-local-secret-parity-local-secret}"
work="$(mktemp -d)"
python3 "$here/plan.py" > "$work/plan.json"
(cd "$here/../../../server" && npx tsx "$here/node.mts" "$work/plan.json") | tail -1 > "$work/node.json"
(cd "$here/../.." && PARITY_SESSION_PLAN="$work/plan.json" PARITY_SESSION_OUT="$work/rust.json" \
  cargo test --quiet auth::session::parity -- --ignored --nocapture >/dev/null)
cp "$work/node.json" "${PARITY_KEEP:-/dev/null}" 2>/dev/null || true
python3 - "$work/node.json" "$work/rust.json" <<'PY'
import json, sys
node, rust = (json.load(open(path)) for path in sys.argv[1:3])
failures = 0
for n, r in zip(node, rust, strict=True):
    if n != r:
        failures += 1
        print(f"MISMATCH {n['name']}\n  node: {json.dumps(n)}\n  rust: {json.dumps(r)}")
print(f"{len(node) - failures}/{len(node)} session cases identical")
sys.exit(1 if failures else 0)
PY
