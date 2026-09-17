#!/usr/bin/env bash
# Bearer credential parity: the same cases through Node's checkApiKey and Rust's
# check_api_key against the parity Postgres, then a field-by-field comparison.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/../env.sh"
export BETTER_AUTH_SECRET="${BETTER_AUTH_SECRET:-parity-local-secret-parity-local-secret}"
work="$(mktemp -d)"
python3 "$here/setup.py" "$here/cases.json" > "$work/plan.json"
(cd "$here/../../../server" && npx tsx "$here/node.mts" "$work/plan.json") | tail -1 > "$work/node.json"
(cd "$here/../.." && PARITY_AUTH_PLAN="$work/plan.json" PARITY_AUTH_OUT="$work/rust.json" \
  cargo test --quiet auth::parity -- --ignored --nocapture >/dev/null)
python3 - "$work/node.json" "$work/rust.json" <<'PY'
import json, sys
node, rust = (json.load(open(path)) for path in sys.argv[1:3])
failures = 0
for n, r in zip(node, rust, strict=True):
    if n != r:
        failures += 1
        print(f"MISMATCH {n['name']}\n  node: {json.dumps(n)}\n  rust: {json.dumps(r)}")
print(f"{len(node) - failures}/{len(node)} bearer cases identical")
sys.exit(1 if failures else 0)
PY
