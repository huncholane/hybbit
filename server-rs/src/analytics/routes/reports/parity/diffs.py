#!/usr/bin/env python3
"""diffs.py RESULTS.json [limit]: the distinct differences a harness run found,
with both outputs."""
import json
import sys

results = json.load(open(sys.argv[1]))
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 30
seen = set()
for d in results["differences"]:
    key = (d["route"], d["node"]["status"], d["rust"]["status"], d["node"]["body"][:30], d["rust"]["body"][:30], bool(d.get("note")))
    if key in seen:
        continue
    seen.add(key)
    if len(seen) > limit:
        break
    r = d["request"] or {}
    print("==", d["route"], r.get("method"), (r.get("path") or "")[:300], r.get("auth"), r.get("contentType"), (r.get("body") or "")[:400])
    print("  node", d["node"]["status"], d["node"]["headers"], d["node"]["body"][:600])
    print("  rust", d["rust"]["status"], d["rust"]["headers"], d["rust"]["body"][:600])
    if d.get("note"):
        print("  rows", json.dumps(d["note"])[:1500])
print("total differences", len(results["differences"]), "distinct", len(seen), "flaky", len(results.get("flaky", [])))
