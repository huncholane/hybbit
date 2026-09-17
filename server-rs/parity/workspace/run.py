#!/usr/bin/env python3
"""Workspace differential run: every case against Node and Rust. Writes start from
freshly inserted fixtures on each side and compare the resulting rows; rate-limited
routes reset their limiter keys before each request so both sides see the same count.

Setup: PARITY_WORKSPACE_OUT=<dir> fixtures.py setup > <dir>/creds.json
Usage: PARITY_WORKSPACE_OUT=<dir> run.py [route-substring ...]
Writes <dir>/results.jsonl (mismatches only) and prints per-route counts.
"""
import collections, json, os, re, sys, time

import cases as C
import hw

PLACEHOLDER = re.compile(r"\{(seg|ann|dash)[A-Za-z0-9]+\}")


def one(target, case, ids):
    if case["limited"]:
        hw.reset_limits()
    path = PLACEHOLDER.sub(lambda m: str(ids[m.group(0)[1:-1]]), case["path"])
    return hw.send(target, case["method"], path, case["headers"], case["body"])


def main():
    filters = sys.argv[1:]
    selected = [c for c in C.all_cases() if not filters or any(f in c["route"] for f in filters)]
    ordered = [c for c in selected if not c["write"]] + [c for c in selected if c["write"]]
    counts, same = collections.Counter(), collections.Counter()
    started = time.time()
    with open(os.path.join(hw.OUT, "results.jsonl"), "w") as out:
        ids = hw.reset_fixtures()
        for index, case in enumerate(ordered):
            if case["write"]:
                ids = hw.reset_fixtures()
                node = one(hw.NODE, case, ids)
                node_rows = hw.snapshot(ids)
                node_ids = ids
                ids = hw.reset_fixtures()
                rust = one(hw.RUST, case, ids)
                rust_rows = hw.snapshot(ids)
            else:
                node = one(hw.NODE, case, ids)
                rust = one(hw.RUST, case, ids)
                node_rows = rust_rows = None
                node_ids = ids
            n, r = hw.comparable(node, node_ids), hw.comparable(rust, ids)
            equal = n == r and node_rows == rust_rows
            counts[case["route"]] += 1
            same[case["route"]] += equal
            if not equal:
                out.write(json.dumps({
                    "case": {k: case[k] for k in ("route", "method", "path", "who")},
                    "body": case["body"].decode("utf-8", "replace")[:300] if case["body"] else None,
                    "node": n, "rust": r, "rows_equal": node_rows == rust_rows,
                    "node_rows": node_rows if node_rows != rust_rows else None,
                    "rust_rows": rust_rows if node_rows != rust_rows else None,
                }, ensure_ascii=False) + "\n")
                out.flush()
            if index % 250 == 0:
                print(f"{index}/{len(ordered)} {time.time() - started:.0f}s mismatches={sum(counts.values()) - sum(same.values())}", flush=True)
    with hw.PG.cursor() as cur:
        hw.clear_rows(cur)
    hw.reset_limits()
    print("route\tpairs\tidentical")
    for route in sorted(counts):
        print(f"{route}\t{counts[route]}\t{same[route]}")
    print("TOTAL", sum(counts.values()), sum(same.values()), flush=True)


main()
