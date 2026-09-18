#!/usr/bin/env python3
"""api-orgs differential run: every case against Node (:3001) and Rust (:3102),
comparing status, the headers that matter, the body bytes and, for writes, the
Postgres rows each side left behind.

Setup: PARITY_ORGS_OUT=<dir> fixtures.py setup > <dir>/creds.json
Usage: PARITY_ORGS_OUT=<dir> run.py [route-substring ...]
Writes <dir>/results.jsonl (mismatches only) and prints per-route counts.
"""
import collections
import json
import os
import sys
import time

import cases as C
import fixtures
import hw

CUR = hw.PG.cursor()


def reset(prep):
    fixtures.build(CUR)
    if prep:
        reference, target = fixtures.PREPS[prep]
        fixtures.fill_keys(CUR, reference, target)


def one(target, case):
    return hw.send(target, case["method"], case["path"], case["headers"], case["body"])


def main():
    filters = sys.argv[1:]
    selected = [c for c in C.all_cases() if not filters or any(f in c["route"] for f in filters)]
    # Reads first: they need no fixture reset between cases
    ordered = [c for c in selected if not c["write"]] + [c for c in selected if c["write"]]
    counts, same = collections.Counter(), collections.Counter()
    started = time.time()
    reset(None)
    with open(os.path.join(hw.OUT, "results.jsonl"), "w") as out:
        for index, case in enumerate(ordered):
            if case["write"]:
                reset(case["prep"])
                node = one(hw.NODE, case)
                node_rows = hw.snapshot()
                reset(case["prep"])
                rust = one(hw.RUST, case)
                rust_rows = hw.snapshot()
            else:
                node = one(hw.NODE, case)
                rust = one(hw.RUST, case)
                node_rows = rust_rows = None
            # Reads are compared byte for byte; only writes need the masking of the
            # ids, keys and timestamps each side generates afresh
            mask = case["write"]
            n, r = hw.comparable(node, mask), hw.comparable(rust, mask)
            equal = n == r and node_rows == rust_rows
            counts[case["route"]] += 1
            same[case["route"]] += equal
            if not equal:
                rows_diff = {}
                if node_rows != rust_rows:
                    for table in node_rows:
                        if node_rows[table] != rust_rows[table]:
                            rows_diff[table] = {"node": node_rows[table], "rust": rust_rows[table]}
                out.write(
                    json.dumps(
                        {
                            "case": {k: case[k] for k in ("route", "method", "path", "who", "prep")},
                            "body": case["body"].decode("utf-8", "replace")[:400] if case["body"] else None,
                            "node": n,
                            "rust": r,
                            "rows": rows_diff,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                out.flush()
            if index % 250 == 0:
                print(
                    f"{index}/{len(ordered)} {time.time() - started:.0f}s "
                    f"mismatches={sum(counts.values()) - sum(same.values())}",
                    flush=True,
                )
    fixtures.cleanup(CUR)
    print("route\tpairs\tidentical")
    for route in sorted(counts):
        print(f"{route}\t{counts[route]}\t{same[route]}")
    print("TOTAL", sum(counts.values()), sum(same.values()), flush=True)


main()
