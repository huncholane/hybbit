#!/usr/bin/env python3
"""api-admin differential run: every case against Node and Rust.

Reads start from one shared fixture set and are sent to both backends from two
threads, so a row another agent changes mid-run lands on both sides; a read that
still differs is retried a few times before it counts as a mismatch. Writes reset
the fixture rows before each backend and compare the resulting Postgres rows too.

Setup: PARITY_ADMIN_OUT=<dir> fixtures.py setup > <dir>/creds.json
Usage: PARITY_ADMIN_OUT=<dir> run.py [route-substring ...]
Writes <dir>/results.jsonl (mismatches only) and prints per-route counts.
"""
import collections
import json
import os
import re
import sys
import threading
import time

import cases as C
import hw

PLACEHOLDER = re.compile(r"\{(flag|exp|goal)-([A-Za-z0-9]+)\}")
BODY_PLACEHOLDER = re.compile(rb'"\{(flag|exp|goal)-([A-Za-z0-9]+)\}"')
GROUPS = {"flag": "flags", "exp": "experiments", "goal": "goals"}
READ_RETRIES = 4


def resolve_path(path, ids):
    return PLACEHOLDER.sub(lambda m: str(ids[GROUPS[m.group(1)]][m.group(2)]), path)


def resolve_body(body, ids):
    if body is None:
        return None
    return BODY_PLACEHOLDER.sub(
        lambda m: str(ids[GROUPS[m.group(1).decode()]][m.group(2).decode()]).encode(), body
    )


def wait_for_backends():
    """Another agent restarts the shared Node process from time to time; a case
    that lands in the gap is retried once both answer again."""
    while True:
        node = hw.send(hw.NODE, "GET", "/api/health", timeout=5)
        rust = hw.send(hw.RUST, "GET", "/api/health", timeout=5)
        if node["status"] == 200 and rust["status"] == 200:
            return
        print("waiting for a backend to come back", file=sys.stderr, flush=True)
        time.sleep(3)


def one(target, case, ids):
    for _ in range(3):
        response = hw.send(
            target, case["method"], resolve_path(case["path"], ids), case["headers"], resolve_body(case["body"], ids)
        )
        if response["status"] != -1:
            return response
        wait_for_backends()
    return response


def both(case, ids):
    """Node and Rust at the same moment, so live tables drift equally for each."""
    out = {}

    def run(name, target):
        out[name] = one(target, case, ids)

    threads = [
        threading.Thread(target=run, args=("node", hw.NODE)),
        threading.Thread(target=run, args=("rust", hw.RUST)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return out["node"], out["rust"]


def main():
    filters = sys.argv[1:]
    selected = [c for c in C.all_cases() if not filters or any(f in c["route"] for f in filters)]
    ordered = [c for c in selected if not c["write"]] + [c for c in selected if c["write"]]
    counts, same = collections.Counter(), collections.Counter()
    started = time.time()
    retried = 0

    hw.ensure_events()
    with open(os.path.join(hw.OUT, "results.jsonl"), "w") as out:
        ids = hw.reset_writable()
        for index, case in enumerate(ordered):
            if case["write"]:
                ids = hw.reset_writable()
                node = one(hw.NODE, case, ids)
                node_rows = hw.snapshot(ids)
                node_ids = ids
                ids = hw.reset_writable()
                rust = one(hw.RUST, case, ids)
                rust_rows = hw.snapshot(ids)
                n, r = hw.comparable(node, node_ids, case["shape"]), hw.comparable(rust, ids, case["shape"])
                equal = n == r and node_rows == rust_rows
            else:
                node_rows = rust_rows = None
                for attempt in range(READ_RETRIES):
                    node, rust = both(case, ids)
                    n, r = hw.comparable(node, ids, case["shape"]), hw.comparable(rust, ids, case["shape"])
                    equal = n == r
                    if equal:
                        break
                    retried += 1
                node_ids = ids

            counts[case["route"]] += 1
            same[case["route"]] += equal
            if not equal:
                out.write(
                    json.dumps(
                        {
                            "case": {k: case[k] for k in ("route", "method", "path", "who")},
                            "body": case["body"].decode("utf-8", "replace")[:400] if case["body"] else None,
                            "node": n,
                            "rust": r,
                            "rows_equal": node_rows == rust_rows,
                            "node_rows": node_rows if node_rows != rust_rows else None,
                            "rust_rows": rust_rows if node_rows != rust_rows else None,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                out.flush()
            if index % 200 == 0:
                print(
                    f"{index}/{len(ordered)} {time.time() - started:.0f}s "
                    f"mismatches={sum(counts.values()) - sum(same.values())}",
                    flush=True,
                )

    hw.reset_writable()
    print("route\tpairs\tidentical")
    for route in sorted(counts):
        print(f"{route}\t{counts[route]}\t{same[route]}")
    print("TOTAL", sum(counts.values()), sum(same.values()), f"read-retries={retried}", flush=True)


main()
