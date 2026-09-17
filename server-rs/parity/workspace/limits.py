#!/usr/bin/env python3
"""Rate limit parity: exhaust each limiter on one backend then the other from a
clean key, and interleave the two backends on one shared counter.

Usage: PARITY_WORKSPACE_OUT=<dir> limits.py
"""
import json, os

import hw
from cases import caller, jbody

KB = hw.O["kb"]
QUERY = {"query": "SELECT 1 AS one FROM scoped_events LIMIT 1"}
FLOWS = [
    ("run-card", "POST", "/api/sites/1/dashboards/run-card", QUERY),
    ("dashboards list", "GET", "/api/sites/1/dashboards", None),
    ("query", "POST", f"/api/organizations/{KB}/analytics/query", QUERY),
    ("generate", "POST", f"/api/organizations/{KB}/analytics/query/generate", {}),
]
CALLERS = [("s:huncho", []), ("k:orgKb", [("X-Forwarded-For", "203.0.113.9, 10.0.0.1")]), ("k:justin", [])]


def shape(response):
    headers = {k: response["headers"].get(k) for k in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after")}
    return {"status": response["status"], "headers": headers, "body": response["body"] if response["status"] == 429 else None}


def request(target, method, path, who, extra, body):
    headers, _ = caller(who)
    headers = headers + extra + ([("Content-Type", "application/json")] if body is not None else [])
    return shape(hw.send(target, method, path, headers, jbody(body) if body is not None else None))


def main():
    total = identical = 0
    out = open(os.path.join(hw.OUT, "limits-results.jsonl"), "w")
    for name, method, path, body in FLOWS:
        for who, extra in CALLERS:
            if who == "k:justin" and name == "dashboards list":
                continue
            sequences = []
            for target in (hw.NODE, hw.RUST):
                hw.reset_limits()
                sequences.append([request(target, method, path, who, extra, body) for _ in range(63)])
            for index, (node, rust) in enumerate(zip(*sequences)):
                total += 1
                identical += node == rust
                if node != rust:
                    out.write(json.dumps({"flow": name, "who": who, "index": index, "node": node, "rust": rust}) + "\n")
            # Interleaved: one shared counter, alternating backends
            hw.reset_limits()
            for index in range(64):
                target = hw.NODE if index % 2 == 0 else hw.RUST
                got = request(target, method, path, who, extra, body)
                expected_remaining = str(max(0, 60 - (index + 1)))
                total += 1
                ok = got["headers"]["x-ratelimit-remaining"] == expected_remaining and (got["status"] == 429) == (index >= 60)
                identical += ok
                if not ok:
                    out.write(json.dumps({"flow": name, "who": who, "interleaved": index, "got": got}) + "\n")
            keys = sorted(k for prefix in hw.LIMITER_PREFIXES for k in hw.REDIS.keys(prefix + "*"))
            print(name, who, "keys:", keys, flush=True)
    hw.reset_limits()
    print("TOTAL", total, identical)


main()
