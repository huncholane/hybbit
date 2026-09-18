#!/usr/bin/env python3
"""How far the two ClickHouse system-table endpoints can be compared at all.

`/api/admin/clickhouse-stats` and `/api/admin/clickhouse-query-log` read
`system.parts` and `system.query_log`, which move under both backends while the
harness runs: every request either backend makes lands in the query log, and
parts merge in the background. The main run therefore compares those two routes
by shape. This script reports how often the full bodies still match byte for
byte, which is the honest measure of what is left.

Usage: PARITY_ADMIN_OUT=<dir> system_tables.py [rounds]
"""
import json
import sys
import threading

import hw

ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 20
COOKIE = [("Cookie", hw.CREDS["sessions"]["sysadmin"])]
PATHS = [
    "/api/admin/clickhouse-stats",
    "/api/admin/clickhouse-stats?days=0",
    "/api/admin/clickhouse-query-log?pageSize=5",
    "/api/admin/clickhouse-query-log?sortBy=read_rows&sortOrder=asc&pageSize=3",
]


def both(path):
    out = {}

    def run(name, target):
        out[name] = hw.send(target, "GET", path, COOKIE)

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
    totals = {}
    for path in PATHS:
        exact = status = shape = 0
        for _ in range(ROUNDS):
            node, rust = both(path)
            status += node["status"] == rust["status"]
            exact += node["body"] == rust["body"]
            shape += hw.comparable(node, {"flags": {}, "experiments": {}, "goals": {}}, True) == hw.comparable(
                rust, {"flags": {}, "experiments": {}, "goals": {}}, True
            )
        totals[path] = {"rounds": ROUNDS, "same_status": status, "same_shape": shape, "same_bytes": exact}
    print(json.dumps(totals, indent=1))


main()
