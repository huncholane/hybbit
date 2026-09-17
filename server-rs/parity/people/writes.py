#!/usr/bin/env python3
"""Write-route parity: dashboard identify, trait replacement and user deletion.

Each case starts from the same fixture state for both backends: reset, send to
Node, snapshot the rows it touched; reset, send to Rust, snapshot. Responses
(status, watched headers, body) and snapshots must match. Only rows with ids
prefixed parity-people-w are created or touched.

Usage: writes.py [--only SUBSTRING] [--out FILE]
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402
import harness  # noqa: E402

CREDS = fixtures.credentials()
SITE = 7  # fixture site (org uYq2)
SITE_KB = 3  # org kb0bi site
TAG = "parity-people-w"


def pg_exec(statements):
    with fixtures.pg() as conn, conn.cursor() as cur:
        for statement, params in statements:
            cur.execute(statement, params)


def pg_rows(query, params=()):
    with fixtures.pg() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        return [list(row) for row in cur.fetchall()]


def reset_pg(profiles, aliases):
    statements = [
        ("DELETE FROM user_profiles WHERE user_id LIKE 'parity-people-w%%'", None),
        ("DELETE FROM user_aliases WHERE user_id LIKE 'parity-people-w%%' OR anonymous_id LIKE 'parity-people-w%%'", None),
    ]
    for site, user_id, traits in profiles:
        statements.append((
            "INSERT INTO user_profiles (site_id, user_id, traits, created_at, updated_at) VALUES (%s, %s, %s, now() - interval '2 days', now() - interval '2 days')",
            (site, user_id, traits),
        ))
    for site, anonymous_id, user_id in aliases:
        statements.append((
            "INSERT INTO user_aliases (site_id, anonymous_id, user_id, created_at) VALUES (%s, %s, %s, now() - interval '2 days')",
            (site, anonymous_id, user_id),
        ))
    pg_exec(statements)


def snapshot_pg():
    profiles = pg_rows(
        "SELECT site_id, user_id, traits::text, updated_at > now() - interval '5 minutes', created_at > now() - interval '5 minutes' "
        "FROM user_profiles WHERE user_id LIKE 'parity-people-w%%' ORDER BY 1, 2"
    )
    aliases = pg_rows(
        "SELECT site_id, anonymous_id, user_id, created_at > now() - interval '5 minutes' FROM user_aliases "
        "WHERE user_id LIKE 'parity-people-w%%' OR anonymous_id LIKE 'parity-people-w%%' ORDER BY 1, 2"
    )
    return {"profiles": profiles, "aliases": aliases}


DEL_EVENTS_SQL = """INSERT INTO events (site_id, timestamp, timestamp_ms, session_id, user_id, identified_user_id, type, pathname, tag, props)
SELECT {site} AS site_id, now() - toIntervalMinute(number) AS timestamp, now64(3) - toIntervalMinute(number) AS timestamp_ms,
  concat('parity-people-w-s', toString(number % 3)) AS session_id,
  multiIf(number % 4 = 0, 'parity-people-w-dev1', number % 4 = 1, 'parity-people-w-dev2', number % 4 = 2, 'parity-people-w-dev1', 'parity-people-w-other-dev') AS user_id,
  multiIf(number % 4 = 0, '', number % 4 = 1, 'parity-people-w-del', number % 4 = 2, 'parity-people-w-someone-else', '') AS identified_user_id,
  'pageview' AS type, '/w' AS pathname, '{tag}' AS tag, '{{}}' AS props
FROM numbers(40)"""


def reset_ch(site):
    fixtures.ch(f"DELETE FROM events WHERE site_id = {site} AND tag = '{TAG}'")
    fixtures.ch(DEL_EVENTS_SQL.format(site=site, tag=TAG))


def snapshot_ch(site):
    return fixtures.ch(
        f"SELECT user_id, identified_user_id, count() FROM events WHERE site_id = {site} AND tag = '{TAG}' GROUP BY ALL ORDER BY ALL FORMAT TSV"
    )


def json_body(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def build_cases():
    cases = []

    def add(name, method, path, cred, body=None, content_type="application/json", pre_profiles=(), pre_aliases=(), headers=None, clickhouse=False):
        merged = dict(CREDS[cred])
        merged.update(headers or {})
        if content_type is not None and body is not None:
            merged["Content-Type"] = content_type
        cases.append({
            "route": name, "method": method, "path": path, "cred": cred, "headers": merged, "body": body,
            "pre_profiles": list(pre_profiles), "pre_aliases": list(pre_aliases), "clickhouse": clickhouse,
        })

    identify = f"/api/sites/{SITE}/users/identify"
    ok_body = {"anonymous_id": "parity-people-w-dev1", "user_id": "parity-people-w-u1"}
    bodies = [
        json_body(ok_body),
        json_body({**ok_body, "traits": {"plan": "pro", "seats": 3, "ratio": 1.5, "whole": 1.0, "big": 1e21, "tiny": 5e-7, "neg": -0.0}}),
        json_body({**ok_body, "traits": {"gone": None, "kept": "x", "10": "ten", "2": "two", "nested": {"a": [1, None, {"b": "c"}]}}}),
        json_body({**ok_body, "traits": {"only": None}}),
        json_body({**ok_body, "traits": {}}),
        json_body({**ok_body, "traits": {"emoji": "é\U0001f600", "quote": "a\"b\\c", "ctl": ""}}),
        json_body({**ok_body, "traits": {"k": "x" * 2030}}),
        json_body({**ok_body, "traits": {"k": "x" * 2040}}),
        json_body({**ok_body, "traits": {"k": "é" * 1100}}),
        json_body({**ok_body, "traits": []}),
        json_body({**ok_body, "traits": None}),
        json_body({**ok_body, "traits": "str"}),
        json_body({"anonymous_id": "same", "user_id": "same"}),
        json_body({"anonymous_id": "", "user_id": ""}),
        json_body({"anonymous_id": 5, "user_id": True}),
        json_body({"anonymous_id": "a" * 256, "user_id": "b" * 255}),
        json_body({"user_id": "parity-people-w-u1"}),
        json_body({}),
        json_body([]),
        "null",
        "\"text\"",
        "{bad json",
        "",
        json_body({**ok_body, "extra": 1}),
        json_body({"anonymous_id": "parity-people-w-dev1", "user_id": "parity-people-w-é" + "x" * 250}),
        '{"anonymous_id":"parity-people-w-dev1","user_id":"parity-people-w-u1","traits":{"__proto__":{"x":1}}}',
        '{"anonymous_id":"parity-people-w-dev1","user_id":"parity-people-w-u1","traits":{"a":1,"a":2}}',
    ]
    for body in bodies:
        add("POST /users/identify", "POST", identify, "cookie-grow", body)
    add("POST /users/identify", "POST", identify, "cookie-grow", bodies[1], pre_profiles=[(SITE, "parity-people-w-u1", '{"plan": "free", "old": true}')])
    add("POST /users/identify", "POST", identify, "cookie-grow", bodies[0], pre_profiles=[(SITE, "parity-people-w-u1", '{"plan": "free"}')])
    add("POST /users/identify", "POST", identify, "cookie-grow", bodies[1], pre_profiles=[(SITE, "parity-people-w-u1", None)])
    add("POST /users/identify", "POST", identify, "cookie-grow", bodies[1], pre_profiles=[(SITE, "parity-people-w-u1", '["array"]')])
    add("POST /users/identify", "POST", identify, "cookie-grow", bodies[0], pre_aliases=[(SITE, "parity-people-w-dev1", "parity-people-w-u0")])
    add("POST /users/identify", "POST", identify, "cookie-grow", json_body(ok_body), content_type="text/plain")
    add("POST /users/identify", "POST", identify, "cookie-grow", json_body(ok_body), content_type="application/xml")
    add("POST /users/identify", "POST", identify, "cookie-grow", json_body(ok_body), content_type="application/json; charset=utf-8")
    add("POST /users/identify", "POST", identify, "cookie-grow", None)
    for cred in ["none", "cookie-owner", "cookie-member", "bearer-org2", "bearer-org2-users", "bearer-org", "bearer-grow"]:
        add("POST /users/identify", "POST", identify, cred, bodies[1])
        add("POST /users/identify", "POST", identify, cred, "{bad")
    for cred in ["cookie-member", "bearer-org-users", "bearer-org-events", "bearer-org-none", "none"]:
        add("POST /users/identify", "POST", f"/api/sites/{SITE_KB}/users/identify", cred, bodies[1])
    add("POST /users/identify", "POST", "/api/sites/5/users/identify", "none", bodies[1])
    add("POST /users/identify", "POST", "/api/sites/abc/users/identify", "bearer-org2", bodies[1])
    add("POST /users/identify", "POST", "/api/sites/abcdefgh/users/identify", "cookie-grow", bodies[1])
    add("POST /users/identify", "POST", "/api/sites/01555dc6cc96/users/identify", "cookie-grow", bodies[1])
    add("POST /users/identify", "POST", "/api/sites/436411d4cae7/users/identify", "cookie-grow", bodies[1])
    add("POST /users/identify", "POST", identify + "?start_date=bad", "cookie-grow", bodies[1])
    add("POST /users/identify", "POST", identify + "?segment_id=990101", "cookie-grow", bodies[1])
    add("POST /users/identify", "POST", identify + "?segment_id=abc", "cookie-grow", bodies[1])
    add("POST /users/identify", "POST", identify, "cookie-grow", bodies[1], headers={"Origin": "https://evil.example"})
    add("POST /users/identify", "POST", identify, "cookie-grow", bodies[1], headers={"Origin": "https://a.hygo.ai"})

    traits_path = f"/api/sites/{SITE}/users/parity-people-w-u1/traits"
    trait_bodies = [
        json_body({"traits": {"plan": "pro", "n": 1.0, "gone": None, "10": 1}}),
        json_body({"traits": {}}),
        json_body({"traits": {"only": None}}),
        json_body({"traits": []}),
        json_body({"traits": None}),
        json_body({}),
        json_body({"traits": {"k": "x" * 2040}}),
        json_body({"traits": {"nested": {"deep": [1, 2.5, "x"]}, "flag": False}}),
        "[]",
        "{bad",
        "",
        json_body({"traits": {"plan": "pro"}, "extra": True}),
    ]
    for body in trait_bodies:
        add("PUT /users/:userId/traits", "PUT", traits_path, "cookie-grow", body)
        add("PUT /users/:userId/traits", "PUT", traits_path, "cookie-grow", body, pre_profiles=[(SITE, "parity-people-w-u1", '{"old": 1, "plan": "free"}')])
    add("PUT /users/:userId/traits", "PUT", traits_path, "cookie-grow", None)
    add("PUT /users/:userId/traits", "PUT", traits_path, "cookie-grow", trait_bodies[0], content_type="text/plain")
    for user in ["parity-people-w-%C3%A9", "parity-people-w-a%2Fb", "parity-people-w-" + "x" * 1484, "parity-people-w-" + "x" * 1490]:
        add("PUT /users/:userId/traits", "PUT", f"/api/sites/{SITE}/users/{user}/traits", "cookie-grow", trait_bodies[0])
    for cred in ["none", "cookie-member", "bearer-org2", "bearer-org2-users", "bearer-org"]:
        add("PUT /users/:userId/traits", "PUT", traits_path, cred, trait_bodies[0])
    add("PUT /users/:userId/traits", "PUT", f"/api/sites/{SITE}/users//traits", "none", trait_bodies[0])
    add("PUT /users/:userId/traits", "PUT", f"/api/sites/{SITE_KB}/users/parity-people-w-u1/traits", "bearer-org-users", trait_bodies[0])
    add("PUT /users/:userId/traits", "PUT", f"/api/sites/{SITE_KB}/users/parity-people-w-u1/traits", "bearer-org-events", trait_bodies[0])

    delete_path = f"/api/sites/{SITE}/users/parity-people-w-del"
    del_profiles = [(SITE, "parity-people-w-del", '{"plan": "pro"}'), (SITE, "parity-people-w-keep", '{}')]
    del_aliases = [(SITE, "parity-people-w-dev2", "parity-people-w-del"), (SITE, "parity-people-w-dev3", "parity-people-w-keep")]
    for cred in ["cookie-grow", "bearer-org2", "bearer-grow"]:
        add("DELETE /users/:userId", "DELETE", delete_path, cred, pre_profiles=del_profiles, pre_aliases=del_aliases, clickhouse=True)
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE}/users/parity-people-w-dev1", "cookie-grow", pre_profiles=del_profiles, pre_aliases=del_aliases, clickhouse=True)
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE}/users/parity-people-w-dev3", "cookie-grow", pre_profiles=del_profiles, pre_aliases=del_aliases, clickhouse=True)
    add("DELETE /users/:userId", "DELETE", delete_path, "cookie-grow", body="", content_type="application/json", pre_profiles=del_profiles, pre_aliases=del_aliases)
    add("DELETE /users/:userId", "DELETE", delete_path, "cookie-grow", body="{bad", content_type="application/json", pre_profiles=del_profiles, pre_aliases=del_aliases)
    for cred in ["none", "cookie-member", "cookie-owner", "bearer-org2-users", "bearer-org", "bearer-member"]:
        add("DELETE /users/:userId", "DELETE", delete_path, cred, pre_profiles=del_profiles, pre_aliases=del_aliases, clickhouse=True)
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE}/users/", "none")
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE}/users/", "cookie-member")
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE}/users/session-count", "cookie-member")
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE}/users/identify", "none")
    add("DELETE /users/:userId", "DELETE", delete_path + "?start_date=bad", "cookie-grow", pre_profiles=del_profiles, pre_aliases=del_aliases)
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE_KB}/users/parity-people-w-del", "cookie-member")
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE_KB}/users/parity-people-w-del", "bearer-org-users")
    add("DELETE /users/:userId", "DELETE", delete_path, "cookie-grow", headers={"Origin": "https://evil.example"})
    add("DELETE /users/:userId", "DELETE", f"/api/sites/{SITE}/users/%zz", "cookie-grow")
    return cases


def run_side(target, case):
    reset_pg(case["pre_profiles"], case["pre_aliases"])
    if case["clickhouse"]:
        reset_ch(SITE)
    status, headers, body = harness.send(target, case["method"], case["path"], case["headers"], case["body"])
    state = snapshot_pg()
    if case["clickhouse"]:
        state["events"] = snapshot_ch(SITE)
    return (status, headers, body), state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only")
    parser.add_argument("--out", default=os.path.join(harness.SCRATCH, "r_writes.json"))
    args = parser.parse_args()
    cases = build_cases()
    if args.only:
        cases = [case for case in cases if args.only in case["route"] or args.only in case["path"]]
    print(f"{len(cases)} write cases", flush=True)
    counts = collections.Counter()
    same = collections.Counter()
    statuses = collections.defaultdict(collections.Counter)
    failures = []
    for index, case in enumerate(cases):
        node_response, node_state = run_side(harness.NODE, case)
        rust_response, rust_state = run_side(harness.RUST, case)
        diffs = harness.differences(node_response, rust_response)
        if node_state != rust_state:
            diffs.append("rows")
        counts[case["route"]] += 1
        statuses[case["route"]][node_response[0]] += 1
        if diffs:
            failures.append({
                "case": {k: case[k] for k in ("route", "method", "path", "cred")},
                "body": case["body"] if case["body"] is None or len(case["body"]) < 300 else case["body"][:300] + "...",
                "diffs": diffs,
                "node": {"status": node_response[0], "body": node_response[2].decode("utf-8", "replace")[:1500], "state": node_state},
                "rust": {"status": rust_response[0], "body": rust_response[2].decode("utf-8", "replace")[:1500], "state": rust_state},
            })
        else:
            same[case["route"]] += 1
        if (index + 1) % 20 == 0:
            print(f"  {index + 1}/{len(cases)}, {len(failures)} differing", flush=True)
    reset_pg([], [])
    fixtures.ch(f"DELETE FROM events WHERE site_id = {SITE} AND tag = '{TAG}'")
    report = {
        "total": len(cases),
        "identical": sum(same.values()),
        "routes": {route: {"pairs": counts[route], "identical": same[route], "statuses": dict(statuses[route])} for route in sorted(counts)},
        "failures": failures,
    }
    with open(args.out, "w") as handle:
        json.dump(report, handle, indent=1, default=str)
    print(json.dumps({k: v for k, v in report.items() if k != "failures"}, indent=1))
    for failure in failures:
        print(json.dumps(failure, default=str)[:3000])


if __name__ == "__main__":
    main()
