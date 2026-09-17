#!/usr/bin/env python3
"""Differential harness for the people routes: every case goes to Node (:3001)
and Rust (:3063) at the same time; status, watched headers and body bytes must be
identical. Mismatches are retried (other agents share the stores, and `now()`
moves) before they count.

Usage: harness.py [--groups access,query,route] [--only SUBSTRING] [--limit N] [--out FILE]
Writes the per-route counts and every remaining difference to --out.
"""
import argparse
import collections
import concurrent.futures
import http.client
import json
import os
import random
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

NODE = ("127.0.0.1", 3001)
RUST = ("127.0.0.1", int(os.environ.get("RUST_PORT", "3063")))
SCRATCH = "/tmp/claude-1000/-home-huncho-code-hygo-repo-hybbit/c715b88b-ff27-4193-85dd-24c1a017449e/scratchpad/analytics-people"

WATCHED = [
    "content-type",
    "cache-control",
    "x-content-type-options",
    "vary",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "retry-after",
]

CREDS = fixtures.credentials()


def send(target, method, path, headers, body):
    for attempt in range(3):
        conn = http.client.HTTPConnection(*target, timeout=120)
        try:
            conn.putrequest(method, path, skip_accept_encoding=True)
            for name, value in headers.items():
                conn.putheader(name, value)
            data = body.encode() if isinstance(body, str) else body
            if data is not None:
                conn.putheader("Content-Length", str(len(data)))
            conn.endheaders()
            if data is not None:
                conn.send(data)
            response = conn.getresponse()
            payload = response.read()
            got = {name.lower(): value for name, value in response.getheaders()}
            return response.status, got, payload
        except (ConnectionError, http.client.HTTPException, TimeoutError) as error:
            if attempt == 2:
                return 599, {}, str(error).encode()
            time.sleep(0.5)
        finally:
            conn.close()


def pair(case):
    results = [None, None]

    def run(index, target):
        results[index] = send(target, case["method"], case["path"], case.get("headers", {}), case.get("body"))

    threads = [threading.Thread(target=run, args=(0, NODE)), threading.Thread(target=run, args=(1, RUST))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def differences(node, rust):
    diffs = []
    if node[0] != rust[0]:
        diffs.append("status")
    for name in WATCHED:
        if node[1].get(name) != rust[1].get(name):
            diffs.append(name)
    if node[2] != rust[2]:
        diffs.append("body")
    return diffs


def run_case(case):
    for attempt in range(4):
        node, rust = pair(case)
        diffs = differences(node, rust)
        if not diffs:
            return case, node[0], None, attempt
        time.sleep(0.3 * (attempt + 1))
    return case, node[0], {
        "diffs": diffs,
        "node": {"status": node[0], "headers": {k: node[1].get(k) for k in WATCHED}, "body": node[2].decode("utf-8", "replace")[:4000]},
        "rust": {"status": rust[0], "headers": {k: rust[1].get(k) for k in WATCHED}, "body": rust[2].decode("utf-8", "replace")[:4000]},
    }, attempt


# ---------------------------------------------------------------------------
# Case generation


def q(params):
    """Query string from (key, value) pairs, keeping repeats."""
    if not params:
        return ""
    parts = []
    for key, value in params:
        if value is None:
            parts.append(urllib.parse.quote(key, safe=""))
        else:
            parts.append(urllib.parse.quote(key, safe="") + "=" + urllib.parse.quote(value, safe=""))
    return "?" + "&".join(parts)


def filters(*items):
    return json.dumps(list(items), separators=(",", ":"))


def f(parameter, kind, *values):
    return {"parameter": parameter, "type": kind, "value": list(values)}


TIME_VARIANTS = [
    [],
    [("start_date", "2026-08-01"), ("end_date", "2026-08-31"), ("time_zone", "UTC")],
    [("start_date", "2026-09-01"), ("end_date", "2026-09-17"), ("time_zone", "America/New_York")],
    [("start_date", "2026-06-01"), ("end_date", "2026-09-16"), ("time_zone", "Asia/Kolkata")],
    [("start_date", "2026-09-10"), ("end_date", "2026-09-10"), ("time_zone", "Pacific/Auckland")],
    [("start_date", "2026-07-15"), ("end_date", "2026-07-20")],
    [("start_datetime", "2026-09-01 00:00:00"), ("end_datetime", "2026-09-15 12:30:00")],
    [("start_datetime", "2026-09-01T00:00:00Z"), ("end_datetime", "2026-09-16T00:00:00+02:00"), ("time_zone", "Europe/Berlin")],
    [("past_minutes_start", "20160"), ("past_minutes_end", "0")],
    [("past_minutes_start", "129600"), ("past_minutes_end", "1440"), ("time_zone", "America/Los_Angeles")],
    [("start_date", ""), ("end_date", ""), ("time_zone", "")],
    [("start_date", "2026-13-01"), ("end_date", "2026-01-01")],
    [("start_date", "2026-08-01")],
    [("time_zone", "Not/AZone")],
    [("start_datetime", "2026-09-02 00:00:00"), ("end_datetime", "2026-09-01 00:00:00")],
    [("past_minutes_start", "abc"), ("past_minutes_end", "0")],
    [("time_zone", "UTC"), ("time_zone", "UTC")],
    [("start_date", "2026/08/01"), ("end_date", "2026-08-31")],
]

FILTER_VARIANTS = [
    None,
    filters(f("country", "equals", "US")),
    filters(f("browser", "equals", "Chrome", "Firefox")),
    filters(f("pathname", "contains", "/blog")),
    filters(f("pathname", "not_contains", "/admin", "/api")),
    filters(f("pathname", "starts_with", "/")),
    filters(f("pathname", "ends_with", "ing")),
    filters(f("pathname", "regex", "^/[a-z]+$")),
    filters(f("pathname", "not_regex", "^/$")),
    filters(f("pathname", "regex", "[")),
    filters(f("pathname", "regex", "^(?!x)")),
    filters(f("pathname", "equals", "/")),
    filters(f("pathname", "not_equals", "/")),
    filters(f("event_name", "equals", "signup_click")),
    filters(f("event_name", "is_not_null")),
    filters(f("channel", "equals", "Direct")),
    filters(f("channel", "not_equals", "Organic Search")),
    filters(f("utm_source", "is_not_null")),
    filters(f("utm_campaign", "equals", "launch")),
    filters(f("referrer", "is_null")),
    filters(f("referrer", "contains", "google")),
    filters(f("entry_page", "equals", "/")),
    filters(f("exit_page", "contains", "/")),
    filters(f("user_id", "equals", "parity-people-alice")),
    filters(f("user_id", "equals", "7ab75f5dcdd7", "parity-people-bob")),
    filters(f("user_id", "not_equals", "parity-people-alice")),
    filters(f("user_id", "is_null")),
    filters(f("user_id", "is_not_null")),
    filters(f("lat", "greater_than", "30")),
    filters(f("lon", "less_than", -80)),
    filters(f("lat", "equals", "37.751")),
    filters(f("lon", "not_equals", "-97.822", "0")),
    filters(f("lat", "greater_than", "abc")),
    filters(f("dimensions", "equals", "1920x1080")),
    filters(f("city", "contains", "a")),
    filters(f("region", "equals", "US-CA")),
    filters(f("operating_system_version", "equals", "Windows 10/11")),
    filters(f("browser_version", "starts_with", "Chrome")),
    filters(f("feature_flag:new_checkout", "equals", "true")),
    filters(f("tag", "equals", "parity-people")),
    filters(f("hostname", "equals", "hygo.ai")),
    filters(f("page_title", "contains", "Hygo")),
    filters(f("querystring", "is_not_null")),
    filters(f("language", "equals", "en-US")),
    filters(f("device_type", "equals", "Mobile")),
    filters(f("timezone", "starts_with", "America/")),
    filters(f("operating_system", "is_null")),
    filters(f("country", "equals", "US"), f("utm_campaign", "is_null"), f("pathname", "contains", "/")),
    "bad",
    "[]",
    "{}",
    filters({"parameter": "password", "type": "equals", "value": ["x"]}),
    filters({"parameter": "browser", "type": "like", "value": ["x"]}),
    filters({"parameter": "browser", "type": "equals", "value": "x"}),
    "",
]

SEGMENT_VARIANTS = ["990101", "990102", "990103", "990104", "990105", "990106", "999999", "abc", "0", "-1", "1.5", ""]


def with_filters(base, value):
    return base if value is None else base + [("filters", value)]


class Builder:
    def __init__(self):
        self.cases = []

    def add(self, route, method, path, cred="cookie-owner", headers=None, body=None):
        merged = dict(CREDS[cred])
        merged.update(headers or {})
        self.cases.append({"route": route, "method": method, "path": path, "cred": cred, "headers": merged, "body": body})


def read_routes(site):
    """Every read route with a sensible base query for `site`."""
    site = str(site)
    error_message = "x is undefined" if site in ("1", "7") else 'undefined is not an object (evaluating \'r["@context"].toLowerCase\')'
    event_name = {"4": "domain_search", "7": "signup_click", "1": "signup_click"}.get(site, "scroll_depth")
    session = "S1nI7tVOCpRqT3" if site in ("1", "7") else "orJ4kuTog2_stI"
    user = "parity-people-alice" if site == "7" else "7ab75f5dcdd7"
    return [
        ("GET /sessions", f"/api/sites/{site}/sessions", []),
        ("GET /sessions/:sessionId", f"/api/sites/{site}/sessions/{session}", []),
        ("GET /sessions/locations", f"/api/sites/{site}/sessions/locations", []),
        ("GET /events", f"/api/sites/{site}/events", []),
        ("GET /events/time-series", f"/api/sites/{site}/events/time-series", [("bucket", "day")]),
        ("GET /events/names", f"/api/sites/{site}/events/names", []),
        ("GET /events/properties", f"/api/sites/{site}/events/properties", [("event_name", event_name)]),
        ("GET /events/autocapture", f"/api/sites/{site}/events/autocapture", [("type", "button_click")]),
        ("GET /events/autocapture-values", f"/api/sites/{site}/events/autocapture-values", [("type", "outbound")]),
        ("GET /events/outbound", f"/api/sites/{site}/events/outbound", []),
        ("GET /errors/names", f"/api/sites/{site}/errors/names", []),
        ("GET /errors/events", f"/api/sites/{site}/errors/events", [("errorMessage", error_message)]),
        ("GET /errors/time-series", f"/api/sites/{site}/errors/time-series", [("errorMessage", error_message), ("bucket", "day")]),
        ("GET /users", f"/api/sites/{site}/users", []),
        ("GET /users/session-count", f"/api/sites/{site}/users/session-count", [("user_id", user)]),
        ("GET /users/:userId", f"/api/sites/{site}/users/{user}", []),
        ("GET /user-traits/keys", f"/api/sites/{site}/user-traits/keys", []),
        ("GET /user-traits/values", f"/api/sites/{site}/user-traits/values", [("key", "plan")]),
        ("GET /user-traits/users", f"/api/sites/{site}/user-traits/users", [("key", "plan"), ("value", "pro")]),
    ]


def access_matrix(builder):
    """Every route, every credential, several sites (public, private, other org,
    text ids, unknown and malformed ids)."""
    sites = ["1", "3", "5", "7", "39", "7c2ff798dacb", "01555dc6cc96", "999", "abc", "0x1", "1.0", "", "99999999999"]
    for site in sites:
        for route, path, params in read_routes(site):
            for cred in CREDS:
                builder.add(route, "GET", path + q(params), cred)
    for route, path, params in read_routes("1"):
        builder.add(route, "GET", path + q(params + [("api_key", "parity-people-token-org")]), "none")
        builder.add(route, "GET", path + q(params + [("api_key", "parity-people-token-org"), ("api_key", "x")]), "none")
        builder.add(route, "GET", path + q(params), "none", headers={"x-private-key": "bbcc8977bf28"})
        builder.add(route, "GET", path + q(params), "none", headers={"x-private-key": "wrong"})
        builder.add(route, "HEAD", path + q(params), "cookie-owner")
        builder.add(route, "GET", path + q(params), "cookie-owner", headers={"Origin": "https://a.hygo.ai"})
        builder.add(route, "GET", path + q(params), "none", headers={"Origin": "https://evil.example"})


def query_matrix(builder):
    """Time ranges, zones, filters of every type and saved segments on sites with data."""
    data_sites = [("7", "cookie-grow"), ("1", "cookie-owner"), ("4", "bearer-org"), ("3", "cookie-member")]
    for site, cred in data_sites:
        for route, path, params in read_routes(site):
            for time_variant in TIME_VARIANTS:
                builder.add(route, "GET", path + q(params + time_variant), cred)
            for filter_variant in FILTER_VARIANTS:
                builder.add(route, "GET", path + q(with_filters(params, filter_variant)), cred)
    rng = random.Random(7)
    for route, path, params in read_routes("7"):
        for _ in range(12):
            combo = params + rng.choice(TIME_VARIANTS[:11]) + ([] if rng.random() < 0.2 else [("filters", rng.choice([v for v in FILTER_VARIANTS if v]))])
            builder.add(route, "GET", path + q(combo), "cookie-grow")
    for site, cred in [("7", "cookie-grow"), ("7", "bearer-org2-users"), ("7", "bearer-org2"), ("1", "cookie-owner"), ("1", "bearer-org-events"), ("5", "none")]:
        for route, path, params in read_routes(site):
            for segment in SEGMENT_VARIANTS:
                builder.add(route, "GET", path + q(params + [("segment_id", segment)]), cred)
            builder.add(route, "GET", path + q(params + [("segment_id", "990101"), ("filters", filters(f("browser", "equals", "Chrome")))]), cred)
            builder.add(route, "GET", path + q(params + [("segment_id", "990101"), ("segment_id", "990103")]), cred)


def route_specific(builder):
    """Each route's own parameters: pagination, sorting, search, ids, buckets."""
    for site, cred in [("7", "cookie-grow"), ("1", "cookie-owner"), ("4", "cookie-member")]:
        base = f"/api/sites/{site}"
        for params in [
            [("page", "2")], [("page", "0")], [("page", "abc")], [("limit", "5")], [("limit", "5"), ("page", "3")],
            [("limit", "0")], [("limit", "abc")], [("limit", "5"), ("limit", "6")], [("page", "")],
            [("user_id", "7ab75f5dcdd7")], [("user_id", "parity-people-alice")], [("user_id", "nobody")],
            [("session_id", "S1nI7tVOCpRqT3")], [("identified_only", "true")], [("identified_only", "TRUE")],
            [("min_pageviews", "3")], [("min_events", "1")], [("min_duration", "60")], [("min_duration", "abc")],
            [("min_pageviews", "")], [("min_pageviews", "2"), ("min_events", "0"), ("min_duration", "10")],
            [("user_id", "a"), ("user_id", "b")],
        ]:
            builder.add("GET /sessions", "GET", base + "/sessions" + q(params), cred)
        for session in ["S1nI7tVOCpRqT3", "VTI8XGubyxIKiy", "PP9-9fMgucG2Id", "nope", "a%2Fb", "%20x", "x" * 1500, "x" * 1501, ""]:
            for params in [[], [("limit", "10")], [("limit", "10"), ("offset", "5")], [("offset", "1000")], [("minutes", "60")],
                           [("minutes", "0x10")], [("minutes", "abc")], [("limit", "0x5")], [("limit", "abc")], [("offset", "-1")],
                           [("minutes", "99999999")], [("limit", "5"), ("limit", "6")]]:
                builder.add("GET /sessions/:sessionId", "GET", base + "/sessions/" + session + q(params), cred)
        for params in [
            [("page_size", "10")], [("page_size", "abc")], [("page_size", "0")], [("page_size", "1000")],
            [("since_timestamp", "2026-09-10 00:00:00")], [("since_timestamp", "2026-09-10 00:00:00"), ("filters", filters(f("channel", "equals", "Direct")))],
            [("since_timestamp", "garbage")], [("since_timestamp", "a"), ("since_timestamp", "b")],
            [("before_timestamp", "2026-09-01 00:00:00")], [("before_timestamp", "2026-09-01 00:00:00"), ("page_size", "20")],
            [("before_timestamp", "nope")], [("start_date", "2026-08-01"), ("end_date", "2026-08-31"), ("page_size", "5")],
            [("page_size", "5"), ("page_size", "7")],
        ]:
            builder.add("GET /events", "GET", base + "/events" + q(params), cred)
        for bucket in ["minute", "five_minutes", "ten_minutes", "fifteen_minutes", "hour", "day", "week", "month", "year", "bogus", "constructor", "toString", "__proto__", "", None]:
            for extra in [[], [("limit", "3")], [("limit", "abc")], [("limit", "99")], [("limit", "-4")], [("start_date", "2026-08-01"), ("end_date", "2026-09-17"), ("time_zone", "Asia/Tokyo")]]:
                params = ([("bucket", bucket)] if bucket is not None else []) + extra
                builder.add("GET /events/time-series", "GET", base + "/events/time-series" + q(params), cred)
                builder.add("GET /errors/time-series", "GET", base + "/errors/time-series" + q(params + [("errorMessage", "x is undefined")]), cred)
        builder.add("GET /events/time-series", "GET", base + "/events/time-series" + q([("bucket", "day"), ("bucket", "hour")]), cred)
        builder.add("GET /errors/time-series", "GET", base + "/errors/time-series" + q([("bucket", "day"), ("bucket", "hour"), ("errorMessage", "x is undefined")]), cred)
        for params in [[], [("event_name", "")], [("event_name", "signup_click")], [("event_name", "domain_search")], [("event_name", "a"), ("event_name", "b")], [("event_name", "nope")]]:
            builder.add("GET /events/properties", "GET", base + "/events/properties" + q(params), cred)
        for kind in ["outbound", "button_click", "form_submit", "copy", "pageview", "", None, "Outbound"]:
            params = [("type", kind)] if kind is not None else []
            builder.add("GET /events/autocapture", "GET", base + "/events/autocapture" + q(params), cred)
            builder.add("GET /events/autocapture-values", "GET", base + "/events/autocapture-values" + q(params), cred)
        builder.add("GET /events/autocapture", "GET", base + "/events/autocapture" + q([("type", "copy"), ("type", "outbound")]), cred)
        for params in [[], [("page", "1")], [("page", "2"), ("limit", "1")], [("limit", "abc"), ("page", "x")], [("limit", "0")], [("page", "")], [("limit", "5")]]:
            builder.add("GET /errors/names", "GET", base + "/errors/names" + q(params), cred)
            for message in ["x is undefined", "", None, "nope"]:
                extra = [("errorMessage", message)] if message is not None else []
                builder.add("GET /errors/events", "GET", base + "/errors/events" + q(params + extra), cred)
        builder.add("GET /errors/events", "GET", base + "/errors/events" + q([("errorMessage", "a"), ("errorMessage", "b")]), cred)
        builder.add("GET /errors/time-series", "GET", base + "/errors/time-series" + q([("bucket", "day")]), cred)
        for params in [
            [("page", "2"), ("page_size", "10")], [("page", "abc")], [("page_size", "abc")], [("page", "0")],
            [("sort_by", "first_seen"), ("sort_order", "asc")], [("sort_by", "pageviews")], [("sort_by", "sessions"), ("sort_order", "desc")],
            [("sort_by", "events")], [("sort_by", "avg_session_duration"), ("sort_order", "asc")], [("sort_by", "bogus")],
            [("identified_only", "true")], [("search", "alice")], [("search", "  ALI  ")], [("search", "example"), ("search_field", "email")],
            [("search", "bob"), ("search_field", "name")], [("search", "parity-people"), ("search_field", "user_id")],
            [("search", "x"), ("search_field", "bogus")], [("search", "x"), ("search_field", "constructor")],
            [("search", "x"), ("search_field", "__proto__")], [("search", "x"), ("search_field", "toString")],
            [("search", "a"), ("search", "b")], [("search", "   ")], [("search", "zzz-no-match")], [("search", "zzz"), ("page", "abc")],
            [("search", "%")], [("search", "_")], [("search", "pro"), ("search_field", "a"), ("search_field", "b")],
            [("sort_by", "last_seen"), ("sort_by", "first_seen")],
        ]:
            builder.add("GET /users", "GET", base + "/users" + q(params), cred)
        for params in [[], [("user_id", "")], [("user_id", "parity-people-alice")], [("user_id", "7ab75f5dcdd7")], [("user_id", "382f1a9ae6f2"), ("time_zone", "Asia/Tokyo")],
                       [("user_id", "a"), ("user_id", "b")], [("user_id", "parity-people-carol"), ("time_zone", "")], [("user_id", "nobody")]]:
            builder.add("GET /users/session-count", "GET", base + "/users/session-count" + q(params), cred)
        for user in ["parity-people-alice", "parity-people-bob", "parity-people-carol", "parity-people-dave", "parity-people-erin",
                     "7ab75f5dcdd7", "a41d6e587300", "382f1a9ae6f2", "417905e6dd78", "parity-people-orphan-device", "nobody",
                     "identify", "session-count", "", "a%2Fb", "x" * 1501, "caf%C3%A9", "%zz"]:
            for params in [[], [("start_date", "2026-08-01"), ("end_date", "2026-08-31")], [("filters", filters(f("country", "equals", "US")))], [("filters", "bad")]]:
                builder.add("GET /users/:userId", "GET", base + "/users/" + user + q(params), cred)
        builder.add("GET /user-traits/keys", "GET", base + "/user-traits/keys", cred)
        for params in [[], [("key", "")], [("key", "plan")], [("key", "email")], [("key", "10")], [("key", "nested")], [("key", "plan"), ("limit", "1")],
                       [("key", "plan"), ("limit", "1"), ("offset", "1")], [("key", "plan"), ("limit", "abc")], [("key", "plan"), ("offset", "-1")],
                       [("key", "a"), ("key", "b")], [("key", "plan"), ("limit", "99999999999999999999")], [("key", "username"), ("offset", "0x10")]]:
            builder.add("GET /user-traits/values", "GET", base + "/user-traits/values" + q(params), cred)
        for params in [[], [("key", "plan")], [("key", "plan"), ("value", "pro")], [("key", "plan"), ("value", "")], [("key", "plan"), ("value", "free")],
                       [("key", "plan"), ("value", "pro"), ("limit", "1")], [("key", "plan"), ("value", "pro"), ("limit", "1"), ("offset", "1")],
                       [("key", "email"), ("value", "dave@example.com")], [("key", "plan"), ("value", "pro"), ("limit", "abc")],
                       [("key", "a"), ("key", "b"), ("value", "x")], [("key", "plan"), ("value", "a"), ("value", "b")], [("value", "pro")],
                       [("key", "username"), ("value", "numeric")]]:
            builder.add("GET /user-traits/users", "GET", base + "/user-traits/users" + q(params), cred)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--groups", default="access,query,route")
    parser.add_argument("--out", default=os.path.join(SCRATCH, "results.json"))
    args = parser.parse_args()

    builder = Builder()
    groups = args.groups.split(",")
    if "access" in groups:
        access_matrix(builder)
    if "query" in groups:
        query_matrix(builder)
    if "route" in groups:
        route_specific(builder)
    cases = builder.cases
    if args.only:
        cases = [case for case in cases if args.only in case["route"] or args.only in case["path"]]
    if args.limit:
        cases = cases[: args.limit]
    print(f"{len(cases)} cases", flush=True)

    counts = collections.Counter()
    same = collections.Counter()
    statuses = collections.defaultdict(collections.Counter)
    failures = []
    retried = 0
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for index, (case, status, failure, attempts) in enumerate(pool.map(run_case, cases)):
            counts[case["route"]] += 1
            statuses[case["route"]][status] += 1
            retried += 1 if attempts else 0
            if failure is None:
                same[case["route"]] += 1
            else:
                failures.append({"case": {k: case[k] for k in ("route", "method", "path", "cred")}, **failure})
            if (index + 1) % 500 == 0:
                print(f"  {index + 1}/{len(cases)} done, {len(failures)} differing, {time.time() - started:.0f}s", flush=True)

    report = {
        "total": len(cases),
        "identical": sum(same.values()),
        "retried": retried,
        "routes": {route: {"pairs": counts[route], "identical": same[route], "statuses": dict(statuses[route])} for route in sorted(counts)},
        "failures": failures,
    }
    with open(args.out, "w") as handle:
        json.dump(report, handle, indent=1)
    print(json.dumps({k: v for k, v in report.items() if k not in ("failures", "routes")}, indent=1))
    print(f"{len(failures)} differing cases written to {args.out}")


if __name__ == "__main__":
    main()
