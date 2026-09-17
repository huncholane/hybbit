#!/usr/bin/env python3
"""Live differential harness for the overview route group.

Sends the same GET requests to the Node backend and to the Rust backend, back to
back, against the parity stores, and compares status, content type and body bytes.

Routes: live-user-count, overview, overview/time-series, overview-lite,
overview-bucketed-lite, metric-lite, metric, page-titles, retention, journeys,
has-data, is-public, events/count, org-event-count.

Principals: cookie sessions (system admin, org member, owner of another org), org
API keys (unrestricted, analytics:read, events:read, sites:read, a wrong scope,
deny-all, another org's key), a user API key, `?api_key=`, private-link keys
(right and wrong), an unknown bearer, and no credentials, over public and private
Sites. Saved segments are created for the `segment_id` param.

Every credential and segment row this script creates carries the
`parity-overview-<run id>-` prefix and is removed at the end (also on Ctrl+C).

A pair that differs is retried: when the retry matches, the first difference is
counted as transient (other agents ingest events into the same stores while this
runs); when Node disagrees with itself the pair is counted as nondeterministic.
Everything else is a real difference and is written out with both responses.

Usage:
  NODE_URL=http://127.0.0.1:3001 RUST_URL=http://127.0.0.1:3877 \
    python3 http_parity.py [--pairs-per-route N] [--seed S] [--workers W] [--out report.json]
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import random
import sys
import threading
import time
import urllib.parse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

import psycopg2
import requests

NODE = os.environ.get("NODE_URL", "http://127.0.0.1:3001")
RUST = os.environ.get("RUST_URL", "http://127.0.0.1:3877")
SECRET = os.environ.get("BETTER_AUTH_SECRET", "parity-local-secret-not-for-production")
PG_DSN = os.environ.get("PARITY_PG_DSN", "host=127.0.0.1 port=55432 user=hygo password=hygo dbname=analytics")
# Every row this run creates is prefixed with its own run id, so concurrent runs
# (or the edge-case scripts importing this module) never delete each other's rows
RUN_ID = os.environ.get("PARITY_RUN_ID") or f"{os.getpid()}{int(time.time()) % 100000}"
PREFIX = f"parity-overview-{RUN_ID}-"

HYGO_ORG = "kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE"
TEST_ORG = "uYq2uOfGurt0dSp3fffpkYYFlUTyVxLh"
USERS = {
    "sysadmin": "XoNIxodDwuJOefJZebreRpXzn7Sq3hlL",  # system admin, owner of Hygo LLC
    "member": "ZDZZHJlo6olnWqliEC5t0kHoxcurXqBM",  # member of Hygo LLC
    "other": "GrOwOZVmycGqPD5WD7yIiw4CWBv0dPBa",  # owner of TestOrg only
}
SESSION_COOKIE = "__Secure-better-auth.session_token"

# key id suffix -> (configId, referenceId, permissions JSON or None)
API_KEYS = {
    "org-full": ("org", HYGO_ORG, None),
    "org-analytics": ("org", HYGO_ORG, '{"analytics":["read"]}'),
    "org-events": ("org", HYGO_ORG, '{"events":["read"]}'),
    "org-sites": ("org", HYGO_ORG, '{"sites":["write"]}'),
    "org-goals": ("org", HYGO_ORG, '{"goals":["read"]}'),
    "org-deny": ("org", HYGO_ORG, "{}"),
    "testorg-full": ("org", TEST_ORG, None),
    "user-member": ("default", USERS["member"], None),
    "user-member-analytics": ("default", USERS["member"], '{"analytics":["read"]}'),
}


def key_secret(name):
    return f"rb_{PREFIX}{name}-secret"


def hash_key(key):
    return base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()).decode().rstrip("=")


def signed_cookie(token):
    signature = base64.b64encode(hmac.new(SECRET.encode(), token.encode(), hashlib.sha256).digest()).decode()
    return f"{SESSION_COOKIE}={urllib.parse.quote(f'{token}.{signature}', safe='')}"


def session_token(name):
    return f"parityoverview{RUN_ID}{name}token"


# ---------------------------------------------------------------------------
# Store setup and cleanup
# ---------------------------------------------------------------------------
def cleanup(cursor):
    cursor.execute("DELETE FROM apikey WHERE id LIKE %s", (PREFIX + "%",))
    cursor.execute("DELETE FROM session WHERE id LIKE %s", (PREFIX + "%",))
    cursor.execute("DELETE FROM segments WHERE name LIKE %s", (PREFIX + "%",))


def setup(cursor):
    cleanup(cursor)
    for name, (config_id, reference_id, permissions) in API_KEYS.items():
        cursor.execute(
            'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, "expiresAt", remaining, '
            '"refillAmount", "refillInterval", "lastRefillAt", permissions, "createdAt", "updatedAt") VALUES '
            "(%s, 'parity', %s, %s, %s, true, NULL, NULL, NULL, NULL, NULL, %s, "
            "(now() AT TIME ZONE 'utc') - interval '2 hours', (now() AT TIME ZONE 'utc') - interval '2 hours')",
            (PREFIX + name, hash_key(key_secret(name)), reference_id, config_id, permissions),
        )
    for name, user_id in USERS.items():
        cursor.execute(
            'INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId") '
            "VALUES (%s, date_trunc('milliseconds', (now() AT TIME ZONE 'utc') + interval '6 days 22 hours'), %s, "
            "(now() AT TIME ZONE 'utc') - interval '3 days', (now() AT TIME ZONE 'utc') - interval '3 days', '', 'parity', %s)",
            (PREFIX + name, session_token(name), user_id),
        )
    segments = {}
    for name, organization, site, public, filters in [
        ("hygo-public-us", HYGO_ORG, None, True, [{"parameter": "country", "type": "equals", "value": ["US"]}]),
        ("site1-private-chrome", HYGO_ORG, 1, False, [{"parameter": "browser", "type": "contains", "value": ["Chrome"]}]),
        ("site4-private-checkout", HYGO_ORG, 4, False, [{"parameter": "pathname", "type": "starts_with", "value": ["/buy"]}]),
        ("testorg-public-desktop", TEST_ORG, 5, True, [{"parameter": "device_type", "type": "equals", "value": ["Desktop"]}]),
        ("hygo-broken-filters", HYGO_ORG, None, True, [{"parameter": "nope", "type": "equals", "value": ["x"]}]),
    ]:
        cursor.execute(
            "INSERT INTO segments (organization_id, site_id, name, filters, is_public) VALUES (%s, %s, %s, %s, %s) "
            "RETURNING segment_id",
            (organization, site, PREFIX + name, json.dumps(filters), public),
        )
        segments[name] = cursor.fetchone()[0]
    cursor.execute("SELECT site_id, private_link_key FROM sites WHERE private_link_key IS NOT NULL")
    private_keys = dict(cursor.fetchall())
    return segments, private_keys


# ---------------------------------------------------------------------------
# Request generation
# ---------------------------------------------------------------------------
TIME_ZONES = ["UTC", "America/New_York", "Asia/Kolkata", "Europe/London", "America/Los_Angeles", "Australia/Lord_Howe", "Pacific/Chatham", "America/Chicago"]
DATES = ["2026-06-01", "2026-07-15", "2026-08-01", "2026-08-31", "2026-09-01", "2026-09-10", "2026-09-14", "2026-09-16", "2026-09-17", "2026-09-18"]
DATETIMES = [
    "2026-09-01 00:00:00",
    "2026-09-10T12:00:00Z",
    "2026-09-10 11:30:00+05:30",
    "2026-08-15T08:15:07-0700",
    "2026-09-16 23:59:59",
    "2026-09-17T06:00:00Z",
    "2026-06-01T00:00:00",
    "2026-09-12 00:00:00-05:00",
]
MINUTES = [("60", "0"), ("1440", "0"), ("30", "15"), ("10080", "0"), ("43200", "1440"), ("5", "0"), ("129600", "0")]


def f(parameter, kind, *values):
    return {"parameter": parameter, "type": kind, "value": list(values)}


FILTER_SETS = [
    [f("country", "equals", "US")],
    [f("country", "equals", "US", "IN")],
    [f("country", "not_equals", "US")],
    [f("browser", "contains", "Chrome")],
    [f("browser", "not_contains", "Mobile", "Safari")],
    [f("device_type", "equals", "Desktop")],
    [f("device_type", "not_equals", "Mobile")],
    [f("hostname", "starts_with", "www.")],
    [f("hostname", "equals", "hygo.ai")],
    [f("operating_system", "ends_with", "dows")],
    [f("region", "is_null")],
    [f("region", "is_not_null")],
    [f("country", "equals")],
    [f("country", "regex", "^U")],
    [f("country", "not_regex", "[invalid")],
    [f("pathname", "equals", "/")],
    [f("pathname", "contains", "buy")],
    [f("pathname", "regex", "^/[a-z]+$")],
    [f("referrer", "equals", "google.com")],
    [f("channel", "equals", "Direct")],
    [f("channel", "not_equals", "Organic Search")],
    [f("utm_source", "equals", "chatgpt.com")],
    [f("utm_campaign", "equals", "fall")],
    [f("event_name", "equals", "calculator_valuation")],
    [f("page_title", "contains", "Vodka")],
    [f("entry_page", "equals", "/")],
    [f("exit_page", "not_equals", "/buy/success")],
    [f("user_id", "equals", "user123")],
    [f("feature_flag:beta", "equals", "on")],
    [f("dimensions", "equals", "1920x1080")],
    [f("lat", "greater_than", 40)],
    [f("querystring", "contains", "session_id")],
    [f("city", "equals", "US-MO-Kansas City")],
    [f("browser_version", "starts_with", "Chrome 1")],
    [f("operating_system_version", "equals", "Windows 10/11")],
    [f("country", "equals", "US"), f("device_type", "equals", "Desktop")],
    [f("country", "equals", "US"), f("pathname", "equals", "/")],
    [f("utm_source", "equals", "chatgpt.com"), f("event_name", "equals", "domain_search")],
    [f("hostname", "equals", "it's"), f("browser", "not_contains", "bot", "spider")],
    [f("browser", "equals", 42)],
]
RAW_FILTERS = ["", "[]", "not json", "{}", '[{"parameter":"nope","type":"equals","value":["x"]}]', '[{"parameter":"country","type":"eq","value":["x"]}]']
BUCKETS = [None, None, "minute", "five_minutes", "ten_minutes", "fifteen_minutes", "hour", "day", "day", "week", "month", "year", "", "fortnight", "constructor", "__proto__", ["day", "hour"]]
BASE_PARAMS = [
    "browser", "operating_system", "language", "country", "region", "city", "device_type", "referrer", "hostname",
    "pathname", "page_title", "querystring", "event_name", "channel", "utm_source", "utm_medium", "utm_campaign",
    "utm_term", "utm_content", "entry_page", "exit_page", "dimensions", "browser_version", "operating_system_version",
    "user_id", "lat", "lon", "timezone", "tag",
]
PARAMETERS = BASE_PARAMS + ["pathname", "country", "device_type", "event_name", "page_title", "entry_page", "exit_page", "feature_flag:beta", "url_param:session_id", "utm_foo", "nope", None, ["country", "browser"], ""]
LIMITS = [None, None, None, "10", "1", "5", "0", "-3", "abc", "2.5", "1e3", "250", "600", ["5", "6"], "0x10"]
PAGES = [None, None, None, "1", "2", "3", "0", "-1", "abc", "2.5", ["2", "3"], ""]


def add(pairs, key, value):
    if value is None:
        return
    if isinstance(value, list):
        pairs.extend((key, item) for item in value)
    else:
        pairs.append((key, value))


def gen_time(rng, pairs, allow_invalid=True):
    roll = rng.random()
    if roll < 0.12:
        return
    if roll < 0.2:
        add(pairs, "start_date", "")
        add(pairs, "end_date", "")
        if rng.random() < 0.5:
            add(pairs, "time_zone", rng.choice(TIME_ZONES))
        return
    if allow_invalid and roll > 0.965:
        add(pairs, *rng.choice([
            ("start_date", "2026-13-01"),
            ("start_datetime", "2026-09-01 00:00:00"),
            ("time_zone", "Mars/Olympus"),
            ("past_minutes_start", "-5"),
            ("start_date", "2026-09-01"),
        ]))
        if rng.random() < 0.5:
            add(pairs, "past_minutes_start", "10")
            add(pairs, "past_minutes_end", "20")
        return
    if roll < 0.55:
        a, b = sorted([rng.choice(DATES), rng.choice(DATES)])
        add(pairs, "start_date", a)
        add(pairs, "end_date", b)
    elif roll < 0.75:
        a, b = rng.choice(DATETIMES), rng.choice(DATETIMES)
        add(pairs, "start_datetime", a)
        add(pairs, "end_datetime", b)
    else:
        start, end = rng.choice(MINUTES)
        add(pairs, "past_minutes_start", start)
        add(pairs, "past_minutes_end", end)
    if rng.random() < 0.8:
        add(pairs, "time_zone", rng.choice(TIME_ZONES))


def gen_filters(rng, pairs, segments):
    roll = rng.random()
    if roll < 0.3:
        return
    if roll < 0.82:
        add(pairs, "filters", json.dumps(rng.choice(FILTER_SETS), separators=(",", ":")))
    elif roll < 0.9:
        add(pairs, "filters", rng.choice(RAW_FILTERS))
    else:
        segment = rng.choice(list(segments.values()) + ["abc", "99999999", "0"])
        add(pairs, "segment_id", str(segment))
        if rng.random() < 0.3:
            add(pairs, "filters", json.dumps(rng.choice(FILTER_SETS), separators=(",", ":")))


SITES = ["1", "2", "3", "4", "5", "7", "37", "39", "45", "46", "7c2ff798dacb", "461d87888934", "99999", "0001"]

ROUTES = [
    "live-user-count", "overview", "overview/time-series", "overview-lite", "overview-bucketed-lite", "metric-lite",
    "metric", "page-titles", "retention", "journeys", "has-data", "is-public", "events/count", "org-event-count",
]


def gen_query(rng, route, segments):
    pairs = []
    if route == "live-user-count":
        add(pairs, "minutes", rng.choice([None, None, "", "5", "30", "1440", "abc", "1.5", "0", ["5", "10"]]))
    elif route in ("overview", "overview-lite"):
        gen_time(rng, pairs)
        gen_filters(rng, pairs, segments)
    elif route in ("overview/time-series", "overview-bucketed-lite"):
        gen_time(rng, pairs)
        gen_filters(rng, pairs, segments)
        add(pairs, "bucket", rng.choice(BUCKETS))
    elif route in ("metric", "metric-lite"):
        gen_time(rng, pairs)
        gen_filters(rng, pairs, segments)
        add(pairs, "parameter", rng.choice(PARAMETERS))
        add(pairs, "limit", rng.choice(LIMITS))
        add(pairs, "page", rng.choice(PAGES))
    elif route == "page-titles":
        gen_time(rng, pairs)
        gen_filters(rng, pairs, segments)
        add(pairs, "limit", rng.choice(LIMITS))
        add(pairs, "page", rng.choice(PAGES))
    elif route == "retention":
        add(pairs, "mode", rng.choice([None, "day", "week", "DAY", "", ["day", "day"]]))
        add(pairs, "range", rng.choice([None, "7", "30", "90", "365", "1000", "3", "0", "abc", "0x20", "-5", "", "12.7"]))
        if rng.random() < 0.2:
            gen_time(rng, pairs)
    elif route == "journeys":
        gen_time(rng, pairs)
        gen_filters(rng, pairs, segments)
        add(pairs, "steps", rng.choice([None, "2", "3", "4", "5", "10", " 4", "3.9"]) if rng.random() < 0.8 else rng.choice(["11", "1", "abc", "", ["3", "4"]]))
        add(pairs, "limit", rng.choice([None, "1", "20", "500", "07"]) if rng.random() < 0.85 else rng.choice(["501", "0", "abc"]))
        add(pairs, "stepFilters", rng.choice([
            None, None, None, "", '{"0":"/"}', '{"1":"/buy/*"}', '{"0":"/","2":"/calculator/**"}', '{"a":"/"}', "[]",
            "null", '{"0":5}', "not json", '{"01":"/x","1":"/"}', '{"99999999999999999999":"/a"}', '{"0":"/it\'s"}',
            '{"2":"/b","0":"/"}', '{"1":"/**"}', '{"0":"' + "x" * 2049 + '"}',
        ]))
    elif route in ("has-data", "is-public"):
        if rng.random() < 0.2:
            gen_time(rng, pairs)
    elif route == "events/count":
        gen_time(rng, pairs)
        gen_filters(rng, pairs, segments)
        add(pairs, "bucket", rng.choice(BUCKETS + ["toString"]))
    elif route == "org-event-count":
        gen_time(rng, pairs)
    return pairs


def principal_headers(rng, private_keys, site):
    """(label, headers, extra query pairs)"""
    choice = rng.choices(
        [
            "anon", "session-sysadmin", "session-member", "session-other", "org-full", "org-analytics", "org-events",
            "org-sites", "org-goals", "org-deny", "testorg-full", "user-member", "user-member-analytics", "query-key",
            "private-link", "private-link-wrong", "bad-bearer", "origin-trusted", "origin-untrusted",
        ],
        weights=[8, 30, 10, 5, 12, 5, 4, 4, 3, 2, 3, 5, 2, 3, 4, 2, 2, 2, 2],
    )[0]
    headers = {}
    extra = []
    if choice.startswith("session-"):
        headers["Cookie"] = signed_cookie(session_token(choice[len("session-"):]))
    elif choice in API_KEYS:
        headers["Authorization"] = f"Bearer {key_secret(choice)}"
    elif choice == "query-key":
        extra.append(("api_key", key_secret("org-full")))
    elif choice == "private-link":
        numeric = {"7c2ff798dacb": 1, "461d87888934": 4}.get(site) or (int(site) if site.isdigit() else None)
        key = private_keys.get(numeric) or rng.choice(list(private_keys.values()))
        headers["x-private-key"] = key
    elif choice == "private-link-wrong":
        headers["x-private-key"] = "not-the-key"
    elif choice == "bad-bearer":
        headers["Authorization"] = "Bearer rb_nothing_here"
    elif choice == "origin-trusted":
        headers["Origin"] = "https://a.hygo.ai"
        headers["Cookie"] = signed_cookie(session_token("sysadmin"))
    elif choice == "origin-untrusted":
        headers["Origin"] = "https://evil.example"
        headers["Cookie"] = signed_cookie(session_token("sysadmin"))
    return choice, headers, extra


def build_requests(seed, per_route, segments, private_keys):
    rng = random.Random(seed)
    built = []
    for route in ROUTES:
        for _ in range(per_route):
            if route == "org-event-count":
                target = rng.choice([HYGO_ORG, HYGO_ORG, TEST_ORG, "not-an-org"])
                path = f"/api/org-event-count/{target}"
                site = None
            else:
                site = rng.choice(SITES)
                path = f"/api/sites/{site}/{route}"
            label, headers, extra = principal_headers(rng, private_keys, site or "")
            pairs = gen_query(rng, route, segments) + extra
            query = urllib.parse.urlencode(pairs, quote_via=urllib.parse.quote)
            method = "HEAD" if rng.random() < 0.01 else "GET"
            built.append({"route": route, "principal": label, "method": method, "path": path + (f"?{query}" if query else ""), "headers": headers})
    rng.shuffle(built)
    return built


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------
local = threading.local()


def session():
    if not hasattr(local, "session"):
        local.session = requests.Session()
    return local.session


def send(base, request):
    try:
        response = session().request(request["method"], base + request["path"], headers=request["headers"], allow_redirects=False, timeout=180)
        content_type = (response.headers.get("content-type") or "").lower().replace(" ", "")
        watched = {name: response.headers.get(name) for name in ("cache-control", "x-content-type-options", "access-control-allow-origin", "access-control-allow-credentials", "vary")}
        return {"status": response.status_code, "content_type": content_type, "body": response.content, "headers": watched}
    except requests.RequestException as error:
        return {"status": -1, "content_type": "", "body": str(error).encode(), "headers": {}}


def same(a, b):
    return a["status"] == b["status"] and a["content_type"] == b["content_type"] and a["body"] == b["body"]


def normalize_vary(value):
    return None if value is None else ",".join(sorted(token.strip().lower() for token in value.split(",")))


def header_diff(a, b):
    diffs = {}
    for name in a["headers"]:
        left, right = a["headers"].get(name), b["headers"].get(name)
        if name == "vary":
            left, right = normalize_vary(left), normalize_vary(right)
        if left != right:
            diffs[name] = [left, right]
    return diffs


def show(response):
    body = response["body"]
    try:
        text = body.decode()
    except UnicodeDecodeError:
        text = repr(body)
    return {"status": response["status"], "content_type": response["content_type"], "body": text[:4000]}


def run_pair(request):
    node = send(NODE, request)
    rust = send(RUST, request)
    if same(node, rust):
        return {"outcome": "identical", "header_diff": header_diff(node, rust), "request": request, "status": node["status"]}
    # Retry: data is being ingested concurrently by other agents
    for _ in range(2):
        node_again = send(NODE, request)
        rust_again = send(RUST, request)
        if same(node_again, rust_again):
            return {"outcome": "transient", "request": request, "status": node_again["status"], "first": {"node": show(node), "rust": show(rust)}}
    node_third = send(NODE, request)
    if not same(node_again, node_third):
        return {"outcome": "node-nondeterministic", "request": request, "status": node["status"], "node": show(node_again), "node_again": show(node_third), "rust": show(rust_again)}
    return {"outcome": "different", "request": request, "status": node_again["status"], "node": show(node_again), "rust": show(rust_again)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs-per-route", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20260917)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out", default="overview_http_parity.json")
    parser.add_argument("--routes", default=",".join(ROUTES))
    args = parser.parse_args()

    connection = psycopg2.connect(PG_DSN)
    connection.autocommit = True
    cursor = connection.cursor()
    segments, private_keys = setup(cursor)
    print(f"setup: {len(API_KEYS)} api keys, {len(USERS)} sessions, segments {segments}", flush=True)

    started = time.time()
    try:
        wanted = set(args.routes.split(","))
        requests_to_send = [item for item in build_requests(args.seed, args.pairs_per_route, segments, private_keys) if item["route"] in wanted]
        results = []
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for index, result in enumerate(pool.map(run_pair, requests_to_send), 1):
                results.append(result)
                if index % 500 == 0:
                    counts = Counter(item["outcome"] for item in results)
                    print(f"{index}/{len(requests_to_send)} {dict(counts)} {time.time() - started:.0f}s", flush=True)
    finally:
        cleanup(cursor)
        connection.close()

    per_route = defaultdict(Counter)
    statuses = defaultdict(Counter)
    header_diffs = []
    for item in results:
        per_route[item["request"]["route"]][item["outcome"]] += 1
        statuses[item["request"]["route"]][item["status"]] += 1
        if item.get("header_diff"):
            header_diffs.append({"request": item["request"], "diff": item["header_diff"]})
    report = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "node": NODE,
        "rust": RUST,
        "seed": args.seed,
        "pairs": len(results),
        "elapsed_seconds": round(time.time() - started),
        "per_route": {route: dict(counts) for route, counts in per_route.items()},
        "statuses": {route: dict(counts) for route, counts in statuses.items()},
        "different": [item for item in results if item["outcome"] == "different"],
        "nondeterministic": [item for item in results if item["outcome"] == "node-nondeterministic"],
        "transient": [item for item in results if item["outcome"] == "transient"],
        "header_diffs": header_diffs,
    }
    with open(args.out, "w") as handle:
        json.dump(report, handle, indent=1, default=str)
    print(json.dumps({"pairs": report["pairs"], "per_route": report["per_route"], "statuses": report["statuses"], "header_diffs": len(header_diffs)}, indent=1))
    print(f"report: {args.out}")
    return 1 if report["different"] else 0


if __name__ == "__main__":
    sys.exit(main())
