#!/usr/bin/env python3
"""HTTP differential harness for the reports routes (funnels, goals, performance,
bots). Every read request goes to Node and the Rust port at the same moment;
status, the content type and error headers, and the body bytes must be identical.
Writes run one backend at a time against fresh fixture rows and also compare the
rows each backend leaves behind (ids normalised).

Usage:
  harness.py GROUP [GROUP ...]     groups: misc funnels goals performance bots writes
Environment:
  NODE_PORT (3001), RUST_PORT (3047), SCALE (cases per group unit, 400), SEED,
  OUT (results json path). Needs fixtures.py setup first.
"""
import concurrent.futures as futures
import http.client
import json
import os
import random
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

NODE = int(os.environ.get("NODE_PORT", "3001"))
RUST = int(os.environ.get("RUST_PORT", "3047"))
rng = random.Random(int(os.environ.get("SEED", "20260917")))
OUT = os.environ.get("OUT", "results.json")
COMPARED_HEADERS = ["content-type", "cache-control", "x-content-type-options", "connection"]


def send(port, method, path, headers, body):
    for attempt in range(3):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=180)
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
            headers = {name: response.getheader(name) for name in COMPARED_HEADERS}
            # Node spells out HTTP/1.1 keep-alive and hyper leaves it implicit; only `close` is a difference
            if (headers["connection"] or "").lower() == "keep-alive":
                headers["connection"] = None
            result = {
                "status": response.status,
                "headers": headers,
                "body": data.decode("utf-8", errors="replace"),
            }
            conn.close()
            return result
        except (ConnectionError, http.client.HTTPException, OSError) as error:
            if attempt == 2:
                return {"status": -1, "headers": {}, "body": f"transport error: {error}"}
            time.sleep(0.5)


def auth_headers(auth):
    headers = {}
    if auth is None:
        return headers
    kind, _, name = auth.partition(":")
    if kind == "key":
        headers["Authorization"] = "Bearer " + fixtures.token(name)
    elif kind == "cookie":
        headers["Cookie"] = fixtures.cookie(name)
    elif kind == "private":
        headers["X-Private-Key"] = name
    return headers


class Case:
    def __init__(self, route, method, path, auth=None, body=None, content_type="application/json"):
        self.route = route
        self.method = method
        self.path = path
        self.auth = auth
        self.body = body
        self.content_type = content_type

    def headers(self):
        headers = auth_headers(self.auth)
        if self.body is not None and self.content_type:
            headers["Content-Type"] = self.content_type
        return headers

    def raw_body(self):
        return self.body.encode() if isinstance(self.body, str) else self.body

    def describe(self):
        return {"method": self.method, "path": self.path, "auth": self.auth, "body": self.body, "contentType": self.content_type}


def pair(case):
    with futures.ThreadPoolExecutor(max_workers=2) as pool:
        node = pool.submit(send, NODE, case.method, case.path, case.headers(), case.raw_body())
        rust = pool.submit(send, RUST, case.method, case.path, case.headers(), case.raw_body())
        return node.result(), rust.result()


def same(node, rust):
    return node["status"] == rust["status"] and node["headers"] == rust["headers"] and node["body"] == rust["body"]


results = {"routes": {}, "differences": [], "flaky": []}


def flush_results():
    with open(OUT, "w") as handle:
        json.dump(results, handle, indent=1)


def record(route, ok, case=None, node=None, rust=None, note=None):
    counts = results["routes"].setdefault(route, {"pairs": 0, "identical": 0, "different": 0, "statuses": {}})
    counts["pairs"] += 1
    counts["identical" if ok else "different"] += 1
    if not ok:
        entry = {"route": route, "request": case.describe() if case else None, "node": node, "rust": rust}
        if note:
            entry["note"] = note
        results["differences"].append(entry)
    if node is not None:
        key = str(node["status"])
        counts["statuses"][key] = counts["statuses"].get(key, 0) + 1


def run_read_cases(cases, workers=8):
    """Each pair is retried twice when it differs (both backends read live
    stores that other processes write to); a pair that then matches is kept in
    `flaky` with its first outputs."""

    def one(case):
        node, rust = pair(case)
        first = (node, rust)
        retried = False
        for _ in range(2):
            if same(node, rust):
                break
            time.sleep(0.3)
            node, rust = pair(case)
            retried = True
        if not same(node, rust):
            # ClickHouse returns ties under ORDER BY in no fixed order, so Node alone
            # can answer one request with different bodies: accept Rust's answer when
            # Node itself produces it within a few more tries
            for _ in range(8):
                again = send(NODE, case.method, case.path, case.headers(), case.raw_body())
                if same(again, rust):
                    node = again
                    break
        return case, node, rust, retried, first

    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for index, (case, node, rust, retried, first) in enumerate(pool.map(one, cases), start=1):
            ok = same(node, rust)
            if ok and retried:
                results["flaky"].append({"route": case.route, "request": case.describe(), "node": first[0], "rust": first[1]})
            record(case.route, ok, case, node, rust)
            if index % 250 == 0:
                print(f"  {index}/{len(cases)} pairs, {len(results['differences'])} differences", flush=True)
                flush_results()


# ---------------------------------------------------------------------------
# Input pools
# ---------------------------------------------------------------------------
def q(params):
    if not params:
        return ""
    return "?" + "&".join(f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}" for k, v in params)


FILTERS = [
    '[{"parameter":"browser","type":"equals","value":["Chrome"]}]',
    '[{"parameter":"utm_campaign","type":"equals","value":["launch"]}]',
    '[{"parameter":"pathname","type":"contains","value":["/blog"]}]',
    '[{"parameter":"pathname","type":"starts_with","value":["/buy"]}]',
    '[{"parameter":"event_name","type":"equals","value":["domain_search"]}]',
    '[{"parameter":"channel","type":"not_equals","value":["Direct"]}]',
    '[{"parameter":"country","type":"equals","value":["US"]},{"parameter":"device_type","type":"equals","value":["Desktop"]}]',
    '[{"parameter":"entry_page","type":"equals","value":["/"]}]',
    '[{"parameter":"exit_page","type":"regex","value":["^/buy"]}]',
    '[{"parameter":"user_id","type":"is_not_null","value":[]}]',
    '[{"parameter":"referrer","type":"equals","value":["google.com"]}]',
    '[{"parameter":"lat","type":"greater_than","value":["20"]}]',
    '[{"parameter":"lat","type":"greater_than","value":["north"]}]',
    '[{"parameter":"pathname","type":"regex","value":["(unclosed"]}]',
    '[{"parameter":"hostname","type":"equals","value":["domhaul.com"]}]',
    '[{"parameter":"browser","type":"not_equals","value":["Chrome","Firefox"]},{"parameter":"operating_system","type":"equals","value":["Windows"]}]',
    '[{"parameter":"city","type":"is_null","value":[]}]',
    '[{"parameter":"asn_org","type":"equals","value":["x"]}]',
    '[{"parameter":"feature_flag:beta","type":"equals","value":["true"]}]',
    '[{"parameter":"utm_source","type":"equals","value":["google"]},{"parameter":"browser_version","type":"equals","value":["Chrome 140"]}]',
    "[]",
    "",
    "not json",
    '{"parameter":"browser"}',
]
TIME_WINDOWS = [
    [],
    [("start_date", "2026-09-01"), ("end_date", "2026-09-17"), ("time_zone", "UTC")],
    [("start_date", "2026-06-01"), ("end_date", "2026-09-17"), ("time_zone", "America/Chicago")],
    [("start_date", "2026-09-10"), ("end_date", "2026-09-16"), ("time_zone", "Asia/Kolkata")],
    [("start_date", "2026-08-01"), ("end_date", "2026-08-31")],
    [("start_date", ""), ("end_date", ""), ("time_zone", "UTC")],
    [("start_datetime", "2026-09-10 00:00:00"), ("end_datetime", "2026-09-17T00:00:00Z"), ("time_zone", "UTC")],
    [("start_datetime", "2026-09-16T08:30:00+02:00"), ("end_datetime", "2026-09-17 06:00:00"), ("time_zone", "Europe/Berlin")],
    [("past_minutes_start", "100000"), ("past_minutes_end", "60")],
    [("start_date", "2026-02-30"), ("end_date", "2026-03-01")],
    [("start_date", "2026-09-01")],
    [("time_zone", "Not/AZone")],
    [("start_datetime", "2026-09-17 00:00:00"), ("end_datetime", "2026-09-10 00:00:00")],
    [("past_minutes_start", "5"), ("past_minutes_end", "10")],
    [("start_date", "2026-09-01"), ("start_date", "2026-09-02"), ("end_date", "2026-09-17")],
    [("time_zone", "America/New_York")],
]
AUTHS = [
    None, "cookie:member", "cookie:owner", "cookie:other-owner", "key:member", "key:member-scoped-read",
    "key:member-scoped-segments", "key:org", "key:org-analytics-only", "key:org-writer", "key:other-org",
    "key:other-owner", "private:bbcc8977bf28", "private:169c6bb7a95d", "private:wrong",
]
READ_AUTH_WEIGHTS = [3, 5, 3, 1, 4, 2, 1, 3, 2, 2, 1, 1, 1, 1, 1]


def auth():
    return rng.choices(AUTHS, weights=READ_AUTH_WEIGHTS)[0]


def common_params():
    params = list(rng.choice(TIME_WINDOWS))
    if rng.random() < 0.45:
        params.append(("filters", rng.choice(FILTERS)))
    if rng.random() < 0.1:
        params.append(("segment_id", rng.choice(SEGMENT_IDS + ["999", "abc", ""])))
    if rng.random() < 0.05:
        params.append(("api_key", fixtures.token(rng.choice(["member", "org", "member-scoped-read"]))))
    return params


SEGMENT_IDS = []
GOAL_IDS = []

# ---------------------------------------------------------------------------
# Funnels
# ---------------------------------------------------------------------------
STEP_TYPES = ["page", "page", "page", "event", "event", "outbound", "button_click", "form_submit", "copy", "path", "", 5, None]
PAGE_VALUES = ["/", "**", "/buy/success", "/buy**", "/blog/*", "/calculator", "/healthiest-*", "/careers/**", "", "/a.b+c?", "/x'y"]
EVENT_VALUES = ["domain_search", "calculator_valuation", "checkout_started", "signup", "hiring_careers_viewed", "", "x'y"]
AUTO_VALUES = ["*", "https://**", "Buy*", "  ", "", "signup"]
WEIRD = [None, 5, True, ["a", "b"], {"a": 1}, 0]


def gen_step():
    if rng.random() < 0.02:
        return rng.choice([None, 5, "step"])
    kind = rng.choice(STEP_TYPES)
    step = {"type": kind}
    if rng.random() < 0.95:
        if kind == "page":
            step["value"] = rng.choice(PAGE_VALUES) if rng.random() < 0.95 else rng.choice(WEIRD)
        elif kind in ("outbound", "button_click", "form_submit", "copy"):
            step["value"] = rng.choice(AUTO_VALUES) if rng.random() < 0.9 else rng.choice(WEIRD)
        else:
            step["value"] = rng.choice(EVENT_VALUES) if rng.random() < 0.9 else rng.choice(WEIRD)
    if rng.random() < 0.5:
        step["name"] = rng.choice(["Landing", "Checkout", "", "123", "Paid"]) if rng.random() < 0.9 else rng.choice(WEIRD)
    if rng.random() < 0.15:
        step["hostname"] = rng.choice(["domhaul.com", "", "www.domhaul.com"]) if rng.random() < 0.8 else rng.choice(WEIRD)
    if rng.random() < 0.15:
        step["propertyFilters"] = rng.choice([
            [{"key": "utm_source", "value": "google"}],
            [{"key": "plan", "value": "pro"}, {"key": "amount", "value": 10}],
            [{"key": "flag", "value": True}],
            [], "ab", 5, [None],
        ])
    if rng.random() < 0.07:
        step["eventPropertyKey"] = "plan"
        step["eventPropertyValue"] = rng.choice(["pro", 5, False])
    return step


def valid_step():
    kind = rng.choice(["page", "event", "outbound", "button_click", "form_submit", "copy"])
    if kind == "page":
        value = rng.choice(PAGE_VALUES[:8])
    elif kind == "event":
        value = rng.choice(EVENT_VALUES[:5])
    else:
        value = rng.choice(AUTO_VALUES)
    step = {"type": kind, "value": value}
    if rng.random() < 0.5:
        step["name"] = rng.choice(["Landing", "Checkout", "Paid", "Größe 😀", 'q"uote'])
    if rng.random() < 0.2:
        step["propertyFilters"] = [{"key": "plan", "value": rng.choice(["pro", 3, True, 1.5e-7, 1e21])}]
    if rng.random() < 0.1:
        step["hostname"] = "domhaul.com"
    if rng.random() < 0.05:
        step["extra"] = {"nested": [1, None, {"b": 2, "a": 1, "10": 3, "2": 4}]}
    return step


def gen_steps_body():
    roll = rng.random()
    if roll < 0.04:
        return None, None
    if roll < 0.07:
        return "{not json", "application/json"
    if roll < 0.09:
        return json.dumps({"steps": [gen_step(), gen_step()]}), "text/plain"
    if roll < 0.11:
        return "null", "application/json"
    if roll < 0.13:
        return json.dumps({"steps": rng.choice(["abcd", {"length": 3}, 5, None, []])}), "application/json"
    if roll < 0.14:
        return "", "application/json"
    if roll < 0.55:
        return json.dumps({"steps": [valid_step() for _ in range(rng.choice([2, 2, 3, 4]))]}), "application/json"
    return json.dumps({"steps": [gen_step() for _ in range(rng.choice([1, 2, 2, 3, 3, 4, 5]))]}), "application/json"


def funnel_cases(count):
    cases = []
    for _ in range(count // 10):
        site = rng.choice(["4", "37", "1", "5", "461d87888934", "3", "99999", "abc"])
        cases.append(Case("GET funnels", "GET", f"/api/sites/{site}/funnels{q(common_params())}", auth()))
    for _ in range(count // 2):
        site = rng.choice(["4", "4", "4", "37", "3", "1", "5", "461d87888934"])
        body, ctype = gen_steps_body()
        cases.append(Case("POST funnels/analyze", "POST", f"/api/sites/{site}/funnels/analyze{q(common_params())}", auth(), body, ctype))
    for _ in range(count - count // 2 - count // 10):
        site = rng.choice(["4", "4", "3", "37", "1", "5"])
        step = rng.choice(["1", "2", "3", "1", "2", "0", "-1", "abc", "2.9", "99", "1e1", " 2"])
        params = common_params()
        if rng.random() < 0.9:
            params.append(("mode", rng.choice(["reached", "reached", "dropped", "dropped", "other", ""])))
        if rng.random() < 0.4:
            params.append(("limit", rng.choice(["10", "5", "0", "abc", "", "1.5"])))
        if rng.random() < 0.4:
            params.append(("page", rng.choice(["1", "2", "0", "x", "1.5"])))
        body, ctype = gen_steps_body()
        path = f"/api/sites/{site}/funnels/{urllib.parse.quote(step)}/sessions{q(params)}"
        cases.append(Case("POST funnels/:stepNumber/sessions", "POST", path, auth(), body, ctype))
    return cases


# ---------------------------------------------------------------------------
# Goals (reads)
# ---------------------------------------------------------------------------
def goal_cases(count):
    ids = GOAL_IDS
    cases = []
    for _ in range(count // 3):
        site = rng.choice(["4", "4", "37", "3", "5", "1", "461d87888934"])
        params = common_params()
        for name, pool in [("page", ["1", "2", "0", "abc", "", "3", "1e3"]), ("page_size", ["10", "5", "100", "101", "0", "x", "3"]),
                           ("sort", ["goalId", "name", "goalType", "createdAt", "bogus"]), ("order", ["asc", "desc", "ASC", ""])]:
            if rng.random() < 0.4:
                params.append((name, rng.choice(pool)))
        cases.append(Case("GET goals", "GET", f"/api/sites/{site}/goals{q(params)}", auth()))
    for _ in range(count // 3):
        site = rng.choice(["4", "4", "37", "3", "5"])
        params = common_params()
        if rng.random() < 0.85:
            params.append(("bucket", rng.choice(["hour", "day", "week", "month", "minute", "fifteen_minutes", "year", "", "hourly", "toString", "__proto__"])))
        if rng.random() < 0.9:
            chosen = rng.sample(ids, k=min(len(ids), rng.choice([1, 2, 3, 5])))
            style = rng.choice(["csv", "json", "repeat", "weird"])
            if style == "csv":
                params.append(("goal_ids", ",".join(str(i) for i in chosen)))
            elif style == "json":
                params.append(("goal_ids", json.dumps(chosen)))
            elif style == "repeat":
                params.extend(("goal_ids", str(i)) for i in chosen)
            else:
                params.append(("goal_ids", rng.choice(["", "abc", "1.5", "99999999999", '["1", null]', " ", "0", "1,,2", "[]"])))
        cases.append(Case("GET goals/time-series", "GET", f"/api/sites/{site}/goals/time-series{q(params)}", auth()))
    for _ in range(count - 2 * (count // 3)):
        site = rng.choice(["4", "4", "37", "3", "5"])
        goal = str(rng.choice(ids)) if rng.random() < 0.85 else rng.choice(["99999", "abc", "1.5", "0", "0x3", "99999999999"])
        params = common_params()
        if rng.random() < 0.4:
            params.append(("limit", rng.choice(["10", "5", "0", "abc", ""])))
        if rng.random() < 0.4:
            params.append(("page", rng.choice(["1", "2", "0", "x"])))
        cases.append(Case("GET goals/:goalId/sessions", "GET", f"/api/sites/{site}/goals/{urllib.parse.quote(goal)}/sessions{q(params)}", auth()))
    return cases


# ---------------------------------------------------------------------------
# Performance and bots
# ---------------------------------------------------------------------------
def performance_cases(count):
    cases = []
    for _ in range(count):
        site = rng.choice(["1", "39", "4", "5", "3", "461d87888934"])
        params = common_params()
        route = rng.choice(["overview", "time-series", "by-dimension"])
        if route == "time-series" and rng.random() < 0.85:
            params.append(("bucket", rng.choice(["hour", "day", "week", "month", "minute", "five_minutes", "year", "", "bogus", "toString"])))
        if route == "by-dimension":
            if rng.random() < 0.95:
                params.append(("dimension", rng.choice(["pathname", "country", "device_type", "browser", "operating_system", "region", "city", ""])))
            if rng.random() < 0.5:
                params.append(("sort_by", rng.choice(["event_count", "lcp_p75", "cls_avg", "ttfb_p99", "pathname", "nope"])))
            if rng.random() < 0.5:
                params.append(("sort_order", rng.choice(["asc", "desc", "ASC"])))
            if rng.random() < 0.4:
                params.append(("limit", rng.choice(["10", "1", "0", "abc"])))
            if rng.random() < 0.4:
                params.append(("page", rng.choice(["1", "2", "0", "x"])))
        cases.append(Case(f"GET performance/{route}", "GET", f"/api/sites/{site}/performance/{route}{q(params)}", auth()))
    return cases


BOT_DIMENSIONS = ["browser", "country", "pathname", "referrer", "city", "dimensions", "operating_system_version", "browser_version",
                  "asn_org", "asn_provider", "bot_category", "bot_name", "bot_operator", "bot_purpose", "matched_ua_pattern", "event_name", ""]


def bot_cases(count):
    cases = []
    for _ in range(count):
        site = rng.choice(["3", "4", "39", "37", "1", "5", "2"])
        params = common_params()
        route = rng.choice(["overview", "time-series", "by-dimension", "ai-summary"])
        if route != "ai-summary" and rng.random() < 0.4:
            params.append(("layer", rng.choice(["ua_pattern", "header_heuristics", "client_signals", "bot_asn", "rate_anomaly", "", "nope", "toString"])))
        if route in ("time-series", "by-dimension") and rng.random() < 0.4:
            params.append(("purpose", rng.choice(["ai", "ai_crawler", "ai_agent", "seo", "search", "monitoring", "", "nope"])))
        if route == "time-series" and rng.random() < 0.85:
            params.append(("bucket", rng.choice(["hour", "day", "week", "month", "minute", "year", "", "bogus"])))
        if route == "by-dimension":
            if rng.random() < 0.95:
                params.append(("dimension", rng.choice(BOT_DIMENSIONS)))
            if rng.random() < 0.4:
                params.append(("limit", rng.choice(["10", "1", "0", "abc"])))
            if rng.random() < 0.4:
                params.append(("page", rng.choice(["1", "2", "0", "x"])))
        cases.append(Case(f"GET bots/{route}", "GET", f"/api/sites/{site}/bots/{route}{q(params)}", auth()))
    return cases


def misc_cases():
    """Routing edges, body parsing edges and method shadowing."""
    cases = []
    two_steps = json.dumps({"steps": [{"type": "page", "value": "/"}, {"type": "page", "value": "/buy/success"}]})
    for who in [None, "cookie:member", "key:org-writer", "key:member-scoped-read", "key:member"]:
        cases += [
            Case("routing", "GET", "/api/sites/4/funnels/analyze", who),
            Case("routing", "GET", "/api/sites/4/goals/time-series/sessions", who),
            Case("routing", "POST", "/api/sites/4/funnels/analyze/sessions", who, two_steps),
            Case("routing", "GET", "/api/sites/4/goals/", who),
            Case("routing", "GET", "/api/sites/4/funnels/", who),
            Case("routing", "GET", "/api/sites/%zz/funnels", who),
            Case("routing", "GET", "/api/sites/abc/funnels", who),
            Case("routing", "GET", "/api/sites/1.5/goals", who),
            Case("routing", "GET", "/api/sites/4/performance/overview/", who),
            Case("routing", "HEAD", "/api/sites/4/funnels", who),
            Case("routing", "GET", "/api/sites/" + "9" * 1501 + "/funnels", who),
            Case("routing", "POST", "/api/sites/4/funnels/analyze", who, "{}", "application/xml"),
            Case("routing", "POST", "/api/sites/4/funnels/analyze", who, '{"steps":[1,2],"__proto__":{"x":1}}'),
            Case("routing", "POST", "/api/sites/4/funnels/analyze", who, two_steps, "application/json; charset=utf-8"),
            Case("routing", "PUT", "/api/sites/4/funnels/analyze", who, "{}"),
            Case("routing", "GET", "/api/sites/4/bots", who),
            Case("routing", "GET", "/api/sites/4/funnels?segment_id=" + (SEGMENT_IDS[0] if SEGMENT_IDS else "1"), who),
        ]
    return cases


# ---------------------------------------------------------------------------
# Writes: one backend at a time; compare responses (ids normalised) and rows
# ---------------------------------------------------------------------------
def psql_json(sql):
    out = fixtures.psql(sql).strip()
    return json.loads(out) if out else None


def funnel_row(report_id):
    return psql_json(
        "SELECT row_to_json(t) FROM (SELECT site_id, user_id, data::text AS data, created_at IS NOT NULL AS has_created, "
        "abs(extract(epoch FROM (now() AT TIME ZONE 'utc') - updated_at)) < 120 AS recently_updated "
        f"FROM funnels WHERE report_id = {int(report_id)}) t"
    )


def goal_row(goal_id):
    return psql_json(
        "SELECT row_to_json(t) FROM (SELECT site_id, name, goal_type, config::text AS config, created_at IS NOT NULL AS has_created "
        f"FROM goals WHERE goal_id = {int(goal_id)}) t"
    )


ID_KEYS = re.compile(r'"(funnelId|goalId)":(\d+)')


def normalise(response, mapping):
    body = response["body"]
    for real, placeholder in mapping.items():
        body = body.replace(f'"funnelId":{real}', f'"funnelId":"{placeholder}"').replace(f'"goalId":{real}', f'"goalId":"{placeholder}"')
    return {**response, "body": body}


def new_ids(response):
    return [int(match.group(2)) for match in ID_KEYS.finditer(response["body"])]


def insert_funnel(site, name):
    data = json.dumps({"name": name, "steps": [{"type": "page", "value": "/"}, {"type": "event", "value": "signup"}]})
    return int(fixtures.psql(f"INSERT INTO funnels (site_id, user_id, data) VALUES ({site}, NULL, {fixtures.q(data)}::jsonb) RETURNING report_id").split()[0])


def insert_goal(site, name):
    return int(fixtures.psql(
        f"INSERT INTO goals (site_id, name, goal_type, config) VALUES ({site}, {fixtures.q(name)}, 'path', '{{\"pathPattern\": \"/\"}}'::jsonb) RETURNING goal_id"
    ).split()[0])


created = {"funnels": set(), "goals": set()}


def gen_funnel_create_body():
    name = "parity-reports-created"
    roll = rng.random() + 0.5 * (rng.random() < 0.7)
    if roll < 0.05:
        return None, None
    if roll < 0.08:
        return "null", "application/json"
    if roll < 0.1:
        return "[1,2]", "application/json"
    if roll < 0.12:
        return json.dumps({"steps": "abcd", "name": name}), "application/json"
    if roll < 0.14:
        return json.dumps({"steps": [{"type": "page", "value": "/"}, None], "name": name}), "application/json"
    if roll < 0.16:
        return json.dumps({"steps": [{"type": "page", "value": "/"}, {"type": "page", "value": "/x"}]}), "text/plain"
    if rng.random() < 0.8:
        body = {"steps": [valid_step() for _ in range(rng.choice([2, 2, 3, 4]))]}
    else:
        body = {"steps": [gen_step() for _ in range(rng.choice([0, 1, 2, 2, 3, 4]))]}
    if rng.random() < 0.95:
        body["name"] = rng.choice([name, name, name, name, name, "", 5, {"x": 1}])
    return json.dumps(body), "application/json"


def gen_goal_body():
    if rng.random() < 0.55:
        kind = rng.choice(["path", "event", "outbound", "button_click", "form_submit", "copy"])
        config = {"path": {"pathPattern": rng.choice(["/buy/**", "/", "/a*b"])}, "event": {"eventName": rng.choice(["signup", "domain_search"])}}.get(kind, {})
        if kind not in ("path", "event") and rng.random() < 0.6:
            config["valuePattern"] = rng.choice(["*", "https://**", "Buy now", "é" * 10])
        if rng.random() < 0.3:
            config["propertyFilters"] = [{"key": "plan", "value": rng.choice(["pro", 7, False, 0.1])}]
        if kind == "event" and rng.random() < 0.2:
            config["eventPropertyKey"] = "plan"
            config["eventPropertyValue"] = rng.choice(["pro", 2, True])
        if rng.random() < 0.1:
            config["unknown"] = 1
        body = {"goalType": kind, "config": config}
        if rng.random() < 0.7:
            body["name"] = rng.choice(["parity-reports-created", "", "parity-reports-ünï"])
        return json.dumps(body), "application/json"
    kind = rng.choice(["path", "event", "outbound", "button_click", "form_submit", "copy", "pageview", None])
    body = {}
    if kind is not None:
        body["goalType"] = kind
    if rng.random() < 0.6:
        body["name"] = rng.choice(["parity-reports-created", "", 7])
    config = {}
    for key, pool in [("pathPattern", ["/buy/**", "", 5]), ("eventName", ["signup", "", None]), ("valuePattern", ["*", "x" * 513, ""]),
                      ("eventPropertyKey", ["plan", ""]), ("eventPropertyValue", ["pro", 3, True, None])]:
        if rng.random() < 0.35:
            config[key] = rng.choice(pool)
    if rng.random() < 0.3:
        config["propertyFilters"] = rng.choice([[{"key": "utm_source", "value": "google"}], [{"key": "a", "value": None}], "x", [{"key": 1, "value": 2.5}]])
    if rng.random() < 0.93:
        body["config"] = config if rng.random() < 0.95 else rng.choice([None, "x"])
    if rng.random() < 0.04:
        return None, None
    if rng.random() < 0.03:
        return "not json", "application/json"
    return json.dumps(body), "application/json"


WRITE_AUTHS = [None, "cookie:member", "cookie:owner", "cookie:other-owner", "key:member", "key:member-scoped-read", "key:org",
               "key:org-writer", "key:org-analytics-only", "key:other-org"]
WRITE_WEIGHTS = [1, 8, 3, 1, 4, 1, 3, 5, 1, 1]


def write_pair(route, build, rows_of):
    """build(server) -> (Case, id_mapping, row_ids); Node runs first, then Rust
    against its own freshly inserted rows."""
    node_case, node_map, node_rows = build("node")
    node = send(NODE, node_case.method, node_case.path, node_case.headers(), node_case.raw_body())
    rust_case, rust_map, rust_rows = build("rust")
    rust = send(RUST, rust_case.method, rust_case.path, rust_case.headers(), rust_case.raw_body())
    for identifier in new_ids(node):
        node_map.setdefault(identifier, "id")
    for identifier in new_ids(rust):
        rust_map.setdefault(identifier, "id")
    node_n, rust_n = normalise(node, node_map), normalise(rust, rust_map)
    node_ids = node_rows + [i for i in new_ids(node) if i not in node_rows]
    rust_ids = rust_rows + [i for i in new_ids(rust) if i not in rust_rows]
    node_state = [rows_of(i) for i in node_ids]
    rust_state = [rows_of(i) for i in rust_ids]
    ok = same(node_n, rust_n) and node_state == rust_state
    note = None if node_state == rust_state else {"node_rows": node_state, "rust_rows": rust_state}
    record(route, ok, node_case, node_n, rust_n, note)
    return node_ids + rust_ids


def matching_site(site):
    return {"4": 4, "37": 37, "461d87888934": 4}.get(site, 4) if rng.random() < 0.85 else rng.choice([4, 37])


def write_cases(count):
    for index in range(count):
        if index and index % 50 == 0:
            print(f"  {index}/{count} writes, {len(results['differences'])} differences", flush=True)
            flush_results()
        kind = rng.choice(["create funnel", "update funnel", "delete funnel", "create goal", "update goal", "delete goal"])
        who = rng.choices(WRITE_AUTHS, weights=WRITE_WEIGHTS)[0]
        site = rng.choice(["4", "4", "4", "37", "37", "5", "1", "461d87888934"])
        if kind == "create funnel":
            body, ctype = gen_funnel_create_body()

            def build(server, body=body, ctype=ctype, who=who, site=site):
                return Case("POST funnels", "POST", f"/api/sites/{site}/funnels", who, body, ctype), {}, []

            created["funnels"].update(write_pair("POST funnels", build, funnel_row))
        elif kind == "update funnel":
            body, ctype = gen_funnel_create_body()
            target_site = matching_site(site)
            variant = rng.choice(["own", "own", "own", "missing", "string", "bad", "bad"])
            bad = rng.choice(["abc", True, "own-list", 1.5, "own-nested", "own-padded", "own-pair", "own-bool-list", {"a": 1}, []])

            def build(server, body=body, ctype=ctype, who=who, site=site, target_site=target_site, variant=variant, bad=bad):
                funnel = insert_funnel(target_site, "parity-reports-update")
                created["funnels"].add(funnel)
                try:
                    parsed = json.loads(body) if body and ctype == "application/json" else None
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    own_forms = {"own-list": [funnel], "own-nested": [[str(funnel)]], "own-padded": f" {funnel} ", "own-pair": [funnel, funnel], "own-bool-list": [True, funnel]}
                    report = {"own": funnel, "missing": 999999, "string": str(funnel), "bad": own_forms.get(bad, bad) if isinstance(bad, str) else bad}[variant]
                    parsed["reportId"] = report
                    new_body = json.dumps(parsed)
                else:
                    new_body = body
                return Case("POST funnels (reportId update)", "POST", f"/api/sites/{site}/funnels", who, new_body, ctype), {funnel: "target"}, [funnel]

            created["funnels"].update(write_pair("POST funnels (reportId update)", build, funnel_row))
        elif kind == "delete funnel":
            target_site = matching_site(site)
            variant = rng.choice(["own", "own", "own", "missing", "abc", "zero", "big", "analyze", "suffix"])

            def build(server, who=who, site=site, target_site=target_site, variant=variant):
                funnel = insert_funnel(target_site, "parity-reports-delete")
                created["funnels"].add(funnel)
                ident = {"own": str(funnel), "missing": "999999", "abc": "abc", "zero": "0", "big": "99999999999", "analyze": "analyze", "suffix": f"{funnel}abc"}[variant]
                return Case("DELETE funnels/:funnelId", "DELETE", f"/api/sites/{site}/funnels/{ident}", who), {funnel: "target"}, [funnel]

            created["funnels"].update(write_pair("DELETE funnels/:funnelId", build, funnel_row))
        elif kind == "create goal":
            body, ctype = gen_goal_body()

            def build(server, body=body, ctype=ctype, who=who, site=site):
                return Case("POST goals", "POST", f"/api/sites/{site}/goals", who, body, ctype), {}, []

            created["goals"].update(write_pair("POST goals", build, goal_row))
        elif kind == "update goal":
            body, ctype = gen_goal_body()
            target_site = matching_site(site)
            variant = rng.choice(["own", "own", "own", "missing", "abc", "time-series", "big", "suffix"])

            def build(server, body=body, ctype=ctype, who=who, site=site, target_site=target_site, variant=variant):
                goal = insert_goal(target_site, "parity-reports-update")
                created["goals"].add(goal)
                ident = {"own": str(goal), "missing": "999999", "abc": "abc", "time-series": "time-series", "big": "99999999999", "suffix": f"{goal}.5"}[variant]
                return Case("PUT goals/:goalId", "PUT", f"/api/sites/{site}/goals/{ident}", who, body, ctype), {goal: "target"}, [goal]

            created["goals"].update(write_pair("PUT goals/:goalId", build, goal_row))
        else:
            target_site = matching_site(site)
            variant = rng.choice(["own", "own", "own", "missing", "abc", "time-series", "zero"])

            def build(server, who=who, site=site, target_site=target_site, variant=variant):
                goal = insert_goal(target_site, "parity-reports-delete")
                created["goals"].add(goal)
                ident = {"own": str(goal), "missing": "999999", "abc": "abc", "time-series": "time-series", "zero": "0"}[variant]
                return Case("DELETE goals/:goalId", "DELETE", f"/api/sites/{site}/goals/{ident}", who), {goal: "target"}, [goal]

            created["goals"].update(write_pair("DELETE goals/:goalId", build, goal_row))


def cleanup_writes():
    """Only rows this run created (snapshot funnels are ids 1 to 7)."""
    if created["funnels"]:
        fixtures.psql(f"DELETE FROM funnels WHERE report_id IN ({','.join(str(i) for i in created['funnels'])}) AND report_id > 7")
        created["funnels"].clear()
    if created["goals"]:
        fixture_ids = set(GOAL_IDS)
        doomed = [str(i) for i in created["goals"] if i not in fixture_ids]
        if doomed:
            fixtures.psql(f"DELETE FROM goals WHERE goal_id IN ({','.join(doomed)})")
        created["goals"].clear()


def main():
    groups = sys.argv[1:] or ["misc", "funnels", "goals", "performance", "bots", "writes"]
    scale = int(os.environ.get("SCALE", "400"))
    fixtures.setup_credentials()
    shown = fixtures.show()
    GOAL_IDS.extend(goal["id"] for goal in (shown["goals"] or []))
    SEGMENT_IDS.extend(str(segment["id"]) for segment in (shown["segments"] or []))
    started = time.time()
    try:
        for group in groups:
            before = sum(r["pairs"] for r in results["routes"].values())
            if group == "misc":
                run_read_cases(misc_cases(), workers=4)
            elif group == "funnels":
                run_read_cases(funnel_cases(scale * 3))
            elif group == "goals":
                run_read_cases(goal_cases(scale * 3))
            elif group == "performance":
                run_read_cases(performance_cases(scale * 2))
            elif group == "bots":
                run_read_cases(bot_cases(scale * 3))
            elif group == "writes":
                write_cases(scale)
                cleanup_writes()
            after = sum(r["pairs"] for r in results["routes"].values())
            print(f"{group}: {after - before} pairs, {len(results['differences'])} differences so far, {time.time() - started:.0f}s", flush=True)
            flush_results()
    finally:
        cleanup_writes()
        flush_results()
        for route, counts in sorted(results["routes"].items()):
            print(f"{route:36} pairs={counts['pairs']:5} identical={counts['identical']:5} different={counts['different']:3} statuses={counts['statuses']}")
        print(f"flaky (differed, then matched on retry): {len(results['flaky'])}")
        print("DONE", flush=True)


if __name__ == "__main__":
    main()
