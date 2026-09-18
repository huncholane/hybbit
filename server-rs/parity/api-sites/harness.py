#!/usr/bin/env python3
"""Differential harness for the read side of /api/sites: every case goes to Node
(:3001) and Rust (:3101) at the same time; status, the watched headers and the
body bytes must be identical. Mismatches are retried (other agents share the
stores and `now()` moves) before they count.

Usage: harness.py [--groups routing,access,...] [--only SUBSTRING] [--limit N] [--out FILE]
Writes the per-route counts and every remaining difference to --out.
"""
import argparse
import collections
import http.client
import json
import os
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402

NODE = ("127.0.0.1", 3001)
RUST = ("127.0.0.1", int(os.environ.get("RUST_PORT", "3101")))
SCRATCH = "/tmp/claude-1000/-home-huncho-code-hygo-repo-hybbit/c715b88b-ff27-4193-85dd-24c1a017449e/scratchpad/api-sites"

WATCHED = [
    "content-type",
    "cache-control",
    "x-content-type-options",
    "vary",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "retry-after",
    "allow",
    "content-length",
]

CREDS = fixtures.credentials()
ALL_CREDS = list(CREDS)

# Site identifiers worth sending: the fixture sites, their text ids, and the
# shapes that exercise resolveSiteId and the handlers' own Number()/parseInt().
SITES = [str(site[0]) for site in fixtures.SITES]
TEXT_IDS = [site[1] for site in fixtures.SITES]
ODD_IDS = [
    "", "0", "-1", "1.5", "abc", "abcd", "abcde", "0x10", " 65200 ", "%2065200%20", "065200",
    "65200x", "9999999", "99999999999999999999", "1e5", "Infinity", "NaN", "null", "undefined",
    "%E2%9C%93", "a%2Fb", "%zz", "x" * 1500, "x" * 1501,
]


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
                try:
                    conn.send(data)
                except (BrokenPipeError, ConnectionResetError):
                    # A body over the route's limit is refused and the connection
                    # closed while it is still being written; the answer is already
                    # on the socket, so read it rather than reporting a transport error
                    pass
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


# --- body normalisation -----------------------------------------------------

def normalise(case, status, body):
    """The only field that cannot be compared byte for byte is `daysElapsed` in
    the usage payload: it is `now - startOfMonth` at the moment each backend
    answers, so the two differ in the microseconds. It is rounded to whole
    seconds here, and the projections it feeds are allowed to land one apart."""
    if "/usage" not in case["path"] or status != 200:
        return body
    try:
        parsed = json.loads(body)
    except ValueError:
        return body
    if not isinstance(parsed, dict) or "daysElapsed" not in parsed:
        return body
    parsed["daysElapsed"] = round(parsed["daysElapsed"] * 86400)
    for key in ("projectedSiteEvents", "projectedOrgEvents"):
        if isinstance(parsed.get(key), (int, float)):
            parsed[key] = round(parsed[key] / 4)
    return json.dumps(parsed, sort_keys=True).encode()


def is_known_shared_gap(case, node, rust):
    """A HEAD that falls through to the router's own 404 reports Node's would-be
    body length and Rust's a fixed one. It is the shared 404/HEAD handling in
    src/http, not this group: `HEAD /api/nonexistent-path-entirely` differs the
    same way. Recorded separately so the counts stay honest."""
    return (case["method"] == "HEAD" and node[0] == 404 and rust[0] == 404
            and node[2] == b"" and rust[2] == b""
            and node[1].get("content-length") != rust[1].get("content-length"))


def differences(case, node, rust):
    diffs = []
    if node[0] != rust[0]:
        diffs.append("status")
    known = is_known_shared_gap(case, node, rust)
    for name in WATCHED:
        # content-length follows the body, which is compared in full below
        if name == "content-length" and ("/usage" in case["path"] or known):
            continue
        if node[1].get(name) != rust[1].get(name):
            diffs.append(name)
    if normalise(case, node[0], node[2]) != normalise(case, rust[0], rust[2]):
        diffs.append("body")
    return diffs


def run_case(case):
    for attempt in range(4):
        node, rust = pair(case)
        diffs = differences(case, node, rust)
        if not diffs:
            return case, node[0], None, is_known_shared_gap(case, node, rust)
        time.sleep(0.3 * (attempt + 1))
    return case, node[0], {
        "diffs": diffs,
        "node": {"status": node[0], "headers": {k: node[1].get(k) for k in WATCHED},
                 "body": node[2].decode("utf-8", "replace")[:3000]},
        "rust": {"status": rust[0], "headers": {k: rust[1].get(k) for k in WATCHED},
                 "body": rust[2].decode("utf-8", "replace")[:3000]},
    }, False


# --- case generation --------------------------------------------------------

CASES = []


def add(group, route, method, path, cred="cookie-owner", headers=None, body=None, content_type=None):
    merged = dict(CREDS[cred])
    merged.update(headers or {})
    if content_type is not None:
        merged["Content-Type"] = content_type
    CASES.append({"group": group, "route": route, "method": method, "path": path, "cred": cred,
                  "headers": merged, "body": body})


EXCLUSION_ROUTES = [
    "excluded-ips", "excluded-countries", "excluded-paths", "excluded-hostnames",
    "excluded-user-agents", "excluded-asns", "excluded-query-params", "organization-excluded-ips",
]

READ_ROUTES = [("", "GET /api/sites/:siteId")] + \
    [(f"/{name}", f"GET …/{name}") for name in EXCLUSION_ROUTES] + \
    [("/usage", "GET …/usage"), ("/private-link-config", "GET …/private-link-config"),
     ("/imports", "GET …/imports"), ("/embed-stats", "GET …/embed-stats")]


def build_access_cases():
    """Every read route against every credential, on a private site, a public
    site, a site with no organization, a site only the restricted member reaches
    and a site of another organization."""
    for site in ["65200", "65201", "65205", "65212", "65204"]:
        for suffix, route in READ_ROUTES:
            for cred in ALL_CREDS:
                add("access", route, "GET", f"/api/sites/{site}{suffix}", cred)


def build_identifier_cases():
    """The same routes over every identifier spelling, with one credential that
    has access and one that does not."""
    identifiers = SITES + TEXT_IDS + ODD_IDS
    for identifier in identifiers:
        for suffix, route in READ_ROUTES:
            for cred in ["cookie-owner", "none"]:
                add("identifiers", route, "GET", f"/api/sites/{identifier}{suffix}", cred)


def build_exclusion_cases():
    """The exclusion reads on the site whose lists carry unicode, long values and
    every pattern shape, and on the site whose columns are all NULL."""
    for site in ["65203", "65211", "65202"]:
        for name in EXCLUSION_ROUTES:
            for cred in ["cookie-owner", "cookie-member", "bearer-org-sites-read", "bearer-owner-wrong", "none"]:
                add("exclusions", f"GET …/{name}", "GET", f"/api/sites/{site}/{name}", cred)


def build_embed_cases():
    minutes = ["30", "1440", "10080", "0", "31", "abc", "", "1440.0", "0x5A0", " 1440 ", "1e3", "10080.1"]
    flags = [("", ""), ("&chart=true", ""), ("", "&countries=true"), ("&chart=true", "&countries=true"),
             ("&chart=TRUE", ""), ("&chart=1", "&countries=false")]
    for site in ["65201", "65210", "65200", "65205", "nosuchsite1"]:
        for value in minutes:
            for chart, countries in flags:
                add("embed", "GET …/embed-stats", "GET",
                    f"/api/sites/{site}/embed-stats?minutes={urllib.parse.quote(value)}{chart}{countries}", "none")
    # repeated and missing parameters, and an origin (this path echoes any origin)
    for query in ["", "?minutes=30&minutes=30", "?minutes=30&minutes=1440", "?chart=true&chart=false",
                  "?minutes", "?minutes=", "?MINUTES=30", "?minutes=30&extra=1"]:
        add("embed", "GET …/embed-stats", "GET", f"/api/sites/65201/embed-stats{query}", "none")
        add("embed", "GET …/embed-stats", "GET", f"/api/sites/65201/embed-stats{query}", "none",
            headers={"Origin": "https://widget.example.com"})
        add("embed", "GET …/embed-stats", "GET", f"/api/sites/65201/embed-stats{query}", "cookie-owner")


def build_routing_cases():
    """Methods a path does not register, empty parameters and malformed URLs."""
    paths = [
        "/api/sites/65200", "/api/sites/", "/api/sites/65200/config", "/api/sites/65200/move",
        "/api/sites/65200/private-link-config", "/api/sites/65200/excluded-ips",
        "/api/sites/65200/organization-excluded-ips", "/api/sites/65200/usage",
        "/api/sites/65200/embed-stats", "/api/sites/65200/imports",
        "/api/sites/65200/imports/0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001",
        "/api/sites/65200/imports/0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001/events",
        "/api/sites//imports", "/api/sites/65200/imports/", "/api/sites/65200/imports//events",
        "/api/site/check-install", "/api/site/check-install/", "/api/sites/65200/excluded-ips/",
        "/api/sites/65200/unknown-route", "/api/sites/65200/config/extra",
    ]
    # An empty JSON body makes every registered write method answer 400 before it
    # touches anything, so these stay read-only. The one method that would delete a
    # fixture, DELETE /api/sites/:siteId, is covered in writes.py instead.
    destructive = {("DELETE", "/api/sites/65200")}
    for path in paths:
        for method in ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
            if (method, path) in destructive:
                continue
            body = "{}" if method in ("POST", "PUT", "PATCH", "DELETE") else None
            add("routing", f"{method} {path}", method, path, "cookie-owner", body=body,
                content_type="application/json" if body else None)
    for path in ["/api/sites/%zz", "/api/sites/65200/imports/%zz", "/api/sites/6%C3%A9200",
                 "/api/sites/%2F65200", "/api/sites/65200%2Fconfig", "/api/sites/%25zz/usage"]:
        add("routing", "bad url", "GET", path, "cookie-owner")


def build_check_install_cases():
    """Valid, expired, tampered, missing and oddly shaped signatures. Each case
    gets its own client address so the per-IP limiter (5 a minute) stays in step
    between the two backends; the limiter itself is exercised in its own group."""
    now = int(time.time())

    def link(site, domain, exp=None, sig=None, extra=""):
        exp = now + 3600 if exp is None else exp
        payload = f"check-install:{site}:{domain}"
        signature = fixtures.sign_payload(f"{payload}:{exp}") if sig is None else sig
        return (f"/api/site/check-install?siteId={urllib.parse.quote(str(site))}"
                f"&domain={urllib.parse.quote(str(domain))}&exp={urllib.parse.quote(str(exp))}"
                f"&sig={urllib.parse.quote(str(signature))}{extra}")

    # An unresolvable domain answers "couldn't reach" without leaving the host
    unreachable = "nonexistent-parity-sites-check.example"
    cases = [
        ("valid", link(65200, unreachable)),
        ("valid other site", link(65201, unreachable)),
        ("expired", link(65200, unreachable, exp=now - 1)),
        ("expiring now", link(65200, unreachable, exp=now)),
        ("far future", link(65200, unreachable, exp=now + 10 ** 9)),
        ("fractional exp", link(65200, unreachable, exp=now + 3600.7)),
        ("non numeric exp", link(65200, unreachable, exp="soon")),
        ("negative exp", link(65200, unreachable, exp=-1)),
        ("empty exp", link(65200, unreachable, exp="")),
        ("tampered sig", link(65200, unreachable, sig="tampered")),
        ("right length wrong sig", link(65200, unreachable, sig="A" * 43)),
        ("empty sig", link(65200, unreachable, sig="")),
        ("sig for another site", f"/api/site/check-install?siteId=65201&domain={unreachable}"
                                 f"&exp={now + 3600}&sig={urllib.parse.quote(fixtures.sign_payload(f'check-install:65200:{unreachable}:{now + 3600}'))}"),
        ("missing sig", f"/api/site/check-install?siteId=65200&domain={unreachable}&exp={now + 3600}"),
        ("missing exp", f"/api/site/check-install?siteId=65200&domain={unreachable}&sig=x"),
        ("missing domain", f"/api/site/check-install?siteId=65200&exp={now + 3600}&sig=x"),
        ("missing siteId", f"/api/site/check-install?domain={unreachable}&exp={now + 3600}&sig=x"),
        ("no query", "/api/site/check-install"),
        ("float siteId", link(65200.5, unreachable)),
        ("negative siteId", link(-1, unreachable)),
        ("zero siteId", link(0, unreachable)),
        ("hex siteId", link("0x10", unreachable)),
        ("huge siteId", link(10 ** 20, unreachable)),
        ("empty domain", link(65200, "")),
        ("space in domain", link(65200, "not a domain")),
        ("localhost", link(65200, "localhost")),
        ("loopback ip", link(65200, "127.0.0.1")),
        ("metadata ip", link(65200, "169.254.169.254")),
        ("internal suffix", link(65200, "svc.internal")),
        ("trailing dot", link(65200, "example.com.")),
        ("uppercase domain", link(65200, "NONEXISTENT-PARITY.EXAMPLE")),
        ("unicode domain", link(65200, "café.example")),
        ("port in domain", link(65200, "example.com:8080")),
        ("path in domain", link(65200, "example.com/x")),
        ("repeated sig", link(65200, unreachable) + "&sig=second"),
        ("repeated siteId", link(65200, unreachable) + "&siteId=65201"),
        ("extra params", link(65200, unreachable, extra="&foo=bar")),
    ]
    for index, (name, path) in enumerate(cases):
        add("check-install", "GET /api/site/check-install", "GET", path, "none",
            headers={"X-Forwarded-For": f"203.0.113.{index % 200 + 1}"})


def build_rate_limit_cases():
    """Seven requests from one address: the first five pass, the rest are 429."""
    now = int(time.time())
    domain = "nonexistent-parity-sites-rate.example"
    signature = fixtures.sign_payload(f"check-install:65200:{domain}:{now + 3600}")
    path = f"/api/site/check-install?siteId=65200&domain={domain}&exp={now + 3600}&sig={urllib.parse.quote(signature)}"
    for index in range(7):
        add("rate-limit", "GET /api/site/check-install (limit)", "GET", path, "none",
            headers={"X-Forwarded-For": "198.18.7.7"})
        _ = index


def build_header_cases():
    """CORS and the write-origin check around the group's reads."""
    origins = ["https://a.hygo.ai", "http://localhost:3002", "https://evil.example", "not a url", ""]
    for origin in origins:
        for path in ["/api/sites/65200", "/api/sites/65201/embed-stats", "/api/sites/65200/excluded-ips",
                     "/api/sites/65200/imports", "/api/sites/65200/usage"]:
            add("headers", f"GET {path} with Origin", "GET", path, "cookie-owner", headers={"Origin": origin})
            add("headers", f"OPTIONS {path}", "OPTIONS", path, "none", headers={"Origin": origin})
    # private-link header on the public-guard route
    for key in ["parity0link1", "wrong", ""]:
        add("headers", "GET /api/sites/:siteId with x-private-key", "GET", "/api/sites/65201", "none",
            headers={"x-private-key": key})
        add("headers", "GET /api/sites/:siteId with x-private-key", "GET", "/api/sites/65200", "none",
            headers={"x-private-key": key})
    # the query-string api_key spelling
    for token in [fixtures.P + "t-owner", fixtures.P + "t-org-wrong", "nope"]:
        for path in ["/api/sites/65200", "/api/sites/65200/excluded-ips", "/api/sites/65200/usage"]:
            add("headers", f"GET {path} with ?api_key", "GET", f"{path}?api_key={token}", "none")
    # validateTimeParams is on every chain in this group
    for query in ["?start_date=bad", "?start_date=2026-01-01&end_date=2026-01-02", "?time_zone=Nowhere/Nothing",
                  "?start_datetime=2026-01-01T00:00:00Z&end_datetime=2026-01-02T00:00:00Z", "?past_minutes=-1"]:
        for path in ["/api/sites/65200", "/api/sites/65200/excluded-ips", "/api/sites/65200/usage",
                     "/api/sites/65200/imports", "/api/sites/65200/private-link-config",
                     "/api/sites/65201/embed-stats"]:
            add("headers", f"GET {path} with time params", "GET", f"{path}{query}", "cookie-owner")
    # expandSegmentParam runs on the public and member chains only
    for query in ["?segment_id=1", "?segment_id=abc", "?segment_id="]:
        for path in ["/api/sites/65200", "/api/sites/65200/excluded-ips", "/api/sites/65200/imports"]:
            add("headers", f"GET {path} with segment_id", "GET", f"{path}{query}", "cookie-owner")


def build_reachable_cases():
    """check-install against domains that really resolve, so the fetch, the
    redirect following and the SSRF guard all run. These leave the host, so they
    are a small, separate group.

    The "snippet is installed" branch is not reachable from here (none of the
    parity domains serves the script in its HTML), so `has_hygo_script` is covered
    by its unit test instead."""
    now = int(time.time())
    domains = ["example.com", "hygo.ai", "rubysair.com", "spiritfacts.com", "domhaul.com",
               "www.example.com", "iana.org", "cloudflare.com"]
    for index, domain in enumerate(domains):
        signature = fixtures.sign_payload(f"check-install:65200:{domain}:{now + 3600}")
        path = (f"/api/site/check-install?siteId=65200&domain={urllib.parse.quote(domain)}"
                f"&exp={now + 3600}&sig={urllib.parse.quote(signature)}")
        add("reachable", "GET /api/site/check-install (network)", "GET", path, "none",
            headers={"X-Forwarded-For": f"192.0.2.{index + 20}"})


def build_credential_cases():
    """Credential shapes the guards read before they reach any of these handlers."""
    tampered = CREDS["cookie-owner"]["Cookie"].replace("%3D", "%3d")
    variants = {
        "tampered cookie": {"Cookie": tampered},
        "cookie without signature": {"Cookie": f"{fixtures.COOKIE}=paritysitesowner"},
        "empty cookie": {"Cookie": f"{fixtures.COOKIE}="},
        "unknown cookie name": {"Cookie": f"other={fixtures.P}s-owner"},
        "basic auth": {"Authorization": "Basic " + fixtures.P + "t-owner"},
        "lowercase bearer": {"Authorization": "bearer " + fixtures.P + "t-owner"},
        "double space bearer": {"Authorization": "Bearer  " + fixtures.P + "t-owner"},
        "bearer with no token": {"Authorization": "Bearer"},
        "bearer plus cookie": {"Authorization": "Bearer " + fixtures.P + "t-org",
                               "Cookie": CREDS["cookie-owner"]["Cookie"]},
        "sysadmin cookie plus user key": {"Authorization": "Bearer " + fixtures.P + "t-outsider",
                                          "Cookie": CREDS["cookie-sysadmin"]["Cookie"]},
    }
    for name, headers in variants.items():
        for path in ["/api/sites/65200", "/api/sites/65200/excluded-ips", "/api/sites/65200/usage",
                     "/api/sites/65200/imports", "/api/sites/65200/private-link-config",
                     "/api/sites/65204/excluded-ips", "/api/sites/65212"]:
            add("credentials", f"GET {path} ({name})", "GET", path, "none", headers=headers)
    for query in ["?api_key=" + fixtures.P + "t-owner&api_key=" + fixtures.P + "t-org",
                  "?api_key=", "?api_key", "?API_KEY=" + fixtures.P + "t-owner"]:
        for path in ["/api/sites/65200", "/api/sites/65200/excluded-ips", "/api/sites/65200/imports"]:
            add("credentials", f"GET {path} (?api_key shapes)", "GET", f"{path}{query}", "none")


GROUPS = {
    "access": build_access_cases,
    "credentials": build_credential_cases,
    "reachable": build_reachable_cases,
    "identifiers": build_identifier_cases,
    "exclusions": build_exclusion_cases,
    "embed": build_embed_cases,
    "routing": build_routing_cases,
    "check-install": build_check_install_cases,
    "rate-limit": build_rate_limit_cases,
    "headers": build_header_cases,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--groups", default=",".join(GROUPS))
    parser.add_argument("--only")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out", default=os.path.join(SCRATCH, "r_reads.json"))
    args = parser.parse_args()

    for name in args.groups.split(","):
        GROUPS[name.strip()]()
    cases = CASES
    if args.only:
        cases = [case for case in cases if args.only in case["path"] or args.only in case["route"]]
    if args.limit:
        cases = cases[: args.limit]
    print(f"{len(cases)} read cases", flush=True)

    counts = collections.Counter()
    same = collections.Counter()
    statuses = collections.defaultdict(collections.Counter)
    failures = []
    # The rate-limit group must run in order on a single thread
    sequential = [case for case in cases if case["group"] == "rate-limit"]
    parallel = [case for case in cases if case["group"] != "rate-limit"]

    known_gaps = collections.Counter()

    def record(result):
        case, status, failure, known = result
        counts[case["route"]] += 1
        statuses[case["route"]][status] += 1
        if known:
            known_gaps[case["route"]] += 1
        if failure:
            failures.append({"case": {k: case[k] for k in ("group", "route", "method", "path", "cred")}, **failure})
        else:
            same[case["route"]] += 1

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for index, result in enumerate(pool.map(run_case, parallel)):
            record(result)
            if (index + 1) % 250 == 0:
                print(f"  {index + 1}/{len(parallel)}, {len(failures)} differing", flush=True)
    for case in sequential:
        record(run_case(case))

    report = {
        "total": len(cases),
        "identical": sum(same.values()),
        "known_shared_head_404_length": sum(known_gaps.values()),
        "routes": {route: {"pairs": counts[route], "identical": same[route], "statuses": dict(statuses[route])}
                   for route in sorted(counts)},
        "failures": failures,
    }
    with open(args.out, "w") as handle:
        json.dump(report, handle, indent=1, default=str)
    print(json.dumps({k: v for k, v in report.items() if k != "failures"}, indent=1))
    for failure in failures[:40]:
        print(json.dumps(failure, default=str)[:2500])


if __name__ == "__main__":
    main()
