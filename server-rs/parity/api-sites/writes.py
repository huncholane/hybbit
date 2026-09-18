#!/usr/bin/env python3
"""Write-route parity for /api/sites: config, move, delete, private links and the
four import routes.

Each case starts from the same fixture state for both backends: reset, send to
Node, snapshot the rows it could have touched; reset, send to Rust, snapshot.
Responses (status, watched headers, body) and snapshots must match. Only sites
65200 and above and rows prefixed `parity-sites-` are created or touched.

Two values are random by construction and are masked on both sides before the
comparison: a generated private link key (6 random bytes) and a new import's
UUID. Row timestamps are compared as "was written just now", not by value.

Usage: writes.py [--only SUBSTRING] [--groups config,move,...] [--out FILE]
"""
import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402
import harness  # noqa: E402

CREDS = fixtures.credentials()

# The scratch sites every write case works on, rebuilt before each request.
SCRATCH_SITES = [65206, 65207, 65208, 65209]
SEGMENT_IDS = [990301, 990302]

HEX12 = re.compile(rb'"privateLinkKey":"[0-9a-f]{12}"')
UUID = re.compile(rb'"importId":"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"')
TIMESTAMP = re.compile(rb'"(startedAt|completedAt)":"[^"]*"')


def mask(body):
    body = HEX12.sub(b'"privateLinkKey":"<KEY>"', body)
    body = UUID.sub(b'"importId":"<UUID>"', body)
    return TIMESTAMP.sub(rb'"\1":"<TS>"', body)


# --- fixture reset ----------------------------------------------------------

def pg_exec(statements):
    with fixtures.pg() as conn, conn.cursor() as cur:
        for statement, params in statements:
            cur.execute(statement, params)


def pg_rows(query, params=()):
    with fixtures.pg() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        return [list(row) for row in cur.fetchall()]


SITE_BY_ID = {site[0]: site for site in fixtures.SITES}


def reset_state(imports=()):
    """Rebuild the scratch sites, their access grants, their segments and any
    import rows a case needs, and clear their ClickHouse events."""
    with fixtures.pg() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM import_status WHERE site_id = ANY(%s)", (SCRATCH_SITES,))
        cur.execute("DELETE FROM segments WHERE segment_id = ANY(%s)", (SEGMENT_IDS,))
        cur.execute("DELETE FROM member_site_access WHERE site_id = ANY(%s)", (SCRATCH_SITES,))
        cur.execute("DELETE FROM team_site_access WHERE site_id = ANY(%s)", (SCRATCH_SITES,))
        cur.execute("DELETE FROM sites WHERE site_id = ANY(%s)", (SCRATCH_SITES,))
        for site_id in SCRATCH_SITES:
            fixtures.insert_site(cur, *SITE_BY_ID[site_id])
        # A restricted grant and a team grant on the move target, so applySiteMove's
        # deletes are visible, plus a site segment and an organization-wide one
        cur.execute("INSERT INTO member_site_access (member_id, site_id, created_at) VALUES (%s, 65208, now())",
                    (fixtures.P + "m-restricted-a",))
        cur.execute(
            "INSERT INTO segments (segment_id, organization_id, site_id, name, filters, is_public) "
            "VALUES (%s, %s, 65208, 'parity-sites-seg', '[]', true)", (SEGMENT_IDS[0], fixtures.ORG_A))
        cur.execute(
            "INSERT INTO segments (segment_id, organization_id, site_id, name, filters, is_public) "
            "VALUES (%s, %s, NULL, 'parity-sites-orgseg', '[]', true)", (SEGMENT_IDS[1], fixtures.ORG_A))
        # `started_at` is distinct per row: `getImportsForSite` orders by it with no
        # tiebreaker, so equal values would leave the list order undefined
        for index, (import_id, site_id, platform, completed) in enumerate(imports):
            cur.execute(
                "INSERT INTO import_status (import_id, site_id, organization_id, platform, imported_events, "
                "skipped_events, invalid_events, started_at, completed_at) "
                "VALUES (%s::uuid, %s, %s, %s::import_platform_enum, 1, 2, 3, "
                "timestamp '2026-09-01 00:00:00' + (%s * interval '1 minute'), %s)",
                (import_id, site_id, fixtures.ORG_A, platform, index,
                 "2026-09-01 00:00:00" if completed else None),
            )
    fixtures.ch(f"DELETE FROM events WHERE site_id IN ({','.join(str(s) for s in SCRATCH_SITES)})")


SITE_SNAPSHOT_COLUMNS = (
    'site_id, id, name, type, domain, organization_id, "public", embed_enabled, "saltUserIds", "blockBots", '
    'first_party_proxy, excluded_ips::text, use_organization_excluded_ips, excluded_countries::text, '
    'excluded_paths::text, excluded_hostnames::text, excluded_user_agents::text, excluded_asns::text, '
    'excluded_query_params::text, "sessionReplay", "webVitals", "trackErrors", "trackOutbound", "trackUrlParams", '
    '"trackInitialPageView", "trackSpaNavigation", "trackIp", "trackButtonClicks", "trackCopy", '
    '"trackFormInteractions", track_heartbeat, heartbeat_interval, bounce_threshold, tags::text, '
    "(private_link_key IS NULL) AS no_key, length(private_link_key) AS key_length, "
    "(updated_at > now() - interval '2 minutes') AS touched"
)


def snapshot(clickhouse=False):
    state = {
        "sites": pg_rows(f"SELECT {SITE_SNAPSHOT_COLUMNS} FROM sites WHERE site_id = ANY(%s) ORDER BY site_id",
                         (SCRATCH_SITES,)),
        "grants": pg_rows("SELECT member_id, site_id FROM member_site_access WHERE site_id = ANY(%s) ORDER BY 1, 2",
                          (SCRATCH_SITES,)),
        "teams": pg_rows("SELECT team_id, site_id FROM team_site_access WHERE site_id = ANY(%s) ORDER BY 1, 2",
                         (SCRATCH_SITES,)),
        "segments": pg_rows("SELECT segment_id, organization_id, site_id FROM segments WHERE segment_id = ANY(%s) "
                            "ORDER BY 1", (SEGMENT_IDS,)),
        # ordered by every column, so two rows that differ only in one of them
        # cannot swap places between the two snapshots
        "imports": pg_rows(
            "SELECT site_id, organization_id, platform::text, imported_events, skipped_events, invalid_events, "
            "(completed_at IS NOT NULL), (started_at > now() - interval '2 minutes') "
            "FROM import_status WHERE site_id = ANY(%s) ORDER BY 1, 2, 3, 4, 5, 6, 7, 8",
            (SCRATCH_SITES,)),
    }
    if clickhouse:
        state["events"] = fixtures.ch(
            "SELECT site_id, timestamp, session_id, user_id, hostname, pathname, querystring, "
            "toString(url_parameters), page_title, referrer, channel, browser, browser_version, operating_system, "
            "operating_system_version, language, country, region, city, lat, lon, screen_width, screen_height, "
            "device_type, type, event_name, toString(props) "
            f"FROM events WHERE site_id IN ({','.join(str(s) for s in SCRATCH_SITES)}) ORDER BY ALL FORMAT TSV")
    return state


# --- cases ------------------------------------------------------------------

CASES = []


def add(group, route, method, path, cred="cookie-owner", body=None, content_type="application/json",
        headers=None, imports=(), clickhouse=False):
    merged = dict(CREDS[cred])
    merged.update(headers or {})
    if content_type is not None and body is not None:
        merged["Content-Type"] = content_type
    CASES.append({"group": group, "route": route, "method": method, "path": path, "cred": cred,
                  "headers": merged, "body": body, "imports": list(imports), "clickhouse": clickhouse})


def js(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


CONFIG = "/api/sites/65206/config"

BOOLEAN_FIELDS = ["public", "embedEnabled", "saltUserIds", "blockBots", "firstPartyProxy",
                  "useOrganizationExcludedIPs", "sessionReplay", "webVitals", "trackErrors", "trackOutbound",
                  "trackUrlParams", "trackInitialPageView", "trackSpaNavigation", "trackIp", "trackButtonClicks",
                  "trackCopy", "trackFormInteractions", "trackHeartbeat"]

LIST_FIELDS = {
    "excludedIPs": (100, ["1.2.3.4", "  10.0.0.1  ", "2001:db8::1", "10.0.0.0/8", "10.1.0.1-10.1.0.9", "nope",
                          "10.0.0.1-", "2001:db8::1-2001:db8::9", "", "   "]),
    "excludedCountries": (250, ["US", " GB ", "us", "USA", "U", "ÉS", "12"]),
    "excludedPaths": (100, ["/a", "  /b  ", "/café/*", "/中文", "x" * 2048, "x" * 2049, "", "   "]),
    "excludedHostnames": (100, ["a.com", "*.vercel.app", "x" * 253, "x" * 254, ""]),
    "excludedUserAgents": (100, ["bot", "متصفح", "x" * 512, "x" * 513, ""]),
    "excludedASNs": (100, ["AS13335", "as13335", "13335", "4294967295", "4294967296", "AS99999999999",
                           "AS", "0", "  AS1  ", "A13335", "12345678901"]),
    "excludedQueryParams": (100, ["preview", "utm_source=x*", "=x", "  a=b  ", "x" * 512, "x" * 513, ""]),
    "tags": (20, ["alpha", "  bêta  ", "x" * 50, "x" * 51, ""]),
}


def build_config_cases():
    # every single field on its own, with a valid and an invalid value
    for field in BOOLEAN_FIELDS:
        for value in [True, False, "true", 1, None, [], {}]:
            add("config", "PUT …/config", "PUT", CONFIG, body=js({field: value}))
    for field, (limit, values) in LIST_FIELDS.items():
        for value in values:
            add("config", "PUT …/config", "PUT", CONFIG, body=js({field: [value]}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({field: []}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({field: values}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({field: ["ok"] * (limit + 1)}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({field: "notalist"}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({field: [1]}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({field: [None]}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({field: [["nested"]]}))
    for name in ["new name", "", " ", "x" * 255, "x" * 256, "café \U0001f600", 5, None, True]:
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"name": name}))
    for domain in ["example.com", "sub.example.com", "https://example.com/", "http://example.com///",
                   "HTTPS://example.com", "café.example", "日本.みんな", "-bad.com",
                   "bad-.com", "example", "example.c", "ex ample.com", "", "x" * 253, "x" * 254,
                   "com.example.app", 5, None]:
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"domain": domain}))
    for site_type in ["web", "mobile", None, "tablet", "", 5, True, []]:
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"type": site_type}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"type": site_type, "domain": "example.com"}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"type": site_type, "domain": "com.example.app"}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"type": site_type, "sessionReplay": True}))
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"type": site_type, "webVitals": True}))
    for number in [5, 300, 4, 301, 1.5, 0, -1, 15.0, 1e21, "15", None, True]:
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"heartbeatInterval": number}))
    for number in [1, 600, 0, 601, 10.5, -5, 10.0, "10", None]:
        add("config", "PUT …/config", "PUT", CONFIG, body=js({"bounceThreshold": number}))
    # whole-body shapes
    for body in ["{}", "[]", "null", '"text"', "5", "true", "{bad json", "", js({"unknown": 1}),
                 js({"name": "ok", "unknown": 1}), js({"__proto__": {"x": 1}}), js({"name": "a", "name": "b"}),
                 js({"name": "ok", "public": True, "tags": ["a"], "excludedIPs": ["1.2.3.4"],
                     "heartbeatInterval": 60, "bounceThreshold": 20, "domain": "https://ok.example.com/"})]:
        add("config", "PUT …/config", "PUT", CONFIG, body=body)
    add("config", "PUT …/config", "PUT", CONFIG, body=None, content_type=None)
    add("config", "PUT …/config", "PUT", CONFIG, body="{}", content_type="text/plain")
    add("config", "PUT …/config", "PUT", CONFIG, body="{}", content_type="application/xml")
    add("config", "PUT …/config", "PUT", CONFIG, body=js({"name": "big"}) + " " * 100, content_type="application/json")
    # a mobile site keeps replay and vitals off whatever the payload says
    add("config", "PUT …/config (mobile)", "PUT", "/api/sites/65202/config", body=js({"name": "mobile rename"}))
    # every credential
    for cred in list(CREDS):
        add("config", "PUT …/config (access)", "PUT", CONFIG, cred, body=js({"name": "by " + cred}))
    # ids the handler re-reads
    for identifier in ["", "0", "-1", "1.5", "abc", "65206", "parity-sites-cfgwrite", "0x65206", "99999999999999999999"]:
        add("config", "PUT …/config (ids)", "PUT", f"/api/sites/{identifier}/config", body=js({"name": "x"}))
    # bodies over the server-wide 10 MB limit
    add("config", "PUT …/config (limit)", "PUT", CONFIG, body=js({"name": "a", "excludedPaths": ["x" * 900]}))
    add("config", "PUT …/config (limit)", "PUT", CONFIG, body='{"name":"' + "a" * (10 * 1024 * 1024) + '"}')


def build_private_link_cases():
    path = "/api/sites/65206/private-link-config"
    for body in [js({"action": "generate_private_link_key"}), js({"action": "revoke_private_link_key"}),
                 js({"action": "nope"}), js({"action": 5}), js({"action": None}), js({}), js([]), "null",
                 "{bad", "", js({"action": "generate_private_link_key", "extra": 1})]:
        add("private-link", "POST …/private-link-config", "POST", path, body=body)
    for cred in list(CREDS):
        add("private-link", "POST …/private-link-config (access)", "POST", path, cred,
            body=js({"action": "generate_private_link_key"}))
    for identifier in ["", "0", "-1", "1.5", "abc", "65206", "parity-sites-cfgwrite", "99999999999999999999"]:
        add("private-link", "POST …/private-link-config (ids)", "POST", f"/api/sites/{identifier}/private-link-config",
            body=js({"action": "generate_private_link_key"}))
    add("private-link", "POST …/private-link-config", "POST", path, body=None, content_type=None)
    add("private-link", "POST …/private-link-config", "POST", path, body=js({"action": "revoke_private_link_key"}),
        content_type="text/plain")


def build_move_cases():
    path = "/api/sites/65208/move"
    targets = [
        fixtures.ORG_B,   # the owner is an admin there: the move goes through
        fixtures.ORG_C,   # not a member
        fixtures.ORG_D,   # a member but not an admin
        fixtures.ORG_A,   # already there
        "no-such-organization", "", " ",
    ]
    for target in targets:
        for cred in ["cookie-owner", "cookie-admin", "cookie-member", "cookie-sysadmin", "cookie-outsider",
                     "bearer-owner", "bearer-org", "bearer-org-sites-write", "none"]:
            add("move", "PUT …/move", "PUT", path, cred, body=js({"organizationId": target}))
    for body in [js({}), js({"organizationId": 5}), js({"organizationId": None}), js([]), "null", "{bad", "",
                 js({"organizationId": fixtures.ORG_B, "extra": 1})]:
        add("move", "PUT …/move", "PUT", path, body=body)
    for identifier in ["", "0", "-1", "1.5", "abc", "65208", "parity-sites-movingit", "99999999999999999999", "65205"]:
        add("move", "PUT …/move (ids)", "PUT", f"/api/sites/{identifier}/move", body=js({"organizationId": fixtures.ORG_B}))
    add("move", "PUT …/move", "PUT", path, body=None, content_type=None)


def build_delete_cases():
    for cred in list(CREDS):
        add("delete", "DELETE /api/sites/:siteId (access)", "DELETE", "/api/sites/65207", cred, clickhouse=True)
    for identifier in ["", "0", "-1", "1.5", "abc", "65207", "parity-sites-deleteme", "99999999999999999999",
                       "0x65207", "65299"]:
        add("delete", "DELETE /api/sites/:siteId (ids)", "DELETE", f"/api/sites/{identifier}", clickhouse=True)
    add("delete", "DELETE /api/sites/:siteId", "DELETE", "/api/sites/65207", body="{bad", clickhouse=True)
    add("delete", "DELETE /api/sites/:siteId", "DELETE", "/api/sites/65207", body="{}", content_type="application/xml")
    # a site with an import row cannot be deleted: the foreign key refuses
    add("delete", "DELETE /api/sites/:siteId (fk)", "DELETE", "/api/sites/65209",
        imports=[("aaaaaaaa-1111-4111-8111-111111111111", 65209, "umami", True)], clickhouse=True)


UMAMI = {
    "session_id": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001", "hostname": "www.example.com", "browser": "crios",
    "os": "Windows 10", "device": "laptop", "screen": "1920x1080", "language": "en-US", "country": "US",
    "region": "US-CA", "city": "Oakland", "url_path": "/pricing", "url_query": "utm_source=news&a=1",
    "referrer_path": "/blog", "referrer_domain": "news.example.org", "page_title": "Pricing",
    "event_type": "1", "event_name": "signup", "distinct_id": "device-1", "created_at": "2026-05-04 12:30:45",
}
PLAUSIBLE = {
    "timestamp": "2026-05-04 12:30:45", "session_id": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001",
    "user_id": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0002", "hostname": "www.example.com", "pathname": "/x",
    "querystring": "utm_medium=cpc&b=2", "referrer": "https://example.com/ref", "browser": "Chrome",
    "browser_version": "120", "operating_system": "macOS", "operating_system_version": "14",
    "device_type": "Desktop", "country": "US", "region": "US-CA", "city": "Oakland", "type": "custom_event",
    "event_name": "signup", "props": '{"a":1,"b":"x"}',
}
SIMPLE = {
    "added_iso": "2026-05-04T12:30:45.123Z", "country_code": "US", "datapoint": "pageview",
    "document_referrer": "https://news.example.org/x", "hostname": "example.com", "lang_language": "en",
    "lang_region": "us", "path": "/", "query": "a=1", "screen_height": "1080", "screen_width": "1920",
    "session_id": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0001",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "uuid": "0195f4d5-0f3c-7a5c-8f2a-7f0d2f9f0002",
}

IMPORT_UMAMI = "aaaaaaaa-0000-4000-8000-000000000001"
IMPORT_PLAUSIBLE = "aaaaaaaa-0000-4000-8000-000000000002"
IMPORT_SIMPLE = "aaaaaaaa-0000-4000-8000-000000000003"
IMPORT_DONE = "aaaaaaaa-0000-4000-8000-000000000004"
IMPORT_OTHER_SITE = "aaaaaaaa-0000-4000-8000-000000000005"

OPEN_IMPORTS = [
    (IMPORT_UMAMI, 65209, "umami", False),
    (IMPORT_PLAUSIBLE, 65209, "plausible", False),
    (IMPORT_SIMPLE, 65209, "simple_analytics", False),
    (IMPORT_DONE, 65209, "umami", True),
    (IMPORT_OTHER_SITE, 65206, "umami", True),
]


def variant(base, **overrides):
    merged = dict(base)
    merged.update(overrides)
    return merged


def build_import_cases():
    # list
    for cred in list(CREDS):
        add("imports", "GET …/imports (access)", "GET", "/api/sites/65209/imports", cred, imports=OPEN_IMPORTS)
    add("imports", "GET …/imports", "GET", "/api/sites/65209/imports", imports=OPEN_IMPORTS)
    # create
    for platform in ["umami", "plausible", "simple_analytics", "matomo", "", None, 5, [], {"x": 1}]:
        add("imports", "POST …/imports", "POST", "/api/sites/65209/imports", body=js({"platform": platform}))
    for body in [js({}), js([]), "null", "{bad", "", js({"platform": "umami", "extra": 1})]:
        add("imports", "POST …/imports", "POST", "/api/sites/65209/imports", body=body)
    add("imports", "POST …/imports", "POST", "/api/sites/65209/imports", body=None, content_type=None)
    for cred in list(CREDS):
        add("imports", "POST …/imports (access)", "POST", "/api/sites/65209/imports", cred,
            body=js({"platform": "umami"}))
    for identifier in ["", "0", "-1", "abc", "65209", "parity-sites-imports1", "65205", "99999999999999999999"]:
        add("imports", "POST …/imports (ids)", "POST", f"/api/sites/{identifier}/imports", body=js({"platform": "umami"}))

    # batch events
    def batch(name, import_id, events, last=None, site=65209, cred="cookie-owner", body=None, content_type="application/json"):
        payload = body if body is not None else js({"events": events} if last is None else {"events": events, "isLastBatch": last})
        add("imports", name, "POST", f"/api/sites/{site}/imports/{import_id}/events", cred, body=payload,
            content_type=content_type, imports=OPEN_IMPORTS, clickhouse=True)

    batch("POST …/imports/:id/events", IMPORT_UMAMI, [UMAMI])
    batch("POST …/imports/:id/events", IMPORT_UMAMI, [UMAMI], last=True)
    batch("POST …/imports/:id/events", IMPORT_UMAMI, [UMAMI], last=False)
    batch("POST …/imports/:id/events", IMPORT_UMAMI, [])
    batch("POST …/imports/:id/events", IMPORT_UMAMI, [UMAMI] * 25)
    for override in [
        {"session_id": "not-a-uuid"}, {"created_at": "2026-13-04 12:30:45"}, {"created_at": "2026-02-31 00:00:00"},
        {"created_at": "2030-01-01 00:00:00"}, {"event_type": "2"}, {"event_type": "3"}, {"country": "usa"},
        {"country": ""}, {"region": ""}, {"region": "usca"}, {"screen": ""}, {"screen": "1920X1080"},
        {"screen": "999999x1"}, {"city": "x" * 61}, {"city": "x" * 60}, {"browser": "x" * 31},
        {"browser": "EDGE-IOS"}, {"os": "Mac OS"}, {"os": "unknown os"}, {"device": "tablet"},
        {"device": "watch"}, {"url_query": ""}, {"url_query": "a=1&a=2&b"}, {"referrer_domain": ""},
        {"referrer_domain": "www.example.com"}, {"referrer_path": ""}, {"distinct_id": "x" * 65},
        {"page_title": "café \U0001f600"}, {"language": "x" * 36},
    ]:
        batch("POST …/imports/:id/events (umami fields)", IMPORT_UMAMI, [variant(UMAMI, **override)], last=True)
    for override in [
        {}, {"props": "{bad"}, {"props": ""}, {"props": "5"}, {"props": "[1,2]"}, {"props": "x" * 4097},
        {"type": "pageview"}, {"type": "nope"}, {"timestamp": "2026-05-04 24:00:00"},
        {"user_id": "nope"}, {"referrer": ""}, {"hostname": "example.com"}, {"querystring": ""},
        {"device_type": "Mobile"}, {"region": "US-C"}, {"event_name": "x" * 257},
    ]:
        batch("POST …/imports/:id/events (plausible)", IMPORT_PLAUSIBLE, [variant(PLAUSIBLE, **override)], last=True)
    for override in [
        {}, {"added_iso": "2026-05-04T12:30:45Z"}, {"added_iso": "2026-05-04T12:30:45+02:00"},
        {"added_iso": "2026-02-30T00:00:00Z"}, {"added_iso": "not a date"}, {"datapoint": "signup"},
        {"lang_region": ""}, {"screen_width": "0"}, {"screen_width": "-1"}, {"screen_width": "12x"},
        {"user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"},
        {"user_agent": ""}, {"query": ""}, {"country_code": ""},
    ]:
        batch("POST …/imports/:id/events (simple analytics)", IMPORT_SIMPLE, [variant(SIMPLE, **override)], last=True)
    # a payload shaped for another platform than the import's
    batch("POST …/imports/:id/events (wrong platform)", IMPORT_UMAMI, [PLAUSIBLE], last=True)
    batch("POST …/imports/:id/events (wrong platform)", IMPORT_PLAUSIBLE, [UMAMI], last=True)
    batch("POST …/imports/:id/events (wrong platform)", IMPORT_SIMPLE, [PLAUSIBLE], last=True)
    # mixed shapes, so no union branch accepts the whole array
    batch("POST …/imports/:id/events (malformed)", IMPORT_UMAMI, [UMAMI, PLAUSIBLE], last=True)
    for body in ["{}", js({"events": "x"}), js({"events": {}}), js({"events": [1]}), js({"events": ["text"]}),
                 js({"events": [None]}), js({"events": [UMAMI], "isLastBatch": "yes"}),
                 js({"events": [variant(UMAMI, event_type=1)]}), js({"events": [UMAMI], "extra": 1}),
                 js([]), "null", "{bad", ""]:
        batch("POST …/imports/:id/events (malformed)", IMPORT_UMAMI, None, body=body)
    batch("POST …/imports/:id/events (malformed)", IMPORT_UMAMI, None, body=None, content_type=None)
    batch("POST …/imports/:id/events (malformed)", IMPORT_UMAMI, [UMAMI], content_type="text/plain")
    # unknown, mismatched and malformed import ids
    for import_id in ["aaaaaaaa-0000-4000-8000-00000000ffff", "not-a-uuid", "", IMPORT_OTHER_SITE,
                      "AAAAAAAA-0000-4000-8000-000000000001"]:
        batch("POST …/imports/:id/events (ids)", import_id, [UMAMI], last=True)
    batch("POST …/imports/:id/events (ids)", IMPORT_UMAMI, [UMAMI], last=True, site=65205)
    batch("POST …/imports/:id/events (ids)", IMPORT_UMAMI, [UMAMI], last=True, site=65206)
    for cred in list(CREDS):
        batch("POST …/imports/:id/events (access)", IMPORT_UMAMI, [UMAMI], cred=cred)
    # the route's own 50 MB body limit, and a payload just under it
    big = [variant(UMAMI, distinct_id=f"d{index}") for index in range(20000)]
    batch("POST …/imports/:id/events (large)", IMPORT_UMAMI, big, last=True)
    oversized = '{"events":[' + ('{"x":"' + "y" * 1000 + '"},') * 52000
    oversized = oversized[:-1] + "]}"
    add("imports", "POST …/imports/:id/events (oversized)", "POST",
        f"/api/sites/65209/imports/{IMPORT_UMAMI}/events", body=oversized, imports=OPEN_IMPORTS, clickhouse=True)

    # delete
    for import_id in [IMPORT_DONE, IMPORT_UMAMI, IMPORT_OTHER_SITE, "aaaaaaaa-0000-4000-8000-00000000ffff",
                      "not-a-uuid", ""]:
        add("imports", "DELETE …/imports/:id", "DELETE", f"/api/sites/65209/imports/{import_id}",
            imports=OPEN_IMPORTS, clickhouse=True)
    for cred in list(CREDS):
        add("imports", "DELETE …/imports/:id (access)", "DELETE", f"/api/sites/65209/imports/{IMPORT_DONE}", cred,
            imports=OPEN_IMPORTS, clickhouse=True)
    for identifier in ["", "0", "abc", "65209", "parity-sites-imports1", "65206"]:
        add("imports", "DELETE …/imports/:id (ids)", "DELETE", f"/api/sites/{identifier}/imports/{IMPORT_DONE}",
            imports=OPEN_IMPORTS, clickhouse=True)


GROUPS = {
    "config": build_config_cases,
    "private-link": build_private_link_cases,
    "move": build_move_cases,
    "delete": build_delete_cases,
    "imports": build_import_cases,
}


def run_side(target, case):
    reset_state(case["imports"])
    response = harness.send(target, case["method"], case["path"], case["headers"], case["body"])
    return response, snapshot(case["clickhouse"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--groups", default=",".join(GROUPS))
    parser.add_argument("--only")
    parser.add_argument("--out", default=os.path.join(harness.SCRATCH, "r_writes.json"))
    args = parser.parse_args()
    for name in args.groups.split(","):
        GROUPS[name.strip()]()
    cases = CASES
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
        diffs = []
        if node_response[0] != rust_response[0]:
            diffs.append("status")
        for name in harness.WATCHED:
            if name == "content-length":
                continue
            if node_response[1].get(name) != rust_response[1].get(name):
                diffs.append(name)
        if mask(node_response[2]) != mask(rust_response[2]):
            diffs.append("body")
        if node_state != rust_state:
            diffs.append("rows")
        counts[case["route"]] += 1
        statuses[case["route"]][node_response[0]] += 1
        if diffs:
            body = case["body"]
            failures.append({
                "case": {k: case[k] for k in ("group", "route", "method", "path", "cred")},
                "body": body if body is None or len(body) < 400 else body[:400] + "...",
                "diffs": diffs,
                "node": {"status": node_response[0], "body": node_response[2].decode("utf-8", "replace")[:1500],
                         "state": node_state},
                "rust": {"status": rust_response[0], "body": rust_response[2].decode("utf-8", "replace")[:1500],
                         "state": rust_state},
            })
        else:
            same[case["route"]] += 1
        if (index + 1) % 25 == 0:
            print(f"  {index + 1}/{len(cases)}, {len(failures)} differing", flush=True)

    reset_state()
    report = {
        "total": len(cases),
        "identical": sum(same.values()),
        "routes": {route: {"pairs": counts[route], "identical": same[route], "statuses": dict(statuses[route])}
                   for route in sorted(counts)},
        "failures": failures,
    }
    with open(args.out, "w") as handle:
        json.dump(report, handle, indent=1, default=str)
    print(json.dumps({k: v for k, v in report.items() if k != "failures"}, indent=1))


if __name__ == "__main__":
    main()
