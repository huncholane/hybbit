#!/usr/bin/env python3
"""Fixtures for the /api/sites parity harness.

Everything created here is prefixed `parity-sites-` and every site id is 65200
or above, so no snapshot row is touched.

setup:   users, organizations, memberships, restricted grants, sites, API keys
         and cookie sessions.
cleanup: removes every row setup created, plus the import rows and ClickHouse
         events the write harness leaves behind.

Usage: fixtures.py setup|cleanup|credentials
"""
import base64
import hashlib
import hmac
import json
import subprocess
import sys
import urllib.parse

import psycopg2

SECRET = "parity-local-secret-not-for-production"
COOKIE = "__Secure-better-auth.session_token"

P = "parity-sites-"

# --- principals -------------------------------------------------------------

U_OWNER = P + "u-owner"
U_ADMIN = P + "u-admin"
U_MEMBER = P + "u-member"
U_RESTRICTED = P + "u-restricted"
U_OUTSIDER = P + "u-outsider"
U_SYSADMIN = P + "u-sysadmin"
U_OWNERB = P + "u-ownerb"

USERS = [
    # (id, email, role)
    (U_OWNER, "owner@parity-sites.test", "user"),
    (U_ADMIN, "admin@parity-sites.test", "user"),
    (U_MEMBER, "member@parity-sites.test", "user"),
    (U_RESTRICTED, "restricted@parity-sites.test", "user"),
    (U_OUTSIDER, "outsider@parity-sites.test", "user"),
    (U_SYSADMIN, "sysadmin@parity-sites.test", "admin"),
    (U_OWNERB, "ownerb@parity-sites.test", "user"),
]

ORG_A = P + "orgA"
ORG_B = P + "orgB"
ORG_C = P + "orgC"
ORG_D = P + "orgD"

ORGS = [
    # (id, name, slug, excluded_ips)
    (ORG_A, "parity-sites A", P + "a", ["10.1.2.3", "192.168.0.0/16", "2001:db8::/32", "10.9.0.1-10.9.0.9"]),
    (ORG_B, "parity-sites B", P + "b", []),
    (ORG_C, "parity-sites C", P + "c", []),
    (ORG_D, "parity-sites D", P + "d", []),
]

MEMBERS = [
    # (id, userId, organizationId, role, restricted)
    (P + "m-owner-a", U_OWNER, ORG_A, "owner", False),
    (P + "m-admin-a", U_ADMIN, ORG_A, "admin", False),
    (P + "m-member-a", U_MEMBER, ORG_A, "member", False),
    (P + "m-restricted-a", U_RESTRICTED, ORG_A, "member", True),
    (P + "m-ownerb-b", U_OWNERB, ORG_B, "owner", False),
    # the A owner is an admin of B: a move to B succeeds
    (P + "m-owner-b", U_OWNER, ORG_B, "admin", False),
    # ... a plain member of D: a move to D is refused with "must be an admin or owner"
    (P + "m-owner-d", U_OWNER, ORG_D, "member", False),
    # ... and no member of C at all: a move to C is refused with "not a member"
    (P + "m-outsider-c", U_OUTSIDER, ORG_C, "owner", False),
]

# --- sites ------------------------------------------------------------------

LONG_PATH = "/" + "seg/" * 400 + "x"  # 1601 characters
UNICODE_PATHS = ["/café/*", "/中文/テスト", "/emoji/\U0001f600"]

SITES = [
    # (site_id, id, name, domain, organization_id, extra column overrides)
    (65200, P + "main0001", "parity main", "parity-main.example.com", ORG_A, {}),
    (65201, P + "public01", "parity public", "parity-public.example.com", ORG_A,
     {"public": True, "embed_enabled": True, "private_link_key": "parity0link1"}),
    (65202, P + "mobile01", "parity mobile", "com.parity.sites.app", ORG_A, {"type": "mobile"}),
    (65203, P + "excl0001", "parity exclusions", "parity-excl.example.com", ORG_A, {
        "excluded_ips": ["10.0.0.1", "2001:db8::1", "172.16.0.0/12", "10.2.0.1-10.2.0.50"],
        "excluded_countries": ["US", "GB", "DE"],
        "excluded_paths": UNICODE_PATHS + [LONG_PATH],
        "excluded_hostnames": ["localhost", "*.vercel.app", "café.example.com"],
        "excluded_user_agents": ["HeadlessChrome", "متصفح", "x" * 500],
        "excluded_asns": ["AS13335", "16509", "4294967295"],
        "excluded_query_params": ["preview", "utm_source=internal-*", "テ=スト"],
        "tags": ["alpha", "bêta"],
        "use_organization_excluded_ips": False,
    }),
    (65204, P + "orgbsite", "parity org B site", "parity-orgb.example.com", ORG_B, {}),
    (65205, P + "noorg001", "parity no org", "parity-noorg.example.com", None, {}),
    (65206, P + "cfgwrite", "parity config write", "parity-cfg.example.com", ORG_A, {}),
    (65207, P + "deleteme", "parity delete", "parity-del.example.com", ORG_A, {}),
    (65208, P + "movingit", "parity move", "parity-move.example.com", ORG_A, {}),
    (65209, P + "imports1", "parity imports", "parity-imp.example.com", ORG_A, {}),
    (65210, P + "embedoff", "parity embed off", "parity-embedoff.example.com", ORG_A, {"public": True}),
    (65211, P + "nulls001", "parity nulls", "parity-nulls.example.com", ORG_A, {
        # every nullable flag left NULL, so the Site Configuration defaults show
        "public": None, "embed_enabled": None, "saltUserIds": None, "first_party_proxy": None,
        "excluded_ips": None, "use_organization_excluded_ips": None, "excluded_countries": None,
        "excluded_paths": None, "excluded_hostnames": None, "excluded_user_agents": None,
        "excluded_asns": None, "excluded_query_params": None, "sessionReplay": None, "webVitals": None,
        "trackErrors": None, "trackOutbound": None, "trackUrlParams": None, "trackInitialPageView": None,
        "trackSpaNavigation": None, "trackIp": None, "trackButtonClicks": None, "trackCopy": None,
        "trackFormInteractions": None, "track_heartbeat": None, "heartbeat_interval": None,
        "bounce_threshold": None, "tags": None, "created_at": None, "updated_at": None,
    }),
    # restricted member reaches only this one
    (65212, P + "granted1", "parity granted", "parity-granted.example.com", ORG_A, {}),
]

SITE_COLUMN_DEFAULTS = {
    "type": None,
    "created_at": "now() AT TIME ZONE 'utc'",
    "updated_at": "now() AT TIME ZONE 'utc'",
    "created_by": None,
    "public": False,
    "embed_enabled": False,
    "saltUserIds": False,
    "blockBots": True,
    "first_party_proxy": False,
    "excluded_ips": [],
    "use_organization_excluded_ips": True,
    "excluded_countries": [],
    "excluded_paths": [],
    "excluded_hostnames": [],
    "excluded_user_agents": [],
    "excluded_asns": [],
    "excluded_query_params": [],
    "sessionReplay": False,
    "webVitals": False,
    "trackErrors": False,
    "trackOutbound": True,
    "trackUrlParams": True,
    "trackInitialPageView": True,
    "trackSpaNavigation": True,
    "trackIp": False,
    "trackButtonClicks": False,
    "trackCopy": False,
    "trackFormInteractions": False,
    "track_heartbeat": False,
    "heartbeat_interval": 15,
    "bounce_threshold": 10,
    "api_key": None,
    "private_link_key": None,
    "tags": [],
    "detected_platform": None,
}

JSON_COLUMNS = {
    "excluded_ips", "excluded_countries", "excluded_paths", "excluded_hostnames",
    "excluded_user_agents", "excluded_asns", "excluded_query_params", "tags",
}

GRANTS = [(P + "m-restricted-a", 65212)]

# --- credentials ------------------------------------------------------------

KEYS = [
    # (id, token, referenceId, configId, permissions)
    (P + "k-owner", P + "t-owner", U_OWNER, "default", None),
    (P + "k-owner-sites-read", P + "t-owner-sites-read", U_OWNER, "default", '{"sites":["read"]}'),
    (P + "k-owner-sites-write", P + "t-owner-sites-write", U_OWNER, "default", '{"sites":["write"]}'),
    (P + "k-owner-wrong", P + "t-owner-wrong", U_OWNER, "default", '{"goals":["read"]}'),
    (P + "k-member", P + "t-member", U_MEMBER, "default", None),
    (P + "k-member-sites-read", P + "t-member-sites-read", U_MEMBER, "default", '{"sites":["read"]}'),
    (P + "k-restricted", P + "t-restricted", U_RESTRICTED, "default", None),
    (P + "k-outsider", P + "t-outsider", U_OUTSIDER, "default", None),
    (P + "k-sysadmin", P + "t-sysadmin", U_SYSADMIN, "default", None),
    (P + "k-org", P + "t-org", ORG_A, "org", None),
    (P + "k-org-sites-read", P + "t-org-sites-read", ORG_A, "org", '{"sites":["read"]}'),
    (P + "k-org-sites-write", P + "t-org-sites-write", ORG_A, "org", '{"sites":["write"]}'),
    (P + "k-org-wrong", P + "t-org-wrong", ORG_A, "org", '{"goals":["read"]}'),
    (P + "k-orgb", P + "t-orgb", ORG_B, "org", None),
    (P + "k-disabled", P + "t-disabled", U_OWNER, "default", None),
]

SESSIONS = [
    ("owner", P + "s-owner", "paritysitesowner", U_OWNER),
    ("admin", P + "s-admin", "paritysitesadmin", U_ADMIN),
    ("member", P + "s-member", "paritysitesmember", U_MEMBER),
    ("restricted", P + "s-restricted", "paritysitesrestricted", U_RESTRICTED),
    ("outsider", P + "s-outsider", "paritysitesoutsider", U_OUTSIDER),
    ("sysadmin", P + "s-sysadmin", "paritysitessysadmin", U_SYSADMIN),
    ("ownerb", P + "s-ownerb", "paritysitesownerb", U_OWNERB),
    ("expired", P + "s-expired", "paritysitesexpired", U_OWNER),
]


def pg():
    return psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")


def ch(query):
    result = subprocess.run(
        ["curl", "-s", "-u", "default:hygo",
         "http://127.0.0.1:58123/?database=analytics&mutations_sync=2", "--data-binary", query],
        capture_output=True, text=True, check=True,
    )
    if "Exception" in result.stdout:
        raise RuntimeError(result.stdout)
    return result.stdout


def hash_key(token):
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode().rstrip("=")


def sign(value):
    signature = base64.b64encode(hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{signature}", safe="")


def sign_payload(payload):
    """server/src/lib/signedToken.ts signPayload: HMAC-SHA256, base64url, unpadded."""
    digest = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def credentials():
    creds = {"none": {}}
    for name, _, token, _ in SESSIONS:
        creds["cookie-" + name] = {"Cookie": f"{COOKIE}={sign(token)}"}
    for key_id, token, *_ in KEYS:
        creds["bearer-" + key_id[len(P) + 2:]] = {"Authorization": f"Bearer {token}"}
    creds["bearer-unknown"] = {"Authorization": "Bearer " + P + "t-nosuchkey"}
    creds["bearer-empty"] = {"Authorization": "Bearer "}
    return creds


# --- setup / cleanup --------------------------------------------------------

def cleanup_pg(cur):
    cur.execute("DELETE FROM import_status WHERE site_id >= 65200")
    cur.execute(f"DELETE FROM import_status WHERE organization_id LIKE '{P}%%'")
    cur.execute(f"DELETE FROM apikey WHERE id LIKE '{P}%%'")
    cur.execute(f"DELETE FROM session WHERE id LIKE '{P}%%'")
    cur.execute("DELETE FROM member_site_access WHERE site_id >= 65200")
    cur.execute(f"DELETE FROM member_site_access WHERE member_id LIKE '{P}%%'")
    cur.execute("DELETE FROM team_site_access WHERE site_id >= 65200")
    cur.execute("DELETE FROM segments WHERE site_id >= 65200")
    cur.execute(f"DELETE FROM segments WHERE organization_id LIKE '{P}%%'")
    cur.execute("DELETE FROM annotations WHERE site_id >= 65200")
    cur.execute(f"DELETE FROM annotations WHERE organization_id LIKE '{P}%%'")
    cur.execute("DELETE FROM goals WHERE site_id >= 65200")
    cur.execute("DELETE FROM funnels WHERE site_id >= 65200")
    cur.execute("DELETE FROM dashboards WHERE site_id >= 65200")
    cur.execute("DELETE FROM sites WHERE site_id >= 65200")
    cur.execute(f"DELETE FROM member WHERE id LIKE '{P}%%'")
    cur.execute(f"DELETE FROM team WHERE \"organizationId\" LIKE '{P}%%'")
    cur.execute(f"DELETE FROM invitation WHERE \"organizationId\" LIKE '{P}%%'")
    cur.execute(f"DELETE FROM organization WHERE id LIKE '{P}%%'")
    cur.execute(f"DELETE FROM \"user\" WHERE id LIKE '{P}%%'")


def insert_site(cur, site_id, text_id, name, domain, organization_id, overrides):
    columns = ["site_id", "id", "name", "domain", "organization_id"]
    placeholders = ["%s", "%s", "%s", "%s", "%s"]
    values = [site_id, text_id, name, domain, organization_id]
    for column, default in SITE_COLUMN_DEFAULTS.items():
        value = overrides[column] if column in overrides else default
        columns.append(f'"{column}"')
        if isinstance(value, str) and value.endswith("'utc'"):
            placeholders.append(value)
            continue
        placeholders.append("%s")
        values.append(json.dumps(value) if column in JSON_COLUMNS and value is not None else value)
    cur.execute(
        f"INSERT INTO sites ({', '.join(columns)}) VALUES ({', '.join(placeholders)})",
        values,
    )


def setup():
    with pg() as conn, conn.cursor() as cur:
        cleanup_pg(cur)
        for user_id, email, role in USERS:
            cur.execute(
                'INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", role) '
                "VALUES (%s, %s, %s, true, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc', %s)",
                (user_id, user_id, email, role),
            )
        for org_id, name, slug, excluded in ORGS:
            cur.execute(
                'INSERT INTO organization (id, name, slug, "createdAt", excluded_ips) '
                "VALUES (%s, %s, %s, now() AT TIME ZONE 'utc', %s)",
                (org_id, name, slug, json.dumps(excluded)),
            )
        for member_id, user_id, org_id, role, restricted in MEMBERS:
            cur.execute(
                'INSERT INTO member (id, "organizationId", "userId", role, "createdAt", has_restricted_site_access) '
                "VALUES (%s, %s, %s, %s, now() AT TIME ZONE 'utc', %s)",
                (member_id, org_id, user_id, role, restricted),
            )
        for site in SITES:
            insert_site(cur, *site)
        for member_id, site_id in GRANTS:
            cur.execute(
                "INSERT INTO member_site_access (member_id, site_id, created_at) VALUES (%s, %s, now())",
                (member_id, site_id),
            )
        for key_id, token, reference, config, permissions in KEYS:
            cur.execute(
                'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, permissions, '
                '"createdAt", "updatedAt") '
                "VALUES (%s, 'parity-sites', %s, %s, %s, %s, %s, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc')",
                (key_id, hash_key(token), reference, config, key_id != P + "k-disabled", permissions),
            )
        for name, session_id, token, user_id in SESSIONS:
            offset = "- interval '2 days'" if name == "expired" else "+ interval '6 days 20 hours'"
            cur.execute(
                'INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", '
                '"userAgent", "userId") VALUES '
                f"(%s, date_trunc('milliseconds', (now() AT TIME ZONE 'utc') {offset}), %s, "
                "(now() AT TIME ZONE 'utc') - interval '1 hour', (now() AT TIME ZONE 'utc') - interval '1 hour', "
                "'', 'parity', %s)",
                (session_id, token, user_id),
            )
    print(f"{len(USERS)} users, {len(ORGS)} orgs, {len(SITES)} sites, {len(KEYS)} keys, {len(SESSIONS)} sessions")


def cleanup():
    with pg() as conn, conn.cursor() as cur:
        cleanup_pg(cur)
    ch("DELETE FROM events WHERE site_id >= 65200")
    ch("DELETE FROM session_replay_events WHERE site_id >= 65200")
    ch("DELETE FROM session_replay_metadata_v2 WHERE site_id >= 65200")
    print("cleaned")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "setup"
    if command == "setup":
        setup()
    elif command == "cleanup":
        cleanup()
    elif command == "credentials":
        json.dump(credentials(), sys.stdout, indent=1)
    else:
        raise SystemExit(f"unknown command {command}")
