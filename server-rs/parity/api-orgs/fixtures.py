#!/usr/bin/env python3
"""Principals and rows for the api-orgs differential harness: users,
organizations, sites, memberships, teams, sessions and API keys, all prefixed
parity-orgs- (site ids 65300 and up) so the other harnesses' rows in the same
database stay untouched.

Usage: fixtures.py setup > $OUT/creds.json
       fixtures.py reset          (re-create every row, keeping the ids)
       fixtures.py cleanup
"""
import base64
import hashlib
import hmac
import json
import sys
import urllib.parse

import psycopg2

SECRET = "parity-local-secret-not-for-production"
COOKIE = "__Secure-better-auth.session_token"
P = "parity-orgs-"
EMAIL_DOMAIN = P + "test"

# (label, system role)
USERS = [
    ("ownerA", "user"),
    ("adminA", "user"),
    ("memberA1", "user"),
    ("memberA2", "user"),
    ("restrictedA", "user"),
    ("ownerB", "user"),
    ("nobody", "user"),
    ("sysadmin", "admin"),
    ("target", "user"),
]

ORGS = {"A": P + "orgA", "B": P + "orgB"}

# Organizations and users from the production snapshot, read only: they carry real
# sites, members, teams and ClickHouse events, which is the only way to exercise the
# session-count query and the site sort with data. The harness only ever adds its own
# session and API key rows for them, never touches theirs.
SNAPSHOT_ORGS = {"kb": "kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE", "testorg": "uYq2uOfGurt0dSp3fffpkYYFlUTyVxLh"}
SNAPSHOT_USERS = {
    "huncho": "XoNIxodDwuJOefJZebreRpXzn7Sq3hlL",
    "justin": "ZDZZHJlo6olnWqliEC5t0kHoxcurXqBM",
    "adminHygo": "GrOwOZVmycGqPD5WD7yIiw4CWBv0dPBa",
}

# (label, org, site_id, public)
SITES = [("A1", "A", 65300, False), ("A2", "A", 65301, True), ("A3", "A", 65302, False), ("B1", "B", 65310, False)]

# (user, org, role, restricted)
MEMBERS = [
    ("ownerA", "A", "owner", False),
    ("adminA", "A", "admin", False),
    ("memberA1", "A", "member", False),
    ("memberA2", "A", "member", False),
    ("restrictedA", "A", "member", True),
    ("ownerB", "B", "owner", False),
]

# (label, org, members, sites)
TEAMS = [
    ("teamA1", "A", ["memberA1"], ["A1"]),
    ("teamA2", "A", ["memberA2", "adminA"], ["A2", "A3"]),
    ("teamB1", "B", ["ownerB"], ["B1"]),
]

# (label, configId, reference, permissions)
KEYS = [
    ("orgA", "org", ("org", "A"), None),
    ("orgA_orgread", "org", ("org", "A"), {"org": ["read"]}),
    ("orgA_orgwrite", "org", ("org", "A"), {"org": ["write"]}),
    ("orgA_siteswrite", "org", ("org", "A"), {"sites": ["write"]}),
    ("orgA_none", "org", ("org", "A"), {"funnels": ["read"]}),
    ("orgB", "org", ("org", "B"), None),
    ("ownerA", "default", ("user", "ownerA"), None),
    ("ownerA_orgread", "default", ("user", "ownerA"), {"org": ["read"]}),
    ("ownerA_orgwrite", "default", ("user", "ownerA"), {"org": ["write"]}),
    ("ownerA_siteswrite", "default", ("user", "ownerA"), {"sites": ["write"]}),
    ("ownerA_none", "default", ("user", "ownerA"), {"funnels": ["read"]}),
    ("adminA", "default", ("user", "adminA"), None),
    ("memberA1", "default", ("user", "memberA1"), None),
    ("memberA1_orgread", "default", ("user", "memberA1"), {"org": ["read"]}),
    ("restrictedA", "default", ("user", "restrictedA"), None),
    ("ownerB", "default", ("user", "ownerB"), None),
    ("nobody", "default", ("user", "nobody"), None),
    ("sysadmin", "default", ("user", "sysadmin"), None),
    # Disabled and already expired keys, to check they do not authenticate and do
    # not hold a slot against the creation cap
    ("ownerA_disabled", "default", ("user", "ownerA"), None),
    ("ownerA_expired", "default", ("user", "ownerA"), None),
    ("orgKb", "org", ("snapshot-org", "kb"), None),
    ("orgKb_orgread", "org", ("snapshot-org", "kb"), {"org": ["read"]}),
    ("huncho", "default", ("snapshot-user", "huncho"), None),
    ("justin", "default", ("snapshot-user", "justin"), {"org": ["read"]}),
]


def conn():
    connection = psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")
    connection.autocommit = True
    return connection


def sign(value):
    signature = base64.b64encode(hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{signature}", safe="")


def hash_key(key):
    return base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()).decode().rstrip("=")


def cleanup(cur):
    cur.execute(f"DELETE FROM team_site_access WHERE team_id IN (SELECT id FROM team WHERE \"organizationId\" LIKE '{P}%')")
    cur.execute(f"DELETE FROM \"teamMember\" WHERE \"teamId\" IN (SELECT id FROM team WHERE \"organizationId\" LIKE '{P}%')")
    cur.execute(f"DELETE FROM team WHERE \"organizationId\" LIKE '{P}%'")
    cur.execute(f"DELETE FROM member_site_access WHERE member_id IN (SELECT id FROM member WHERE \"organizationId\" LIKE '{P}%')")
    cur.execute(f"DELETE FROM apikey WHERE id LIKE '{P}%' OR \"referenceId\" LIKE '{P}%' OR \"referenceId\" IN (SELECT id FROM \"user\" WHERE email LIKE '%{EMAIL_DOMAIN}%')")
    cur.execute(f"DELETE FROM member WHERE \"organizationId\" LIKE '{P}%'")
    cur.execute(f"DELETE FROM sites WHERE organization_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM organization WHERE id LIKE '{P}%'")
    cur.execute(f"DELETE FROM session WHERE id LIKE '{P}%' OR \"userId\" IN (SELECT id FROM \"user\" WHERE email LIKE '%{EMAIL_DOMAIN}%')")
    cur.execute(f"DELETE FROM account WHERE \"userId\" IN (SELECT id FROM \"user\" WHERE email LIKE '%{EMAIL_DOMAIN}%')")
    cur.execute(f"DELETE FROM \"user\" WHERE email LIKE '%{EMAIL_DOMAIN}%'")


def build(cur):
    cleanup(cur)
    creds = {"sessions": {}, "keys": {}, "sites": {}, "orgs": dict(ORGS), "users": {}, "members": {}, "teams": {}}

    for name, role in USERS:
        uid = P + "u-" + name
        creds["users"][name] = uid
        cur.execute(
            'INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", role, banned, '
            '"sendAutoEmailReports") VALUES (%s, %s, %s, true, %s, %s, %s, false, true)',
            (uid, "Parity " + name, f"{name}@{EMAIL_DOMAIN}", "2026-01-01 00:00:00", "2026-01-01 00:00:00", role),
        )

    for key, oid in ORGS.items():
        cur.execute(
            'INSERT INTO organization (id, name, slug, "createdAt", "excluded_ips") VALUES (%s, %s, %s, %s, %s::jsonb)',
            (oid, "Parity " + key, (P + "org" + key).lower(), "2026-01-01 00:00:00", json.dumps(["10.0.0.1"])),
        )

    for label, org, site_id, public in SITES:
        cur.execute(
            "INSERT INTO sites (id, site_id, name, domain, organization_id, public, created_by, created_at, "
            "updated_at, api_key, private_link_key) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                "aabbccdd00" + str(site_id)[-2:],
                site_id,
                "Parity " + label,
                f"{label.lower()}.parity-orgs.test",
                ORGS[org],
                public,
                creds["users"]["ownerA"],
                "2026-01-01 00:00:00",
                "2026-01-02 00:00:00",
                "rb_" + label,
                "plk_" + label,
            ),
        )
        creds["sites"][label] = site_id

    for user, org, role, restricted in MEMBERS:
        mid = P + "m-" + user
        creds["members"][user] = mid
        cur.execute(
            'INSERT INTO member (id, "organizationId", "userId", role, "createdAt", has_restricted_site_access) '
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (mid, ORGS[org], creds["users"][user], role, "2026-01-03 00:00:00", restricted),
        )
    cur.execute(
        "INSERT INTO member_site_access (member_id, site_id, created_at, created_by) VALUES (%s, %s, %s, %s)",
        (P + "m-restrictedA", 65302, "2026-01-04 00:00:00", creds["users"]["ownerA"]),
    )

    for label, org, members, sites in TEAMS:
        tid = P + "t-" + label
        creds["teams"][label] = tid
        cur.execute(
            'INSERT INTO team (id, name, "organizationId", "createdAt", "updatedAt") VALUES (%s, %s, %s, %s, %s)',
            (tid, "Parity " + label, ORGS[org], "2026-01-05 00:00:00", "2026-01-06 00:00:00"),
        )
        for member in members:
            cur.execute(
                'INSERT INTO "teamMember" (id, "teamId", "userId", "createdAt") VALUES (%s, %s, %s, %s)',
                (f"{P}tm-{label}-{member}", tid, creds["users"][member], "2026-01-05 00:00:00"),
            )
        for site in sites:
            cur.execute(
                "INSERT INTO team_site_access (team_id, site_id, created_at) VALUES (%s, %s, %s)",
                (tid, creds["sites"][site], "2026-01-05 00:00:00"),
            )

    session_users = {name: creds["users"][name] for name, _ in USERS}
    session_users.update(SNAPSHOT_USERS)
    creds["orgs"].update(SNAPSHOT_ORGS)
    for name, user_id in session_users.items():
        token = "potok" + name
        cur.execute(
            'INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", '
            '"userId") VALUES (%s, (now() AT TIME ZONE \'utc\') + interval \'6 days 20 hours\', %s, %s, %s, %s, %s, %s)',
            (P + "s-" + name, token, "2026-01-01 00:00:00", "2026-01-01 00:00:00", "", "parity", user_id),
        )
        creds["sessions"][name] = f"{COOKIE}={sign(token)}"

    for name, config, (kind, ref), perms in KEYS:
        key = "pokey_" + name + "_x9Q2"
        reference = {
            "org": lambda: ORGS[ref],
            "user": lambda: creds["users"][ref],
            "snapshot-org": lambda: SNAPSHOT_ORGS[ref],
            "snapshot-user": lambda: SNAPSHOT_USERS[ref],
        }[kind]()
        enabled = name != "ownerA_disabled"
        expires = "(now() AT TIME ZONE 'utc') - interval '1 hour'" if name == "ownerA_expired" else "NULL"
        cur.execute(
            f'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, permissions, "createdAt", '
            f'"updatedAt", "expiresAt", "rateLimitEnabled", "requestCount") '
            f"VALUES (%s, 'parity', %s, %s, %s, %s, %s, %s, %s, {expires}, false, 0)",
            (
                P + "k-" + name,
                hash_key(key),
                reference,
                config,
                enabled,
                json.dumps(perms) if perms is not None else None,
                "2026-01-01 00:00:00",
                "2026-01-01 00:00:00",
            ),
        )
        creds["keys"][name] = key

    return creds


def fill_keys(cur, reference, target):
    """Top the owner up to `target` usable API keys, so the creation cap (50) is
    either reached or one short of it. Disabled and expired keys do not count."""
    cur.execute(
        'SELECT count(*) FROM apikey WHERE "referenceId" = %s AND enabled = true '
        'AND ("expiresAt" IS NULL OR "expiresAt" > now() AT TIME ZONE \'utc\')',
        (reference,),
    )
    count = max(0, target - cur.fetchone()[0])
    for index in range(count):
        cur.execute(
            'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, "createdAt", "updatedAt", '
            '"rateLimitEnabled", "requestCount") VALUES (%s, %s, %s, %s, %s, true, %s, %s, false, 0)',
            (
                f"{P}k-fill-{index}",
                "fill",
                hash_key(f"pofill_{index}"),
                reference,
                "default" if reference.startswith(P + "u-") else "org",
                "2026-01-01 00:00:00",
                "2026-01-01 00:00:00",
            ),
        )


PREPS = {
    "fill-user": (P + "u-ownerA", 50),
    "fill-user-49": (P + "u-ownerA", 49),
    "fill-org": (ORGS["A"], 50),
    "fill-org-49": (ORGS["A"], 49),
}


def main():
    connection = conn()
    cur = connection.cursor()
    action = sys.argv[1] if len(sys.argv) > 1 else "setup"
    if action in PREPS:
        reference, count = PREPS[action]
        fill_keys(cur, reference, count)
    elif action in ("setup", "reset"):
        creds = build(cur)
        if action == "setup":
            json.dump(creds, sys.stdout, indent=1)
    else:
        cleanup(cur)
        print("cleaned", file=sys.stderr)


if __name__ == "__main__":
    main()
