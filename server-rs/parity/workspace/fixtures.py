#!/usr/bin/env python3
"""Principals for the workspace parity harness: users, organizations, sites,
memberships, sessions and API keys, all prefixed parity-workspace-.

Usage: fixtures.py setup > $OUT/creds.json
       fixtures.py cleanup
"""
import base64, hashlib, hmac, json, sys, urllib.parse

import psycopg2

SECRET = "parity-local-secret-not-for-production"
COOKIE = "__Secure-better-auth.session_token"
P = "parity-workspace-"
HUNCHO = "XoNIxodDwuJOefJZebreRpXzn7Sq3hlL"  # system admin, owner of kb0bi
JUSTIN = "ZDZZHJlo6olnWqliEC5t0kHoxcurXqBM"  # member of kb0bi
ADMIN_HYGO = "GrOwOZVmycGqPD5WD7yIiw4CWBv0dPBa"  # owner of TestOrg
KB = "kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE"
TESTORG = "uYq2uOfGurt0dSp3fffpkYYFlUTyVxLh"


def conn():
    return psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")


def sign(value):
    signature = base64.b64encode(hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{signature}", safe="")


def hash_key(key):
    return base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()).decode().rstrip("=")


def cleanup(cur):
    cur.execute(f"DELETE FROM annotations WHERE title LIKE '{P}%' OR organization_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM segments WHERE name LIKE '{P}%' OR organization_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM dashboards WHERE name LIKE '{P}%' OR site_id IN (SELECT site_id FROM sites WHERE organization_id LIKE '{P}%')")
    cur.execute(f"DELETE FROM apikey WHERE id LIKE '{P}%'")
    cur.execute(f"DELETE FROM session WHERE id LIKE '{P}%'")
    cur.execute(f"DELETE FROM member_site_access WHERE member_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM member WHERE id LIKE '{P}%'")
    cur.execute(f"DELETE FROM sites WHERE organization_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM organization WHERE id LIKE '{P}%'")
    cur.execute(f"DELETE FROM \"user\" WHERE id LIKE '{P}%'")


USERS = {
    "ownerA": "user", "adminA": "user", "memberA1": "user", "memberA2": "user", "restrictedA": "user",
    "ownerB": "user", "nobody": "user", "sysadmin": "admin",
}


def setup(cur):
    cleanup(cur)
    creds = {"sessions": {}, "keys": {}, "sites": {}, "orgs": {}, "users": {}}
    for name, role in USERS.items():
        uid = P + "u-" + name
        creds["users"][name] = uid
        cur.execute(
            'INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", role) '
            "VALUES (%s, %s, %s, true, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc', %s)",
            (uid, "Parity " + name, f"{name}@parity-workspace.test", role),
        )
    orgs = {"A": P + "orgA", "B": P + "orgB"}
    creds["orgs"] = dict(orgs, kb=KB, testorg=TESTORG)
    for key, oid in orgs.items():
        cur.execute(
            "INSERT INTO organization (id, name, slug, \"createdAt\") VALUES (%s, %s, %s, now() AT TIME ZONE 'utc')",
            (oid, "Parity " + key, (P + "org" + key).lower()),
        )
    for label, org, public, link in [("A1", "A", False, "pwlinkA1secret"), ("A2", "A", True, None), ("A3", "A", False, None), ("B1", "B", False, None)]:
        cur.execute(
            "INSERT INTO sites (id, name, domain, organization_id, public, private_link_key, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING site_id",
            (P + "site" + label, "Parity " + label, f"{label.lower()}.parity-workspace.test", orgs[org], public, link, creds["users"]["ownerA"]),
        )
        creds["sites"][label] = cur.fetchone()[0]
    creds["sites"].update({"kb1": 1, "kb2": 2, "test5": 5, "test6": 6})
    for user, org, role, restricted in [
        ("ownerA", "A", "owner", False), ("adminA", "A", "admin", False), ("memberA1", "A", "member", False),
        ("memberA2", "A", "member", False), ("restrictedA", "A", "member", True), ("ownerB", "B", "owner", False),
    ]:
        cur.execute(
            'INSERT INTO member (id, "organizationId", "userId", role, "createdAt", has_restricted_site_access) '
            "VALUES (%s, %s, %s, %s, now() AT TIME ZONE 'utc', %s)",
            (P + "m-" + user, orgs[org], creds["users"][user], role, restricted),
        )
    cur.execute("INSERT INTO member_site_access (member_id, site_id) VALUES (%s, %s)", (P + "m-restrictedA", creds["sites"]["A3"]))
    session_users = dict(creds["users"])
    session_users.update({"huncho": HUNCHO, "justin": JUSTIN, "adminHygo": ADMIN_HYGO})
    for name, uid in session_users.items():
        token = "pwtok" + name
        cur.execute(
            'INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId") VALUES '
            "(%s, date_trunc('milliseconds', (now() AT TIME ZONE 'utc') + interval '6 days 20 hours'), %s, "
            "now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc', '', 'parity', %s)",
            (P + "s-" + name, token, uid),
        )
        creds["sessions"][name] = f"{COOKIE}={sign(token)}"
    keys = [
        ("orgA", "org", orgs["A"], None),
        ("orgA_segread", "org", orgs["A"], {"segments": ["read"], "annotations": ["read"]}),
        ("orgA_sql", "org", orgs["A"], {"sql": ["read"], "dashboards": ["read"]}),
        ("orgA_write", "org", orgs["A"], {"dashboards": ["write"], "segments": ["write"], "annotations": ["write"]}),
        ("orgA_none", "org", orgs["A"], {"funnels": ["read"]}),
        ("orgB", "org", orgs["B"], None),
        ("orgKb", "org", KB, None),
        ("orgKb_sql", "org", KB, {"sql": ["read"]}),
        ("memberA1", "default", creds["users"]["memberA1"], None),
        ("memberA1_segread", "default", creds["users"]["memberA1"], {"segments": ["read"]}),
        ("memberA2", "default", creds["users"]["memberA2"], None),
        ("adminA", "default", creds["users"]["adminA"], None),
        ("restrictedA", "default", creds["users"]["restrictedA"], None),
        ("sysadmin", "default", creds["users"]["sysadmin"], None),
        ("justin", "default", JUSTIN, {"sql": ["read"], "dashboards": ["write"]}),
    ]
    for name, config, ref, perms in keys:
        key = "pwkey_" + name + "_x9Q2"
        cur.execute(
            'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, permissions, "createdAt", "updatedAt") '
            "VALUES (%s, 'parity', %s, %s, %s, true, %s, (now() AT TIME ZONE 'utc') - interval '2 hours', "
            "(now() AT TIME ZONE 'utc') - interval '2 hours')",
            (P + "k-" + name, hash_key(key), ref, config, json.dumps(perms) if perms is not None else None),
        )
        creds["keys"][name] = key
    return creds


def main():
    c = conn()
    c.autocommit = True
    cur = c.cursor()
    if sys.argv[1] == "setup":
        json.dump(setup(cur), sys.stdout, indent=1)
    else:
        cleanup(cur)
        print("cleaned", file=sys.stderr)


main()
