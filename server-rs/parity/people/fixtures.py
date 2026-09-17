#!/usr/bin/env python3
"""Fixtures for the people-routes parity harness.

setup:   API keys, cookie sessions, segments, user profiles and aliases (all ids
         prefixed parity-people-, segments 990101..990106), plus identified-user
         events copied into site 7 (which has no events of its own) tagged
         'parity-people'.
cleanup: removes every row setup created.

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
OWNER = "XoNIxodDwuJOefJZebreRpXzn7Sq3hlL"  # owner of kb0bi, system admin
MEMBER = "ZDZZHJlo6olnWqliEC5t0kHoxcurXqBM"  # member of kb0bi
GROW = "GrOwOZVmycGqPD5WD7yIiw4CWBv0dPBa"  # owner of uYq2
ORG = "kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE"
ORG2 = "uYq2uOfGurt0dSp3fffpkYYFlUTyVxLh"
FIXTURE_SITE = 7
TAG = "parity-people"

ALICE_DEVICE = "7ab75f5dcdd7"
BOB_DEVICE = "a41d6e587300"
CAROL_DEVICE = "382f1a9ae6f2"
DAVE_DEVICE = "417905e6dd78"

KEYS = [
    # (id, token, referenceId, configId, permissions)
    ("parity-people-k-owner", "parity-people-token-owner", OWNER, "default", None),
    ("parity-people-k-member", "parity-people-token-member", MEMBER, "default", None),
    ("parity-people-k-grow", "parity-people-token-grow", GROW, "default", None),
    ("parity-people-k-org", "parity-people-token-org", ORG, "org", None),
    ("parity-people-k-org-events", "parity-people-token-org-events", ORG, "org", '{"events":["read"],"sessions":["read"]}'),
    ("parity-people-k-org-users", "parity-people-token-org-users", ORG, "org", '{"users":["write"],"analytics":["read"]}'),
    ("parity-people-k-org-none", "parity-people-token-org-none", ORG, "org", '{"goals":["read"]}'),
    ("parity-people-k-org2", "parity-people-token-org2", ORG2, "org", None),
    ("parity-people-k-org2-users", "parity-people-token-org2-users", ORG2, "org", '{"users":["read"],"segments":["read"]}'),
    ("parity-people-k-owner-sessions", "parity-people-token-owner-sessions", OWNER, "default", '{"sessions":["read"]}'),
]

SESSIONS = [
    ("parity-people-s-owner", "paritypeopleowner", OWNER),
    ("parity-people-s-member", "paritypeoplemember", MEMBER),
    ("parity-people-s-grow", "paritypeoplegrow", GROW),
]

SEGMENTS = [
    # (id, org, site, is_public, filters)
    (990101, ORG2, FIXTURE_SITE, True, [{"parameter": "country", "type": "equals", "value": ["US"]}]),
    (990102, ORG2, FIXTURE_SITE, False, [{"parameter": "pathname", "type": "contains", "value": ["/"]}]),
    (990103, ORG2, None, True, [{"parameter": "device_type", "type": "equals", "value": ["Desktop"]}]),
    (990104, ORG, 1, True, [{"parameter": "browser", "type": "equals", "value": ["Chrome"]}]),
    (990105, ORG, 1, False, [{"parameter": "channel", "type": "equals", "value": ["Direct"]}]),
    (990106, ORG, None, True, [{"parameter": "bogus", "type": "equals", "value": ["x"]}]),
]

PROFILES = [
    ("parity-people-alice", {"username": "alice", "email": "alice@example.com", "plan": "pro", "score": 1.5, "10": "ten", "nested": {"a": [1, 2, {"b": None}]}}),
    ("parity-people-bob", {"username": "bob", "name": "Bob Builder", "plan": "free", "active": True, "big": 12345678901234567890}),
    ("parity-people-carol", {"username": "carol", "email": "carol@example.org", "plan": "pro", "n": 1.0}),
    ("parity-people-dave", {"plan": "pro", "email": "dave@example.com", "name": "Dave"}),
    ("parity-people-erin", None),
    ("parity-people-frank", {}),
    ("parity-people-12345", {"username": "numeric", "plan": None}),
]

ALIASES = [
    (ALICE_DEVICE, "parity-people-alice"),
    (BOB_DEVICE, "parity-people-bob"),
    (CAROL_DEVICE, "parity-people-carol"),
    (DAVE_DEVICE, "parity-people-dave"),
    ("parity-people-orphan-device", "parity-people-erin"),
]


def pg():
    return psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")


def ch(query):
    result = subprocess.run(
        ["curl", "-s", "-u", "default:hygo", "http://127.0.0.1:58123/?database=analytics&mutations_sync=2", "--data-binary", query],
        capture_output=True,
        text=True,
        check=True,
    )
    if "Exception" in result.stdout:
        raise RuntimeError(result.stdout)
    return result.stdout


def hash_key(token):
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode().rstrip("=")


def sign(value):
    signature = base64.b64encode(hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{signature}", safe="")


def credentials():
    creds = {"none": {}}
    for session_id, token, _ in SESSIONS:
        creds["cookie-" + session_id.split("-")[-1]] = {"Cookie": f"{COOKIE}={sign(token)}"}
    for key_id, token, *_ in KEYS:
        creds["bearer-" + key_id.replace("parity-people-k-", "")] = {"Authorization": f"Bearer {token}"}
    return creds


def cleanup_pg(cur):
    cur.execute("DELETE FROM apikey WHERE id LIKE 'parity-people-%'")
    cur.execute("DELETE FROM session WHERE id LIKE 'parity-people-%'")
    cur.execute("DELETE FROM segments WHERE segment_id BETWEEN 990100 AND 990199")
    cur.execute("DELETE FROM user_profiles WHERE user_id LIKE 'parity-people-%'")
    cur.execute("DELETE FROM user_aliases WHERE user_id LIKE 'parity-people-%' OR anonymous_id LIKE 'parity-people-%'")


def setup():
    with pg() as conn, conn.cursor() as cur:
        cleanup_pg(cur)
        for key_id, token, reference, config, permissions in KEYS:
            cur.execute(
                'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, permissions, "createdAt", "updatedAt") '
                "VALUES (%s, 'parity-people', %s, %s, %s, true, %s, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc')",
                (key_id, hash_key(token), reference, config, permissions),
            )
        for session_id, token, user in SESSIONS:
            cur.execute(
                'INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId") VALUES '
                "(%s, date_trunc('milliseconds', (now() AT TIME ZONE 'utc') + interval '6 days 20 hours'), %s, "
                "(now() AT TIME ZONE 'utc') - interval '1 hour', (now() AT TIME ZONE 'utc') - interval '1 hour', '', 'parity', %s)",
                (session_id, token, user),
            )
        for segment_id, org, site, public, filters in SEGMENTS:
            cur.execute(
                "INSERT INTO segments (segment_id, organization_id, site_id, name, filters, is_public) VALUES (%s, %s, %s, %s, %s, %s)",
                (segment_id, org, site, f"parity-people-{segment_id}", json.dumps(filters), public),
            )
        for user_id, traits in PROFILES:
            cur.execute(
                "INSERT INTO user_profiles (site_id, user_id, traits) VALUES (%s, %s, %s)",
                (FIXTURE_SITE, user_id, None if traits is None else json.dumps(traits)),
            )
        for anonymous_id, user_id in ALIASES:
            cur.execute(
                "INSERT INTO user_aliases (site_id, anonymous_id, user_id, created_at) VALUES (%s, %s, %s, now() - interval '3 days')",
                (FIXTURE_SITE, anonymous_id, user_id),
            )

    existing = ch(f"SELECT count() FROM events WHERE site_id = {FIXTURE_SITE} AND tag = '{TAG}' FORMAT TSV").strip()
    if existing == "0":
        # Site 1's history plus site 4's form and copy interactions, with identities.
        # The subquery matters: INSERT ... SELECT * REPLACE straight from `events`
        # inserts nothing on this ClickHouse version.
        ch(
            f"""INSERT INTO events SELECT * REPLACE (
                  {FIXTURE_SITE} AS site_id,
                  '{TAG}' AS tag,
                  multiIf(
                    user_id = '{ALICE_DEVICE}', 'parity-people-alice',
                    user_id = '{BOB_DEVICE}', 'parity-people-bob',
                    user_id = '{CAROL_DEVICE}' AND timestamp >= toDateTime('2026-08-01 00:00:00'), 'parity-people-carol',
                    identified_user_id)
                  AS identified_user_id)
                FROM (
                  SELECT * FROM events
                  WHERE site_id = 1 OR (site_id = 4 AND type IN ('form_submit', 'copy', 'input_change', 'button_click'))
                )"""
        )
    print(ch(f"SELECT count(), countIf(identified_user_id != '') FROM events WHERE site_id = {FIXTURE_SITE} AND tag = '{TAG}' FORMAT TSV").strip())


def cleanup():
    with pg() as conn, conn.cursor() as cur:
        cleanup_pg(cur)
    ch(f"DELETE FROM events WHERE site_id = {FIXTURE_SITE} AND tag LIKE '{TAG}%'")
    print("cleaned")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "setup"
    if command == "setup":
        setup()
    elif command == "cleanup":
        cleanup()
    elif command == "credentials":
        json.dump(credentials(), sys.stdout, indent=1)
