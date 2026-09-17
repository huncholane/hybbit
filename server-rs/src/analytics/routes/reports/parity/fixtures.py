#!/usr/bin/env python3
"""Credentials and fixture rows for the reports HTTP parity run (harness.py).

Everything created here is prefixed parity-reports- so cleanup never touches
snapshot rows. Sessions are signed with BETTER_AUTH_SECRET the way better-call
signs them (see server-rs/parity/session/plan.py).

Usage: fixtures.py setup | credentials | cleanup | show
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import urllib.parse

SECRET = os.environ.get("BETTER_AUTH_SECRET", "parity-local-secret-not-for-production")
COOKIE = "__Secure-better-auth.session_token"
ORG = "kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE"
OTHER_ORG = "uYq2uOfGurt0dSp3fffpkYYFlUTyVxLh"
OWNER = "XoNIxodDwuJOefJZebreRpXzn7Sq3hlL"  # system admin, owner of ORG
MEMBER = "ZDZZHJlo6olnWqliEC5t0kHoxcurXqBM"  # plain member of ORG
OTHER_OWNER = "GrOwOZVmycGqPD5WD7yIiw4CWBv0dPBa"  # owner of OTHER_ORG

KEYS = {
    # name: (referenceId, configId, permissions)
    "member": (MEMBER, "default", None),
    "member-scoped-read": (MEMBER, "default", {"funnels": ["read"], "goals": ["read"], "analytics": ["read"]}),
    "member-scoped-segments": (MEMBER, "default", {"funnels": ["read"], "goals": ["read"], "analytics": ["read"], "segments": ["read"]}),
    "org": (ORG, "org", None),
    "org-analytics-only": (ORG, "org", {"analytics": ["read"]}),
    "org-writer": (ORG, "org", {"funnels": ["read", "write"], "goals": ["read", "write"]}),
    "other-org": (OTHER_ORG, "org", None),
    "other-owner": (OTHER_OWNER, "default", None),
}
SESSIONS = {"member": MEMBER, "owner": OWNER, "other-owner": OTHER_OWNER}


def psql(sql):
    env = dict(os.environ, PGPASSWORD="hygo")
    out = subprocess.run(
        ["psql", "-h", "127.0.0.1", "-p", "55432", "-U", "hygo", "analytics", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
        env=env, capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr)
    return out.stdout


def q(value):
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "''") + "'"


def token(name):
    return f"parity-reports-key-{name}"


def sign(value):
    signature = base64.b64encode(hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{signature}", safe="")


def cookie(name):
    return f"{COOKIE}={sign('parity-reports-session-' + name)}"


def setup_credentials():
    statements = ["DELETE FROM apikey WHERE id LIKE 'parity-reports-%'", "DELETE FROM session WHERE id LIKE 'parity-reports-%'"]
    for name, (reference, config, permissions) in KEYS.items():
        hashed = base64.urlsafe_b64encode(hashlib.sha256(token(name).encode()).digest()).decode().rstrip("=")
        statements.append(
            'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, permissions, "createdAt", "updatedAt") VALUES ('
            f"{q('parity-reports-' + name)}, 'parity-reports', {q(hashed)}, {q(reference)}, {q(config)}, true, "
            f"{q(json.dumps(permissions) if permissions else None)}, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc')"
        )
    for name, user in SESSIONS.items():
        statements.append(
            'INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId") VALUES ('
            f"'parity-reports-session-{name}', (now() AT TIME ZONE 'utc') + interval '6 days 23 hours', "
            f"'parity-reports-session-{name}', now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc', '', 'parity', {q(user)})"
        )
    psql(";\n".join(statements))


GOALS = [
    # (site, name, type, config)
    (4, "parity-reports-path", "path", {"pathPattern": "/buy/**"}),
    (4, "parity-reports-path-filters", "path", {"pathPattern": "/", "propertyFilters": [{"key": "utm_source", "value": "google"}]}),
    (4, "parity-reports-event", "event", {"eventName": "domain_search"}),
    (4, "parity-reports-event-legacy", "event", {"eventName": "signup", "eventPropertyKey": "plan", "eventPropertyValue": "pro"}),
    (4, "parity-reports-event-number", "event", {"eventName": "calculator_valuation", "propertyFilters": [{"key": "amount", "value": 10}]}),
    (4, None, "button_click", {}),
    (4, "parity-reports-form", "form_submit", {"valuePattern": "*"}),
    (4, "parity-reports-copy", "copy", {"valuePattern": "  "}),
    (4, "parity-reports-outbound", "outbound", {"valuePattern": "https://**"}),
    (4, "parity-reports-bool", "event", {"eventName": "domain_search", "propertyFilters": [{"key": "flag", "value": True}]}),
    (4, "parity-reports-a", "path", {"pathPattern": "/*"}),
    (4, "parity-reports-b", "path", {"pathPattern": "/pricing"}),
    (37, "parity-reports-37", "path", {"pathPattern": "/careers/**"}),
    (37, "parity-reports-37-event", "event", {"eventName": "hiring_careers_viewed"}),
    (5, "parity-reports-public", "path", {"pathPattern": "**"}),
    (3, "parity-reports-bad-type", "pageview", {"pathPattern": "/"}),
    (3, "parity-reports-empty-path", "path", {"pathPattern": ""}),
]

FIXTURE_GOALS = "name LIKE 'parity-reports-%' OR (name IS NULL AND config::text = '{}' AND site_id = 4)"


def setup_goals():
    psql(f"DELETE FROM goals WHERE {FIXTURE_GOALS}")
    for site, name, kind, config in GOALS:
        # one statement per goal so created_at values differ
        psql(f"INSERT INTO goals (site_id, name, goal_type, config) VALUES ({site}, {q(name)}, {q(kind)}, {q(json.dumps(config))}::jsonb)")


SEGMENTS = [
    (ORG, 4, "parity-reports-seg-mobile", [{"parameter": "device_type", "type": "equals", "value": ["Mobile"]}], False),
    (ORG, None, "parity-reports-seg-org", [{"parameter": "country", "type": "equals", "value": ["US"]}], True),
    (OTHER_ORG, 5, "parity-reports-seg-other", [{"parameter": "browser", "type": "equals", "value": ["Chrome"]}], True),
]


def setup_segments():
    psql("DELETE FROM segments WHERE name LIKE 'parity-reports-%'")
    for org, site, name, filters, public in SEGMENTS:
        psql(
            "INSERT INTO segments (organization_id, site_id, name, filters, is_public) VALUES "
            f"({q(org)}, {site if site is not None else 'NULL'}, {q(name)}, {q(json.dumps(filters))}::jsonb, {'true' if public else 'false'})"
        )


def show():
    goals = psql(f"SELECT json_agg(json_build_object('id', goal_id, 'site', site_id) ORDER BY goal_id) FROM goals WHERE {FIXTURE_GOALS}")
    segments = psql("SELECT json_agg(json_build_object('id', segment_id, 'site', site_id, 'name', name) ORDER BY segment_id) FROM segments WHERE name LIKE 'parity-reports-%'")
    return {"goals": json.loads(goals or "null"), "segments": json.loads(segments or "null")}


def cleanup():
    psql("DELETE FROM apikey WHERE id LIKE 'parity-reports-%'")
    psql("DELETE FROM session WHERE id LIKE 'parity-reports-%'")
    psql(f"DELETE FROM goals WHERE {FIXTURE_GOALS}")
    psql("DELETE FROM segments WHERE name LIKE 'parity-reports-%'")
    psql("DELETE FROM funnels WHERE data->>'name' LIKE 'parity-reports-%'")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "show"
    if action == "setup":
        setup_credentials()
        setup_goals()
        setup_segments()
        print(json.dumps(show()))
    elif action == "credentials":
        setup_credentials()
    elif action == "cleanup":
        cleanup()
    else:
        print(json.dumps(show()))
