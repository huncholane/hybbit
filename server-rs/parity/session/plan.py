#!/usr/bin/env python3
"""Builds the cookie-session parity plan: per case, SQL that resets the parity-*
session rows and a Cookie header signed with BETTER_AUTH_SECRET the way better-call
signs it, so Node's getSession and the Rust port see identical requests.

Usage: BETTER_AUTH_SECRET=... plan.py > plan.json
"""
import base64, hashlib, hmac, json, os, sys, urllib.parse

SECRET = os.environ["BETTER_AUTH_SECRET"]
OWNER = "XoNIxodDwuJOefJZebreRpXzn7Sq3hlL"
NAME = "__Secure-better-auth.session_token"
DONT_REMEMBER = "__Secure-better-auth.dont_remember"


def sign(value, secret=SECRET):
    signature = base64.b64encode(hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{signature}", safe="")


def session_row(token, expires_offset_seconds):
    return (
        'INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId") VALUES ('
        f"'parity-{token}', date_trunc('milliseconds', (now() AT TIME ZONE 'utc') + interval '{expires_offset_seconds} seconds'), "
        f"'{token}', (now() AT TIME ZONE 'utc') - interval '3 days', (now() AT TIME ZONE 'utc') - interval '3 days', '', 'parity', '{OWNER}')"
    )


DAY = 86400
cases = [
    ("no cookie header", [], None),
    ("valid session, refresh not due", [("paritytok1", 7 * DAY - 3600)], f"{NAME}={sign('paritytok1')}"),
    ("valid session, refresh due", [("paritytok2", 5 * DAY)], f"{NAME}={sign('paritytok2')}"),
    ("refresh due but dont_remember", [("paritytok3", 5 * DAY)], f"{NAME}={sign('paritytok3')}; {DONT_REMEMBER}={sign('true')}"),
    ("dont_remember with a bad signature still refreshes", [("paritytok4", 5 * DAY)], f"{NAME}={sign('paritytok4')}; {DONT_REMEMBER}={sign('true', 'wrong')}"),
    ("expired session is deleted", [("paritytok5", -60)], f"{NAME}={sign('paritytok5')}"),
    ("bad signature", [("paritytok6", 6 * DAY)], f"{NAME}={sign('paritytok6', 'wrong')}"),
    ("unsigned token", [("paritytok7", 6 * DAY)], f"{NAME}=paritytok7"),
    ("development cookie name in production", [("paritytok8", 6 * DAY)], f"better-auth.session_token={sign('paritytok8')}"),
    ("unknown token", [], f"{NAME}={sign('paritynobody')}"),
    ("first cookie wins", [("paritytok9", 6 * DAY)], f"{NAME}={sign('paritytok9')}; {NAME}={sign('paritynobody')}"),
    ("later duplicate ignored", [("paritytok10", 6 * DAY)], f"{NAME}={sign('paritynobody')}; {NAME}={sign('paritytok10')}"),
    ("quoted cookie value", [("paritytok11", 6 * DAY)], f'{NAME}="{sign("paritytok11")}"'),
    ("undecoded signature", [("paritytok12", 6 * DAY)], f"{NAME}={urllib.parse.unquote(sign('paritytok12'))}"),
    ("segment without equals before the cookie", [("paritytok13", 6 * DAY)], f"junk; other=1; {NAME}={sign('paritytok13')}"),
    ("malformed percent escape", [("paritytok14", 6 * DAY)], f"{NAME}={sign('paritytok14')}%zz"),
    ("empty token", [], f"{NAME}={sign('')}"),
    ("whitespace around", [("paritytok15", 6 * DAY)], f"  {NAME}  =  {sign('paritytok15')}  ;x=1"),
]

plan = {
    "state": """SELECT coalesce(json_agg(t ORDER BY t.token), '[]')::text FROM (
      SELECT token, "expiresAt" > (now() AT TIME ZONE 'utc') + interval '6 days 23 hours' AS slid
      FROM session WHERE id LIKE 'parity-%') t""",
    "cleanup": ["DELETE FROM session WHERE id LIKE 'parity-%'"],
    "cases": [
        {
            "name": name,
            "setup": ["DELETE FROM session WHERE id LIKE 'parity-%'"] + [session_row(token, offset) for token, offset in rows],
            "cookie": cookie,
        }
        for name, rows, cookie in cases
    ],
}
json.dump(plan, sys.stdout, indent=1)
