#!/usr/bin/env python3
"""Builds the bearer parity plan from cases.json: per case, SQL that resets the
parity-* apikey and oauthAccessToken rows and inserts the case's credentials, so
Node and Rust always start from identical rows.

Usage: setup.py <cases.json> > plan.json
The plan lists, per case, the setup statements, the credential and the target, plus
the query both runners use to read back the parity-* rows.
"""
import hashlib, base64, json, sys

STATE_SQL = """SELECT coalesce(json_agg(t ORDER BY t.id), '[]')::text FROM (
  SELECT id, remaining, "requestCount" AS request_count, enabled,
         "lastRequest" IS NOT NULL AS stamped,
         "lastRefillAt" > (now() AT TIME ZONE 'utc') - interval '1 minute' AS refilled_recently
  FROM apikey WHERE id LIKE 'parity-%') t"""


def quote(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def offset(seconds, milliseconds=False):
    """A UTC timestamp relative to now; microsecond precision unless the row should
    look Node-written (Node stores JS Dates, so milliseconds)."""
    if seconds is None:
        return "NULL"
    value = f"(now() AT TIME ZONE 'utc') + interval '{int(seconds)} seconds'"
    return f"date_trunc('milliseconds', {value})" if milliseconds else value


def case_plan(spec, case):
    def resolve(value):
        if isinstance(value, str) and value.startswith("$"):
            return spec[value[1:]]
        return value

    statements = [
        "DELETE FROM apikey WHERE id LIKE 'parity-%'",
        "DELETE FROM \"oauthAccessToken\" WHERE id LIKE 'parity-%'",
        'INSERT INTO "oauthApplication" (id, name, "clientId", "redirectUrls", type, "createdAt", "updatedAt") '
        "VALUES ('parity-app', 'parity', 'parity-client', 'http://localhost/cb', 'public', now(), now()) "
        "ON CONFLICT (id) DO NOTHING",
    ]
    for key in case.get("keys", []):
        hashed = base64.urlsafe_b64encode(hashlib.sha256(key["key"].encode()).digest()).decode().rstrip("=")
        statements.append(
            'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, "expiresAt", remaining, '
            '"refillAmount", "refillInterval", "lastRefillAt", permissions, "createdAt", "updatedAt") VALUES ('
            + ", ".join([
                quote(key["id"]), quote("parity"), quote(hashed), quote(resolve(key["referenceId"])),
                quote(key.get("configId")), quote(key.get("enabled", True)), offset(key.get("expiresAtOffsetSeconds")),
                quote(key.get("remaining")), quote(key.get("refillAmount")), quote(key.get("refillInterval")),
                offset(key.get("lastRefillAtOffsetSeconds"), key.get("millisecondTimestamps", False)), quote(key.get("permissions")),
                "(now() AT TIME ZONE 'utc') - interval '2 hours'", "(now() AT TIME ZONE 'utc') - interval '2 hours'",
            ])
            + ")"
        )
    for token in case.get("oauth", []):
        statements.append(
            'INSERT INTO "oauthAccessToken" (id, "accessToken", "accessTokenExpiresAt", "clientId", "userId", scopes, '
            '"createdAt", "updatedAt") VALUES ('
            + ", ".join([
                quote(token["id"]), quote(token["accessToken"]), offset(token["expiresOffsetSeconds"]),
                quote(spec["client"]), quote(resolve(token["userId"])), quote(token["scopes"]),
                "now() AT TIME ZONE 'utc'", "now() AT TIME ZONE 'utc'",
            ])
            + ")"
        )
    target = {name: resolve(value) for name, value in case.get("target", {}).items()}
    return {
        "name": case["name"],
        "setup": statements,
        "token": case.get("token"),
        "queryApiKey": case.get("queryApiKey"),
        "target": target,
    }


def main():
    spec = json.load(open(sys.argv[1]))
    plan = {
        "state": STATE_SQL,
        "cleanup": [
            "DELETE FROM apikey WHERE id LIKE 'parity-%'",
            "DELETE FROM \"oauthAccessToken\" WHERE id LIKE 'parity-%'",
            "DELETE FROM \"oauthApplication\" WHERE id = 'parity-app'",
        ],
        "cases": [case_plan(spec, case) for case in spec["cases"]],
    }
    json.dump(plan, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
