"""Shared plumbing for the api-orgs differential harness: raw HTTP, Postgres row
snapshots with symbolic ids, and response normalisation.

Outputs (creds.json, results.jsonl) live in $PARITY_ORGS_OUT."""
import http.client
import json
import os
import re

import psycopg2

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("PARITY_ORGS_OUT", "/tmp/parity-orgs")
NODE = ("127.0.0.1", int(os.environ.get("NODE_PORT", "3001")))
RUST = ("127.0.0.1", int(os.environ.get("RUST_PORT", "3102")))
P = "parity-orgs-"

INTERESTING_HEADERS = [
    "content-type",
    "cache-control",
    "x-content-type-options",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "vary",
    "connection",
    "allow",
    "retry-after",
    "location",
    "set-cookie",
]


def send(target, method, path, headers=None, body=None, timeout=60):
    """One request on a fresh connection. body: bytes or None. headers: list of pairs."""
    conn = http.client.HTTPConnection(*target, timeout=timeout)
    try:
        conn.putrequest(method, path, skip_accept_encoding=True, skip_host=False)
        for name, value in headers or []:
            conn.putheader(name, value)
        if body is not None and not any(n.lower() in ("content-length", "transfer-encoding") for n, _ in headers or []):
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body:
            conn.send(body)
        response = conn.getresponse()
        data = response.read()
        hdrs = {}
        for name, value in response.getheaders():
            hdrs.setdefault(name.lower(), value)
        return {"status": response.status, "headers": hdrs, "body": data.decode("utf-8", "replace")}
    except Exception as err:  # noqa: BLE001
        return {"status": -1, "headers": {}, "body": f"transport error: {type(err).__name__}"}
    finally:
        conn.close()


def connect():
    conn = psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")
    conn.autocommit = True
    return conn


PG = connect()

# Tables a write in this group can touch. Each is snapshotted for rows belonging to
# the harness only, so the other agents' fixtures in the same database are invisible.
SNAPSHOT_TABLES = [
    ("member", f"\"organizationId\" LIKE '{P}%'", "id"),
    ("member_site_access", f"member_id IN (SELECT id FROM member WHERE \"organizationId\" LIKE '{P}%')", "id"),
    ("team", f"\"organizationId\" LIKE '{P}%'", "id"),
    ("teamMember", f"\"teamId\" IN (SELECT id FROM team WHERE \"organizationId\" LIKE '{P}%')", "id"),
    ("team_site_access", f"team_id IN (SELECT id FROM team WHERE \"organizationId\" LIKE '{P}%')", "id"),
    ("sites", f"organization_id LIKE '{P}%'", "site_id"),
    ("organization", f"id LIKE '{P}%'", "id"),
    ("apikey", f"id LIKE '{P}%' OR \"referenceId\" LIKE '{P}%'", "id"),
    ("user", f"id LIKE '{P}%' OR email LIKE '%{P}test%'", "id"),
    ("account", f"\"userId\" LIKE '{P}%' OR \"userId\" IN (SELECT id FROM \"user\" WHERE email LIKE '%{P}test%')", "id"),
]

# Columns whose value is a fresh id, secret or timestamp: masked so two runs that
# produce equivalent rows compare equal.
VOLATILE = {
    "member": ["id", "createdAt"],
    "member_site_access": ["id", "created_at"],
    "team": ["id", "createdAt", "updatedAt"],
    "teamMember": ["id", "teamId", "createdAt"],
    "team_site_access": ["id", "team_id", "created_at"],
    "sites": ["id", "site_id", "created_at", "updated_at", "api_key", "private_link_key", "detected_platform"],
    "organization": [],
    "apikey": ["id", "key", "start", "createdAt", "updatedAt", "expiresAt", "lastRequest"],
    "user": ["id", "createdAt", "updatedAt"],
    "account": ["id", "accountId", "userId", "password", "createdAt", "updatedAt"],
}


GENERATED_ID = re.compile(r"^[0-9A-Za-z]{32}$")


def mask_value(value):
    """A freshly generated Better Auth id differs between the two runs; the
    harness's own ids all carry the prefix, so anything else of that shape is one."""
    if isinstance(value, str) and not value.startswith(P) and GENERATED_ID.match(value):
        return "<generated>"
    return value


def snapshot():
    """Every row this harness owns, with volatile columns masked."""
    out = {}
    with PG.cursor() as cur:
        for table, where, order in SNAPSHOT_TABLES:
            cur.execute(f'SELECT row_to_json(t)::text FROM (SELECT * FROM "{table}" WHERE {where}) t')
            rows = []
            for (text,) in cur.fetchall():
                row = json.loads(text)
                for column in VOLATILE[table]:
                    if column in row and row[column] is not None:
                        row[column] = f"<{column}>"
                row = {name: mask_value(value) for name, value in row.items()}
                rows.append(row)
            rows.sort(key=lambda r: json.dumps(r, sort_keys=True))
            out[table] = rows
    return out


ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
PG_STAMP = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HEX12 = re.compile(r'"id":"[0-9a-f]{12}"')
KEY_ID = re.compile(r'"(id|key|start)":"[0-9A-Za-z_-]{6,90}"')
SITE_ID = re.compile(r'"(siteId|site_id)":\d+')
NEW_ID = re.compile(r'"id":"[0-9A-Za-z]{32}"')
RESETS = re.compile(r'"resetsInSeconds":\d+')


def normalize(text):
    """Mask the parts of a body that legitimately differ between two runs: fresh
    ids, generated keys, timestamps and the seconds-to-midnight countdown."""
    text = UUID.sub("<uuid>", text)
    text = ISO.sub("<iso>", text)
    text = PG_STAMP.sub("<stamp>", text)
    text = HEX12.sub('"id":"<hex12>"', text)
    text = NEW_ID.sub('"id":"<id32>"', text)
    text = KEY_ID.sub(lambda m: f'"{m.group(1)}":"<{m.group(1)}>"', text)
    text = SITE_ID.sub(lambda m: f'"{m.group(1)}":<siteId>', text)
    text = RESETS.sub('"resetsInSeconds":<seconds>', text)
    return text


def comparable(response, mask_new_ids):
    headers = {name: response["headers"].get(name) for name in INTERESTING_HEADERS}
    # Content-Length is only comparable where the body is compared byte for byte; a
    # masked body hides the generated ids and countdowns whose width differs
    if not mask_new_ids:
        headers["content-length"] = response["headers"].get("content-length")
    if headers["connection"] and headers["connection"].lower() != "close":
        headers["connection"] = None
    if headers["vary"]:
        headers["vary"] = headers["vary"].lower()
    body = response["body"]
    if mask_new_ids:
        body = normalize(body)
    else:
        body = RESETS.sub('"resetsInSeconds":<seconds>', body)
    return {"status": response["status"], "headers": headers, "body": body}
