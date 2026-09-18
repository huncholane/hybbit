"""Shared plumbing for the api-admin differential harness: raw HTTP, the Postgres
fixtures writes start from, resulting-row snapshots and response normalisation.

Outputs (creds.json, results.jsonl) live in $PARITY_ADMIN_OUT.
"""
import calendar
import http.client
import json
import os
import re
import sys
import time

import psycopg2

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fixtures as F  # noqa: E402

OUT = os.environ.get("PARITY_ADMIN_OUT", "/tmp/parity-admin")
NODE = ("127.0.0.1", int(os.environ.get("NODE_PORT", "3001")))
RUST = ("127.0.0.1", int(os.environ.get("RUST_PORT", "3103")))
CREDS = json.load(open(os.path.join(OUT, "creds.json")))
P = F.P

INTERESTING_HEADERS = [
    "content-type",
    "cache-control",
    "x-content-type-options",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "vary",
    "connection",
    "allow",
    "x-ratelimit-limit",
    "retry-after",
]


def send(target, method, path, headers=None, body=None, timeout=120):
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


PG = psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")
PG.autocommit = True

SITES = CREDS["sites"]
ORGS = CREDS["orgs"]
USERS = CREDS["users"]
SITE_LIST = ",".join(str(site) for site in F.SITE_IDS.values())
FLAG_KEYS = [flag[2] for flag in F.FLAGS]
FLAG_KEY_LIST = ",".join("'" + key.replace("'", "''") + "'" for key in FLAG_KEYS)


def ensure_principals():
    """Other agents run against the same stores and some of their cleanups reach
    wider than their own rows, so the principals are checked before every reset and
    rebuilt when any of them has gone. The tokens are deterministic, so creds.json
    stays valid."""
    with PG.cursor() as cur:
        cur.execute(
            "SELECT (SELECT count(*) FROM sites WHERE site_id IN (%s)), "
            '(SELECT count(*) FROM organization WHERE id LIKE %%s), (SELECT count(*) FROM "user" WHERE id LIKE %%s), '
            "(SELECT count(*) FROM session WHERE id LIKE %%s), (SELECT count(*) FROM apikey WHERE id LIKE %%s), "
            "(SELECT count(*) FROM goals WHERE name LIKE %%s)" % SITE_LIST,
            (P + "%", P + "%", P + "%", P + "%", P + "%"),
        )
        sites, orgs, users, sessions, keys, goals = cur.fetchone()
        if (sites, orgs, users, goals) == (len(F.SITE_IDS), len(F.ORGS), len(F.USERS), len(F.GOALS)) and sessions and keys:
            return
        print(
            f"rebuilding principals (sites={sites} orgs={orgs} users={users} goals={goals})",
            file=sys.stderr,
            flush=True,
        )
        F.setup_principals(cur)


def clickhouse_event_count():
    return int(F.clickhouse(f"SELECT count() FROM events WHERE site_id IN ({SITE_LIST})").strip() or 0)


def ensure_events():
    if clickhouse_event_count() != len(F.clickhouse_events()):
        print("rebuilding ClickHouse fixture events", file=sys.stderr, flush=True)
        F.setup_events()


def reset_writable(attempts=6):
    """Put every row a write case can touch back to its fixture value and return
    the fresh symbolic ids. ClickHouse rows are never written by these routes, so
    they stay as `fixtures.py setup` left them.

    Other agents write the same tables, so a reset can deadlock against one of
    their transactions; Postgres kills one side and the reset simply runs again."""
    for attempt in range(attempts):
        try:
            return _reset_writable()
        except psycopg2.errors.DeadlockDetected:  # noqa: PERF203
            print(f"reset deadlocked, retrying ({attempt + 1})", file=sys.stderr, flush=True)
            time.sleep(0.2 * (attempt + 1))
    return _reset_writable()


def _reset_writable():
    ensure_principals()
    ids = {"goals": {}, "flags": {}, "experiments": {}}
    with PG.cursor() as cur:
        # Goal ids survive the reset but are re-read, because a rebuild renumbers them
        cur.execute(f"SELECT name, goal_id FROM goals WHERE name LIKE '{P}%'")
        for name, goal_id in cur.fetchall():
            ids["goals"][name[len(P) :]] = goal_id
        cur.execute(f"DELETE FROM experiments WHERE site_id IN ({SITE_LIST}) OR name LIKE '{P}%'")
        cur.execute(
            f"DELETE FROM feature_flags WHERE site_id IN ({SITE_LIST}) "
            f"OR (site_id = {F.REAL_SITE} AND key IN ({FLAG_KEY_LIST}))"
        )
        cur.execute(f"DELETE FROM telemetry WHERE instance_id LIKE '{P}%'")
        cur.execute(f"DELETE FROM member_site_access WHERE member_id LIKE '{P}%' OR site_id IN ({SITE_LIST})")

        for index, (key, site, flag_key, flag_type, extras) in enumerate(F.FLAGS):
            site_id = site if isinstance(site, int) else F.SITE_IDS[site]
            cur.execute(
                "INSERT INTO feature_flags (site_id, key, description, enabled, runtime, flag_type, payload, "
                "variants, rollout_percentage, rules, condition_sets, salt, version, created_at, updated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s) RETURNING flag_id",
                (
                    site_id,
                    flag_key,
                    extras.get("description"),
                    extras.get("enabled", False),
                    extras.get("runtime", "client"),
                    flag_type,
                    json.dumps(extras["payload"]) if "payload" in extras else None,
                    json.dumps(extras.get("variants", [])),
                    extras.get("rolloutPercentage", 100),
                    json.dumps(extras.get("rules", [])),
                    json.dumps(extras.get("conditionSets", [])),
                    f"{P}salt{index}",
                    1,
                    f"2026-07-{10 + index:02d} 00:00:00.125",
                    f"2026-07-{10 + index:02d} 00:00:00.125",
                ),
            )
            ids["flags"][key] = cur.fetchone()[0]

        for index, (key, site, flag, goal, status) in enumerate(F.EXPERIMENTS):
            site_id = site if isinstance(site, int) else F.SITE_IDS[site]
            cur.execute(
                "INSERT INTO experiments (site_id, feature_flag_id, primary_goal_id, name, description, hypothesis, "
                "status, winning_variant, started_at, ended_at, created_at, updated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING experiment_id",
                (
                    site_id,
                    ids["flags"][flag],
                    ids["goals"][goal] if goal else None,
                    P + key,
                    "description " + key,
                    "hypothesis " + key,
                    status,
                    None,
                    "2026-08-01 00:00:00" if status == "running" else None,
                    None,
                    f"2026-08-{10 + index:02d} 00:00:00.75",
                    f"2026-08-{10 + index:02d} 00:00:00.75",
                ),
            )
            ids["experiments"][key] = cur.fetchone()[0]

        # Organizations: the override columns a subscription-override write changes
        for key, name, override, custom, customer, events, over in F.ORGS:
            cur.execute(
                'UPDATE organization SET "planOverride" = %s, custom_plan = %s::jsonb WHERE id = %s',
                (override, json.dumps(custom) if custom else None, ORGS[key]),
            )
        # Sites: the organization a move changes, and the timestamp it stamps
        for index, (key, org, site_type, domain, public, replay) in enumerate(F.SITES):
            cur.execute(
                "UPDATE sites SET organization_id = %s, updated_at = %s WHERE site_id = %s",
                (ORGS[org] if org else None, f"2026-06-{10 + index:02d} 07:30:00.25", F.SITE_IDS[key]),
            )
        # Members: the role, restriction and grants a member write changes
        for user, org, role, restricted in [
            ("ownerA", "A", "owner", False),
            ("adminA", "A", "admin", False),
            ("memberA", "A", "member", False),
            ("restrictedA", "A", "member", True),
            ("ownerB", "B", "owner", False),
            ("sysadmin", "C", "owner", False),
            ("ownerA", "D", "owner", False),
            ("adminA", "E", "owner", False),
            ("ownerB", "F", "owner", False),
        ]:
            cur.execute(
                'UPDATE member SET role = %s, has_restricted_site_access = %s WHERE id = %s',
                (role, restricted, f"{P}m-{user}-{org}"),
            )
        cur.execute(
            "INSERT INTO member_site_access (member_id, site_id, created_at) VALUES (%s, %s, %s)",
            (f"{P}m-restrictedA-A", F.SITE_IDS["a3"], "2026-05-02 09:00:00"),
        )
    return ids


RECENT = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?Z?$")


def is_recent(text):
    if not isinstance(text, str) or not RECENT.match(text):
        return False
    try:
        stamp = calendar.timegm(time.strptime(text[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return False
    return abs(stamp - time.time()) < 900


def symbolic(ids):
    """(table, id) -> "@name" for every fixture row a response can name."""
    table = {}
    for key, value in ids["flags"].items():
        table[("flagId", value)] = "@flag-" + key
        table[("featureFlagId", value)] = "@flag-" + key
    for key, value in ids["experiments"].items():
        table[("experimentId", value)] = "@exp-" + key
    for key, value in ids["goals"].items():
        table[("goalId", value)] = "@goal-" + key
        table[("primaryGoalId", value)] = "@goal-" + key
    return table


ID_FIELDS = ("flagId", "featureFlagId", "experimentId", "goalId", "primaryGoalId")
STAMP_FIELDS = ("createdAt", "updatedAt", "startedAt", "endedAt")
# Volatile members of the two system-table endpoints, compared by shape only
SHAPE_ONLY = {"tableStats", "rowsByDate", "insertRate", "queryErrors", "items", "total"}


def shape(node):
    if isinstance(node, dict):
        return {"{}": [[name, shape(value)] for name, value in node["{}"]]}
    if isinstance(node, list):
        # Row count varies with live traffic, so only the element shape is kept
        return sorted({json.dumps(shape(item), sort_keys=True) for item in node})
    return type(node).__name__


def normalize_body(text, ids, shape_only):
    """Symbolic fixture ids, masked fresh timestamps and generated salts, with key
    order preserved. `shape_only` members keep their structure but not their values."""
    try:
        value = json.loads(text, object_pairs_hook=lambda pairs: {"{}": pairs})
    except ValueError:
        return text
    table = symbolic(ids)

    def walk(node):
        if isinstance(node, dict):
            out = []
            for name, item in node["{}"]:
                if shape_only and name in SHAPE_ONLY:
                    out.append([name, shape(item)])
                elif name in ID_FIELDS and isinstance(item, int):
                    out.append([name, table.get((name, item), "@new")])
                elif name in STAMP_FIELDS and is_recent(item):
                    out.append([name, "<recent>"])
                elif name == "salt" and isinstance(item, str) and not item.startswith(P):
                    out.append([name, "<salt>"])
                else:
                    out.append([name, walk(item)])
            return {"{}": out}
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return json.dumps(walk(value), ensure_ascii=False)


# The ClickHouse error the missing cloud table produces echoes the query, whose
# bounds come from `DateTime.now()` and so differ by seconds between the two calls
TO_DATETIME = re.compile(r"toDateTime\('[0-9-]{10} [0-9:]{8}'\)")
RAW_IDS = re.compile(r'"(flagId|featureFlagId|experimentId|goalId|primaryGoalId)":\d+')
RAW_STAMPS = re.compile(r'"(createdAt|updatedAt|startedAt|endedAt)":"[0-9 :.TZ+-]+"')
RAW_SALT = re.compile(r'"salt":"[0-9a-f]{32}"')


def comparable(response, ids, shape_only=False):
    headers = {name: response["headers"].get(name) for name in INTERESTING_HEADERS}
    if headers["connection"] and headers["connection"].lower() != "close":
        headers["connection"] = None
    if headers["vary"]:
        headers["vary"] = headers["vary"].lower()
    raw = TO_DATETIME.sub("toDateTime('<now>')", response["body"])
    raw = RAW_SALT.sub('"salt":"<salt>"', RAW_STAMPS.sub(r'"\1":"<ts>"', RAW_IDS.sub(r'"\1":<id>', raw)))
    if shape_only:
        raw = ""
    body = normalize_body(TO_DATETIME.sub("toDateTime('<now>')", response["body"]), ids, shape_only)
    # The raw text catches number spelling and escaping; the parsed form catches
    # key order and values
    return {"status": response["status"], "headers": headers, "body": body, "raw": raw}


SNAPSHOT_TABLES = [
    (
        "feature_flags",
        "flag_id",
        f"site_id IN ({SITE_LIST}) OR (site_id = {F.REAL_SITE} AND key IN ({FLAG_KEY_LIST})) OR key LIKE '{P}%'",
    ),
    ("experiments", "experiment_id", f"site_id IN ({SITE_LIST}) OR name LIKE '{P}%'"),
    ("member", "id", f"id LIKE '{P}%'"),
    ("member_site_access", "id", f"member_id LIKE '{P}%' OR site_id IN ({SITE_LIST})"),
    ("organization", "id", f"id LIKE '{P}%'"),
    ("sites", "site_id", f"site_id IN ({SITE_LIST})"),
    ("telemetry", "id", f"instance_id LIKE '{P}%'"),
    ("segments", "segment_id", f"site_id IN ({SITE_LIST})"),
]


def snapshot(ids):
    """Every row a write can reach, with generated ids, fresh timestamps and
    generated salts masked so two runs of the same case compare equal."""
    reverse = {}
    for key, value in ids["flags"].items():
        reverse[("feature_flags", value)] = "@flag-" + key
    for key, value in ids["experiments"].items():
        reverse[("experiments", value)] = "@exp-" + key
    flag_ids = {value: "@flag-" + key for key, value in ids["flags"].items()}
    goal_ids = {value: "@goal-" + key for key, value in ids["goals"].items()}

    out = {}
    with PG.cursor() as cur:
        for table, id_col, where in SNAPSHOT_TABLES:
            cur.execute(f"SELECT row_to_json(t)::text FROM (SELECT * FROM {table} WHERE {where}) t")
            rows = []
            for (text,) in cur.fetchall():
                row = json.loads(text)
                if id_col in row and isinstance(row[id_col], int):
                    row[id_col] = reverse.get((table, row[id_col]), row[id_col] if table == "sites" else "@new")
                if table == "experiments":
                    row["feature_flag_id"] = flag_ids.get(row.get("feature_flag_id"), "@other")
                    row["primary_goal_id"] = goal_ids.get(row.get("primary_goal_id"), row.get("primary_goal_id"))
                if table == "member_site_access":
                    row.pop("id", None)
                for col in ("created_at", "updated_at", "started_at", "ended_at", "timestamp"):
                    if is_recent(row.get(col)):
                        row[col] = "<recent>"
                if table == "feature_flags" and isinstance(row.get("salt"), str) and not row["salt"].startswith(P):
                    row["salt"] = "<salt>"
                rows.append(row)
            rows.sort(key=lambda r: json.dumps(r, sort_keys=True))
            out[table] = rows
    return out
