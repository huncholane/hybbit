"""Shared plumbing for the workspace differential harness: raw HTTP, a tiny Redis
client, Postgres row fixtures with symbolic ids, and response normalisation.

Outputs (creds.json, results) live in $PARITY_WORKSPACE_OUT."""
import calendar, http.client, json, os, re, socket, time

import psycopg2

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("PARITY_WORKSPACE_OUT", "/tmp/parity-workspace")
NODE = ("127.0.0.1", int(os.environ.get("NODE_PORT", "3001")))
RUST = ("127.0.0.1", int(os.environ.get("RUST_PORT", "3057")))
CREDS = json.load(open(os.path.join(OUT, "creds.json")))
P = "parity-workspace-"

INTERESTING_HEADERS = [
    "content-type", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after",
    "cache-control", "x-content-type-options", "access-control-allow-origin", "access-control-allow-credentials",
    "vary", "connection", "allow",
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


class Redis:
    def __init__(self, port=56379, password="hygo"):
        self.sock = socket.create_connection(("127.0.0.1", port))
        self.buf = b""
        self.cmd("AUTH", password)

    def _line(self):
        while b"\r\n" not in self.buf:
            self.buf += self.sock.recv(65536)
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _read(self):
        line = self._line()
        kind, rest = line[:1], line[1:]
        if kind in (b"+", b"-"):
            return rest.decode()
        if kind == b":":
            return int(rest)
        if kind == b"$":
            length = int(rest)
            if length < 0:
                return None
            while len(self.buf) < length + 2:
                self.buf += self.sock.recv(65536)
            data, self.buf = self.buf[:length], self.buf[length + 2:]
            return data.decode()
        if kind == b"*":
            return [self._read() for _ in range(int(rest))]
        raise RuntimeError(line)

    def cmd(self, *args):
        out = b"*%d\r\n" % len(args)
        for arg in args:
            data = str(arg).encode()
            out += b"$%d\r\n%s\r\n" % (len(data), data)
        self.sock.sendall(out)
        return self._read()

    def keys(self, pattern):
        cursor, found = "0", []
        while True:
            cursor, batch = self.cmd("SCAN", cursor, "MATCH", pattern, "COUNT", 1000)
            found += batch
            if cursor == "0":
                return found


REDIS = Redis()
LIMITER_PREFIXES = [
    "fastify-rate-limit-POST/api/sites/:siteId/dashboards/run-card-",
    "fastify-rate-limit-POST/api/organizations/:organizationId/analytics/query-",
    "fastify-rate-limit-POST/api/organizations/:organizationId/analytics/query/generate-",
]


def reset_limits():
    for prefix in LIMITER_PREFIXES:
        for key in REDIS.keys(prefix + "*"):
            REDIS.cmd("DEL", key)


PG = psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")
PG.autocommit = True
U = CREDS["users"]
S = CREDS["sites"]
O = CREDS["orgs"]
JUSTIN = "ZDZZHJlo6olnWqliEC5t0kHoxcurXqBM"

SEGMENTS = [
    ("segA1m1", O["A"], S["A1"], U["memberA1"], "a member1 mobile", "d1", [{"parameter": "country", "type": "equals", "value": ["DE"]}], False),
    ("segA1m2pub", O["A"], S["A1"], U["memberA2"], "b member2 lat", None, [{"parameter": "lat", "type": "greater_than", "value": [48.1]}], True),
    ("segOrgAadmin", O["A"], None, U["adminA"], "c org admin", "org wide", [{"parameter": "browser", "type": "not_equals", "value": ["Chrome", "Safari"]}], True),
    ("segOrgAownerPriv", O["A"], None, U["ownerA"], "d org owner private", None, [{"parameter": "user_id", "type": "is_not_null", "value": []}], False),
    ("segA2m1pub", O["A"], S["A2"], U["memberA1"], "e a2 public", None, [{"parameter": "pathname", "type": "regex", "value": ["^/docs"]}], True),
    ("segA3restricted", O["A"], S["A3"], U["restrictedA"], "f a3 restricted", None, [{"parameter": "device_type", "type": "equals", "value": ["Mobile"]}], False),
    ("segB1", O["B"], S["B1"], U["ownerB"], "g b1", None, [{"parameter": "country", "type": "equals", "value": ["US"]}], True),
    ("segKb", O["kb"], 1, JUSTIN, "h kb justin", None, [{"parameter": "country", "type": "equals", "value": ["FR"]}], False),
    ("segNullUser", O["A"], S["A1"], None, "i a1 no user", None, [{"parameter": "channel", "type": "equals", "value": ["Direct"]}], True),
]

ANNOTATIONS = [
    ("annA1m1", O["A"], S["A1"], U["memberA1"], "a1 member1", None, "2026-08-18 07:00:00+00", None, "amber", "🚀", False),
    ("annA1m2pub", O["A"], S["A1"], U["memberA2"], "a1 member2", "desc", "2026-08-24 12:10:00.5+00", "2026-08-26 00:00:00+00", None, None, True),
    ("annOrgA", O["A"], None, U["adminA"], "org admin", None, "2026-07-31 23:30:00+00", None, "sky", None, True),
    ("annOrgApriv", O["A"], None, U["ownerA"], "org owner private", None, "2026-09-01 04:00:00.123456+00", "2026-09-03 04:00:00+00", None, "🏷️", False),
    ("annA2pub", O["A"], S["A2"], U["memberA1"], "a2 public", None, "2026-09-10 00:00:00+00", None, "lime", None, True),
    ("annA3", O["A"], S["A3"], U["restrictedA"], "a3 restricted", None, "2026-09-11 00:00:00+00", None, None, None, False),
    ("annB1", O["B"], S["B1"], U["ownerB"], "b1", None, "2026-09-12 00:00:00+00", None, None, None, True),
    ("annKb", O["kb"], 1, JUSTIN, "kb justin", None, "2026-09-13 00:00:00+00", None, None, None, False),
    ("annNullUser", O["A"], S["A1"], None, "a1 no user", None, "2026-01-01 00:00:00+00", "2026-12-31 23:59:59.999+00", "rose", "x", True),
]

CARD = {"cards": [{"id": "c1", "title": "Events", "sql": "SELECT count() FROM scoped_events", "vizType": "stat",
                   "mapping": {"valueColumn": "count()", "valueFormat": "number"}, "gridPos": {"x": 0, "y": 0, "w": 4, "h": 2}}]}
DASHBOARDS = [
    ("dashA1m1", S["A1"], U["memberA1"], "a1 member1", CARD, "2026-02-01 00:00:00.5"),
    ("dashA1old", S["A1"], U["adminA"], "a1 admin old", {"cards": []}, "2026-01-01 00:00:00"),
    ("dashA2", S["A2"], U["memberA2"], "a2", CARD, "2026-03-01 00:00:00"),
    ("dashB1", S["B1"], U["ownerB"], "b1", {"cards": []}, "2026-03-02 00:00:00"),
    ("dashKb", 1, JUSTIN, "kb", CARD, "2026-03-03 00:00:00"),
    ("dashNoSite", None, U["adminA"], "no site", {"cards": []}, "2026-03-04 00:00:00"),
]


def clear_rows(cur):
    cur.execute(f"DELETE FROM annotations WHERE title LIKE '{P}%' OR organization_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM segments WHERE name LIKE '{P}%' OR organization_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM dashboards WHERE name LIKE '{P}%' OR site_id IN (SELECT site_id FROM sites WHERE organization_id LIKE '{P}%')")


def reset_fixtures():
    """Delete every workspace row and insert the fixture set; returns key -> id."""
    ids = {}
    with PG.cursor() as cur:
        clear_rows(cur)
        for index, (key, org, site, user, name, desc, filters, public) in enumerate(SEGMENTS):
            cur.execute(
                "INSERT INTO segments (organization_id, site_id, user_id, name, description, filters, is_public, created_at, updated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s) RETURNING segment_id",
                (org, site, user, P + name, desc, json.dumps(filters), public, f"2026-01-0{1 + index} 10:00:00.123456", f"2026-01-0{1 + index} 11:00:00"),
            )
            ids[key] = cur.fetchone()[0]
        for index, (key, org, site, user, title, desc, date, end, color, icon, public) in enumerate(ANNOTATIONS):
            cur.execute(
                "INSERT INTO annotations (site_id, organization_id, user_id, title, description, date, end_date, color, icon, is_public, created_at, updated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING annotation_id",
                (site, org, user, P + title, desc, date, end, color, icon, public, f"2026-02-0{1 + index} 10:00:00.5", f"2026-02-0{1 + index} 10:00:00.5"),
            )
            ids[key] = cur.fetchone()[0]
        for key, site, user, name, config, updated in DASHBOARDS:
            cur.execute(
                "INSERT INTO dashboards (site_id, user_id, name, config, created_at, updated_at) VALUES (%s,%s,%s,%s::jsonb,%s,%s) RETURNING dashboard_id",
                (site, user, P + name, json.dumps(config), "2026-01-01 00:00:00", updated),
            )
            ids[key] = cur.fetchone()[0]
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


def snapshot(ids):
    """Every workspace row, ids symbolic and fresh timestamps masked."""
    reverse = {}
    for key, value in ids.items():
        table = "segments" if key.startswith("seg") else "annotations" if key.startswith("ann") else "dashboards"
        reverse[(table, value)] = key
    out = {}
    with PG.cursor() as cur:
        for table, id_col, where in [
            ("segments", "segment_id", f"name LIKE '{P}%' OR organization_id LIKE '{P}%'"),
            ("annotations", "annotation_id", f"title LIKE '{P}%' OR organization_id LIKE '{P}%'"),
            ("dashboards", "dashboard_id", f"name LIKE '{P}%' OR site_id IN (SELECT site_id FROM sites WHERE organization_id LIKE '{P}%')"),
        ]:
            cur.execute(f"SELECT row_to_json(t)::text FROM (SELECT * FROM {table} WHERE {where}) t")
            rows = []
            for (text,) in cur.fetchall():
                row = json.loads(text)
                row[id_col] = reverse.get((table, row[id_col]), "@new")
                for col in ("created_at", "updated_at"):
                    if is_recent(row.get(col)):
                        row[col] = "<recent>"
                rows.append(row)
            rows.sort(key=lambda r: json.dumps(r, sort_keys=True))
            out[table] = rows
    return out


UUID = re.compile(r'"queryId":"[0-9a-f-]{36}"')
ID_FIELDS = {"segmentId": "seg", "annotationId": "ann", "dashboardId": "dash"}


def normalize_body(text, ids):
    """Symbolic fixture ids, masked query ids and fresh timestamps; key order kept."""
    text = UUID.sub('"queryId":"<uuid>"', text)
    try:
        value = json.loads(text, object_pairs_hook=lambda pairs: {"{}": pairs})
    except ValueError:
        return text
    reverse = {}
    for key, number in ids.items():
        for field, prefix in ID_FIELDS.items():
            if key.startswith(prefix):
                reverse[(field, number)] = "@" + key

    def walk(node):
        if isinstance(node, dict):
            out = []
            for name, item in node["{}"]:
                if name in ID_FIELDS and isinstance(item, int):
                    out.append([name, reverse.get((name, item), "@new")])
                elif name in ("createdAt", "updatedAt") and is_recent(item):
                    out.append([name, "<recent>"])
                else:
                    out.append([name, walk(item)])
            return {"{}": out}
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return json.dumps(walk(value), ensure_ascii=False)


RAW_IDS = re.compile(r'"(segmentId|annotationId|dashboardId)":\d+')
RAW_STAMPS = re.compile(r'"(createdAt|updatedAt)":"[0-9 :.TZ+-]+"')


def comparable(response, ids):
    headers = {name: response["headers"].get(name) for name in INTERESTING_HEADERS}
    if headers["connection"] and headers["connection"].lower() != "close":
        headers["connection"] = None
    if headers["vary"]:
        headers["vary"] = headers["vary"].lower()
    raw = UUID.sub('"queryId":"<uuid>"', response["body"])
    raw = RAW_STAMPS.sub(r'"\1":"<ts>"', RAW_IDS.sub(r'"\1":<id>', raw))
    # The raw text catches number spelling and escaping; the parsed form catches key order and values
    return {"status": response["status"], "headers": headers, "body": normalize_body(response["body"], ids), "raw": raw}
