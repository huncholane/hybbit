"""Differential runner: every scenario runs once against Node and once against Rust
with fresh fixtures; responses and database rows are normalised (random ids numbered
in order of appearance, timestamps bucketed relative to now, signed cookies verified,
password hashes checked) and compared step by step."""

import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import time
import traceback
import urllib.parse

import harness as h

ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
RAND_RE = re.compile(r"^[A-Za-z0-9]{32}$")
RAND64_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
HASH_RE = re.compile(r"^[0-9a-f]{32}:[0-9a-f]{128}$")
OTP_RE = re.compile(r"^(\d{6}):(\d+|NaN)$")
DUMP = False
IGNORED_HEADERS = {"date", "connection", "keep-alive", "transfer-encoding", "content-length", "vary"}


class Run:
    def __init__(self, port, label):
        self.port = port
        self.label = label
        self.obs = []  # (endpoint, observation)
        self.symbols = {}
        self.counter = 0
        self.passwords = []
        self.tag = f"{label}{h.rand_id(8).lower()}"
        self.symbols[self.tag] = "<tag>"

    # -- fixtures -------------------------------------------------------------
    def name(self, value, symbol):
        self.symbols[value] = f"<{symbol}>"
        return value

    def user(self, key, **kw):
        user = h.create_user(f"{self.tag}-{key}", **kw)
        self.name(user["id"], f"user:{key}")
        self.name(user["email"], f"email:{key}")
        if kw.get("password"):
            self.passwords.append(kw["password"])
        return user

    def session(self, key, user_id, **kw):
        token = h.create_session(user_id, **kw)
        self.name(token, f"token:{key}")
        return token

    def org(self, key, owner_id=None, **kw):
        org = h.create_org(f"{self.tag}-{key}", owner_id=owner_id, **kw)
        self.name(org["id"], f"org:{key}")
        self.name(org["slug"], f"slug:{key}")
        return org

    def password(self, value):
        self.passwords.append(value)
        return value

    # -- requests ---------------------------------------------------------------
    def req(self, endpoint, method, path, note="", unordered=None, **kw):
        """`unordered`: a key path (list of keys, [] for the body itself) naming an
        array both backends read without ORDER BY; it is compared as a multiset."""
        started = time.time()
        r = h.request(self.port, method, path, **kw)
        normalized = self.normalize_response(r, started)
        if unordered is not None:
            paths = unordered if unordered and isinstance(unordered[0], list) else [unordered]
            for key_path in paths:
                normalized["body"] = sort_at(normalized["body"], key_path)
        self.obs.append((endpoint, {"step": f"{method} {path.split('?')[0]} {note}".strip(), "response": normalized}))
        return r

    def check(self, endpoint, label, value):
        self.obs.append((endpoint, {"step": label, "value": self.normalize(value, time.time())}))

    def db(self, endpoint, label, sql, *params):
        rows = h.q(sql, *params)
        self.obs.append((endpoint, {"step": f"db {label}", "rows": self.normalize(rows, time.time())}))
        return rows

    # -- normalisation -------------------------------------------------------------
    def rand(self, value):
        if value not in self.symbols:
            self.counter += 1
            self.symbols[value] = f"<r{self.counter}>"
        return self.symbols[value]

    def bucket(self, when, now):
        delta = (when - now) / 60.0
        return f"<ts{int(round(delta)):+d}m>"

    def normalize_string(self, value, now):
        if value in self.symbols:
            return self.symbols[value]
        if ISO_RE.match(value):
            parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)
            return self.bucket(parsed.timestamp(), now)
        if re.match(r"^10\.\d+\.\d+\.\d+$", value):
            return "<ip>"
        m = re.match(r"^parity-auth-(ses|acc|mem|key)-[A-Za-z0-9]+$", value)
        if m:
            return f"<fixture-{m.group(1)}>"
        if re.match(r"^[A-Za-z0-9_-]{128}$", value):
            return "<verifier128>"
        if re.match(r"^[A-Za-z0-9_-]{43}$", value) and not re.match(r"^[A-Z_]+$", value):
            return "<b64url43>"
        m = re.match(r"^(Sites do not belong to organization: )([\d, ]+)$", value)
        if m:
            return m.group(1) + ", ".join(self.symbols.get(int(n), n) for n in m.group(2).split(", "))
        if re.match(r"^[A-Za-z0-9_-]{32}$", value) and ("-" in value or "_" in value):
            return self.rand(value)
        if HASH_RE.match(value):
            for password in self.passwords:
                if h.verify_password(value, password):
                    return f"<scrypt:{password}>"
            return "<scrypt:?>"
        m = OTP_RE.match(value)
        if m:
            return f"<otp>:{m.group(2)}"
        if RAND_RE.match(value):
            return self.rand(value)
        if JWT_RE.match(value) and value.count(".") == 2 and len(value) > 40:
            try:
                payload = json.loads(base64.urlsafe_b64decode(value.split(".")[1] + "=="))
                return {"jwt": self.normalize(payload, now)}
            except Exception:
                return "<jwt?>"
        if value.startswith("http") or value.startswith("/"):
            parsed = urllib.parse.urlsplit(value)
            if parsed.query:
                pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                normalized = [(k, self.normalize_string(v, now) if not v.isdigit() else v) for k, v in pairs]
                return {"url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else parsed.path, "query": normalized}
        for symbol_value, symbol in sorted(((k, v) for k, v in self.symbols.items() if isinstance(k, str)), key=lambda kv: -len(kv[0])):
            if len(symbol_value) >= 8 and symbol_value in value:
                value = value.replace(symbol_value, symbol)
        if value.startswith("{") or value.startswith("["):
            try:
                return {"json": self.normalize(json.loads(value), now)}
            except ValueError:
                pass
        return value

    def normalize(self, value, now):
        if isinstance(value, dict):
            return [(k, self.normalize(v, now)) for k, v in value.items()]
        if isinstance(value, list):
            return [self.normalize(v, now) for v in value]
        if isinstance(value, str):
            return self.normalize_string(value, now)
        if isinstance(value, int) and not isinstance(value, bool) and value in self.symbols:
            return self.symbols[value]
        if isinstance(value, int) and not isinstance(value, bool) and 1_600_000_000_000 < value < 2_000_000_000_000:
            return self.bucket(value / 1000.0, now) + "(epoch-ms)"
        if isinstance(value, int) and not isinstance(value, bool) and 1_600_000_000 < value < 2_000_000_000:
            return self.bucket(float(value), now) + "(epoch-s)"
        if isinstance(value, dt.datetime):
            precision = "" if value.microsecond % 1000 == 0 else "!sub-ms"
            return self.bucket(value.replace(tzinfo=dt.timezone.utc).timestamp(), now) + precision
        return value

    def normalize_cookie(self, cookie, now):
        name, _, rest = cookie.partition("=")
        value, _, attrs = rest.partition(";")
        decoded = urllib.parse.unquote(value)
        signed = None
        if "." in decoded:
            body, sig = decoded.rsplit(".", 1)
            expected = base64.b64encode(hmac.new(h.SECRET.encode(), body.encode(), hashlib.sha256).digest()).decode()
            if hmac.compare_digest(sig, expected):
                signed = body
        shown = {"signed": self.normalize_string(signed, now)} if signed is not None else self.normalize_string(decoded, now)
        return [name, shown, attrs.strip()]

    def normalize_response(self, r, now):
        headers = {}
        for k, v in r.headers:
            if k in IGNORED_HEADERS or k == "set-cookie":
                continue
            headers[k] = v
        out = {"status": r.status}
        out["cookies"] = [self.normalize_cookie(c, now) for c in r.set_cookies]
        if "location" in headers:
            out["location"] = self.normalize_string(headers.pop("location"), now)
        out["headers"] = sorted((k, v) for k, v in headers.items())
        body = r.json() if r.body else None
        if r.body and body is None and r.body != "null":
            out["body"] = self.normalize_string(r.body, now)
        else:
            out["body"] = self.normalize(body, now)
        return out


def run_scenarios(scenarios, node_port, rust_port, only=None):
    results = {}  # endpoint -> [pass, total]
    mismatches = []
    for scenario in scenarios:
        if only and not any(o in scenario.__name__ for o in only):
            continue
        records = []
        for label, port in (("n", node_port), ("r", rust_port)):
            run = Run(port, label)
            try:
                scenario(run)
            except Exception:
                print(f"[{scenario.__name__}/{label}] exception:\n{traceback.format_exc()}")
                run.obs.append(("<scenario>", {"step": "exception", "value": traceback.format_exc().splitlines()[-1]}))
            records.append(run)
            # Each backend run gets a clean slate so searches cannot see the other run's rows.
            h.cleanup()
        node, rust = records
        if DUMP:
            for endpoint, observation in node.obs:
                print(f"[{scenario.__name__}] {endpoint}: {json.dumps(observation)[:700]}")
        for index in range(max(len(node.obs), len(rust.obs))):
            n = node.obs[index] if index < len(node.obs) else ("<missing>", None)
            r = rust.obs[index] if index < len(rust.obs) else ("<missing>", None)
            endpoint = n[0] if n[0] != "<missing>" else r[0]
            stats = results.setdefault(endpoint, [0, 0])
            stats[1] += 1
            if json.dumps(n[1], sort_keys=False) == json.dumps(r[1], sort_keys=False):
                stats[0] += 1
            else:
                order_only = n[1] is not None and r[1] is not None and json.dumps(sortdeep(n[1])) == json.dumps(sortdeep(r[1]))
                if not order_only and n[1] is not None and r[1] is not None and json.dumps(without_open_acao(n[1])) == json.dumps(without_open_acao(r[1])):
                    order_only = "acao"
                mismatches.append((scenario.__name__, endpoint, n[1], r[1], order_only))
        h.cleanup()
    return results, mismatches


def without_open_acao(observation):
    """The observation with Access-Control-Allow-Origin blanked when Node answered
    `*` (Better Auth's own open CORS on mcp/authorize and mcp/register, which the
    Rust CORS layer currently overwrites with the reflected origin)."""
    response = observation.get("response") if isinstance(observation, dict) else None
    if not response:
        return observation
    headers = [[k, "<acao>" if k == "access-control-allow-origin" else v] for k, v in response["headers"]]
    return {**observation, "response": {**response, "headers": headers}}


def sort_at(body, path):
    """Sort the array at `path` (keys into the normalised [key, value] pair lists)."""
    if not path:
        return sorted(body, key=lambda item: json.dumps(item)) if isinstance(body, list) else body
    if not isinstance(body, list):
        return body
    return [[k, sort_at(v, path[1:])] if k == path[0] else [k, v] for k, v in body]


def sortdeep(value):
    if isinstance(value, dict):
        return {k: sortdeep(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        if all(isinstance(v, list) and len(v) == 2 and isinstance(v[0], str) for v in value) and value:
            return sorted(([k, sortdeep(v)] for k, v in value), key=lambda kv: kv[0])
        return [sortdeep(v) for v in value]
    return value
