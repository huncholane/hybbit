"""Shared helpers for the /api/auth differential suite: raw HTTP with every
Set-Cookie kept, Better Auth cookie signing, scrypt password hashes and parity
fixtures (ids and emails prefixed parity-auth-)."""

import base64
import hashlib
import hmac
import http.client
import json
import os
import random
import string
import time
import unicodedata
import urllib.parse
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

SECRET = os.environ.get("BETTER_AUTH_SECRET", "parity-local-secret-not-for-production")
PREFIX = "__Secure-better-auth."
SESSION_COOKIE = PREFIX + "session_token"
DONT_REMEMBER_COOKIE = PREFIX + "dont_remember"
ADMIN_SESSION_COOKIE = PREFIX + "admin_session"
ORIGIN = "https://a.hygo.ai"

_ip_counter = [random.randint(1, 200)]


def fresh_ip():
    """A distinct X-Forwarded-For per request keeps Better Auth's in-memory rate
    limiter (keyed on ip|path) from interfering between cases."""
    _ip_counter[0] += 1
    n = _ip_counter[0] + int(time.time() * 1000) % 60000
    return f"10.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255 or 1}"


def db():
    conn = psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")
    conn.autocommit = True
    return conn


def q(sql, *params):
    with db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        if cur.description:
            return [dict(r) for r in cur.fetchall()]
        return []


def rand_id(n=32):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def sign(value, secret=SECRET):
    sig = base64.b64encode(hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{sig}", safe="")


def verify_signed(raw_cookie_value, secret=SECRET):
    value = urllib.parse.unquote(raw_cookie_value)
    if "." not in value:
        return None
    body, sig = value.rsplit(".", 1)
    expected = base64.b64encode(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()).decode()
    return body if hmac.compare_digest(sig, expected) else None


def hash_password(password, salt_hex=None):
    salt_hex = salt_hex or os.urandom(16).hex()
    key = hashlib.scrypt(unicodedata.normalize("NFKC", password).encode(), salt=salt_hex.encode(), n=16384, r=16, p=1, dklen=64, maxmem=128 * 1024 * 1024)
    return f"{salt_hex}:{key.hex()}"


def verify_password(stored, password):
    salt_hex, key_hex = stored.split(":")
    return hash_password(password, salt_hex) == stored


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers  # list of (lower name, value)
        self.body = body

    def header(self, name):
        for k, v in self.headers:
            if k == name.lower():
                return v
        return None

    def all(self, name):
        return [v for k, v in self.headers if k == name.lower()]

    @property
    def set_cookies(self):
        return self.all("set-cookie")

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    def cookie_value(self, name):
        """The value a browser keeps: the last Set-Cookie of that name wins."""
        found = None
        for c in self.set_cookies:
            n, _, rest = c.partition("=")
            if n == name:
                found = rest.split(";", 1)[0]
        return found


def request(port, method, path, headers=None, body=None, json_body=None, cookies=None, origin=True, ip=None):
    headers = dict(headers or {})
    if json_body is not None:
        body = json.dumps(json_body)
        headers.setdefault("Content-Type", "application/json")
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if origin and "Origin" not in headers and method not in ("GET", "HEAD"):
        headers["Origin"] = ORIGIN
    headers.setdefault("X-Forwarded-For", ip or fresh_ip())
    if isinstance(body, str):
        body = body.encode()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    conn.putrequest(method, path, skip_accept_encoding=True)
    for k, v in headers.items():
        conn.putheader(k, v)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    resp = conn.getresponse()
    data = resp.read()
    out = Response(resp.status, [(k.lower(), v) for k, v in resp.getheaders()], data.decode(errors="replace"))
    conn.close()
    return out


def now_sql():
    return "(now() AT TIME ZONE 'utc')"


def create_user(tag, email=None, name="Parity User", password=None, role="user", email_verified=True, banned=None, ban_expires_sql=None, created_offset_sec=-86400 * 30):
    uid = f"parity-auth-{tag}-{rand_id(8)}"
    email = email or f"parity-auth-{tag}-{rand_id(6).lower()}@example.com"
    q(
        f'''INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", role, banned, "banReason", "banExpires")
            VALUES (%s, %s, %s, %s, date_trunc('milliseconds', {now_sql()} + interval '{created_offset_sec} seconds'),
                    date_trunc('milliseconds', {now_sql()} + interval '{created_offset_sec} seconds'), %s, %s, %s, {ban_expires_sql or 'NULL'})''',
        uid, name, email, email_verified, role, banned, "Bad" if banned else None,
    )
    if password is not None:
        q(
            f'''INSERT INTO account (id, "accountId", "providerId", "userId", password, "createdAt", "updatedAt")
                VALUES (%s, %s, 'credential', %s, %s, date_trunc('milliseconds', {now_sql()}), date_trunc('milliseconds', {now_sql()}))''',
            f"parity-auth-acc-{rand_id(10)}", uid, uid, hash_password(password),
        )
    return {"id": uid, "email": email, "name": name, "password": password}


def create_session(user_id, expires_offset_sec=6 * 86400, created_offset_sec=-60, active_org=None, impersonated_by=None, token=None):
    token = token or rand_id(32)
    sid = f"parity-auth-ses-{rand_id(10)}"
    q(
        f'''INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId", "activeOrganizationId", "impersonatedBy")
            VALUES (%s, date_trunc('milliseconds', {now_sql()} + interval '{expires_offset_sec} seconds'), %s,
                    date_trunc('milliseconds', {now_sql()} + interval '{created_offset_sec} seconds'),
                    date_trunc('milliseconds', {now_sql()} + interval '{created_offset_sec} seconds'), '', 'parity', %s, %s, %s)''',
        sid, token, user_id, active_org, impersonated_by,
    )
    return token


def session_cookies(token, dont_remember=False):
    c = {SESSION_COOKIE: sign(token)}
    if dont_remember:
        c[DONT_REMEMBER_COOKIE] = sign("true")
    return c


def create_org(tag, owner_id=None, slug=None, name=None):
    oid = f"parity-auth-org-{tag}-{rand_id(6)}"
    slug = slug or f"parity-auth-{tag}-{rand_id(6).lower()}"
    q(
        f'''INSERT INTO organization (id, name, slug, "createdAt") VALUES (%s, %s, %s, date_trunc('milliseconds', {now_sql()}))''',
        oid, name or f"Parity Org {tag}", slug,
    )
    if owner_id:
        add_member(oid, owner_id, "owner")
    return {"id": oid, "slug": slug}


def add_member(org_id, user_id, role, restricted=False):
    mid = f"parity-auth-mem-{rand_id(10)}"
    q(
        f'''INSERT INTO member (id, "organizationId", "userId", role, "createdAt", has_restricted_site_access)
            VALUES (%s, %s, %s, %s, date_trunc('milliseconds', {now_sql()}), %s)''',
        mid, org_id, user_id, role, restricted,
    )
    return mid


def cleanup():
    """Delete every row the suite created, children first."""
    users = "(SELECT id FROM \"user\" WHERE id LIKE 'parity-auth-%%' OR email LIKE 'parity-auth-%%')"
    orgs = "(SELECT id FROM organization WHERE id LIKE 'parity-auth-%%' OR slug LIKE 'parity-auth-%%')"
    statements = [
        f"DELETE FROM member_site_access WHERE member_id IN (SELECT id FROM member WHERE \"organizationId\" IN {orgs} OR \"userId\" IN {users})",
        f"DELETE FROM \"teamMember\" WHERE \"userId\" IN {users} OR \"teamId\" IN (SELECT id FROM team WHERE \"organizationId\" IN {orgs})",
        f"DELETE FROM team WHERE \"organizationId\" IN {orgs}",
        f"DELETE FROM invitation WHERE \"organizationId\" IN {orgs} OR email LIKE 'parity-auth-%%'",
        f"DELETE FROM member WHERE \"organizationId\" IN {orgs} OR \"userId\" IN {users}",
        f"DELETE FROM apikey WHERE \"referenceId\" IN {users} OR \"referenceId\" IN {orgs} OR id LIKE 'parity-auth-%%'",
        f"DELETE FROM sites WHERE organization_id IN {orgs}",
        f"DELETE FROM organization WHERE id IN {orgs}",
        "DELETE FROM verification WHERE identifier LIKE '%%parity-auth-%%' OR value LIKE '%%parity-auth-%%'",
        f"DELETE FROM \"oauthAccessToken\" WHERE \"userId\" IN {users} OR \"clientId\" LIKE 'parity-auth-%%' OR \"clientId\" IN (SELECT \"clientId\" FROM \"oauthApplication\" WHERE name LIKE 'parity-auth-%%')",
        f"DELETE FROM \"oauthConsent\" WHERE \"userId\" IN {users}",
        "DELETE FROM \"oauthApplication\" WHERE name LIKE 'parity-auth-%%' OR \"clientId\" LIKE 'parity-auth-%%'",
        f"DELETE FROM session WHERE \"userId\" IN {users}",
        f"DELETE FROM account WHERE \"userId\" IN {users}",
        "DELETE FROM \"user\" WHERE id LIKE 'parity-auth-%%' OR email LIKE 'parity-auth-%%'",
    ]
    for s in statements:
        q(s)
