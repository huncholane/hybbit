"""Core Better Auth routes: sessions, sign-in/up/out, social, edges."""

import base64
import hashlib
import hmac
import json
import time

import harness as h

A = "/api/auth"
SESSION_ROWS = 'SELECT token, "expiresAt", "createdAt", "updatedAt", "ipAddress", "userAgent", "impersonatedBy", "activeOrganizationId" FROM session WHERE "userId" = %s ORDER BY "expiresAt", "createdAt"'
USER_ROW = 'SELECT name, email, "emailVerified", image, role, banned, "banReason", "banExpires", "sendAutoEmailReports", "createdAt", "updatedAt" FROM "user" WHERE id = %s'


def jwt(payload, secret=h.SECRET):
    enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = enc(b'{"alg":"HS256"}')
    body = enc(json.dumps(payload, separators=(",", ":")).encode())
    sig = enc(hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def sc_edges(run):
    e = "router edges"
    run.req(e, "GET", f"{A}/nope")
    run.req(e, "GET", f"{A}/sign-out", note="wrong method")
    run.req(e, "HEAD", f"{A}/get-session")
    run.req(e, "GET", f"{A}/", note="empty path")
    run.req(e, "GET", f"{A}//get-session", note="double slash")
    run.req(e, "GET", f"{A}/get-session/", note="trailing slash")
    run.req(e, "OPTIONS", f"{A}/sign-out", note="preflight trusted", headers={"Origin": h.ORIGIN, "Access-Control-Request-Method": "POST"})
    run.req(e, "OPTIONS", f"{A}/sign-out", note="options untrusted", headers={"Origin": "https://evil.example"})
    run.req(e, "GET", f"{A}/ok")
    run.req(e, "GET", f"{A}/error?error=bad%20code&error_description=hi%3Cb%3E", note="error page")
    run.req(e, "GET", f"{A}/error?error=OK_CODE")
    run.req(e, "POST", f"{A}/sign-in/email", note="no content type", body="{}")
    run.req(e, "POST", f"{A}/sign-in/email", note="text/plain", body="{}", headers={"Content-Type": "text/plain"})
    run.req(e, "POST", f"{A}/sign-in/email", note="xml", body="<x/>", headers={"Content-Type": "application/xml"})
    run.req(e, "POST", f"{A}/sign-in/email", note="bad json", body="{bad", headers={"Content-Type": "application/json"})
    run.req(e, "POST", f"{A}/sign-in/email", note="json null", body="null", headers={"Content-Type": "application/json"})
    run.req(e, "POST", f"{A}/update-user", note="form not allowed", body="name=x", headers={"Content-Type": "application/x-www-form-urlencoded"})
    run.req(e, "POST", f"{A}/sign-in/email", note="untrusted origin", json_body={}, headers={"Origin": "https://evil.example"})
    run.req(e, "POST", f"{A}/sign-out", note="cookie without origin", origin=False, headers={"Cookie": "a=b"})
    run.req(e, "POST", f"{A}/sign-out", note="cookie with referer", origin=False, headers={"Cookie": "a=b", "Referer": "https://a.hygo.ai/settings"})
    run.req(e, "POST", f"{A}/sign-out", note="cookie with bad referer", origin=False, headers={"Cookie": "a=b", "Referer": "https://evil.example/x"})
    run.req(e, "POST", f"{A}/sign-out", note="x-request-id", headers={"X-Request-Id": "req-123"})
    run.req(e, "POST", f"{A}/sign-out", note="infra cookie", cookies={"__infra-rid": "abc"})
    run.req(e, "GET", f"{A}/get-session", note="infra cookie on GET", cookies={"__infra-rid": "abc"}, headers={"X-Request-Id": "req-1"})
    run.req(e, "GET", f"{A}/dash/config", note="dash not ported (404 in Rust)")


def sc_rate_limit(run):
    e = "rate limiter"
    ip = h.fresh_ip()
    for i in range(4):
        r = run.req(e, "POST", f"{A}/sign-in/email", note=f"attempt {i + 1}", json_body={"email": "parity-auth-rl@example.com", "password": "x"}, ip=ip)
    ip2 = h.fresh_ip()
    for i in range(4):
        run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note=f"otp attempt {i + 1}", json_body={"email": "parity-auth-rl@example.com", "type": "forget-password"}, ip=ip2)
    ip3 = h.fresh_ip()
    for i in range(3):
        run.req(e, "POST", f"{A}/sign-in/email/", note=f"trailing slash counts {i + 1}", json_body={}, ip=ip3)
    run.req(e, "POST", f"{A}/sign-in/email", note="same bucket as trailing slash", json_body={}, ip=ip3)
    run.req(e, "GET", f"{A}/get-session", note="no xff", headers={"X-Forwarded-For": "1.1.1.1, 2.2.2.2"})


def sc_get_session(run):
    e = "get-session"
    u = run.user("gs", password=run.password("parity-pass-1"))
    run.req(e, "GET", f"{A}/get-session", note="no cookie")
    t1 = run.session("fresh", u["id"], expires_offset_sec=7 * 86400 - 60)
    run.req(e, "GET", f"{A}/get-session", note="fresh", cookies=h.session_cookies(t1))
    run.db(e, "fresh untouched", SESSION_ROWS, u["id"])
    t2 = run.session("due", u["id"], expires_offset_sec=5 * 86400)
    run.req(e, "GET", f"{A}/get-session", note="refresh due", cookies=h.session_cookies(t2))
    run.db(e, "refreshed", SESSION_ROWS, u["id"])
    t3 = run.session("due-dr", u["id"], expires_offset_sec=5 * 86400)
    run.req(e, "GET", f"{A}/get-session", note="dont remember", cookies=h.session_cookies(t3, dont_remember=True))
    t4 = run.session("due-q", u["id"], expires_offset_sec=5 * 86400)
    run.req(e, "GET", f"{A}/get-session?disableRefresh=true", note="disableRefresh", cookies=h.session_cookies(t4))
    t5 = run.session("expired", u["id"], expires_offset_sec=-60)
    run.req(e, "GET", f"{A}/get-session", note="expired", cookies={**h.session_cookies(t5), h.PREFIX + "session_data": "e30"})
    run.db(e, "expired deleted", SESSION_ROWS, u["id"])
    run.req(e, "GET", f"{A}/get-session", note="bad signature", cookies={h.SESSION_COOKIE: h.sign(t1, "wrong")})
    run.req(e, "GET", f"{A}/get-session", note="unsigned", cookies={h.SESSION_COOKIE: t1})
    run.req(e, "GET", f"{A}/get-session", note="unknown token", cookies=h.session_cookies("parityauthnope"))
    run.req(e, "GET", f"{A}/get-session", note="bad session_data base64", cookies={**h.session_cookies(t1), h.PREFIX + "session_data": "!!!"})
    run.req(e, "POST", f"{A}/get-session", note="POST", cookies=h.session_cookies(t1))


def sc_sign_out(run):
    e = "sign-out"
    u = run.user("so", password=run.password("parity-pass-1"))
    t = run.session("s", u["id"])
    run.req(e, "POST", f"{A}/sign-out", cookies=h.session_cookies(t))
    run.db(e, "session deleted", SESSION_ROWS, u["id"])
    run.req(e, "POST", f"{A}/sign-out", note="no cookie")
    run.req(e, "POST", f"{A}/sign-out", note="session_data chunks", cookies={h.PREFIX + "session_data.0": "a", h.PREFIX + "session_data.1": "b"})


def sc_sign_in(run):
    e = "sign-in/email"
    u = run.user("si", password=run.password("parity-pass-1"), name="Sign In")
    r = run.req(e, "POST", f"{A}/sign-in/email", note="ok", json_body={"email": u["email"].upper(), "password": "parity-pass-1"})
    run.db(e, "session", SESSION_ROWS, u["id"])
    run.req(e, "POST", f"{A}/sign-in/email", note="wrong password", json_body={"email": u["email"], "password": "nope-nope-nope"})
    run.req(e, "POST", f"{A}/sign-in/email", note="unknown", json_body={"email": "parity-auth-unknown@example.com", "password": "x"})
    run.req(e, "POST", f"{A}/sign-in/email", note="invalid email", json_body={"email": "no-at-sign", "password": "x"})
    run.req(e, "POST", f"{A}/sign-in/email", note="validation", json_body={"email": 1, "rememberMe": "no"})
    run.req(e, "POST", f"{A}/sign-in/email", note="remember false + callback", json_body={"email": u["email"], "password": "parity-pass-1", "rememberMe": False, "callbackURL": "/dashboard"})
    run.req(e, "POST", f"{A}/sign-in/email", note="empty callback", json_body={"email": u["email"], "password": "parity-pass-1", "callbackURL": ""})
    run.req(e, "POST", f"{A}/sign-in/email", note="untrusted callback", json_body={"email": u["email"], "password": "parity-pass-1", "callbackURL": "https://evil.example/x"})
    run.req(e, "POST", f"{A}/sign-in/email", note="form body", body=f"email={u['email']}&password=parity-pass-1", headers={"Content-Type": "application/x-www-form-urlencoded"})
    run.req(e, "POST", f"{A}/sign-in/email", note="cross-site navigation", json_body={"email": u["email"], "password": "parity-pass-1"}, origin=False, headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"})
    run.req(e, "POST", f"{A}/sign-in/email", note="fetch metadata, no origin", json_body={"email": u["email"], "password": "parity-pass-1"}, origin=False, headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"})
    nocred = run.user("nocred")
    run.req(e, "POST", f"{A}/sign-in/email", note="no credential account", json_body={"email": nocred["email"], "password": "whatever-1"})
    banned = run.user("banned", password=run.password("parity-pass-2"), banned=True)
    run.req(e, "POST", f"{A}/sign-in/email", note="banned", json_body={"email": banned["email"], "password": "parity-pass-2"})
    lifted = run.user("lifted", password=run.password("parity-pass-3"), banned=True, ban_expires_sql="(now() AT TIME ZONE 'utc') - interval '1 hour'")
    run.req(e, "POST", f"{A}/sign-in/email", note="expired ban", json_body={"email": lifted["email"], "password": "parity-pass-3"})
    run.db(e, "ban lifted", USER_ROW, lifted["id"])
    t = run.session("existing", u["id"])
    run.req(e, "POST", f"{A}/sign-in/email", note="with session cookie", json_body={"email": u["email"], "password": "parity-pass-1"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/sign-in/email", note="cookie no origin", json_body={"email": u["email"], "password": "parity-pass-1"}, cookies=h.session_cookies(t), origin=False)


def sc_sign_up_social(run):
    e = "sign-up/email"
    run.req(e, "POST", f"{A}/sign-up/email", note="disabled", json_body={"email": "parity-auth-new@example.com", "password": "abcdefgh1", "name": "x"})
    run.req(e, "POST", f"{A}/sign-up/email", note="validation", json_body={"email": "bad"})
    s = "sign-in/social"
    run.req(s, "POST", f"{A}/sign-in/social", note="github", json_body={"provider": "github", "callbackURL": f"/parity-auth-cb-{run.tag}"})
    run.db(s, "state row", "SELECT identifier, value, \"expiresAt\" FROM verification WHERE value LIKE %s", f"%%parity-auth-cb-{run.tag}%%")
    run.req(s, "POST", f"{A}/sign-in/social", note="github disableRedirect scopes", json_body={"provider": "github", "callbackURL": f"/parity-auth-cb2-{run.tag}", "disableRedirect": True, "scopes": ["repo"], "loginHint": "me"})
    run.req(s, "POST", f"{A}/sign-in/social", note="google", json_body={"provider": "google", "callbackURL": f"/parity-auth-cb3-{run.tag}"})
    run.db(s, "google state row", "SELECT identifier, value, \"expiresAt\" FROM verification WHERE value LIKE %s", f"%%parity-auth-cb3-{run.tag}%%")
    run.req(s, "POST", f"{A}/sign-in/social", note="unknown", json_body={"provider": "twitter"})
    run.req(s, "POST", f"{A}/sign-in/social", note="github id token", json_body={"provider": "github", "idToken": {"token": "x"}})
    run.req(s, "POST", f"{A}/sign-in/social", note="untrusted errorCallbackURL", json_body={"provider": "github", "errorCallbackURL": "https://evil.example"})
    run.req(s, "POST", f"{A}/sign-in/social", note="missing provider", json_body={})


SCENARIOS = [sc_edges, sc_rate_limit, sc_get_session, sc_sign_out, sc_sign_in, sc_sign_up_social]
