"""Cross-compatibility: state written by one backend is read by the other.

Each scenario runs twice like every other: once with Node as the issuer and Rust
as the verifier, once the other way round. The recorded observations are what the
verifier made of the issuer's state, so identical records mean the round trip
works in both directions (and a failure shows up as a mismatch or as an error
status in both)."""

import base64
import hashlib
import json
import os
import urllib.parse

import harness as h
from sc_core import A
from sc_mcp import REDIRECT, authorize_query, code_from, form, pkce

NODE_PORT = int(os.environ.get("NODE_PORT", 3021))
RUST_PORT = int(os.environ.get("RUST_PORT", 3057))


def other_port(run):
    return RUST_PORT if run.port == NODE_PORT else NODE_PORT


def on(run, port, endpoint, method, path, note="", **kw):
    """A request against an explicit port, recorded like Run.req."""
    saved = run.port
    run.port = port
    try:
        return run.req(endpoint, method, path, note=note, **kw)
    finally:
        run.port = saved


def session_token_from(response):
    raw = response.cookie_value(h.SESSION_COOKIE)
    return h.verify_signed(raw) if raw else None


def sc_cross_sessions(run):
    other = other_port(run)
    user = run.user("xsess", name="Cross Session", password=run.password("parity-cross-1"))
    e = "cross: session"
    signed_in = run.req(e, "POST", f"{A}/sign-in/email", note="issuer sign-in", json_body={"email": user["email"], "password": "parity-cross-1"})
    token = session_token_from(signed_in)
    if token:
        run.name(token, "token:issued")
    on(run, other, e, "GET", f"{A}/get-session", note="verifier reads issuer session", cookies=h.session_cookies(token or "none"))
    on(run, other, e, "POST", f"{A}/update-user", note="verifier updates through issuer session", json_body={"name": "Cross Renamed"}, cookies=h.session_cookies(token or "none"))
    run.req(e, "GET", f"{A}/get-session", note="issuer sees verifier update", cookies=h.session_cookies(token or "none"))
    not_remembered = run.req(e, "POST", f"{A}/sign-in/email", note="issuer sign-in rememberMe false", json_body={"email": user["email"], "password": "parity-cross-1", "rememberMe": False})
    short = session_token_from(not_remembered)
    if short:
        run.name(short, "token:short")
    on(run, other, e, "GET", f"{A}/get-session", note="verifier reads dont_remember session", cookies=h.session_cookies(short or "none", dont_remember=True))
    on(run, other, e, "POST", f"{A}/sign-out", note="verifier signs out issuer session", cookies=h.session_cookies(token or "none"))
    run.req(e, "GET", f"{A}/get-session", note="issuer sees sign-out", cookies=h.session_cookies(token or "none"))
    # a session the issuer refreshes on read (older than updateAge) stays valid on the verifier
    stale = h.create_session(user["id"], expires_offset_sec=5 * 86400, created_offset_sec=-2 * 86400)
    run.name(stale, "token:stale")
    run.req(e, "GET", f"{A}/get-session", note="issuer refreshes stale session", cookies=h.session_cookies(stale))
    on(run, other, e, "GET", f"{A}/get-session", note="verifier reads refreshed session", cookies=h.session_cookies(stale))


def sc_cross_passwords(run):
    other = other_port(run)
    user = run.user("xpass", password=run.password("parity-cross-old"))
    run.password("parity-cross-new")
    run.password("parity-cross-otp")
    e = "cross: password"
    t = run.session("pass", user["id"])
    run.req(e, "POST", f"{A}/change-password", note="issuer changes password", json_body={"currentPassword": "parity-cross-old", "newPassword": "parity-cross-new"}, cookies=h.session_cookies(t))
    on(run, other, e, "POST", f"{A}/sign-in/email", note="verifier accepts new password", json_body={"email": user["email"], "password": "parity-cross-new"})
    on(run, other, e, "POST", f"{A}/sign-in/email", note="verifier rejects old password", json_body={"email": user["email"], "password": "parity-cross-old"})
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="issuer sends reset OTP", json_body={"email": user["email"], "type": "forget-password"})
    rows = h.q("SELECT value FROM verification WHERE identifier = %s ORDER BY \"createdAt\" DESC LIMIT 1", f"forget-password-otp-{user['email']}")
    otp = rows[0]["value"].split(":")[0] if rows else "000000"
    on(run, other, e, "POST", f"{A}/email-otp/check-verification-otp", note="verifier checks issuer OTP", json_body={"email": user["email"], "type": "forget-password", "otp": otp})
    on(run, other, e, "POST", f"{A}/email-otp/reset-password", note="verifier resets with issuer OTP", json_body={"email": user["email"], "otp": otp, "password": "parity-cross-otp"})
    run.req(e, "POST", f"{A}/sign-in/email", note="issuer accepts verifier reset", json_body={"email": user["email"], "password": "parity-cross-otp"})
    run.db(e, "credential account", 'SELECT password, "updatedAt" FROM account WHERE "userId" = %s AND "providerId" = %s', user["id"], "credential")


def sc_cross_admin(run):
    other = other_port(run)
    admin = run.user("xadmin", role="admin")
    target = run.user("xtarget")
    e = "cross: impersonation"
    t = run.session("admin", admin["id"])
    r = run.req(e, "POST", f"{A}/admin/impersonate-user", note="issuer impersonates", json_body={"userId": target["id"]}, cookies=h.session_cookies(t))
    imp_raw = r.cookie_value(h.SESSION_COOKIE)
    admin_raw = r.cookie_value(h.ADMIN_SESSION_COOKIE)
    dont_raw = r.cookie_value(h.DONT_REMEMBER_COOKIE)
    imp = h.verify_signed(imp_raw) if imp_raw else None
    if imp:
        run.name(imp, "token:impersonation")
    cookies = {k: v for k, v in ((h.SESSION_COOKIE, imp_raw), (h.ADMIN_SESSION_COOKIE, admin_raw), (h.DONT_REMEMBER_COOKIE, dont_raw)) if v}
    on(run, other, e, "GET", f"{A}/get-session", note="verifier reads impersonation session", cookies=cookies)
    on(run, other, e, "POST", f"{A}/admin/stop-impersonating", note="verifier stops impersonation", cookies=cookies)


def sc_cross_oauth(run):
    other = other_port(run)
    user = run.user("xoauth")
    t = run.session("oauth", user["id"])
    e = "cross: oauth"
    reg = run.req(e, "POST", f"{A}/mcp/register", note="issuer registers client", json_body={"client_name": f"parity-auth-{run.tag}-x", "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"})
    cid = (reg.json() or {}).get("client_id") or "missing"
    run.name(cid, "client:x")
    verifier, challenge = pkce(run, "x")
    # the verifier issues the code for the issuer's client, the issuer exchanges it
    r = on(run, other, e, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge)}", note="verifier authorizes issuer client", cookies=h.session_cookies(t))
    code = code_from(r, run, "x")
    tok = run.req(e, "POST", f"{A}/mcp/token", note="issuer exchanges verifier code", body=form({"grant_type": "authorization_code", "code": code or "x", "redirect_uri": REDIRECT, "client_id": cid, "code_verifier": verifier}), headers={"Content-Type": "application/x-www-form-urlencoded"})
    payload = tok.json() or {}
    access = payload.get("access_token") or "none"
    refresh = payload.get("refresh_token") or "none"
    run.name(access, "access:issuer")
    run.name(refresh, "refresh:issuer")
    on(run, other, e, "GET", f"{A}/mcp/get-session", note="verifier reads issuer token", headers={"Authorization": f"Bearer {access}"})
    gate_note = "node MCP gate accepts token"
    mcp_headers = {"Authorization": f"Bearer {access}", "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    node_gate = h.request(NODE_PORT, "POST", "/api/mcp", headers=mcp_headers, body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    run.check(e, gate_note, {"status": node_gate.status})
    rust_gate = h.request(RUST_PORT, "GET", "/__parity/bearer", headers={"Authorization": f"Bearer {access}"})
    run.check(e, "rust bearer gate accepts token", rust_gate.json())
    bad_gate = h.request(NODE_PORT, "POST", "/api/mcp", headers={**mcp_headers, "Authorization": "Bearer parity-auth-nope"}, body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    run.check(e, "node MCP gate rejects unknown token", {"status": bad_gate.status})
    run.check(e, "rust bearer gate rejects unknown token", h.request(RUST_PORT, "GET", "/__parity/bearer", headers={"Authorization": "Bearer parity-auth-nope"}).json())
    refreshed = on(run, other, e, "POST", f"{A}/mcp/token", note="verifier refreshes issuer token", body=form({"grant_type": "refresh_token", "refresh_token": refresh, "client_id": cid}), headers={"Content-Type": "application/x-www-form-urlencoded"})
    new_access = (refreshed.json() or {}).get("access_token") or "none"
    run.name(new_access, "access:verifier")
    run.req(e, "GET", f"{A}/mcp/get-session", note="issuer reads verifier token", headers={"Authorization": f"Bearer {new_access}"})
    node_gate2 = h.request(NODE_PORT, "POST", "/api/mcp", headers={**mcp_headers, "Authorization": f"Bearer {new_access}"}, body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    run.check(e, "node MCP gate accepts refreshed token", {"status": node_gate2.status})
    run.check(e, "rust bearer gate accepts refreshed token", h.request(RUST_PORT, "GET", "/__parity/bearer", headers={"Authorization": f"Bearer {new_access}"}).json())


SCENARIOS = [sc_cross_sessions, sc_cross_passwords, sc_cross_admin, sc_cross_oauth]
