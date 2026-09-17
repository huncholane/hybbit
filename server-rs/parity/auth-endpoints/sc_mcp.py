"""MCP OAuth provider: discovery, dynamic registration, authorize (with the login
prompt resume), token (authorization_code with PKCE, refresh_token), get-session
and oauth2/consent."""

import base64
import hashlib
import json
import urllib.parse

import harness as h
from sc_core import A

REDIRECT = "http://localhost:4321/callback"
SCOPES = "openid profile email offline_access analytics:read"
APP_ROWS = 'SELECT name, icon, metadata, "clientSecret", "redirectUrls", type, disabled, "userId", "createdAt", "updatedAt" FROM "oauthApplication" WHERE name LIKE %s ORDER BY name'
TOKEN_ROWS = 'SELECT "accessToken", "refreshToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "clientId", "userId", scopes, "createdAt", "updatedAt" FROM "oauthAccessToken" WHERE "userId" = %s ORDER BY "createdAt", scopes'


def pkce(run, label):
    verifier = run.name(h.rand_id(64), f"verifier:{label}")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    run.name(challenge, f"challenge:{label}")
    return verifier, challenge


def register(run, label, public=True, session=None, **extra):
    body = {"client_name": f"parity-auth-{run.tag}-{label}", "redirect_uris": [REDIRECT], **extra}
    if public:
        body["token_endpoint_auth_method"] = "none"
    r = run.req("mcp/register", "POST", f"{A}/mcp/register", note=label, json_body=body, cookies=h.session_cookies(session) if session else None)
    data = r.json() or {}
    if data.get("client_id"):
        run.name(data["client_id"], f"client:{label}")
    if data.get("client_secret"):
        run.name(data["client_secret"], f"secret:{label}")
    return data


def authorize_query(client_id, challenge=None, scope=SCOPES, state="st-1", redirect=REDIRECT, **extra):
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "scope": scope, "state": state}
    if challenge:
        params.update({"code_challenge": challenge, "code_challenge_method": "S256"})
    params.update(extra)
    return urllib.parse.urlencode(params)


def code_from(response, run, label):
    location = response.header("location") or ""
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))
    code = query.get("code")
    if code:
        run.name(code, f"code:{label}")
    return code


def form(data):
    return urllib.parse.urlencode(data)


def token_request(run, note, data, headers=None):
    hdrs = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
    r = run.req("mcp/token", "POST", f"{A}/mcp/token", note=note, body=form(data), headers=hdrs)
    payload = r.json() or {}
    for key in ("access_token", "refresh_token"):
        if payload.get(key):
            run.name(payload[key], f"{key}:{note}")
    return payload


def sc_mcp_discovery(run):
    w = "well-known"
    for path in (
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/api/mcp",
        "/.well-known/openid-configuration",
        "/.well-known/openid-configuration/api/mcp",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/api/mcp",
    ):
        run.req(w, "GET", path)
    run.req(w, "GET", f"{A}/.well-known/oauth-authorization-server", note="auth mount")
    run.req(w, "GET", f"{A}/.well-known/oauth-protected-resource", note="auth mount")


def sc_mcp_register(run):
    user = run.user("mreg")
    t = run.session("reg", user["id"])
    register(run, "public")
    register(run, "confidential", public=False, session=t, metadata={"b": 1, "a": "x"}, logo_uri="https://x.test/l.png", client_uri="https://x.test", scope="openid")
    register(run, "grant-types", grant_types=["authorization_code", "refresh_token"], response_types=["code"])
    register(run, "implicit-without-token", grant_types=["implicit"])
    register(run, "code-without-code", response_types=["token"])
    register(run, "bad-grant", grant_types=["magic"])
    register(run, "empty-redirects", redirect_uris=[])
    register(run, "javascript", redirect_uris=["javascript:alert(1)"])
    run.req("mcp/register", "POST", f"{A}/mcp/register", note="no name", json_body={"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"})
    run.req("mcp/register", "POST", f"{A}/mcp/register", note="no redirect uris", json_body={"client_name": f"parity-auth-{run.tag}-x"})
    run.req("mcp/register", "POST", f"{A}/mcp/register", note="bad method", json_body={"client_name": f"parity-auth-{run.tag}-y", "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "private_key_jwt"})
    run.db("mcp/register", "applications", APP_ROWS, f"parity-auth-{run.tag}-%")


def sc_mcp_code_flow(run):
    user = run.user("mcode", name="Mia Code")
    t = run.session("code", user["id"])
    client = register(run, "flow")
    conf = register(run, "conf", public=False)
    cid = client.get("client_id", "missing")
    au = "mcp/authorize"
    verifier, challenge = pkce(run, "one")
    run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge)}", note="no session")
    r = run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge)}", note="with session", cookies=h.session_cookies(t))
    code = code_from(r, run, "one")
    run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, redirect='http://evil.test/cb')}", note="wrong redirect", cookies=h.session_cookies(t))
    run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, scope='openid admin:everything')}", note="bad scope", cookies=h.session_cookies(t))
    run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query('nope-client', challenge)}", note="unknown client", cookies=h.session_cookies(t))
    run.req(au, "GET", f"{A}/mcp/authorize?client_id={cid}&redirect_uri={urllib.parse.quote(REDIRECT)}", note="no response_type", cookies=h.session_cookies(t))
    run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, None, code_challenge_method='S256')}", note="method without challenge", cookies=h.session_cookies(t))
    run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, None, code_challenge='abc', code_challenge_method='plain')}", note="plain method", cookies=h.session_cookies(t))
    run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, None, response_type='token')}", note="token response type", cookies=h.session_cookies(t))
    run.db(au, "code rows", "SELECT value, \"expiresAt\" FROM verification WHERE value LIKE %s ORDER BY \"createdAt\"", f"%{user['id']}%")

    tk = "mcp/token"
    base = {"grant_type": "authorization_code", "redirect_uri": REDIRECT, "client_id": cid}
    token_request(run, "wrong verifier", {**base, "code": code, "code_verifier": "x" * 64})
    r2 = run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, state='st-2')}", note="second code", cookies=h.session_cookies(t))
    code2 = code_from(r2, run, "two")
    token_request(run, "wrong redirect", {**base, "code": code2, "code_verifier": verifier, "redirect_uri": "http://localhost:4321/other"})
    r3 = run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, state='st-3')}", note="third code", cookies=h.session_cookies(t))
    code3 = code_from(r3, run, "three")
    token_request(run, "missing verifier", {**base, "code": code3})
    r4 = run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, state='st-4')}", note="fourth code", cookies=h.session_cookies(t))
    code4 = code_from(r4, run, "four")
    tokens = token_request(run, "exchange", {**base, "code": code4, "code_verifier": verifier})
    token_request(run, "reused code", {**base, "code": code4, "code_verifier": verifier})
    token_request(run, "no grant", {"code": "x", "client_id": cid})
    token_request(run, "unsupported grant", {"grant_type": "password", "code": "x", "client_id": cid})
    token_request(run, "no code", {"grant_type": "authorization_code", "client_id": cid})
    token_request(run, "json body", {})
    run.req(tk, "POST", f"{A}/mcp/token", note="json content type", json_body={**base, "code": "x"})

    r5 = run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, state='st-5')}", note="fifth code", cookies=h.session_cookies(t))
    code5 = code_from(r5, run, "five")
    h.q("UPDATE verification SET \"expiresAt\" = (now() AT TIME ZONE 'utc') - interval '1 minute' WHERE identifier = %s", code5 or "")
    token_request(run, "expired code", {**base, "code": code5, "code_verifier": verifier})

    refresh = tokens.get("refresh_token")
    token_request(run, "refresh", {"grant_type": "refresh_token", "refresh_token": refresh or "none", "client_id": cid})
    token_request(run, "refresh wrong client", {"grant_type": "refresh_token", "refresh_token": refresh or "none", "client_id": "other"})
    token_request(run, "refresh unknown", {"grant_type": "refresh_token", "refresh_token": "nope", "client_id": cid})
    token_request(run, "refresh missing", {"grant_type": "refresh_token", "client_id": cid})

    # confidential client: Basic auth and client_secret_post
    ccid = conf.get("client_id", "missing")
    secret = conf.get("client_secret", "missing")
    rc = run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(ccid, None, scope='openid email')}", note="confidential", cookies=h.session_cookies(t))
    ccode = code_from(rc, run, "conf")
    basic = base64.b64encode(f"{ccid}:wrong".encode()).decode()
    token_request(run, "basic wrong secret", {"grant_type": "authorization_code", "redirect_uri": REDIRECT, "code": ccode}, headers={"Authorization": f"Basic {basic}"})
    rc2 = run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(ccid, None, scope='openid email', state='c2')}", note="confidential 2", cookies=h.session_cookies(t))
    ccode2 = code_from(rc2, run, "conf2")
    basic = base64.b64encode(f"{ccid}:{secret}".encode()).decode()
    token_request(run, "basic", {"grant_type": "authorization_code", "redirect_uri": REDIRECT, "code": ccode2}, headers={"Authorization": f"Basic {basic}"})
    rc3 = run.req(au, "GET", f"{A}/mcp/authorize?{authorize_query(ccid, None, scope='openid', state='c3')}", note="confidential 3", cookies=h.session_cookies(t))
    ccode3 = code_from(rc3, run, "conf3")
    token_request(run, "secret post missing", {"grant_type": "authorization_code", "redirect_uri": REDIRECT, "code": ccode3, "client_id": ccid})
    token_request(run, "basic garbage", {"grant_type": "authorization_code", "redirect_uri": REDIRECT, "code": "x"}, headers={"Authorization": "Basic !!!"})
    token_request(run, "basic mismatch", {"grant_type": "authorization_code", "redirect_uri": REDIRECT, "code": "x", "client_id": "other"}, headers={"Authorization": f"Basic {basic}"})
    run.db(tk, "access tokens", TOKEN_ROWS, user["id"])

    gs = "mcp/get-session"
    access = tokens.get("access_token") or "none"
    run.req(gs, "GET", f"{A}/mcp/get-session", note="bearer", headers={"Authorization": f"Bearer {access}"})
    run.req(gs, "GET", f"{A}/mcp/get-session", note="unknown bearer", headers={"Authorization": "Bearer nope"})
    run.req(gs, "GET", f"{A}/mcp/get-session", note="no header")
    h.q("UPDATE \"oauthAccessToken\" SET \"accessTokenExpiresAt\" = (now() AT TIME ZONE 'utc') - interval '1 minute' WHERE \"accessToken\" = %s", access)
    run.req(gs, "GET", f"{A}/mcp/get-session", note="expired", headers={"Authorization": f"Bearer {access}"})


def sc_mcp_login_prompt(run):
    user = run.user("mlogin", password=run.password("parity-login-pass"))
    client = register(run, "login")
    cid = client.get("client_id", "missing")
    _, challenge = pkce(run, "login")
    r = run.req("mcp/authorize", "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, prompt='login consent')}", note="prompt cookie")
    prompt = r.cookie_value("oidc_login_prompt")
    cookies = {"oidc_login_prompt": prompt} if prompt else {}
    r2 = run.req("sign-in/email", "POST", f"{A}/sign-in/email", note="resumes authorization", json_body={"email": user["email"], "password": "parity-login-pass"}, cookies=cookies)
    code_from(r2, run, "login")
    run.req("sign-in/email", "POST", f"{A}/sign-in/email", note="tampered prompt cookie", json_body={"email": user["email"], "password": "parity-login-pass"}, cookies={"oidc_login_prompt": "abc.def"})
    r3 = run.req("mcp/authorize", "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, prompt='none login')}", note="prompt none login")
    prompt3 = r3.cookie_value("oidc_login_prompt")
    run.req("sign-in/email", "POST", f"{A}/sign-in/email", note="prompt none with login", json_body={"email": user["email"], "password": "parity-login-pass"}, cookies={"oidc_login_prompt": prompt3} if prompt3 else {})
    run.req("mcp/authorize", "GET", f"{A}/mcp/authorize", note="no query")


def sc_mcp_consent(run):
    user = run.user("mconsent")
    t = run.session("consent", user["id"])
    client = register(run, "consent")
    cid = client.get("client_id", "missing")
    verifier, challenge = pkce(run, "consent")
    c = "oauth2/consent"
    r = run.req("mcp/authorize", "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, prompt='consent', state='cs')}", note="consent prompt", cookies=h.session_cookies(t))
    code = code_from(r, run, "consent")
    run.req(c, "POST", f"{A}/oauth2/consent", note="no session", json_body={"accept": True, "consent_code": code})
    run.req(c, "POST", f"{A}/oauth2/consent", note="missing code", json_body={"accept": True}, cookies=h.session_cookies(t))
    run.req(c, "POST", f"{A}/oauth2/consent", note="invalid code", json_body={"accept": True, "consent_code": "nope"}, cookies=h.session_cookies(t))
    run.req(c, "POST", f"{A}/oauth2/consent", note="validation", json_body={"consent_code": code}, cookies=h.session_cookies(t))
    accepted = run.req(c, "POST", f"{A}/oauth2/consent", note="accept", json_body={"accept": True, "consent_code": code}, cookies=h.session_cookies(t))
    redirect = (accepted.json() or {}).get("redirectURI") or ""
    new_code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect).query)).get("code")
    if new_code:
        run.name(new_code, "code:consented")
    run.db(c, "consent rows", 'SELECT "clientId", scopes, "consentGiven" FROM "oauthConsent" WHERE "userId" = %s', user["id"])
    token_request(run, "consented exchange", {"grant_type": "authorization_code", "redirect_uri": REDIRECT, "client_id": cid, "code": new_code or "x", "code_verifier": verifier})
    r2 = run.req("mcp/authorize", "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, prompt='consent', state='deny')}", note="consent prompt 2", cookies=h.session_cookies(t))
    code2 = code_from(r2, run, "deny")
    run.req(c, "POST", f"{A}/oauth2/consent", note="deny", json_body={"accept": False, "consent_code": code2}, cookies=h.session_cookies(t))
    run.req(c, "POST", f"{A}/oauth2/consent", note="denied code reused", json_body={"accept": True, "consent_code": code2}, cookies=h.session_cookies(t))
    r3 = run.req("mcp/authorize", "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, state='plain')}", note="no consent prompt", cookies=h.session_cookies(t))
    code3 = code_from(r3, run, "plain")
    run.req(c, "POST", f"{A}/oauth2/consent", note="consent not required", json_body={"accept": True, "consent_code": code3}, cookies=h.session_cookies(t))
    r4 = run.req("mcp/authorize", "GET", f"{A}/mcp/authorize?{authorize_query(cid, challenge, prompt='consent', state='cookie')}", note="consent prompt 3", cookies=h.session_cookies(t))
    code4 = code_from(r4, run, "cookie")
    run.req(c, "POST", f"{A}/oauth2/consent", note="code from cookie", json_body={"accept": True}, cookies={**h.session_cookies(t), "oidc_consent_prompt": h.sign(code4 or "x")})


SCENARIOS = [sc_mcp_discovery, sc_mcp_register, sc_mcp_code_flow, sc_mcp_login_prompt, sc_mcp_consent]
