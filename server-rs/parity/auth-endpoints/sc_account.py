"""Account routes: update-user, change-password, change-email, verify-email,
delete-user, send-verification-email, list/revoke sessions."""

import time

import harness as h
from sc_core import A, SESSION_ROWS, USER_ROW, jwt

ACCOUNT_ROWS = 'SELECT "providerId", "accountId", password, "createdAt", "updatedAt" FROM account WHERE "userId" = %s ORDER BY "providerId"'


def sc_update_user(run):
    e = "update-user"
    u = run.user("uu", password=run.password("parity-pass-1"))
    t = run.session("s", u["id"])
    run.req(e, "POST", f"{A}/update-user", note="name", json_body={"name": "New Name"}, cookies=h.session_cookies(t))
    run.db(e, "user", USER_ROW, u["id"])
    run.req(e, "POST", f"{A}/update-user", note="reports + image", json_body={"sendAutoEmailReports": False, "image": "https://img.example/x.png"}, cookies=h.session_cookies(t, dont_remember=True))
    run.db(e, "user after reports", USER_ROW, u["id"])
    run.req(e, "POST", f"{A}/update-user", note="no fields", json_body={"foo": 1}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/update-user", note="email", json_body={"email": "x@y.z"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/update-user", note="role not allowed", json_body={"role": "admin"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/update-user", note="banned false allowed as falsy", json_body={"banned": False}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/update-user", note="array body", json_body=[1], cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/update-user", note="no session", json_body={"name": "x"})
    run.db(e, "user final", USER_ROW, u["id"])


def sc_change_password(run):
    e = "change-password"
    u = run.user("cp", password=run.password("parity-pass-1"))
    t = run.session("s", u["id"])
    other = run.session("other", u["id"])
    run.password("parity-pass-2")
    run.password("parity-pass-3")
    run.req(e, "POST", f"{A}/change-password", note="wrong current", json_body={"currentPassword": "nope-nope-1", "newPassword": "parity-pass-2"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/change-password", note="too short", json_body={"currentPassword": "parity-pass-1", "newPassword": "short"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/change-password", note="too long", json_body={"currentPassword": "parity-pass-1", "newPassword": "x" * 129}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/change-password", note="ok", json_body={"currentPassword": "parity-pass-1", "newPassword": "parity-pass-2"}, cookies=h.session_cookies(t))
    run.db(e, "account", ACCOUNT_ROWS, u["id"])
    run.req("sign-in/email", "POST", f"{A}/sign-in/email", note="new password works", json_body={"email": u["email"], "password": "parity-pass-2"})
    run.req(e, "POST", f"{A}/change-password", note="revoke others", json_body={"currentPassword": "parity-pass-2", "newPassword": "parity-pass-3", "revokeOtherSessions": True}, cookies=h.session_cookies(t))
    run.db(e, "sessions after revoke", 'SELECT count(*) AS n, bool_or(token = %s) AS old_kept FROM session WHERE "userId" = %s', t, u["id"])
    run.req(e, "POST", f"{A}/change-password", note="validation", json_body={"newPassword": 5}, cookies=h.session_cookies(other))
    nocred = run.user("nocred")
    t2 = run.session("s2", nocred["id"])
    run.req(e, "POST", f"{A}/change-password", note="no credential", json_body={"currentPassword": "parity-pass-1", "newPassword": "parity-pass-2"}, cookies=h.session_cookies(t2))


def sc_change_email(run):
    e = "change-email"
    u = run.user("ce", password=run.password("parity-pass-1"))
    t = run.session("s", u["id"])
    taken = run.user("taken")
    run.req(e, "POST", f"{A}/change-email", note="verified user", json_body={"newEmail": f"parity-auth-new-{run.tag}@example.com", "callbackURL": "/settings"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/change-email", note="taken", json_body={"newEmail": taken["email"]}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/change-email", note="same", json_body={"newEmail": u["email"].upper()}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/change-email", note="invalid", json_body={"newEmail": "nope"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/change-email", note="untrusted callback", json_body={"newEmail": f"parity-auth-x-{run.tag}@example.com", "callbackURL": "https://evil.example"}, cookies=h.session_cookies(t))
    unverified = run.user("unv", email_verified=False)
    t2 = run.session("s2", unverified["id"])
    run.req(e, "POST", f"{A}/change-email", note="unverified user", json_body={"newEmail": f"parity-auth-new2-{run.tag}@example.com"}, cookies=h.session_cookies(t2))
    run.db(e, "users unchanged", 'SELECT email, "emailVerified" FROM "user" WHERE id IN (%s, %s) ORDER BY email', u["id"], unverified["id"])


def sc_verify_email(run):
    e = "verify-email"
    now = int(time.time())
    unverified = run.user("ve", email_verified=False, password=run.password("parity-pass-1"))
    token = jwt({"email": unverified["email"], "iat": now, "exp": now + 3600})
    run.req(e, "GET", f"{A}/verify-email?token={token}", note="plain")
    run.db(e, "verified", USER_ROW, unverified["id"])
    run.req(e, "GET", f"{A}/verify-email?token={token}&callbackURL=/done", note="already verified redirect")
    expired = jwt({"email": unverified["email"], "iat": now - 7200, "exp": now - 3600})
    run.req(e, "GET", f"{A}/verify-email?token={expired}", note="expired")
    run.req(e, "GET", f"{A}/verify-email?token={expired}&callbackURL=/done?x=1", note="expired with callback")
    run.req(e, "GET", f"{A}/verify-email?token=garbage&callbackURL=/done", note="garbage")
    run.req(e, "GET", f"{A}/verify-email?token={jwt({'email': unverified['email'], 'iat': now, 'exp': now + 60}, 'wrong-secret')}", note="wrong secret")
    run.req(e, "GET", f"{A}/verify-email?token={token}&callbackURL=https://evil.example", note="untrusted callback")
    run.req(e, "GET", f"{A}/verify-email", note="missing token")
    run.req(e, "GET", f"{A}/verify-email?token={jwt({'email': 'parity-auth-ghost@example.com', 'iat': now, 'exp': now + 60})}", note="unknown user")
    run.req(e, "GET", f"{A}/verify-email?token={jwt({'email': 'not-an-email', 'iat': now, 'exp': now + 60})}", note="bad payload")
    mover = run.user("mover", password=run.password("parity-pass-2"))
    new_email = f"parity-auth-moved-{run.tag}@example.com"
    run.name(new_email, "email:moved")
    confirm = jwt({"email": mover["email"], "updateTo": new_email, "requestType": "change-email-confirmation", "iat": now, "exp": now + 3600})
    run.req(e, "GET", f"{A}/verify-email?token={confirm}", note="change confirmation")
    change = jwt({"email": mover["email"], "updateTo": new_email, "requestType": "change-email-verification", "iat": now, "exp": now + 3600})
    other = run.user("other")
    t_other = run.session("other", other["id"])
    run.req(e, "GET", f"{A}/verify-email?token={change}", note="change with someone else's session", cookies=h.session_cookies(t_other))
    run.req(e, "GET", f"{A}/verify-email?token={change}&callbackURL=/settings", note="change without session")
    run.db(e, "moved user", USER_ROW, mover["id"])
    run.db(e, "session created", SESSION_ROWS, mover["id"])
    legacy_user = run.user("legacy")
    legacy_email = f"parity-auth-legacy-{run.tag}@example.com"
    run.name(legacy_email, "email:legacy-new")
    legacy = jwt({"email": legacy_user["email"], "updateTo": legacy_email, "iat": now, "exp": now + 3600})
    t_legacy = run.session("legacy", legacy_user["id"])
    run.req(e, "GET", f"{A}/verify-email?token={legacy}", note="legacy change with session", cookies=h.session_cookies(t_legacy))
    run.db(e, "legacy user", USER_ROW, legacy_user["id"])


def sc_delete_user(run):
    e = "delete-user"
    u = run.user("du", password=run.password("parity-pass-1"))
    t = run.session("fresh", u["id"])
    h.q("""INSERT INTO apikey (id, key, "referenceId", enabled, "rateLimitEnabled", "requestCount", "createdAt", "updatedAt", "configId")
           VALUES (%s, %s, %s, true, false, 0, now(), now(), 'default')""", f"parity-auth-key-{h.rand_id(8)}", h.rand_id(43), u["id"])
    run.req(e, "POST", f"{A}/delete-user", note="fresh session", json_body={}, cookies=h.session_cookies(t))
    run.db(e, "gone", 'SELECT (SELECT count(*) FROM "user" WHERE id = %s) AS users, (SELECT count(*) FROM session WHERE "userId" = %s) AS sessions, (SELECT count(*) FROM account WHERE "userId" = %s) AS accounts, (SELECT count(*) FROM apikey WHERE "referenceId" = %s) AS keys', u["id"], u["id"], u["id"], u["id"])
    stale_user = run.user("stale", password=run.password("parity-pass-2"))
    stale = run.session("stale", stale_user["id"], created_offset_sec=-2 * 86400)
    run.req(e, "POST", f"{A}/delete-user", note="stale session", json_body={}, cookies=h.session_cookies(stale))
    run.req(e, "POST", f"{A}/delete-user", note="wrong password", json_body={"password": "nope-nope-1"}, cookies=h.session_cookies(stale))
    run.req(e, "POST", f"{A}/delete-user", note="bogus token", json_body={"token": "abc"}, cookies=h.session_cookies(stale))
    run.req(e, "POST", f"{A}/delete-user", note="password on stale session", json_body={"password": "parity-pass-2"}, cookies=h.session_cookies(stale))
    run.db(e, "stale gone", 'SELECT count(*) AS n FROM "user" WHERE id = %s', stale_user["id"])
    run.req(e, "POST", f"{A}/delete-user", note="no session", json_body={})
    run.req(e, "POST", f"{A}/delete-user", note="no body", cookies=h.session_cookies(stale))


def sc_sessions(run):
    u = run.user("ls", password=run.password("parity-pass-1"))
    t = run.session("main", u["id"])
    other = run.session("other", u["id"])
    admin = run.user("lsadmin", role="admin")
    h.q(f"""INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId", "impersonatedBy")
            VALUES (%s, (now() AT TIME ZONE 'utc') + interval '1 hour', %s, date_trunc('milliseconds', now() AT TIME ZONE 'utc'), date_trunc('milliseconds', now() AT TIME ZONE 'utc'), '', 'imp', %s, %s)""",
         f"parity-auth-ses-{h.rand_id(8)}", run.name(h.rand_id(32), "token:imp"), u["id"], admin["id"])
    run.session("expired", u["id"], expires_offset_sec=-10)
    # listSessions reads without ORDER BY in both backends
    run.req("list-sessions", "GET", f"{A}/list-sessions", cookies=h.session_cookies(t), unordered=[])
    stale = run.session("stale", u["id"], created_offset_sec=-2 * 86400)
    run.req("list-sessions", "GET", f"{A}/list-sessions", note="stale", cookies=h.session_cookies(stale))
    run.req("revoke-session", "POST", f"{A}/revoke-session", json_body={"token": other}, cookies=h.session_cookies(t))
    run.req("revoke-session", "POST", f"{A}/revoke-session", note="foreign token ignored", json_body={"token": "nope"}, cookies=h.session_cookies(t))
    run.db("revoke-session", "sessions", SESSION_ROWS, u["id"])
    run.req("revoke-other-sessions", "POST", f"{A}/revoke-other-sessions", cookies=h.session_cookies(t))
    run.db("revoke-other-sessions", "sessions", SESSION_ROWS, u["id"])
    run.req("revoke-sessions", "POST", f"{A}/revoke-sessions", cookies=h.session_cookies(t))
    run.db("revoke-sessions", "sessions", SESSION_ROWS, u["id"])


def sc_send_verification(run):
    e = "send-verification-email"
    u = run.user("sve", email_verified=False)
    t = run.session("s", u["id"])
    run.req(e, "POST", f"{A}/send-verification-email", note="unauthenticated", json_body={"email": "parity-auth-nobody@example.com"})
    run.req(e, "POST", f"{A}/send-verification-email", note="mismatch", json_body={"email": "parity-auth-other@example.com"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/send-verification-email", note="own unverified", json_body={"email": u["email"]}, cookies=h.session_cookies(t))
    v = run.user("svev")
    tv = run.session("sv", v["id"])
    run.req(e, "POST", f"{A}/send-verification-email", note="already verified", json_body={"email": v["email"]}, cookies=h.session_cookies(tv))


SCENARIOS = [sc_update_user, sc_change_password, sc_change_email, sc_verify_email, sc_delete_user, sc_sessions, sc_send_verification]
