"""Email OTP plugin routes."""

import harness as h
from sc_core import A, SESSION_ROWS, USER_ROW
from sc_account import ACCOUNT_ROWS

OTP_ROWS = 'SELECT identifier, value, "expiresAt", "createdAt", "updatedAt" FROM verification WHERE identifier = %s ORDER BY "createdAt"'


def otp_of(identifier):
    rows = h.q('SELECT value FROM verification WHERE identifier = %s ORDER BY "createdAt" DESC LIMIT 1', identifier)
    return rows[0]["value"].rsplit(":", 1)[0] if rows else None


def put_otp(identifier, otp, attempts=0, expires_sec=300):
    h.q(
        """INSERT INTO verification (id, identifier, value, "expiresAt", "createdAt", "updatedAt")
           VALUES (%s, %s, %s, date_trunc('milliseconds', (now() AT TIME ZONE 'utc') + %s * interval '1 second'),
                   date_trunc('milliseconds', now() AT TIME ZONE 'utc'), date_trunc('milliseconds', now() AT TIME ZONE 'utc'))""",
        f"parity-auth-ver-{h.rand_id(8)}", identifier, f"{otp}:{attempts}", expires_sec,
    )


def sc_send_otp(run):
    e = "email-otp/send-verification-otp"
    u = run.user("otp", password=run.password("parity-pass-1"))
    ident = f"forget-password-otp-{u['email']}"
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="known email", json_body={"email": u["email"].upper(), "type": "forget-password"})
    run.db(e, "row", OTP_ROWS, ident)
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="second code", json_body={"email": u["email"], "type": "forget-password"})
    run.db(e, "rows", OTP_ROWS, ident)
    unknown = f"parity-auth-unknown-{run.tag}@example.com"
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="unknown email", json_body={"email": unknown, "type": "forget-password"})
    run.db(e, "no row", OTP_ROWS, f"forget-password-otp-{unknown}")
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="sign-in unknown", json_body={"email": unknown, "type": "sign-in"})
    run.db(e, "no sign-in row", OTP_ROWS, f"sign-in-otp-{unknown}")
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="sign-in known", json_body={"email": u["email"], "type": "sign-in"})
    run.db(e, "sign-in row", OTP_ROWS, f"sign-in-otp-{u['email']}")
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="change-email type", json_body={"email": u["email"], "type": "change-email"})
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="bad type", json_body={"email": u["email"], "type": "nope"})
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="bad email", json_body={"email": "nope", "type": "sign-in"})
    run.req(e, "POST", f"{A}/email-otp/send-verification-otp", note="cross-site navigation", json_body={"email": u["email"], "type": "sign-in"}, origin=False, headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"})
    r = "email-otp/request-password-reset"
    run.req(r, "POST", f"{A}/email-otp/request-password-reset", json_body={"email": u["email"]})
    run.req(r, "POST", f"{A}/email-otp/request-password-reset", note="unknown", json_body={"email": unknown})
    run.req(r, "POST", f"{A}/email-otp/request-password-reset", note="validation", json_body={})
    run.req("forget-password/email-otp", "POST", f"{A}/forget-password/email-otp", json_body={"email": u["email"]})
    run.db(r, "rows", 'SELECT count(*) AS n FROM verification WHERE identifier = %s', ident)


def sc_reset_password(run):
    e = "email-otp/reset-password"
    u = run.user("rp", password=run.password("parity-pass-1"), email_verified=False)
    run.password("parity-pass-new")
    t = run.session("keep", u["id"])
    ident = f"forget-password-otp-{u['email']}"
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="no code", json_body={"email": u["email"], "otp": "000000", "password": "parity-pass-new"})
    put_otp(ident, "123456")
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="wrong", json_body={"email": u["email"], "otp": "654321", "password": "parity-pass-new"})
    run.db(e, "attempt 1", OTP_ROWS, ident)
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="wrong again", json_body={"email": u["email"], "otp": "654320", "password": "parity-pass-new"})
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="ok", json_body={"email": u["email"].upper(), "otp": "123456", "password": "parity-pass-new"})
    run.db(e, "consumed", OTP_ROWS, ident)
    run.db(e, "account", ACCOUNT_ROWS, u["id"])
    run.db(e, "user verified", USER_ROW, u["id"])
    run.db(e, "sessions kept", SESSION_ROWS, u["id"])
    run.req("sign-in/email", "POST", f"{A}/sign-in/email", note="new password", json_body={"email": u["email"], "password": "parity-pass-new"})
    put_otp(ident, "111111", attempts=3)
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="too many attempts", json_body={"email": u["email"], "otp": "111111", "password": "parity-pass-new"})
    run.db(e, "locked out row gone", OTP_ROWS, ident)
    put_otp(ident, "222222")
    for i in range(3):
        run.req(e, "POST", f"{A}/email-otp/reset-password", note=f"wrong {i}", json_body={"email": u["email"], "otp": "000000", "password": "parity-pass-new"})
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="right after three wrong", json_body={"email": u["email"], "otp": "222222", "password": "parity-pass-new"})
    put_otp(ident, "333333", expires_sec=-5)
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="expired", json_body={"email": u["email"], "otp": "333333", "password": "parity-pass-new"})
    run.db(e, "expired deleted", OTP_ROWS, ident)
    put_otp(ident, "444444")
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="short password after valid otp", json_body={"email": u["email"], "otp": "444444", "password": "short"})
    run.db(e, "consumed anyway", OTP_ROWS, ident)
    put_otp(ident, "555555", attempts="x")
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="NaN attempts", json_body={"email": u["email"], "otp": "000001", "password": "parity-pass-new"})
    run.db(e, "NaN row", OTP_ROWS, ident)
    nocred = run.user("rpnocred")
    nident = f"forget-password-otp-{nocred['email']}"
    put_otp(nident, "777777")
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="no credential account", json_body={"email": nocred["email"], "otp": "777777", "password": "parity-pass-new"})
    run.db(e, "account created", ACCOUNT_ROWS, nocred["id"])
    ghost = f"parity-auth-ghost-{run.tag}@example.com"
    put_otp(f"forget-password-otp-{ghost}", "888888")
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="unknown user with code", json_body={"email": ghost, "otp": "888888", "password": "parity-pass-new"})
    run.req(e, "POST", f"{A}/email-otp/reset-password", note="validation", json_body={"email": u["email"]})


def sc_otp_sign_in(run):
    e = "sign-in/email-otp"
    u = run.user("osi", email_verified=False, password=run.password("parity-pass-1"))
    old = run.session("old", u["id"])
    ident = f"sign-in-otp-{u['email']}"
    put_otp(ident, "121212")
    run.req(e, "POST", f"{A}/sign-in/email-otp", note="unverified user", json_body={"email": u["email"], "otp": "121212"})
    run.db(e, "credential dropped", ACCOUNT_ROWS, u["id"])
    run.db(e, "sessions", SESSION_ROWS, u["id"])
    run.db(e, "user", USER_ROW, u["id"])
    ghost = f"parity-auth-ghost-{run.tag}@example.com"
    put_otp(f"sign-in-otp-{ghost}", "343434")
    run.req(e, "POST", f"{A}/sign-in/email-otp", note="unknown email (sign-ups disabled)", json_body={"email": ghost, "otp": "343434"})
    run.db(e, "no user", 'SELECT count(*) AS n FROM "user" WHERE email = %s', ghost)
    run.req(e, "POST", f"{A}/sign-in/email-otp", note="wrong", json_body={"email": u["email"], "otp": "000000"})
    run.req(e, "POST", f"{A}/sign-in/email-otp", note="validation", json_body={"email": u["email"]})
    c = "email-otp/check-verification-otp"
    put_otp(f"email-verification-otp-{u['email']}", "565656")
    run.req(c, "POST", f"{A}/email-otp/check-verification-otp", note="wrong", json_body={"email": u["email"], "type": "email-verification", "otp": "000000"})
    run.db(c, "attempt counted", OTP_ROWS, f"email-verification-otp-{u['email']}")
    run.req(c, "POST", f"{A}/email-otp/check-verification-otp", note="right", json_body={"email": u["email"], "type": "email-verification", "otp": "565656"})
    run.req(c, "POST", f"{A}/email-otp/check-verification-otp", note="unknown user", json_body={"email": ghost, "type": "sign-in", "otp": "1"})
    v = "email-otp/verify-email"
    run.req(v, "POST", f"{A}/email-otp/verify-email", note="right", json_body={"email": u["email"], "otp": "565656"})
    run.db(v, "user", USER_ROW, u["id"])
    run.req(v, "POST", f"{A}/email-otp/verify-email", note="consumed", json_body={"email": u["email"], "otp": "565656"})
    ch = "email-otp/request-email-change"
    t = run.session("s", u["id"])
    run.req(ch, "POST", f"{A}/email-otp/request-email-change", note="disabled", json_body={"newEmail": "parity-auth-x@example.com"}, cookies=h.session_cookies(t))
    run.req(ch, "POST", f"{A}/email-otp/request-email-change", note="no session", json_body={"newEmail": "parity-auth-x@example.com"})
    run.req("email-otp/change-email", "POST", f"{A}/email-otp/change-email", note="disabled", json_body={"newEmail": "parity-auth-x@example.com", "otp": "1"}, cookies=h.session_cookies(t))


SCENARIOS = [sc_send_otp, sc_reset_password, sc_otp_sign_in]
