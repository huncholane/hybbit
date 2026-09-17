"""API key listing/deletion and the admin plugin."""

import json

import harness as h
from sc_core import A, SESSION_ROWS, USER_ROW


def insert_key(run, key, reference_id, config_id="default", permissions=None, metadata="null", expires_sql="NULL", name=None, prefix=None, start=None):
    kid = run.name(f"parity-auth-key-{h.rand_id(10)}", f"key:{key}")
    h.q(
        f"""INSERT INTO apikey (id, name, start, prefix, key, "referenceId", enabled, "rateLimitEnabled", "rateLimitTimeWindow", "rateLimitMax",
                               "requestCount", "expiresAt", "createdAt", "updatedAt", "configId", permissions, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, true, false, 86400000, 10, 0, {expires_sql},
                    date_trunc('milliseconds', now() AT TIME ZONE 'utc'), date_trunc('milliseconds', now() AT TIME ZONE 'utc'), %s, %s, %s::jsonb)""",
        kid, name or f"k-{key}", start, prefix, h.rand_id(43), reference_id, config_id, permissions, metadata,
    )
    return kid


def sc_api_keys(run):
    owner = run.user("kowner")
    member = run.user("kmember")
    outsider = run.user("koutsider")
    org = run.org("k", owner_id=owner["id"])
    h.add_member(org["id"], member["id"], "member")
    insert_key(run, "own", owner["id"], config_id=None, permissions='{"sites":["read"]}', name="Legacy")
    insert_key(run, "own2", owner["id"], metadata='"{\\"createdBy\\":\\"x\\"}"', start="abcdef")
    # the shape batchMigrateLegacyMetadata rewrites (a string after drizzle and parseJSON)
    legacy = json.dumps(json.dumps(json.dumps(json.dumps({"createdBy": "legacy", "at": "2024-01-01T00:00:00Z", "b": 1, "1": 2}))))
    insert_key(run, "own3", owner["id"], metadata=legacy)
    insert_key(run, "own4", owner["id"], metadata='{"b": 1, "10": 2, "2": 3}', permissions='{"at":"2024-02-30T00:00:00Z","z":1,"3":2}')
    insert_key(run, "expired", owner["id"], expires_sql="(now() AT TIME ZONE 'utc') - interval '1 day'")
    org_key = insert_key(run, "org", org["id"], config_id="org", metadata=f'{{"createdBy":"{owner["id"]}"}}', prefix="rb_org_", start="rb_org")
    member_key = insert_key(run, "member", member["id"])
    t_owner = run.session("owner", owner["id"])
    t_member = run.session("member", member["id"])
    t_out = run.session("out", outsider["id"])
    l = "api-key/list"
    run.req(l, "GET", f"{A}/api-key/list", note="user keys", cookies=h.session_cookies(t_owner), unordered=[["apiKeys"]])
    run.req(l, "GET", f"{A}/api-key/list?organizationId={org['id']}", note="org keys as owner", cookies=h.session_cookies(t_owner))
    run.req(l, "GET", f"{A}/api-key/list?organizationId={org['id']}", note="org keys as member", cookies=h.session_cookies(t_member))
    run.req(l, "GET", f"{A}/api-key/list?organizationId={org['id']}", note="outsider", cookies=h.session_cookies(t_out))
    run.req(l, "GET", f"{A}/api-key/list?limit=1&offset=0&sortBy=name&sortDirection=desc", note="paged", cookies=h.session_cookies(t_owner))
    run.req(l, "GET", f"{A}/api-key/list?limit=-1", note="bad limit", cookies=h.session_cookies(t_owner))
    run.req(l, "GET", f"{A}/api-key/list", note="no session")
    run.db(l, "metadata migrated", 'SELECT name, metadata::text AS metadata, "updatedAt" FROM apikey WHERE "referenceId" = %s ORDER BY name', owner["id"])
    d = "api-key/delete"
    broken = run.user("kbroken")
    broken_key = insert_key(run, "broken", broken["id"], metadata=json.dumps(json.dumps(json.dumps("not json at all"))))
    t_broken = run.session("broken", broken["id"])
    run.req(l, "GET", f"{A}/api-key/list", note="unparseable metadata", cookies=h.session_cookies(t_broken))
    run.req(d, "POST", f"{A}/api-key/delete", note="unparseable metadata", json_body={"keyId": broken_key}, cookies=h.session_cookies(t_broken))
    run.db(d, "unparseable key kept", 'SELECT name FROM apikey WHERE "referenceId" = %s', broken["id"])
    run.req(d, "POST", f"{A}/api-key/delete", note="someone else's", json_body={"keyId": member_key}, cookies=h.session_cookies(t_owner))
    run.req(d, "POST", f"{A}/api-key/delete", note="org key without configId", json_body={"keyId": org_key}, cookies=h.session_cookies(t_owner))
    run.req(d, "POST", f"{A}/api-key/delete", note="org key as member", json_body={"keyId": org_key, "configId": "org"}, cookies=h.session_cookies(t_member))
    run.req(d, "POST", f"{A}/api-key/delete", note="org key as owner", json_body={"keyId": org_key, "configId": "org"}, cookies=h.session_cookies(t_owner))
    run.req(d, "POST", f"{A}/api-key/delete", note="own key", json_body={"keyId": member_key, "configId": "unknown"}, cookies=h.session_cookies(t_member))
    run.req(d, "POST", f"{A}/api-key/delete", note="missing", json_body={"keyId": "nope"}, cookies=h.session_cookies(t_member))
    run.req(d, "POST", f"{A}/api-key/delete", note="validation", json_body={}, cookies=h.session_cookies(t_member))
    run.db(d, "remaining", 'SELECT name, "configId" FROM apikey WHERE "referenceId" IN (%s, %s, %s) ORDER BY name', owner["id"], member["id"], org["id"])
    banned = run.user("kbanned", banned=True)
    t_banned = h.create_session(banned["id"])
    run.name(t_banned, "token:banned")
    run.req(d, "POST", f"{A}/api-key/delete", note="banned user", json_body={"keyId": "x"}, cookies=h.session_cookies(t_banned))


def sc_admin(run):
    admin = run.user("aadmin", role="admin", name="Admin A")
    admin2 = run.user("aadmin2", role="admin")
    user = run.user("auser", name="Zed User", password=run.password("parity-pass-1"))
    other = run.user("aother", name="Alpha Other")
    t_admin = run.session("admin", admin["id"])
    t_user = run.session("user", user["id"])
    user_session = run.session("user2", user["id"])
    p = "admin/has-permission"
    run.req(p, "POST", f"{A}/admin/has-permission", note="admin", json_body={"permissions": {"user": ["impersonate"]}}, cookies=h.session_cookies(t_admin))
    run.req(p, "POST", f"{A}/admin/has-permission", note="user", json_body={"permissions": {"user": ["impersonate"]}}, cookies=h.session_cookies(t_user))
    run.req(p, "POST", f"{A}/admin/has-permission", note="singular", json_body={"permission": {"user": ["list"]}}, cookies=h.session_cookies(t_admin))
    run.req(p, "POST", f"{A}/admin/has-permission", note="no session", json_body={"permissions": {"user": ["list"]}})
    lu = "admin/list-users"
    search = f"{run.tag}-a"
    run.req(lu, "GET", f"{A}/admin/list-users?searchValue={search}&searchField=email&searchOperator=contains&limit=10&offset=0&sortBy=name&sortDirection=asc", note="search", cookies=h.session_cookies(t_admin))
    run.req(lu, "GET", f"{A}/admin/list-users?searchValue={search}&filterField=role&filterOperator=eq&filterValue=admin&sortBy=createdAt&sortDirection=desc", note="filter role", cookies=h.session_cookies(t_admin))
    run.req(lu, "GET", f"{A}/admin/list-users?searchValue=Zed&searchField=name&searchOperator=starts_with&limit=5", note="name prefix", cookies=h.session_cookies(t_admin))
    run.req(lu, "GET", f"{A}/admin/list-users?searchValue={search}&sortBy=nope", note="bad sort", cookies=h.session_cookies(t_admin))
    run.req(lu, "GET", f"{A}/admin/list-users?searchValue=x&searchField=bogus", note="bad field", cookies=h.session_cookies(t_admin))
    run.req(lu, "GET", f"{A}/admin/list-users", note="as user", cookies=h.session_cookies(t_user))
    run.req(lu, "GET", f"{A}/admin/list-users", note="no session")
    im = "admin/impersonate-user"
    r = run.req(im, "POST", f"{A}/admin/impersonate-user", json_body={"userId": user["id"]}, cookies=h.session_cookies(t_admin))
    run.db(im, "impersonation session", SESSION_ROWS, user["id"])
    run.req(im, "POST", f"{A}/admin/impersonate-user", note="admin target", json_body={"userId": admin2["id"]}, cookies=h.session_cookies(t_admin))
    run.req(im, "POST", f"{A}/admin/impersonate-user", note="as user", json_body={"userId": other["id"]}, cookies=h.session_cookies(t_user))
    run.req(im, "POST", f"{A}/admin/impersonate-user", note="missing user", json_body={"userId": "parity-auth-nope"}, cookies=h.session_cookies(t_admin))
    imp_token = h.q('SELECT token FROM session WHERE "userId" = %s AND "impersonatedBy" IS NOT NULL', user["id"])
    st = "admin/stop-impersonating"
    if imp_token:
        cookies = {h.SESSION_COOKIE: h.sign(imp_token[0]["token"]), h.DONT_REMEMBER_COOKIE: h.sign("true"), h.ADMIN_SESSION_COOKIE: h.sign(f"{t_admin}:")}
        run.req(st, "POST", f"{A}/admin/stop-impersonating", note="no admin cookie", cookies={h.SESSION_COOKIE: h.sign(imp_token[0]["token"])})
        run.req(st, "POST", f"{A}/admin/stop-impersonating", cookies=cookies)
        run.db(st, "impersonation ended", SESSION_ROWS, user["id"])
    run.req(st, "POST", f"{A}/admin/stop-impersonating", note="not impersonating", cookies=h.session_cookies(t_user))
    run.req(st, "POST", f"{A}/admin/stop-impersonating", note="no session")
    uu = "admin/update-user"
    run.req(uu, "POST", f"{A}/admin/update-user", note="name", json_body={"userId": other["id"], "data": {"name": "Renamed"}}, cookies=h.session_cookies(t_admin))
    run.req(uu, "POST", f"{A}/admin/update-user", note="email", json_body={"userId": other["id"], "data": {"email": f"PARITY-AUTH-renamed-{run.tag}@example.com"}}, cookies=h.session_cookies(t_admin))
    run.name(f"parity-auth-renamed-{run.tag}@example.com", "email:renamed")
    run.req(uu, "POST", f"{A}/admin/update-user", note="email taken", json_body={"userId": other["id"], "data": {"email": user["email"]}}, cookies=h.session_cookies(t_admin))
    run.req(uu, "POST", f"{A}/admin/update-user", note="empty", json_body={"userId": other["id"], "data": {}}, cookies=h.session_cookies(t_admin))
    run.req(uu, "POST", f"{A}/admin/update-user", note="password", json_body={"userId": other["id"], "data": {"password": "x"}}, cookies=h.session_cookies(t_admin))
    run.req(uu, "POST", f"{A}/admin/update-user", note="ban self", json_body={"userId": admin["id"], "data": {"banned": True}}, cookies=h.session_cookies(t_admin))
    run.req(uu, "POST", f"{A}/admin/update-user", note="as user", json_body={"userId": other["id"], "data": {"name": "x"}}, cookies=h.session_cookies(t_user))
    run.db(uu, "other", USER_ROW, other["id"])
    sr = "admin/set-role"
    run.req(sr, "POST", f"{A}/admin/set-role", json_body={"userId": other["id"], "role": ["admin", "user"]}, cookies=h.session_cookies(t_admin))
    run.req(sr, "POST", f"{A}/admin/set-role", note="missing", json_body={"userId": "parity-auth-nope", "role": "user"}, cookies=h.session_cookies(t_admin))
    run.req(sr, "POST", f"{A}/admin/set-role", note="as user", json_body={"userId": other["id"], "role": "admin"}, cookies=h.session_cookies(t_user))
    b = "admin/ban-user"
    run.req(b, "POST", f"{A}/admin/ban-user", json_body={"userId": user["id"], "banReason": "spam", "banExpiresIn": 3600}, cookies=h.session_cookies(t_admin))
    run.db(b, "banned", USER_ROW, user["id"])
    run.db(b, "sessions revoked", SESSION_ROWS, user["id"])
    run.req(b, "POST", f"{A}/admin/ban-user", note="default reason", json_body={"userId": other["id"]}, cookies=h.session_cookies(t_admin))
    run.req(b, "POST", f"{A}/admin/ban-user", note="self", json_body={"userId": admin["id"]}, cookies=h.session_cookies(t_admin))
    run.req("sign-in/email", "POST", f"{A}/sign-in/email", note="banned user", json_body={"email": user["email"], "password": "parity-pass-1"})
    ub = "admin/unban-user"
    run.req(ub, "POST", f"{A}/admin/unban-user", json_body={"userId": user["id"]}, cookies=h.session_cookies(t_admin))
    run.db(ub, "unbanned", USER_ROW, user["id"])
    run.req(ub, "POST", f"{A}/admin/unban-user", note="missing", json_body={"userId": "parity-auth-nope"}, cookies=h.session_cookies(t_admin))
    ls = "admin/list-user-sessions"
    run.session("listed", other["id"])
    run.req(ls, "POST", f"{A}/admin/list-user-sessions", json_body={"userId": other["id"]}, cookies=h.session_cookies(t_admin))
    run.req("admin/revoke-user-sessions", "POST", f"{A}/admin/revoke-user-sessions", json_body={"userId": other["id"]}, cookies=h.session_cookies(t_admin))
    run.req("admin/revoke-user-session", "POST", f"{A}/admin/revoke-user-session", json_body={"sessionToken": "nope"}, cookies=h.session_cookies(t_admin))
    run.req("admin/get-user", "GET", f"{A}/admin/get-user?id={other['id']}", cookies=h.session_cookies(t_admin))
    run.req("admin/get-user", "GET", f"{A}/admin/get-user?id=nope", note="missing", cookies=h.session_cookies(t_admin))


SCENARIOS = [sc_api_keys, sc_admin]
