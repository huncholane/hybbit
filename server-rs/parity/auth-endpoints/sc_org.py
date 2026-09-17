"""Organization plugin routes and the auth.ts hooks around them."""

import harness as h
from sc_core import A, SESSION_ROWS

ORG_ROWS = 'SELECT name, slug, logo, metadata, "createdAt", "stripeCustomerId", "monthlyEventCount", "overMonthlyLimit", "planOverride" FROM organization WHERE slug = %s'
MEMBER_ROWS = 'SELECT "userId", role, "createdAt", has_restricted_site_access FROM member WHERE "organizationId" = %s ORDER BY role, "userId"'
INVITATION_ROWS = 'SELECT email, role, status, "teamId", "expiresAt", "createdAt", "inviterId", has_restricted_site_access, site_ids FROM invitation WHERE "organizationId" = %s ORDER BY email, status'


def add_site(org_id, name):
    rows = h.q("INSERT INTO sites (name, domain, organization_id) VALUES (%s, %s, %s) RETURNING site_id", f"parity-auth-{name}", f"{name}.parity-auth.test", org_id)
    return rows[0]["site_id"]


def sc_org_create(run):
    e = "organization/create"
    u = run.user("oc")
    t = run.session("s", u["id"])
    slug = f"parity-auth-new-{run.tag}"
    run.name(slug, "slug:new")
    r = run.req(e, "POST", f"{A}/organization/create", json_body={"name": "New Org", "slug": slug, "metadata": {"a": 1}, "logo": None}, cookies=h.session_cookies(t))
    run.db(e, "org", ORG_ROWS, slug)
    org_id = (h.q("SELECT id FROM organization WHERE slug = %s", slug) or [{"id": None}])[0]["id"]
    run.db(e, "members", MEMBER_ROWS, org_id)
    run.db(e, "team", 'SELECT t.name, tm."userId" FROM team t JOIN "teamMember" tm ON tm."teamId" = t.id WHERE t."organizationId" = %s', org_id)
    run.db(e, "session active", 'SELECT "activeOrganizationId" = %s AS org_active, "activeTeamId" IS NOT NULL AS team_active FROM session WHERE token = %s', org_id, t)
    run.req(e, "POST", f"{A}/organization/create", note="slug taken", json_body={"name": "Dup", "slug": slug}, cookies=h.session_cookies(t))
    slug2 = f"parity-auth-keep-{run.tag}"
    run.name(slug2, "slug:keep")
    run.req(e, "POST", f"{A}/organization/create", note="keep active, no metadata", json_body={"name": "Keep", "slug": slug2, "keepCurrentActiveOrganization": True}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/organization/create", note="empty name", json_body={"name": "", "slug": "x"}, cookies=h.session_cookies(t))
    run.req(e, "POST", f"{A}/organization/create", note="no session", json_body={"name": "x", "slug": f"parity-auth-x-{run.tag}"})
    run.req("organization/list", "GET", f"{A}/organization/list", cookies=h.session_cookies(t))
    run.req("organization/check-slug", "POST", f"{A}/organization/check-slug", note="taken", json_body={"slug": slug}, cookies=h.session_cookies(t))
    run.req("organization/check-slug", "POST", f"{A}/organization/check-slug", note="free", json_body={"slug": f"parity-auth-free-{run.tag}"}, cookies=h.session_cookies(t))


def sc_org_read_update(run):
    owner = run.user("owner")
    admin = run.user("admin")
    member = run.user("member")
    outsider = run.user("outsider")
    org = run.org("o", owner_id=owner["id"])
    h.add_member(org["id"], admin["id"], "admin")
    h.add_member(org["id"], member["id"], "member")
    h.q("INSERT INTO team (id, name, \"organizationId\", \"createdAt\") VALUES (%s, 'Team', %s, date_trunc('milliseconds', now() AT TIME ZONE 'utc'))", run.name(f"parity-auth-team-{h.rand_id(6)}", "team"), org["id"])
    t_owner = run.session("owner", owner["id"], active_org=org["id"])
    t_member = run.session("member", member["id"])
    t_out = run.session("out", outsider["id"], active_org=org["id"])
    g = "organization/get-full-organization"
    run.req(g, "GET", f"{A}/organization/get-full-organization", note="active", cookies=h.session_cookies(t_owner), unordered=[["invitations"], ["members"], ["teams"]])
    run.req(g, "GET", f"{A}/organization/get-full-organization?organizationSlug={org['slug']}&membersLimit=2", note="by slug limited", cookies=h.session_cookies(t_member), unordered=[["invitations"], ["teams"]])
    run.req(g, "GET", f"{A}/organization/get-full-organization", note="no active", cookies=h.session_cookies(t_member))
    run.req(g, "GET", f"{A}/organization/get-full-organization", note="outsider", cookies=h.session_cookies(t_out))
    run.db(g, "outsider active cleared", 'SELECT "activeOrganizationId" FROM session WHERE token = %s', t_out)
    run.req(g, "GET", f"{A}/organization/get-full-organization?organizationId=parity-auth-missing", note="missing", cookies=h.session_cookies(t_owner))
    run.req(g, "GET", f"{A}/organization/get-full-organization", note="no session")
    s = "organization/set-active"
    run.req(s, "POST", f"{A}/organization/set-active", note="by id", json_body={"organizationId": org["id"]}, cookies=h.session_cookies(t_member))
    run.req(s, "POST", f"{A}/organization/set-active", note="by slug", json_body={"organizationSlug": org["slug"]}, cookies=h.session_cookies(t_member))
    run.req(s, "POST", f"{A}/organization/set-active", note="current", json_body={}, cookies=h.session_cookies(t_member, dont_remember=True))
    run.req(s, "POST", f"{A}/organization/set-active", note="null", json_body={"organizationId": None}, cookies=h.session_cookies(t_member))
    run.req(s, "POST", f"{A}/organization/set-active", note="null again", json_body={"organizationId": None}, cookies=h.session_cookies(t_member))
    run.req(s, "POST", f"{A}/organization/set-active", note="outsider", json_body={"organizationId": org["id"]}, cookies=h.session_cookies(t_out))
    run.req(s, "POST", f"{A}/organization/set-active", note="unknown slug", json_body={"organizationSlug": "parity-auth-nope"}, cookies=h.session_cookies(t_member))
    u = "organization/update"
    run.req(u, "POST", f"{A}/organization/update", note="owner name", json_body={"organizationId": org["id"], "data": {"name": "Renamed"}}, cookies=h.session_cookies(t_owner))
    run.req(u, "POST", f"{A}/organization/update", note="active org metadata", json_body={"data": {"metadata": {"x": "y"}, "logo": "https://logo"}}, cookies=h.session_cookies(t_owner))
    run.req(u, "POST", f"{A}/organization/update", note="member forbidden", json_body={"organizationId": org["id"], "data": {"name": "Nope"}}, cookies=h.session_cookies(t_member))
    run.req(u, "POST", f"{A}/organization/update", note="outsider", json_body={"organizationId": org["id"], "data": {"name": "Nope"}}, cookies=h.session_cookies(t_out))
    other = run.org("other", owner_id=owner["id"])
    run.req(u, "POST", f"{A}/organization/update", note="slug taken", json_body={"organizationId": org["id"], "data": {"slug": other["slug"]}}, cookies=h.session_cookies(t_owner))
    run.req(u, "POST", f"{A}/organization/update", note="empty data", json_body={"organizationId": org["id"], "data": {}}, cookies=h.session_cookies(t_owner))
    run.req(u, "POST", f"{A}/organization/update", note="no session", json_body={"data": {"name": "x"}})
    run.db(u, "org", ORG_ROWS, org["slug"])
    run.req("organization/has-permission", "POST", f"{A}/organization/has-permission", note="admin apiKey", json_body={"organizationId": org["id"], "permissions": {"apiKey": ["delete"]}}, cookies=h.session_cookies(t_owner))
    t_admin = run.session("admin", admin["id"], active_org=org["id"])
    run.req("organization/has-permission", "POST", f"{A}/organization/has-permission", note="admin org delete", json_body={"permissions": {"organization": ["delete"]}}, cookies=h.session_cookies(t_admin))
    run.req("organization/has-permission", "POST", f"{A}/organization/has-permission", note="xor both", json_body={"permission": {}, "permissions": {}}, cookies=h.session_cookies(t_admin))
    run.req("organization/has-permission", "POST", f"{A}/organization/has-permission", note="outsider", json_body={"organizationId": org["id"], "permissions": {"member": ["create"]}}, cookies=h.session_cookies(t_out))
    run.req("organization/get-active-member", "GET", f"{A}/organization/get-active-member", cookies=h.session_cookies(t_admin))
    run.req("organization/get-active-member", "GET", f"{A}/organization/get-active-member", note="none active", cookies=h.session_cookies(t_member))


def sc_org_invitations(run):
    owner = run.user("iowner")
    admin = run.user("iadmin")
    member = run.user("imember")
    invitee = run.user("invitee")
    org = run.org("io", owner_id=owner["id"])
    elsewhere = run.org("elsewhere")
    h.add_member(org["id"], admin["id"], "admin")
    h.add_member(org["id"], member["id"], "member")
    site_a = add_site(org["id"], f"a-{run.tag}")
    site_b = add_site(org["id"], f"b-{run.tag}")
    foreign = add_site(elsewhere["id"], f"f-{run.tag}")
    run.symbols[site_a] = "<site:a>"; run.symbols[site_b] = "<site:b>"; run.symbols[foreign] = "<site:foreign>"; run.name(str(site_a), "site:a"); run.name(str(site_b), "site:b")
    t_owner = run.session("owner", owner["id"], active_org=org["id"])
    t_admin = run.session("admin", admin["id"])
    t_member = run.session("member", member["id"])
    t_invitee = run.session("invitee", invitee["id"])
    i = "organization/invite-member"
    rows = lambda label: run.db(i, label, INVITATION_ROWS, org["id"])
    run.req(i, "POST", f"{A}/organization/invite-member", note="restricted member", json_body={"email": invitee["email"].upper(), "role": "member", "organizationId": org["id"], "hasRestrictedSiteAccess": True, "siteIds": [site_a, site_a, site_b]}, cookies=h.session_cookies(t_admin))
    rows("after restricted")
    run.req(i, "POST", f"{A}/organization/invite-member", note="already invited", json_body={"email": invitee["email"], "role": "member", "organizationId": org["id"]}, cookies=h.session_cookies(t_admin))
    run.req(i, "POST", f"{A}/organization/invite-member", note="resend", json_body={"email": invitee["email"], "role": "member", "organizationId": org["id"], "resend": True}, cookies=h.session_cookies(t_owner))
    fresh = f"parity-auth-fresh-{run.tag}@example.com"
    run.name(fresh, "email:fresh")
    run.req(i, "POST", f"{A}/organization/invite-member", note="restricted admin role", json_body={"email": fresh, "role": "admin", "hasRestrictedSiteAccess": True, "siteIds": [site_a]}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="restricted no sites", json_body={"email": fresh, "role": "member", "hasRestrictedSiteAccess": True, "siteIds": []}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="foreign site", json_body={"email": fresh, "role": "member", "hasRestrictedSiteAccess": True, "siteIds": [site_a, foreign]}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="unknown role", json_body={"email": fresh, "role": "boss,member"}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="admin invites owner", json_body={"email": fresh, "role": "owner", "organizationId": org["id"]}, cookies=h.session_cookies(t_admin))
    run.req(i, "POST", f"{A}/organization/invite-member", note="member inviter", json_body={"email": fresh, "role": "member", "organizationId": org["id"]}, cookies=h.session_cookies(t_member))
    run.req(i, "POST", f"{A}/organization/invite-member", note="already member", json_body={"email": member["email"], "role": "member"}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="bad email", json_body={"email": "nope", "role": "member"}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="bad team", json_body={"email": fresh, "role": "member", "teamId": "parity-auth-noteam"}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="plain with roles array", json_body={"email": fresh, "role": ["member", "admin"]}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="validation", json_body={"email": fresh, "siteIds": ["x"]}, cookies=h.session_cookies(t_owner))
    run.req(i, "POST", f"{A}/organization/invite-member", note="no active org", json_body={"email": fresh, "role": "member"}, cookies=h.session_cookies(t_admin))
    rows("final")
    inv = h.q('SELECT id FROM invitation WHERE "organizationId" = %s AND email = %s', org["id"], invitee["email"].lower())[0]["id"]
    run.name(inv, "invitation:restricted")
    fresh_inv = h.q('SELECT id FROM invitation WHERE "organizationId" = %s AND email = %s', org["id"], fresh)
    if fresh_inv:
        run.name(fresh_inv[0]["id"], "invitation:fresh")
    l = "organization/list-invitations"
    run.req(l, "GET", f"{A}/organization/list-invitations?organizationId={org['id']}", cookies=h.session_cookies(t_member), unordered=[])
    run.req(l, "GET", f"{A}/organization/list-invitations", note="no org", cookies=h.session_cookies(t_member))
    run.req(l, "GET", f"{A}/organization/list-invitations?organizationId={org['id']}", note="outsider", cookies=h.session_cookies(t_invitee))
    gi = "organization/get-invitation"
    run.req(gi, "GET", f"{A}/organization/get-invitation?id={inv}", cookies=h.session_cookies(t_invitee))
    run.req(gi, "GET", f"{A}/organization/get-invitation?id={inv}", note="not recipient", cookies=h.session_cookies(t_member))
    run.req(gi, "GET", f"{A}/organization/get-invitation?id=nope", note="missing", cookies=h.session_cookies(t_member))
    run.req("organization/list-user-invitations", "GET", f"{A}/organization/list-user-invitations", cookies=h.session_cookies(t_invitee))
    run.req("organization/list-user-invitations", "GET", f"{A}/organization/list-user-invitations?email=x@y.z", note="email param", cookies=h.session_cookies(t_invitee))
    a = "organization/accept-invitation"
    run.req(a, "POST", f"{A}/organization/accept-invitation", note="not recipient", json_body={"invitationId": inv}, cookies=h.session_cookies(t_member))
    run.req(a, "POST", f"{A}/organization/accept-invitation", json_body={"invitationId": inv}, cookies=h.session_cookies(t_invitee))
    run.db(a, "members", MEMBER_ROWS, org["id"])
    run.db(a, "site grants", 'SELECT msa.site_id::text AS site FROM member_site_access msa JOIN member m ON m.id = msa.member_id WHERE m."userId" = %s ORDER BY msa.site_id', invitee["id"])
    run.db(a, "invitee session", SESSION_ROWS, invitee["id"])
    run.req(a, "POST", f"{A}/organization/accept-invitation", note="again", json_body={"invitationId": inv}, cookies=h.session_cookies(t_invitee))
    if fresh_inv:
        run.req("organization/cancel-invitation", "POST", f"{A}/organization/cancel-invitation", note="member cannot", json_body={"invitationId": fresh_inv[0]["id"]}, cookies=h.session_cookies(t_member))
        run.req("organization/cancel-invitation", "POST", f"{A}/organization/cancel-invitation", json_body={"invitationId": fresh_inv[0]["id"]}, cookies=h.session_cookies(t_admin))
    run.req("organization/cancel-invitation", "POST", f"{A}/organization/cancel-invitation", note="missing", json_body={"invitationId": "nope"}, cookies=h.session_cookies(t_admin))
    reject_user = run.user("rejecter")
    t_reject = run.session("rejecter", reject_user["id"])
    h.q("""INSERT INTO invitation (id, email, "inviterId", "organizationId", role, status, "createdAt", "expiresAt", has_restricted_site_access, site_ids)
           VALUES (%s, %s, %s, %s, 'member', 'pending', now(), (now() AT TIME ZONE 'utc') + interval '1 day', false, '[]')""", run.name(f"parity-auth-inv-{h.rand_id(6)}", "invitation:reject"), reject_user["email"], owner["id"], org["id"])
    run.req("organization/reject-invitation", "POST", f"{A}/organization/reject-invitation", json_body={"invitationId": run_symbol(run, "invitation:reject")}, cookies=h.session_cookies(t_reject))
    run.db("organization/reject-invitation", "rows", INVITATION_ROWS, org["id"])
    expired_user = run.user("expiredinv")
    t_expired = run.session("expiredinv", expired_user["id"])
    h.q("""INSERT INTO invitation (id, email, "inviterId", "organizationId", role, status, "createdAt", "expiresAt", has_restricted_site_access, site_ids)
           VALUES (%s, %s, %s, %s, 'member', 'pending', now(), (now() AT TIME ZONE 'utc') - interval '1 day', false, '[]')""", run.name(f"parity-auth-inv-{h.rand_id(6)}", "invitation:expired"), expired_user["email"], owner["id"], org["id"])
    run.req(a, "POST", f"{A}/organization/accept-invitation", note="expired", json_body={"invitationId": run_symbol(run, "invitation:expired")}, cookies=h.session_cookies(t_expired))


def run_symbol(run, symbol):
    for value, name in run.symbols.items():
        if name == f"<{symbol}>":
            return value
    return None


def sc_org_members(run):
    owner = run.user("mowner")
    owner2 = run.user("mowner2")
    admin = run.user("madmin")
    member = run.user("mmember")
    byemail = run.user("mbyemail")
    org = run.org("m", owner_id=owner["id"])
    mid_admin = h.add_member(org["id"], admin["id"], "admin")
    mid_member = h.add_member(org["id"], member["id"], "member")
    mid_email = h.add_member(org["id"], byemail["id"], "member")
    for mid, key in ((mid_admin, "admin"), (mid_member, "member"), (mid_email, "byemail")):
        run.name(mid, f"member:{key}")
    owner_mid = h.q('SELECT id FROM member WHERE "organizationId" = %s AND "userId" = %s', org["id"], owner["id"])[0]["id"]
    run.name(owner_mid, "member:owner")
    team = run.name(f"parity-auth-team-{h.rand_id(6)}", "team")
    h.q("INSERT INTO team (id, name, \"organizationId\", \"createdAt\") VALUES (%s, 'T', %s, now())", team, org["id"])
    h.q("INSERT INTO \"teamMember\" (id, \"teamId\", \"userId\", \"createdAt\") VALUES (%s, %s, %s, now())", f"parity-auth-tm-{h.rand_id(6)}", team, member["id"])
    h.q("""INSERT INTO invitation (id, email, "inviterId", "organizationId", role, status, "createdAt", "expiresAt", has_restricted_site_access, site_ids)
           VALUES (%s, %s, %s, %s, 'member', 'accepted', now(), now() + interval '1 day', false, '[]')""", f"parity-auth-inv-{h.rand_id(6)}", member["email"], owner["id"], org["id"])
    t_owner = run.session("owner", owner["id"], active_org=org["id"])
    t_admin = run.session("admin", admin["id"], active_org=org["id"])
    t_member = run.session("member", member["id"], active_org=org["id"])
    r = "organization/remove-member"
    run.req(r, "POST", f"{A}/organization/remove-member", note="member cannot", json_body={"memberIdOrEmail": mid_admin, "organizationId": org["id"]}, cookies=h.session_cookies(t_member))
    run.req(r, "POST", f"{A}/organization/remove-member", note="admin removes owner", json_body={"memberIdOrEmail": owner["email"], "organizationId": org["id"]}, cookies=h.session_cookies(t_admin))
    run.req(r, "POST", f"{A}/organization/remove-member", note="last owner", json_body={"memberIdOrEmail": owner_mid}, cookies=h.session_cookies(t_owner))
    run.req(r, "POST", f"{A}/organization/remove-member", note="by id", json_body={"memberIdOrEmail": mid_member}, cookies=h.session_cookies(t_admin))
    run.db(r, "member gone + invitation purged + team", 'SELECT (SELECT count(*) FROM member WHERE id = %s) AS member, (SELECT count(*) FROM invitation WHERE email = %s) AS invitations, (SELECT count(*) FROM "teamMember" WHERE "userId" = %s) AS teams', mid_member, member["email"], member["id"])
    run.req(r, "POST", f"{A}/organization/remove-member", note="by email", json_body={"memberIdOrEmail": byemail["email"].upper()}, cookies=h.session_cookies(t_owner))
    run.req(r, "POST", f"{A}/organization/remove-member", note="missing", json_body={"memberIdOrEmail": "nobody@example.com"}, cookies=h.session_cookies(t_owner))
    u = "organization/update-member-role"
    run.req(u, "POST", f"{A}/organization/update-member-role", note="admin to member", json_body={"memberId": mid_admin, "role": "member"}, cookies=h.session_cookies(t_owner))
    run.req(u, "POST", f"{A}/organization/update-member-role", note="unknown role", json_body={"memberId": mid_admin, "role": ["member", "chief"]}, cookies=h.session_cookies(t_owner))
    run.req(u, "POST", f"{A}/organization/update-member-role", note="empty role", json_body={"memberId": mid_admin, "role": ""}, cookies=h.session_cookies(t_owner))
    run.req(u, "POST", f"{A}/organization/update-member-role", note="owner demotes self alone", json_body={"memberId": owner_mid, "role": "admin"}, cookies=h.session_cookies(t_owner))
    run.req(u, "POST", f"{A}/organization/update-member-role", note="admin cannot set owner", json_body={"memberId": mid_admin, "role": "owner", "organizationId": org["id"]}, cookies=h.session_cookies(t_admin))
    run.req(u, "POST", f"{A}/organization/update-member-role", note="member missing", json_body={"memberId": "nope", "role": "admin"}, cookies=h.session_cookies(t_owner))
    run.db(u, "members", MEMBER_ROWS, org["id"])
    h.add_member(org["id"], owner2["id"], "owner")
    t_owner2 = run.session("owner2", owner2["id"], active_org=org["id"])
    lv = "organization/leave"
    h.q("""INSERT INTO invitation (id, email, "inviterId", "organizationId", role, status, "createdAt", "expiresAt", has_restricted_site_access, site_ids)
           VALUES (%s, %s, %s, %s, 'owner', 'accepted', now(), now() + interval '1 day', false, '[]')""", f"parity-auth-inv-{h.rand_id(6)}", owner2["email"], owner["id"], org["id"])
    run.req(lv, "POST", f"{A}/organization/leave", json_body={"organizationId": org["id"]}, cookies=h.session_cookies(t_owner2))
    run.db(lv, "left", 'SELECT (SELECT count(*) FROM member WHERE "userId" = %s) AS member, (SELECT count(*) FROM invitation WHERE email = %s) AS invitations, (SELECT "activeOrganizationId" FROM session WHERE token = %s) AS active', owner2["id"], owner2["email"], t_owner2)
    run.req(lv, "POST", f"{A}/organization/leave", note="only owner", json_body={"organizationId": org["id"]}, cookies=h.session_cookies(t_owner))
    run.req(lv, "POST", f"{A}/organization/leave", note="not member", json_body={"organizationId": org["id"]}, cookies=h.session_cookies(t_owner2))
    d = "organization/delete"
    h.q("""INSERT INTO apikey (id, key, "referenceId", enabled, "rateLimitEnabled", "requestCount", "createdAt", "updatedAt", "configId")
           VALUES (%s, %s, %s, true, false, 0, now(), now(), 'org')""", f"parity-auth-key-{h.rand_id(8)}", h.rand_id(43), org["id"])
    run.req(d, "POST", f"{A}/organization/delete", note="admin cannot", json_body={"organizationId": org["id"]}, cookies=h.session_cookies(t_admin))
    run.req(d, "POST", f"{A}/organization/delete", json_body={"organizationId": org["id"]}, cookies=h.session_cookies(t_owner))
    run.db(d, "gone", 'SELECT (SELECT count(*) FROM organization WHERE id = %s) AS orgs, (SELECT count(*) FROM member WHERE "organizationId" = %s) AS members, (SELECT count(*) FROM apikey WHERE "referenceId" = %s) AS keys, (SELECT count(*) FROM team WHERE "organizationId" = %s) AS teams', org["id"], org["id"], org["id"], org["id"])
    run.db(d, "sessions", 'SELECT "activeOrganizationId" FROM session WHERE token IN (%s, %s) ORDER BY token = %s', t_owner, t_admin, t_owner)
    run.req(d, "POST", f"{A}/organization/delete", note="again", json_body={"organizationId": org["id"]}, cookies=h.session_cookies(t_owner))
    with_site = run.org("withsite", owner_id=owner["id"])
    add_site(with_site["id"], f"s-{run.tag}")
    run.req(d, "POST", f"{A}/organization/delete", note="org with sites (FK)", json_body={"organizationId": with_site["id"]}, cookies=h.session_cookies(t_owner))


SCENARIOS = [sc_org_create, sc_org_read_update, sc_org_invitations, sc_org_members]
