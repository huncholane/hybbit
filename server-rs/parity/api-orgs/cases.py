"""Every request pair the api-orgs harness sends.

A case is {route, method, path, headers, body, write, prep, who}. `write` makes the
runner reset the fixtures before each backend and compare the resulting rows;
`prep` names an extra fixture step to run after the reset.
"""
import base64
import hashlib
import hmac
import json
import time

import hw

C = json.load(open(hw.OUT + "/creds.json"))
S, K, O, U, M, T, SITES = (
    C["sessions"],
    C["keys"],
    C["orgs"],
    C["users"],
    C["members"],
    C["teams"],
    C["sites"],
)
SECRET = "parity-local-secret-not-for-production"
KB_ORG = "kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE"  # an organization from the snapshot, nobody here belongs to


def sign(payload):
    return base64.urlsafe_b64encode(hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).digest()).decode().rstrip("=")


# --------------------------------------------------------------------------
# Principals

SESSION_USERS = ["ownerA", "adminA", "memberA1", "memberA2", "restrictedA", "ownerB", "nobody", "sysadmin"]
# Snapshot principals, used for reads against organizations that carry real sites,
# members, teams and ClickHouse events
SNAPSHOT_SESSIONS = ["huncho", "justin", "adminHygo"]
KEY_NAMES = [
    "orgA",
    "orgA_orgread",
    "orgA_orgwrite",
    "orgA_siteswrite",
    "orgA_none",
    "orgB",
    "ownerA",
    "ownerA_orgread",
    "ownerA_orgwrite",
    "ownerA_siteswrite",
    "ownerA_none",
    "adminA",
    "memberA1",
    "memberA1_orgread",
    "restrictedA",
    "ownerB",
    "nobody",
    "sysadmin",
    "ownerA_disabled",
    "ownerA_expired",
    "orgKb",
    "orgKb_orgread",
    "huncho",
    "justin",
]


def principals():
    """name -> header list. Covers cookies, bearers, the query form, a bearer next
    to a cookie, and no credential at all."""
    out = {"anon": []}
    for name in SESSION_USERS + SNAPSHOT_SESSIONS:
        out["cookie:" + name] = [("Cookie", S[name])]
    for name in KEY_NAMES:
        out["bearer:" + name] = [("Authorization", "Bearer " + K[name])]
    out["bearer:bogus"] = [("Authorization", "Bearer not-a-real-key")]
    out["bearer:empty"] = [("Authorization", "Bearer ")]
    out["bearer:basic"] = [("Authorization", "Basic " + K["ownerA"])]
    out["cookie:bad"] = [("Cookie", "__Secure-better-auth.session_token=potokownerA.tampered")]
    out["cookie+bearer"] = [("Cookie", S["memberA1"]), ("Authorization", "Bearer " + K["orgA"])]
    out["sysadmin+bearer"] = [("Cookie", S["sysadmin"]), ("Authorization", "Bearer " + K["nobody"])]
    return out


P = principals()
# A smaller set for the dimensions that do not need every principal
CORE = [
    "anon",
    "cookie:ownerA",
    "cookie:adminA",
    "cookie:memberA1",
    "cookie:restrictedA",
    "cookie:ownerB",
    "cookie:sysadmin",
    "bearer:orgA",
    "bearer:orgA_orgread",
    "bearer:orgA_none",
    "bearer:ownerA",
    "bearer:ownerA_orgread",
    "bearer:ownerA_none",
    "bearer:memberA1",
    "bearer:ownerB",
    "bearer:bogus",
]

ORG_IDS = {
    "A": O["A"],
    "B": O["B"],
    "kb": KB_ORG,
    "unknown": "parity-orgs-missing",
    "empty": "",
    "encoded": "parity-orgs-org%2FA",
    "spaces": "parity%20orgs",
    "numeric": "12345",
    "long": "x" * 1600,
    "unicode": "%E2%9C%93",
    "bad-escape": "a%zz",
}


def case(route, method, path, who, body=None, write=False, prep=None, extra_headers=()):
    headers = list(P[who]) + list(extra_headers)
    if body is not None and not any(name.lower() == "content-type" for name, _ in headers):
        headers.append(("Content-Type", "application/json"))
    return {
        "route": route,
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
        "write": write,
        "prep": prep,
        "who": who,
    }


def js(value):
    return json.dumps(value).encode()


# --------------------------------------------------------------------------
# GET /api/organizations and GET /api/user/organizations


def organization_listings():
    out = []
    for who in P:
        out.append(case("GET /organizations", "GET", "/api/organizations", who))
        out.append(case("GET /user/organizations", "GET", "/api/user/organizations", who))
    for method in ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
        out.append(case("GET /organizations", method, "/api/organizations", "cookie:ownerA"))
        out.append(case("GET /user/organizations", method, "/api/user/organizations", "cookie:ownerA"))
    # The query string is parsed before the handler on every route
    for query in ["?api_key=" + K["ownerA"], "?api_key=x&api_key=y", "?startDate=nope&endDate=2026-01-01", "?"]:
        out.append(case("GET /organizations", "GET", "/api/organizations" + query, "anon"))
        out.append(case("GET /user/organizations", "GET", "/api/user/organizations" + query, "anon"))
        out.append(case("GET /user/organizations", "GET", "/api/user/organizations" + query, "cookie:ownerA"))
    return out


# --------------------------------------------------------------------------
# The org-scoped reads


def org_reads():
    out = []
    reads = [
        ("GET /organizations/:id/sites", "sites"),
        ("GET /organizations/:id/members", "members"),
        ("GET /organizations/:id/teams", "teams"),
        ("GET /organizations/:id/excluded-ips", "excluded-ips"),
        ("GET /organizations/:id/api-usage", "api-usage"),
    ]
    for route, suffix in reads:
        for who in P:
            out.append(case(route, "GET", f"/api/organizations/{O['A']}/{suffix}", who))
        for label, org in ORG_IDS.items():
            if label == "A":
                continue
            for who in CORE:
                out.append(case(route, "GET", f"/api/organizations/{org}/{suffix}", who))
        for method in ["POST", "PUT", "DELETE", "PATCH"]:
            if (route.endswith("sites") and method == "POST") or (route.endswith("excluded-ips") and method == "PUT"):
                continue
            out.append(case(route, method, f"/api/organizations/{O['A']}/{suffix}", "cookie:ownerA"))
        out.append(case(route, "GET", f"/api/organizations/{O['A']}/{suffix}/", "cookie:ownerA"))
        out.append(case(route, "GET", f"/api/organizations/{O['A']}/{suffix}/extra", "cookie:ownerA"))
        out.append(case(route, "GET", f"/api/organizations/{O['A']}/{suffix}?startDate=nope", "cookie:ownerA"))
        out.append(
            case(route, "GET", f"/api/organizations/{O['A']}/{suffix}?api_key=" + K["orgA"], "anon")
        )
        out.append(case(route, "GET", f"/api/organizations/{O['A']}/{suffix}?api_key=" + K["orgA_none"], "anon"))
    # Teams for a team member and a non-member, which changes the filtered list
    for who in ["cookie:memberA1", "cookie:memberA2", "cookie:restrictedA", "bearer:memberA1", "bearer:orgA"]:
        out.append(case("GET /organizations/:id/teams", "GET", f"/api/organizations/{O['A']}/teams", who))
        out.append(case("GET /organizations/:id/teams", "GET", f"/api/organizations/{O['B']}/teams", who))
    return out


# --------------------------------------------------------------------------
# PUT /organizations/:id/excluded-ips

EXCLUDED_IP_BODIES = [
    None,
    b"",
    b"null",
    b"[]",
    b'"text"',
    b"5",
    b"{}",
    js({"excludedIPs": []}),
    js({"excludedIPs": ["1.2.3.4"]}),
    js({"excludedIPs": ["  1.2.3.4  "]}),
    js({"excludedIPs": ["1.2.3.4", "10.0.0.0/8", "10.0.0.1-10.0.0.9"]}),
    js({"excludedIPs": ["2001:db8::/32"]}),
    js({"excludedIPs": ["2001:db8::1-2001:db8::9"]}),
    js({"excludedIPs": ["nope"]}),
    js({"excludedIPs": ["1.2.3.4", "nope", "also-nope"]}),
    js({"excludedIPs": [""]}),
    js({"excludedIPs": ["   "]}),
    js({"excludedIPs": [1]}),
    js({"excludedIPs": [None]}),
    js({"excludedIPs": [True]}),
    js({"excludedIPs": [["1.2.3.4"]]}),
    js({"excludedIPs": [{"ip": "1.2.3.4"}]}),
    js({"excludedIPs": "1.2.3.4"}),
    js({"excludedIPs": None}),
    js({"excludedIPs": ["1.2.3.4"] * 100}),
    js({"excludedIPs": ["1.2.3.4"] * 101}),
    js({"excludedIPs": ["1.2.3.4"], "extra": 1}),
    js({"excludedIPs": ["1.2.3.4/"]}),
    js({"excludedIPs": ["-"]}),
    js({"excludedIPs": ["1.2.3.4-"]}),
    b'{"excludedIPs":["\\ud800"]}',
    b'{"excludedIPs": ',
]


def excluded_ip_writes():
    out = []
    for body in EXCLUDED_IP_BODIES:
        out.append(case("PUT /organizations/:id/excluded-ips", "PUT", f"/api/organizations/{O['A']}/excluded-ips", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(
            case(
                "PUT /organizations/:id/excluded-ips",
                "PUT",
                f"/api/organizations/{O['A']}/excluded-ips",
                who,
                js({"excludedIPs": ["9.9.9.9"]}),
                write=True,
            )
        )
    for label, org in ORG_IDS.items():
        if label == "A":
            continue
        out.append(
            case(
                "PUT /organizations/:id/excluded-ips",
                "PUT",
                f"/api/organizations/{org}/excluded-ips",
                "cookie:ownerA",
                js({"excludedIPs": ["9.9.9.9"]}),
                write=True,
            )
        )
    out.append(
        case(
            "PUT /organizations/:id/excluded-ips",
            "PUT",
            f"/api/organizations/{O['A']}/excluded-ips",
            "cookie:ownerA",
            b"not json",
            write=True,
            extra_headers=[("Content-Type", "text/plain")],
        )
    )
    return out


# --------------------------------------------------------------------------
# Teams

TEAM_CREATE_BODIES = [
    None,
    b"",
    b"null",
    b'"text"',
    b"5",
    b"[]",
    b"{}",
    js({"name": "Team"}),
    js({"name": "  Team  "}),
    js({"name": ""}),
    js({"name": "   "}),
    js({"name": None}),
    js({"name": 5}),
    js({"name": True}),
    js({"name": []}),
    js({"name": {}}),
    js({"name": "Team", "memberUserIds": []}),
    js({"name": "Team", "memberUserIds": [U["memberA1"]]}),
    js({"name": "Team", "memberUserIds": [U["memberA1"], U["memberA2"]]}),
    js({"name": "Team", "memberUserIds": [U["ownerB"]]}),
    js({"name": "Team", "memberUserIds": [U["memberA1"], U["ownerB"], "missing"]}),
    js({"name": "Team", "memberUserIds": None}),
    js({"name": "Team", "memberUserIds": "abc"}),
    js({"name": "Team", "memberUserIds": 0}),
    js({"name": "Team", "memberUserIds": False}),
    js({"name": "Team", "memberUserIds": {}}),
    js({"name": "Team", "memberUserIds": [1]}),
    js({"name": "Team", "memberUserIds": [None]}),
    js({"name": "Team", "memberUserIds": [True]}),
    js({"name": "Team", "siteIds": []}),
    js({"name": "Team", "siteIds": [SITES["A1"]]}),
    js({"name": "Team", "siteIds": [SITES["A1"], SITES["A2"]]}),
    js({"name": "Team", "siteIds": [SITES["B1"]]}),
    js({"name": "Team", "siteIds": [SITES["A1"], SITES["B1"], 999999]}),
    js({"name": "Team", "siteIds": ["65300"]}),
    js({"name": "Team", "siteIds": [1.5]}),
    js({"name": "Team", "siteIds": [2**40]}),
    js({"name": "Team", "siteIds": [None]}),
    js({"name": "Team", "siteIds": [True]}),
    js({"name": "Team", "siteIds": "abc"}),
    js({"name": "Team", "siteIds": None}),
    js({"name": "Team", "memberUserIds": [U["memberA1"]], "siteIds": [SITES["A1"]]}),
    js({"name": "Team", "memberUserIds": [U["memberA1"], U["memberA1"]], "siteIds": [SITES["A1"], SITES["A1"]]}),
    js({"name": "Parity teamA1"}),
]

TEAM_UPDATE_BODIES = [
    None,
    b"null",
    b"{}",
    js({"name": "Renamed"}),
    js({"name": "  Renamed  "}),
    js({"name": ""}),
    js({"name": None}),
    js({"name": 5}),
    js({"memberUserIds": []}),
    js({"memberUserIds": [U["memberA2"]]}),
    js({"memberUserIds": [U["ownerB"]]}),
    js({"memberUserIds": None}),
    js({"memberUserIds": ""}),
    js({"memberUserIds": 0}),
    js({"memberUserIds": {}}),
    js({"siteIds": []}),
    js({"siteIds": [SITES["A2"]]}),
    js({"siteIds": [SITES["B1"]]}),
    js({"siteIds": None}),
    js({"siteIds": "x"}),
    js({"name": "Renamed", "memberUserIds": [U["memberA2"]], "siteIds": [SITES["A2"]]}),
]


def team_writes():
    out = []
    for body in TEAM_CREATE_BODIES:
        out.append(case("POST /organizations/:id/teams", "POST", f"/api/organizations/{O['A']}/teams", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(case("POST /organizations/:id/teams", "POST", f"/api/organizations/{O['A']}/teams", who, js({"name": "Team"}), write=True))
    for label, org in ORG_IDS.items():
        if label == "A":
            continue
        out.append(case("POST /organizations/:id/teams", "POST", f"/api/organizations/{org}/teams", "cookie:ownerA", js({"name": "Team"}), write=True))

    for body in TEAM_UPDATE_BODIES:
        out.append(case("PUT /organizations/:id/teams/:teamId", "PUT", f"/api/organizations/{O['A']}/teams/{T['teamA1']}", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(case("PUT /organizations/:id/teams/:teamId", "PUT", f"/api/organizations/{O['A']}/teams/{T['teamA1']}", who, js({"name": "Renamed"}), write=True))
    for team in [T["teamB1"], "missing", "", "a" * 1600, "%2F", "team%20a1"]:
        out.append(case("PUT /organizations/:id/teams/:teamId", "PUT", f"/api/organizations/{O['A']}/teams/{team}", "cookie:ownerA", js({"name": "Renamed"}), write=True))
        out.append(case("DELETE /organizations/:id/teams/:teamId", "DELETE", f"/api/organizations/{O['A']}/teams/{team}", "cookie:ownerA", None, write=True))
    for who in P:
        out.append(case("DELETE /organizations/:id/teams/:teamId", "DELETE", f"/api/organizations/{O['A']}/teams/{T['teamA1']}", who, None, write=True))
    for label, org in ORG_IDS.items():
        if label == "A":
            continue
        out.append(case("DELETE /organizations/:id/teams/:teamId", "DELETE", f"/api/organizations/{org}/teams/{T['teamA1']}", "cookie:ownerA", None, write=True))
    out.append(case("DELETE /organizations/:id/teams/:teamId", "DELETE", f"/api/organizations/{O['A']}/teams/{T['teamA2']}", "cookie:ownerA", None, write=True))
    return out


# --------------------------------------------------------------------------
# Members

ADD_MEMBER_BODIES = [
    None,
    b"null",
    b"{}",
    b'"text"',
    b"[]",
    js({"email": f"target@{hw.P}test", "role": "member"}),
    js({"email": f"target@{hw.P}test", "role": "admin"}),
    js({"email": f"target@{hw.P}test", "role": "owner"}),
    js({"email": f"target@{hw.P}test", "role": "viewer"}),
    js({"email": f"target@{hw.P}test", "role": ""}),
    js({"email": f"target@{hw.P}test", "role": None}),
    js({"email": f"target@{hw.P}test", "role": 5}),
    js({"email": f"target@{hw.P}test"}),
    js({"role": "member"}),
    js({"email": "", "role": "member"}),
    js({"email": None, "role": "member"}),
    js({"email": 5, "role": "member"}),
    js({"email": True, "role": "member"}),
    js({"email": ["a"], "role": "member"}),
    js({"email": f"TARGET@{hw.P}test", "role": "member"}),
    js({"email": f"ownerA@{hw.P}test", "role": "member"}),
    js({"email": f"missing@{hw.P}test", "role": "member"}),
]

CREATE_USER_BODIES = [
    None,
    b"null",
    b"{}",
    js({"email": f"new@{hw.P}test", "password": "password123", "role": "member"}),
    js({"email": f"NEW@{hw.P}test", "password": "password123", "role": "member"}),
    js({"email": f"new@{hw.P}test", "name": "New Person", "password": "password123", "role": "admin"}),
    js({"email": f"new@{hw.P}test", "password": "password123", "role": "owner"}),
    js({"email": f"new@{hw.P}test", "password": "password123", "role": "nope"}),
    js({"email": f"new@{hw.P}test", "password": "short", "role": "member"}),
    js({"email": f"new@{hw.P}test", "password": "", "role": "member"}),
    js({"email": f"new@{hw.P}test", "password": 12345678, "role": "member"}),
    js({"email": f"new@{hw.P}test", "password": True, "role": "member"}),
    js({"email": f"new@{hw.P}test", "password": "password123"}),
    js({"password": "password123", "role": "member"}),
    js({"email": f"ownerA@{hw.P}test", "password": "password123", "role": "member"}),
    js({"email": 5, "password": "password123", "role": "member"}),
    js({"email": f"new@{hw.P}test", "name": "", "password": "password123", "role": "member"}),
    js({"email": f"new@{hw.P}test", "name": 5, "password": "password123", "role": "member"}),
    js({"email": f"  spaced@{hw.P}test  ", "password": "password123", "role": "member"}),
]

SITE_ACCESS_BODIES = [
    None,
    b"null",
    b"{}",
    js({"hasRestrictedSiteAccess": True, "siteIds": [SITES["A1"]]}),
    js({"hasRestrictedSiteAccess": True, "siteIds": [SITES["A1"], SITES["A2"]]}),
    js({"hasRestrictedSiteAccess": True, "siteIds": []}),
    js({"hasRestrictedSiteAccess": False, "siteIds": [SITES["A1"]]}),
    js({"hasRestrictedSiteAccess": False, "siteIds": []}),
    js({"hasRestrictedSiteAccess": True, "siteIds": [SITES["B1"]]}),
    js({"hasRestrictedSiteAccess": True, "siteIds": [SITES["A1"], SITES["B1"], 999999]}),
    js({"hasRestrictedSiteAccess": True, "siteIds": None}),
    js({"hasRestrictedSiteAccess": True}),
    js({"siteIds": [SITES["A1"]]}),
    js({"hasRestrictedSiteAccess": "yes", "siteIds": []}),
    js({"hasRestrictedSiteAccess": 1, "siteIds": []}),
    js({"hasRestrictedSiteAccess": None, "siteIds": []}),
    js({"hasRestrictedSiteAccess": True, "siteIds": ["65300"]}),
    js({"hasRestrictedSiteAccess": True, "siteIds": [1.5]}),
    js({"hasRestrictedSiteAccess": True, "siteIds": [None]}),
    js({"hasRestrictedSiteAccess": True, "siteIds": [True]}),
    js({"hasRestrictedSiteAccess": True, "siteIds": "x"}),
    js({"hasRestrictedSiteAccess": True, "siteIds": [SITES["A1"], SITES["A1"]]}),
]


def member_writes():
    out = []
    for body in ADD_MEMBER_BODIES:
        out.append(case("POST /organizations/:id/members", "POST", f"/api/organizations/{O['A']}/members", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(case("POST /organizations/:id/members", "POST", f"/api/organizations/{O['A']}/members", who, js({"email": f"target@{hw.P}test", "role": "member"}), write=True))
        out.append(case("POST /organizations/:id/members", "POST", f"/api/organizations/{O['A']}/members", who, js({"email": f"target@{hw.P}test", "role": "owner"}), write=True))
    for label, org in ORG_IDS.items():
        if label == "A":
            continue
        out.append(case("POST /organizations/:id/members", "POST", f"/api/organizations/{org}/members", "cookie:ownerA", js({"email": f"target@{hw.P}test", "role": "member"}), write=True))

    for body in CREATE_USER_BODIES:
        out.append(case("POST /organizations/:id/users", "POST", f"/api/organizations/{O['A']}/users", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(case("POST /organizations/:id/users", "POST", f"/api/organizations/{O['A']}/users", who, js({"email": f"new@{hw.P}test", "password": "password123", "role": "member"}), write=True))
    for label, org in ORG_IDS.items():
        if label == "A":
            continue
        out.append(case("POST /organizations/:id/users", "POST", f"/api/organizations/{org}/users", "cookie:ownerA", js({"email": f"new@{hw.P}test", "password": "password123", "role": "member"}), write=True))

    for body in SITE_ACCESS_BODIES:
        out.append(case("PUT /organizations/:id/members/:memberId/sites", "PUT", f"/api/organizations/{O['A']}/members/{M['memberA1']}/sites", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(case("PUT /organizations/:id/members/:memberId/sites", "PUT", f"/api/organizations/{O['A']}/members/{M['memberA1']}/sites", who, js({"hasRestrictedSiteAccess": True, "siteIds": [SITES["A1"]]}), write=True))
    for member in [M["ownerA"], M["adminA"], M["restrictedA"], M["ownerB"], "missing", "", "a" * 1600]:
        out.append(case("PUT /organizations/:id/members/:memberId/sites", "PUT", f"/api/organizations/{O['A']}/members/{member}/sites", "cookie:ownerA", js({"hasRestrictedSiteAccess": True, "siteIds": [SITES["A1"]]}), write=True))
    for label, org in ORG_IDS.items():
        if label == "A":
            continue
        out.append(case("PUT /organizations/:id/members/:memberId/sites", "PUT", f"/api/organizations/{org}/members/{M['memberA1']}/sites", "cookie:ownerA", js({"hasRestrictedSiteAccess": True, "siteIds": [SITES["A1"]]}), write=True))
    return out


# --------------------------------------------------------------------------
# POST /organizations/:id/sites

ADD_SITE_BODIES = [
    None,
    b"null",
    b"{}",
    b'"text"',
    b"[]",
    js({"name": "Site", "domain": "new.parity-orgs.test"}),
    js({"name": "Site", "domain": "https://new.parity-orgs.test"}),
    js({"name": "Site", "domain": "http://new.parity-orgs.test///"}),
    js({"name": "Site", "domain": "NEW.PARITY-ORGS.TEST"}),
    js({"name": "Site", "domain": "bücher.example"}),
    js({"name": "Site", "domain": "xn--bcher-kva.example"}),
    js({"name": "Site", "domain": "a.b.c.example.com"}),
    js({"name": "Site", "domain": "nope"}),
    js({"name": "Site", "domain": ""}),
    js({"name": "Site", "domain": "-bad.example.com"}),
    js({"name": "Site", "domain": "bad-.example.com"}),
    js({"name": "Site", "domain": "example.c"}),
    js({"name": "Site", "domain": "example.com/path"}),
    js({"name": "Site", "domain": "192.168.0.1"}),
    js({"name": "Site", "domain": 5}),
    js({"name": "Site", "domain": None}),
    js({"name": "Site"}),
    js({"domain": "new.parity-orgs.test"}),
    js({"name": None, "domain": "new.parity-orgs.test"}),
    js({"name": 5, "domain": "new.parity-orgs.test"}),
    js({"name": "Site", "domain": "com.example.app", "type": "mobile"}),
    js({"name": "Site", "domain": "not a bundle", "type": "mobile"}),
    js({"name": "Site", "domain": "com.example.app", "type": "mobile", "sessionReplay": True}),
    js({"name": "Site", "domain": "com.example.app", "type": "mobile", "webVitals": True}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "type": "web"}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "type": "desktop"}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "public": True, "saltUserIds": True, "blockBots": False}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "public": "yes"}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "public": 1}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "public": None}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "excludedIPs": ["1.2.3.4"], "tags": ["a"]}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "excludedIPs": "x"}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "excludedCountries": ["US"]}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "trackErrors": True, "webVitals": True, "sessionReplay": True}),
    js({"name": "Site", "domain": "new.parity-orgs.test", "unknownField": 1}),
    js({"name": "Site", "domain": "a1.parity-orgs.test"}),
]


def site_writes():
    out = []
    for body in ADD_SITE_BODIES:
        out.append(case("POST /organizations/:id/sites", "POST", f"/api/organizations/{O['A']}/sites", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(case("POST /organizations/:id/sites", "POST", f"/api/organizations/{O['A']}/sites", who, js({"name": "Site", "domain": "new.parity-orgs.test"}), write=True))
    for label, org in ORG_IDS.items():
        if label == "A":
            continue
        out.append(case("POST /organizations/:id/sites", "POST", f"/api/organizations/{org}/sites", "cookie:ownerA", js({"name": "Site", "domain": "new.parity-orgs.test"}), write=True))
    return out


# --------------------------------------------------------------------------
# Account settings and unsubscribe

ACCOUNT_BODIES = [
    None,
    b"",
    b"null",
    b"{}",
    b'"text"',
    b"5",
    b"[]",
    b"[1]",
    js({"sendAutoEmailReports": True}),
    js({"sendAutoEmailReports": False}),
    js({"sendAutoEmailReports": "yes"}),
    js({"sendAutoEmailReports": 1}),
    js({"sendAutoEmailReports": None}),
    js({"sendAutoEmailReports": []}),
    js({"sendAutoEmailReports": {}}),
    js({"other": 1}),
    js({"sendAutoEmailReports": True, "other": 1}),
    b'{"sendAutoEmailReports": ',
]


def account_writes():
    out = []
    for body in ACCOUNT_BODIES:
        out.append(case("POST /user/account-settings", "POST", "/api/user/account-settings", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(case("POST /user/account-settings", "POST", "/api/user/account-settings", who, js({"sendAutoEmailReports": False}), write=True))
        out.append(case("POST /user/unsubscribe-marketing", "POST", "/api/user/unsubscribe-marketing", who, None, write=True))
    for method in ["GET", "PUT", "DELETE", "PATCH"]:
        out.append(case("POST /user/account-settings", method, "/api/user/account-settings", "cookie:ownerA"))
        out.append(case("POST /user/unsubscribe-marketing", method, "/api/user/unsubscribe-marketing", "cookie:ownerA"))
    return out


def unsubscribe_links():
    """Valid, expired, tampered and missing signatures on the one-click link."""
    out = []
    email = f"ownerA@{hw.P}test"
    future = int(time.time()) + 3600
    past = int(time.time()) - 3600
    good = sign(f"unsubscribe:{email}:{future}")
    stale = sign(f"unsubscribe:{email}:{past}")
    variants = [
        "",
        f"?email={email}",
        f"?email={email}&exp={future}&sig={good}",
        f"?email={email}&exp={past}&sig={stale}",
        f"?email={email}&exp={future}&sig={good}x",
        f"?email={email}&exp={future}&sig=",
        f"?email={email}&exp={future}",
        f"?email={email}&sig={good}",
        f"?email={email}&exp=nonsense&sig={good}",
        f"?email={email}&exp={future}.9&sig={good}",
        f"?email={email}&exp=1e20&sig={good}",
        f"?email=other@{hw.P}test&exp={future}&sig={good}",
        f"?email=&exp={future}&sig={good}",
        f"?email=missing@{hw.P}test",
        f"?email={email}&email=second@{hw.P}test",
        f"?email={email}&sig={good}&sig={good}",
        "?email=%E2%9C%93",
        f"?EMAIL={email}",
    ]
    for query in variants:
        for method in ["GET", "POST"]:
            out.append(
                case(
                    "GET|POST /user/unsubscribe-marketing-oneclick",
                    method,
                    "/api/user/unsubscribe-marketing-oneclick" + query,
                    "anon",
                    b"" if method == "POST" else None,
                    write=True,
                )
            )
    for method in ["PUT", "DELETE", "PATCH"]:
        out.append(case("GET|POST /user/unsubscribe-marketing-oneclick", method, "/api/user/unsubscribe-marketing-oneclick", "anon"))
    # A signed link still works for a signed-in caller and for a bearer
    for who in ["cookie:ownerA", "bearer:ownerA"]:
        out.append(case("GET|POST /user/unsubscribe-marketing-oneclick", "GET", f"/api/user/unsubscribe-marketing-oneclick?email={email}&exp={future}&sig={good}", who, None, write=True))
    return out


# --------------------------------------------------------------------------
# API keys

API_KEY_BODIES = [
    None,
    b"null",
    b"{}",
    b'"text"',
    js({"name": "Key"}),
    js({"name": "  Key  "}),
    js({"name": ""}),
    js({"name": "   "}),
    js({"name": None}),
    js({"name": 5}),
    js({"name": "x" * 32}),
    js({"name": "x" * 33}),
    js({"name": "Key", "expiresIn": 86400}),
    js({"name": "Key", "expiresIn": 86399}),
    js({"name": "Key", "expiresIn": 365 * 86400}),
    js({"name": "Key", "expiresIn": 365 * 86400 + 1}),
    js({"name": "Key", "expiresIn": 0}),
    js({"name": "Key", "expiresIn": -1}),
    js({"name": "Key", "expiresIn": 1.5}),
    js({"name": "Key", "expiresIn": "86400"}),
    js({"name": "Key", "expiresIn": None}),
    js({"name": "Key", "permissions": {}}),
    js({"name": "Key", "permissions": {"org": ["read"]}}),
    js({"name": "Key", "permissions": {"org": ["read", "write"], "sites": ["read"]}}),
    js({"name": "Key", "permissions": {"org": []}}),
    js({"name": "Key", "permissions": {"nope": ["read"]}}),
    js({"name": "Key", "permissions": {"sql": ["write"]}}),
    js({"name": "Key", "permissions": {"org": "read"}}),
    js({"name": "Key", "permissions": {"org": [1]}}),
    js({"name": "Key", "permissions": {"org": [None]}}),
    js({"name": "Key", "permissions": []}),
    js({"name": "Key", "permissions": "org:read"}),
    js({"name": "Key", "permissions": None}),
    js({"name": "Key", "expiresIn": 86400, "permissions": {"org": ["read"]}}),
    js({"name": "Key", "prefix": "zz_"}),
    js({"name": "Key", "userId": U["ownerB"]}),
    js({"name": "Key", "metadata": {"a": 1}}),
    js({"name": "Key", "remaining": 5}),
]


def api_key_writes():
    out = []
    for body in API_KEY_BODIES:
        out.append(case("POST /user/api-keys", "POST", "/api/user/api-keys", "cookie:ownerA", body, write=True))
        out.append(case("POST /organizations/:id/api-keys", "POST", f"/api/organizations/{O['A']}/api-keys", "cookie:ownerA", body, write=True))
    for who in P:
        out.append(case("POST /user/api-keys", "POST", "/api/user/api-keys", who, js({"name": "Key"}), write=True))
        out.append(case("POST /organizations/:id/api-keys", "POST", f"/api/organizations/{O['A']}/api-keys", who, js({"name": "Key"}), write=True))
    for label, org in ORG_IDS.items():
        if label == "A":
            continue
        out.append(case("POST /organizations/:id/api-keys", "POST", f"/api/organizations/{org}/api-keys", "cookie:ownerA", js({"name": "Key"}), write=True))
    # The creation cap: 50 usable keys already held by the owner
    out.append(case("POST /user/api-keys", "POST", "/api/user/api-keys", "cookie:ownerA", js({"name": "Key"}), write=True, prep="fill-user"))
    out.append(case("POST /organizations/:id/api-keys", "POST", f"/api/organizations/{O['A']}/api-keys", "cookie:ownerA", js({"name": "Key"}), write=True, prep="fill-org"))
    # One short of the cap still succeeds
    out.append(case("POST /user/api-keys", "POST", "/api/user/api-keys", "cookie:ownerA", js({"name": "Key"}), write=True, prep="fill-user-49"))
    out.append(case("POST /organizations/:id/api-keys", "POST", f"/api/organizations/{O['A']}/api-keys", "cookie:ownerA", js({"name": "Key"}), write=True, prep="fill-org-49"))
    for method in ["GET", "PUT", "DELETE", "PATCH"]:
        out.append(case("POST /user/api-keys", method, "/api/user/api-keys", "cookie:ownerA"))
        out.append(case("POST /organizations/:id/api-keys", method, f"/api/organizations/{O['A']}/api-keys", "cookie:ownerA"))
    return out


# --------------------------------------------------------------------------
# Paths that must not match, and bodies the framework rejects


def routing_cases():
    out = []
    paths = [
        "/api/organizations/",
        "/api/organizations//sites",
        "/api/organizations//teams",
        "/api/organizations//members",
        "/api/organizations//excluded-ips",
        "/api/organizations//api-usage",
        f"/api/organizations/{O['A']}/teams/",
        f"/api/organizations/{O['A']}/members//sites",
        f"/api/organizations/{O['A']}",
        f"/api/organizations/{O['A']}/unknown",
        "/api/user/",
        "/api/user/organizations/",
        "/api/user/api-keys/",
        "/api/user/unsubscribe-marketing-oneclick/",
        "/api/organizations/%2F/teams",
        "/api/organizations/a%zz/teams",
        "/api/organizations/" + "x" * 1501 + "/teams",
        "/api/organizations/" + "x" * 1500 + "/teams",
    ]
    for path in paths:
        for method in ["GET", "POST", "PUT", "DELETE"]:
            out.append(case("routing", method, path, "cookie:ownerA", b"{}" if method in ("POST", "PUT") else None))

    # Body parsing: the content types Fastify accepts and rejects
    bodies = [
        (b'{"name":"Team"}', "application/json"),
        (b'{"name":"Team"}', "application/json; charset=utf-8"),
        (b"plain text", "text/plain"),
        (b'{"name":"Team"}', "application/xml"),
        (b"", "application/json"),
        (b"   ", "application/json"),
        (b"{bad json}", "application/json"),
        (b'{"__proto__":{"x":1},"name":"Team"}', "application/json"),
        (b'{"name":"Team"}', None),
    ]
    for body, content_type in bodies:
        extra = [("Content-Type", content_type)] if content_type else []
        out.append(
            case(
                "body parsing",
                "POST",
                f"/api/organizations/{O['A']}/teams",
                "cookie:ownerA",
                body,
                write=True,
                extra_headers=extra,
            )
        )
    # CORS and the write-origin check
    for origin in ["https://a.hygo.ai", "https://evil.example", "http://localhost:3002", "not a url"]:
        out.append(case("cors", "GET", f"/api/organizations/{O['A']}/teams", "cookie:ownerA", None, extra_headers=[("Origin", origin)]))
        out.append(case("cors", "POST", f"/api/organizations/{O['A']}/teams", "cookie:ownerA", js({"name": "T"}), write=True, extra_headers=[("Origin", origin)]))
        out.append(case("cors", "OPTIONS", f"/api/organizations/{O['A']}/teams", "anon", None, extra_headers=[("Origin", origin), ("Access-Control-Request-Method", "POST")]))
    return out


def snapshot_reads():
    """The same reads against two organizations from the production snapshot, whose
    sites carry ClickHouse events: the only way to exercise the session-count query,
    the descending sort and a non-trivial member roster."""
    out = []
    readers = ["cookie:huncho", "cookie:justin", "cookie:adminHygo", "bearer:orgKb", "bearer:orgKb_orgread", "bearer:huncho", "bearer:justin", "anon"]
    for suffix in ["sites", "members", "teams", "excluded-ips", "api-usage"]:
        for org_key in ["kb", "testorg"]:
            for who in readers:
                out.append(case(f"snapshot GET /organizations/:id/{suffix}", "GET", f"/api/organizations/{O[org_key]}/{suffix}", who))
    for who in readers:
        out.append(case("snapshot GET /organizations", "GET", "/api/organizations", who))
        out.append(case("snapshot GET /user/organizations", "GET", "/api/user/organizations", who))
    return out


def all_cases():
    return (
        organization_listings()
        + org_reads()
        + excluded_ip_writes()
        + team_writes()
        + member_writes()
        + site_writes()
        + account_writes()
        + unsubscribe_links()
        + api_key_writes()
        + routing_cases()
        + snapshot_reads()
    )
