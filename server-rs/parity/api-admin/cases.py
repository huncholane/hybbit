"""Every request pair the api-admin harness sends.

A case is {route, method, path, headers, body, who, write, shape}. Paths may carry
`{flag-mv}`, `{exp-exposure}` or `{goal-convert}` placeholders, which the runner
replaces with the ids of the fixture row set the request is about to see.
"""
import json
import urllib.parse

import hw

CREDS = hw.CREDS
S = CREDS["sites"]
O = CREDS["orgs"]
U = CREDS["users"]
P = hw.P

SESSIONS = ["sysadmin", "ownerA", "adminA", "memberA", "restrictedA", "ownerB", "outsider"]
KEYS = [
    "orgA",
    "orgA_flags_read",
    "orgA_flags_write",
    "orgA_exp_read",
    "orgA_exp_write",
    "orgA_wrong",
    "orgB",
    "sysadmin",
    "memberA",
    "adminA",
    "outsider",
]
PRINCIPALS = ["none"] + ["s:" + name for name in SESSIONS] + ["k:" + name for name in KEYS]
# A smaller set for the variant sweeps, covering an allowed and a refused caller
WRITE_PRINCIPALS = ["s:ownerA", "k:orgA"]
ADMIN_PRINCIPALS = ["s:sysadmin", "s:ownerA", "none"]


def headers_for(who, body=None):
    headers = []
    if who.startswith("s:"):
        headers.append(("Cookie", CREDS["sessions"][who[2:]]))
    elif who.startswith("k:"):
        headers.append(("Authorization", "Bearer " + CREDS["keys"][who[2:]]))
    if body is not None:
        headers.append(("Content-Type", "application/json"))
    return headers


def case(route, method, path, who, body=None, write=None, shape=False):
    payload = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    return {
        "route": route,
        "method": method,
        "path": path,
        "who": who,
        "headers": headers_for(who, payload),
        "body": payload,
        "write": method in ("POST", "PUT", "PATCH", "DELETE") if write is None else write,
        "shape": shape,
    }


# ---------------------------------------------------------------------------------
# The admin panel
# ---------------------------------------------------------------------------------

ADMIN_READ_ROUTES = [
    ("admin/clickhouse-stats", "/api/admin/clickhouse-stats", True),
    ("admin/clickhouse-query-log", "/api/admin/clickhouse-query-log", True),
    ("admin/sites", "/api/admin/sites", False),
    ("admin/organizations", "/api/admin/organizations", False),
    ("admin/organization-options", "/api/admin/organization-options", False),
    ("admin/subscription-plans", "/api/admin/subscription-plans", False),
    ("admin/service-event-count", "/api/admin/service-event-count", False),
]

STATS_QUERIES = [
    "",
    "?days=1",
    "?days=0",
    "?days=-5",
    "?days=abc",
    "?days=",
    "?days=2.7",
    "?days=1e3",
    "?days=1&days=2",
    "?days=%207%20",
    "?days=0x10",
    "?days=999999999999",
]

QUERY_LOG_QUERIES = [
    "",
    "?page=2",
    "?page=0",
    "?page=-1",
    "?page=abc",
    "?page=1.9",
    "?pageSize=1",
    "?pageSize=1000",
    "?pageSize=0",
    "?pageSize=abc",
    "?pageSize=",
    "?sortBy=read_rows",
    "?sortBy=memory_usage&sortOrder=asc",
    "?sortBy=type&sortOrder=ASC",
    "?sortBy=bogus",
    "?sortBy=constructor",
    "?sortBy=__proto__",
    "?sortBy=toString",
    "?sortBy=hasOwnProperty",
    "?queryKind=Select",
    "?queryKind=Insert",
    "?queryKind=Other",
    "?queryKind=Drop",
    "?queryKind=Select&queryKind=Insert",
    "?type=QueryFinish",
    "?type=ExceptionWhileProcessing",
    "?type=QueryStart",
    "?page=2&pageSize=3&sortBy=written_rows&sortOrder=asc&queryKind=Insert&type=QueryFinish",
    "?page=1&pageSize=2&sortBy=query_duration_ms",
    "?page=99999&pageSize=5",
]

OPTIONS_QUERIES = [
    "",
    "?search=parity-admin",
    "?search=%20parity-admin%20",
    "?search=a1.parity-admin.test",
    "?search=ownerA@parity-admin.test",
    "?search=" + P + "orgB",
    "?search=nothing-matches-this",
    "?search=%25",
    "?search=_",
    "?limit=1",
    "?limit=50",
    "?limit=51",
    "?limit=0",
    "?limit=-1",
    "?limit=1.5",
    "?limit=abc",
    "?limit=",
    "?limit=1e1",
    "?search=parity&limit=2",
    "?search=a&search=b",
    "?limit=1&limit=2",
    "?search=" + "x" * 201,
]

EVENT_COUNT_QUERIES = [
    "",
    "?start_date=2026-09-01&end_date=2026-09-18",
    "?start_date=2026-09-11&end_date=2026-09-14&time_zone=Europe/Berlin",
    "?time_zone=UTC",
    "?time_zone=America/New_York",
    "?time_zone=",
    "?time_zone=Not/AZone",
    "?start_date=2026-09-01",
    "?end_date=2026-09-18",
    "?start_date=&end_date=",
    "?start_date=bogus",
    "?start_date=2026-13-45&end_date=2026-09-18",
    "?start_date=2026-09-18&end_date=2026-09-01",
    "?past_minutes_start=60&past_minutes_end=0",
    "?start_datetime=2026-09-11%2000:00:00&end_datetime=2026-09-14%2023:59:59",
    "?start_date=2026-09-11&end_date=2026-09-14&time_zone=Pacific/Kiritimati",
    "?start_date=2026-09-11&end_date=2026-09-14&time_zone=utc",
    "?start_date=2026-09-11&end_date=2026-09-14&time_zone=GMT",
    "?start_date=2026-02-29&end_date=2026-03-01",
    "?start_date=2026-09-11&end_date=2026-09-11",
    "?time_zone=UTC&time_zone=UTC",
    "?start_date=0000-01-01&end_date=2026-09-18",
    "?start_date=2026-09-11&end_date=2026-09-14&extra=ignored",
    "?start_date=2026-09-11&end_date=2026-09-14&time_zone=Asia/Kathmandu",
    "?start_date=2026-09-11&end_date=2026-09-14&time_zone=Australia/Lord_Howe",
]

OVERRIDE_BODIES = [
    {"mode": "none"},
    {"mode": "preset", "planOverride": "pro1m"},
    {"mode": "preset", "planOverride": "appsumo-4"},
    {"mode": "preset", "planOverride": "appsumo-7"},
    {"mode": "preset", "planOverride": "appsumo-8"},
    {"mode": "preset", "planOverride": "appsumo-0"},
    {"mode": "preset", "planOverride": "standard100k-annual"},
    {"mode": "preset", "planOverride": "secret-tier"},
    {"mode": "preset", "planOverride": ""},
    {"mode": "preset"},
    {"mode": "preset", "planOverride": 5},
    {"mode": "custom", "customPlan": {"events": 1000, "members": 2, "websites": 3}},
    {"mode": "custom", "customPlan": {"events": 1000, "members": None, "websites": None}},
    {"mode": "custom", "customPlan": {"events": 0, "members": 1, "websites": 1}},
    {"mode": "custom", "customPlan": {"events": 1.5, "members": 1, "websites": 1}},
    {"mode": "custom", "customPlan": {"events": 1000, "members": -1, "websites": 1}},
    {"mode": "custom", "customPlan": {"events": 1000, "members": 1}},
    {"mode": "custom", "customPlan": {}},
    {"mode": "custom", "customPlan": None},
    {"mode": "custom"},
    {"mode": "bogus"},
    {"mode": None},
    {},
    [],
    "text",
    5,
    None,
]

MEMBER_BODIES = [
    {"role": "admin", "hasRestrictedSiteAccess": False, "siteIds": []},
    {"role": "member", "hasRestrictedSiteAccess": False, "siteIds": []},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": [S["a1"], S["a3"]]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": [S["a1"], S["a1"]]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": []},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": [S["b1"]]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": [999999]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": [0]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": [-1]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": [1.5]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": [99999999999]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": ["1"]},
    {"role": "member", "hasRestrictedSiteAccess": True, "siteIds": list(range(1, 502))},
    {"role": "owner", "hasRestrictedSiteAccess": False, "siteIds": []},
    {"role": "root", "hasRestrictedSiteAccess": False, "siteIds": []},
    {"role": 5, "hasRestrictedSiteAccess": False, "siteIds": []},
    {"role": "admin", "hasRestrictedSiteAccess": 1, "siteIds": []},
    {"role": "admin", "hasRestrictedSiteAccess": False, "siteIds": {}},
    {"role": "admin", "hasRestrictedSiteAccess": False},
    {"hasRestrictedSiteAccess": False, "siteIds": []},
    {},
    [],
    "text",
    None,
]

MOVE_BODIES = [
    {"organizationId": O["B"]},
    {"organizationId": O["A"]},
    {"organizationId": "does-not-exist"},
    {"organizationId": ""},
    {"organizationId": 5},
    {"organizationId": None},
    {},
    {"organizationId": O["B"], "extra": 1},
    [],
    "text",
    None,
]

TELEMETRY_BODIES = [
    {"instanceId": P + "i1", "version": "1.0", "tableCounts": {"events": 1}, "clickhouseSizeGb": 1.5},
    {"instanceId": P + "i2", "version": "1.0", "tableCounts": {}, "clickhouseSizeGb": 0},
    {"instanceId": "", "version": "1.0", "tableCounts": {}, "clickhouseSizeGb": 0},
    {"version": "1.0", "tableCounts": {}, "clickhouseSizeGb": 0},
    {},
    None,
]


def admin_cases():
    cases = []
    # Every panel route against every principal
    for route, path, shape in ADMIN_READ_ROUTES:
        for who in PRINCIPALS:
            cases.append(case(route, "GET", path, who, shape=shape))
    for who in PRINCIPALS:
        member_path = f"/api/admin/organizations/{O['A']}/members/{P}m-memberA-A"
        cases.append(case("admin/member-get", "GET", member_path, who))
        cases.append(
            case(
                "admin/member-patch",
                "PATCH",
                member_path,
                who,
                {"role": "member", "hasRestrictedSiteAccess": False, "siteIds": []},
            )
        )
        cases.append(case("admin/member-delete", "DELETE", member_path, who))
        cases.append(
            case(
                "admin/subscription-override",
                "PUT",
                f"/api/admin/organizations/{O['A']}/subscription-override",
                who,
                {"mode": "none"},
            )
        )
        cases.append(
            case("admin/move-site", "PUT", f"/api/admin/sites/{S['a1']}/move", who, {"organizationId": O["B"]})
        )
        cases.append(
            case(
                "admin/telemetry",
                "POST",
                "/api/admin/telemetry",
                who,
                {"instanceId": P + "i", "version": "1", "tableCounts": {}, "clickhouseSizeGb": 1},
            )
        )

    # Query parameter sweeps
    for who in ADMIN_PRINCIPALS:
        for query in STATS_QUERIES:
            cases.append(case("admin/clickhouse-stats", "GET", "/api/admin/clickhouse-stats" + query, who, shape=True))
        for query in QUERY_LOG_QUERIES:
            cases.append(
                case("admin/clickhouse-query-log", "GET", "/api/admin/clickhouse-query-log" + query, who, shape=True)
            )
        for query in OPTIONS_QUERIES:
            cases.append(case("admin/organization-options", "GET", "/api/admin/organization-options" + query, who))
        for query in EVENT_COUNT_QUERIES:
            cases.append(case("admin/service-event-count", "GET", "/api/admin/service-event-count" + query, who))

    # Write bodies
    for who in ["s:sysadmin", "s:ownerA"]:
        for org in ["A", "C", "E"]:
            for body in OVERRIDE_BODIES:
                cases.append(
                    case(
                        "admin/subscription-override",
                        "PUT",
                        f"/api/admin/organizations/{O[org]}/subscription-override",
                        who,
                        body,
                    )
                )
        for body in OVERRIDE_BODIES[:6]:
            cases.append(
                case(
                    "admin/subscription-override",
                    "PUT",
                    "/api/admin/organizations/does-not-exist/subscription-override",
                    who,
                    body,
                )
            )
        for member in ["memberA-A", "ownerA-A", "restrictedA-A", "ownerB-B", "sysadmin-C"]:
            org = O[member.rsplit("-", 1)[1]]
            for body in MEMBER_BODIES:
                cases.append(
                    case("admin/member-patch", "PATCH", f"/api/admin/organizations/{org}/members/{P}m-{member}", who, body)
                )
        for body in MOVE_BODIES:
            for site in [S["a1"], S["orphan"], S["b1"], 999999, 0, -1]:
                cases.append(case("admin/move-site", "PUT", f"/api/admin/sites/{site}/move", who, body))
        for body in TELEMETRY_BODIES:
            cases.append(case("admin/telemetry", "POST", "/api/admin/telemetry", who, body))

    # Unknown and malformed identifiers
    for who in ["s:sysadmin", "none"]:
        for path in [
            f"/api/admin/organizations/nope/members/{P}m-memberA-A",
            f"/api/admin/organizations/{O['A']}/members/nope",
            f"/api/admin/organizations/{O['B']}/members/{P}m-memberA-A",
            "/api/admin/organizations//members/x",
            f"/api/admin/organizations/{O['A']}/members/",
            f"/api/admin/organizations/{O['A']}/members/%2e%2e",
            f"/api/admin/organizations/{O['A']}/members/%zz",
            f"/api/admin/organizations/{'x' * 1600}/members/y",
        ]:
            cases.append(case("admin/member-get", "GET", path, who))
            cases.append(case("admin/member-delete", "DELETE", path, who))
        for path in [
            "/api/admin/sites/abc/move",
            "/api/admin/sites/0/move",
            "/api/admin/sites/-1/move",
            # `parseInt` stops at the dot, so this is site a1 and not a snapshot Site
            f"/api/admin/sites/{S['a1']}.5/move",
            "/api/admin/sites/99999999999/move",
            "/api/admin/sites//move",
            "/api/admin/sites/%20/move",
        ]:
            cases.append(case("admin/move-site", "PUT", path, who, {"organizationId": O["B"]}))

    # Methods a panel path does not register
    for route, path, shape in ADMIN_READ_ROUTES:
        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD"]:
            cases.append(case(route, method, path, "s:sysadmin", write=False, shape=shape))
    for method in ["GET", "PUT", "PATCH", "DELETE", "HEAD"]:
        cases.append(case("admin/telemetry", method, "/api/admin/telemetry", "s:sysadmin", write=False))
    for method in ["POST", "GET", "PATCH", "DELETE"]:
        cases.append(
            case("admin/move-site", method, f"/api/admin/sites/{S['a1']}/move", "s:sysadmin", write=(method != "GET"))
        )
    return cases


# ---------------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------------

SITE_PARAMS = [
    str(S["a1"]),
    str(S["a2"]),
    str(S["b1"]),
    str(S["orphan"]),
    str(S["real"]),
    "999999",
    "0",
    "abc",
]

RULE_FIELDS = [
    "hostname",
    "pathname",
    "query",
    "referrer",
    "language",
    "country",
    "region",
    "city",
    "device_type",
    "user_id",
    "trait",
]
RULE_OPERATORS = ["equals", "not_equals", "contains", "starts_with", "ends_with", "regex"]


def flag(**extra):
    body = {"key": "pa_new_flag"}
    body.update(extra)
    return body


FLAG_BODIES = [
    flag(),
    flag(description="a description", enabled=True, runtime="server", flagType="boolean", rolloutPercentage=25),
    flag(runtime="both"),
    flag(runtime="edge"),
    flag(flagType="remote_config", payload={"a": [1, 2, {"b": None}]}),
    flag(flagType="remote_config", payload="text"),
    flag(flagType="remote_config", payload=5),
    flag(flagType="remote_config", payload=True),
    flag(flagType="remote_config", payload=None),
    flag(flagType="remote_config", payload=[1, 2, 3]),
    flag(flagType="remote_config", payload="x" * 4097),
    flag(flagType="remote_config", payload=list(range(101))),
    flag(flagType="remote_config", variants=[{"key": "a", "rolloutPercentage": 50}]),
    flag(flagType="boolean", variants=[{"key": "a", "rolloutPercentage": 50}]),
    flag(
        flagType="multivariate",
        variants=[{"key": "control", "rolloutPercentage": 50}, {"key": "treatment", "rolloutPercentage": 50}],
    ),
    flag(flagType="multivariate", variants=[{"key": "control", "rolloutPercentage": 100}]),
    flag(
        flagType="multivariate",
        variants=[{"key": "a", "rolloutPercentage": 60}, {"key": "a", "rolloutPercentage": 40}],
    ),
    flag(
        flagType="multivariate",
        variants=[{"key": "a", "rolloutPercentage": 60}, {"key": "b", "rolloutPercentage": 60}],
    ),
    flag(
        flagType="multivariate",
        variants=[{"key": "a", "name": "A", "rolloutPercentage": 50, "payload": {"x": 1}}, {"key": "b", "rolloutPercentage": 50}],
    ),
    flag(flagType="multivariate", variants=[{"key": "1bad", "rolloutPercentage": 50}, {"key": "b", "rolloutPercentage": 50}]),
    flag(flagType="multivariate", variants=[{"key": "a"}, {"key": "b", "rolloutPercentage": 50}]),
    flag(flagType="multivariate", variants=[{"key": "a", "rolloutPercentage": -1}, {"key": "b", "rolloutPercentage": 50}]),
    flag(flagType="multivariate", variants=[{"key": "a", "rolloutPercentage": 101}, {"key": "b", "rolloutPercentage": 0}]),
    flag(flagType="multivariate", variants=[{"key": "a", "rolloutPercentage": 1.5}, {"key": "b", "rolloutPercentage": 50}]),
    flag(flagType="multivariate", variants=[{"key": f"v{n}", "rolloutPercentage": 0} for n in range(21)]),
    flag(flagType="multivariate", variants=[{"key": "a", "rolloutPercentage": 50, "name": "x" * 121}, {"key": "b", "rolloutPercentage": 50}]),
    flag(key=""),
    flag(key="   "),
    flag(key="1bad"),
    flag(key="_bad"),
    flag(key="a" * 101),
    flag(key="a.b:c-d_e"),
    flag(key=5),
    flag(key=None),
    {"enabled": True},
    flag(description=None),
    flag(description=""),
    flag(description="x" * 1001),
    flag(description=5),
    flag(enabled="yes"),
    flag(rolloutPercentage=-1),
    flag(rolloutPercentage=101),
    flag(rolloutPercentage=1.5),
    flag(rolloutPercentage="50"),
    flag(rules=[{"field": "country", "operator": "equals", "value": "DE"}]),
    flag(rules=[{"field": "country", "operator": "equals", "value": ["DE", "FR"]}]),
    flag(rules=[{"field": "country", "operator": "equals", "value": 5}]),
    flag(rules=[{"field": "country", "operator": "equals", "value": True}]),
    flag(rules=[{"field": "country", "operator": "equals", "value": [1, "a", False]}]),
    flag(rules=[{"field": "country", "operator": "equals", "value": list(range(51))}]),
    flag(rules=[{"field": "country", "operator": "equals", "value": "x" * 513}]),
    flag(rules=[{"field": "query", "operator": "equals", "value": "a"}]),
    flag(rules=[{"field": "query", "key": "utm", "operator": "equals", "value": "a"}]),
    flag(rules=[{"field": "trait", "operator": "equals", "value": "a"}]),
    flag(rules=[{"field": "trait", "key": "", "operator": "equals", "value": "a"}]),
    flag(rules=[{"field": "pathname", "operator": "regex", "value": "^/pricing(/|$)"}]),
    flag(rules=[{"field": "pathname", "operator": "regex", "value": "(a+)+$"}]),
    flag(rules=[{"field": "pathname", "operator": "regex", "value": "["}]),
    flag(rules=[{"field": "pathname", "operator": "regex", "value": 5}]),
    flag(rules=[{"field": "pathname", "operator": "regex", "value": ["^/a", "(b+)+"]}]),
    flag(rules=[{"field": "nope", "operator": "equals", "value": "a"}]),
    flag(rules=[{"field": "country", "operator": "nope", "value": "a"}]),
    flag(rules=[{"field": f, "operator": "equals", "value": "a", "key": "k"} for f in RULE_FIELDS]),
    flag(rules=[{"field": "country", "operator": o, "value": "a"} for o in RULE_OPERATORS[:5]]),
    flag(rules=[{"field": "country", "operator": "equals", "value": "a"} for _ in range(26)]),
    flag(rules={}),
    flag(conditionSets=[{"name": "set", "rules": [{"field": "country", "operator": "equals", "value": "DE"}]}]),
    flag(conditionSets=[{"rules": [], "rolloutPercentage": 50}]),
    flag(conditionSets=[{"rules": []}]),
    flag(
        flagType="multivariate",
        variants=[{"key": "a", "rolloutPercentage": 50}, {"key": "b", "rolloutPercentage": 50}],
        conditionSets=[
            {
                "rules": [],
                "variants": [{"key": "x", "rolloutPercentage": 50}, {"key": "y", "rolloutPercentage": 50}],
            }
        ],
    ),
    flag(
        flagType="multivariate",
        conditionSets=[
            {
                "rules": [],
                "variants": [{"key": "x", "rolloutPercentage": 50}, {"key": "y", "rolloutPercentage": 50}],
            }
        ],
    ),
    flag(
        flagType="multivariate",
        conditionSets=[{"rules": [], "variants": [{"key": "x", "rolloutPercentage": 100}]}],
        variants=[{"key": "a", "rolloutPercentage": 50}, {"key": "b", "rolloutPercentage": 50}],
    ),
    flag(
        flagType="multivariate",
        conditionSets=[
            {
                "rules": [],
                "rolloutPercentage": 10,
                "variants": [{"key": "x", "rolloutPercentage": 50}, {"key": "y", "rolloutPercentage": 50}],
            }
        ],
        variants=[{"key": "a", "rolloutPercentage": 50}, {"key": "b", "rolloutPercentage": 50}],
    ),
    flag(conditionSets=[{"rules": [], "variants": [{"key": "x", "rolloutPercentage": 100}]}]),
    flag(flagType="remote_config", conditionSets=[{"rules": [], "variants": [{"key": "x", "rolloutPercentage": 100}]}]),
    flag(conditionSets=[{"rules": [], "payload": {"a": 1}}]),
    flag(conditionSets=[{"rules": [], "payload": None}]),
    flag(conditionSets=[{"rules": []} for _ in range(21)]),
    flag(conditionSets=[{"name": 5, "rules": []}]),
    flag(key="parity_admin_bool"),
    flag(unknown="dropped"),
    [],
    "text",
    5,
    None,
    b"{not json",
]

FLAG_UPDATE_BODIES = [
    {"key": "pa_renamed"},
    {"key": "parity_admin_rc"},
    {"description": "changed"},
    {"description": None},
    {"description": ""},
    {"enabled": True},
    {"enabled": False},
    {"runtime": "server"},
    {"runtime": "nope"},
    {"flagType": "multivariate"},
    {"flagType": "multivariate", "variants": [{"key": "a", "rolloutPercentage": 50}, {"key": "b", "rolloutPercentage": 50}]},
    {"payload": {"deep": {"er": [1, 2]}}},
    {"payload": None},
    {"rolloutPercentage": 0},
    {"rolloutPercentage": 100},
    {"rolloutPercentage": 101},
    {"rules": []},
    {"rules": [{"field": "city", "operator": "contains", "value": "Ber"}]},
    {"rules": [{"field": "pathname", "operator": "regex", "value": "(a|a)*$"}]},
    {"conditionSets": []},
    {"conditionSets": [{"rules": [{"field": "language", "operator": "starts_with", "value": "de"}]}]},
    {"variants": []},
    {"key": "pa_renamed", "enabled": True, "rolloutPercentage": 10, "description": "all at once"},
    {},
    {"unknown": 1},
    {"flagId": 5},
    [],
    "text",
    None,
]


def flag_cases():
    cases = []
    # Every route against every principal, on a Site in organization A
    for who in PRINCIPALS:
        cases.append(case("flags/list", "GET", f"/api/sites/{S['a1']}/feature-flags", who))
        cases.append(case("flags/create", "POST", f"/api/sites/{S['a1']}/feature-flags", who, flag()))
        cases.append(case("flags/update", "PUT", f"/api/sites/{S['a1']}/feature-flags/{{flag-mv}}", who, {"enabled": True}))
        cases.append(case("flags/delete", "DELETE", f"/api/sites/{S['a1']}/feature-flags/{{flag-mv}}", who))

    # The same routes across Sites the caller may or may not reach
    for site in SITE_PARAMS:
        for who in PRINCIPALS:
            cases.append(case("flags/list", "GET", f"/api/sites/{site}/feature-flags", who))
        for who in ["s:ownerA", "k:orgA", "s:outsider", "none"]:
            cases.append(case("flags/create", "POST", f"/api/sites/{site}/feature-flags", who, flag()))
            cases.append(case("flags/delete", "DELETE", f"/api/sites/{site}/feature-flags/{{flag-mv}}", who))

    # Bodies
    for who in WRITE_PRINCIPALS:
        for body in FLAG_BODIES:
            cases.append(case("flags/create", "POST", f"/api/sites/{S['a1']}/feature-flags", who, body))
        for body in FLAG_UPDATE_BODIES:
            cases.append(
                case("flags/update", "PUT", f"/api/sites/{S['a1']}/feature-flags/{{flag-mv}}", who, body)
            )
            cases.append(
                case("flags/update", "PUT", f"/api/sites/{S['a1']}/feature-flags/{{flag-rc}}", who, body)
            )

    # Flag ids
    for flag_id in ["{flag-mv}", "{flag-b1flag}", "999999", "0", "-1", "abc", "1.5", "99999999999", "", "%20"]:
        for who in ["s:ownerA", "k:orgA_flags_write", "none"]:
            cases.append(
                case("flags/update", "PUT", f"/api/sites/{S['a1']}/feature-flags/{flag_id}", who, {"enabled": True})
            )
            cases.append(case("flags/delete", "DELETE", f"/api/sites/{S['a1']}/feature-flags/{flag_id}", who))

    # Methods a flag path does not register
    for method in ["PUT", "DELETE", "PATCH", "HEAD"]:
        cases.append(case("flags/list", method, f"/api/sites/{S['a1']}/feature-flags", "s:ownerA", write=False))
    for method in ["GET", "POST", "PATCH"]:
        cases.append(
            case("flags/update", method, f"/api/sites/{S['a1']}/feature-flags/{{flag-mv}}", "s:ownerA", write=False)
        )
    # The evaluate route is not this group's, but the path shape must still agree
    for method in ["GET", "PUT", "DELETE"]:
        cases.append(
            case("flags/evaluate-path", method, f"/api/sites/{S['a1']}/feature-flags/evaluate", "s:ownerA", write=False)
        )
    return cases


# ---------------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------------


def experiment(**extra):
    body = {"name": "parity-admin new", "featureFlagId": "{flag-free}"}
    body.update(extra)
    return body


EXPERIMENT_BODIES = [
    experiment(),
    experiment(description="d", hypothesis="h", status="running", winningVariant="control"),
    experiment(status="draft"),
    experiment(status="paused"),
    experiment(status="completed"),
    experiment(status="archived"),
    experiment(status=5),
    experiment(name=""),
    experiment(name="   "),
    experiment(name="x" * 161),
    experiment(name=5),
    experiment(name=None),
    {"featureFlagId": "{flag-free}"},
    {"name": "parity-admin new"},
    experiment(description=None),
    experiment(description=""),
    experiment(description="x" * 1001),
    experiment(description=5),
    experiment(hypothesis=None),
    experiment(hypothesis="x" * 1001),
    experiment(winningVariant=None),
    experiment(winningVariant=""),
    experiment(winningVariant="x" * 101),
    experiment(featureFlagId="{flag-mv}"),
    experiment(featureFlagId="{flag-bool}"),
    experiment(featureFlagId="{flag-rc}"),
    experiment(featureFlagId="{flag-b1flag}"),
    experiment(featureFlagId=999999),
    experiment(featureFlagId=0),
    experiment(featureFlagId=-1),
    experiment(featureFlagId=1.5),
    experiment(featureFlagId="5"),
    experiment(featureFlagId=None),
    experiment(primaryGoalId="{goal-convert}"),
    experiment(primaryGoalId="{goal-assign}"),
    experiment(primaryGoalId=999999),
    experiment(primaryGoalId=None),
    experiment(primaryGoalId=0),
    experiment(primaryGoalId=-1),
    experiment(primaryGoalId=1.5),
    experiment(unknown=1),
    {},
    [],
    "text",
    None,
]

EXPERIMENT_UPDATE_BODIES = [
    {"name": "renamed"},
    {"name": ""},
    {"description": None},
    {"description": "changed"},
    {"hypothesis": None},
    {"status": "running"},
    {"status": "completed"},
    {"status": "paused"},
    {"status": "nope"},
    {"winningVariant": "control"},
    {"winningVariant": None},
    {"featureFlagId": "{flag-free}"},
    {"featureFlagId": "{flag-bool}"},
    {"featureFlagId": 999999},
    {"primaryGoalId": "{goal-pricing}"},
    {"primaryGoalId": None},
    {"primaryGoalId": 999999},
    {"primaryGoalId": "{goal-assign}"},
    {"name": "everything", "description": "d", "hypothesis": "h", "status": "completed", "winningVariant": "treatment"},
    {},
    {"unknown": 1},
    [],
    "text",
    None,
]

def encoded(value):
    """A `filters` value as the dashboard sends it: JSON, percent encoded. Raw
    braces and quotes are left out of the sweep on purpose: hyper rejects a query
    string containing them before any handler runs, where Node's parser accepts
    it, which is an HTTP edge difference rather than a route one."""
    return urllib.parse.quote(json.dumps(value, separators=(",", ":")), safe="")


RESULTS_QUERIES = [
    "",
    "?start_date=2026-09-01&end_date=2026-09-18&time_zone=UTC",
    "?start_date=2026-09-12&end_date=2026-09-13&time_zone=UTC",
    "?start_date=2026-01-01&end_date=2026-01-02",
    "?time_zone=Europe/Berlin",
    "?past_minutes_start=60&past_minutes_end=0",
    "?filters=" + encoded([{"parameter": "country", "type": "equals", "value": ["DE"]}]),
    "?filters=" + encoded([{"parameter": "utm_campaign", "type": "equals", "value": ["parity_admin"]}]),
    "?filters=" + encoded([{"parameter": "browser", "type": "not_equals", "value": ["Chrome"]}]),
    "?filters=" + encoded([{"parameter": "pathname", "type": "contains", "value": ["/pric"]}]),
    "?filters=" + encoded([{"parameter": "entry_page", "type": "equals", "value": ["/pricing"]}]),
    "?filters=not-json",
    "?filters=%5B%5D",
    "?filters=" + encoded([{"parameter": "nope", "type": "equals", "value": ["x"]}]),
    "?filters=" + encoded([{"parameter": "country", "type": "bogus", "value": ["DE"]}]),
    "?filters=" + encoded([{"parameter": "pathname", "type": "matches", "value": ["(a+)+"]}]),
    "?filters=" + encoded([{"parameter": "country", "type": "equals", "value": []}]),
    "?filters=" + encoded({"parameter": "country", "type": "equals", "value": ["DE"]}),
    "?start_date=bogus",
    "?time_zone=Not/AZone",
    "?start_date=2026-09-11&end_date=2026-09-14&filters="
    + encoded([{"parameter": "country", "type": "equals", "value": ["DE"]}]),
]


def experiment_cases():
    cases = []
    for who in PRINCIPALS:
        cases.append(case("experiments/list", "GET", f"/api/sites/{S['a1']}/experiments", who))
        cases.append(case("experiments/create", "POST", f"/api/sites/{S['a1']}/experiments", who, experiment()))
        cases.append(
            case("experiments/update", "PUT", f"/api/sites/{S['a1']}/experiments/{{exp-exposure}}", who, {"name": "x"})
        )
        cases.append(case("experiments/delete", "DELETE", f"/api/sites/{S['a1']}/experiments/{{exp-exposure}}", who))
        cases.append(
            case("experiments/results", "GET", f"/api/sites/{S['a1']}/experiments/{{exp-exposure}}/results", who)
        )

    for site in SITE_PARAMS:
        for who in PRINCIPALS:
            cases.append(case("experiments/list", "GET", f"/api/sites/{site}/experiments", who))
        for who in ["s:ownerA", "k:orgA", "s:outsider", "none"]:
            cases.append(case("experiments/create", "POST", f"/api/sites/{site}/experiments", who, experiment()))
            cases.append(
                case("experiments/results", "GET", f"/api/sites/{site}/experiments/{{exp-exposure}}/results", who)
            )

    for who in WRITE_PRINCIPALS:
        for body in EXPERIMENT_BODIES:
            cases.append(case("experiments/create", "POST", f"/api/sites/{S['a1']}/experiments", who, body))
        for body in EXPERIMENT_UPDATE_BODIES:
            cases.append(
                case("experiments/update", "PUT", f"/api/sites/{S['a1']}/experiments/{{exp-exposure}}", who, body)
            )
            cases.append(
                case("experiments/update", "PUT", f"/api/sites/{S['a1']}/experiments/{{exp-nogoal}}", who, body)
            )

    for experiment_id in ["{exp-exposure}", "{exp-assignment}", "999999", "0", "-1", "abc", "1.5", "99999999999", "", "%20"]:
        for who in ["s:ownerA", "k:orgA_exp_write", "none"]:
            cases.append(
                case("experiments/update", "PUT", f"/api/sites/{S['a1']}/experiments/{experiment_id}", who, {"name": "x"})
            )
            cases.append(case("experiments/delete", "DELETE", f"/api/sites/{S['a1']}/experiments/{experiment_id}", who))
        for who in ["s:ownerA", "k:orgA_exp_read", "none"]:
            cases.append(
                case("experiments/results", "GET", f"/api/sites/{S['a1']}/experiments/{experiment_id}/results", who)
            )

    # Results over the fixture and the real production data, with every window
    for who in ["s:ownerA", "k:orgA"]:
        for query in RESULTS_QUERIES:
            cases.append(
                case(
                    "experiments/results",
                    "GET",
                    f"/api/sites/{S['a1']}/experiments/{{exp-exposure}}/results" + query,
                    who,
                )
            )
            cases.append(
                case(
                    "experiments/results",
                    "GET",
                    f"/api/sites/{S['a2']}/experiments/{{exp-assignment}}/results" + query,
                    who,
                )
            )
            cases.append(
                case(
                    "experiments/results",
                    "GET",
                    f"/api/sites/{S['a1']}/experiments/{{exp-nogoal}}/results" + query,
                    who,
                )
            )
    # The snapshot Site, whose events carry real feature flag assignments: these
    # principals actually reach it, so the results run over production data
    for who in ["s:kbOwner", "s:kbMember", "k:kbOrg", "k:kbOrg_exp_read", "k:kbOrg_flags_read", "s:sysadmin", "none"]:
        for query in RESULTS_QUERIES:
            cases.append(
                case(
                    "experiments/results",
                    "GET",
                    f"/api/sites/{S['real']}/experiments/{{exp-real}}/results" + query,
                    who,
                )
            )
        cases.append(case("experiments/list", "GET", f"/api/sites/{S['real']}/experiments", who))
        cases.append(case("flags/list", "GET", f"/api/sites/{S['real']}/feature-flags", who))

    for method in ["PUT", "DELETE", "PATCH", "HEAD"]:
        cases.append(case("experiments/list", method, f"/api/sites/{S['a1']}/experiments", "s:ownerA", write=False))
    for method in ["GET", "POST", "PATCH"]:
        cases.append(
            case("experiments/update", method, f"/api/sites/{S['a1']}/experiments/{{exp-exposure}}", "s:ownerA", write=False)
        )
    for method in ["POST", "PUT", "DELETE"]:
        cases.append(
            case(
                "experiments/results",
                method,
                f"/api/sites/{S['a1']}/experiments/{{exp-exposure}}/results",
                "s:ownerA",
                write=False,
            )
        )
    return cases


def all_cases():
    return admin_cases() + flag_cases() + experiment_cases()
