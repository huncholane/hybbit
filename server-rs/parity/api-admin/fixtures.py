#!/usr/bin/env python3
"""Principals and data for the api-admin parity harness: users, organizations,
sites (ids 65400 and up), goals, funnels, feature flags, experiments, sessions,
API keys and the ClickHouse events the experiment results endpoint reads. Every
row is prefixed parity-admin- so cleanup can find it again.

Usage: fixtures.py setup > $OUT/creds.json
       fixtures.py cleanup
"""
import base64
import hashlib
import hmac
import json
import sys
import urllib.parse
import urllib.request

import psycopg2

SECRET = "parity-local-secret-not-for-production"
COOKIE = "__Secure-better-auth.session_token"
P = "parity-admin-"
CH = "http://127.0.0.1:58123/?database=analytics"
CH_HEADERS = {"X-ClickHouse-User": "default", "X-ClickHouse-Key": "hygo"}

# An existing snapshot site whose events already carry feature flag assignments,
# so the assignment fallback runs over real production data. Only rows we add are
# ever written or removed; the site itself is left alone.
REAL_SITE = 4
REAL_FLAG_KEY = "checkout"
REAL_GOAL_EVENT = "checkout_started"
# Snapshot users who can reach REAL_SITE, so the results endpoint runs over real
# production events. Only sessions and API keys are added for them; the user rows
# themselves are never touched.
REAL_USERS = {
    "kbOwner": "XoNIxodDwuJOefJZebreRpXzn7Sq3hlL",
    "kbMember": "ZDZZHJlo6olnWqliEC5t0kHoxcurXqBM",
}
REAL_ORG = "kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE"

SITE_IDS = {
    "a1": 65400,  # org A, no type, private, session replay on
    "a2": 65401,  # org A, mobile, public
    "a3": 65402,  # org A, web, empty domain
    "b1": 65403,  # org B
    "g1": 65404,  # org G, which has no members at all
    "c1": 65405,  # org C, the custom plan
    "orphan": 65406,  # no organization
}


def conn():
    return psycopg2.connect(host="127.0.0.1", port=55432, user="hygo", password="hygo", dbname="analytics")


def sign(value):
    signature = base64.b64encode(hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{signature}", safe="")


def hash_key(key):
    return base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()).decode().rstrip("=")


def clickhouse(sql, body=None):
    request = urllib.request.Request(CH, data=(body or sql).encode(), headers=CH_HEADERS)
    if body is not None:
        request.full_url = CH + "&query=" + urllib.parse.quote(sql)
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read().decode()


def cleanup(cur):
    site_list = ",".join(str(site) for site in SITE_IDS.values())
    real_keys = ",".join("'" + flag[2].replace("'", "''") + "'" for flag in FLAGS)
    cur.execute(f"DELETE FROM experiments WHERE site_id IN ({site_list}) OR name LIKE '{P}%'")
    # The flag on the snapshot Site is ours too, and its key carries no prefix
    cur.execute(
        f"DELETE FROM feature_flags WHERE site_id IN ({site_list}) OR key LIKE '{P}%' "
        f"OR (site_id = {REAL_SITE} AND (key IN ({real_keys}) OR key LIKE 'pa\\_%'))"
    )
    cur.execute(f"DELETE FROM goals WHERE site_id IN ({site_list}) OR name LIKE '{P}%'")
    cur.execute(f"DELETE FROM funnels WHERE site_id IN ({site_list})")
    cur.execute(f"DELETE FROM segments WHERE site_id IN ({site_list}) OR organization_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM apikey WHERE id LIKE '{P}%'")
    cur.execute(f"DELETE FROM session WHERE id LIKE '{P}%'")
    cur.execute(f"DELETE FROM member_site_access WHERE member_id LIKE '{P}%' OR site_id IN ({site_list})")
    cur.execute(f"DELETE FROM team_site_access WHERE site_id IN ({site_list})")
    cur.execute(f"DELETE FROM member WHERE id LIKE '{P}%'")
    cur.execute(f"DELETE FROM sites WHERE site_id IN ({site_list}) OR organization_id LIKE '{P}%'")
    cur.execute(f"DELETE FROM organization WHERE id LIKE '{P}%'")
    cur.execute(f'DELETE FROM "user" WHERE id LIKE \'{P}%\'')
    cur.execute(f"DELETE FROM telemetry WHERE instance_id LIKE '{P}%'")


def cleanup_clickhouse():
    site_list = ",".join(str(site) for site in SITE_IDS.values())
    clickhouse(f"ALTER TABLE events DELETE WHERE site_id IN ({site_list})")


USERS = {
    "sysadmin": "admin",
    "ownerA": "user",
    "adminA": "user",
    "memberA": "user",
    "restrictedA": "user",
    "ownerB": "user",
    "outsider": "user",
}

# id, name, planOverride, custom_plan, stripeCustomerId, monthlyEventCount, overMonthlyLimit
ORGS = [
    ("A", "parity-admin A", None, None, None, 0, False),
    ("B", "parity-admin B", "pro1m", None, None, 12, False),
    ("C", "parity-admin C", None, {"events": 1234567, "members": None, "websites": 7}, None, 0, False),
    ("D", "parity-admin D", "appsumo-4", None, None, 0, False),
    ("E", "parity-admin E", "not-a-real-plan", None, None, 0, False),
    ("F", "parity-admin F", None, None, "cus_parityadmin", 4242, True),
    ("G", "parity-admin G", None, None, None, 0, False),
]

# key, org, type, domain, public, sessionReplay
SITES = [
    ("a1", "A", None, "a1.parity-admin.test", False, True),
    ("a2", "A", "mobile", "a2.parity-admin.test", True, False),
    ("a3", "A", "web", "", False, False),
    ("b1", "B", "web", "b1.parity-admin.test", False, False),
    ("g1", "G", "web", "g1.parity-admin.test", False, False),
    ("c1", "C", None, "c1.parity-admin.test", True, True),
    ("orphan", None, "web", "orphan.parity-admin.test", False, False),
]

# key, site, goal_type, config
GOALS = [
    ("convert", "a1", "event", {"eventName": "parity_admin_convert"}),
    ("pricing", "a1", "path", {"pathPattern": "/pricing"}),
    ("assign", "a2", "event", {"eventName": "parity_admin_convert"}),
    ("realgoal", REAL_SITE, "event", {"eventName": REAL_GOAL_EVENT}),
]

VARIANTS = [
    {"key": "control", "name": "Control", "rolloutPercentage": 50},
    {"key": "treatment", "name": "Treatment", "rolloutPercentage": 50},
]

# key, site, flag key, flag type, extras
FLAGS = [
    ("bool", "a1", "parity_admin_bool", "boolean", {"enabled": True, "rolloutPercentage": 40}),
    ("mv", "a1", "parity_admin_mv", "multivariate", {"enabled": True, "variants": VARIANTS}),
    ("rc", "a1", "parity_admin_rc", "remote_config", {"payload": {"colour": "blue", "count": 3}}),
    ("free", "a1", "parity_admin_free", "multivariate", {"variants": VARIANTS}),
    ("proto", "a1", "constructor", "boolean", {}),
    ("assign", "a2", "parity_admin_assign", "multivariate", {"enabled": True, "variants": VARIANTS}),
    ("b1flag", "b1", "parity_admin_b1", "boolean", {}),
    (
        "conditions",
        "a1",
        "parity_admin_cond",
        "multivariate",
        {
            "enabled": True,
            "rules": [{"field": "country", "operator": "equals", "value": ["DE", "FR"]}],
            "conditionSets": [
                {
                    "name": "EU",
                    "rules": [{"field": "pathname", "operator": "regex", "value": "^/eu(/|$)"}],
                    "variants": [
                        {"key": "eu_a", "rolloutPercentage": 60},
                        {"key": "eu_b", "rolloutPercentage": 40},
                    ],
                }
            ],
            "variants": VARIANTS,
        },
    ),
    ("realflag", REAL_SITE, REAL_FLAG_KEY, "multivariate", {"enabled": True, "variants": VARIANTS}),
]

# key, site, flag key, goal key, status
EXPERIMENTS = [
    ("exposure", "a1", "mv", "convert", "running"),
    ("nogoal", "a1", "free", None, "draft"),
    ("assignment", "a2", "assign", "assign", "running"),
    ("real", REAL_SITE, "realflag", "realgoal", "running"),
]


def clickhouse_events():
    """Exposure events on site a1 and bare assignments on site a2, so the results
    endpoint has both measurement paths to walk over."""
    rows = []

    def event(site, session, stamp, event_type, name, props, flags):
        rows.append(
            {
                "site_id": site,
                "timestamp": stamp,
                "timestamp_ms": stamp + ".000",
                "session_id": session,
                "user_id": "u-" + session,
                "hostname": "a.parity-admin.test",
                "pathname": "/pricing",
                "querystring": "",
                "url_parameters": {"utm_campaign": "parity_admin"} if session.endswith("1") else {},
                "page_title": "",
                "referrer": "",
                "channel": "Direct",
                "browser": "Chrome",
                "browser_version": "140",
                "operating_system": "macOS",
                "operating_system_version": "15",
                "language": "en-US",
                "country": "DE",
                "region": "BE",
                "city": "Berlin",
                "lat": 52.5,
                "lon": 13.4,
                "screen_width": 1440,
                "screen_height": 900,
                "device_type": "Desktop",
                "type": event_type,
                "event_name": name,
                "props": props,
                "feature_flags": flags,
                "identified_user_id": "",
                "tag": "",
                "ip": "",
                "timezone": "Europe/Berlin",
                "is_datacenter_asn": 0,
            }
        )

    a1 = SITE_IDS["a1"]
    a2 = SITE_IDS["a2"]
    # Four exposed sessions on a1: two per variant, one of each converts
    plan = [
        ("pa-s1", "control", True),
        ("pa-s2", "control", False),
        ("pa-s3", "treatment", True),
        ("pa-s4", "treatment", True),
    ]
    for index, (session, variant, converts) in enumerate(plan):
        day = 11 + index
        stamp = f"2026-09-{day:02d} 10:00:00"
        flags = {"parity_admin_mv": variant}
        event(a1, session, stamp, "pageview", "", {}, flags)
        event(
            a1,
            session,
            f"2026-09-{day:02d} 10:00:05",
            "custom_event",
            "feature_flag_exposure",
            {"key": "parity_admin_mv", "value": variant},
            flags,
        )
        # A second exposure for the same session proves only the first arm counts
        event(
            a1,
            session,
            f"2026-09-{day:02d} 10:00:09",
            "custom_event",
            "feature_flag_exposure",
            {"key": "parity_admin_mv", "value": "treatment" if variant == "control" else "control"},
            flags,
        )
        if converts:
            event(
                a1,
                session,
                f"2026-09-{day:02d} 10:05:00",
                "custom_event",
                "parity_admin_convert",
                {"amount": 10},
                flags,
            )
    # a2 carries assignments only, so the exposure query finds nothing
    for index, (session, variant, converts) in enumerate(
        [("pa-t1", "control", True), ("pa-t2", "treatment", False), ("pa-t3", "treatment", True)]
    ):
        day = 12 + index
        flags = {"parity_admin_assign": variant}
        event(a2, session, f"2026-09-{day:02d} 09:00:00", "pageview", "", {}, flags)
        if converts:
            event(a2, session, f"2026-09-{day:02d} 09:10:00", "custom_event", "parity_admin_convert", {}, flags)
    return rows


def setup_principals(cur):
    """Users, organizations, Sites, memberships, sessions, API keys, goals and
    funnels: everything a request needs to exist before it is sent. Safe to re-run,
    which the harness does whenever another agent's cleanup has taken the rows out
    from under it (the session tokens and API keys are deterministic, so the
    credentials stay valid)."""
    cleanup(cur)
    creds = {"sessions": {}, "keys": {}, "sites": dict(SITE_IDS), "orgs": {}, "users": {}, "flags": {}, "goals": {}, "experiments": {}}
    creds["sites"]["real"] = REAL_SITE

    for name, role in USERS.items():
        uid = P + "u-" + name
        creds["users"][name] = uid
        cur.execute(
            'INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", role) '
            "VALUES (%s, %s, %s, true, %s, %s, %s)",
            (uid, "parity-admin " + name, f"{name}@parity-admin.test", "2026-05-01 00:00:00", "2026-05-01 00:00:00", role),
        )

    for index, (key, name, override, custom, customer, events, over) in enumerate(ORGS):
        oid = P + "org" + key
        creds["orgs"][key] = oid
        cur.execute(
            'INSERT INTO organization (id, name, slug, "createdAt", "planOverride", custom_plan, '
            '"stripeCustomerId", "monthlyEventCount", "overMonthlyLimit") '
            "VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)",
            (
                oid,
                name,
                (P + "org" + key).lower(),
                f"2026-04-{10 + index:02d} 08:00:00.5",
                override,
                json.dumps(custom) if custom else None,
                customer,
                events,
                over,
            ),
        )

    for index, (key, org, site_type, domain, public, replay) in enumerate(SITES):
        cur.execute(
            'INSERT INTO sites (site_id, id, name, domain, organization_id, public, "sessionReplay", type, '
            "created_at, updated_at, created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                SITE_IDS[key],
                P + "site" + key,
                "parity-admin " + key,
                domain,
                creds["orgs"][org] if org else None,
                public,
                replay,
                site_type,
                f"2026-06-{10 + index:02d} 07:30:00.25",
                f"2026-06-{10 + index:02d} 07:30:00.25",
                creds["users"]["ownerA"],
            ),
        )

    for user, org, role, restricted in [
        ("ownerA", "A", "owner", False),
        ("adminA", "A", "admin", False),
        ("memberA", "A", "member", False),
        ("restrictedA", "A", "member", True),
        ("ownerB", "B", "owner", False),
        ("sysadmin", "C", "owner", False),
        ("ownerA", "D", "owner", False),
        ("adminA", "E", "owner", False),
        ("ownerB", "F", "owner", False),
    ]:
        member_id = f"{P}m-{user}-{org}"
        cur.execute(
            'INSERT INTO member (id, "organizationId", "userId", role, "createdAt", has_restricted_site_access) '
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (member_id, creds["orgs"][org], creds["users"][user], role, "2026-05-02 09:00:00", restricted),
        )
    cur.execute(
        "INSERT INTO member_site_access (member_id, site_id, created_at) VALUES (%s, %s, %s)",
        (f"{P}m-restrictedA-A", SITE_IDS["a3"], "2026-05-02 09:00:00"),
    )

    for key, site, goal_type, config in GOALS:
        site_id = site if isinstance(site, int) else SITE_IDS[site]
        cur.execute(
            "INSERT INTO goals (site_id, name, goal_type, config, created_at) VALUES (%s,%s,%s,%s::jsonb,%s) "
            "RETURNING goal_id",
            (site_id, P + key, goal_type, json.dumps(config), "2026-07-01 00:00:00"),
        )
        creds["goals"][key] = cur.fetchone()[0]

    cur.execute(
        "INSERT INTO funnels (site_id, user_id, data, created_at, updated_at) VALUES (%s,%s,%s::jsonb,%s,%s)",
        (SITE_IDS["a1"], creds["users"]["ownerA"], json.dumps({"steps": []}), "2026-07-01 00:00:00", "2026-07-01 00:00:00"),
    )

    for index, (key, site, flag_key, flag_type, extras) in enumerate(FLAGS):
        site_id = site if isinstance(site, int) else SITE_IDS[site]
        cur.execute(
            "INSERT INTO feature_flags (site_id, key, description, enabled, runtime, flag_type, payload, variants, "
            "rollout_percentage, rules, condition_sets, salt, version, created_at, updated_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s) RETURNING flag_id",
            (
                site_id,
                flag_key,
                extras.get("description"),
                extras.get("enabled", False),
                extras.get("runtime", "client"),
                flag_type,
                json.dumps(extras["payload"]) if "payload" in extras else None,
                json.dumps(extras.get("variants", [])),
                extras.get("rolloutPercentage", 100),
                json.dumps(extras.get("rules", [])),
                json.dumps(extras.get("conditionSets", [])),
                f"{P}salt{index}",
                1,
                f"2026-07-{10 + index:02d} 00:00:00.125",
                f"2026-07-{10 + index:02d} 00:00:00.125",
            ),
        )
        creds["flags"][key] = cur.fetchone()[0]

    for index, (key, site, flag, goal, status) in enumerate(EXPERIMENTS):
        site_id = site if isinstance(site, int) else SITE_IDS[site]
        cur.execute(
            "INSERT INTO experiments (site_id, feature_flag_id, primary_goal_id, name, description, hypothesis, "
            "status, winning_variant, started_at, ended_at, created_at, updated_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING experiment_id",
            (
                site_id,
                creds["flags"][flag],
                creds["goals"][goal] if goal else None,
                P + key,
                "description " + key,
                "hypothesis " + key,
                status,
                None,
                "2026-08-01 00:00:00" if status == "running" else None,
                None,
                f"2026-08-{10 + index:02d} 00:00:00.75",
                f"2026-08-{10 + index:02d} 00:00:00.75",
            ),
        )
        creds["experiments"][key] = cur.fetchone()[0]

    session_users = dict(creds["users"])
    session_users.update(REAL_USERS)
    for name, uid in session_users.items():
        token = "patok" + name
        cur.execute(
            'INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId") '
            "VALUES (%s, date_trunc('milliseconds', (now() AT TIME ZONE 'utc') + interval '6 days 20 hours'), %s, "
            "now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc', '', 'parity', %s)",
            (P + "s-" + name, token, uid),
        )
        creds["sessions"][name] = f"{COOKIE}={sign(token)}"

    keys = [
        ("orgA", "org", creds["orgs"]["A"], None),
        ("orgA_flags_read", "org", creds["orgs"]["A"], {"flags": ["read"]}),
        ("orgA_flags_write", "org", creds["orgs"]["A"], {"flags": ["write"]}),
        ("orgA_exp_read", "org", creds["orgs"]["A"], {"experiments": ["read"]}),
        ("orgA_exp_write", "org", creds["orgs"]["A"], {"experiments": ["write"]}),
        ("orgA_wrong", "org", creds["orgs"]["A"], {"funnels": ["read"]}),
        ("orgB", "org", creds["orgs"]["B"], None),
        ("kbOrg", "org", REAL_ORG, None),
        ("kbOrg_exp_read", "org", REAL_ORG, {"experiments": ["read"]}),
        ("kbOrg_flags_read", "org", REAL_ORG, {"flags": ["read"]}),
        ("sysadmin", "default", creds["users"]["sysadmin"], None),
        ("memberA", "default", creds["users"]["memberA"], None),
        ("adminA", "default", creds["users"]["adminA"], None),
        ("outsider", "default", creds["users"]["outsider"], None),
    ]
    for name, config, ref, perms in keys:
        key = "pakey_" + name + "_z7Q1"
        cur.execute(
            'INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, permissions, "createdAt", "updatedAt") '
            "VALUES (%s, 'parity', %s, %s, %s, true, %s, (now() AT TIME ZONE 'utc') - interval '2 hours', "
            "(now() AT TIME ZONE 'utc') - interval '2 hours')",
            (P + "k-" + name, hash_key(key), ref, config, json.dumps(perms) if perms is not None else None),
        )
        creds["keys"][name] = key

    return creds


def setup_events():
    """The ClickHouse rows the experiment results endpoint reads. Replaces whatever
    is there for these Site ids, so re-running it never doubles the counts."""
    cleanup_clickhouse()
    rows = clickhouse_events()
    body = "\n".join(json.dumps(row) for row in rows) + "\n"
    clickhouse("INSERT INTO events FORMAT JSONEachRow", body)


def setup(cur):
    creds = setup_principals(cur)
    setup_events()
    return creds


def main():
    connection = conn()
    connection.autocommit = True
    cur = connection.cursor()
    if sys.argv[1] == "setup":
        json.dump(setup(cur), sys.stdout, indent=1)
    else:
        cleanup(cur)
        cleanup_clickhouse()
        print("cleaned", file=sys.stderr)


if __name__ == "__main__":
    main()
