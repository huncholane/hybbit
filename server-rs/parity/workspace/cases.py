"""Request cases for the workspace routes. Each case: route label, method, path (may
hold {fixtureKey} placeholders), headers, body bytes, write flag (fresh fixtures and
a row comparison) and limited flag (limiter keys reset before each request)."""
import json

from hw import CREDS, O, P, S

SESS = CREDS["sessions"]
KEYS = CREDS["keys"]


def caller(name):
    """Auth headers and an optional query suffix for a caller label."""
    if name == "anon":
        return [], ""
    kind, _, who = name.partition(":")
    if kind == "s":
        return [("Cookie", SESS[who])], ""
    if kind == "k":
        return [("Authorization", "Bearer " + KEYS[who])], ""
    if kind == "q":
        return [], "api_key=" + KEYS[who]
    return {
        "mix:memberA1+sysadmin": ([("Authorization", "Bearer " + KEYS["memberA1"]), ("Cookie", SESS["sysadmin"])], ""),
        "mix:adminA+memberA1": ([("Authorization", "Bearer " + KEYS["adminA"]), ("Cookie", SESS["memberA1"])], ""),
        "link:A1": ([("x-private-key", "pwlinkA1secret")], ""),
        "link:bad": ([("x-private-key", "nope")], ""),
        "bad:key": ([("Authorization", "Bearer pwkey_not_real")], ""),
    }[name]


ALL_CALLERS = [
    "anon", "s:ownerA", "s:adminA", "s:memberA1", "s:memberA2", "s:restrictedA", "s:ownerB", "s:nobody", "s:sysadmin",
    "s:huncho", "s:justin", "s:adminHygo", "k:orgA", "k:orgA_segread", "k:orgA_sql", "k:orgA_write", "k:orgA_none",
    "k:orgB", "k:orgKb", "k:orgKb_sql", "k:memberA1", "k:memberA1_segread", "k:memberA2", "k:adminA", "k:restrictedA",
    "k:sysadmin", "k:justin", "q:orgA", "q:memberA1", "mix:memberA1+sysadmin", "mix:adminA+memberA1", "link:A1",
    "link:bad", "bad:key",
]
WRITE_CALLERS = [
    "anon", "s:ownerA", "s:adminA", "s:memberA1", "s:memberA2", "s:restrictedA", "s:ownerB", "s:sysadmin", "s:justin",
    "k:orgA", "k:orgA_write", "k:orgA_segread", "k:memberA1", "k:adminA", "mix:memberA1+sysadmin", "link:A1",
]
SITE_PARAMS = [str(S["A1"]), str(S["A2"]), str(S["A3"]), str(S["B1"]), "1", "5", P + "siteA1", "0x65", "1.01e2", "101abc", ""]
JSON_CT = [("Content-Type", "application/json")]


def jbody(value):
    return json.dumps(value, ensure_ascii=False).encode()


def make(route, method, path, who, body=None, content_type=JSON_CT, write=False, limited=False, extra=None, query=""):
    headers, auth_query = caller(who)
    parts = [part for part in (query, auth_query) if part]
    separator = "&" if "?" in path else "?"
    full = path + (separator + "&".join(parts) if parts else "")
    hdrs = list(headers) + (list(extra) if extra else [])
    if body is not None and content_type:
        hdrs += content_type
    return {"route": route, "method": method, "path": full, "headers": hdrs, "body": body, "write": write, "limited": limited, "who": who}


F = [{"parameter": "country", "type": "equals", "value": ["DE"]}]


def segment_cases():
    cases = []
    for site in SITE_PARAMS:
        for who in ALL_CALLERS:
            cases.append(make("GET segments", "GET", f"/api/sites/{site}/segments", who))
    for site in [str(S["A1"]), str(S["A2"]), str(S["B1"])]:
        for seg in ["{segA1m1}", "{segA1m2pub}", "{segOrgAadmin}", "{segOrgAownerPriv}", "{segA2m1pub}", "{segB1}",
                    "{segNullUser}", "{segA3restricted}", "2000000000", "abc", "0", "2147483648", ""]:
            for who in ["anon", "s:memberA1", "s:adminA", "s:restrictedA", "s:ownerB", "s:sysadmin", "k:orgA",
                        "k:orgA_none", "k:orgB", "k:memberA1_segread", "link:A1", "mix:memberA1+sysadmin"]:
                cases.append(make("GET segment", "GET", f"/api/sites/{site}/segments/{seg}", who))
    for query in ["segment_id={segA1m1}", "segment_id=abc", "start_date=2026-01-01", "segment_id={segB1}", "segment_id={segA1m2pub}"]:
        for who in ["s:memberA1", "anon", "k:orgA_none", "link:A1"]:
            cases.append(make("GET segments", "GET", f"/api/sites/{S['A1']}/segments", who, query=query))
    cases.append(make("HEAD segments", "HEAD", f"/api/sites/{S['A1']}/segments", "s:memberA1"))

    bodies = [
        {"name": P + "new", "filters": F},
        {"name": P + "new pub", "filters": F, "isPublic": True},
        {"name": P + "new org", "filters": F, "scope": "organization"},
        {"name": P + "new site", "filters": F, "scope": "site", "description": "  hello  "},
        {"name": "   ", "filters": F},
        {"name": P + "n" * 81, "filters": F},
        {"name": P + "empty", "filters": []},
        {"name": P + "many", "filters": [{"parameter": "browser", "type": "equals", "value": [f"b{i}"]} for i in range(21)]},
        {"name": P + "badparam", "filters": [{"parameter": "session_id", "type": "equals", "value": ["x"]}]},
        {"name": P + "badregex", "filters": [{"parameter": "pathname", "type": "regex", "value": ["(unclosed"]}]},
        {"name": P + "strict", "filters": F, "siteId": 4},
        [], "str", None, 5,
        {"name": P + "nums", "filters": [{"parameter": "country", "type": "equals", "value": ["DE", 1.5, 1e21, 0.1]}]},
        {"name": P + "latword", "filters": [{"parameter": "lat", "type": "equals", "value": ["north"]}]},
        {"name": P + "nulldesc", "filters": F, "description": None},
        {"name": P + "pubstr", "filters": F, "isPublic": "yes"},
        {"name": P + "objval", "filters": [{"parameter": "browser", "type": "equals", "value": [{"name": "Chrome"}]}]},
        {"name": P + "ünïcødé 🚀", "filters": F},
        {"name": P + "longdesc", "filters": F, "description": "d" * 501},
        {"name": P + "values51", "filters": [{"parameter": "country", "type": "equals", "value": [f"v{i}" for i in range(51)]}]},
        {"name": P + "ctl", "filters": [{"parameter": "country", "type": "equals", "value": ["a\u0000b \"\\"]}]},
        {"name": P + "flag", "filters": [{"parameter": "feature_flag:new-checkout", "type": "equals", "value": ["true"]},
                                         {"parameter": "user_id", "type": "is_null", "value": []}], "scope": "site"},
        {"name": 5, "filters": "x", "scope": "team", "isPublic": 1, "description": 7},
    ]
    for body in bodies:
        for who in WRITE_CALLERS:
            cases.append(make("POST segments", "POST", f"/api/sites/{S['A1']}/segments", who, jbody(body), write=True))
    for who in ["s:justin", "s:huncho", "k:orgKb", "s:memberA1"]:
        cases.append(make("POST segments", "POST", "/api/sites/1/segments", who, jbody(bodies[0]), write=True))
        cases.append(make("POST segments", "POST", f"/api/sites/{S['A2']}/segments", who, jbody(bodies[2]), write=True))
    raw_bodies = [
        (b"", None), (b'{"name":"x"}', [("Content-Type", "text/plain")]), (b"{not json", JSON_CT), (b"", JSON_CT),
        (b'{"__proto__":{"a":1},"name":"x"}', JSON_CT), (b"<x/>", [("Content-Type", "application/xml")]),
        (b'{"name":"parity-workspace-body","filters":[]}', None), (b"\xef\xbb\xbfnull", JSON_CT),
        (b'{"constructor":{"prototype":{}}}', JSON_CT), (b"[" * 5000 + b"]" * 5000, JSON_CT),
        (b'{"name":"parity-workspace-dup","name":"parity-workspace-dup2","filters":[{"parameter":"country","type":"equals","value":["\\ud800"]}]}', JSON_CT),
        (b'{"name":"parity-workspace-big","filters":[{"parameter":"lat","type":"greater_than","value":[1e400]}]}', JSON_CT),
    ]
    for raw, ct in raw_bodies:
        for who in ["s:memberA1", "anon"]:
            cases.append(make("POST segments", "POST", f"/api/sites/{S['A1']}/segments", who, raw, content_type=ct, write=True))

    updates = [
        {"name": P + "renamed"}, {"isPublic": True}, {"scope": "organization"}, {"scope": "site"}, {"filters": []}, {},
        {"description": None}, {"foo": 1}, {"filters": F, "name": P + "all", "description": "x", "isPublic": False},
        None, {"name": ""}, {"filters": [{"parameter": "nope", "type": "equals", "value": ["x"]}]},
    ]
    for seg in ["{segA1m1}", "{segA1m2pub}", "{segOrgAadmin}", "{segNullUser}"]:
        for body in updates:
            for who in ["anon", "s:memberA1", "s:memberA2", "s:adminA", "s:sysadmin", "k:orgA", "k:memberA1", "mix:memberA1+sysadmin"]:
                cases.append(make("PUT segment", "PUT", f"/api/sites/{S['A1']}/segments/{seg}", who, jbody(body), write=True))
    for seg in ["{segA2m1pub}", "2000000000", "abc", "{segB1}", "2147483648"]:
        cases.append(make("PUT segment", "PUT", f"/api/sites/{S['A1']}/segments/{seg}", "s:adminA", jbody(updates[0]), write=True))
    for seg in ["{segA1m1}", "{segA1m2pub}", "{segOrgAadmin}", "{segOrgAownerPriv}", "{segA2m1pub}", "{segNullUser}", "{segB1}", "2000000000", "x"]:
        for who in WRITE_CALLERS:
            cases.append(make("DELETE segment", "DELETE", f"/api/sites/{S['A1']}/segments/{seg}", who, write=True))
    cases.append(make("DELETE segment", "DELETE", f"/api/sites/{S['A1']}/segments/{{segA1m1}}", "s:memberA1", b"{}", write=True))
    cases.append(make("DELETE segment", "DELETE", f"/api/sites/{S['A1']}/segments/{{segA1m1}}", "s:memberA1", b"", write=True))
    return cases


def annotation_cases():
    cases = []
    queries = ["", "start_date=2026-08-01", "end_date=2026-08-31", "start_date=2026-08-01&end_date=2026-08-31",
               "start_date=2026-08-31&end_date=2026-08-01", "start_date=2026-13-01",
               "start_date=2026-08-01&time_zone=America/New_York", "end_date=2026-08-24&time_zone=Pacific/Kiritimati",
               "time_zone=Not/AZone", "start_date=2026-08-01&start_date=2026-08-02", "start_date=&end_date=",
               "time_zone=utc&start_date=2026-09-01&end_date=2026-09-01", "start_date=0050-01-01",
               "segment_id=abc", "end_date=2026-09-01&time_zone=%2B05:30", "start_date=2026-07-31&time_zone=Asia/Kolkata",
               "start_date=2026-03-08&end_date=2026-03-08&time_zone=america/new_york", "time_zone=",
               "start_date=2026-09-03&time_zone=Australia/Lord_Howe", "end_date=2026-08-26&time_zone=-03"]
    for site in [str(S["A1"]), str(S["A2"]), str(S["B1"]), "1", "5", P + "siteA1", ""]:
        for who in ALL_CALLERS:
            cases.append(make("GET annotations", "GET", f"/api/sites/{site}/annotations", who))
    for query in queries:
        for who in ["anon", "s:memberA1", "s:restrictedA", "k:orgA_segread", "link:A1"]:
            for site in [str(S["A1"]), str(S["A2"])]:
                cases.append(make("GET annotations", "GET", f"/api/sites/{site}/annotations", who, query=query))

    bodies = [
        {"title": P + "t", "date": "2026-08-18"},
        {"title": P + "full", "date": "2026-08-18", "endDate": "2026-08-19T10:00:00+02:00", "color": "rose", "icon": "🔥", "isPublic": True, "description": "  d "},
        {"title": P + "org", "date": "2026-08-18", "scope": "organization"},
        {"title": P + "offset", "date": "2026-08-24T16:10:00.5+0200"},
        {"title": P + "feb30", "date": "2026-02-30"},
        {"title": P + "nooffset", "date": "2026-08-18T14:10:00"},
        {"title": P + "reversed", "date": "2026-08-14", "endDate": "2026-08-11"},
        {"title": P + "same", "date": "2026-08-14", "endDate": "2026-08-14T00:00:00Z"},
        {"title": "", "date": "2026-08-18"}, {"title": P + "t" * 121, "date": "2026-08-18"},
        {"title": P + "c", "date": "2026-08-18", "color": "emerald"}, {"title": P + "i", "date": "2026-08-18", "icon": "ab"},
        {"title": P + "fam", "date": "2026-08-18", "icon": "👨‍👩‍👧"}, {"title": P + "noicon", "date": "2026-08-18", "icon": ""},
        {"title": P + "longicon", "date": "2026-08-18", "icon": "x" * 17},
        {"title": P + "pubstr", "date": "2026-08-18", "isPublic": "true"},
        {"title": P + "team", "date": "2026-08-18", "scope": "team"},
        {"title": P + "nulls", "date": "2026-08-18", "description": None, "endDate": None, "color": None, "icon": None},
        [], None, "text",
        {"title": P + "trim", "date": " 2026-08-18 "}, {"title": P + "y50", "date": "0050-01-01"},
        {"title": P + "far", "date": "9999-12-31T23:59:59-14:00"}, {"title": P + "foo", "date": "2026-08-18", "foo": 1},
        {"title": P + "num", "date": 12345}, {"title": P + "flag🇺🇸", "date": "2026-08-18", "icon": "🇺🇸"},
        {"date": "2026-08-18"}, {"title": P + "hour", "date": "2026-08-18T24:00Z"},
        {"title": 5, "description": 6, "date": None, "endDate": 7, "color": 8, "icon": 9, "isPublic": 10, "scope": 11},
    ]
    for body in bodies:
        for who in ["anon", "s:memberA1", "s:adminA", "s:restrictedA", "k:orgA", "k:orgA_write", "k:orgA_segread", "k:memberA1", "link:A1", "s:sysadmin"]:
            cases.append(make("POST annotations", "POST", f"/api/sites/{S['A1']}/annotations", who, jbody(body), write=True))
    for who in ["s:justin", "s:memberA1", "s:restrictedA", "mix:memberA1+sysadmin"]:
        cases.append(make("POST annotations", "POST", f"/api/sites/{S['A3']}/annotations", who, jbody(bodies[2]), write=True))

    updates = [
        {}, {"foo": 1}, {"title": P + "renamed"}, {"date": "2026-09-30"}, {"endDate": None}, {"endDate": "2026-01-01"},
        {"scope": "organization"}, {"scope": "site"}, {"icon": ""}, {"isPublic": True, "color": "violet"},
        {"description": "  x  "}, {"date": "bad"}, None, {"date": "2026-08-25", "endDate": "2026-08-25T00:00:00.001Z"},
    ]
    for ann in ["{annA1m1}", "{annA1m2pub}", "{annOrgA}", "{annNullUser}"]:
        for body in updates:
            for who in ["anon", "s:memberA1", "s:memberA2", "s:adminA", "k:orgA", "mix:memberA1+sysadmin"]:
                cases.append(make("PUT annotation", "PUT", f"/api/sites/{S['A1']}/annotations/{ann}", who, jbody(body), write=True))
    for ann in ["{annA2pub}", "{annB1}", "2000000000", "0x1", "99999999999", ""]:
        cases.append(make("PUT annotation", "PUT", f"/api/sites/{S['A1']}/annotations/{ann}", "s:adminA", jbody(updates[2]), write=True))
    for ann in ["{annA1m1}", "{annA1m2pub}", "{annOrgA}", "{annOrgApriv}", "{annA2pub}", "{annNullUser}", "{annB1}", "2000000000", "-1"]:
        for who in WRITE_CALLERS:
            cases.append(make("DELETE annotation", "DELETE", f"/api/sites/{S['A1']}/annotations/{ann}", who, write=True))
    return cases


CARD = {"id": "c1", "title": "t", "sql": "SELECT 1", "vizType": "table", "mapping": {"yColumns": ["a"], "extra": 1},
        "gridPos": {"x": 0, "y": 1, "w": 0.5, "h": 2}, "zzz": True}


def dashboard_cases():
    cases = []
    for site in SITE_PARAMS:
        for who in ALL_CALLERS:
            cases.append(make("GET dashboards", "GET", f"/api/sites/{site}/dashboards", who, limited=True))
    for dash in ["{dashA1m1}", "{dashA1old}", "{dashA2}", "{dashB1}", "{dashNoSite}", "2000000000", "run-card", "0x1",
                 "2147483648", "", "abc", "1" * 1501]:
        for who in ["anon", "s:memberA1", "s:adminA", "s:sysadmin", "k:orgA", "k:orgA_sql", "k:orgA_segread", "link:A1"]:
            cases.append(make("GET dashboard", "GET", f"/api/sites/{S['A1']}/dashboards/{dash}", who, limited=True))
    cases.append(make("HEAD dashboards", "HEAD", f"/api/sites/{S['A1']}/dashboards", "s:memberA1", limited=True))

    card_types = [dict(CARD, id=f"c{i}", vizType=viz) for i, viz in enumerate(["table", "line", "area", "bar", "hbar", "pie", "stat", "map", "calendar"])]
    bodies = [
        {"name": P + "d"}, {"name": P + "cfg", "config": {"cards": [CARD]}}, {"name": P + "alltypes", "config": {"cards": card_types}},
        {"name": P + "many", "config": {"cards": [dict(CARD, id=f"c{i}") for i in range(21)]}},
        {"name": P + "missing", "config": {"cards": [{"id": ""}]}}, {"name": P + "viz", "config": {"cards": [dict(CARD, vizType="donut")]}},
        {"name": ""}, {}, {"name": P + "nullcfg", "config": None}, {"name": P + "cardsstr", "config": {"cards": "x"}},
        {"name": P + "extra", "other": 1, "config": {"cards": [], "more": 2}}, [], None,
        {"name": P + "ctl", "config": {"cards": [dict(CARD, title="a\u0000  ")]}},
        {"name": P + "fmt", "config": {"cards": [dict(CARD, mapping={"valueFormat": "bytes", "xColumn": "x", "seriesColumn": "s", "countryColumn": "c", "dateColumn": "d", "valueColumn": "v"})]}},
        {"name": P + "badfmt", "config": {"cards": [dict(CARD, mapping={"valueFormat": "kb", "yColumns": [1]})]}},
        {"name": 7},
    ]
    for body in bodies:
        for who in ["anon", "s:memberA1", "s:sysadmin", "k:orgA", "k:orgA_write", "k:orgA_sql", "link:A1"]:
            cases.append(make("POST dashboards", "POST", f"/api/sites/{S['A1']}/dashboards", who, jbody(body), write=True))
    big = b'{"name":"parity-workspace-big","config":{"cards":[{"id":"c","title":"t","sql":"s","vizType":"table","mapping":{},"gridPos":{"x":1e400,"y":-0.0,"w":1e21,"h":123456789012345678901}}]}}'
    cases.append(make("POST dashboards", "POST", f"/api/sites/{S['A1']}/dashboards", "s:memberA1", big, write=True))
    updates = [{}, {"name": ""}, {"name": P + "r"}, {"config": {"cards": [CARD]}}, {"config": {"cards": 5}}, None, {"name": P + "both", "config": {"cards": []}}]
    for dash in ["{dashA1m1}", "{dashA2}", "{dashNoSite}", "2000000000", "run-card"]:
        for body in updates:
            for who in ["anon", "s:memberA2", "k:orgA_write", "k:orgA_sql"]:
                cases.append(make("PUT dashboard", "PUT", f"/api/sites/{S['A1']}/dashboards/{dash}", who, jbody(body), write=True))
    for dash in ["{dashA1m1}", "{dashA1old}", "{dashA2}", "{dashB1}", "2000000000", "run-card", ""]:
        for who in ["anon", "s:memberA1", "s:memberA2", "k:orgA_write", "k:orgA_sql", "k:orgB"]:
            cases.append(make("DELETE dashboard", "DELETE", f"/api/sites/{S['A1']}/dashboards/{dash}", who, write=True))
    return cases


CARD_QUERIES = [
    {"query": "SELECT count() AS c FROM scoped_events"},
    {"query": "SELECT toStartOfInterval(toTimeZone(timestamp, {{tz}}), INTERVAL {{bucket}}) b, count() c FROM scoped_events GROUP BY b ORDER BY b",
     "bucket": "day", "startDate": "2026-09-01", "endDate": "2026-09-10", "timeZone": "America/New_York"},
    {"query": "SELECT toStartOfInterval(timestamp, INTERVAL {{ BUCKET }}) b, count() c FROM scoped_events GROUP BY b ORDER BY b LIMIT 5",
     "startDateTime": "2026-09-01 00:00:00", "endDateTime": "2026-09-02 00:00:00"},
    {"query": "SELECT count() c FROM scoped_events", "pastMinutesStart": 600000, "pastMinutesEnd": 0},
    {"query": "SELECT count() c FROM scoped_events", "startDate": "2026-09-01"},
    {"query": "SELECT count() c FROM scoped_events", "startDate": "2026-02-30", "endDate": "2026-03-01"},
    {"query": "SELECT count() c FROM scoped_events", "startDateTime": "2026-09-02 00:00:00", "endDateTime": "2026-09-01 00:00:00"},
    {"query": "SELECT 1", "bucket": "decade"}, {"query": ""}, {"query": "DROP TABLE events"}, {"query": "SELECT * FROM events"},
    {"query": "SELECT 1 FROM scoped_events " + "x" * 20001}, {"query": 5}, [], None,
    {"query": "SELECT nonexistent FROM scoped_events"},
    {"query": "SELECT pathname, count() c FROM scoped_events GROUP BY pathname ORDER BY c DESC, pathname LIMIT 5"},
    {"query": "SELECT 1/3 AS f, toUInt64(18446744073709551615) AS big, toDecimal64(1.5, 2) d, [1,2] arr, map('a',1) m, NULL n, nan AS x, inf AS y, 'ü🚀\\0' s, toDateTime('2026-01-01 00:00:00') t, toFloat32(0.1) f32, 1e21 e FROM scoped_events LIMIT 1"},
    {"query": "SELECT count() c FROM scoped_events", "timeZone": ""}, {"query": "SELECT count() c FROM scoped_events", "timeZone": "Not/AZone"},
    {"query": "SELECT 1 AS one FROM scoped_events LIMIT 1;;"}, {"query": "SELECT count() c FROM scoped_events", "pastMinutesStart": "60", "pastMinutesEnd": 0},
    {"query": "SELECT count() c FROM scoped_events", "pastMinutesStart": 1, "pastMinutesEnd": 5},
    {"query": "SELECT * FROM scoped_events WHERE site_id = 2 ORDER BY timestamp_ms, session_id LIMIT 2"},
    {"query": "WITH x AS (SELECT count() c FROM scoped_events) SELECT * FROM x"},
    {"query": "SELECT * FROM system.tables"}, {"query": "SELECT hostName() h FROM scoped_events LIMIT 1"},
    {"query": "SELECT sleepEachRow(3) FROM scoped_events LIMIT 4"},
    {"query": "SELECT count() FROM scoped_events", "startDate": "2026-09-01", "endDate": "2026-09-01", "timeZone": "+05:30"},
    {"query": "SELECT toTimeZone(timestamp, {{tz}}) FROM scoped_events ORDER BY timestamp_ms, session_id LIMIT 1", "timeZone": "Europe/Berlin"},
    {"query": "SELECT count() FROM scoped_events SETTINGS max_result_rows = 0"},
    {"query": "SELECT number FROM numbers(5)"},
    {"query": "SELECT * FROM url('http://127.0.0.1:1/', CSV, 'a String')"},
    {"query": "SELECT throwIf(1) FROM scoped_events LIMIT 1"},
    {"query": "SELECT arrayJoin(range(1500)) n FROM scoped_events LIMIT 1 BY site_id"},
]


def custom_sql_cases():
    cases = []
    for body in CARD_QUERIES:
        for who in ["anon", "s:huncho", "s:justin", "k:orgKb", "k:justin", "k:orgKb_sql", "s:memberA1"]:
            for site in ["1", "2", str(S["A1"])]:
                cases.append(make("POST run-card", "POST", f"/api/sites/{site}/dashboards/run-card", who, jbody(body), limited=True))
    for who in ALL_CALLERS:
        cases.append(make("POST run-card", "POST", "/api/sites/1/dashboards/run-card", who, jbody(CARD_QUERIES[0]), limited=True))
    queries = [dict(q) for q in CARD_QUERIES if isinstance(q, dict)]
    extras = [{"query": "SELECT count() c FROM scoped_events", "siteId": 1}, {"query": "SELECT count() c FROM scoped_events", "siteId": 101},
              {"query": "SELECT count() c FROM scoped_events", "siteId": 1.5}, {"query": "SELECT count() c FROM scoped_events", "siteId": "1"},
              {"query": "SELECT count() c FROM scoped_events", "siteId": -1}, {"query": "SELECT count() c FROM scoped_events", "siteId": 0},
              {"query": "SELECT site_id, count() c FROM scoped_events GROUP BY site_id ORDER BY site_id"}, {"siteId": 1}]
    for body in queries + extras + [[], None]:
        for who in ["anon", "s:huncho", "s:justin", "k:orgKb", "k:orgKb_sql", "k:justin", "k:orgA_sql", "s:nobody"]:
            cases.append(make("POST query", "POST", f"/api/organizations/{O['kb']}/analytics/query", who, jbody(body), limited=True))
    for org in [O["A"], O["B"], O["testorg"], "nonexistent-org"]:
        for who in ALL_CALLERS:
            cases.append(make("POST query", "POST", f"/api/organizations/{org}/analytics/query", who, jbody(extras[6]), limited=True))
    gen_bodies = [{}, {"prompt": "count events"}, {"prompt": "x", "currentSiteId": 1}, {"prompt": "x", "currentSiteId": 101},
                  {"prompt": "x", "history": [{"role": "user", "content": "a"}, {"role": "assistant", "content": "SELECT 1"}]},
                  {"prompt": "p" * 4001}, {"prompt": "x", "history": [{"role": "user", "content": "a"}] * 13},
                  {"prompt": "x", "history": [{"role": "bot", "content": "a"}]}, {"prompt": " "}, {"prompt": "x", "currentQuery": 5},
                  {"prompt": "x", "currentSiteId": 2.5}, [], None]
    for body in gen_bodies:
        for who in ["anon", "s:huncho", "s:justin", "k:orgKb", "k:orgKb_sql", "k:orgA_sql", "s:memberA1"]:
            for org in [O["kb"], O["A"]]:
                cases.append(make("POST generate", "POST", f"/api/organizations/{org}/analytics/query/generate", who, jbody(body), limited=True))
    return cases


def misc_cases():
    cases = []
    trusted = [("Origin", "https://a.hygo.ai")]
    evil = [("Origin", "https://evil.example")]
    for origin in (trusted, evil):
        cases.append(make("GET segments", "GET", f"/api/sites/{S['A1']}/segments", "s:memberA1", extra=origin))
        cases.append(make("POST segments", "POST", f"/api/sites/{S['A1']}/segments", "s:memberA1", jbody({"name": P + "o", "filters": F}), extra=origin, write=True))
        cases.append(make("POST query", "POST", f"/api/organizations/{O['kb']}/analytics/query", "s:justin", jbody({"query": "SELECT 1 AS one FROM scoped_events LIMIT 1"}), extra=origin, limited=True))
    for path in [f"/api/sites/{S['A1']}/segments/", f"/api/sites/{S['A1']}/dashboards/", "/api/sites//segments", "/api/sites//dashboards",
                 f"/api/sites/{S['A1']}/annotations/", f"/api/sites/{S['A1']}/segments/%2F", "/api/sites/%31%30%31/segments",
                 f"/api/sites/{S['A1']}/segments/1%2501", f"/api/sites/{S['A1']}/segments/%zz", "/api/sites/101/segments/" + "9" * 1500,
                 "/api/sites/101/segments/" + "9" * 1501, "/api/organizations//analytics/query", "/api/organizations/%E2%9C%93/analytics/query"]:
        for method in ["GET", "PUT", "DELETE", "POST"]:
            cases.append(make("routing", method, path, "s:memberA1", jbody({}) if method in ("PUT", "POST") else None, write=method != "GET", limited=True))
    cases.append(make("routing", "GET", "/api/organizations/x/analytics/query", "s:justin"))
    cases.append(make("routing", "GET", f"/api/sites/{S['A1']}/annotations/1", "s:justin"))
    cases.append(make("POST query", "POST", f"/api/organizations/{O['kb']}/analytics/query", "k:orgKb", jbody({"query": "SELECT 1 AS one FROM scoped_events LIMIT 1"}),
                      extra=[("X-Forwarded-For", " 8.8.8.8 , 1.1.1.1")], limited=True))
    return cases


def all_cases():
    return segment_cases() + annotation_cases() + dashboard_cases() + custom_sql_cases() + misc_cases()
