#!/usr/bin/env python3
"""Session replay parity: the record route, then the list, events and delete routes,
against Node and Rust sharing the parity stores.

Record: every case goes to Node on one twin Site and to Rust on its identically
configured twin, so each backend's rows can be told apart; responses must be
byte-identical and the rows identical after mapping the twin site ids and session
ids (plus a tolerance on timestamps that depend on the server clock). One case goes
to both backends on the same Site to check they land in the same Redis session.

Reads: both backends answer the same requests over the recorded data with every
kind of credential; deletes run on twin sessions.

Usage: run.py [node_url] [rust_url]   (defaults http://127.0.0.1:3001, :3077)
Both backends must run with parity/env.sh. Creates sites 65170-65174, API keys,
sessions and user profiles prefixed parity-replay-, and removes them at the end.
"""
import base64, hashlib, hmac, http.client, json, os, subprocess, sys, time, urllib.parse

NODE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3001"
RUST = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3077"
CLICKHOUSE = ("127.0.0.1", 58123, "default", "hygo")
SECRET = os.environ.get("BETTER_AUTH_SECRET", "parity-local-secret-not-for-production")
ORG = "kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE"
OWNER = "XoNIxodDwuJOefJZebreRpXzn7Sq3hlL"
MEMBER = "ZDZZHJlo6olnWqliEC5t0kHoxcurXqBM"
STRANGER = "GrOwOZVmycGqPD5WD7yIiw4CWBv0dPBa"
SITE_A, SITE_B, SITE_OFF, PUBLIC_A, PUBLIC_B = 65170, 65171, 65172, 65173, 65174
TEST_SITES = [SITE_A, SITE_B, SITE_OFF, PUBLIC_A, PUBLIC_B]
PRIVATE_KEY = "parity-replay-private-link"
VERBOSE = os.environ.get("VERBOSE") == "1"

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"
FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0"
HEADLESS = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"

failures = []


def fail(kind, name, node, rust):
    failures.append((kind, name))
    print(f"{kind} MISMATCH {name}\n  node: {truncate(node)}\n  rust: {truncate(rust)}")


def truncate(value, limit=1500):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit] + f"... ({len(text)} chars)"


# ---------------------------------------------------------------- stores

def psql(sql):
    result = subprocess.run(
        ["psql", "-h", "127.0.0.1", "-p", "55432", "-U", "hygo", "analytics", "-v", "ON_ERROR_STOP=1", "-q", "-t", "-A", "-c", sql],
        env={**os.environ, "PGPASSWORD": "hygo"}, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout


def clickhouse(sql, parse=True):
    host, port, user, password = CLICKHOUSE
    connection = http.client.HTTPConnection(host, port, timeout=600)
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    connection.request("POST", "/?database=analytics&default_format=JSONEachRow", body=sql.encode(),
                       headers={"Authorization": f"Basic {auth}", "User-Agent": "parity-replay-harness"})
    response = connection.getresponse()
    text = response.read().decode("utf-8", "replace")
    if response.status != 200:
        raise RuntimeError(text)
    return [json.loads(line) for line in text.splitlines() if line] if parse else text


def quote(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    return "'" + str(value).replace("'", "''") + "'"


def hashed_key(key):
    return base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()).decode().rstrip("=")


def sign(value):
    signature = base64.b64encode(hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.quote(f"{value}.{signature}", safe="")


def cleanup():
    psql("DELETE FROM user_profiles WHERE site_id IN (%s)" % ",".join(map(str, TEST_SITES)))
    psql("DELETE FROM sites WHERE site_id IN (%s)" % ",".join(map(str, TEST_SITES)))
    psql("DELETE FROM apikey WHERE id LIKE 'parity-replay-%'")
    psql("DELETE FROM session WHERE id LIKE 'parity-replay-%'")
    for table in ("session_replay_events", "session_replay_metadata_v2"):
        clickhouse(f"DELETE FROM {table} WHERE site_id IN ({','.join(map(str, TEST_SITES))})", parse=False)


KEYS = {
    "user-owner": dict(reference=OWNER, config="default", permissions=None),
    "org-replay-read": dict(reference=ORG, config="org", permissions='{"replay":["read"]}'),
    "org-replay-write": dict(reference=ORG, config="org", permissions='{"replay":["write"]}'),
    "org-analytics-only": dict(reference=ORG, config="org", permissions='{"analytics":["read"]}'),
    "org-unrestricted": dict(reference=ORG, config="org", permissions=None),
    "stranger-key": dict(reference=STRANGER, config="default", permissions=None),
}


def setup():
    cleanup()
    exclusions = {
        "excluded_ips": ["198.51.100.0/24"], "excluded_paths": ["/admin/*"], "excluded_hostnames": ["*.vercel.app"],
        "excluded_user_agents": ["HeadlessChrome"], "excluded_countries": ["SE"], "excluded_query_params": ["secret"],
        "excluded_asns": ["AS15169"],
    }
    for site_id, replay, public, proxy, salted, text_id in [
        (SITE_A, True, False, False, False, "parityrpx65170"), (SITE_B, True, False, False, False, "parityrpx65171"),
        (SITE_OFF, False, False, False, False, "parityrpoff172"), (PUBLIC_A, True, True, True, True, "parityrppub173"),
        (PUBLIC_B, True, True, True, True, "parityrppub174"),
    ]:
        columns = {"site_id": site_id, "id": text_id, "name": f"parity replay {site_id}", "domain": "shop.example.com",
                   "organization_id": ORG, "created_by": OWNER, "public": public, '"sessionReplay"': replay,
                   "first_party_proxy": proxy, '"saltUserIds"': salted, '"blockBots"': True, "private_link_key": PRIVATE_KEY}
        values = [quote(v) for v in columns.values()]
        names = list(columns.keys())
        if site_id in (SITE_A, SITE_B):
            for name, value in exclusions.items():
                names.append(name)
                values.append(quote(json.dumps(value)) + "::jsonb")
        psql(f"INSERT INTO sites ({', '.join(names)}) VALUES ({', '.join(values)})")
    for key, spec in KEYS.items():
        psql('INSERT INTO apikey (id, name, key, "referenceId", "configId", enabled, permissions, "createdAt", "updatedAt") VALUES ('
             + ", ".join([quote(f"parity-replay-{key}"), quote("parity"), quote(hashed_key(f"parity-replay-{key}")),
                          quote(spec["reference"]), quote(spec["config"]), "true", quote(spec["permissions"]),
                          "(now() AT TIME ZONE 'utc') - interval '2 hours'", "(now() AT TIME ZONE 'utc') - interval '2 hours'"]) + ")")
    for token, user in [("ownertok", OWNER), ("membertok", MEMBER), ("strangertok", STRANGER)]:
        psql('INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId") VALUES ('
             f"'parity-replay-{token}', date_trunc('milliseconds', (now() AT TIME ZONE 'utc') + interval '6 days 23 hours'), "
             f"'parity-replay-{token}', (now() AT TIME ZONE 'utc') - interval '3 days', (now() AT TIME ZONE 'utc') - interval '3 days', '', 'parity', '{user}')")
    for site_id in (SITE_A, SITE_B, PUBLIC_A, PUBLIC_B):
        psql("INSERT INTO user_profiles (site_id, user_id, traits) VALUES "
             f"({site_id}, 'user-42', '{{\"plan\":\"pro\",\"seats\":3,\"2\":\"two\",\"ratio\":1.5}}'::jsonb), "
             f"({site_id}, 'ユーザー😀', '[1,2]'::jsonb)")


# ---------------------------------------------------------------- http

def send(base, method, path, body=None, headers=None, chunked=False):
    url = urllib.parse.urlparse(base)
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=120)
    headers = dict(headers or {})
    if chunked:
        connection.putrequest(method, path, skip_accept_encoding=True)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders()
        for start in range(0, len(body), 7):
            piece = body[start:start + 7]
            connection.send(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
        connection.send(b"0\r\n\r\n")
    else:
        if body is not None and "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))
        try:
            connection.request(method, path, body=body, headers=headers)
        except (BrokenPipeError, ConnectionResetError):
            # The server answered (413) and closed before the body was sent
            pass
    try:
        response = connection.getresponse()
    except (ConnectionResetError, http.client.RemoteDisconnected) as error:
        return {"status": "connection error", "headers": {}, "body": type(error).__name__}
    raw = response.read()
    wanted = ("content-type", "cache-control", "x-content-type-options", "access-control-allow-origin",
              "access-control-allow-credentials", "retry-after", "allow")
    picked = {name: response.getheader(name) for name in wanted if response.getheader(name) is not None}
    if (response.getheader("connection") or "").lower() == "close":
        picked["connection"] = "close"
    return {"status": response.status, "headers": picked, "body": raw.decode("utf-8", "replace")}


def compare_responses(kind, name, node, rust):
    if node != rust:
        fail(kind, name, node, rust)
        return False
    if VERBOSE:
        print(f"ok {kind} {name}: {node['status']} {truncate(node['body'], 200)}")
    return True


# ---------------------------------------------------------------- recordings

NOW = int(time.time() * 1000)


def full_snapshot(t, title="Parity"):
    return {"type": 2, "data": {"node": {"type": 0, "childNodes": [
        {"type": 1, "name": "html", "publicId": "", "systemId": "", "id": 2},
        {"type": 2, "tagName": "html", "attributes": {"lang": "en"}, "childNodes": [
            {"type": 2, "tagName": "head", "attributes": {}, "childNodes": [
                {"type": 2, "tagName": "title", "attributes": {}, "childNodes": [{"type": 3, "textContent": title, "id": 6}], "id": 5},
                {"type": 2, "tagName": "style", "attributes": {"_cssText": ".a{color:red}\n.b::after{content:\"\\201C\"}"}, "childNodes": [], "id": 7}], "id": 4},
            {"type": 2, "tagName": "body", "attributes": {"class": "home", "data-x": "1"}, "childNodes": [
                {"type": 2, "tagName": "input", "attributes": {"type": "password", "value": "********"}, "childNodes": [], "id": 9},
                {"type": 3, "textContent": "Welcome ✓ … 日本語", "id": 10}], "id": 8}], "id": 3}],
        "compatMode": "CSS1Compat", "id": 1}, "initialOffset": {"left": 0, "top": 0}}, "timestamp": t}


def recording(t0, count=6):
    events = [{"type": 4, "data": {"href": "https://shop.example.com/", "width": 1280, "height": 720}, "timestamp": t0},
              full_snapshot(t0 + 5)]
    kinds = [
        lambda t, i: {"type": 3, "data": {"source": 2, "type": 2, "id": 9, "x": 120.5 + i, "y": 33}, "timestamp": t},
        lambda t, i: {"type": 3, "data": {"source": 3, "id": 1, "x": 0, "y": 1450 * i}, "timestamp": t},
        lambda t, i: {"type": 3, "data": {"source": 5, "text": "*****", "isChecked": False, "id": 9}, "timestamp": t},
        lambda t, i: {"type": 3, "data": {"source": 0, "texts": [{"id": 10, "value": f"tick {i}"}], "attributes": [{"id": 8, "attributes": {"class": None}}],
                                          "removes": [{"parentId": 8, "id": 9}], "adds": [{"parentId": 8, "nextId": None, "node": {"type": 3, "textContent": "Hi 😀", "id": 44 + i}}]}, "timestamp": t},
        lambda t, i: {"type": 5, "data": {"tag": "navigation", "payload": {"path": f"/p/{i}"}}, "timestamp": t},
    ]
    for i in range(count):
        events.append(kinds[i % len(kinds)](t0 + 1000 * (i + 1), i))
    return events


def metadata(case, **overrides):
    value = {"pageUrl": f"https://shop.example.com/parity/{case}?utm_source=newsletter&utm_medium=email",
             "viewportWidth": 1920, "viewportHeight": 1080, "language": "en-US"}
    value.update(overrides)
    return {k: v for k, v in value.items() if v is not ...}


def browser(ip, ua=CHROME, referer="https://www.google.com/", origin="https://shop.example.com", content_type="application/json"):
    headers = {"Content-Type": content_type, "User-Agent": ua, "Accept": "*/*", "Origin": origin,
               "Cf-Connecting-Ip": ip, "X-Forwarded-For": ip, "X-Real-Ip": ip}
    if referer is not None:
        headers["Referer"] = referer
    if ua is None:
        del headers["User-Agent"]
    return {k: v for k, v in headers.items() if v is not None}


CASES = []
_ip_counter = [10]


def next_ip():
    _ip_counter[0] += 1
    return f"73.162.{_ip_counter[0] // 250}.{_ip_counter[0] % 250 + 1}"


def case(name, body=None, raw=None, headers=None, site="twin", path=None, clock=False, chunked=False, method="POST"):
    CASES.append({"name": name, "body": body, "raw": raw, "headers": headers, "site": site, "path": path, "clock": clock,
                  "chunked": chunked, "method": method})


def build_cases():
    ip = next_ip()
    case("full batch, anonymous", {"userId": "", "events": recording(NOW - 60_000), "metadata": metadata("full")}, headers=browser(ip))
    case("second batch, same session", {"userId": "", "events": recording(NOW - 30_000, 4)[2:], "metadata": metadata("second", viewportWidth=1280, viewportHeight=800)},
         headers=browser(ip))
    case("identified user with padding", {"userId": "  user-42  ", "events": recording(NOW - 50_000), "metadata": metadata("identified")},
         headers=browser(next_ip(), SAFARI_MAC, referer="https://shop.example.com/cart"))
    case("events only, no metadata", {"userId": "", "events": recording(NOW - 40_000, 3)}, headers=browser(next_ip(), FIREFOX_LINUX))
    case("metadata only, no events", {"userId": "", "events": [], "metadata": metadata("meta-only")}, headers=browser(next_ip()), clock=True)
    case("no events, no metadata", {"userId": "u-empty", "events": []}, headers=browser(next_ip()))
    unicode_events = recording(NOW - 20_000, 3) + [{"type": 5, "data": {"tag": "ユーザー", "payload": {"emoji": "👩‍👩‍👧", "rtl": "مرحبا", "nul": "a\u0000b", "sep": "\u2028\u2029", "quote": "\"'\\/"}}, "timestamp": NOW - 19_000}]
    case("unicode everywhere", {"userId": "ユーザー😀", "events": unicode_events,
                                "metadata": metadata("unicode", pageUrl="https://例え.jp/パス/ü?q=é&utm_source=ニュース#frag", language="zh-Hant-TW")},
         headers=browser(next_ip(), IPHONE, referer="https://t.co/xyz"))
    lone = ('{"userId":"\\ud83d","events":[{"type":"\\udc00x","data":{"text":"\\ud800 and \\udfff","key\\ud800":["\\ud83d\\ude00","\\uDBFF"]},"timestamp":%d},'
            '{"type":2,"data":{"s":"\\u0041\\u00e9\\u0007\\u001f\\u007f"},"timestamp":%d}],'
            '"metadata":{"pageUrl":"https://shop.example.com/lone/\\ud800?x=\\udc00","viewportWidth":390,"viewportHeight":844,"language":"\\ud800en"}}') % (NOW - 15_000, NOW - 14_000)
    case("lone surrogates in user id, type, url, language, data", raw=lone.encode(), headers=browser(next_ip(), IPHONE))
    numbers = ('{"userId":"","events":[{"type":3.0,"data":{"a":1.0,"b":1e21,"c":-0,"d":1e400,"e":123456789012345678901,"f":5e-324,"g":0.1,"h":-1.5E-7},"timestamp":%d.5},'
               '{"type":3.5,"data":[1E2,-0.0,2e-324],"timestamp":%d},{"type":1e21,"data":0,"timestamp":%d},{"type":2,"data":"5","timestamp":%d}],'
               '"metadata":{"pageUrl":"https://shop.example.com/numbers","viewportWidth":1280.0,"viewportHeight":1e400}}') % (NOW - 12_000, NOW - 11_999, NOW - 11_998, NOW - 11_997)
    case("number spellings", raw=numbers.encode(), headers=browser(next_ip()))
    dupes = ('{"userId":"ignored","events":[{"type":2,"data":1,"timestamp":1}],"userId":"dupe-user",'
             '"events":[{"type":2,"type":3,"data":{"b":1,"10":"ten","2":"two","a":{"x":1,"x":2},"b":3,"01":"zero-one","4294967295":"max"},"timestamp":%d,"data":{"z":0,"1":1,"z":2}},'
             '{"type":2,"data":{"__proto":1,"constructor":{"x":1}},"timestamp":%d}],"metadata":{"pageUrl":"https://shop.example.com/a","pageUrl":"https://shop.example.com/dupes"}}') % (NOW - 9_000, NOW - 8_000)
    case("duplicate and array-index keys", raw=dupes.encode(), headers=browser(next_ip()))
    big_text = ("lorem ipsum dolor sit amet ✓ " * 400)
    big_events = [full_snapshot(NOW - 100_000 + i * 10, title=big_text) for i in range(300)]
    case("large batch (about 4 MB)", {"userId": "", "events": big_events, "metadata": metadata("large")}, headers=browser(next_ip()))
    near = [{"type": 3, "data": {"source": 0, "adds": [{"node": {"textContent": "x" * 9000}}]}, "timestamp": NOW - 90_000 + i} for i in range(1150)]
    near_body = json.dumps({"userId": "", "events": near, "metadata": metadata("near-limit")}, separators=(",", ":")).encode()
    case(f"near the 10 MB limit ({len(near_body)} bytes)", raw=near_body, headers=browser(next_ip()))
    over = json.dumps({"userId": "", "events": [{"type": 3, "data": "y" * (10 * 1024 * 1024), "timestamp": NOW}]}).encode()
    case("over the 10 MB limit", raw=over, headers=browser(next_ip()))
    deep = '{"userId":"","events":[{"type":2,"data":%s0%s,"timestamp":%d}],"metadata":{"pageUrl":"https://shop.example.com/deep"}}' % ("[" * 3000, "]" * 3000, NOW - 7_000)
    case("data nested 3000 levels", raw=deep.encode(), headers=browser(next_ip()))
    case("skewed device clock, 2090", {"userId": "", "events": recording(3_802_000_000_000, 4), "metadata": metadata("future")},
         headers=browser(next_ip()), clock=True)
    case("skewed device clock, two years ago", {"userId": "", "events": recording(NOW - 2 * 365 * 86_400_000, 4), "metadata": metadata("past")},
         headers=browser(next_ip()), clock=True)
    corrupt = recording(NOW - 5_000, 4)
    corrupt[3]["timestamp"] = 2_966_000_000_000
    case("one corrupt timestamp", {"userId": "", "events": corrupt, "metadata": metadata("corrupt")}, headers=browser(next_ip()), clock=True)
    infinite = ('{"userId":"","events":[{"type":2,"data":{},"timestamp":%d},{"type":3,"data":{},"timestamp":1e400},{"type":3,"data":{},"timestamp":-1e400},{"type":3,"data":{},"timestamp":%d}],'
                '"metadata":{"pageUrl":"https://shop.example.com/infinite"}}') % (NOW - 4_000, NOW - 3_000)
    case("infinite timestamps", raw=infinite.encode(), headers=browser(next_ip()), clock=True)
    case("event without data", {"userId": "", "events": [full_snapshot(NOW - 2_000), {"type": 3, "timestamp": NOW - 1_000}], "metadata": metadata("no-data")},
         headers=browser(next_ip()))
    case("viewport out of UInt16 range", {"userId": "", "events": recording(NOW - 2_500, 2), "metadata": metadata("viewport", viewportWidth=-5, viewportHeight=70000)},
         headers=browser(next_ip()))
    case("viewport zero", {"userId": "", "events": recording(NOW - 2_600, 2), "metadata": metadata("viewport-zero", viewportWidth=0, viewportHeight=0, language=...)},
         headers=browser(next_ip(), IPHONE))
    case("invalid: missing userId", {"events": recording(NOW, 1)}, headers=browser(next_ip()))
    case("invalid: events not an array", {"userId": "", "events": {"0": 1}}, headers=browser(next_ip()))
    case("invalid: field types", {"userId": 5, "events": [{"type": True, "data": 1, "timestamp": "1"}, 7], "metadata": {"viewportWidth": "1", "language": None}},
         headers=browser(next_ip()))
    case("invalid: metadata null", {"userId": "", "events": [], "metadata": None}, headers=browser(next_ip()))
    case("invalid: body is an array", [1, 2], headers=browser(next_ip()))
    case("invalid: body is a string", "hello", headers=browser(next_ip()))
    case("text/plain JSON body", raw=json.dumps({"userId": "", "events": []}).encode(), headers=browser(next_ip(), content_type="text/plain"))
    case("no body and no content type", raw=None, headers={k: v for k, v in browser(next_ip()).items() if k != "Content-Type"})
    case("invalid JSON", raw=b'{"userId": "", "events": [', headers=browser(next_ip()))
    case("empty JSON body", raw=b"", headers=browser(next_ip()))
    case("unsupported media type", raw=b"a=1", headers=browser(next_ip(), content_type="application/x-www-form-urlencoded"))
    case("prototype poisoning deep in data", raw=b'{"userId":"","events":[{"type":2,"data":{"a":[{"__proto__":{"x":1}}]},"timestamp":1}]}', headers=browser(next_ip()))
    case("byte order mark", raw="\ufeff".encode() + json.dumps({"userId": "", "events": recording(NOW - 1_500, 2), "metadata": metadata("bom")}).encode(),
         headers=browser(next_ip()))
    invalid_utf8 = b'{"userId":"","events":[{"type":2,"data":{"s":"bad \xff\xfe bytes \xe2\x82"},"timestamp":%d}],"metadata":{"pageUrl":"https://shop.example.com/utf8"}}' % (NOW - 1_400)
    case("invalid UTF-8, chunked", raw=invalid_utf8, headers=browser(next_ip()), chunked=True)
    case("invalid UTF-8 with content-length", raw=invalid_utf8, headers=browser(next_ip()))
    case("replay disabled site, valid body", {"userId": "", "events": recording(NOW, 1)}, headers=browser(next_ip()), site="off")
    case("replay disabled site, invalid body", {"nope": True}, headers=browser(next_ip()), site="off")
    case("unknown site", {"userId": "", "events": recording(NOW, 1)}, headers=browser(next_ip()), site="unknown")
    case("site by text id", {"userId": "", "events": recording(NOW - 1_300, 2), "metadata": metadata("text-id")}, headers=browser(next_ip()), site="text")
    case("excluded IP", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-ip")}, headers={"Content-Type": "application/json", "User-Agent": CHROME, "X-Real-Ip": "198.51.100.7"})
    case("excluded organization IP", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-org-ip")}, headers=browser("104.50.131.150"))
    case("excluded path", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-path", pageUrl="https://shop.example.com/admin/users?tab=1")}, headers=browser(next_ip()))
    case("excluded relative path", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-rel", pageUrl="/admin/settings?x=1#y")}, headers=browser(next_ip()))
    case("excluded hostname", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-host", pageUrl="https://preview.vercel.app/app")}, headers=browser(next_ip()))
    case("excluded user agent", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-ua")}, headers=browser(next_ip(), HEADLESS))
    case("excluded country", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-country")}, headers=browser("89.160.20.112"))
    case("excluded query param", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-query", pageUrl="https://shop.example.com/p?secret=1")}, headers=browser(next_ip()))
    case("excluded ASN", {"userId": "", "events": recording(NOW, 1), "metadata": metadata("x-asn")}, headers=browser("8.8.8.8"))
    case("relative page URL, recorded", {"userId": "", "events": recording(NOW - 1_200, 2), "metadata": metadata("rel", pageUrl="/checkout?utm_source=x")}, headers=browser(next_ip()))
    case("no user agent header", {"userId": "", "events": recording(NOW - 1_100, 2), "metadata": metadata("no-ua")}, headers=browser(next_ip(), ua=None))
    case("self referrer, paid search", {"userId": "", "events": recording(NOW - 1_000, 2), "metadata": metadata("paid", pageUrl="https://shop.example.com/p?gclid=abc")},
         headers=browser(next_ip(), referer="https://shop.example.com/cart"))
    case("GB IPv6 visitor", {"userId": "", "events": recording(NOW - 900, 2), "metadata": metadata("ipv6")}, headers=browser("2a02:c7c:b01e:6f00::5", referer=None))
    case("first-party proxy, salted, public", {"userId": "", "events": recording(NOW - 800, 3), "metadata": metadata("proxy")},
         headers={**browser("34.117.59.81"), "X-Forwarded-For": "98.207.44.30, 34.117.59.81", "X-Real-Ip": "98.207.44.30"}, site="public")
    case("public site, identified", {"userId": "user-42", "events": recording(NOW - 700, 3), "metadata": metadata("public-identified")},
         headers=browser(next_ip(), SAFARI_MAC), site="public")
    case("type as string", {"userId": "", "events": [{"type": "custom-string", "data": {"k": "v"}, "timestamp": NOW - 600}, full_snapshot(NOW - 590)],
                            "metadata": metadata("string-type")}, headers=browser(next_ip()))
    case("GET on the record route", raw=None, headers={}, method="GET", site="off")
    case("record path with a trailing slash", {"userId": "", "events": []}, headers=browser(next_ip()), path="/api/session-replay/record/{site}/", site="off")
    case("site id longer than maxParamLength", {"userId": "", "events": []}, headers=browser(next_ip()), path="/api/session-replay/record/" + "1" * 1501)
    case("site id exactly maxParamLength", {"userId": "", "events": []}, headers=browser(next_ip()), path="/api/session-replay/record/" + "1" * 1500)
    case("empty site id", {"userId": "", "events": []}, headers=browser(next_ip()), path="/api/session-replay/record/")
    case("DELETE on the record route", raw=None, headers={}, method="DELETE", site="off")
    case("percent-encoded text site id", {"userId": "", "events": recording(NOW - 1_250, 2), "metadata": metadata("encoded-id")},
         headers=browser(next_ip()), path="/api/session-replay/record/parityrp%78{site}")


def site_ids(case_spec):
    return {"twin": (SITE_A, SITE_B), "off": (SITE_OFF, SITE_OFF), "unknown": (99999, 99999), "text": ("parityrpx65170", "parityrpx65171"),
            "public": (PUBLIC_A, PUBLIC_B)}[case_spec["site"]]


def record_request(spec, backend_site):
    path = spec["path"] or f"/api/session-replay/record/{backend_site}"
    path = path.replace("{site}", str(backend_site))
    if spec["raw"] is not None or spec["body"] is None:
        body = spec["raw"]
    else:
        body = json.dumps(spec["body"], ensure_ascii=False).encode()
    return path, body


def run_record_cases():
    total = 0
    for spec in CASES:
        node_site, rust_site = site_ids(spec)
        node_path, body = record_request(spec, node_site)
        rust_path, _ = record_request(spec, rust_site)
        node = send(NODE, spec["method"], node_path, body, spec["headers"], spec["chunked"])
        rust = send(RUST, spec["method"], rust_path, body, spec["headers"], spec["chunked"])
        total += 1
        compare_responses("RECORD RESPONSE", spec["name"], node, rust)
    print(f"record responses: {total - sum(1 for k, _ in failures if k == 'RECORD RESPONSE')}/{total} identical")
    return total


def shared_session_check():
    """Node then Rust record the same visitor on the same Site: one session."""
    ip = next_ip()
    body = json.dumps({"userId": "", "events": recording(NOW - 500, 2), "metadata": metadata("shared")}).encode()
    for base in (NODE, RUST):
        send(base, "POST", f"/api/session-replay/record/{SITE_A}", body, browser(ip, FIREFOX_LINUX))
    rows = clickhouse(f"SELECT session_id, user_id, count() AS n FROM session_replay_events WHERE site_id = {SITE_A} "
                      f"AND event_data LIKE '%parity/shared%' GROUP BY session_id, user_id")
    metadata_rows = clickhouse(f"SELECT session_id, user_id FROM session_replay_metadata_v2 WHERE site_id = {SITE_A} AND page_url LIKE '%parity/shared%'")
    sessions = {row["session_id"] for row in metadata_rows}
    ok = len(metadata_rows) == 2 and len(sessions) == 1 and len({row["user_id"] for row in metadata_rows}) == 1
    if not ok:
        fail("SHARED SESSION", "Node and Rust batches for one visitor", metadata_rows, rows)
    else:
        print(f"shared session: both backends wrote to session {sessions.pop()} (1/1)")


# ---------------------------------------------------------------- rows

def normalized_rows(table, site, order):
    rows = clickhouse(f"SELECT * FROM {table} WHERE site_id = {site} ORDER BY {order}")
    return rows


def compare_rows():
    tolerance_ms = 120_000
    results = []
    for table, order in [("session_replay_events", "user_id, identified_user_id, timestamp, sequence_number, event_type, event_data"),
                         ("session_replay_metadata_v2", "user_id, identified_user_id, page_url, start_time, event_count")]:
        for site_a, site_b in [(SITE_A, SITE_B), (PUBLIC_A, PUBLIC_B)]:
            node_rows = normalized_rows(table, site_a, order)
            rust_rows = normalized_rows(table, site_b, order)
            groups = {}
            for backend, rows in (("node", node_rows), ("rust", rust_rows)):
                sessions = {}
                for row in rows:
                    key = (row["user_id"], row["identified_user_id"])
                    # Session ids are random: number them per visitor, in row order
                    visitor_sessions = sessions.setdefault(key, {})
                    row["site_id"] = "SITE"
                    row["session_id"] = visitor_sessions.setdefault(row["session_id"], f"session-{len(visitor_sessions) + 1}")
                    groups.setdefault(key, {"node": [], "rust": []})[backend].append(row)
            identical = 0
            for key, pair in groups.items():
                node_group, rust_group = pair["node"], pair["rust"]
                if len(node_group) == len(rust_group):
                    matched = True
                    for n, r in zip(node_group, rust_group):
                        n, r = dict(n), dict(r)
                        for field in ("timestamp", "start_time", "end_time"):
                            if field in n and field in r and n[field] != r[field] and n[field] and r[field]:
                                gap = abs(parse_ch_time(n[field]) - parse_ch_time(r[field]))
                                if gap <= tolerance_ms:
                                    n[field] = r[field] = f"within {tolerance_ms} ms"
                        # the session mapping is per backend; within a group it must be consistent
                        if n != r:
                            matched = False
                            fail(f"ROW {table}", f"site {site_a}/{site_b} user {key}", n, r)
                            break
                    identical += matched
                else:
                    fail(f"ROW COUNT {table}", f"site {site_a}/{site_b} user {key}", len(node_group), len(rust_group))
            results.append((table, site_a, identical, len(groups), len(node_rows), len(rust_rows)))
            print(f"{table} sites {site_a}/{site_b}: {identical}/{len(groups)} visitor groups identical ({len(node_rows)} node rows, {len(rust_rows)} rust rows)")
    return results


def parse_ch_time(text):
    from datetime import datetime, timezone
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp() * 1000


# ---------------------------------------------------------------- reads

def cookie(token):
    return {"Cookie": f"__Secure-better-auth.session_token={sign(token)}"}


def bearer(key):
    return {"Authorization": f"Bearer parity-replay-{key}"}


AUTHS = {
    "unauthenticated": {},
    "owner session": cookie("parity-replay-ownertok"),
    "member session": cookie("parity-replay-membertok"),
    "stranger session": cookie("parity-replay-strangertok"),
    "user key (owner, unrestricted)": bearer("user-owner"),
    "org key replay:read": bearer("org-replay-read"),
    "org key replay:write": bearer("org-replay-write"),
    "org key analytics:read only": bearer("org-analytics-only"),
    "org key unrestricted": bearer("org-unrestricted"),
    "stranger's key": bearer("stranger-key"),
    "invalid bearer": {"Authorization": "Bearer parity-replay-nope"},
    "private link key": {"X-Private-Key": PRIVATE_KEY},
    "wrong private link key": {"X-Private-Key": "nope"},
}


FLAKES = []


def read_pair(name, method, path, headers):
    node = send(NODE, method, path, None, headers)
    rust = send(RUST, method, path, None, headers)
    if node != rust and method in ("GET", "HEAD"):
        # Other agents share the Node process and the parity Postgres: a membership
        # they change for a moment stays in Node's 15 s site-access cache. Retry once
        # past that window before calling it a difference.
        time.sleep(16)
        retry_node = send(NODE, method, path, None, headers)
        retry_rust = send(RUST, method, path, None, headers)
        if retry_node == retry_rust:
            FLAKES.append((name, node["status"], rust["status"]))
            print(f"flaky (identical on retry) {name}: first node {node['status']}, rust {rust['status']}")
            return retry_node
    compare_responses("READ", name, node, rust)
    return node


def run_reads():
    count = 0
    start = len([k for k, _ in failures if k == "READ"])
    sessions = {}
    for site in (SITE_A, SITE_B, PUBLIC_A, PUBLIC_B):
        listing = read_pair(f"list site {site} as owner", "GET", f"/api/sites/{site}/session-replay/list", AUTHS["owner session"])
        count += 1
        sessions[site] = [row["session_id"] for row in json.loads(listing["body"])["data"]] if listing["status"] == 200 else []
    print("recorded sessions visible in lists:", {site: len(ids) for site, ids in sessions.items()})

    for auth_name, headers in AUTHS.items():
        for site in (SITE_A, PUBLIC_A):
            read_pair(f"list site {site} as {auth_name}", "GET", f"/api/sites/{site}/session-replay/list", headers)
            count += 1
            for session_id in sessions[site][:2]:
                read_pair(f"events {site}/{session_id} as {auth_name}", "GET", f"/api/sites/{site}/session-replay/{session_id}", headers)
                count += 1

    owner = AUTHS["owner session"]
    queries = [
        "limit=2", "limit=2&offset=1", "offset=abc", "limit=0", "limit=-1", "limit=1.5", "limit=abc", "limit=1&limit=2",
        "userId=user-42", "userId=%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC%F0%9F%98%80", "userId=nobody", "userId=a&userId=b",
        "minDuration=1", "minDuration=0", "minDuration=abc", "minDuration=86400",
        "start_date=2026-01-01&end_date=2099-01-01&time_zone=UTC", "start_date=2026-09-17&end_date=2026-09-17&time_zone=America%2FNew_York",
        "past_minutes_start=60&past_minutes_end=0", "past_minutes_start=abc", "start_date=bad",
        "filters=%5B%7B%22parameter%22%3A%22browser%22%2C%22type%22%3A%22equals%22%2C%22value%22%3A%5B%22Chrome%22%5D%7D%5D",
        "filters=not-json", "filters=%5B%5D", "segment_id=999999", "api_key=parity-replay-org-replay-read",
    ]
    for query in queries:
        read_pair(f"list site {SITE_A} ?{query}", "GET", f"/api/sites/{SITE_A}/session-replay/list?{query}", owner)
        count += 1
        read_pair(f"list site {SITE_A} ?{query} (unauthenticated)", "GET", f"/api/sites/{SITE_A}/session-replay/list?{query}", {})
        count += 1

    for session_id in sessions[SITE_A] + sessions[SITE_B] + sessions[PUBLIC_A] + sessions[PUBLIC_B]:
        site = next(site for site, ids in sessions.items() if session_id in ids)
        read_pair(f"events {site}/{session_id} as owner", "GET", f"/api/sites/{site}/session-replay/{session_id}", owner)
        count += 1
        read_pair(f"HEAD events {site}/{session_id}", "HEAD", f"/api/sites/{site}/session-replay/{session_id}", owner)
        count += 1

    for name, path in [
        ("events for an unknown session", f"/api/sites/{SITE_A}/session-replay/nosuchsession"),
        ("events for an encoded session id", f"/api/sites/{SITE_A}/session-replay/a%2Fb%20c"),
        ("events via text site id", f"/api/sites/parityrpx65170/session-replay/{(sessions[SITE_A] or ['x'])[0]}"),
        ("list via text site id", "/api/sites/parityrpx65170/session-replay/list"),
        ("list for an unknown text site", "/api/sites/nosuchsite123/session-replay/list"),
        ("list for an unknown numeric site", "/api/sites/99999/session-replay/list"),
        ("list for site 0", "/api/sites/0/session-replay/list"),
        ("list for a hex site id", f"/api/sites/0x{SITE_A:x}/session-replay/list"),
        ("empty session id", f"/api/sites/{SITE_A}/session-replay/"),
        ("list with an empty site id", "/api/sites//session-replay/list"),
        ("events with an empty site id", "/api/sites//session-replay/abc"),
        ("events with both ids empty", "/api/sites//session-replay/"),
        ("PUT events", f"/api/sites/{SITE_A}/session-replay/abc"),
        ("list with trailing slash", f"/api/sites/{SITE_A}/session-replay/list/"),
        ("long session id", f"/api/sites/{SITE_A}/session-replay/" + "s" * 1501),
        ("HEAD list", f"/api/sites/{SITE_A}/session-replay/list"),
        ("POST list", f"/api/sites/{SITE_A}/session-replay/list"),
    ]:
        method = name.split(" ", 1)[0] if name.split(" ", 1)[0] in ("HEAD", "POST", "PUT") else "GET"
        read_pair(name, method, path, owner)
        count += 1
    mismatches = len([k for k, _ in failures if k == "READ"]) - start
    print(f"read responses: {count - mismatches}/{count} identical")
    return sessions


def run_deletes():
    count = 0
    start = len([k for k, _ in failures if k in ("DELETE", "READ")])
    # Twin sessions: a fresh visitor per backend, recorded through Node on the same Site
    targets = []
    for label in ("node", "rust"):
        body = json.dumps({"userId": "", "events": recording(NOW - 400, 3), "metadata": metadata(f"delete-{label}")}).encode()
        send(NODE, "POST", f"/api/session-replay/record/{SITE_A}", body, browser(next_ip()))
    time.sleep(1)
    listing = json.loads(read_pair("list before deleting", "GET", f"/api/sites/{SITE_A}/session-replay/list?limit=1000", AUTHS["owner session"])["body"])["data"]
    count += 1
    by_page = {row["page_url"].split("?")[0].rsplit("/", 1)[-1]: row["session_id"] for row in listing}
    node_session, rust_session = by_page["delete-node"], by_page["delete-rust"]

    def delete_pair(name, headers, node_path, rust_path=None):
        nonlocal count
        node = send(NODE, "DELETE", node_path, None, headers)
        rust = send(RUST, "DELETE", rust_path or node_path, None, headers)
        count += 1
        if node != rust:
            fail("DELETE", name, node, rust)
        return node, rust

    # Refused credentials first, so nothing is deleted yet
    for auth_name in ("unauthenticated", "stranger session", "org key replay:read", "org key analytics:read only", "invalid bearer",
                      "private link key", "stranger's key"):
        delete_pair(f"delete as {auth_name}", AUTHS[auth_name], f"/api/sites/{SITE_A}/session-replay/{node_session}", f"/api/sites/{SITE_A}/session-replay/{rust_session}")
    delete_pair("delete a public site's replay unauthenticated", {}, f"/api/sites/{PUBLIC_A}/session-replay/nosuch")
    delete_pair("delete an unknown session", AUTHS["owner session"], f"/api/sites/{SITE_A}/session-replay/nosuchsession")
    delete_pair("delete the literal 'list'", AUTHS["owner session"], f"/api/sites/{SITE_A}/session-replay/list")
    delete_pair("delete with an empty session id", AUTHS["owner session"], f"/api/sites/{SITE_A}/session-replay/")
    delete_pair("delete with an empty site id", AUTHS["owner session"], "/api/sites//session-replay/abc")
    delete_pair("delete 'list' with an empty site id", AUTHS["owner session"], "/api/sites//session-replay/list")
    delete_pair("delete with both ids empty", AUTHS["owner session"], "/api/sites//session-replay/")
    delete_pair("delete via text site id, unknown session", AUTHS["owner session"], "/api/sites/parityrpx65170/session-replay/nosuch")
    delete_pair("delete via hex site id, unknown session", AUTHS["owner session"], f"/api/sites/0x{SITE_A:x}/session-replay/nosuch")
    # The real deletions: twin sessions, one per backend
    delete_pair("delete with org key replay:write", AUTHS["org key replay:write"], f"/api/sites/{SITE_A}/session-replay/{node_session}", f"/api/sites/{SITE_A}/session-replay/{rust_session}")
    delete_pair("delete again (already gone)", AUTHS["owner session"], f"/api/sites/{SITE_A}/session-replay/{node_session}", f"/api/sites/{SITE_A}/session-replay/{rust_session}")
    for session_id in (node_session, rust_session):
        remaining = clickhouse(f"SELECT (SELECT count() FROM session_replay_events WHERE site_id = {SITE_A} AND session_id = '{session_id}') AS events, "
                               f"(SELECT count() FROM session_replay_metadata_v2 WHERE site_id = {SITE_A} AND session_id = '{session_id}') AS metadata")[0]
        count += 1
        if int(remaining["events"]) or int(remaining["metadata"]):
            fail("DELETE", f"rows left after deleting {session_id}", remaining, {"events": 0, "metadata": 0})
    mismatches = len([k for k, _ in failures if k in ("DELETE", "READ")]) - start
    print(f"delete checks: {count - mismatches}/{count} identical")


def query_log_check(since):
    """The replay reads and deletes each backend sent, as ClickHouse logged them
    (parameters substituted, so twin session ids are masked). Inserts are left out:
    async insert flushes are logged without the client's user agent."""
    time.sleep(8)  # the query log flushes every 7.5 s
    rows = clickhouse(
        "SELECT http_user_agent AS agent, replaceRegexpAll(query, 'session_id = \\'[A-Za-z0-9_-]{14}\\'', 'session_id = SESSION') AS text, "
        "count() AS n FROM system.query_log "
        f"WHERE type = 'QueryFinish' AND event_time >= toDateTime({int(since)}) AND query LIKE '%session_replay_%' "
        "AND query_kind IN ('Select', 'Delete') AND http_user_agent != 'parity-replay-harness' "
        f"AND match(query, '_CAST\\\\(({'|'.join(map(str, TEST_SITES))}), ''UInt16''\\\\)') "
        "AND (query LIKE 'SELECT session_id, user_id, identified_user_id, start_time%' OR query LIKE 'SELECT site_id, session_id%' "
        "OR query LIKE 'SELECT toUnixTimestamp64Milli%' OR query LIKE 'DELETE FROM session_replay_%') GROUP BY agent, text")
    node_texts = {row["text"] for row in rows if row["agent"].startswith("clickhouse-js")}
    rust_texts = {row["text"] for row in rows if row["agent"] == ""}
    only_node, only_rust = node_texts - rust_texts, rust_texts - node_texts
    if only_node or only_rust:
        fail("QUERY LOG", "distinct SQL texts", sorted(only_node)[:5], sorted(only_rust)[:5])
    print(f"query log: {len(node_texts & rust_texts)} distinct replay SQL texts sent by both, {len(only_node)} only by Node, {len(only_rust)} only by Rust")


def main():
    started = time.time()
    setup()
    try:
        build_cases()
        time.sleep(1)
        # Aggregating merges would combine one backend's metadata rows before the
        # other's; mutations (the deletes) cannot run while merges are stopped
        clickhouse("SYSTEM STOP MERGES analytics.session_replay_metadata_v2", parse=False)
        try:
            run_record_cases()
            time.sleep(2)
            compare_rows()
        finally:
            clickhouse("SYSTEM START MERGES analytics.session_replay_metadata_v2", parse=False)
        shared_session_check()
        run_reads()
        run_deletes()
        query_log_check(started)
    finally:
        if os.environ.get("KEEP") != "1":
            cleanup()
    print(f"{len(failures)} mismatches, {len(FLAKES)} reads differed once and matched on retry")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
