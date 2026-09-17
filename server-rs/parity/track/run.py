#!/usr/bin/env python3
"""Tracking ingest parity: every case goes to Node, then the identical request to
Rust, against the same parity stores. Compares HTTP responses, then the rows each
backend wrote to events, bot_events and bot_observations.

Sending each request to both backends back to back is deliberate: they share
Redis, so the Rust request must land in the session the Node request opened, and
the user ids must agree for rows to match.

Usage: run.py [node_url] [rust_url]   (defaults http://127.0.0.1:3001, :3031)
Both backends must run against parity/env.sh; see parity/run-node.sh.
"""
import base64, http.client, json, sys, time, urllib.parse, uuid

NODE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3001"
RUST = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3031"
CLICKHOUSE = ("127.0.0.1", 58123, "default", "hygo")
RUN = uuid.uuid4().hex[:8]

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"
FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0"


def browser_headers(ip, ua=CHROME, language="en-US,en;q=0.9"):
    """What a browser request looks like after Cloudflare and Caddy."""
    return {
        "Content-Type": "application/json",
        "User-Agent": ua,
        "Accept": "*/*",
        "Accept-Language": language,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Origin": "https://hygo.ai",
        "Referer": "https://hygo.ai/",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Sec-Ch-Ua": '"Chromium";v="138", "Not)A;Brand";v="8"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Cf-Connecting-Ip": ip,
        "X-Forwarded-For": ip,
        "X-Real-Ip": ip,
    }


def event(site, kind="pageview", case="", **fields):
    body = {"type": kind, "site_id": str(site), "hostname": "hygo.ai", "pathname": f"/parity-{RUN}-BACKEND/{case}",
            "querystring": "", "screenWidth": 1920, "screenHeight": 1080, "language": "en-US",
            "page_title": "Parity", "referrer": ""}
    body.update(fields)
    return body


CASES = []


def case(name, path="/api/track", body=None, headers=None, raw=None):
    CASES.append({"name": name, "path": path, "body": body, "headers": headers or {}, "raw": raw})


V1, V2, V3, V4 = "73.162.10.20", "98.207.44.12", "2a02:c7c:b01e:6f00::1", "81.2.69.160"
case("pageview with utm and google referrer", body=event(1, case="first", querystring="?utm_source=newsletter&utm_medium=email&utm_campaign=fall",
     referrer="https://www.google.com/"), headers=browser_headers(V1))
case("second pageview same visitor", body=event(1, case="second"), headers=browser_headers(V1))
case("heartbeat with a live session", body=event(1, "heartbeat", case="hb"), headers=browser_headers(V1))
case("heartbeat without a session", body=event(1, "heartbeat", case="hb-none"), headers=browser_headers("73.162.99.99", FIREFOX_LINUX))
case("custom event with properties", body=event(1, "custom_event", case="custom", event_name="signup_click",
     properties=json.dumps({"plan": "pro", "seats": 3, "nested": {"a": [1, 2.5, None]}})), headers=browser_headers(V1))
case("performance metrics with a null", body=event(1, "performance", case="perf", lcp=1234.5, cls=0, inp=None, fcp=800, ttfb=120.25),
     headers=browser_headers(V1))
case("outbound link", body=event(1, "outbound", case="outbound", properties=json.dumps({"url": "https://example.com/x", "text": "Go"})),
     headers=browser_headers(V1))
case("error event", body=event(1, "error", case="error", event_name="TypeError",
     properties=json.dumps({"message": "x is undefined", "stack": "at foo", "lineNumber": 3})), headers=browser_headers(V1))
case("excluded site IP", body=event(1, case="excluded-ip"), headers=browser_headers("104.50.131.150"))
case("excluded organization IPv6 range", body=event(2, case="excluded-v6"), headers=browser_headers("2600:6c4d:1040:5251::42"))
case("curl on a site that blocks bots", body=event(1, case="curl"), headers={"Content-Type": "application/json", "User-Agent": "curl/8.9.1",
     "Cf-Connecting-Ip": V2, "X-Forwarded-For": V2, "X-Real-Ip": V2})
case("googlebot on a site that does not block bots, IP stored", body=event(5, case="googlebot"),
     headers=browser_headers("66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"))
case("site storing IPs", body=event(5, case="track-ip"), headers=browser_headers(V2))
case("IPv6 iPhone visitor in German", body=event(3, case="iphone", screenWidth=390, screenHeight=844, language="de-DE",
     referrer="https://www.instagram.com/"), headers=browser_headers(V3, IPHONE, "de-DE,de;q=0.9"))
case("anonymous id", body=event(3, case="anon", anonymous_id="parity-anon-123"), headers=browser_headers(V4))
case("identified user with padding", body=event(3, case="identified", user_id="  parity-user-7  "), headers=browser_headers(V4))
case("feature flags", body=event(4, case="flags", feature_flags={"checkout": "variant-b", "10": "numeric-key"}), headers=browser_headers(V4))
case("self referrer is cleared, paid search", body=event(4, case="paid", referrer="https://hygo.ai/pricing", querystring="?gclid=abc123"),
     headers=browser_headers(V4))
case("client bot signals", body=event(1, case="signals", _bs=9, _bsm=2047), headers=browser_headers("24.5.6.7"))
case("datacenter visitor", body=event(4, case="datacenter"), headers=browser_headers("34.117.59.81"))
case("unknown site", body=event(99999, case="unknown"), headers=browser_headers(V1))
case("missing type", body={"site_id": "1"}, headers=browser_headers(V1))
case("wrong field types", body=event(1, case="types", screenWidth="1920", tag=5), headers=browser_headers(V1))
case("extra field", body=event(1, case="extra", surprise=True), headers=browser_headers(V1))
case("text/plain body", raw=json.dumps(event(1, case="text")).encode(), headers={**browser_headers(V1), "Content-Type": "text/plain"})
case("invalid json", raw=b'{"type": "pageview",', headers=browser_headers(V1))
case("empty json body", raw=b"", headers=browser_headers(V1))
case("unsupported media type", raw=b"a=1", headers={**browser_headers(V1), "Content-Type": "application/x-www-form-urlencoded"})
case("prototype poisoning", raw=b'{"type":"pageview","site_id":"1","__proto__":{"x":1}}', headers=browser_headers(V1))
case("identify with traits", path="/api/identify", body={"site_id": "3", "user_id": f"parity-{RUN}", "traits": {"email": "p@example.com", "plan": "pro", "n": 1.5}},
     headers=browser_headers(V4))
case("identify invalid", path="/api/identify", body={"site_id": "3"}, headers=browser_headers(V4))
case("identify unknown site", path="/api/identify", body={"site_id": "99999", "user_id": "x"}, headers=browser_headers(V4))


def send(base, spec, backend):
    url = urllib.parse.urlparse(base)
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
    if spec["raw"] is not None:
        payload = spec["raw"]
    else:
        payload = json.dumps(spec["body"]).replace("BACKEND", backend).encode()
    headers = dict(spec["headers"])
    headers["Content-Length"] = str(len(payload))
    connection.request("POST", spec["path"], body=payload, headers=headers)
    response = connection.getresponse()
    text = response.read().decode()
    try:
        body = json.loads(text)
    except ValueError:
        body = text
    return {"status": response.status, "content_type": response.getheader("Content-Type"), "body": body}


def clickhouse(sql):
    host, port, user, password = CLICKHOUSE
    connection = http.client.HTTPConnection(host, port, timeout=30)
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    connection.request("POST", "/?database=analytics&default_format=JSONEachRow", body=sql.encode(),
                       headers={"Authorization": f"Basic {auth}"})
    response = connection.getresponse()
    text = response.read().decode()
    if response.status != 200:
        raise RuntimeError(text)
    return [json.loads(line) for line in text.splitlines() if line]


def main():
    failures = 0
    for spec in CASES:
        node = send(NODE, spec, "node")
        rust = send(RUST, spec, "rust")
        if node != rust:
            failures += 1
            print(f"RESPONSE MISMATCH {spec['name']}\n  node: {json.dumps(node)}\n  rust: {json.dumps(rust)}")
    print(f"{len(CASES) - failures}/{len(CASES)} responses identical")

    time.sleep(4)  # both queues flush every second
    row_failures = 0
    row_total = 0
    for table in ("events", "bot_events", "bot_observations"):
        rows = clickhouse(f"SELECT * FROM {table} WHERE pathname LIKE '/parity-{RUN}-%' ORDER BY pathname")
        grouped = {"node": {}, "rust": {}}
        for row in rows:
            backend = row["pathname"].split("-")[2].split("/")[0]
            case_name = row["pathname"].split("/", 2)[2]
            for volatile in ("timestamp", "timestamp_ms"):
                row.pop(volatile, None)
            row["pathname"] = row["pathname"].replace(f"-{backend}/", "-BACKEND/")
            grouped[backend].setdefault(case_name, []).append(row)
        cases = sorted(set(grouped["node"]) | set(grouped["rust"]))
        for name in cases:
            row_total += 1
            node_rows, rust_rows = grouped["node"].get(name), grouped["rust"].get(name)
            if node_rows != rust_rows:
                row_failures += 1
                print(f"ROW MISMATCH {table} {name}\n  node: {json.dumps(node_rows)}\n  rust: {json.dumps(rust_rows)}")
        print(f"{table}: {len(cases) - sum(1 for n in cases if grouped['node'].get(n) != grouped['rust'].get(n))}/{len(cases)} cases with identical rows "
              f"({sum(len(v) for v in grouped['node'].values())} node rows, {sum(len(v) for v in grouped['rust'].values())} rust rows)")
    sys.exit(1 if failures or row_failures else 0)


if __name__ == "__main__":
    main()
