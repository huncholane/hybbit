#!/usr/bin/env python3
"""HTTP parity for the two feature flag evaluate routes: temporary flags on parity
site 1 (removed afterwards, cache keys cleared), then the same requests to Node and
Rust. `generatedAt` is the only field normalised.

Usage: evaluate_http.py [node_url] [rust_url]   (defaults http://127.0.0.1:3001, :3031)
"""
import http.client, json, subprocess, sys, urllib.parse

NODE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3001"
RUST = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3031"
PSQL = ["psql", "-h", "127.0.0.1", "-p", "55432", "-U", "hygo", "analytics", "-Atc"]
REDIS_KEY = "feature-flags:definitions:1"


def sql(statement):
    subprocess.run(PSQL + [statement], check=True, env={"PGPASSWORD": "hygo", "PATH": "/usr/bin:/bin"}, capture_output=True)


def clear_cache():
    subprocess.run(["redis-cli", "-p", "56379", "-a", "hygo", "--no-auth-warning", "DEL", REDIS_KEY], capture_output=True)


FLAGS = [
    ("parity-bool", "client", "boolean", "true", 50, "[]", "[]", "null"),
    ("parity-both", "both", "boolean", "true", 100,
     '[{"field":"country","operator":"equals","value":"US"}]', "[]", '{"theme":"dark","ratio":1.0,"big":1e21}'),
    ("parity-multi", "client", "multivariate", "true", 100, "[]",
     '[{"key":"a","rolloutPercentage":30,"payload":{"x":1}},{"key":"b","rolloutPercentage":70}]', "null"),
    ("parity-regex", "server", "boolean", "true", 100,
     '[{"field":"pathname","operator":"regex","value":"^/pricing(/.*)?$"}]', "[]", "null"),
    ("parity-device", "both", "remote_config", "true", 100,
     '[{"field":"device_type","operator":"equals","value":"Mobile"}]', "[]", '[1,2,3]'),
    ("parity-off", "both", "boolean", "false", 100, "[]", "[]", "null"),
]


def setup():
    sql("DELETE FROM feature_flags WHERE key LIKE 'parity-%'")
    for key, runtime, kind, enabled, rollout, rules, variants, payload in FLAGS:
        payload_sql = "NULL" if payload == "null" else f"'{payload}'::jsonb"
        sql("INSERT INTO feature_flags (site_id, key, enabled, runtime, flag_type, payload, variants, rollout_percentage, rules, salt) "
            f"VALUES (1, '{key}', {enabled}, '{runtime}', '{kind}', {payload_sql}, '{variants}'::jsonb, {rollout}, '{rules}'::jsonb, 'parity-salt')")
    clear_cache()


def teardown():
    sql("DELETE FROM feature_flags WHERE key LIKE 'parity-%'")
    clear_cache()


IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"
CASES = []
for anon in ("visitor-1", "visitor-2", "visitor-3", "  padded  "):
    for ip, ua in (("73.162.10.20", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/138.0 Safari/537.36"), ("81.2.69.160", IPHONE)):
        CASES.append(("/api/site/1/feature-flags/evaluate", {"anonymousId": anon, "pathname": "/pricing/pro", "screenWidth": 390,
                      "screenHeight": 844, "querystring": "?a=1&a=2&b=%zz"}, ip, ua))
CASES += [
    ("/api/site/1/feature-flags/evaluate", {"anonymousId": "x", "identifiedUserId": "nobody", "query": {"k": "v"}}, "73.162.10.20", "curl/8"),
    ("/api/site/1/feature-flags/evaluate", {}, "73.162.10.20", "curl/8"),
    ("/api/site/1/feature-flags/evaluate", {"anonymousId": "", "screenWidth": -1, "language": "x" * 40}, "73.162.10.20", "curl/8"),
    ("/api/site/1/feature-flags/evaluate", None, "73.162.10.20", "curl/8"),
    ("/api/site/99999/feature-flags/evaluate", {"anonymousId": "x"}, "73.162.10.20", "curl/8"),
    ("/api/site/2/feature-flags/evaluate", {"anonymousId": "x"}, "73.162.10.20", "curl/8"),
    ("/api/sites/1/feature-flags/evaluate", {"anonymousId": "x"}, "73.162.10.20", "curl/8"),
]


def send(base, path, body, ip, ua):
    url = urllib.parse.urlparse(base)
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
    headers = {"User-Agent": ua, "Cf-Connecting-Ip": ip, "X-Forwarded-For": ip, "X-Real-Ip": ip}
    payload = b""
    if body is not None:
        payload = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    connection.request("POST", path, body=payload or None, headers=headers)
    response = connection.getresponse()
    text = response.read().decode()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            parsed.pop("generatedAt", None)
    except ValueError:
        parsed = text
    return {"status": response.status, "type": response.getheader("Content-Type"), "body": parsed, "raw_numbers": "1e+21" in text}


def main():
    setup()
    failures = 0
    try:
        for path, body, ip, ua in CASES:
            node, rust = send(NODE, path, body, ip, ua), send(RUST, path, body, ip, ua)
            if node != rust:
                failures += 1
                print(f"MISMATCH {path} {json.dumps(body)} {ip}\n  node: {json.dumps(node)}\n  rust: {json.dumps(rust)}")
    finally:
        teardown()
    print(f"{len(CASES) - failures}/{len(CASES)} evaluate responses identical")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
