#!/usr/bin/env python3
"""Send the same requests to the Node (:3001) and Rust (:3011) backends and diff them.

Usage: compare.py [cases/phase0.json ...]   (default: every file in cases/)

A case is {"name", "method", "path", "headers"?: {...}, "body"?: any, "ignore_headers"?: [...]}.
Compared: status, the headers in WATCHED_HEADERS, and the body (parsed JSON when
both sides send JSON, otherwise the raw bytes). Exit code 1 when anything differs.
"""

import glob
import json
import os
import sys
import urllib.error
import urllib.request

NODE = os.environ.get("NODE_URL", "http://127.0.0.1:3001")
RUST = os.environ.get("RUST_URL", "http://127.0.0.1:3011")

WATCHED_HEADERS = [
    "content-type",
    "cache-control",
    "vary",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "x-content-type-options",
    "etag",
    "last-modified",
    "location",
    "set-cookie",
    "pragma",
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def send(base, case):
    body = case.get("body")
    data = None
    headers = dict(case.get("headers", {}))
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(base + case["path"], data=data, method=case["method"], headers=headers)
    try:
        with OPENER.open(request, timeout=60) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def normalize_header(name, value):
    if value is None:
        return None
    if name == "content-type":
        return value.lower().replace(" ", "")
    if name == "vary":
        return ",".join(sorted(token.strip().lower() for token in value.split(",")))
    return value


def parse_body(headers, raw):
    if "json" in (headers.get("content-type") or ""):
        try:
            return json.loads(raw)
        except ValueError:
            pass
    return raw


def same_json(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return float(left) == float(right)
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(same_json(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def compare(case):
    node = send(NODE, case)
    rust = send(RUST, case)
    problems = []

    if node[0] != rust[0]:
        problems.append(f"status node={node[0]} rust={rust[0]}")

    ignored = {name.lower() for name in case.get("ignore_headers", [])}
    for name in WATCHED_HEADERS:
        if name in ignored:
            continue
        left = normalize_header(name, node[1].get(name))
        right = normalize_header(name, rust[1].get(name))
        if left != right:
            problems.append(f"header {name}: node={left!r} rust={right!r}")

    if case["method"] != "HEAD":
        left, right = parse_body(node[1], node[2]), parse_body(rust[1], rust[2])
        if not same_json(left, right):
            show = lambda value: (json.dumps(value)[:300] if not isinstance(value, bytes) else f"<{len(value)} bytes> {value[:120]!r}")
            problems.append(f"body:\n      node={show(left)}\n      rust={show(right)}")

    return problems


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    files = sys.argv[1:] or sorted(glob.glob(os.path.join(here, "cases", "*.json")))
    failures = 0
    total = 0
    for path in files:
        with open(path) as handle:
            cases = json.load(handle)
        for case in cases:
            total += 1
            problems = compare(case)
            if problems:
                failures += 1
                print(f"FAIL {case['name']}")
                for problem in problems:
                    print(f"    {problem}")
            else:
                print(f"ok   {case['name']}")
    print(f"\n{total - failures}/{total} cases match")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
