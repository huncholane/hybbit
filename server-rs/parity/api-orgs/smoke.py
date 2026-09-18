#!/usr/bin/env python3
"""A handful of requests against both backends, printing both answers. For
eyeballing a route while porting it; run.py is the real comparison."""
import json
import sys

import hw

C = json.load(open(hw.OUT + "/creds.json"))
S, K, O, U, M, T = C["sessions"], C["keys"], C["orgs"], C["users"], C["members"], C["teams"]


def cookie(name):
    return [("Cookie", S[name])]


def bearer(name):
    return [("Authorization", "Bearer " + K[name])]


CASES = [
    ("GET", "/api/organizations", cookie("ownerA"), None),
    ("GET", "/api/organizations", bearer("ownerA"), None),
    ("GET", "/api/organizations", [], None),
    ("GET", "/api/user/organizations", cookie("ownerA"), None),
    ("GET", f"/api/organizations/{O['A']}/sites", cookie("ownerA"), None),
    ("GET", f"/api/organizations/{O['A']}/sites", cookie("restrictedA"), None),
    ("GET", f"/api/organizations/{O['A']}/members", cookie("ownerA"), None),
    ("GET", f"/api/organizations/{O['A']}/teams", cookie("ownerA"), None),
    ("GET", f"/api/organizations/{O['A']}/teams", cookie("memberA1"), None),
    ("GET", f"/api/organizations/{O['A']}/excluded-ips", cookie("ownerA"), None),
    ("GET", f"/api/organizations/{O['A']}/api-usage", cookie("ownerA"), None),
    ("GET", "/api/user/unsubscribe-marketing-oneclick", [], None),
    ("GET", "/api/user/unsubscribe-marketing-oneclick?email=ownerA@parity-orgs-test", [], None),
    ("POST", "/api/user/unsubscribe-marketing-oneclick?email=ownerA@parity-orgs-test", [], b""),
    ("POST", "/api/user/account-settings", cookie("ownerA"), b'{"sendAutoEmailReports":false}'),
    ("POST", "/api/user/account-settings", cookie("ownerA"), b'{"sendAutoEmailReports":"x"}'),
    ("POST", "/api/user/account-settings", cookie("ownerA"), None),
    ("PUT", f"/api/organizations/{O['A']}/excluded-ips", cookie("ownerA"), b'{"excludedIPs":["1.2.3.4"]}'),
    ("PUT", f"/api/organizations/{O['A']}/excluded-ips", cookie("ownerA"), b'{"excludedIPs":["nope"]}'),
    ("POST", f"/api/organizations/{O['A']}/teams", cookie("ownerA"), b'{"name":"  New  "}'),
    ("POST", f"/api/organizations/{O['A']}/teams", cookie("ownerA"), None),
    ("PUT", f"/api/organizations/{O['A']}/teams/{T['teamA1']}", cookie("ownerA"), b'{"name":"Renamed"}'),
    ("DELETE", f"/api/organizations/{O['A']}/teams/{T['teamA1']}", cookie("ownerA"), None),
    ("POST", f"/api/organizations/{O['A']}/members", cookie("ownerA"), b'{"email":"target@parity-orgs-test","role":"member"}'),
    ("POST", f"/api/organizations/{O['A']}/members", cookie("ownerA"), None),
    ("POST", f"/api/organizations/{O['A']}/users", cookie("ownerA"), b'{"email":"NEW@parity-orgs-test","password":"password123","role":"member"}'),
    ("PUT", f"/api/organizations/{O['A']}/members/{M['memberA1']}/sites", cookie("ownerA"), b'{"hasRestrictedSiteAccess":true,"siteIds":[65300]}'),
    ("PUT", f"/api/organizations/{O['A']}/members/{M['memberA1']}/sites", cookie("ownerA"), None),
    ("POST", "/api/user/api-keys", cookie("ownerA"), b'{"name":"smoke"}'),
    ("POST", f"/api/organizations/{O['A']}/api-keys", cookie("ownerA"), b'{"name":"smoke org"}'),
    ("POST", f"/api/organizations/{O['A']}/sites", cookie("ownerA"), b'{"name":"Smoke","domain":"smoke.parity-orgs.test"}'),
    ("POST", f"/api/organizations/{O['A']}/sites", cookie("ownerA"), b'{"name":"Smoke","domain":"nope"}'),
    ("GET", f"/api/organizations/{O['A']}/teams/{T['teamA1']}", cookie("ownerA"), None),
    ("DELETE", "/api/organizations", cookie("ownerA"), None),
]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    import subprocess

    for method, path, headers, body in CASES:
        if only and only not in path:
            continue
        subprocess.run([sys.executable, hw.HERE + "/fixtures.py", "reset"], check=True)
        node = hw.send(hw.NODE, method, path, headers, body)
        node_rows = hw.snapshot()
        subprocess.run([sys.executable, hw.HERE + "/fixtures.py", "reset"], check=True)
        rust = hw.send(hw.RUST, method, path, headers, body)
        rust_rows = hw.snapshot()
        same = hw.comparable(node, True) == hw.comparable(rust, True)
        rows_same = node_rows == rust_rows
        print(f"{'OK ' if same and rows_same else 'DIFF'} {method} {path[:70]} body={body!r:.40}")
        if not same:
            print("  node:", json.dumps(hw.comparable(node, True))[:700])
            print("  rust:", json.dumps(hw.comparable(rust, True))[:700])
        if not rows_same:
            for table in node_rows:
                if node_rows[table] != rust_rows[table]:
                    print(f"  rows[{table}] node:", json.dumps(node_rows[table])[:500])
                    print(f"  rows[{table}] rust:", json.dumps(rust_rows[table])[:500])


main()
