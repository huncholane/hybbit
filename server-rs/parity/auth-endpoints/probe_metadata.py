"""Probe how Node reads and migrates apikey.metadata of various stored shapes."""
import json
import sys

import harness as h

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 3021
A = "/api/auth"
J = json.dumps({"b": 1, "1": 2, "at": "2024-01-01T00:00:00Z"})
S = "not json"
cases = {
    "E1 object": json.dumps({"a": 1, "at": "2024-01-01T00:00:00Z"}),
    "E2 string J": json.dumps(J),
    "E3 string dumps(J)": json.dumps(json.dumps(J)),
    "E4 string dumps2(J)": json.dumps(json.dumps(json.dumps(J))),
    "E5 string S": json.dumps(S),
    "E6 string dumps(S)": json.dumps(json.dumps(S)),
    "E7 string dumps2(S)": json.dumps(json.dumps(json.dumps(S))),
    "E8 number": "5",
    "E9 string 5": json.dumps("5"),
    "E10 empty string": json.dumps(""),
    "E11 false": "false",
    "E12 string true": json.dumps("true"),
    "E13 string ISO": json.dumps("2024-01-01T00:00:00Z"),
    "E14 string dumps(ISO)": json.dumps(json.dumps("2024-01-01T00:00:00Z")),
    "E15 null": "null",
}
try:
    for label, stored in cases.items():
        user = h.create_user(f"probe-{label.split()[0].lower()}")
        ids = []
        for i in range(2):
            kid = f"parity-auth-key-{h.rand_id(10)}"
            h.q(
                """INSERT INTO apikey (id, name, key, "referenceId", enabled, "rateLimitEnabled", "requestCount", "createdAt", "updatedAt", "configId", metadata)
                   VALUES (%s, %s, %s, %s, true, false, 0, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc', 'default', %s::jsonb)""",
                kid, f"k{i}", h.rand_id(43), user["id"], stored,
            )
            ids.append(kid)
        token = h.create_session(user["id"])
        d = h.request(PORT, "POST", f"{A}/api-key/delete", json_body={"keyId": ids[1]}, cookies=h.session_cookies(token))
        l = h.request(PORT, "GET", f"{A}/api-key/list", cookies=h.session_cookies(token))
        body = l.json()
        listed = [k.get("metadata", "<absent>") for k in body["apiKeys"]] if isinstance(body, dict) and "apiKeys" in body else l.body[:200]
        after = h.q("SELECT metadata::text AS m FROM apikey WHERE id = %s", ids[0])
        print(json.dumps({"case": label, "stored": h.q("SELECT %s::jsonb::text AS m", stored)[0]["m"], "delete": d.status, "list": l.status, "listed": listed, "after": after[0]["m"] if after else None}))
finally:
    h.cleanup()
