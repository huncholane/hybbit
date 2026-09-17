#!/usr/bin/env python3
"""Generate-route differential run against the OpenRouter mock: Node on :3058 and
Rust on :3059 (run-generate-backends.sh). Compares the responses and the request
each backend sent to the mock.

Usage: PARITY_WORKSPACE_OUT=<dir> generate.py
"""
import collections, json, os, urllib.request

import hw
from cases import caller, jbody

NODE, RUST = ("127.0.0.1", 3058), ("127.0.0.1", 3059)
SCENARIOS = [
    "ok-plain", "ok-fenced", "ok-label", "invalid-sql", "redefine", "empty-choices", "no-choices", "empty-length",
    "whitespace-stop", "null-content", "array-content", "http-500", "http-401", "http-429", "bad-json", "null-body",
    "choice-null", "choices-string", "choices-object", "no-message", "numeric-finish", "bom-json", "slow", "unicode", "drop",
]
KB = hw.O["kb"]


def last_request():
    with urllib.request.urlopen("http://127.0.0.1:3070/last") as response:
        return json.loads(response.read())


def bodies(prompt):
    yield {"prompt": prompt}
    yield {"prompt": prompt, "currentSiteId": 1, "currentQuery": "  SELECT 1 FROM scoped_events  "}
    yield {"prompt": prompt, "history": [{"role": "user", "content": " first "}, {"role": "assistant", "content": "SELECT 2"}] * 6}
    yield {"prompt": prompt, "currentSiteId": 2, "history": [{"role": "assistant", "content": "ü🚀 \"quoted\"\n\\"}], "currentQuery": ""}


def main():
    counts, same = collections.Counter(), collections.Counter()
    out = open(os.path.join(hw.OUT, "generate-results.jsonl"), "w")
    for scenario in SCENARIOS:
        for body in bodies(scenario):
            for who in ["s:huncho", "s:justin", "k:orgKb", "k:orgKb_sql"]:
                headers, _ = caller(who)
                headers = headers + [("Content-Type", "application/json")]
                results = []
                for target in (NODE, RUST):
                    hw.reset_limits()
                    response = hw.send(target, "POST", f"/api/organizations/{KB}/analytics/query/generate", headers, jbody(body))
                    sent = last_request() if scenario != "drop" else {}
                    results.append((hw.comparable(response, {}), sent))
                counts[scenario] += 1
                equal = results[0] == results[1]
                same[scenario] += equal
                if not equal:
                    out.write(json.dumps({"scenario": scenario, "who": who, "body": body, "node": results[0], "rust": results[1]}, ensure_ascii=False) + "\n")
    for scenario in SCENARIOS:
        print(f"{scenario}\t{counts[scenario]}\t{same[scenario]}")
    print("TOTAL", sum(counts.values()), sum(same.values()))


main()
