#!/usr/bin/env python3
"""Print a report written by harness.py or writes.py: the counts per route and
every remaining difference."""
import json
import sys

for path in sys.argv[1:]:
    with open(path) as handle:
        report = json.load(handle)
    print(f"== {path}")
    print(f"   total {report['total']}  identical {report['identical']}  "
          f"known-shared-gaps {report.get('known_shared_head_404_length', 0)}  "
          f"failures {len(report['failures'])}")
    for route, counts in report["routes"].items():
        flag = "" if counts["pairs"] == counts["identical"] else "   <-- DIFFERS"
        print(f"   {counts['identical']:>5}/{counts['pairs']:<5} {route}  {counts['statuses']}{flag}")
    for failure in report["failures"]:
        print("   FAIL " + json.dumps(failure, default=str)[:2000])
