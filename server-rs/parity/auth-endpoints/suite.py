#!/usr/bin/env python3
"""Differential suite for /api/auth: Node (NODE_PORT, default 3021) vs Rust (RUST_PORT, default 3057).

Usage: suite.py [scenario-name-substring ...] [--verbose]
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import diffcore
import sc_core

MODULES = [sc_core]
for optional in ("sc_account", "sc_otp", "sc_org", "sc_keys_admin", "sc_mcp", "sc_cross"):
    try:
        MODULES.append(__import__(optional))
    except ModuleNotFoundError:
        pass

args = [a for a in sys.argv[1:] if not a.startswith("--")]
verbose = "--verbose" in sys.argv
diffcore.DUMP = "--dump" in sys.argv
scenarios = [s for m in MODULES for s in m.SCENARIOS]
results, mismatches = diffcore.run_scenarios(scenarios, int(os.environ.get("NODE_PORT", 3021)), int(os.environ.get("RUST_PORT", 3057)), only=args or None)

total_pass = sum(p for p, _ in results.values())
total = sum(t for _, t in results.values())
print("\n=== per endpoint ===")
for endpoint, (passed, count) in sorted(results.items()):
    print(f"{passed:4d}/{count:<4d} {endpoint}")
print(f"\n{total_pass}/{total} checks identical")
acao_only = [m for m in mismatches if m[4] == "acao"]
print(f"{len(acao_only)} of {len(mismatches)} mismatches differ only in Access-Control-Allow-Origin (Node `*`, Rust CORS layer reflects the origin)")
for scenario, endpoint, node, rust, order_only in mismatches:
    label = " (Access-Control-Allow-Origin only)" if order_only == "acao" else " (key order only)" if order_only else ""
    print(f"\n--- MISMATCH [{scenario}] {endpoint}{label}")
    print("  node:", json.dumps(node)[: None if verbose else 1500])
    print("  rust:", json.dumps(rust)[: None if verbose else 1500])
sys.exit(1 if mismatches else 0)
