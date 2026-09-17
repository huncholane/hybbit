#!/usr/bin/env python3
"""A stand-in for OpenRouter's chat completions endpoint. The scenario is picked
from the prompt (the text after "Current user request:\n" in the last message);
GET /last returns the most recent request (headers that matter and raw body) so
the harness can compare what each backend sent.

Usage: openrouter_mock.py [port]   (default 3070)
"""
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAST = {}


def choice(content, finish="stop", extra=None):
    body = {"id": "gen-1", "model": "mock", "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": finish}]}
    body.update(extra or {})
    return 200, json.dumps(body)


SCENARIOS = {
    "ok-plain": lambda: choice("SELECT count() AS events FROM scoped_events"),
    "ok-fenced": lambda: choice("Here you go:\n```sql\nSELECT pathname, count() c FROM scoped_events GROUP BY pathname LIMIT 10;\n```\n"),
    "ok-label": lambda: choice("sql: SELECT 1 FROM scoped_events;;"),
    "invalid-sql": lambda: choice("SELECT * FROM events"),
    "redefine": lambda: choice("WITH scoped_events AS (SELECT 1) SELECT * FROM scoped_events"),
    "empty-choices": lambda: (200, '{"choices":[]}'),
    "no-choices": lambda: (200, "{}"),
    "empty-length": lambda: choice("", "length"),
    "whitespace-stop": lambda: choice("   ", "stop"),
    "null-content": lambda: choice(None, None),
    "array-content": lambda: choice(["SELECT 1"]),
    "http-500": lambda: (500, "boom"),
    "http-401": lambda: (401, '{"error":{"message":"No auth"}}'),
    "http-429": lambda: (429, ""),
    "bad-json": lambda: (200, "not json"),
    "null-body": lambda: (200, "null"),
    "choice-null": lambda: (200, '{"choices":[null]}'),
    "choices-string": lambda: (200, '{"choices":"abc"}'),
    "choices-object": lambda: (200, '{"choices":{"length":0}}'),
    "no-message": lambda: (200, '{"choices":[{"finish_reason":"length"}]}'),
    "numeric-finish": lambda: (200, '{"choices":[{"message":{"content":""},"finish_reason":0}]}'),
    "bom-json": lambda: (200, "﻿" + json.dumps({"choices": [{"message": {"content": "SELECT 2 FROM scoped_events"}}]})),
    "slow": lambda: (time.sleep(1.5), choice("SELECT 3 FROM scoped_events"))[1],
    "unicode": lambda: choice("SELECT 'ü🚀' AS s FROM scoped_events"),
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        data = json.dumps(LAST).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        LAST.clear()
        LAST.update({
            "path": self.path,
            "headers": {name: self.headers.get(name) for name in ("Authorization", "Content-Type", "HTTP-Referer", "X-Title")},
            "body": raw.decode("utf-8", "replace"),
        })
        try:
            prompt = json.loads(raw)["messages"][-1]["content"].split("Current user request:\n", 1)[1]
        except Exception:  # noqa: BLE001
            prompt = ""
        if prompt == "drop":
            self.close_connection = True
            self.connection.close()
            return
        status, body = SCENARIOS.get(prompt, SCENARIOS["ok-plain"])()
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("x-request-id", "req-mock")
        self.end_headers()
        self.wfile.write(data)


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 3070), Handler).serve_forever()
