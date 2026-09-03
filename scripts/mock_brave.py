#!/usr/bin/env python3
"""Mock of api.search.brave.com for testing brave-rotator without spending quota.

Per key it enforces what Brave documents:
  * MOCK_RPS requests per 1-second sliding window (default 1) -> 429 beyond that
  * MOCK_MONTH successful requests per "month" (default 15000, 0 = unlimited) -> 429 once spent
  * every response carries X-RateLimit-Limit / -Policy / -Remaining / -Reset
Special keys: starting with "bad" -> 401, starting with "flaky" -> 500 on every 2nd call.
GET /mock/stats returns how many responses of each status were served.

Usage: MOCK_PORT=19999 MOCK_RPS=1 MOCK_MONTH=6 python3 scripts/mock_brave.py
"""
import json
import math
import os
import sys
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RPS = int(os.environ.get("MOCK_RPS", "1"))
MONTH = int(os.environ.get("MOCK_MONTH", "15000"))
PORT = int(os.environ.get("MOCK_PORT", "9999"))
LATENCY = float(os.environ.get("MOCK_LATENCY_MS", "0")) / 1000.0
WINDOW = 1.0
MONTH_WINDOW = 2_592_000

lock = threading.RLock()
sends = defaultdict(deque)      # key -> timestamps inside the sliding window
used = defaultdict(int)         # key -> successful requests this "month"
calls = defaultdict(int)        # key -> total calls (for the flaky key)
per_status = defaultdict(int)   # status -> count
month_reset_at = time.time() + 16 * 86400


def tail(key):
    return (key or "-")[-4:]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-brave/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock] %s key=..%s %s\n" % (
            time.strftime("%H:%M:%S"), tail(self.headers.get("X-Subscription-Token")), fmt % args))

    def rl_headers(self, key, now):
        q = sends[key]
        sec_remaining = max(0, RPS - len(q))
        sec_reset = max(1, math.ceil(WINDOW - (now - q[0]))) if q else 1
        month_remaining = max(0, MONTH - used[key]) if MONTH else 0
        return {
            "X-RateLimit-Limit": f"{RPS}, {MONTH}",
            "X-RateLimit-Policy": f"{RPS};w={int(WINDOW)}, {MONTH};w={MONTH_WINDOW}",
            "X-RateLimit-Remaining": f"{sec_remaining}, {month_remaining}",
            "X-RateLimit-Reset": f"{sec_reset}, {int(month_reset_at - now)}",
        }

    def do_GET(self):
        self.handle_any()

    def do_POST(self):
        self.handle_any()

    def handle_any(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if LATENCY:
            time.sleep(LATENCY)

        if self.path.startswith("/mock/stats"):
            with lock:
                body = {"per_status": dict(per_status),
                        "used_per_key": {tail(k): v for k, v in used.items()}}
            return self.reply(200, body, {})

        key = self.headers.get("X-Subscription-Token")
        now = time.time()
        if not key or key.startswith("bad"):
            return self.reply(401, {"type": "ErrorResponse", "status": 401,
                                    "detail": "Invalid subscription token"}, {})
        with lock:
            calls[key] += 1
            if key.startswith("flaky") and calls[key] % 2 == 0:
                return self.reply(500, {"type": "ErrorResponse", "status": 500,
                                        "detail": "mock internal error"}, {})
            q = sends[key]
            while q and now - q[0] >= WINDOW:
                q.popleft()
            if MONTH and used[key] >= MONTH:
                return self.reply(429, {"type": "ErrorResponse", "status": 429,
                                        "detail": "Monthly quota exceeded"}, self.rl_headers(key, now))
            if len(q) >= RPS:
                return self.reply(429, {"type": "ErrorResponse", "status": 429,
                                        "detail": "Rate limit exceeded"}, self.rl_headers(key, now))
            q.append(now)
            used[key] += 1
            headers = self.rl_headers(key, now)
        body = {"type": "search", "mock": True, "served_by_key": tail(key), "path": self.path}
        return self.reply(200, body, headers)

    def reply(self, code, body, headers):
        data = json.dumps(body).encode()
        with lock:
            per_status[str(code)] += 1
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"mock brave listening on 127.0.0.1:{PORT} (rps={RPS}, month={MONTH})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
