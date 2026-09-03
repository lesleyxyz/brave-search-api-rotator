#!/usr/bin/env bash
# End-to-end check of brave-rotator against the mock Brave API in scripts/mock_brave.py.
# Verifies: transparent rotation, per-second pacing (the mock never sees a 429), a bad key being
# disabled and its request retried on another key, monthly exhaustion parking keys, and the
# health/status endpoints. Needs python3 and curl >= 7.84.
#
#   ./scripts/e2e.sh                       # builds target/release first
#   BIN=path/to/brave-rotator ./scripts/e2e.sh
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${BIN:-}"
if [[ -z "$BIN" ]]; then
  cargo build --release --quiet
  BIN="${CARGO_TARGET_DIR:-target}/release/brave-rotator"
fi
MOCK_PORT="${MOCK_PORT:-19999}"
PROXY_PORT="${PROXY_PORT:-18080}"
MONTH="${MOCK_MONTH:-6}"
TMP="$(mktemp -d)"
PROXY="http://127.0.0.1:$PROXY_PORT"
MOCK="http://127.0.0.1:$MOCK_PORT"

cleanup() { kill "${MOCK_PID:-}" "${ROT_PID:-}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- rotator log ---" >&2; tail -40 "$TMP/rotator.log" >&2
  echo "--- mock log ---" >&2; tail -20 "$TMP/mock.log" >&2
  exit 1
}

MOCK_PORT="$MOCK_PORT" MOCK_RPS=1 MOCK_MONTH="$MONTH" python3 scripts/mock_brave.py >"$TMP/mock.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 50); do
  curl -sf "$MOCK/mock/stats" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "$MOCK/mock/stats" >/dev/null || fail "mock did not come up"

BRAVE_API_KEYS="mockkeyAAAA, mockkeyBBBB, badkeyCCCC" \
BRAVE_BASE_URL="$MOCK" \
LISTEN_ADDR="127.0.0.1:$PROXY_PORT" \
REPORT_INTERVAL_SECS=3 MAX_QUEUE_WAIT_MS=8000 RUST_LOG=debug NO_COLOR=1 \
"$BIN" >"$TMP/rotator.log" 2>&1 &
ROT_PID=$!

for _ in $(seq 1 50); do
  curl -sf "$PROXY/proxy/health" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "$PROXY/proxy/health" >/dev/null || fail "proxy did not come up"
echo "proxy up (pid $ROT_PID) -> mock up (pid $MOCK_PID); logs in $TMP"

echo
echo "== 1. burst of 8 concurrent requests over 2 good keys + 1 bad key =="
start_ms=$(( $(date +%s%N) / 1000000 ))
seq 1 8 | xargs -P 8 -I{} curl -s -o /dev/null \
  -w "%{http_code} key=%header{x-rotator-key} attempts=%header{x-rotator-attempts} pool-remaining=[%header{x-ratelimit-remaining}]\n" \
  "$PROXY/res/v1/web/search?q=test{}&count=1" | sort | tee "$TMP/burst.txt"
elapsed_ms=$(( $(date +%s%N) / 1000000 - start_ms ))
echo "elapsed: ${elapsed_ms}ms (8 requests over a 2 req/s pool must take >= 3s, and well under the 8s queue budget)"
[[ "$(grep -c '^200 ' "$TMP/burst.txt")" -eq 8 ]] || fail "expected 8x HTTP 200"
(( elapsed_ms >= 3000 && elapsed_ms < 7000 )) || fail "unexpected pacing: ${elapsed_ms}ms"
stats=$(curl -s "$MOCK/mock/stats")
echo "mock saw: $stats"
echo "$stats" | grep -q '"429"' && fail "the mock returned a 429: pacing failed"
echo "$stats" | grep -q '"401": 1' || fail "expected exactly one 401 (bad key probed once, then disabled)"
grep -q 'badkeyCCCC\|k3:..CCCC: DISABLED' "$TMP/rotator.log" || fail "expected a DISABLED log line for the bad key"
echo "OK: all 200, spread over both keys, mock never rate-limited us, bad key disabled after one 401"

echo
echo "== 2. monthly exhaustion (mock quota: $MONTH successful requests per key) =="
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code} key=%header{x-rotator-key} retry-after=%header{retry-after}\n" \
    "$PROXY/res/v1/web/search?q=more$i"
done | tee "$TMP/exhaust.txt"
grep -q '^503 ' "$TMP/exhaust.txt" || fail "expected 503 no_usable_key once both quotas are spent"
curl -s "$PROXY/proxy/status" | python3 -c '
import json, sys
d = json.load(sys.stdin)["pool"]
print("status endpoint -> healthy:", d["keys_healthy"], "| monthly remaining:", d["month_remaining_total"])
for k in d["keys"]:
    print("   ", k["key"], k["state"], "| monthly", k["monthly"]["remaining"], "/", k["monthly"]["limit"],
          "| resets in", k["monthly"]["reset_in"], "| reason:", k["reason"])
assert d["keys_healthy"] == 0, d
assert [k["state"] for k in d["keys"]] == ["exhausted", "exhausted", "disabled"], d
'
health_code=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY/proxy/health")
[[ "$health_code" == "503" ]] || fail "health should be 503 when no key is usable (got $health_code)"
if LISTEN_ADDR="127.0.0.1:$PROXY_PORT" "$BIN" healthcheck; then
  fail "healthcheck subcommand should exit non-zero while degraded"
fi
echo "OK: both keys parked as exhausted until the reported reset, health reports degraded"

echo
echo "== 3. resources =="
echo "rotator RSS: $(ps -o rss= -p "$ROT_PID" 2>/dev/null | tr -d ' ') KB | binary: $(du -h "$BIN" | cut -f1) | $(file -b "$BIN" | cut -d, -f1-2)"

echo
echo "== rotator log highlights =="
grep -E "WARN|INFO.*(status:|learned|DISABLED|EXHAUSTED|recovered)" "$TMP/rotator.log" | tail -12
echo
echo "ALL CHECKS PASSED"
