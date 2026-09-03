# brave-rotator

A small, fast reverse proxy for the [Brave Search API](https://api-dashboard.search.brave.com/)
that spreads traffic over several subscription keys and never lets a key run into Brave's
rate limits blindly.

Written in Rust (tokio + hyper + rustls). The release binary is a single static file of a few
megabytes, idles at well under 10 MB RSS, and runs from a `scratch` container.

## What it does

Point any Brave client at this proxy instead of `https://api.search.brave.com`. Every path is
forwarded verbatim (`/res/v1/web/search`, `/res/v1/news/search`, …); the proxy only swaps in
one of its own keys as `X-Subscription-Token`.

**Rate-limit compliance** (see Brave's [rate-limiting guide](https://api-dashboard.search.brave.com/documentation/guides/rate-limiting)):

* Brave enforces a **1-second sliding window** per key. The proxy keeps its own record of when
  it last used each key and never sends more than the plan's requests/second inside one second
  (plus a `WINDOW_MARGIN_MS` safety margin for network jitter). A request that finds every key
  busy waits its turn (FIFO) for the next free slot instead of being fired into a certain 429.
* The plan limits are **learned and cached** from `X-RateLimit-Limit` after the first response,
  so a 20 req/s plan is used at 20 req/s and a free plan at 1 req/s, per key.
* **Monthly quota** (`X-RateLimit-Remaining` / `X-RateLimit-Reset`) is cached per key. A key
  whose quota hits zero is parked until the reset time Brave reported, without wasting requests
  to find out. The proactive check also fires on the *last successful* request of the month.
  Plans without a monthly cap (Brave reports a limit of `0`) are recognised and never parked.
* If Brave still answers 429, the key is held for the time given in `X-RateLimit-Reset` /
  `Retry-After` and the request is transparently retried on another key.

**Rotation:** least-recently-used among eligible keys, which is plain round-robin while all
keys are healthy and automatically skips keys that are busy, exhausted or disabled.

**Failing keys:** a key that returns 401/403 (revoked, wrong plan, …) is disabled for 5 min,
then 10, 20, … up to 1 h, and probed again with one live request each time. Three consecutive
5xx or transport errors disable a key for 30 s (doubling up to 10 min). The request that hit
the bad key is retried on another key, so clients rarely notice. Every `REPORT_INTERVAL_SECS`
(default 60 s) a status line is printed and each disabled/exhausted key gets its own warning:

```
INFO status: 2/3 keys healthy, capacity 51 req/s, monthly remaining 1812 of 2000 + 1 key(s) without cap, upstream attempts 1240 ok / 3 failed (0 were 429s)
WARN key k3:..9f2c is DISABLED: HTTP 401: {"type":"ErrorResponse","status":401,"detail":"Invalid subscription token"}; retrying at 2026-09-03T20:41:07Z (in 4m 12s)
```

## Logs

By default every proxied request is logged at INFO with its search query, the key that served
it, the upstream status and timing (`ACCESS_LOG=false` turns the per-request line off; errors
are always logged). Anything Brave answers with a non-2xx status is a WARN line that includes
Brave's error body and, for the usual mistakes, a hint:

```
INFO  GET /res/v1/web/search q="rust async runtime" -> 200 via k2:..wOrd in 311ms
INFO  key k1:..RECn: first successful request (HTTP 200)
INFO  key k1:..RECn: plan limits learned: 1 req/s, 2000 req/month, 1997 remaining, month resets in 27days 5h 41m 4s
WARN  GET /search q="hello" -> 404 via k1:..RECn in 180ms: {"type":"ErrorResponse","status":404,...} (hint: Brave Search API endpoints live under /res/v1/, e.g. /res/v1/web/search?q=...; check the base URL configured in your client)
WARN  GET /res/v1/web/search -> 422 via k3:..NlKG in 140ms: {"type":"ErrorResponse","status":422,"detail":[...]} (hint: Brave rejected the query parameters, see its detail above)
```

So if a client such as SearXNG is pointed at the proxy with a wrong base path, the 404 and the
hint show up immediately. `RUST_LOG=brave_rotator=debug` adds retry/hold details without the
noise of the HTTP libraries.

## Running

```bash
# .env
BRAVE_API_KEYS=BSAxxxxxxxx,BSAyyyyyyyy,BSAzzzzzzzz
PROXY_TOKEN=change-me            # optional but recommended

docker compose up -d --build
curl -H "X-Proxy-Token: change-me" \
     "http://localhost:8080/res/v1/web/search?q=brave+search&count=3"
```

Without Docker (needs Rust 1.98+ and a C compiler for the TLS crate):

```bash
cargo build --release                                     # dynamic binary for this machine
cargo build --release --target x86_64-unknown-linux-musl  # fully static (Docker uses this)
BRAVE_API_KEYS=... ./target/release/brave-rotator
```

Tip for WSL when the repo lives under `/mnt/c`: set `CARGO_TARGET_DIR=$HOME/.cache/cargo-target/brave-rotator`
so build artifacts stay on the Linux filesystem, which is several times faster.

## Configuration (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `BRAVE_API_KEYS` | required | Keys, separated by commas, semicolons or whitespace. Duplicates are dropped. `BRAVE_KEYS` is accepted as an alias. |
| `PROXY_TOKEN` | unset | If set, clients must send it as `X-Proxy-Token` or `X-Subscription-Token`. Without it anyone who can reach the port can spend your quota. |
| `LISTEN_ADDR` | `0.0.0.0:8080` | Bind address. |
| `BRAVE_BASE_URL` | `https://api.search.brave.com` | Upstream base URL (point it at a mock for tests). |
| `MAX_QUEUE_WAIT_MS` | `5000` | How long a request may wait for a free per-second slot before it gets a 429 with `Retry-After`. |
| `UPSTREAM_TIMEOUT_MS` | `15000` | Total budget for one upstream request. |
| `WINDOW_MARGIN_MS` | `100` | Extra time added to Brave's 1-second window to absorb network jitter. |
| `DEFAULT_RPS_PER_KEY` | `1` | Requests/second assumed per key until Brave reports the real limit. |
| `REPORT_INTERVAL_SECS` | `60` | Console status/health report interval. |
| `MAX_BODY_BYTES` | `4194304` | Largest request/response body buffered. |
| `WORKER_THREADS` | `2` | Tokio worker threads. |
| `ACCESS_LOG` | `true` | Log every proxied request (with its `q` query) at INFO. Errors are logged regardless. |
| `RUST_LOG` | `info` | Log filter; `brave_rotator=debug` adds retry and hold details. |

## Endpoints

* `ANY /...` – proxied to Brave. Response headers `X-RateLimit-Limit` / `X-RateLimit-Remaining`
  are rewritten to pool-wide values (`<req/s capacity>, <monthly total>`), and `X-Rotator-Key`
  / `X-Rotator-Attempts` tell you which key served the request.
* `GET /proxy/status` – JSON with per-key state (`ok`, `busy`, `cooling`, `exhausted`,
  `disabled`), learned limits, cached monthly remaining/reset time, and counters.
* `GET /proxy/health` – `200` while at least one key is usable, else `503`. Also used by the
  container `HEALTHCHECK` via `brave-rotator healthcheck`.

Error responses generated by the proxy itself are JSON: `{"error": "...", "detail": "...",
"status": N, "retry_after_ms": M}` with errors `unauthorized`, `body_too_large`,
`rotator_saturated` (429, all keys busy longer than `MAX_QUEUE_WAIT_MS`), `no_usable_key`
(503, all keys disabled or exhausted) and `upstream_unreachable` (502).

## CI / releases

`.github/workflows/docker-release.yml` runs `cargo fmt --check`, clippy, the unit tests and the
mock end-to-end test, then builds the image and pushes it to
`ghcr.io/<owner>/brave-search-api-rotator` (the name compose.yml uses) on pushes to `main`,
`v*` tags (which also create a GitHub release) and a daily schedule. The build stage pulls
`dhi.io/rust`, which requires a Docker Hub login: add the repository secrets
`DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (a free Docker account is enough for the Community
images). Without them the login step is skipped and the pull of `dhi.io/rust` fails; switch the
`FROM` line to the commented `rust:<version>-alpine` alternative if you prefer no login.

## Local end-to-end test without spending quota

`scripts/mock_brave.py` imitates Brave's rate limiting (1 req/s per key, a small monthly quota,
any key starting with `bad` gets 401) and `scripts/e2e.sh` runs the proxy against it:

```bash
./scripts/e2e.sh
```
