//! HTTP handlers: the transparent proxy plus the `/proxy/status` and `/proxy/health` endpoints.

use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::pool::{AcquireError, Outcome, Pool, Verdict};
use crate::ratelimit::RateLimitInfo;
use crate::upstream::{Upstream, UpstreamResponse};

pub struct AppState {
    pub cfg: Config,
    pub pool: Pool,
    pub upstream: Upstream,
    pub started: Instant,
}

/// Headers that must not be forwarded in either direction (RFC 9110 §7.6.1) or that we own.
fn hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

fn strip_request_header(name: &HeaderName) -> bool {
    hop_by_hop(name)
        || matches!(
            name.as_str(),
            "host"
                | "expect"
                | "x-subscription-token"
                | "x-api-key"
                | "x-proxy-token"
                | "authorization"
        )
}

fn strip_response_header(name: &HeaderName) -> bool {
    hop_by_hop(name) || name.as_str().starts_with("x-ratelimit-")
}

fn authorized(cfg: &Config, headers: &HeaderMap) -> bool {
    let Some(expected) = cfg.proxy_token.as_deref() else {
        return true;
    };
    ["x-proxy-token", "x-subscription-token"]
        .iter()
        .filter_map(|h| headers.get(*h))
        .any(|v| v.as_bytes() == expected.as_bytes())
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

fn error_response(
    status: StatusCode,
    error: &str,
    detail: impl Into<String>,
    retry_after_ms: Option<u128>,
) -> Response {
    let mut body = json!({ "error": error, "detail": detail.into(), "status": status.as_u16() });
    if let Some(ms) = retry_after_ms {
        body["retry_after_ms"] = json!(ms);
    }
    let mut resp = json_response(status, body);
    if let Some(ms) = retry_after_ms {
        let secs = ms.div_ceil(1000).max(1);
        if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
    }
    resp
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes a URL query component (`+` becomes a space).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Value of query parameter `name` in `path_and_query`, decoded.
fn query_param(path_and_query: &str, name: &str) -> Option<String> {
    let (_, query) = path_and_query.split_once('?')?;
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (url_decode(k) == name).then(|| url_decode(v))
    })
}

/// Truncates to `max` characters for log lines.
fn short(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push_str("...");
        t
    }
}

/// `METHOD /path q="decoded query"` for log lines (falls back to the raw query string).
fn describe_request(method: &http::Method, path_and_query: &str) -> String {
    let path = path_and_query.split('?').next().unwrap_or("/");
    match query_param(path_and_query, "q") {
        Some(q) => format!("{method} {path} q={:?}", short(&q, 120)),
        None => match path_and_query.split_once('?') {
            Some((_, qs)) if !qs.is_empty() => format!("{method} {path} ?{}", short(qs, 120)),
            _ => format!("{method} {path}"),
        },
    }
}

/// A hint for the most common client-side mistakes, appended to error logs.
fn hint_for(status: u16, path: &str) -> &'static str {
    match status {
        404 if !path.starts_with("/res/v1/") => {
            " (hint: Brave Search API endpoints live under /res/v1/, e.g. /res/v1/web/search?q=...; \
             check the base URL configured in your client)"
        }
        404 => {
            " (hint: unknown endpoint, see https://api-dashboard.search.brave.com/documentation)"
        }
        400 | 422 => " (hint: Brave rejected the query parameters, see its detail above)",
        _ => "",
    }
}

/// First ~160 printable characters of an error body, for logs and status.
fn snippet(body: &Bytes) -> String {
    let s = String::from_utf8_lossy(body);
    let cleaned: String = s.chars().filter(|c| !c.is_control()).collect();
    let trimmed = cleaned.trim();
    let mut out: String = trimmed.chars().take(160).collect();
    if trimmed.chars().count() > 160 {
        out.push_str("...");
    }
    out
}

pub async fn proxy(State(st): State<Arc<AppState>>, req: Request) -> Response {
    if !authorized(&st.cfg, req.headers()) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or wrong X-Proxy-Token",
            None,
        );
    }

    let (parts, body) = req.into_parts();
    let body = match to_bytes(body, st.cfg.max_body_bytes).await {
        Ok(b) => b,
        Err(e) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                e.to_string(),
                None,
            );
        }
    };
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();

    let mut fwd_headers = HeaderMap::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        if !strip_request_header(name) {
            fwd_headers.append(name.clone(), value.clone());
        }
    }

    let req_desc = describe_request(&parts.method, &path_and_query);
    let started = Instant::now();
    let deadline = started + st.cfg.max_queue_wait;
    let max_attempts = st.pool.len().clamp(2, 5) as u32;
    let mut tried: Vec<usize> = Vec::with_capacity(max_attempts as usize);
    let mut last_response: Option<(UpstreamResponse, String)> = None;
    let mut last_error: Option<String> = None;
    let mut acquire_error: Option<AcquireError> = None;
    let mut attempts = 0u32;

    while attempts < max_attempts {
        let lease = match st.pool.acquire(deadline, &tried).await {
            Ok(l) => l,
            Err(e) => {
                acquire_error = Some(e);
                break;
            }
        };
        attempts += 1;
        tried.push(lease.idx);
        let sent_at = Instant::now();

        match st
            .upstream
            .send(
                &parts.method,
                &path_and_query,
                &fwd_headers,
                body.clone(),
                &lease.token,
            )
            .await
        {
            Ok(resp) => {
                let rl = RateLimitInfo::from_headers(&resp.headers);
                let snip = if resp.status.is_success() {
                    None
                } else {
                    Some(snippet(&resp.body))
                };
                let verdict = st.pool.record(
                    lease.idx,
                    Outcome::Response {
                        status: resp.status.as_u16(),
                        rl,
                        body_snippet: snip.as_deref(),
                    },
                );
                let elapsed = sent_at.elapsed().as_millis();
                let status = resp.status.as_u16();
                let retried = if attempts > 1 {
                    format!(" (attempt {attempts})")
                } else {
                    String::new()
                };
                match verdict {
                    Verdict::Ok => {
                        if st.cfg.access_log {
                            info!(
                                "{req_desc} -> {status} via {} in {elapsed}ms{retried}",
                                lease.label
                            );
                        } else {
                            debug!(
                                "{req_desc} -> {status} via {} in {elapsed}ms{retried}",
                                lease.label
                            );
                        }
                        return build_response(&st, resp, &lease.label, attempts);
                    }
                    Verdict::ReturnToClient => {
                        warn!(
                            "{req_desc} -> {status} via {} in {elapsed}ms: {}{}",
                            lease.label,
                            snip.as_deref().unwrap_or("(empty body)"),
                            hint_for(status, parts.uri.path())
                        );
                        return build_response(&st, resp, &lease.label, attempts);
                    }
                    Verdict::RetryOtherKey => {
                        info!(
                            "{req_desc} -> {status} via {} in {elapsed}ms: {}; trying another key",
                            lease.label,
                            snip.as_deref().unwrap_or("(empty body)")
                        );
                        last_response = Some((resp, lease.label));
                    }
                }
            }
            Err(e) => {
                st.pool.record(lease.idx, Outcome::Transport(e.to_string()));
                info!(
                    "{req_desc} via {} failed: {e}; trying another key",
                    lease.label
                );
                last_error = Some(e.to_string());
            }
        }
    }

    match acquire_error {
        Some(AcquireError::Saturated { retry_after }) => {
            let ms = retry_after.as_millis();
            warn!(
                "{req_desc}: all keys busy for another {ms}ms (> MAX_QUEUE_WAIT_MS); rejecting with 429"
            );
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rotator_saturated",
                format!("every key's per-second budget is spent; next slot in {ms}ms"),
                Some(ms),
            );
        }
        Some(AcquireError::Unavailable {
            retry_after,
            summary,
        }) => {
            warn!("{req_desc}: no usable key ({summary})");
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "no_usable_key",
                summary,
                retry_after.map(|d| d.as_millis()),
            );
        }
        None => {}
    }

    if let Some((resp, label)) = last_response {
        warn!(
            "{req_desc}: giving up after {attempts} attempts, returning upstream {} from {label}",
            resp.status.as_u16()
        );
        return build_response(&st, resp, &label, attempts);
    }
    let detail = last_error.unwrap_or_else(|| "no attempt could be made".into());
    warn!("{req_desc}: upstream unreachable: {detail}");
    error_response(
        StatusCode::BAD_GATEWAY,
        "upstream_unreachable",
        detail,
        None,
    )
}

fn build_response(st: &AppState, up: UpstreamResponse, key_label: &str, attempts: u32) -> Response {
    let mut resp = Response::new(Body::from(up.body));
    *resp.status_mut() = up.status;
    let h = resp.headers_mut();
    for (name, value) in &up.headers {
        if !strip_response_header(name) {
            h.append(name.clone(), value.clone());
        }
    }
    // Replace the per-key rate-limit headers with a pool-wide view.
    let snap = st.pool.snapshot();
    // Brave's convention: a monthly value of 0 means "no monthly cap".
    let month = |v: Option<u64>| {
        if snap.month_unlimited_keys > 0 {
            "0".to_string()
        } else {
            v.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
        }
    };
    set(
        h,
        "x-ratelimit-limit",
        &format!("{}, {}", snap.rps_capacity, month(snap.month_limit_total)),
    );
    set(
        h,
        "x-ratelimit-remaining",
        &format!(
            "{}, {}",
            snap.slots_available_now,
            month(snap.month_remaining_total)
        ),
    );
    set(h, "x-rotator-key", key_label);
    set(h, "x-rotator-attempts", &attempts.to_string());
    resp
}

fn set(h: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        h.insert(HeaderName::from_static(name), v);
    }
}

pub async fn status(State(st): State<Arc<AppState>>, req: Request) -> Response {
    if !authorized(&st.cfg, req.headers()) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or wrong X-Proxy-Token",
            None,
        );
    }
    let snap = st.pool.snapshot();
    let body = json!({
        "service": "brave-rotator",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": crate::pool::fmt_dur(st.started.elapsed()),
        "config": {
            "upstream": st.cfg.upstream_base,
            "max_queue_wait_ms": st.cfg.max_queue_wait.as_millis(),
            "upstream_timeout_ms": st.cfg.upstream_timeout.as_millis(),
            "window_margin_ms": st.cfg.window_margin.as_millis(),
            "auth_required": st.cfg.proxy_token.is_some(),
            "access_log": st.cfg.access_log,
        },
        "pool": snap,
    });
    json_response(StatusCode::OK, body)
}

pub async fn health(State(st): State<Arc<AppState>>) -> Response {
    let snap = st.pool.snapshot();
    let ok = snap.keys_healthy > 0;
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    json_response(
        status,
        json!({
            "status": if ok { "ok" } else { "degraded" },
            "keys_healthy": snap.keys_healthy,
            "keys_total": snap.keys_total,
        }),
    )
}
