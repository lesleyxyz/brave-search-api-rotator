//! The key pool: per-key rate-limit bookkeeping, health tracking and fair rotation.
//!
//! Every key keeps a local model of Brave's two limit windows:
//!
//! * **per-second sliding window** – we remember the timestamps of our own sends and never
//!   exceed the plan's requests/second (learned from `X-RateLimit-Limit`, default 1) within
//!   one second plus a small jitter margin. A request that finds every key busy waits for the
//!   earliest free slot instead of being fired into a certain 429.
//! * **monthly quota** – remaining count and the reset time are cached from the response
//!   headers, so a key whose quota hits zero is parked until Brave says it resets, without
//!   burning a request to find out.
//!
//! Rotation is least-recently-used among eligible keys, which degrades gracefully into plain
//! round-robin when all keys are healthy and spreads load evenly across the pool.
//!
//! Keys that misbehave (401/403, repeated 5xx or transport errors) are disabled with an
//! exponential backoff and probed again afterwards; the periodic reporter prints them.

use std::cmp::Reverse;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use tracing::{debug, info, warn};

use crate::ratelimit::RateLimitInfo;

/// Brave's burst window.
pub const WINDOW: Duration = Duration::from_secs(1);

const FAIL_THRESHOLD: u32 = 3;
const FAIL_BACKOFF_BASE: Duration = Duration::from_secs(30);
const FAIL_BACKOFF_MAX: Duration = Duration::from_secs(10 * 60);
const AUTH_BACKOFF_BASE: Duration = Duration::from_secs(5 * 60);
const AUTH_BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);
const UNEXPLAINED_429_THRESHOLD: u32 = 5;
const UNEXPLAINED_429_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// If Brave says the month is exhausted but does not tell us when it resets.
const EXHAUSTED_FALLBACK: Duration = Duration::from_secs(6 * 60 * 60);
/// Fallback park duration when a self-imposed monthly cap (BRAVE_MONTHLY_LIMITS) is hit and
/// Brave's own response gave us no reset time to go by.
const OVERRIDE_CAP_FALLBACK: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MAX_LEARNED_RPS: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Ok,
    /// Skipped until `until`, then probed with one live request.
    Disabled {
        until: Instant,
        reason: String,
    },
    /// Monthly quota used up; skipped until Brave's reported reset time.
    Exhausted {
        until: Instant,
    },
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Stats {
    pub requests: u64,
    pub ok: u64,
    pub upstream_429: u64,
    pub client_4xx: u64,
    pub server_5xx: u64,
    pub transport_errors: u64,
    pub last_status: Option<u16>,
    pub last_error: Option<String>,
}

#[derive(Debug)]
pub struct KeyState {
    pub token: String,
    pub label: String,
    pub health: Health,
    /// Requests/second this key may burst (from X-RateLimit-Limit, default from config).
    pub sec_limit: u32,
    pub limits_learned: bool,
    pub month_limit: Option<u64>,
    pub month_remaining: Option<u64>,
    pub month_reset_at: Option<Instant>,
    /// Short hold requested by upstream (per-second 429).
    pub hold_until: Option<Instant>,
    /// Timestamps of our sends inside the current sliding window.
    pub sends: VecDeque<Instant>,
    pub last_used: Option<Instant>,
    pub last_ok: Option<Instant>,
    pub consecutive_failures: u32,
    pub consecutive_429: u32,
    /// Times this key was disabled without a success in between (backoff exponent).
    pub disable_strikes: u32,
    pub disabled_since: Option<Instant>,
    pub stats: Stats,
    /// Self-imposed monthly cap from BRAVE_MONTHLY_LIMITS, if set for this key. Enforced
    /// in addition to (the stricter of) whatever Brave itself reports.
    pub monthly_cap_override: Option<u64>,
}

impl KeyState {
    fn new(idx: usize, token: String, default_rps: u32, monthly_cap_override: Option<u64>) -> Self {
        let tail: String = token
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        Self {
            label: format!("k{}:..{}", idx + 1, tail),
            token,
            health: Health::Ok,
            sec_limit: default_rps.max(1),
            limits_learned: false,
            month_limit: None,
            month_remaining: None,
            month_reset_at: None,
            hold_until: None,
            sends: VecDeque::with_capacity(4),
            last_used: None,
            last_ok: None,
            consecutive_failures: 0,
            consecutive_429: 0,
            disable_strikes: 0,
            disabled_since: None,
            stats: Stats::default(),
            monthly_cap_override,
        }
    }

    /// Re-enables keys whose cooldown has elapsed.
    fn refresh(&mut self, now: Instant) {
        match &self.health {
            Health::Disabled { until, reason } if *until <= now => {
                info!(
                    "key {}: cooldown over, probing again (was: {})",
                    self.label, reason
                );
                self.health = Health::Ok;
            }
            Health::Exhausted { until } if *until <= now => {
                info!(
                    "key {}: monthly quota should have reset, probing again",
                    self.label
                );
                self.month_remaining = None;
                self.month_reset_at = None;
                self.health = Health::Ok;
            }
            _ => {}
        }
    }

    fn prune_window(&mut self, now: Instant, window: Duration) {
        while let Some(&t) = self.sends.front() {
            if now.saturating_duration_since(t) >= window {
                self.sends.pop_front();
            } else {
                break;
            }
        }
    }

    /// `Ok(())` if a request may be sent now, otherwise the earliest instant it may.
    fn availability(&mut self, now: Instant, window: Duration) -> Result<(), Instant> {
        match &self.health {
            Health::Disabled { until, .. } | Health::Exhausted { until } => return Err(*until),
            Health::Ok => {}
        }
        if let Some(h) = self.hold_until {
            if h > now {
                return Err(h);
            }
            self.hold_until = None;
        }
        self.prune_window(now, window);
        if self.sends.len() as u32 >= self.sec_limit.max(1)
            && let Some(&oldest) = self.sends.front()
        {
            return Err(oldest + window);
        }
        Ok(())
    }

    fn free_slots(&self) -> u32 {
        if self.health != Health::Ok || self.hold_until.is_some() {
            return 0;
        }
        self.sec_limit
            .max(1)
            .saturating_sub(self.sends.len() as u32)
    }

    /// Brave reports a monthly limit of 0 for plans without a monthly cap. A locally
    /// configured override always takes precedence, since it exists precisely to correct
    /// cases where Brave's headers under- or over-state the real usable quota.
    fn month_unlimited(&self) -> bool {
        if self.monthly_cap_override.is_some() {
            return false;
        }
        self.month_limit == Some(0)
    }

    /// Requests already counted against the effective monthly cap this cycle. Uses our own
    /// success counter when an override is active (Brave's own  header may be
    /// tracking a different, higher limit than our override).
    fn effective_month_used(&self) -> u64 {
        if self.monthly_cap_override.is_some() {
            self.stats.ok
        } else {
            self.month_limit
                .zip(self.month_remaining)
                .map(|(l, r)| l.saturating_sub(r))
                .unwrap_or(0)
        }
    }

    /// Remaining monthly quota as used for ranking: unknown or unlimited count as "plenty".
    fn month_remaining_for_ranking(&self) -> u64 {
        if let Some(cap) = self.monthly_cap_override {
            return cap.saturating_sub(self.effective_month_used());
        }
        if self.month_unlimited() {
            u64::MAX
        } else {
            self.month_remaining.unwrap_or(u64::MAX)
        }
    }

    /// True once the self-imposed override cap (if any) has been used up this cycle.
    fn override_cap_exhausted(&self) -> bool {
        self.monthly_cap_override
            .is_some_and(|cap| self.effective_month_used() >= cap)
    }

    fn learn_limits(&mut self, now: Instant, rl: &RateLimitInfo) {
        if let Some(l) = rl.limit.second.filter(|l| *l > 0) {
            self.sec_limit = l.min(MAX_LEARNED_RPS) as u32;
        }
        if rl.limit.month.is_some() {
            self.month_limit = rl.limit.month;
        }
        if rl.remaining.month.is_some() {
            self.month_remaining = rl.remaining.month;
        }
        if let Some(r) = rl.month_reset() {
            self.month_reset_at = Some(now + r);
        }
        if !self.limits_learned && (rl.limit.second.is_some() || rl.limit.month.is_some()) {
            self.limits_learned = true;
            if self.month_unlimited() {
                info!(
                    "key {}: plan limits learned: {} req/s, no monthly cap",
                    self.label, self.sec_limit
                );
            } else {
                info!(
                    "key {}: plan limits learned: {} req/s, {} req/month, {} remaining, month resets in {}",
                    self.label,
                    self.sec_limit,
                    self.month_limit
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    self.month_remaining
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    rl.month_reset().map(fmt_dur).unwrap_or_else(|| "?".into()),
                );
            }
        }
    }

    fn disable(&mut self, now: Instant, base: Duration, max: Duration, reason: String) {
        self.disable_strikes = self.disable_strikes.saturating_add(1);
        let factor = 1u32 << (self.disable_strikes - 1).min(16);
        let dur = base.saturating_mul(factor).min(max);
        let until = now + dur;
        self.disabled_since.get_or_insert(now);
        self.consecutive_failures = 0;
        self.consecutive_429 = 0;
        warn!(
            "key {}: DISABLED for {} (strike {}) - {}; will probe again at {}",
            self.label,
            fmt_dur(dur),
            self.disable_strikes,
            reason,
            fmt_instant(until)
        );
        self.health = Health::Disabled { until, reason };
    }

    fn exhaust(&mut self, now: Instant, reset_in: Option<Duration>) {
        let reset_in = reset_in.unwrap_or(EXHAUSTED_FALLBACK);
        let until = now + reset_in;
        if !matches!(self.health, Health::Exhausted { .. }) {
            warn!(
                "key {}: monthly quota EXHAUSTED ({} req/month); parked until {} (in {})",
                self.label,
                self.month_limit
                    .map(fmt_quota)
                    .unwrap_or_else(|| "?".into()),
                fmt_instant(until),
                fmt_dur(reset_in)
            );
        }
        self.month_remaining = Some(0);
        self.month_reset_at = Some(until);
        self.health = Health::Exhausted { until };
    }

    fn fail(&mut self, now: Instant, what: &str) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= FAIL_THRESHOLD {
            let reason = format!(
                "{what} ({} consecutive failures)",
                self.consecutive_failures
            );
            self.disable(now, FAIL_BACKOFF_BASE, FAIL_BACKOFF_MAX, reason);
        } else {
            warn!(
                "key {}: {} ({}/{} before disabling)",
                self.label, what, self.consecutive_failures, FAIL_THRESHOLD
            );
        }
    }
}

/// What a request should do after the pool has digested an upstream outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Success: hand the response to the client.
    Ok,
    /// The key (or upstream) failed in a way another key might not: try again with a different key.
    RetryOtherKey,
    /// The request itself was rejected (400/404/422 …): hand the response to the client as-is.
    ReturnToClient,
}

pub enum Outcome<'a> {
    Response {
        status: u16,
        rl: Option<RateLimitInfo>,
        body_snippet: Option<&'a str>,
    },
    Transport(String),
}

#[derive(Debug)]
pub struct Lease {
    pub idx: usize,
    pub token: String,
    pub label: String,
}

/// Why `try_acquire` could not hand out a key right now.
#[derive(Debug)]
pub enum Next {
    /// Some key becomes eligible at this instant.
    At(Instant),
    /// Every key is disabled or exhausted.
    Unavailable {
        earliest: Option<Instant>,
        summary: String,
    },
}

#[derive(Debug)]
pub enum AcquireError {
    /// All keys are healthy but the per-second budget is spent for longer than the caller can wait.
    Saturated { retry_after: Duration },
    /// No key is usable at all (all disabled/exhausted).
    Unavailable {
        retry_after: Option<Duration>,
        summary: String,
    },
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub window_margin: Duration,
    pub default_rps: u32,
    /// Positional self-imposed monthly cap per key, matching the order of  passed to
    /// . Shorter than  or entries of  fall back to Brave-detected limits.
    pub monthly_limits: Vec<Option<u64>>,
}

pub struct Pool {
    inner: Mutex<Vec<KeyState>>,
    /// FIFO turnstile so waiting requests are served in arrival order and never stampede.
    turnstile: tokio::sync::Mutex<()>,
    cfg: PoolConfig,
}

impl Pool {
    pub fn new(keys: &[String], cfg: PoolConfig) -> Self {
        let keys = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let cap_override = cfg.monthly_limits.get(i).copied().flatten();
                KeyState::new(i, k.clone(), cfg.default_rps, cap_override)
            })
            .collect();
        Self {
            inner: Mutex::new(keys),
            turnstile: tokio::sync::Mutex::new(()),
            cfg,
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<KeyState>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn window(&self) -> Duration {
        WINDOW + self.cfg.window_margin
    }

    /// Non-blocking selection at `now`. Reserves the slot (records the send) on success.
    ///
    /// `exclude` lists keys already tried for this request; they are only considered if no
    /// other key could ever serve it.
    pub fn try_acquire(&self, now: Instant, exclude: &[usize]) -> Result<Lease, Next> {
        let window = self.window();
        let mut keys = self.lock();
        for k in keys.iter_mut() {
            k.refresh(now);
        }

        // Lower is better: least recently used first, then the key with most monthly quota left.
        type Score = (Option<Instant>, Reverse<u64>);
        // Returns (best eligible key, earliest time any considered key frees up, any healthy key seen).
        let pick = |keys: &mut Vec<KeyState>,
                    skip_excluded: bool|
         -> (Option<usize>, Option<Instant>, bool) {
            let mut best: Option<(usize, Score)> = None;
            let mut next: Option<Instant> = None;
            let mut any_healthy = false;
            for (i, k) in keys.iter_mut().enumerate() {
                if skip_excluded && exclude.contains(&i) {
                    continue;
                }
                if k.health == Health::Ok {
                    any_healthy = true;
                }
                match k.availability(now, window) {
                    Ok(()) => {
                        let score = (k.last_used, Reverse(k.month_remaining_for_ranking()));
                        if best.as_ref().is_none_or(|(_, s)| score < *s) {
                            best = Some((i, score));
                        }
                    }
                    Err(at) => next = Some(next.map_or(at, |n: Instant| n.min(at))),
                }
            }
            (best.map(|(i, _)| i), next, any_healthy)
        };

        let mut result = pick(&mut keys, true);
        if result.0.is_none() && !exclude.is_empty() && !result.2 {
            // Only excluded keys could serve this: allow them again (e.g. single-key pools).
            result = pick(&mut keys, false);
        }

        match result {
            (Some(i), _, _) => {
                let k = &mut keys[i];
                k.sends.push_back(now);
                k.last_used = Some(now);
                k.stats.requests += 1;
                Ok(Lease {
                    idx: i,
                    token: k.token.clone(),
                    label: k.label.clone(),
                })
            }
            (None, next, true) => Err(Next::At(next.unwrap_or(now))),
            (None, next, false) => {
                let summary = keys
                    .iter()
                    .map(|k| match &k.health {
                        Health::Disabled { reason, until } => {
                            format!(
                                "{} disabled ({}) until {}",
                                k.label,
                                reason,
                                fmt_instant(*until)
                            )
                        }
                        Health::Exhausted { until } => {
                            format!(
                                "{} monthly quota exhausted until {}",
                                k.label,
                                fmt_instant(*until)
                            )
                        }
                        Health::Ok => format!("{} ok", k.label),
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(Next::Unavailable {
                    earliest: next,
                    summary,
                })
            }
        }
    }

    /// Waits (in FIFO order) for a key with a free rate-limit slot, up to `deadline`.
    pub async fn acquire(
        &self,
        deadline: Instant,
        exclude: &[usize],
    ) -> Result<Lease, AcquireError> {
        let _turn = self.turnstile.lock().await;
        loop {
            let now = Instant::now();
            match self.try_acquire(now, exclude) {
                Ok(lease) => return Ok(lease),
                Err(Next::At(at)) => {
                    if at > deadline {
                        return Err(AcquireError::Saturated {
                            retry_after: at - now,
                        });
                    }
                    tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
                }
                Err(Next::Unavailable { earliest, summary }) => {
                    return Err(AcquireError::Unavailable {
                        retry_after: earliest.map(|e| e.saturating_duration_since(now)),
                        summary,
                    });
                }
            }
        }
    }

    /// Digest the result of a request sent with `idx` and decide what the caller should do.
    pub fn record(&self, idx: usize, outcome: Outcome<'_>) -> Verdict {
        let now = Instant::now();
        let mut keys = self.lock();
        let Some(k) = keys.get_mut(idx) else {
            return Verdict::ReturnToClient;
        };

        match outcome {
            Outcome::Transport(err) => {
                k.stats.transport_errors += 1;
                k.stats.last_status = None;
                k.stats.last_error = Some(err.clone());
                k.fail(now, &format!("transport error: {err}"));
                Verdict::RetryOtherKey
            }
            Outcome::Response {
                status,
                rl,
                body_snippet,
            } => {
                k.stats.last_status = Some(status);
                if let Some(rl) = &rl {
                    k.learn_limits(now, rl);
                }
                let detail = body_snippet
                    .filter(|s| !s.is_empty())
                    .map(|s| format!(": {s}"))
                    .unwrap_or_default();
                match status {
                    200..=299 => {
                        k.stats.ok += 1;
                        if k.stats.ok == 1 {
                            info!("key {}: first successful request (HTTP {status})", k.label);
                        }
                        k.last_ok = Some(now);
                        k.consecutive_failures = 0;
                        k.consecutive_429 = 0;
                        k.stats.last_error = None;
                        if k.disable_strikes > 0 {
                            info!("key {}: recovered (HTTP {status})", k.label);
                            k.disable_strikes = 0;
                            k.disabled_since = None;
                        }
                        // Proactive: the last allowed request of the month tells us so.
                        if rl.is_some_and(|r| r.month_exhausted()) {
                            k.exhaust(now, rl.and_then(|r| r.month_reset()));
                        } else if k.override_cap_exhausted() {
                            let reset_in = rl
                                .and_then(|r| r.month_reset())
                                .unwrap_or(OVERRIDE_CAP_FALLBACK);
                            k.exhaust(now, Some(reset_in));
                        }
                        Verdict::Ok
                    }
                    429 => {
                        k.stats.upstream_429 += 1;
                        k.consecutive_429 += 1;
                        k.stats.last_error = Some(format!("HTTP 429{detail}"));
                        match rl {
                            Some(r) if r.month_exhausted() => k.exhaust(now, r.month_reset()),
                            Some(r) => {
                                let wait = r.second_wait();
                                k.hold_until = Some(now + wait);
                                debug!(
                                    "key {}: upstream per-second limit hit, holding {}",
                                    k.label,
                                    fmt_dur(wait)
                                );
                            }
                            None => {
                                k.hold_until = Some(now + 2 * WINDOW);
                                if k.consecutive_429 >= UNEXPLAINED_429_THRESHOLD {
                                    let reason = format!(
                                        "{} consecutive 429s without rate-limit headers{detail}",
                                        k.consecutive_429
                                    );
                                    k.disable(
                                        now,
                                        UNEXPLAINED_429_BACKOFF,
                                        UNEXPLAINED_429_BACKOFF,
                                        reason,
                                    );
                                }
                            }
                        }
                        Verdict::RetryOtherKey
                    }
                    401 | 403 => {
                        k.stats.client_4xx += 1;
                        let reason = format!("HTTP {status}{detail}");
                        k.stats.last_error = Some(reason.clone());
                        k.disable(now, AUTH_BACKOFF_BASE, AUTH_BACKOFF_MAX, reason);
                        Verdict::RetryOtherKey
                    }
                    400..=499 => {
                        k.stats.client_4xx += 1;
                        k.stats.last_error = Some(format!("HTTP {status}{detail}"));
                        Verdict::ReturnToClient
                    }
                    500..=599 => {
                        k.stats.server_5xx += 1;
                        k.stats.last_error = Some(format!("HTTP {status}{detail}"));
                        k.fail(now, &format!("HTTP {status}{detail}"));
                        Verdict::RetryOtherKey
                    }
                    _ => Verdict::ReturnToClient,
                }
            }
        }
    }

    pub fn snapshot(&self) -> PoolSnapshot {
        let now = Instant::now();
        let window = self.window();
        let mut keys = self.lock();
        let mut out = PoolSnapshot {
            now: fmt_instant(now),
            keys_total: keys.len(),
            ..Default::default()
        };
        for k in keys.iter_mut() {
            k.refresh(now);
            let avail = k.availability(now, window);
            let (state, reason, until) = match &k.health {
                Health::Ok if k.hold_until.is_some_and(|h| h > now) => (
                    "cooling",
                    Some("upstream asked us to slow down".to_string()),
                    k.hold_until,
                ),
                Health::Ok if avail.is_err() => ("busy", None, avail.err()),
                Health::Ok => ("ok", None, None),
                Health::Disabled { until, reason } => {
                    ("disabled", Some(reason.clone()), Some(*until))
                }
                Health::Exhausted { until } => (
                    "exhausted",
                    Some("monthly quota used up".to_string()),
                    Some(*until),
                ),
            };
            if k.health == Health::Ok {
                out.keys_healthy += 1;
                out.rps_capacity += u64::from(k.sec_limit.max(1));
                out.slots_available_now += u64::from(k.free_slots());
            }
            if k.month_unlimited() {
                if k.health == Health::Ok {
                    out.month_unlimited_keys += 1;
                }
            } else {
                if let Some(m) = k.month_limit {
                    out.month_limit_total = Some(out.month_limit_total.unwrap_or(0) + m);
                }
                if let Some(m) = k.month_remaining {
                    out.month_remaining_total = Some(out.month_remaining_total.unwrap_or(0) + m);
                }
            }
            out.totals.requests += k.stats.requests;
            out.totals.ok += k.stats.ok;
            out.totals.upstream_429 += k.stats.upstream_429;
            out.totals.client_4xx += k.stats.client_4xx;
            out.totals.server_5xx += k.stats.server_5xx;
            out.totals.transport_errors += k.stats.transport_errors;

            out.keys.push(KeySnapshot {
                key: k.label.clone(),
                state,
                reason,
                until: until.map(fmt_instant),
                until_in: until.map(|u| fmt_dur(u.saturating_duration_since(now))),
                disabled_since: k.disabled_since.map(fmt_instant),
                per_second: PerSecond {
                    limit: k.sec_limit,
                    limits_learned: k.limits_learned,
                    in_window: k.sends.len() as u32,
                    next_slot_in_ms: avail
                        .err()
                        .map(|at| at.saturating_duration_since(now).as_millis() as u64)
                        .unwrap_or(0),
                },
                monthly: Monthly {
                    unlimited: k.month_unlimited(),
                    limit: k.month_limit.filter(|_| !k.month_unlimited()),
                    remaining: k.month_remaining.filter(|_| !k.month_unlimited()),
                    reset_at: k.month_reset_at.map(fmt_instant),
                    reset_in: k
                        .month_reset_at
                        .map(|r| fmt_dur(r.saturating_duration_since(now))),
                },
                last_used_ago: k
                    .last_used
                    .map(|t| fmt_dur(now.saturating_duration_since(t))),
                last_ok_ago: k.last_ok.map(|t| fmt_dur(now.saturating_duration_since(t))),
                stats: k.stats.clone(),
            });
        }
        out
    }
}

#[derive(Debug, Default, Serialize)]
pub struct PoolSnapshot {
    pub now: String,
    pub keys_total: usize,
    pub keys_healthy: usize,
    /// Sum of requests/second across healthy keys.
    pub rps_capacity: u64,
    /// Requests that could be sent right now without waiting.
    pub slots_available_now: u64,
    /// Sum over keys with a monthly cap (keys without a cap are excluded).
    pub month_limit_total: Option<u64>,
    pub month_remaining_total: Option<u64>,
    /// Healthy keys on a plan without a monthly cap.
    pub month_unlimited_keys: usize,
    pub totals: Stats,
    pub keys: Vec<KeySnapshot>,
}

#[derive(Debug, Serialize)]
pub struct KeySnapshot {
    pub key: String,
    pub state: &'static str,
    pub reason: Option<String>,
    pub until: Option<String>,
    pub until_in: Option<String>,
    pub disabled_since: Option<String>,
    pub per_second: PerSecond,
    pub monthly: Monthly,
    pub last_used_ago: Option<String>,
    pub last_ok_ago: Option<String>,
    pub stats: Stats,
}

#[derive(Debug, Serialize)]
pub struct PerSecond {
    pub limit: u32,
    pub limits_learned: bool,
    pub in_window: u32,
    pub next_slot_in_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct Monthly {
    /// Plan without a monthly cap (Brave reports limit 0); `limit`/`remaining` are then null.
    pub unlimited: bool,
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_at: Option<String>,
    pub reset_in: Option<String>,
}

fn fmt_quota(v: u64) -> String {
    if v == 0 {
        "unlimited".to_string()
    } else {
        v.to_string()
    }
}

/// Whole seconds, humanised ("2h 5m 3s").
pub fn fmt_dur(d: Duration) -> String {
    humantime::format_duration(Duration::from_secs(d.as_secs())).to_string()
}

/// Converts a monotonic instant to wall-clock RFC 3339 (seconds precision).
pub fn fmt_instant(i: Instant) -> String {
    let now_i = Instant::now();
    let now_s = SystemTime::now();
    let at = if i >= now_i {
        now_s.checked_add(i - now_i)
    } else {
        now_s.checked_sub(now_i - i)
    };
    at.map(|t| humantime::format_rfc3339_seconds(t).to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratelimit::Windows;

    fn pool(n: usize) -> Pool {
        let keys: Vec<String> = (0..n).map(|i| format!("BSA{i:04}key")).collect();
        Pool::new(
            &keys,
            PoolConfig {
                window_margin: Duration::from_millis(100),
                default_rps: 1,
                monthly_limits: Vec::new(),
            },
        )
    }

    fn rl(limit: (u64, u64), remaining: (u64, u64), reset: (u64, u64)) -> RateLimitInfo {
        RateLimitInfo {
            limit: Windows {
                second: Some(limit.0),
                month: Some(limit.1),
            },
            remaining: Windows {
                second: Some(remaining.0),
                month: Some(remaining.1),
            },
            reset: Windows {
                second: Some(reset.0),
                month: Some(reset.1),
            },
            ..Default::default()
        }
    }

    #[test]
    fn rotates_round_robin_and_respects_per_second_window() {
        let p = pool(3);
        let t0 = Instant::now();
        let a = p.try_acquire(t0, &[]).unwrap();
        let b = p.try_acquire(t0, &[]).unwrap();
        let c = p.try_acquire(t0, &[]).unwrap();
        assert_eq!([a.idx, b.idx, c.idx], [0, 1, 2]);

        // All three used within the window: nothing until the window (1s + 100ms margin) passes.
        match p.try_acquire(t0 + Duration::from_millis(500), &[]) {
            Err(Next::At(at)) => assert_eq!(at, t0 + Duration::from_millis(1100)),
            other => panic!("expected wait, got {other:?}"),
        }
        // After the window the LRU key comes first again.
        let d = p
            .try_acquire(t0 + Duration::from_millis(1100), &[])
            .unwrap();
        assert_eq!(d.idx, 0);
    }

    #[test]
    fn learns_higher_rps_from_headers() {
        let p = pool(1);
        let t0 = Instant::now();
        let l = p.try_acquire(t0, &[]).unwrap();
        p.record(
            l.idx,
            Outcome::Response {
                status: 200,
                rl: Some(rl((20, 0), (19, 0), (1, 100))),
                body_snippet: None,
            },
        );
        // 19 more sends allowed inside the same window now.
        for _ in 0..19 {
            p.try_acquire(t0 + Duration::from_millis(10), &[]).unwrap();
        }
        assert!(matches!(
            p.try_acquire(t0 + Duration::from_millis(20), &[]),
            Err(Next::At(_))
        ));
    }

    #[test]
    fn monthly_exhaustion_parks_key_until_reset() {
        let p = pool(2);
        let t0 = Instant::now();
        let l = p.try_acquire(t0, &[]).unwrap();
        assert_eq!(l.idx, 0);
        let v = p.record(
            l.idx,
            Outcome::Response {
                status: 429,
                rl: Some(rl((1, 2000), (1, 0), (1, 3600))),
                body_snippet: Some("quota"),
            },
        );
        assert_eq!(v, Verdict::RetryOtherKey);
        let snap = p.snapshot();
        assert_eq!(snap.keys[0].state, "exhausted");
        assert_eq!(snap.keys[0].monthly.remaining, Some(0));

        // Only key 1 serves from now on...
        let l2 = p.try_acquire(t0 + Duration::from_millis(10), &[0]).unwrap();
        assert_eq!(l2.idx, 1);
        // ...and even after its window frees up, key 0 stays parked.
        let l3 = p.try_acquire(t0 + Duration::from_secs(5), &[]).unwrap();
        assert_eq!(l3.idx, 1);
        // Until the reported reset passes.
        let l4 = p.try_acquire(t0 + Duration::from_secs(3601), &[]).unwrap();
        assert_eq!(l4.idx, 0);
    }

    #[test]
    fn auth_failure_disables_with_backoff_and_reports_unavailable() {
        let p = pool(1);
        let t0 = Instant::now();
        let l = p.try_acquire(t0, &[]).unwrap();
        assert_eq!(
            p.record(
                l.idx,
                Outcome::Response {
                    status: 401,
                    rl: None,
                    body_snippet: Some("bad key")
                }
            ),
            Verdict::RetryOtherKey
        );
        match p.try_acquire(t0 + Duration::from_secs(2), &[]) {
            Err(Next::Unavailable {
                earliest: Some(at),
                summary,
            }) => {
                assert!(at >= t0 + AUTH_BACKOFF_BASE - Duration::from_secs(1));
                assert!(summary.contains("HTTP 401"), "{summary}");
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
        // Probe after the backoff; failing again disables it once more.
        let l = p
            .try_acquire(t0 + AUTH_BACKOFF_BASE + Duration::from_secs(1), &[])
            .unwrap();
        p.record(
            l.idx,
            Outcome::Response {
                status: 401,
                rl: None,
                body_snippet: None,
            },
        );
        let snap = p.snapshot();
        assert_eq!(snap.keys[0].state, "disabled");
        assert_eq!(snap.keys_healthy, 0);
    }

    #[test]
    fn server_errors_need_three_strikes() {
        let p = pool(1);
        let t0 = Instant::now();
        for i in 0..3 {
            let l = p.try_acquire(t0 + Duration::from_secs(2 * i), &[]).unwrap();
            p.record(l.idx, Outcome::Transport("connection reset".into()));
        }
        assert_eq!(p.snapshot().keys[0].state, "disabled");
    }

    #[test]
    fn single_key_pool_may_reuse_excluded_key() {
        let p = pool(1);
        let t0 = Instant::now();
        let l = p.try_acquire(t0, &[]).unwrap();
        p.record(
            l.idx,
            Outcome::Response {
                status: 429,
                rl: Some(rl((1, 100), (0, 50), (1, 10))),
                body_snippet: None,
            },
        );
        // Excluded, but it is the only key: we get a wait time, not "unavailable".
        match p.try_acquire(t0 + Duration::from_millis(10), &[0]) {
            Err(Next::At(at)) => assert!(at >= t0 + Duration::from_secs(1)),
            other => panic!("expected At, got {other:?}"),
        }
    }

    #[test]
    fn plan_without_monthly_cap_is_never_exhausted_and_excluded_from_totals() {
        let p = pool(2);
        let t0 = Instant::now();
        let a = p.try_acquire(t0, &[]).unwrap();
        // Brave reports "0" for both the monthly limit and remaining on plans without a cap.
        p.record(
            a.idx,
            Outcome::Response {
                status: 200,
                rl: Some(rl((50, 0), (49, 0), (1, 100))),
                body_snippet: None,
            },
        );
        let b = p.try_acquire(t0, &[]).unwrap();
        assert_eq!(b.idx, 1);
        p.record(
            b.idx,
            Outcome::Response {
                status: 200,
                rl: Some(rl((1, 2000), (0, 1500), (1, 100))),
                body_snippet: None,
            },
        );
        let s = p.snapshot();
        assert_eq!(s.keys[0].state, "ok");
        assert!(s.keys[0].monthly.unlimited);
        assert_eq!(s.keys[0].monthly.remaining, None);
        assert_eq!(s.month_unlimited_keys, 1);
        assert_eq!(s.month_limit_total, Some(2000));
        assert_eq!(s.month_remaining_total, Some(1500));
        assert_eq!(s.rps_capacity, 51);
        // Still usable after many successes: no quota to run out of.
        for i in 1..=10 {
            let l = p.try_acquire(t0 + Duration::from_millis(i), &[1]).unwrap();
            assert_eq!(l.idx, 0);
            p.record(
                l.idx,
                Outcome::Response {
                    status: 200,
                    rl: Some(rl((50, 0), (40, 0), (1, 100))),
                    body_snippet: None,
                },
            );
        }
        assert_eq!(p.snapshot().keys[0].state, "ok");
    }
}
