//! Parsing of Brave's rate-limit response headers.
//!
//! Per <https://api-dashboard.search.brave.com/documentation/guides/rate-limiting> every
//! response carries four headers, each a comma-separated pair where index 0 describes the
//! 1-second sliding burst window and index 1 the monthly quota window:
//!
//! ```text
//! X-RateLimit-Limit:     1, 15000            (0 for the month means unlimited)
//! X-RateLimit-Policy:    1;w=1, 15000;w=2592000
//! X-RateLimit-Remaining: 0, 14523
//! X-RateLimit-Reset:     1, 1234567          (seconds from now)
//! ```
//!
//! Only successful requests are counted against the quota; a 429 does not consume it.

use http::HeaderMap;
use std::time::Duration;

/// One value per limit window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Windows {
    pub second: Option<u64>,
    pub month: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimitInfo {
    pub limit: Windows,
    pub remaining: Windows,
    /// Seconds until each window resets.
    pub reset: Windows,
    /// Window sizes in seconds from `X-RateLimit-Policy`.
    pub window: Windows,
    /// `Retry-After` in seconds, if the upstream sent one.
    pub retry_after: Option<u64>,
}

impl RateLimitInfo {
    /// Returns `None` when the response carries no `X-RateLimit-*` header at all.
    pub fn from_headers(h: &HeaderMap) -> Option<Self> {
        let get = |name: &str| h.get(name).and_then(|v| v.to_str().ok());
        let limit = get("x-ratelimit-limit");
        let remaining = get("x-ratelimit-remaining");
        let reset = get("x-ratelimit-reset");
        let policy = get("x-ratelimit-policy");
        if limit.is_none() && remaining.is_none() && reset.is_none() && policy.is_none() {
            return None;
        }
        Some(Self {
            limit: limit.map(parse_windows).unwrap_or_default(),
            remaining: remaining.map(parse_windows).unwrap_or_default(),
            reset: reset.map(parse_windows).unwrap_or_default(),
            window: policy.map(parse_policy_windows).unwrap_or_default(),
            retry_after: get("retry-after").and_then(|v| v.trim().parse().ok()),
        })
    }

    /// True when the monthly quota is used up. A monthly limit of 0 means "unlimited".
    pub fn month_exhausted(&self) -> bool {
        if self.limit.month == Some(0) {
            return false;
        }
        self.remaining.month == Some(0)
    }

    /// How long to hold a key after a per-second 429 (at least one second).
    pub fn second_wait(&self) -> Duration {
        let secs = self
            .reset
            .second
            .unwrap_or(1)
            .max(self.retry_after.unwrap_or(0))
            .clamp(1, 60);
        Duration::from_secs(secs)
    }

    /// Time until the monthly quota resets, if reported.
    pub fn month_reset(&self) -> Option<Duration> {
        self.reset.month.map(Duration::from_secs)
    }
}

/// Parses `"1, 15000"` (tolerating `"1;w=1, 15000;w=2592000"` and single values).
fn parse_windows(v: &str) -> Windows {
    let mut parts = v.split(',').map(|p| {
        p.trim()
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .parse::<u64>()
            .ok()
    });
    Windows {
        second: parts.next().flatten(),
        month: parts.next().flatten(),
    }
}

/// Parses the `w=` window sizes out of `"1;w=1, 15000;w=2592000"`.
fn parse_policy_windows(v: &str) -> Windows {
    let mut parts = v.split(',').map(|p| {
        p.split(';')
            .map(str::trim)
            .find_map(|kv| kv.strip_prefix("w="))
            .and_then(|w| w.trim().parse::<u64>().ok())
    });
    Windows {
        second: parts.next().flatten(),
        month: parts.next().flatten(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn parses_documented_example() {
        let h = headers(&[
            ("X-RateLimit-Limit", "1, 15000"),
            ("X-RateLimit-Policy", "1;w=1, 15000;w=2592000"),
            ("X-RateLimit-Remaining", "0, 14523"),
            ("X-RateLimit-Reset", "1, 1234567"),
        ]);
        let rl = RateLimitInfo::from_headers(&h).expect("headers present");
        assert_eq!(
            rl.limit,
            Windows {
                second: Some(1),
                month: Some(15000)
            }
        );
        assert_eq!(
            rl.remaining,
            Windows {
                second: Some(0),
                month: Some(14523)
            }
        );
        assert_eq!(
            rl.reset,
            Windows {
                second: Some(1),
                month: Some(1234567)
            }
        );
        assert_eq!(
            rl.window,
            Windows {
                second: Some(1),
                month: Some(2592000)
            }
        );
        assert!(!rl.month_exhausted());
        assert_eq!(rl.second_wait(), Duration::from_secs(1));
        assert_eq!(rl.month_reset(), Some(Duration::from_secs(1234567)));
    }

    #[test]
    fn detects_monthly_exhaustion_and_unlimited_plans() {
        let h = headers(&[
            ("X-RateLimit-Limit", "1, 2000"),
            ("X-RateLimit-Remaining", "1, 0"),
        ]);
        assert!(RateLimitInfo::from_headers(&h).unwrap().month_exhausted());

        let h = headers(&[
            ("X-RateLimit-Limit", "50, 0"),
            ("X-RateLimit-Remaining", "49, 0"),
        ]);
        assert!(
            !RateLimitInfo::from_headers(&h).unwrap().month_exhausted(),
            "0 limit = unlimited"
        );
    }

    #[test]
    fn honours_retry_after_and_odd_formatting() {
        let h = headers(&[
            ("X-RateLimit-Remaining", " 0 ,  10 "),
            ("X-RateLimit-Reset", "2,100"),
            ("Retry-After", "5"),
        ]);
        let rl = RateLimitInfo::from_headers(&h).unwrap();
        assert_eq!(
            rl.remaining,
            Windows {
                second: Some(0),
                month: Some(10)
            }
        );
        assert_eq!(rl.second_wait(), Duration::from_secs(5));
        assert_eq!(rl.limit, Windows::default());
    }

    #[test]
    fn absent_headers_yield_none() {
        assert!(RateLimitInfo::from_headers(&HeaderMap::new()).is_none());
        let h = headers(&[("Content-Type", "application/json")]);
        assert!(RateLimitInfo::from_headers(&h).is_none());
    }
}
