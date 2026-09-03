//! Runtime configuration, read once from environment variables.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// Brave Search API subscription tokens to rotate between (deduplicated, in the order given).
    pub keys: Vec<String>,
    /// Number of duplicate keys dropped while parsing `BRAVE_API_KEYS` (reported at startup).
    pub duplicate_keys: usize,
    /// Address the proxy listens on.
    pub listen: SocketAddr,
    /// Upstream base URL, without trailing slash.
    pub upstream_base: String,
    /// Total time budget for one upstream request/response.
    pub upstream_timeout: Duration,
    /// How long a client request may wait for a free rate-limit slot before it is rejected with 429.
    pub max_queue_wait: Duration,
    /// How often the health/quota summary is printed to the console.
    pub report_interval: Duration,
    /// Safety margin added to Brave's 1-second sliding window (network jitter).
    pub window_margin: Duration,
    /// Per-key requests/second assumed until Brave tells us the real plan limit.
    pub default_rps_per_key: u32,
    /// Largest request or response body we buffer.
    pub max_body_bytes: usize,
    /// Optional shared secret clients must present (X-Proxy-Token or X-Subscription-Token).
    pub proxy_token: Option<String>,
    /// Tokio worker threads.
    pub worker_threads: usize,
    /// Log every proxied request (method, path, search query, key, status, timing) at INFO.
    pub access_log: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let raw = first_env(&["BRAVE_API_KEYS", "BRAVE_KEYS"]).unwrap_or_default();
        let mut keys: Vec<String> = Vec::new();
        let mut duplicate_keys = 0;
        for k in raw.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let k = k.trim();
            if k.is_empty() {
                continue;
            }
            if keys.iter().any(|e| e == k) {
                duplicate_keys += 1;
                continue;
            }
            keys.push(k.to_string());
        }
        if keys.is_empty() {
            return Err(
                "BRAVE_API_KEYS is empty. Provide one or more comma-separated Brave Search API keys."
                    .to_string(),
            );
        }

        let listen: SocketAddr = parse_env("LISTEN_ADDR", "0.0.0.0:8080")?;

        let upstream_base = env_or("BRAVE_BASE_URL", "https://api.search.brave.com")
            .trim_end_matches('/')
            .to_string();
        let uri: http::Uri = upstream_base
            .parse()
            .map_err(|e| format!("BRAVE_BASE_URL is not a valid URL: {e}"))?;
        if uri.scheme().is_none() || uri.authority().is_none() {
            return Err(
                "BRAVE_BASE_URL must include scheme and host, e.g. https://api.search.brave.com"
                    .into(),
            );
        }

        let proxy_token = std::env::var("PROXY_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(Config {
            keys,
            duplicate_keys,
            listen,
            upstream_base,
            upstream_timeout: Duration::from_millis(parse_env("UPSTREAM_TIMEOUT_MS", "15000")?),
            max_queue_wait: Duration::from_millis(parse_env("MAX_QUEUE_WAIT_MS", "5000")?),
            report_interval: Duration::from_secs(
                parse_env::<u64>("REPORT_INTERVAL_SECS", "60")?.max(1),
            ),
            window_margin: Duration::from_millis(parse_env("WINDOW_MARGIN_MS", "100")?),
            default_rps_per_key: parse_env::<u32>("DEFAULT_RPS_PER_KEY", "1")?.max(1),
            max_body_bytes: parse_env("MAX_BODY_BYTES", "4194304")?,
            proxy_token,
            worker_threads: parse_env::<usize>("WORKER_THREADS", "2")?.max(1),
            access_log: parse_bool("ACCESS_LOG", true)?,
        })
    }
}

fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|n| std::env::var(n).ok().filter(|v| !v.trim().is_empty()))
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn parse_env<T: FromStr>(name: &str, default: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    let raw = env_or(name, default);
    raw.trim()
        .parse::<T>()
        .map_err(|e| format!("{name}={raw:?} is invalid: {e}"))
}

fn parse_bool(name: &str, default: bool) -> Result<bool, String> {
    let raw = env_or(name, if default { "true" } else { "false" });
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{name}={raw:?} is invalid: expected true or false")),
    }
}
