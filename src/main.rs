//! brave-rotator: a small, rate-limit-aware reverse proxy that spreads Brave Search API
//! traffic over several subscription keys.
//!
//! Point your client at this service instead of `https://api.search.brave.com`; the proxy
//! injects a key per request, paces requests so Brave's per-second limit is never exceeded,
//! parks keys whose monthly quota is spent until it resets, and disables keys that fail.

mod config;
mod pool;
mod proxy;
mod ratelimit;
mod upstream;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::routing::get;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::pool::{Pool, PoolConfig};
use crate::proxy::AppState;
use crate::upstream::Upstream;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(healthcheck());
    }

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(std::env::var_os("NO_COLOR").is_none())
        .init();

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("configuration error: {e}");
            std::process::exit(2);
        }
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.worker_threads)
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = rt.block_on(run(cfg)) {
        error!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "brave-rotator {} starting: {} key(s), upstream {}, listening on {}",
        env!("CARGO_PKG_VERSION"),
        cfg.keys.len(),
        cfg.upstream_base,
        cfg.listen
    );
    if cfg.duplicate_keys > 0 {
        warn!(
            "{} duplicate key(s) in BRAVE_API_KEYS were ignored",
            cfg.duplicate_keys
        );
    }
    if cfg.proxy_token.is_none() {
        warn!(
            "PROXY_TOKEN is not set: anyone who can reach {} can spend your quota",
            cfg.listen
        );
    }

    let pool = Pool::new(
        &cfg.keys,
        PoolConfig {
            window_margin: cfg.window_margin,
            default_rps: cfg.default_rps_per_key,
        },
    );
    let upstream = Upstream::new(
        cfg.upstream_base.clone(),
        cfg.upstream_timeout,
        cfg.max_body_bytes,
    );
    let state = Arc::new(AppState {
        pool,
        upstream,
        started: Instant::now(),
        cfg: cfg.clone(),
    });

    tokio::spawn(reporter(state.clone(), cfg.report_interval));

    let app = Router::new()
        .route("/proxy/status", get(proxy::status))
        .route("/proxy/health", get(proxy::health))
        .fallback(proxy::proxy)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    info!(
        "ready: point clients at http://{}/res/v1/web/search?q=... (every key assumed {} req/s until Brave reports the plan limits)",
        cfg.listen, cfg.default_rps_per_key
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    info!("bye");
    Ok(())
}

/// Periodically prints a one-line summary plus one line per key that is not fully usable.
async fn reporter(st: Arc<AppState>, every: Duration) {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await; // the first tick fires immediately; skip it
    loop {
        ticker.tick().await;
        let s = st.pool.snapshot();
        let t = &s.totals;
        let failed = t.upstream_429 + t.client_4xx + t.server_5xx + t.transport_errors;
        let monthly = match (
            s.month_remaining_total,
            s.month_limit_total,
            s.month_unlimited_keys,
        ) {
            (None, None, 0) => "unknown yet".to_string(),
            (None, None, n) => format!("no cap ({n} key(s))"),
            (rem, lim, n) => {
                let mut m = format!(
                    "{} of {}",
                    rem.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                    lim.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
                );
                if n > 0 {
                    m.push_str(&format!(" + {n} key(s) without cap"));
                }
                m
            }
        };
        info!(
            "status: {}/{} keys healthy, capacity {} req/s, monthly remaining {}, upstream attempts {} ok / {} failed ({} were 429s)",
            s.keys_healthy, s.keys_total, s.rps_capacity, monthly, t.ok, failed, t.upstream_429,
        );
        for k in s
            .keys
            .iter()
            .filter(|k| k.state == "disabled" || k.state == "exhausted")
        {
            warn!(
                "key {} is {}: {}; retrying at {} (in {})",
                k.key,
                k.state.to_uppercase(),
                k.reason.as_deref().unwrap_or("-"),
                k.until.as_deref().unwrap_or("?"),
                k.until_in.as_deref().unwrap_or("?"),
            );
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received, draining connections");
}

/// `brave-rotator healthcheck`: exit 0 when the local instance reports at least one healthy key.
/// Used as the container HEALTHCHECK since the image has no shell or curl.
fn healthcheck() -> i32 {
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(_) => return 2,
    };
    let host = if addr.ip().is_unspecified() {
        if addr.is_ipv4() {
            "127.0.0.1".to_string()
        } else {
            "::1".to_string()
        }
    } else {
        addr.ip().to_string()
    };
    let target = SocketAddr::new(
        host.parse().unwrap_or(std::net::Ipv4Addr::LOCALHOST.into()),
        addr.port(),
    );
    let Ok(mut s) = TcpStream::connect_timeout(&target, Duration::from_secs(2)) else {
        return 1;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"GET /proxy/health HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return 1;
    }
    let mut buf = Vec::with_capacity(512);
    let _ = s.read_to_end(&mut buf);
    let head = String::from_utf8_lossy(&buf);
    if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
        0
    } else {
        1
    }
}
