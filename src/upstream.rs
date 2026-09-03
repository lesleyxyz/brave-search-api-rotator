//! Minimal HTTPS client towards the Brave API (hyper + rustls, bundled webpki roots).

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

pub struct Upstream {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    base: String,
    timeout: Duration,
    max_body: usize,
}

pub struct UpstreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug)]
pub enum UpstreamError {
    Timeout(Duration),
    Request(String),
    Body(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Timeout(d) => write!(f, "upstream timed out after {}ms", d.as_millis()),
            UpstreamError::Request(e) => write!(f, "upstream request failed: {e}"),
            UpstreamError::Body(e) => write!(f, "upstream body error: {e}"),
        }
    }
}

impl Upstream {
    pub fn new(base: String, timeout: Duration, max_body: usize) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_connect_timeout(Some(timeout.min(Duration::from_secs(10))));
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(8)
            .build(https);
        Self {
            client,
            base,
            timeout,
            max_body,
        }
    }

    /// Forwards one request using `key` as the subscription token. Never retries.
    pub async fn send(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Bytes,
        key: &str,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let uri = format!("{}{}", self.base, path_and_query);
        let mut req = Request::builder()
            .method(method.clone())
            .uri(&uri)
            .body(Full::new(body))
            .map_err(|e| UpstreamError::Request(format!("invalid request for {uri}: {e}")))?;

        let h = req.headers_mut();
        for (name, value) in headers {
            h.append(name.clone(), value.clone());
        }
        let token = HeaderValue::from_str(key)
            .map_err(|_| UpstreamError::Request("key contains invalid header characters".into()))?;
        h.insert("x-subscription-token", token);
        if !h.contains_key(header::ACCEPT) {
            h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        }
        if !h.contains_key(header::USER_AGENT) {
            h.insert(
                header::USER_AGENT,
                HeaderValue::from_static(concat!("brave-rotator/", env!("CARGO_PKG_VERSION"))),
            );
        }

        let fut = async {
            let resp = self
                .client
                .request(req)
                .await
                .map_err(|e| UpstreamError::Request(e.to_string()))?;
            let (parts, body) = resp.into_parts();
            let body = Limited::new(body, self.max_body)
                .collect()
                .await
                .map_err(|e| UpstreamError::Body(e.to_string()))?
                .to_bytes();
            Ok(UpstreamResponse {
                status: parts.status,
                headers: parts.headers,
                body,
            })
        };
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(UpstreamError::Timeout(self.timeout)),
        }
    }
}
