//! Rate-limit + ACL middleware для LOGOS Node (Axum 0.7).
//! ENV:
//!   LRB_QPS, LRB_BURST
//!   LRB_RATE_BYPASS_CIDRS="127.0.0.1/32,::1/128"
//!   LRB_ADMIN_ALLOW_CIDRS="127.0.0.1/32,::1/128"

use axum::{body::Body, http::{Request, StatusCode}, middleware::Next, response::IntoResponse};
use dashmap::DashMap;
use ipnet::IpNet;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{net::{IpAddr, Ipv4Addr}, str::FromStr, time::Instant};

static BUCKETS: Lazy<DashMap<IpAddr, Mutex<TokenBucket>>> = Lazy::new(DashMap::new);
static BYPASS:  Lazy<Vec<IpNet>> = Lazy::new(|| parse_cidrs(env_get("LRB_RATE_BYPASS_CIDRS").unwrap_or_else(|| "127.0.0.1/32,::1/128".into())));
static ADMIN:   Lazy<Vec<IpNet>> = Lazy::new(|| parse_cidrs(env_get("LRB_ADMIN_ALLOW_CIDRS").unwrap_or_else(|| "127.0.0.1/32,::1/128".into())));

#[derive(Debug)]
struct TokenBucket { capacity: u64, tokens: f64, qps: f64, last: Instant }
impl TokenBucket {
    fn new(qps: u64, burst: u64) -> Self {
        Self { capacity: burst, tokens: burst as f64, qps: qps as f64, last: Instant::now() }
    }
    fn try_take(&mut self) -> bool {
        let dt = self.last.elapsed(); self.last = Instant::now();
        self.tokens = (self.tokens + self.qps * dt.as_secs_f64()).min(self.capacity as f64);
        if self.tokens >= 1.0 { self.tokens -= 1.0; true } else { false }
    }
}

pub async fn rate_limit_mw(req: Request<Body>, next: Next) -> axum::response::Response {
    let ip = client_ip(&req).unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let path = req.uri().path();

    // 1) Жёсткая ACL для /admin/*
    if path.starts_with("/admin/") {
        if !ip_in(&ip, &*ADMIN) {
            return (StatusCode::FORBIDDEN, "admin denied").into_response();
        }
        // ВАЖНО: /admin/* не лимитируем (чтобы не получать 429)
        return next.run(req).await;
    }

    // 2) Bypass для доверенных сетей
    if !ip_in(&ip, &*BYPASS) {
        let (qps, burst) = load_limits();
        let entry = BUCKETS.entry(ip).or_insert_with(|| Mutex::new(TokenBucket::new(qps, burst)));
        let mut bucket = entry.lock();
        if !bucket.try_take() {
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, "").into_response();
            resp.headers_mut().insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from_static("0.1"));
            return resp;
        }
    }

    next.run(req).await
}

fn env_get(k: &str) -> Option<String> { std::env::var(k).ok() }
fn load_limits() -> (u64, u64) {
    let qps = env_get("LRB_QPS").and_then(|s| s.parse().ok()).unwrap_or(30);
    let burst = env_get("LRB_BURST").and_then(|s| s.parse().ok()).unwrap_or(60);
    (qps, burst)
}
fn parse_cidrs(csv: String) -> Vec<IpNet> {
    csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).filter_map(|s| IpNet::from_str(s).ok()).collect()
}
fn ip_in(ip: &IpAddr, nets: &[IpNet]) -> bool { nets.iter().any(|n| n.contains(ip)) }
fn client_ip(req: &Request<Body>) -> Option<IpAddr> {
    if let Some(xff) = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next().map(|s| s.trim()) { if let Ok(ip) = first.parse() { return Some(ip); } }
    }
    if let Some(xri) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = xri.parse() { return Some(ip); }
    }
    None
}
