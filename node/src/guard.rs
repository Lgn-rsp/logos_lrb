use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use ipnet::IpNet;
use parking_lot::Mutex;

/// Парсим список CIDR из строки "a,b,c"
pub fn parse_ip_allowlist(s: &str) -> Vec<IpNet> {
    s.split(',')
        .filter_map(|x| x.trim().parse::<IpNet>().ok())
        .collect()
}

/// IP-ACL для админ-ручек
pub async fn admin_ip_gate(
    req: Request<Body>,
    next: Next,
    allow: Arc<Vec<IpNet>>,
) -> Result<Response, StatusCode> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = match peer {
        Some(sa) => sa.ip(),
        None => return Err(StatusCode::FORBIDDEN),
    };
    if !allow.iter().any(|net| net.contains(&ip)) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}

/// Храним для IP свой защищённый мьютексом бакет
struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    qps: f64,
    burst: f64,
    map: DashMap<std::net::IpAddr, Arc<Mutex<Bucket>>>,
    bypass: Arc<Vec<IpNet>>,
}

impl RateLimiter {
    pub fn new(qps: u64, burst: u64, bypass: Arc<Vec<IpNet>>) -> Self {
        Self {
            qps: qps as f64,
            burst: burst as f64,
            map: DashMap::new(),
            bypass,
        }
    }

    fn is_bypass(&self, ip: &std::net::IpAddr) -> bool {
        self.bypass.iter().any(|n| n.contains(ip))
    }

    fn check_and_consume(&self, ip: std::net::IpAddr) -> bool {
        if self.is_bypass(&ip) {
            return true;
        }

        let now = Instant::now();
        let bucket_arc = self
            .map
            .entry(ip)
            .or_insert_with(|| {
                Arc::new(Mutex::new(Bucket {
                    tokens: self.burst,
                    last: now,
                }))
            })
            .clone();

        let mut b = bucket_arc.lock();
        let add = self.qps * b.last.elapsed().as_secs_f64();
        b.tokens = (b.tokens + add).min(self.burst);
        b.last = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Axum middleware: per-IP rate-limit (возвращает 429 при превышении)
pub async fn rate_limit_ip_gate(
    req: Request<Body>,
    next: Next,
    limiter: Arc<RateLimiter>,
) -> Result<Response, StatusCode> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = match peer {
        Some(sa) => sa.ip(),
        None => return Err(StatusCode::TOO_MANY_REQUESTS),
    };
    if !limiter.check_and_consume(ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(req).await)
}
