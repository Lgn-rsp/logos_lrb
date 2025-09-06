//! Guard & Rate-Limit (prod) для Axum 0.7:
//! - Admin IP ACL (CIDR allowlist) через from_fn_with_state.
//! - Per-IP rate-limit (token bucket) с bypass по путям и по CIDR.
//! - PATH_BYPASS: /healthz, /livez, /readyz, /metrics, /openapi.json.

use axum::response::IntoResponse;  // ← ДОБАВИТЬ ЭТУ СТРОКУ
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use ipnet::IpNet;
use parking_lot::Mutex;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::time::Instant;

/// Пути, которые никогда не ограничиваются лимитером.
const PATH_BYPASS: &[&str] = &[
    "/healthz",
    "/livez",
    "/readyz",
    "/metrics",
    "/openapi.json",
];

/// ===== Admin IP ACL (используем from_fn_with_state) =====
pub async fn admin_ip_gate(
    State(allow): State<Arc<Vec<IpNet>>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(ip) = client_ip(&req) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if ip_in_allowlist(ip, &allow) {
        next.run(req).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

/// ===== Rate Limiter (token bucket per IP) =====
pub struct RateLimiter {
    qps: f64,
    burst: f64,
    /// подсети, которым разрешён обход лимитера
    pub bypass: Arc<Vec<IpNet>>,
    buckets: DashMap<IpAddr, Mutex<TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(qps: u64, burst: u64, bypass: Arc<Vec<IpNet>>) -> Self {
        let qps = qps as f64;
        let burst = if burst > 0 { burst as f64 } else { qps.max(1.0) * 2.0 };
        Self {
            qps,
            burst,
            bypass,
            buckets: DashMap::new(),
        }
    }

    /// true если IP клиента входит в bypass CIDR
    fn is_bypass(&self, req: &Request<Body>) -> bool {
        if let Some(ip) = client_ip(req) {
            return ip_in_allowlist(ip, &self.bypass);
        }
        false
    }

    /// Проверка и списание токена. false → 429.
    fn check(&self, req: &Request<Body>) -> bool {
        if self.qps <= 0.0 {
            return true;
        }
        let Some(ip) = client_ip(req) else { return false; };

        let entry = self
            .buckets
            .entry(ip)
            .or_insert_with(|| Mutex::new(TokenBucket { tokens: self.burst, last: Instant::now() }));
        let mut tb = entry.lock();

        // refill
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(tb.last).as_secs_f64();
        if elapsed > 0.0 {
            tb.tokens = (tb.tokens + self.qps * elapsed).min(self.burst);
            tb.last = now;
        }

        if tb.tokens >= 1.0 {
            tb.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Axum 0.7 middleware: rate-limit с bypass по путям и CIDR (from_fn_with_state).
pub async fn rate_limit_ip_gate(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // 1) Allowlist путей
    let path = req.uri().path();
    if PATH_BYPASS.iter().any(|p| *p == path) {
        return next.run(req).await;
    }

    // 2) CIDR bypass (напр., 127.0.0.1/32,::1/128)
    if limiter.is_bypass(&req) {
        return next.run(req).await;
    }

    // 3) Rate-limit
    if limiter.check(&req) {
        next.run(req).await
    } else {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    }
}

/// ===== Утилиты IP/ACL =====

/// Разбор CSV-списка подсетей в Vec<IpNet>.
/// Пример: "127.0.0.1/32,::1/128,10.0.0.0/8"
pub fn parse_ip_allowlist(csv: &str) -> Vec<IpNet> {
    csv.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| IpNet::from_str(s).ok())
        .collect()
}

/// Проверка, входит ли ip в allowlist.
pub fn ip_in_allowlist(ip: IpAddr, allow: &[IpNet]) -> bool {
    allow.iter().any(|net| net.contains(&ip))
}

/// IP клиента из X-Forwarded-For или ConnectInfo<SocketAddr>.
fn client_ip(req: &Request<Body>) -> Option<IpAddr> {
    // a) X-Forwarded-For: берём первый адрес
    if let Some(h) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = h.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    // b) ConnectInfo<SocketAddr> (Axum 0.7)
    if let Some(ci) = req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>() {
        return Some(ci.0.ip());
    }
    None
}
