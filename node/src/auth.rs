// node/src/auth.rs
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct Claims {
    exp: i64,
    sub: Option<String>,
    iat: Option<i64>,
}

// ------------ time ------------
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ------------ helpers ------------
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string())
}

fn header_or_bearer(headers: &HeaderMap, primary_header: &str) -> Option<String> {
    if let Some(v) = header_value(headers, primary_header) {
        if !v.is_empty() { return Some(v); }
    }
    if let Some(v) = header_value(headers, "authorization") {
        if let Some(rest) = v.strip_prefix("Bearer ") {
            let t = rest.trim();
            if !t.is_empty() { return Some(t.to_string()); }
        }
    }
    None
}

/// Простейший IP-ACL: LRB_ADMIN_IP_ALLOW="1.2.3.4,10.0.0.0/8"
fn ip_acl_allows(ip: Option<IpAddr>, env_key: &str) -> bool {
    let allow = std::env::var(env_key).unwrap_or_default();
    if allow.trim().is_empty() { return true; }
    let rules: Vec<&str> = allow.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if rules.is_empty() { return true; }
    if let Some(client) = ip {
        for r in rules {
            if let Ok(one) = r.parse::<IpAddr>() {
                if one == client { return true; }
            } else if let Some((net, bits)) = r.split_once('/') {
                if let (Ok(nip), Ok(b)) = (net.parse::<IpAddr>(), bits.parse::<u8>()) {
                    if let (IpAddr::V4(a), IpAddr::V4(n)) = (client, nip) {
                        let mask: u32 = if b == 0 { 0 } else { (!0u32) << (32 - b as u32) };
                        if (u32::from(a) & mask) == (u32::from(n) & mask) { return true; }
                    }
                }
            }
        }
        false
    } else { false }
}

// ------------ публичные проверки ------------

/// Админ-доступ:
/// 1) если задан нормальный LRB_ADMIN_KEY — принимаем X-Admin-Key (приоритетно)
/// 2) если задан LRB_ADMIN_JWT_SECRET — принимаем JWT (X-Admin-Key или Authorization: Bearer)
/// 3) IP-ACL: LRB_ADMIN_IP_ALLOW (пусто = разрешить всем)
pub fn require_admin(headers: &HeaderMap, remote_ip: Option<IpAddr>) -> Result<(), StatusCode> {
    if !ip_acl_allows(remote_ip, "LRB_ADMIN_IP_ALLOW") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // статический ключ (удобно для таймеров/автоматизаций)
    if let Ok(k) = std::env::var("LRB_ADMIN_KEY") {
        let k = k.trim();
        if !k.is_empty() && k != "CHANGE_ADMIN_KEY" {
            if let Some(presented) = header_or_bearer(headers, "X-Admin-Key") {
                if presented == k { return Ok(()); }
            }
        }
    }

    // JWT HS256
    if let Ok(secret) = std::env::var("LRB_ADMIN_JWT_SECRET") {
        let secret = secret.trim();
        if !secret.is_empty() {
            if let Some(tok) = header_or_bearer(headers, "X-Admin-Key") {
                if let Ok(data) = decode::<Claims>(
                    &tok,
                    &DecodingKey::from_secret(secret.as_bytes()),
                    &Validation::new(Algorithm::HS256),
                ) {
                    if data.claims.exp > now_ts() { return Ok(()); }
                }
            }
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Доступ к мосту: LRB_BRIDGE_KEY в X-Bridge-Key или Authorization: Bearer <key>
pub fn require_bridge(headers: &HeaderMap) -> Result<(), StatusCode> {
    let k = std::env::var("LRB_BRIDGE_KEY").unwrap_or_default();
    let k = k.trim();
    if k.is_empty() || k == "CHANGE_ME" { return Err(StatusCode::UNAUTHORIZED); }

    if let Some(presented) = header_or_bearer(headers, "X-Bridge-Key") {
        if presented == k { return Ok(()); }
    }
    if let Some(bearer) = header_or_bearer(headers, "Authorization") {
        if bearer == k { return Ok(()); }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// ------------ JWT minting (для /admin/token) ------------
#[derive(Serialize)]
struct ClaimsOut { sub: String, exp: i64, iat: i64 }

/// Выпуск JWT (HS256) c TTL (сек): возвращает строку токена.
pub fn mint_jwt(secret: &str, sub: &str, ttl_secs: i64) -> Result<String, StatusCode> {
    if ttl_secs <= 0 { return Err(StatusCode::BAD_REQUEST); }
    let now = now_ts();
    let claims = ClaimsOut { sub: sub.to_string(), iat: now, exp: now + ttl_secs };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
