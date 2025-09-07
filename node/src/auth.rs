//! Auth-модуль: защита bridge/admin, поддержка X-Admin-JWT (HS256).
//! Переменные окружения:
//!  - LRB_BRIDGE_KEY           (обязательно для /bridge/*)
//!  - LRB_ADMIN_KEY            (legacy, можно оставить для совместимости)
//!  - LRB_ADMIN_JWT_SECRET     (обязательно для JWT: HS256)
//!
//! JWT требования:
//!  - header.alg = HS256
//!  - payload: { "sub":"admin", "iat":<sec>, "exp":<sec> }
//!  - подпись по LRB_ADMIN_JWT_SECRET

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

fn forbid_default(val: &str) -> Result<()> {
    if val.is_empty() || val.contains("CHANGE") || val.contains("DEFAULT") {
        Err(anyhow!("insecure default key"))
    } else {
        Ok(())
    }
}

/* -------- Bridge (ключ обязателен) -------- */
pub fn require_bridge(headers: &HeaderMap) -> Result<()> {
    let expect = std::env::var("LRB_BRIDGE_KEY")
        .map_err(|_| anyhow!("LRB_BRIDGE_KEY is not set"))?;
    forbid_default(&expect)?;
    let got = headers
        .get("X-Bridge-Key").ok_or_else(|| anyhow!("missing X-Bridge-Key"))?
        .to_str().map_err(|_| anyhow!("invalid X-Bridge-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad bridge key")); }
    Ok(())
}

/* -------- Admin (JWT с бэкапом X-Admin-Key) -------- */
#[derive(Debug, Deserialize)]
struct AdminClaims {
    sub: String,
    iat: Option<u64>,
    exp: Option<u64>,
}

pub fn require_admin(headers: &HeaderMap) -> Result<()> {
    // 1) Пробуем JWT
    if let Ok(token) = headers.get("X-Admin-JWT").and_then(|h| h.to_str().ok()).ok_or(()) {
        let secret = std::env::var("LRB_ADMIN_JWT_SECRET")
            .map_err(|_| anyhow!("LRB_ADMIN_JWT_SECRET is not set"))?;
        forbid_default(&secret)?;
        let mut val = Validation::new(Algorithm::HS256);
        val.sub = Some("admin".to_string());
        let data = decode::<AdminClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &val
        ).map_err(|e| anyhow!("admin jwt invalid: {e}"))?;
        if data.claims.sub != "admin" { return Err(anyhow!("forbidden")); }
        return Ok(());
    }

    // 2) Legacy: X-Admin-Key, если JWT не дан
    let expect = std::env::var("LRB_ADMIN_KEY")
        .map_err(|_| anyhow!("LRB_ADMIN_JWT_SECRET or LRB_ADMIN_KEY required"))?;
    forbid_default(&expect)?;
    let got = headers
        .get("X-Admin-Key").ok_or_else(|| anyhow!("missing X-Admin-Key"))?
        .to_str().map_err(|_| anyhow!("invalid X-Admin-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad admin key")); }
    Ok(())
}

/* -------- Строгая проверка секретов при старте -------- */
pub fn assert_secrets_on_start() -> Result<()> {
    // не падаем, если bridge отключён — падаем только при пустых значениях
    if let Ok(v) = std::env::var("LRB_BRIDGE_KEY") { forbid_default(&v)?; }
    // один из вариантов админ-доступа должен быть установлен осмысленно
    if let Ok(v) = std::env::var("LRB_ADMIN_JWT_SECRET") { forbid_default(&v)?; }
    else if let Ok(v) = std::env::var("LRB_ADMIN_KEY") { forbid_default(&v)?; }
    else { return Err(anyhow!("admin secret not set (LRB_ADMIN_JWT_SECRET or LRB_ADMIN_KEY)")); }
    Ok(())
}
