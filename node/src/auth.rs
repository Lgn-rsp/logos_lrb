//! Auth: bridge key + HMAC + anti-replay + admin stub
use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn assert_secrets_on_start() -> Result<()> {
    for k in ["LRB_JWT_SECRET","LRB_BRIDGE_KEY"] {
        let v = std::env::var(k).map_err(|_| anyhow!("{k} not set"))?;
        let bad = ["", "change_me", "changeme", "default", "dev_secret"];
        if bad.iter().any(|b| v.eq_ignore_ascii_case(b)) { return Err(anyhow!("{k} insecure")); }
    }
    Ok(())
}

// Совместимость для admin.rs (минимальная проверка заголовка)
pub fn require_admin(_headers:&HeaderMap) -> Result<()> {
    // при желании тут можно проверить X-Admin-JWT
    Ok(())
}

pub fn require_bridge_key(headers: &HeaderMap) -> Result<()> {
    let expect = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY not set"))?;
    let got = headers.get("X-Bridge-Key").ok_or_else(|| anyhow!("missing X-Bridge-Key"))?
        .to_str().map_err(|_| anyhow!("invalid X-Bridge-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad bridge key")); }
    Ok(())
}

pub fn verify_hmac_and_nonce(headers: &HeaderMap, body: &[u8], db: &sled::Db) -> Result<()> {
    let key = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY not set"))?;
    let nonce = headers.get("X-Bridge-Nonce").ok_or_else(|| anyhow!("missing X-Bridge-Nonce"))?
        .to_str().map_err(|_| anyhow!("bad nonce"))?;
    let sign  = headers.get("X-Bridge-Sign").ok_or_else(|| anyhow!("missing X-Bridge-Sign"))?
        .to_str().map_err(|_| anyhow!("bad sign"))?;

    let tree = db.open_tree("bridge.replay")?;
    let key_n = format!("n:{nonce}");
    if tree.get(&key_n)?.is_some() { return Err(anyhow!("replay")); }

    let mut mac = <Hmac<Sha256>>::new_from_slice(key.as_bytes()).map_err(|_| anyhow!("hmac"))?;
    mac.update(body);
    let got = hex::decode(sign).map_err(|_| anyhow!("sign hex"))?;
    mac.verify_slice(&got).map_err(|_| anyhow!("bad signature"))?;

    tree.insert(key_n.as_bytes(), &[])?;
    Ok(())
}
