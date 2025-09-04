use axum::{extract::Extension, Json};
use axum::http::{StatusCode, HeaderMap};
use serde::{Serialize, Deserialize};
use std::{fs, path::PathBuf};
use crate::{state::AppState, auth};

#[derive(Serialize)]
pub struct NodeInfo {
    pub rid: String,
    pub vk_b58: String,
    pub slot_ms: Option<u64>,
    pub max_block_txs: Option<usize>,
    pub mempool_cap: Option<usize>,
    pub env: serde_json::Value,
}

pub async fn node_info(Extension(st): Extension<AppState>) -> Json<NodeInfo> {
    let vk_b58 = bs58::encode(st.self_vk.to_bytes()).into_string();
    let rid = vk_b58.clone();
    let slot_ms = std::env::var("LRB_SLOT_MS").ok().and_then(|s| s.parse::<u64>().ok());
    let max_block_txs = std::env::var("LRB_MAX_BLOCK_TX").ok().and_then(|s| s.parse::<usize>().ok());
    let mempool_cap = std::env::var("LRB_MEMPOOL_CAP").ok().and_then(|s| s.parse::<usize>().ok());
    let keys = [
        "LRB_SLOT_MS","LRB_MAX_BLOCK_TX","LRB_MEMPOOL_CAP","LRB_MAX_AMOUNT",
        "LRB_DEV","LRB_PEERS","LRB_VALIDATORS","LRB_QUORUM_N",
        "LRB_BRIDGE_MAX_PER_TX","LRB_DATA_PATH","LRB_NODE_KEY_PATH",
    ];
    let mut envmap = serde_json::Map::new();
    for k in keys.iter() { if let Ok(val) = std::env::var(k) { envmap.insert((*k).to_string(), serde_json::Value::String(val)); } }
    Json(NodeInfo { rid, vk_b58, slot_ms, max_block_txs, mempool_cap, env: serde_json::Value::Object(envmap) })
}

/* ===== JWT mint для админки ===== */
#[derive(Serialize)] pub struct TokenResp { pub ok:bool, pub token:String, pub ttl_sec:usize }
pub async fn admin_token(Extension(st): Extension<AppState>, headers: HeaderMap, axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String,String>>)
-> Result<Json<TokenResp>, StatusCode> {
    // Требуем предъявить действительный ADMIN KEY (или Bearer KEY) для выдачи токена
    // IP ACL внутри require_admin
    let ip = None; // опционально можно протащить remote_ip из Tower layers
    auth::require_admin(&headers, ip)?;

    let ttl = q.get("ttl").and_then(|s| s.parse::<usize>().ok()).unwrap_or(600);
    let secret = std::env::var("LRB_ADMIN_JWT_SECRET").map_err(|_| StatusCode::UNAUTHORIZED)?;
    if secret.trim().is_empty() { return Err(StatusCode::UNAUTHORIZED); }
    let tok = auth::mint_jwt(&secret, "admin", ttl as i64)?;
    Ok(Json(TokenResp { ok:true, token: tok, ttl_sec: ttl }))
}

/* ===== Snapshot / Restore ===== */
#[derive(Serialize, Deserialize)]
pub struct Snapshot { pub head:u64, pub finalized:u64, pub lgn_balances:Vec<(String,u64)>, pub rlgn_balances:Vec<(String,u64)> }

pub async fn snapshot(Extension(st): Extension<AppState>, headers: HeaderMap)
-> Result<Json<Snapshot>, StatusCode> {
    if !st.rl_admin.try_take(1) { return Err(StatusCode::TOO_MANY_REQUESTS); }
    let ip = None;
    auth::require_admin(&headers, ip)?;

    let (h, _) = st.engine.ledger().head().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let fin = st.engine.ledger().get_finalized().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let lg = st.engine.ledger().export_balances().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rg = st.engine.ledger().export_rbalances().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(Snapshot { head:h, finalized:fin, lgn_balances:lg, rlgn_balances:rg }))
}

pub async fn snapshot_file(Extension(st): Extension<AppState>, headers: HeaderMap, axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String,String>>)
-> Result<Json<serde_json::value::Value>, StatusCode> {
    if !st.rl_admin.try_take(1) { return Err(StatusCode::TOO_MANY_REQUESTS); }
    let ip = None;
    auth::require_admin(&headers, ip)?;

    let name = params.get("name").cloned().unwrap_or_else(|| format!("snap-{}.json", crate::state::now_ms()));
    let safe = name.chars().all(|c| c.is_ascii_alphanumeric() || c=='-' || c=='_' || c=='.');
    if !safe { return Err(StatusCode::BAD_REQUEST); }

    let (h, _) = st.engine.ledger().head().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let fin = st.engine.ledger().get_finalized().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let lg = st.engine.ledger().export_balances().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rg = st.engine.ledger().export_rbalances().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let snap = Snapshot { head:h, finalized:fin, lgn_balances:lg, rlgn_balances:rg };
    let data = serde_json::to_vec_pretty(&snap).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut path = PathBuf::from("/var/lib/logos/snapshots"); path.push(name);
    fs::write(&path, data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok": true, "file": path.to_string_lossy()})))
}

#[derive(Deserialize)] pub struct RestoreReq { pub file: String }
pub async fn restore(Extension(st): Extension<AppState>, headers: HeaderMap, Json(req): Json<RestoreReq>)
-> Result<Json<serde_json::value::Value>, StatusCode> {
    if !st.rl_admin.try_take(1) { return Err(StatusCode::TOO_MANY_REQUESTS); }
    let ip = None;
    auth::require_admin(&headers, ip)?;

    let safe = req.file.chars().all(|c| c.is_ascii_alphanumeric() || c=='-' || c=='_' || c=='.' || c=='/' );
    if !safe || !req.file.starts_with("/var/lib/logos/snapshots/") { return Err(StatusCode::BAD_REQUEST); }
    let data = fs::read(&req.file).map_err(|_| StatusCode::NOT_FOUND)?;
    let snap: Snapshot = serde_json::from_slice(&data).map_err(|_| StatusCode::BAD_REQUEST)?;
    for (rid_s, amt) in snap.lgn_balances { let rid = lrb_core::Rid(rid_s); st.engine.ledger().set_balance(&rid, amt).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; }
    for (rid_s, amt) in snap.rlgn_balances { let rid = lrb_core::Rid(rid_s); st.engine.ledger().set_rbalance(&rid, amt).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; }
    Ok(Json(serde_json::json!({"ok": true})))
}

/* validators info */
#[derive(Serialize)] pub struct ValidatorsInfo { pub validators: Vec<String>, pub quorum_n: usize }
pub async fn validators_info(Extension(st): Extension<AppState>) -> Json<ValidatorsInfo> {
    let vals = st.validators.iter().cloned().collect::<Vec<_>>();
    Json(ValidatorsInfo { validators: vals, quorum_n: st.quorum_n })
}
