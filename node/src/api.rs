use axum::{
    extract::{Path, Extension, Query},
    Json,
};
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use lrb_core::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use crate::state::*;

/* ---------- типы ---------- */
#[derive(Serialize)] pub struct Healthz { pub ok: bool }
#[derive(Deserialize)] pub struct SubmitTx {
    pub from:String, pub to:String, pub amount:u64, pub nonce:u64,
    pub public_key_b58:String, pub signature_b64:String
}
#[derive(Serialize)] pub struct SubmitResp { pub accepted: bool, pub tx_id: String, pub lgn_cost_microunits: u64 }
#[derive(Deserialize)] pub struct DebugCanonReq { pub from:String, pub to:String, pub amount:u64, pub nonce:u64, pub public_key_b58:String }
#[derive(Serialize)] pub struct DebugCanonResp { pub canon_hex:String, pub server_tx_id:String }

/* ---------- базовые ---------- */
pub async fn healthz() -> Json<Healthz> { Json(Healthz{ok:true}) }

pub async fn head(Extension(st): Extension<AppState>) -> Json<serde_json::Value> {
    let (h, hash) = st.engine.ledger().head().unwrap_or((0, String::new()));
    let fin = st.engine.ledger().get_finalized().unwrap_or(0);
    Json(serde_json::json!({ "height": h, "hash": hash, "finalized": fin }))
}

pub async fn balance(Path(rid): Path<String>, Extension(st): Extension<AppState>) -> Json<serde_json::Value> {
    let rid = Rid(rid); let bal = st.engine.ledger().get_balance(&rid);
    Json(serde_json::json!({ "rid": rid.as_str(), "balance": bal }))
}

/* ---------- состояние аккаунта ---------- */
pub async fn account_state(Path(rid): Path<String>, Extension(st): Extension<AppState>)
-> Result<Json<serde_json::Value>, StatusCode> {
    let r = Rid(rid);
    let bal = st.engine.ledger().get_balance(&r);
    let n   = st.engine.ledger().get_nonce(&r);
    Ok(Json(serde_json::json!({ "rid": r.as_str(), "balance": bal, "nonce": n })))
}

/* ---------- одиночный submit ---------- */
pub async fn submit_tx(Extension(st): Extension<AppState>, Json(req): Json<SubmitTx>)
-> Result<Json<SubmitResp>, StatusCode> {
    if !st.rl_submit.try_take(1) { return Err(StatusCode::TOO_MANY_REQUESTS); }
    TX_SUBMITTED.inc();
    if req.amount == 0 { return Err(StatusCode::BAD_REQUEST); }
    let pk_bytes = bs58::decode(&req.public_key_b58).into_vec().map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig_bytes = B64.decode(req.signature_b64.as_bytes()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let tx = Tx { id:"".into(), from:Rid(req.from.clone()), to:Rid(req.to.clone()),
                  amount:req.amount, nonce:req.nonce, public_key:pk_bytes, signature:sig_bytes };
    let tx = Tx { id: tx.compute_id(), ..tx };
    if lrb_core::phase_integrity::verify_tx_signature(&tx).is_err() { return Err(StatusCode::UNPROCESSABLE_ENTITY); }
    st.engine.mempool_sender().send(tx.clone()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(SubmitResp { accepted:true, tx_id: tx.id, lgn_cost_microunits: st.engine.lgn_cost_microunits() }))
}

/* ---------- batch submit ---------- */
#[derive(Serialize)] pub struct BatchItem { pub tx_id:String, pub ok:bool, pub err:Option<String> }
#[derive(Serialize)] pub struct BatchResp { pub accepted:usize, pub rejected:usize, pub items:Vec<BatchItem>, pub lgn_cost_microunits:u64 }

pub async fn submit_tx_batch(Extension(st): Extension<AppState>, Json(reqs): Json<Vec<SubmitTx>>)
-> Result<Json<BatchResp>, StatusCode> {
    let n = reqs.len(); if n == 0 { return Err(StatusCode::BAD_REQUEST); }
    let maxb = std::env::var("LRB_MAX_BATCH").ok().and_then(|s| s.parse::<usize>().ok()).unwrap_or(1000);
    if n > maxb { return Err(StatusCode::PAYLOAD_TOO_LARGE); }
    if !st.rl_submit.try_take(n as u64) { return Err(StatusCode::TOO_MANY_REQUESTS); }

    let mut items = Vec::with_capacity(n); let mut accepted = 0usize;
    let sender = st.engine.mempool_sender();
    for r in reqs {
        if r.amount == 0 {
            items.push(BatchItem{ tx_id:String::new(), ok:false, err:Some("amount=0".into())});
            continue;
        }
        let pk_bytes = match bs58::decode(&r.public_key_b58).into_vec() { Ok(v)=>v, Err(_)=>{ items.push(BatchItem{tx_id:String::new(), ok:false, err:Some("bad public_key_b58".into())}); continue; } };
        let sig_bytes = match B64.decode(r.signature_b64.as_bytes()) { Ok(v)=>v, Err(_)=>{ items.push(BatchItem{tx_id:String::new(), ok:false, err:Some("bad signature_b64".into())}); continue; } };
        let tx = Tx { id:String::new(), from:Rid(r.from), to:Rid(r.to), amount:r.amount, nonce:r.nonce, public_key:pk_bytes, signature:sig_bytes };
        let tx = Tx { id: tx.compute_id(), ..tx };
        if lrb_core::phase_integrity::verify_tx_signature(&tx).is_err() { items.push(BatchItem{tx_id:tx.id, ok:false, err:Some("bad signature".into())}); continue; }
        if sender.send(tx.clone()).is_err() { items.push(BatchItem{tx_id:tx.id, ok:false, err:Some("enqueue failed".into())}); continue; }
        items.push(BatchItem{tx_id:tx.id, ok:true, err:None}); accepted+=1;
    }
    TX_SUBMITTED.inc_by(accepted as u64);
    Ok(Json(BatchResp{ accepted, rejected: items.len()-accepted, items, lgn_cost_microunits: st.engine.lgn_cost_microunits() }))
}

/* ---------- debug / block / tx ---------- */
pub async fn debug_canon(Json(req): Json<DebugCanonReq>) -> Result<Json<DebugCanonResp>, StatusCode> {
    let pk_bytes = bs58::decode(&req.public_key_b58).into_vec().map_err(|_| StatusCode::BAD_REQUEST)?;
    let tx = Tx { id:"".to_string(), from:Rid(req.from), to:Rid(req.to),
                  amount:req.amount, nonce:req.nonce, public_key:pk_bytes, signature:vec![0u8;64] };
    Ok(Json(DebugCanonResp { canon_hex: hex::encode(tx.canonical_bytes()), server_tx_id: tx.compute_id() }))
}

pub async fn get_block(Path(height): Path<u64>, Extension(st): Extension<AppState>)
-> Result<Json<Block>, StatusCode> {
    st.engine.ledger().get_block_by_height(height).map(Json).map_err(|_| StatusCode::NOT_FOUND)
}

/* простой ответ по tx: только высота, если есть */
pub async fn get_tx(Path(txid): Path<String>, Extension(st): Extension<AppState>)
-> Result<Json<serde_json::Value>, StatusCode> {
    match st.engine.ledger().get_tx_height(&txid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
        Some(h) => Ok(Json(serde_json::json!({ "tx_id": txid, "height": h }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/* детальный ответ по tx (блок целиком) */
#[derive(Serialize)] pub struct TxFull { pub tx_id:String, pub height:u64, pub block:serde_json::Value, pub found:bool }
pub async fn get_tx_full(Path(txid): Path<String>, Extension(st): Extension<AppState>)
-> Result<Json<TxFull>, StatusCode> {
    match st.engine.ledger().get_tx_height(&txid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
        Some(h) => {
            let blk = st.engine.ledger().get_block_by_height(h).map_err(|_| StatusCode::NOT_FOUND)?;
            let blk_json = serde_json::to_value(&blk).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(TxFull{ tx_id: txid, height: h, block: blk_json, found:true }))
        }
        None => Ok(Json(TxFull{ tx_id: txid, height: 0, block: serde_json::json!({}), found:false })),
    }
}

/* ---------- история аккаунта (пагинация курсором) ---------- */
#[derive(Serialize)] pub struct AccountTxsPage {
    pub rid:String, pub limit:usize, pub items:Vec<serde_json::Value>,
    pub next_cursor_h: Option<u64>, pub next_cursor_seq: Option<u32>
}
pub async fn account_txs(
    Path(rid_s): Path<String>,
    Query(q): Query<HashMap<String,String>>,
    Extension(st): Extension<AppState>
) -> Result<Json<AccountTxsPage>, StatusCode> {
    let rid = Rid(rid_s);
    let limit = q.get("limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(100);
    let ch = q.get("cursor_h").and_then(|s| s.parse::<u64>().ok());
    let cs = q.get("cursor_seq").and_then(|s| s.parse::<u32>().ok());
    let (items, next_h, next_s) = st.engine.ledger().list_account_txs_page(&rid, ch, cs, limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(AccountTxsPage{
        rid: rid.as_str().to_string(), limit, items,
        next_cursor_h: next_h, next_cursor_seq: next_s
    }))
}

/* ---------- эксплорер (последние блоки/tx) ---------- */
#[derive(Serialize)] pub struct RecentBlocks { pub items: Vec<serde_json::Value> }
pub async fn recent_blocks(Extension(st): Extension<AppState>, Query(q): Query<HashMap<String,String>>)
-> Result<Json<RecentBlocks>, StatusCode> {
    let limit = q.get("limit").and_then(|s| s.parse::<u64>().ok()).unwrap_or(20);
    let (mut h, _) = st.engine.ledger().head().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for _ in 0..limit {
        if h == 0 { break; }
        if let Ok(b) = st.engine.ledger().get_block_by_height(h) {
            out.push(serde_json::to_value(b).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
        }
        if h == 0 { break; }
        h -= 1;
    }
    Ok(Json(RecentBlocks{ items: out }))
}

#[derive(Serialize)] pub struct RecentTxs { pub items: Vec<serde_json::Value> }
pub async fn recent_txs(Extension(st): Extension<AppState>, Query(q): Query<HashMap<String,String>>)
-> Result<Json<RecentTxs>, StatusCode> {
    let limit = q.get("limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
    let (mut h, _) = st.engine.ledger().head().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    while out.len() < limit && h > 0 {
        if let Ok(b) = st.engine.ledger().get_block_by_height(h) {
            for tx in b.txs.iter().rev() {
                if out.len() >= limit { break; }
                out.push(serde_json::json!({"height": b.height, "tx_id": tx.id, "from": tx.from.0, "to": tx.to.0, "amount": tx.amount}));
            }
        }
        if h == 0 { break; }
        h -= 1;
    }
    Ok(Json(RecentTxs{ items: out }))
}

/* ---------- DEV faucet ---------- */
#[allow(dead_code)]
pub async fn faucet(Path((rid_s,amount_s)):Path<(String,String)>, Extension(st):Extension<AppState>)
-> Result<Json<serde_json::Value>, StatusCode> {
    if !st.dev_mode { return Err(StatusCode::FORBIDDEN); }
    let rid = Rid(rid_s); let amount:u64 = amount_s.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let cur = st.engine.ledger().get_balance(&rid); let newb = cur.saturating_add(amount);
    st.engine.ledger().set_balance(&rid, newb).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok": true, "rid": rid.as_str(), "balance": newb })))
}
