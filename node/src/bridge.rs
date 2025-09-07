use axum::{extract::State, response::IntoResponse, Json};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use blake3;

use crate::state::AppState;
use crate::auth::require_bridge;
use crate::metrics::inc_total;

#[derive(Deserialize, Debug)]
pub struct DepositReq {
    pub txid: String,        // внешний tx (например, L1 hash)
    pub amount: u64,         // сумма депозита
    pub from_chain: String,  // сеть-источник (ETH/BTC/…)
    pub to_rid: String,      // RID получателя в LRB
}

#[derive(Deserialize, Debug)]
pub struct RedeemReq  {
    pub rtoken_tx: String,   // внутренняя операция/tx rToken
    pub to_chain: String,    // сеть-назначение
    pub to_addr: String,     // адрес-назначение во внешней сети
    pub amount: u64,         // сумма на вывод
}

#[derive(Deserialize, Debug)]
pub struct VerifyReq  {
    pub op_id: String,       // идентификатор операции для проверки статуса
}

#[derive(Serialize)]
pub struct BridgeResp {
    pub ok: bool,
    pub op_id: String,
    pub info: String,
}

/// Хелпер: стабильный op_id по concat входных полей
fn opid(parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update(b"|");
    }
    h.finalize().to_hex().to_string()
}

pub async fn deposit(State(_app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<DepositReq>) -> impl IntoResponse {
    inc_total("bridge_deposit");
    if let Err(e) = require_bridge(&headers) {
        return Json(BridgeResp { ok: false, op_id: String::new(), info: format!("forbidden: {e}") });
    }
    // используем ВСЕ поля, формируем детерминированный op_id
    let op_id = opid(&[ "deposit", &req.txid, &req.amount.to_string(), &req.from_chain, &req.to_rid ]);
    // TODO: тут можно писать заявку в sled (таблица rbridge_ops), сейчас MVP-ответ
    Json(BridgeResp {
        ok: true,
        op_id,
        info: format!("deposit registered: txid={}, amount={}, from_chain={}, to_rid={}", req.txid, req.amount, req.from_chain, req.to_rid),
    })
}

pub async fn redeem(State(_app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<RedeemReq>) -> impl IntoResponse {
    inc_total("bridge_redeem");
    if let Err(e) = require_bridge(&headers) {
        return Json(BridgeResp { ok: false, op_id: String::new(), info: format!("forbidden: {e}") });
    }
    let op_id = opid(&[ "redeem", &req.rtoken_tx, &req.amount.to_string(), &req.to_chain, &req.to_addr ]);
    // TODO: запись заявки на вывод в sled
    Json(BridgeResp {
        ok: true,
        op_id,
        info: format!("redeem accepted: rtoken_tx={}, amount={}, to_chain={}, to_addr={}", req.rtoken_tx, req.amount, req.to_chain, req.to_addr),
    })
}

pub async fn verify(State(_app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<VerifyReq>) -> impl IntoResponse {
    inc_total("bridge_verify");
    if let Err(e) = require_bridge(&headers) {
        return Json(BridgeResp { ok: false, op_id: String::new(), info: format!("forbidden: {e}") });
    }
    // TODO: lookup статуса по op_id в sled; пока MVP: echo
    Json(BridgeResp {
        ok: true,
        op_id: req.op_id,
        info: "status: pending (mvp)".into(),
    })
}
