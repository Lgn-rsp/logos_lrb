//! Bridge: rToken deposit/redeem/verify — prod-ready (single-node, idempotent).
//! Требует корректного X-Bridge-Key (см. LRB_BRIDGE_KEY).
//! Идемпотентность по внешнему ключу квитанции/билета через ledger.bridge_seen_mark().

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::{AppState, auth::require_bridge};
use lrb_core::types::Rid;

#[derive(Deserialize)]
pub struct DepositReq {
    /// RID получателя в LOGOS (base58 от pubkey)
    pub rid: String,
    /// Сумма в rLGN
    pub amount: u64,
    /// Внешний уникальный id транзакции/квитанции (например, txid из ETH)
    pub ext_txid: String,
}

#[derive(Serialize)]
pub struct DepositResp {
    pub status: &'static str,
    pub rid: String,
    pub credited: u64,
    pub ext_txid: String,
}

pub async fn deposit(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DepositReq>,
) -> Result<Json<DepositResp>, StatusCode> {
    require_bridge(&headers)?;

    if req.amount == 0 || req.rid.trim().is_empty() || req.ext_txid.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Идемпотентность внешней транзакции
    let rk = format!("deposit:{}", req.ext_txid.trim());
    if !st.ledger.bridge_seen_mark(&rk).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
        return Ok(Json(DepositResp {
            status: "ok_repeat",
            rid: req.rid,
            credited: req.amount,
            ext_txid: req.ext_txid,
        }));
    }

    // Минтим rLGN
    let rid = Rid(req.rid.clone());
    st.ledger.mint_rtoken(&rid, req.amount).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(DepositResp {
        status: "ok",
        rid: req.rid,
        credited: req.amount,
        ext_txid: req.ext_txid,
    }))
}

#[derive(Deserialize)]
pub struct RedeemReq {
    pub rid: String,
    pub amount: u64,
    /// Целевая цепь (например, "ETH")
    #[serde(default)]
    pub target_chain: String,
    /// Адрес в целевой цепи
    #[serde(default)]
    pub target_address: String,
}

#[derive(Serialize)]
pub struct RedeemResp {
    pub status: &'static str,
    pub rid: String,
    pub debited: u64,
    /// Билет на вывод во внешней сети (используется оффчейн-исполнителем)
    pub redeem_ticket: String,
    pub target_chain: String,
    pub target_address: String,
}

pub async fn redeem(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, StatusCode> {
    require_bridge(&headers)?;
    if req.amount == 0 || req.rid.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Детерминированный билет — для идемпотентности и трекинга
    let redeem_ticket = format!(
        "redeem:{}:{}:{}:{}",
        req.rid.trim(),
        req.amount,
        req.target_chain.trim(),
        req.target_address.trim()
    );

    // Если билет уже «виден» — повтор
    if !st.ledger.bridge_seen_mark(&redeem_ticket).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
        return Ok(Json(RedeemResp {
            status: "ok_repeat",
            rid: req.rid,
            debited: req.amount,
            redeem_ticket,
            target_chain: req.target_chain,
            target_address: req.target_address,
        }));
    }

    // Сжигаем rLGN под вывод (если баланса не хватит — вернётся 400)
    let rid = Rid(req.rid.clone());
    st.ledger.burn_rtoken(&rid, req.amount).map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(Json(RedeemResp {
        status: "ok",
        rid: req.rid,
        debited: req.amount,
        redeem_ticket,
        target_chain: req.target_chain,
        target_address: req.target_address,
    }))
}

#[derive(Deserialize)]
pub struct VerifyReq {
    pub ticket: String,
}

#[derive(Serialize)]
pub struct VerifyResp {
    pub status: &'static str,
    pub ok: bool,
    pub ticket: String,
}

pub async fn verify(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, StatusCode> {
    require_bridge(&headers)?;
    if req.ticket.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Первая попытка помечает — ok:false; повтор — ok:true
    let existed = !st.ledger.bridge_seen_mark(&req.ticket).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(VerifyResp { status: "ok", ok: existed, ticket: req.ticket }))
}
