use axum::{extract::Extension, Json};
use axum::http::{StatusCode, HeaderMap};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use crate::state::{AppState, BR_DEPOSIT, BR_REDEEM, now_ms};
use crate::auth;

#[derive(Deserialize)] pub struct DepositReq { pub rid:String, pub amount:u64, pub ext_txid:String }
#[derive(Serialize)]   pub struct DepositResp { pub ok:bool, pub rid:String, pub r_balance:u64 }
#[derive(Deserialize)] pub struct RedeemReq { pub rid:String, pub amount:u64, pub request_id:String }
#[derive(Serialize)]   pub struct RedeemResp { pub ok:bool, pub rid:String, pub r_balance:u64, pub redeem_ticket:String, pub signature_b64:String }
#[derive(Deserialize)] pub struct VerifyReq { pub ticket:String, pub signature_b64:String, pub vk_b58:String }
#[derive(Serialize)]   pub struct VerifyResp { pub ok:bool }

pub async fn deposit(Extension(st): Extension<AppState>, headers: HeaderMap, Json(req): Json<DepositReq>)
-> Result<Json<DepositResp>, StatusCode> {
    if !st.rl_bridge.try_take(1) { return Err(StatusCode::TOO_MANY_REQUESTS); }
    auth::require_bridge(&headers)?;  // IP ACL / JWT / key

    if req.amount == 0 || req.amount > st.bridge_max_per_tx { return Err(StatusCode::BAD_REQUEST); }
    let rk = format!("dep:{}", req.ext_txid);
    if !st.replay_bridge.check_and_note(rk.clone(), now_ms()) { return Err(StatusCode::TOO_MANY_REQUESTS); }
    if let Ok(false) = st.engine.ledger().bridge_seen_mark(&rk) { return Err(StatusCode::CONFLICT); }

    let rid = lrb_core::Rid(req.rid.clone());
    let newb = st.engine.ledger().mint_rtoken(&rid, req.amount).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    BR_DEPOSIT.inc();
    Ok(Json(DepositResp { ok:true, rid: rid.as_str().to_string(), r_balance: newb }))
}

pub async fn redeem(Extension(st): Extension<AppState>, headers: HeaderMap, Json(req): Json<RedeemReq>)
-> Result<Json<RedeemResp>, StatusCode> {
    if !st.rl_bridge.try_take(1) { return Err(StatusCode::TOO_MANY_REQUESTS); }
    auth::require_bridge(&headers)?; // IP ACL / JWT / key

    if req.amount == 0 || req.amount > st.bridge_max_per_tx { return Err(StatusCode::BAD_REQUEST); }
    let rk = format!("red:{}", req.request_id);
    if !st.replay_bridge.check_and_note(rk.clone(), now_ms()) { return Err(StatusCode::TOO_MANY_REQUESTS); }
    if let Ok(false) = st.engine.ledger().bridge_seen_mark(&rk) { return Err(StatusCode::CONFLICT); }

    let rid = lrb_core::Rid(req.rid.clone());
    let newb = st.engine.ledger().burn_rtoken(&rid, req.amount).map_err(|_| StatusCode::BAD_REQUEST)?;
    BR_REDEEM.inc();

    let ticket = format!("redeem:{}:{}:{}", rid.as_str(), req.amount, req.request_id);
    let sig = st.sk.sign(ticket.as_bytes());
    let signature_b64 = B64.encode(sig.to_bytes());
    Ok(Json(RedeemResp { ok:true, rid: rid.as_str().to_string(), r_balance: newb, redeem_ticket: ticket, signature_b64 }))
}

pub async fn verify(Json(req): Json<VerifyReq>) -> Result<Json<VerifyResp>, StatusCode> {
    let pk_bytes = bs58::decode(&req.vk_b58).into_vec().map_err(|_| StatusCode::BAD_REQUEST)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| StatusCode::BAD_REQUEST)?).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig_bytes = B64.decode(req.signature_b64.as_bytes()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().map_err(|_| StatusCode::BAD_REQUEST)?);
    Ok(Json(VerifyResp { ok: vk.verify(req.ticket.as_bytes(), &sig).is_ok() }))
}
