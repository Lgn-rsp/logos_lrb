use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use serde_json::json;

use crate::state::AppState;
use crate::auth::require_admin;
use crate::metrics::inc_total;

#[derive(Deserialize)] pub struct SetBalanceReq { pub rid: String, pub amount: u128 }
#[derive(Deserialize)] pub struct BumpNonceReq  { pub rid: String }
#[derive(Deserialize)] pub struct SetNonceReq   { pub rid: String, pub value: u64 }
#[derive(Deserialize)] pub struct MintReq       { pub amount: u64 }
#[derive(Deserialize)] pub struct BurnReq       { pub amount: u64 }

pub async fn set_balance(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<SetBalanceReq>) -> impl IntoResponse {
    inc_total("admin_set_balance");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.set_balance(&req.rid, req.amount) { Ok(_) => Json(json!({"ok":true})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
pub async fn bump_nonce(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<BumpNonceReq>) -> impl IntoResponse {
    inc_total("admin_bump_nonce");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.bump_nonce(&req.rid) { Ok(n)=>Json(json!({"ok":true,"nonce":n})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
pub async fn set_nonce(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<SetNonceReq>) -> impl IntoResponse {
    inc_total("admin_set_nonce");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.set_nonce(&req.rid, req.value) { Ok(_)=>Json(json!({"ok":true,"nonce":req.value})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
pub async fn mint(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<MintReq>) -> impl IntoResponse {
    inc_total("admin_mint");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.add_minted(req.amount) { Ok(net)=>Json(json!({"ok":true,"net_supply":net})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
pub async fn burn(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<BurnReq>) -> impl IntoResponse {
    inc_total("admin_burn");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.add_burned(req.amount) { Ok(net)=>Json(json!({"ok":true,"net_supply":net})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
