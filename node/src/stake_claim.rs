use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use std::sync::Arc;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ClaimReq { pub rid:String, pub amount:u64 }

/// Финализация награды: зачисляем в ledger (при необходимости добавь запись в историю)
pub async fn claim_settle(State(st):State<Arc<AppState>>, Json(req):Json<ClaimReq>) -> (StatusCode,String){
    {
        let l = st.ledger.lock();
        let bal = l.get_balance(&req.rid).unwrap_or(0);
        let newb = bal.saturating_add(req.amount as u128);
        if let Err(e) = l.set_balance(&req.rid, newb as u128) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"{e}\"}}"));
        }
        // Если хочешь — вставь спец-tx «reward» в историю (StoredTx).
    }
    (StatusCode::OK, "{\"ok\":true}".into())
}
