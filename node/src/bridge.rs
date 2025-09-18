//! rToken bridge: durable journal + idempotency + retry worker

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{warn,error};

use crate::{state::AppState, metrics};
use crate::bridge_journal::{Journal,OpKind,OpStatus};

#[derive(Deserialize)]
pub struct DepositReq { pub rid:String, pub amount:u64, pub ext_txid:String }   // внешний депозит → кредитуем локально
#[derive(Deserialize)]
pub struct RedeemReq  { pub rid:String, pub amount:u64, pub ext_txid:String }   // локальный вывод → дебетим и платим наружу

#[inline]
fn journal(st:&AppState)->Journal { Journal::open(st.sled()).expect("journal") }

/* -------------------- DEPOSIT (idempotent) -------------------- */
pub async fn deposit(State(st):State<Arc<AppState>>, Json(req):Json<DepositReq>) -> (StatusCode,String){
    let j = journal(&st);
    let op = match j.begin(OpKind::Deposit, &req.rid, req.amount, &req.ext_txid){
        Ok(op) => op,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"journal_begin:{e}\"}}")),
    };
    metrics::inc_bridge("deposit","begin");

    // credit in ledger (idempotent: op уже создан)
    let l = st.ledger.lock();
    let bal  = l.get_balance(&req.rid).unwrap_or(0);
    let newb = bal.saturating_add(req.amount);
    if let Err(e) = l.set_balance(&req.rid, newb as u128) {
        error!("deposit set_balance: {e}");
        let _ = j.set_status(&op.op_id, OpStatus::Failed, Some(e.to_string()));
        let _ = j.schedule_retry(&op.op_id, 5_000);
        metrics::inc_bridge("deposit","failed");
        return (StatusCode::ACCEPTED, "{\"status\":\"queued\"}".into());
    }
    drop(l);

    let _ = j.set_status(&op.op_id, OpStatus::Confirmed, None);
    metrics::inc_bridge("deposit","confirmed");
    (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id))
}

/* -------------------- REDEEM (idempotent) -------------------- */
pub async fn redeem(State(st):State<Arc<AppState>>, Json(req):Json<RedeemReq>) -> (StatusCode,String){
    let j = journal(&st);
    let op = match j.begin(OpKind::Redeem, &req.rid, req.amount, &req.ext_txid){
        Ok(op) => op,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"journal_begin:{e}\"}}")),
    };
    metrics::inc_bridge("redeem","begin");

    // debit locally (burn)
    let l = st.ledger.lock();
    let bal = l.get_balance(&req.rid).unwrap_or(0);
    if bal < req.amount {
        metrics::inc_bridge("redeem","insufficient");
        return (StatusCode::BAD_REQUEST, "{\"error\":\"insufficient\"}".into());
    }
    let newb = bal - req.amount;
    if let Err(e) = l.set_balance(&req.rid, newb as u128) {
        error!("redeem set_balance: {e}");
        let _ = j.set_status(&op.op_id, OpStatus::Failed, Some(e.to_string()));
        let _ = j.schedule_retry(&op.op_id, 5_000);
        metrics::inc_bridge("redeem","failed");
        return (StatusCode::ACCEPTED, "{\"status\":\"queued\"}".into());
    }
    drop(l);

    // TODO: вызов внешнего payout-адаптера; по успеху:
    let _ = j.set_status(&op.op_id, OpStatus::Redeemed, None);
    metrics::inc_bridge("redeem","redeemed");
    (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id))
}

/* -------------------- RETRY worker (idempotent) -------------------- */
pub async fn retry_worker(st:Arc<AppState>){
    let j = journal(&st);
    loop {
        match j.due_retries(100){
            Ok(list) if !list.is_empty() => {
                for op_id in list {
                    match j.get_by_id(&op_id){
                        Ok(op) => {
                            warn!("bridge retry: op_id={} kind={:?} amount={}", op_id, op.kind, op.amount);
                            // На этом этапе можно повторно выполнить бизнес-операцию.
                            // Пока просто перезапланируем с backoff (демо).
                            let _ = j.set_status(&op_id, OpStatus::Pending, None);
                            let _ = j.schedule_retry(&op_id, 30_000);
                        }
                        Err(_) => { /* пропускаем */ }
                    }
                }
            }
            _ => {}
        }
        tokio::time::sleep(std::time::Duration::from_millis(3_000)).await;
    }
}

/* -------------------- Health (journal stats) -------------------- */
pub async fn health(State(st):State<Arc<AppState>>)->(StatusCode,String){
    let j = journal(&st);
    match j.stats(){
        Ok((pending,confirmed,redeemed)) =>
            (StatusCode::OK, format!("{{\"pending\":{pending},\"confirmed\":{confirmed},\"redeemed\":{redeemed}}}")),
        Err(e) =>
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"{e}\"}}")),
    }
}
