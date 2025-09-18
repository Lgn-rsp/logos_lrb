//! rToken bridge: durable journal + idempotency + retry worker + external payout (async & Send-safe)

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{warn,error};

use crate::{state::AppState, metrics};
use crate::bridge_journal::{Journal,OpKind,OpStatus,JournalOp};
use crate::payout_adapter::PayoutAdapter;

#[derive(Deserialize)]
pub struct DepositReq { pub rid:String, pub amount:u64, pub ext_txid:String }
#[derive(Deserialize)]
pub struct RedeemReq  { pub rid:String, pub amount:u64, pub ext_txid:String }

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

    // credit in ledger (без await, guard не пересекает await)
    {
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
    } // <- guard дропнулся здесь

    let _ = j.set_status(&op.op_id, OpStatus::Confirmed, None);
    metrics::inc_bridge("deposit","confirmed");
    (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id))
}

/* -------------------- REDEEM (idempotent, Send-safe) -------------------- */
pub async fn redeem(State(st):State<Arc<AppState>>, Json(req):Json<RedeemReq>) -> (StatusCode,String){
    let j = journal(&st);
    let op = match j.begin(OpKind::Redeem, &req.rid, req.amount, &req.ext_txid){
        Ok(op) => op,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"journal_begin:{e}\"}}")),
    };
    metrics::inc_bridge("redeem","begin");

    // debit locally (burn) в отдельном скоупе — никаких await внутри!
    {
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
    } // <- guard дропнулся, теперь можно await

    // external payout (async)
    match PayoutAdapter::from_env() {
        Ok(adapter) => {
            if let Err(e) = adapter.send_payout(&req.rid, req.amount, &req.ext_txid).await {
                error!("payout error: {e}");
                let _ = j.set_status(&op.op_id, OpStatus::Failed, Some(e.to_string()));
                let _ = j.schedule_retry(&op.op_id, 30_000);
                metrics::inc_bridge("redeem","payout_failed");
                return (StatusCode::ACCEPTED, "{\"status\":\"queued\"}".into());
            }
        }
        Err(e) => {
            error!("payout adapter init: {e}");
            let _ = j.set_status(&op.op_id, OpStatus::Failed, Some(e.to_string()));
            let _ = j.schedule_retry(&op.op_id, 30_000);
            metrics::inc_bridge("redeem","payout_init_failed");
            return (StatusCode::ACCEPTED, "{\"status\":\"queued\"}".into());
        }
    }

    let _ = j.set_status(&op.op_id, OpStatus::Redeemed, None);
    metrics::inc_bridge("redeem","redeemed");
    (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id))
}

/* -------------------- RETRY worker (idempotent & Send-safe) -------------------- */
async fn retry_deposit(st:&AppState, j:&Journal, op:&JournalOp){
    // всё без await внутри скоупа
    {
        let l = st.ledger.lock();
        let bal  = l.get_balance(&op.rid).unwrap_or(0);
        let newb = bal.saturating_add(op.amount);
        if l.set_balance(&op.rid, newb as u128).is_ok(){
            let _ = j.set_status(&op.op_id, OpStatus::Confirmed, None);
            metrics::inc_bridge("deposit","confirmed");
            let _ = j.clear_retry(&op.op_id);
            return;
        }
    }
    let _ = j.schedule_retry(&op.op_id, 60_000);
}

async fn retry_redeem(j:&Journal, op:&JournalOp){
    match PayoutAdapter::from_env() {
        Ok(adapter) => {
            match adapter.send_payout(&op.rid, op.amount, &op.ext_txid).await {
                Ok(()) => {
                    let _ = j.set_status(&op.op_id, OpStatus::Redeemed, None);
                    metrics::inc_bridge("redeem","redeemed");
                    let _ = j.clear_retry(&op.op_id);
                }
                Err(e) => {
                    warn!("retry payout error: {e}");
                    let _ = j.schedule_retry(&op.op_id, 90_000);
                }
            }
        }
        Err(e) => {
            warn!("retry payout adapter init: {e}");
            let _ = j.schedule_retry(&op.op_id, 90_000);
        }
    }
}

pub async fn retry_worker(st:Arc<AppState>){
    let j = journal(&st);
    loop {
        if let Ok(list) = j.due_retries(100) {
            for op_id in list {
                if let Ok(op) = j.get_by_id(&op_id) {
                    match op.kind {
                        OpKind::Deposit => retry_deposit(&st, &j, &op).await,
                        OpKind::Redeem  => retry_redeem(&j, &op).await,
                    }
                }
            }
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
