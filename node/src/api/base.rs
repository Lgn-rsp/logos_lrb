use axum::{extract::{Path, State}, Json};
use std::sync::Arc;
use crate::state::AppState;
use super::{OkMsg, Head, Balance, Economy, HistoryItem};

pub async fn healthz() -> Json<OkMsg> {
    Json(OkMsg { status: "ok" })
}

pub async fn head(State(app): State<Arc<AppState>>) -> Json<Head> {
    let l = app.ledger.lock();
    // В новом ledger нет head_height(), используем height()
    let h = l.height().unwrap_or(0);
    let fin = h.saturating_sub(1);
    Json(Head { height: h, finalized: fin })
}

pub async fn balance(
    Path(rid): Path<String>,
    State(app): State<Arc<AppState>>,
) -> Json<Balance> {
    let l = app.ledger.lock();
    let bal = l.get_balance(&rid).unwrap_or(0);
    let n = l.get_nonce(&rid).unwrap_or(0);
    Json(Balance {
        rid,
        balance: bal as u128,
        nonce: n,
    })
}

pub async fn economy(State(app): State<Arc<AppState>>) -> Json<Economy> {
    const CAP_MICRO: u64 = 81_000_000_u64 * 1_000_000_u64;
    // ledger.supply() уже даёт (u64, u64)
    let (minted, burned) = app.ledger.lock().supply().unwrap_or((0, 0));
    let supply = minted.saturating_sub(burned);
    Json(Economy {
        supply,
        burned,
        cap: CAP_MICRO,
    })
}

pub async fn history(
    Path(rid): Path<String>,
    State(app): State<Arc<AppState>>,
) -> Json<Vec<HistoryItem>> {
    let l = app.ledger.lock();
    let rows = l.account_txs_page(&rid, 0, 100).unwrap_or_default();

    Json(
        rows
            .into_iter()
            .map(|r| HistoryItem {
                txid: r.txid,
                height: r.height,
                from: r.from,
                to: r.to,
                amount: r.amount,
                nonce: r.nonce,
                // r.ts сейчас Option<u64>, аккуратно делим на 1000
                ts: r.ts.map(|ts| ts / 1000),
            })
            .collect(),
    )
}
