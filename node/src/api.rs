use axum::{extract::{Path, State}, response::IntoResponse, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::metrics::inc_total;
use crate::state::AppState;
use crate::storage::{TxIn, HistoryItem};

#[derive(Serialize)]
struct OkMsg { status: &'static str }

pub async fn healthz() -> impl IntoResponse {
    inc_total("healthz");
    Json(OkMsg{ status: "ok" })
}

#[derive(Serialize)]
struct Head { height: u64 }

pub async fn head(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    inc_total("head");
    let h = app.ledger.lock().height().unwrap_or(0);
    Json(Head { height: h })
}

#[derive(Serialize)]
struct Balance { rid: String, balance: u128, nonce: u64 }

pub async fn balance(State(app): State<Arc<AppState>>, Path(rid): Path<String>) -> impl IntoResponse {
    inc_total("balance");
    let l = app.ledger.lock();
    let bal = l.get_balance(&rid).unwrap_or(0);
    let n = l.get_nonce(&rid).unwrap_or(0);
    Json(Balance { rid, balance: bal, nonce: n })
}

#[derive(Serialize)]
struct SubmitResult { ok: bool, txid: Option<String>, info: String }

pub async fn submit_tx(State(app): State<Arc<AppState>>, Json(tx): Json<TxIn>) -> impl IntoResponse {
    inc_total("submit_tx");

    // 1) Выполняем леджер-операцию в отдельном скоупе (не держим lock через await!)
    let stx_res = {
        let l = app.ledger.lock();
        l.submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.clone())
    };

    match stx_res {
        Ok(stx) => {
            // 2) После выхода из скоупа мьютекс уже освобождён — теперь можно await
            if let Some(ref arch) = app.archive {
                let _ = arch.record_tx(&stx.txid, stx.height, &stx.from, &stx.to, stx.amount, stx.nonce, stx.ts).await;
            }
            Json(SubmitResult{ ok: true, txid: Some(stx.txid), info: "accepted".into() })
        }
        Err(e)  => Json(SubmitResult{ ok: false, txid: None, info: format!("{}", e) }),
    }
}

#[derive(Serialize)]
struct Economy { supply: u64, burned: u64, cap: u64 }

pub async fn economy(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    inc_total("economy");
    let (minted, burned) = app.ledger.lock().supply().unwrap_or((0,0));
    Json(Economy { supply: minted.saturating_sub(burned), burned, cap: 81_000_000 })
}

pub async fn history(State(app): State<Arc<AppState>>, Path(rid): Path<String>) -> impl IntoResponse {
    inc_total("history");
    let l = app.ledger.lock();
    let rows = l.account_txs_page(&rid, 0, 100).unwrap_or_default();
    let list: Vec<HistoryItem> = rows.into_iter().map(|r| HistoryItem{
        txid: r.txid, height: r.height, from: r.from, to: r.to, amount: r.amount, nonce: r.nonce, ts: r.ts
    }).collect();
    Json(list)
}

/* --- Архив: публичные эндпоинты (async-await) --- */

pub async fn archive_history(State(app): State<Arc<AppState>>, Path(rid): Path<String>) -> impl IntoResponse {
    inc_total("archive_history");
    if let Some(ref arch) = app.archive {
        let v = arch.history_page(&rid, 0, 100).await.unwrap_or_default();
        return Json(v); // Vec<serde_json::Value>
    }
    // архив выключен — возвращаем пустой список того же типа
    Json(Vec::<serde_json::Value>::new())
}

pub async fn archive_tx(State(app): State<Arc<AppState>>, Path(txid): Path<String>) -> impl IntoResponse {
    inc_total("archive_tx");
    if let Some(ref arch) = app.archive {
        let v = arch.get_tx(&txid).await.unwrap_or(None);
        return Json(serde_json::json!({ "ok": v.is_some(), "tx": v }));
    }
    Json(serde_json::json!({"ok":false,"err":"archive disabled"}))
}
