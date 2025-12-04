use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{info, warn, error};

use crate::{state::AppState, metrics};
use super::{TxIn, SubmitResult, SubmitBatchReq, SubmitBatchItem};
use super::{canonical_msg, verify_sig};

pub async fn submit_tx(
    State(app): State<Arc<AppState>>,
    Json(tx): Json<TxIn>,
) -> (StatusCode, Json<SubmitResult>) {
    let msg = canonical_msg(&tx.from, &tx.to, tx.amount, tx.nonce);

    if let Err(e) = verify_sig(&tx.from, &msg, &tx.sig_hex) {
        metrics::inc_tx_rejected("bad_signature");
        return (
            StatusCode::UNAUTHORIZED,
            Json(SubmitResult { ok: false, txid: None, info: e }),
        );
    }

    let prev = app.ledger.lock().get_nonce(&tx.from).unwrap_or(0);
    if tx.nonce <= prev {
        metrics::inc_tx_rejected("nonce_reuse");
        return (
            StatusCode::CONFLICT,
            Json(SubmitResult {
                ok: false,
                txid: None,
                info: "nonce_reuse".into(),
            }),
        );
    }

    let stx = match app
        .ledger
        .lock()
        .submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.as_deref())
    {
        Ok(s) => s,
        Err(e) => {
            metrics::inc_tx_rejected("internal");
            return (
                StatusCode::OK,
                Json(SubmitResult {
                    ok: false,
                    txid: None,
                    info: e.to_string(),
                }),
            );
        }
    };

    if let Some(arch) = &app.archive {
        let ts_sec = stx.ts.map(|ts| ts / 1000);
        match arch
            .record_tx(
                &stx.txid,
                stx.height,
                &stx.from,
                &stx.to,
                stx.amount,
                stx.nonce,
                ts_sec,
            )
            .await
        {
            Ok(()) => info!("archive: wrote tx {}", stx.txid),
            Err(e) => error!("archive: write failed: {}", e),
        }
    } else {
        warn!("archive: not configured");
    }

    metrics::inc_tx_accepted();
    (
        StatusCode::OK,
        Json(SubmitResult {
            ok: true,
            txid: Some(stx.txid),
            info: "accepted".into(),
        }),
    )
}

pub async fn submit_tx_batch(
    State(app): State<Arc<AppState>>,
    Json(req): Json<SubmitBatchReq>,
) -> (StatusCode, Json<Vec<SubmitBatchItem>>) {
    let mut out = Vec::with_capacity(req.txs.len());

    // 1) проверяем и коммитим tx по правилам (подпись, nonce)
    for (i, tx) in req.txs.into_iter().enumerate() {
        let msg = canonical_msg(&tx.from, &tx.to, tx.amount, tx.nonce);

        if let Err(e) = verify_sig(&tx.from, &msg, &tx.sig_hex) {
            metrics::inc_tx_rejected("bad_signature");
            out.push(SubmitBatchItem {
                ok: false,
                txid: None,
                info: e,
                index: i,
            });
            continue;
        }

        let prev = app.ledger.lock().get_nonce(&tx.from).unwrap_or(0);
        if tx.nonce <= prev {
            metrics::inc_tx_rejected("nonce_reuse");
            out.push(SubmitBatchItem {
                ok: false,
                txid: None,
                info: "nonce_reuse".into(),
                index: i,
            });
            continue;
        }

        match app
            .ledger
            .lock()
            .submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.as_deref())
        {
            Ok(s) => {
                metrics::inc_tx_accepted();
                out.push(SubmitBatchItem {
                    ok: true,
                    txid: Some(s.txid),
                    info: "accepted".into(),
                    index: i,
                });
            }
            Err(e) => {
                metrics::inc_tx_rejected("internal");
                out.push(SubmitBatchItem {
                    ok: false,
                    txid: None,
                    info: e.to_string(),
                    index: i,
                });
            }
        }
    }

    // 2) инжест в архив — собираем только принятые
    if let Some(arch) = &app.archive {
        let mut rows: Vec<(String, u64, String, String, u64, u64, Option<u64>)> =
            Vec::new();

        for item in &out {
            if !item.ok {
                continue;
            }
            let txid = match &item.txid {
                Some(t) => t.clone(),
                None => continue,
            };

            if let Ok(Some(stx)) = app.ledger.lock().get_tx(&txid) {
                let ts_sec = stx.ts.map(|ts| ts / 1000);
                rows.push((
                    txid.clone(),
                    stx.height,
                    stx.from.clone(),
                    stx.to.clone(),
                    stx.amount,
                    stx.nonce,
                    ts_sec,
                ));
            }
        }

        if !rows.is_empty() {
            if let Err(e) = arch.record_txs_batch(&rows).await {
                error!("archive: batch write failed: {}", e);
            }
        }
    }

    (StatusCode::OK, Json(out))
}
