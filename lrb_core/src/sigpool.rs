use crate::phase_integrity::verify_tx_signature;
use crate::types::Tx;
use tokio::task::JoinSet;

/// Параллельная фильтрация валидных по подписи транзакций.
/// workers: количество тасков; по умолчанию 4–8 (задать через ENV в движке).
pub async fn filter_valid_sigs_parallel(txs: Vec<Tx>, workers: usize) -> Vec<Tx> {
    if txs.is_empty() {
        return txs;
    }
    let w = workers.max(1);
    let chunk = (txs.len() + w - 1) / w;
    let mut set = JoinSet::new();
    for part in txs.chunks(chunk) {
        let vec = part.to_vec();
        set.spawn(async move {
            let mut ok = Vec::with_capacity(vec.len());
            for t in vec {
                if verify_tx_signature(&t).is_ok() {
                    ok.push(t);
                }
            }
            ok
        });
    }
    let mut out = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(mut v) = res {
            out.append(&mut v);
        }
    }
    out
}
