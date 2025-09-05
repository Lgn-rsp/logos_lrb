use crate::sigpool::filter_valid_sigs_parallel;
use crate::{dynamic_balance::DynamicBalance, ledger::Ledger, spam_guard::SpamGuard, types::*};
use crate::{phase_consensus::PhaseConsensus, phase_filters::block_passes_phase};
use anyhow::Result;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{
    broadcast,
    mpsc::{unbounded_channel, UnboundedSender},
};

// точный монотонный ts для индексации
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn env_u64(key: &str, def: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(def)
}
fn env_usize(key: &str, def: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(def)
}

#[derive(Clone)]
pub struct Engine {
    ledger: Arc<Ledger>,
    guard: SpamGuard,
    dyn_cost: DynamicBalance,
    proposer: Rid,
    mempool_tx: UnboundedSender<Tx>,
    mempool: Arc<Mutex<Vec<Tx>>>,
    commit_tx: Arc<Mutex<Option<broadcast::Sender<Block>>>>,

    slot_ms: u64,
    sig_workers: usize,
    consensus: Arc<Mutex<PhaseConsensus>>,
}

impl Engine {
    pub fn new(ledger: Ledger, proposer: Rid) -> Arc<Self> {
        let mempool_cap = env_u64("LRB_MEMPOOL_CAP", 100_000);
        let max_block_tx = env_u64("LRB_MAX_BLOCK_TX", 10_000);
        let max_amount = env_u64("LRB_MAX_AMOUNT", u64::MAX / 2);
        let slot_ms = env_u64("LRB_SLOT_MS", 500);
        let quorum_n = env_usize("LRB_QUORUM_N", 1);
        let sig_workers = env_usize("LRB_SIG_WORKERS", 4);

        let mempool: Arc<Mutex<Vec<Tx>>> = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = unbounded_channel::<Tx>();

        let engine = Arc::new(Self {
            ledger: Arc::new(ledger),
            guard: SpamGuard::new(mempool_cap as usize, max_block_tx as usize, max_amount),
            dyn_cost: DynamicBalance::new(100, 2),
            proposer,
            mempool_tx: tx.clone(),
            mempool: mempool.clone(),
            commit_tx: Arc::new(Mutex::new(None)),
            slot_ms,
            sig_workers,
            consensus: Arc::new(Mutex::new(PhaseConsensus::new(quorum_n))),
        });

        // приём транзакций в mempool с лимитами
        let guard = engine.guard.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(tx) = rx.recv().await {
                let mut lock = mempool.lock().unwrap();
                if guard.check_mempool(lock.len()).is_ok() {
                    lock.push(tx);
                }
            }
        });

        engine
    }

    pub fn ledger(&self) -> Arc<Ledger> {
        self.ledger.clone()
    }
    pub fn proposer(&self) -> Rid {
        self.proposer.clone()
    }
    pub fn set_commit_notifier(&self, sender: broadcast::Sender<Block>) {
        *self.commit_tx.lock().unwrap() = Some(sender);
    }
    pub fn check_amount_valid(&self, amount: u64) -> Result<()> {
        self.guard.check_amount(amount)
    }
    pub fn mempool_sender(&self) -> UnboundedSender<Tx> {
        self.mempool_tx.clone()
    }
    pub fn mempool_len(&self) -> usize {
        self.mempool.lock().unwrap().len()
    }
    pub fn finalized_height(&self) -> u64 {
        self.consensus.lock().unwrap().finalized()
    }

    pub fn register_vote(&self, height: u64, block_hash: &str, rid_b58: &str) -> bool {
        let mut cons = self.consensus.lock().unwrap();
        if let Some((h, voted_hash)) = cons.vote(height, block_hash, rid_b58) {
            if let Ok(local) = self.ledger.get_block_by_height(h) {
                if local.block_hash == voted_hash {
                    let _ = self.ledger.set_finalized(h);
                    return true;
                }
            }
        }
        false
    }

    pub async fn run_block_producer(self: Arc<Self>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(self.slot_ms));

        loop {
            interval.tick().await;

            // 1) забираем пачку из мемпула
            let raw = {
                let mut mp = self.mempool.lock().unwrap();
                if mp.is_empty() {
                    continue;
                }
                let take = self.guard.max_block_txs().min(mp.len());
                mp.drain(0..take).collect::<Vec<Tx>>()
            };

            // 2) проверка подписей параллельно
            let mut valid = filter_valid_sigs_parallel(raw, self.sig_workers).await;
            if valid.is_empty() {
                continue;
            }

            // 3) базовые лимиты/amount
            valid.retain(|t| self.guard.check_amount(t.amount).is_ok());
            if valid.is_empty() {
                continue;
            }

            // 4) формируем блок (h+1)
            let (h, prev_hash) = self.ledger.head().unwrap_or((0, String::new()));
            let b = Block::new(h + 1, prev_hash, self.proposer.clone(), valid);

            // 5) фазовый фильтр (резонанс). Если не прошёл — НЕ теряем tx: возвращаем в хвост mempool.
            if !block_passes_phase(&b) {
                let mut mp = self.mempool.lock().unwrap();
                mp.extend(b.txs.into_iter()); // вернуть в очередь, обработаем в следующем слоте
                continue;
            }

            // 6) атомарный коммит блока
            if let Err(e) = self.ledger.commit_block_atomic(&b) {
                // при ошибке — вернуть tx в mempool и идти дальше
                let mut mp = self.mempool.lock().unwrap();
                mp.extend(b.txs.into_iter());
                eprintln!("commit_block_atomic error at height {}: {:?}", b.height, e);
                continue;
            }

            // 7) индексирование блока для истории/эксплорера (не мешает продюсеру)
            let ts = now_ms();
            if let Err(e) = self.ledger.index_block(b.height, &b.block_hash, ts, &b.txs) {
                // индексация не должна ломать производство блоков
                eprintln!("index_block error at height {}: {:?}", b.height, e);
            }

            // 8) локальный голос и уведомление подписчикам
            let _ = self.register_vote(b.height, &b.block_hash, self.proposer.as_str());
            if let Some(tx) = self.commit_tx.lock().unwrap().as_ref() {
                let _ = tx.send(b.clone());
            }
        }
    }

    pub fn lgn_cost_microunits(&self) -> u64 {
        self.dyn_cost.lgn_cost(self.mempool_len() as usize)
    }
}

pub fn engine_with_channels(ledger: Ledger, proposer: Rid) -> (Arc<Engine>, UnboundedSender<Tx>) {
    let engine = Engine::new(ledger, proposer);
    let sender = engine.mempool_sender();
    (engine, sender)
}
