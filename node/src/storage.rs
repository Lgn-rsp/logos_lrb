//! Узловое persistent-хранилище (sled, один Tree "kv"):
//!   accounts/<RID>                  -> JSON {balance, nonce}
//!   chain/height                    -> LE u64
//!   blocks/<height:016x>            -> JSON BlockRecord {height, ts_ms, txs}
//!   history/<RID>/<nonce:016x>      -> JSON HistoryItem {nonce, from, to, amount, height, ts_ms}

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    pub nonce: u64,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub height: u64,
    pub ts_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    pub height: u64,
    pub ts_ms: u64,
    pub txs: Vec<TxIn>,
}

pub struct Storage {
    db: sled::Db,
    kv: sled::Tree,
}

impl Storage {
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        std::fs::create_dir_all(&path).ok();
        let db = sled::open(path)?;
        let kv = db.open_tree("kv")?;
        let _ = kv.compare_and_swap(
            b"chain/height",
            None as Option<&[u8]>,
            Some(0u64.to_le_bytes().to_vec()),
        )?;
        Ok(Self { db, kv })
    }

    #[inline]
    fn k_account(rid: &str) -> String {
        format!("accounts/{}", rid)
    }
    #[inline]
    fn k_block(height: u64) -> String {
        format!("blocks/{:016x}", height)
    }
    #[inline]
    fn k_hist(rid: &str, nonce: u64) -> String {
        format!("history/{}/{:016x}", rid, nonce)
    }

    #[inline]
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    // ------- Accounts

    pub fn get_account(&self, rid: &str) -> Result<AccountState> {
        if let Some(v) = self.kv.get(Self::k_account(rid).as_bytes())? {
            let st: AccountState = serde_json::from_slice(&v)?;
            Ok(st)
        } else {
            Ok(AccountState::default())
        }
    }

    pub fn faucet(&self, rid: &str, amount: u64) -> Result<AccountState> {
        let mut st = self.get_account(rid)?;
        st.balance = st.balance.saturating_add(amount);
        self.kv
            .insert(Self::k_account(rid).as_bytes(), serde_json::to_vec(&st)?)?;
        self.db.flush()?;
        Ok(st)
    }

    // ------- Apply batch: атомарно применяем префикс и индексируем историю+блок

    pub fn apply_batch(&self, txs: &[TxIn]) -> Result<u64> {
        let mut batch = sled::Batch::default();
        let mut acc_cache: std::collections::HashMap<String, AccountState> =
            std::collections::HashMap::new();

        for tx in txs {
            if tx.from == tx.to {
                let mut from = acc_cache
                    .remove(&tx.from)
                    .unwrap_or(self.get_account(&tx.from).unwrap_or_default());
                from.nonce = from.nonce.saturating_add(1);
                acc_cache.insert(tx.from.clone(), from);
            } else {
                let mut from = acc_cache
                    .remove(&tx.from)
                    .unwrap_or(self.get_account(&tx.from).unwrap_or_default());
                let mut to = acc_cache
                    .remove(&tx.to)
                    .unwrap_or(self.get_account(&tx.to).unwrap_or_default());

                if from.balance >= tx.amount {
                    from.balance = from.balance.saturating_sub(tx.amount);
                    to.balance = to.balance.saturating_add(tx.amount);
                }
                from.nonce = from.nonce.saturating_add(1);

                acc_cache.insert(tx.from.clone(), from);
                acc_cache.insert(tx.to.clone(), to);
            }
        }

        for (rid, st) in acc_cache.iter() {
            batch.insert(Self::k_account(rid).as_bytes(), serde_json::to_vec(st)?);
        }

        let cur_h = self.get_height()?;
        let new_h = cur_h + 1;
        let ts_ms = Self::now_ms();

        let block = BlockRecord {
            height: new_h,
            ts_ms,
            txs: txs.to_vec(),
        };
        batch.insert("chain/height".as_bytes(), new_h.to_le_bytes().to_vec());
        batch.insert(Self::k_block(new_h).as_bytes(), serde_json::to_vec(&block)?);

        for tx in txs {
            let item = HistoryItem {
                nonce: tx.nonce,
                from: tx.from.clone(),
                to: tx.to.clone(),
                amount: tx.amount,
                height: new_h,
                ts_ms,
            };
            batch.insert(
                Self::k_hist(&tx.from, tx.nonce).as_bytes(),
                serde_json::to_vec(&item)?,
            );
            batch.insert(
                Self::k_hist(&tx.to, tx.nonce).as_bytes(),
                serde_json::to_vec(&item)?,
            );
        }

        self.kv.apply_batch(batch)?;
        self.db.flush()?;
        Ok(new_h)
    }

    pub fn get_height(&self) -> Result<u64> {
        if let Some(v) = self.kv.get(b"chain/height")? {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&v[..8.min(v.len())]);
            Ok(u64::from_le_bytes(arr))
        } else {
            Ok(0)
        }
    }

    pub fn get_block(&self, height: u64) -> Result<Option<BlockRecord>> {
        Ok(self
            .kv
            .get(Self::k_block(height).as_bytes())?
            .map(|v| serde_json::from_slice::<BlockRecord>(&v))
            .transpose()?)
    }

    /// Страница истории по RID: nonce >= from_nonce, не более limit; возвращает (items, next_from)
    pub fn history_page(
        &self,
        rid: &str,
        from_nonce: u64,
        limit: usize,
    ) -> Result<(Vec<HistoryItem>, Option<u64>)> {
        let prefix = format!("history/{}/", rid);
        let start = format!("{}{:016x}", prefix, from_nonce);
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut last_nonce: Option<u64> = None;
        let mut iter = self.kv.range(start.as_bytes()..);

        while let Some(kv) = iter.next() {
            let (k, v) = kv?;
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            let item: HistoryItem = serde_json::from_slice(&v)?;
            out.push(item.clone());
            last_nonce = Some(item.nonce);
            if out.len() >= limit {
                break;
            }
        }

        let next_from = if let Some(n) = last_nonce {
            let next_key = format!("{}{:016x}", prefix, n.saturating_add(1));
            if let Some(kv) = self.kv.range(next_key.as_bytes()..).next() {
                let (k, _) = kv?;
                if k.starts_with(prefix.as_bytes()) {
                    Some(n.saturating_add(1))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok((out, next_from))
    }

    /// Старый интерфейс для совместимости
    pub fn history_from(
        &self,
        rid: &str,
        from_nonce: u64,
        limit: usize,
    ) -> Result<Vec<HistoryItem>> {
        Ok(self.history_page(rid, from_nonce, limit)?.0)
    }
}

// Входная транзакция
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct TxIn {
    pub from: String,
    pub to: String,
    pub amount: u64,
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub sig_hex: String,
}
