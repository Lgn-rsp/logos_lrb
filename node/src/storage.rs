//! Узловое persistent-хранилище (sled, один Tree "kv"):
//!   accounts/<RID>                  -> JSON {balance, nonce}
//!   chain/height                    -> LE u64
//!   blocks/<height:016x>            -> JSON BlockRecord {height, ts_ms, txs}
//!   history/<RID>/<nonce:016x>      -> JSON HistoryItem {nonce, from, to, amount, height, ts_ms}
//!   economy/minted                  -> LE u64
//!   economy/burned                  -> LE u64
//!   mix/<height:016x>               -> JSON MixRecord {height, ts_ms, deltas: [(rid, i128)]}
//!
//! Комиссии v2: LRB_FEE_PER_TX (u64, по умолчанию 0) списываются с отправителя, суммируются и сжигаются.
//! PhaseMix v1: если LRB_PHASEMIX_ENABLE=1 — формируем агрегат Δ по RID и сохраняем в mix/<height>.
//!              По умолчанию fee в Δ не учитывается (LRB_PHASEMIX_INCLUDE_FEE=0).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

#[derive(Clone, Serialize, Deserialize)]
pub struct MixRecord {
    pub height: u64,
    pub ts_ms: u64,
    pub deltas: Vec<(String, i128)>, // RID -> delta (i128 для симметрии)
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
        let _ = kv.compare_and_swap(b"chain/height", None as Option<&[u8]>, Some(0u64.to_le_bytes().to_vec()))?;
        let _ = kv.compare_and_swap(b"economy/minted", None as Option<&[u8]>, Some(0u64.to_le_bytes().to_vec()))?;
        let _ = kv.compare_and_swap(b"economy/burned", None as Option<&[u8]>, Some(0u64.to_le_bytes().to_vec()))?;
        Ok(Self { db, kv })
    }

    #[inline] fn k_account(rid: &str) -> String { format!("accounts/{}", rid) }
    #[inline] fn k_block(height: u64) -> String { format!("blocks/{:016x}", height) }
    #[inline] fn k_hist(rid: &str, nonce: u64) -> String { format!("history/{}/{:016x}", rid, nonce) }
    #[inline] fn k_mix(height: u64) -> String { format!("mix/{:016x}", height) }

    #[inline] fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
    }

    // ======== Economy helpers ========
    fn read_u64(&self, key: &[u8]) -> Result<u64> {
        if let Some(v) = self.kv.get(key)? {
            let mut arr = [0u8; 8]; arr.copy_from_slice(&v[..8.min(v.len())]); Ok(u64::from_le_bytes(arr))
        } else { Ok(0) }
    }
    fn write_u64(&self, key: &[u8], val: u64) -> Result<()> { self.kv.insert(key, val.to_le_bytes().to_vec())?; Ok(()) }

    fn cap_env() -> u64 { std::env::var("LRB_SUPPLY_CAP").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(81_000_000) }
    fn fee_env() -> u64 { std::env::var("LRB_FEE_PER_TX").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) }
    fn phasemix_enabled() -> bool { std::env::var("LRB_PHASEMIX_ENABLE").ok().as_deref() == Some("1") }
    fn phasemix_include_fee() -> bool { std::env::var("LRB_PHASEMIX_INCLUDE_FEE").ok().as_deref() == Some("1") }

    pub fn economy_snapshot(&self) -> Result<EconomySnapshot> {
        let minted = self.read_u64(b"economy/minted")?;
        let burned = self.read_u64(b"economy/burned")?;
        let cap = Self::cap_env();
        let supply = minted.saturating_sub(burned);
        Ok(EconomySnapshot { cap, minted, burned, supply })
    }

    pub fn try_mint_under_cap(&self, amt: u64) -> Result<u64> {
        let cap = Self::cap_env();
        let minted = self.read_u64(b"economy/minted")?;
        let burned = self.read_u64(b"economy/burned")?;
        let supply = minted.saturating_sub(burned);
        let new_supply = supply.checked_add(amt).ok_or_else(|| anyhow!("supply overflow"))?;
        if new_supply > cap { return Err(anyhow!("supply cap exceeded: new_supply={} cap={}", new_supply, cap)); }
        let new_minted = minted.checked_add(amt).ok_or_else(|| anyhow!("minted overflow"))?;
        self.write_u64(b"economy/minted", new_minted)?;
        self.db.flush()?; Ok(new_minted)
    }

    pub fn inc_burned(&self, amt: u64) -> Result<u64> {
        if amt == 0 { return Ok(self.read_u64(b"economy/burned")?); }
        let burned = self.read_u64(b"economy/burned")?;
        let new_burn = burned.checked_add(amt).ok_or_else(|| anyhow!("burn overflow"))?;
        self.write_u64(b"economy/burned", new_burn)?;
        self.db.flush()?; Ok(new_burn)
    }

    // ======== Accounts / Faucet / Blocks / History / Mix ========
    pub fn get_account(&self, rid: &str) -> Result<AccountState> {
        if let Some(v) = self.kv.get(Self::k_account(rid).as_bytes())? {
            let st: AccountState = serde_json::from_slice(&v)?; Ok(st)
        } else { Ok(AccountState::default()) }
    }

    pub fn faucet(&self, rid: &str, amount: u64) -> Result<AccountState> {
        if amount == 0 { return Err(anyhow!("amount must be > 0")); }
        let _ = self.try_mint_under_cap(amount)?;
        let mut st = self.get_account(rid)?; st.balance = st.balance.saturating_add(amount);
        self.kv.insert(Self::k_account(rid).as_bytes(), serde_json::to_vec(&st)?)?;
        self.db.flush()?; Ok(st)
    }

    /// Применяем batch: учитываем комиссию, записываем блок/историю, формируем Mix (Δ по RID).
    pub fn apply_batch(&self, txs: &[TxIn]) -> Result<u64> {
        let fee = Self::fee_env();
        let include_fee_in_delta = Self::phasemix_include_fee();
        let mut total_fee: u64 = 0;

        let mut batch = sled::Batch::default();
        let mut acc_cache: HashMap<String, AccountState> = HashMap::new();
        let mut deltas: HashMap<String, i128> = HashMap::new(); // RID -> Δ

        for tx in txs {
            if tx.from == tx.to {
                // само-трансфер: только nonce (+ fee если задана)
                let mut from = acc_cache.remove(&tx.from).unwrap_or(self.get_account(&tx.from).unwrap_or_default());
                // комиссию списываем
                if fee > 0 {
                    if from.balance < fee { continue; }
                    from.balance = from.balance.saturating_sub(fee);
                    total_fee = total_fee.saturating_add(fee);
                    if include_fee_in_delta { *deltas.entry(tx.from.clone()).or_default() -= fee as i128; }
                }
                from.nonce = from.nonce.saturating_add(1);
                acc_cache.insert(tx.from.clone(), from);
            } else {
                let mut from = acc_cache.remove(&tx.from).unwrap_or(self.get_account(&tx.from).unwrap_or_default());
                let mut to   = acc_cache.remove(&tx.to).unwrap_or(self.get_account(&tx.to).unwrap_or_default());
                let need = tx.amount.saturating_add(fee);
                if from.balance >= need {
                    from.balance = from.balance.saturating_sub(need);
                    to.balance   = to.balance.saturating_add(tx.amount);
                    from.nonce   = from.nonce.saturating_add(1);
                    // Δ (без fee по умолчанию)
                    *deltas.entry(tx.from.clone()).or_default() -= tx.amount as i128;
                    *deltas.entry(tx.to.clone()).or_default()   += tx.amount as i128;
                    if fee > 0 {
                        total_fee = total_fee.saturating_add(fee);
                        if include_fee_in_delta {
                            *deltas.entry(tx.from.clone()).or_default() -= fee as i128;
                        }
                    }
                } else {
                    // недостаточно средств — пропускаем tx
                    continue;
                }
                acc_cache.insert(tx.from.clone(), from);
                acc_cache.insert(tx.to.clone(),   to);
            }
        }

        for (rid, st) in acc_cache.iter() {
            batch.insert(Self::k_account(rid).as_bytes(), serde_json::to_vec(st)?);
        }

        let cur_h = self.get_height()?;
        let new_h = cur_h + 1;
        let ts_ms = Self::now_ms();

        let block = BlockRecord { height: new_h, ts_ms, txs: txs.to_vec() };
        batch.insert(b"chain/height", new_h.to_le_bytes().to_vec());
        batch.insert(Self::k_block(new_h).as_bytes(), serde_json::to_vec(&block)?);

        for tx in txs {
            let item = HistoryItem { nonce: tx.nonce, from: tx.from.clone(), to: tx.to.clone(), amount: tx.amount, height: new_h, ts_ms };
            batch.insert(Self::k_hist(&tx.from, tx.nonce).as_bytes(), serde_json::to_vec(&item)?);
            batch.insert(Self::k_hist(&tx.to,   tx.nonce).as_bytes(), serde_json::to_vec(&item)?);
        }

        // Сохраняем MixRecord, если включён PhaseMix
        if Self::phasemix_enabled() {
            let mut vec: Vec<(String,i128)> = deltas.into_iter().collect();
            // отбрасываем нулевые Δ и сортируем для стабильности
            vec.retain(|(_,d)| *d != 0);
            vec.sort_by(|a,b| a.0.cmp(&b.0));
            let mix = MixRecord { height: new_h, ts_ms, deltas: vec };
            batch.insert(Self::k_mix(new_h).as_bytes(), serde_json::to_vec(&mix)?);
        }

        self.kv.apply_batch(batch)?;
        self.db.flush()?;

        if total_fee > 0 { let _ = self.inc_burned(total_fee)?; }

        Ok(new_h)
    }

    pub fn get_height(&self) -> Result<u64> {
        if let Some(v) = self.kv.get(b"chain/height")? {
            let mut arr = [0u8; 8]; arr.copy_from_slice(&v[..8.min(v.len())]); Ok(u64::from_le_bytes(arr))
        } else { Ok(0) }
    }

    pub fn get_block(&self, height: u64) -> Result<Option<BlockRecord>> {
        Ok(self.kv.get(Self::k_block(height).as_bytes())?.map(|v| serde_json::from_slice::<BlockRecord>(&v)).transpose()?)
    }

    pub fn get_mix(&self, height: u64) -> Result<Option<MixRecord>> {
        Ok(self.kv.get(Self::k_mix(height).as_bytes())?.map(|v| serde_json::from_slice::<MixRecord>(&v)).transpose()?)
    }

    pub fn history_page(&self, rid: &str, from_nonce: u64, limit: usize) -> Result<(Vec<HistoryItem>, Option<u64>)> {
        let prefix = format!("history/{}/", rid);
        let start  = format!("{}{:016x}", prefix, from_nonce);
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut last_nonce: Option<u64> = None;
        let mut iter = self.kv.range(start.as_bytes()..);
        while let Some(kv) = iter.next() {
            let (k, v) = kv?; if !k.starts_with(prefix.as_bytes()) { break; }
            let item: HistoryItem = serde_json::from_slice(&v)?; out.push(item.clone());
            last_nonce = Some(item.nonce); if out.len() >= limit { break; }
        }
        let next_from = if let Some(n) = last_nonce {
            let next_key = format!("{}{:016x}", prefix, n.saturating_add(1));
            if let Some(kv) = self.kv.range(next_key.as_bytes()..).next() {
                let (k, _) = kv?; if k.starts_with(prefix.as_bytes()) { Some(n.saturating_add(1)) } else { None }
            } else { None }
        } else { None };
        Ok((out, next_from))
    }

    pub fn history_from(&self, rid: &str, from_nonce: u64, limit: usize) -> Result<Vec<HistoryItem>> {
        Ok(self.history_page(rid, from_nonce, limit)?.0)
    }
}

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

#[derive(Serialize)]
pub struct EconomySnapshot {
    pub cap: u64,
    pub minted: u64,
    pub burned: u64,
    pub supply: u64,
}
