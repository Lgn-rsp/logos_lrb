//! Ledger — sled-backed storage (single DB open only in AppState).
//! НИКАКИХ sled::open внутри этого модуля.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, IVec, Tree};

const META_HEIGHT: &[u8]         = b"height";
const META_SUPPLY_MINTED: &[u8]  = b"supply_minted";
const META_SUPPLY_BURNED: &[u8]  = b"supply_burned";
const META_LAST_HASH: &[u8]      = b"last_block_hash";

#[derive(Clone)]
pub struct Ledger {
    pub(crate) db: Db,
    t_meta:  Tree,
    t_bal:   Tree,
    t_nonce: Tree,
    t_tx:    Tree,
    t_txidx: Tree,
    t_acctx: Tree,
    t_bmeta: Tree,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTx {
    pub txid:   String,
    pub height: u64,
    pub from:   String,
    pub to:     String,
    pub amount: u64,
    pub nonce:  u64,
    pub memo:   Option<String>,
    pub ts:     Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRec {
    pub txid:   String,
    pub height: u64,
    pub from:   String,
    pub to:     String,
    pub amount: u64,
    pub nonce:  u64,
    pub ts:     Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMeta {
    pub height:     u64,
    pub block_hash: String,
}

impl Ledger {
    /// Создать Ledger из уже ОТКРЫТОГО sled::Db (AppState отвечает за open).
    pub fn from_db(db: Db) -> Self {
        let t_meta  = db.open_tree("meta").expect("open meta");
        let t_bal   = db.open_tree("bal").expect("open bal");
        let t_nonce = db.open_tree("nonce").expect("open nonce");
        let t_tx    = db.open_tree("tx").expect("open tx");
        let t_txidx = db.open_tree("txidx").expect("open txidx");
        let t_acctx = db.open_tree("acctx").expect("open acctx");
        let t_bmeta = db.open_tree("bmeta").expect("open bmeta");

        // инициализируем дефолты
        if t_meta.get(META_HEIGHT).ok().flatten().is_none() {
            t_meta.insert(META_HEIGHT, be_u64(0).to_vec()).unwrap();
        }
        if t_meta.get(META_SUPPLY_MINTED).ok().flatten().is_none() {
            t_meta.insert(META_SUPPLY_MINTED, be_u128(0).to_vec()).unwrap();
        }
        if t_meta.get(META_SUPPLY_BURNED).ok().flatten().is_none() {
            t_meta.insert(META_SUPPLY_BURNED, be_u128(0).to_vec()).unwrap();
        }
        if t_meta.get(META_LAST_HASH).ok().flatten().is_none() {
            t_meta.insert(META_LAST_HASH, b"".to_vec()).unwrap();
        }

        Self { db, t_meta, t_bal, t_nonce, t_tx, t_txidx, t_acctx, t_bmeta }
    }

    // ===== helpers for BE conversions =====
    #[inline]
    fn from_be_u64(iv: &IVec) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(iv.as_ref());
        u64::from_be_bytes(b)
    }
    #[inline]
    fn from_be_u128(iv: &IVec) -> u128 {
        let mut b = [0u8; 16];
        b.copy_from_slice(iv.as_ref());
        u128::from_be_bytes(b)
    }

    // ===== meta/head =====
    pub fn height(&self) -> Result<u64> {
        Ok(self
            .t_meta
            .get(META_HEIGHT)?
            .map(|v| Self::from_be_u64(&v))
            .unwrap_or(0))
    }
    pub fn set_height(&self, h: u64) -> Result<()> {
        self.t_meta.insert(META_HEIGHT, be_u64(h).to_vec())?;
        Ok(())
    }
    pub fn last_block_hash(&self) -> Result<String> {
        Ok(self
            .t_meta
            .get(META_LAST_HASH)?
            .map(|v| String::from_utf8_lossy(&v).into())
            .unwrap_or_default())
    }
    pub fn set_last_block_hash(&self, s: &str) -> Result<()> {
        self.t_meta
            .insert(META_LAST_HASH, s.as_bytes().to_vec())?;
        Ok(())
    }
    pub fn head(&self) -> Result<(u64, String)> {
        Ok((self.height()?, self.last_block_hash()?))
    }

    // ===== supply =====
    pub fn supply(&self) -> Result<(u64, u64)> {
        let m = self
            .t_meta
            .get(META_SUPPLY_MINTED)?
            .map(|v| Self::from_be_u128(&v))
            .unwrap_or(0);
        let b = self
            .t_meta
            .get(META_SUPPLY_BURNED)?
            .map(|v| Self::from_be_u128(&v))
            .unwrap_or(0);
        let minted = u64::try_from(m).unwrap_or(u64::MAX);
        let burned = u64::try_from(b).unwrap_or(u64::MAX);
        Ok((minted, burned))
    }
    pub fn add_minted(&self, v: u64) -> Result<()> {
        let cur = self
            .t_meta
            .get(META_SUPPLY_MINTED)?
            .map(|iv| Self::from_be_u128(&iv))
            .unwrap_or(0);
        self.t_meta.insert(
            META_SUPPLY_MINTED,
            be_u128(cur.saturating_add(v as u128)).to_vec(),
        )?;
        Ok(())
    }
    pub fn add_burned(&self, v: u64) -> Result<()> {
        let cur = self
            .t_meta
            .get(META_SUPPLY_BURNED)?
            .map(|iv| Self::from_be_u128(&iv))
            .unwrap_or(0);
        self.t_meta.insert(
            META_SUPPLY_BURNED,
            be_u128(cur.saturating_add(v as u128)).to_vec(),
        )?;
        Ok(())
    }

    // ===== balances / nonce =====
    pub fn get_balance(&self, rid: &str) -> Result<u128> {
        Ok(self
            .t_bal
            .get(rid.as_bytes())?
            .map(|v| Self::from_be_u128(&v))
            .unwrap_or(0))
    }
    pub fn set_balance(&self, rid: &str, value: u128) -> Result<()> {
        self.t_bal
            .insert(rid.as_bytes(), be_u128(value).to_vec())?;
        Ok(())
    }
    pub fn get_nonce(&self, rid: &str) -> Result<u64> {
        Ok(self
            .t_nonce
            .get(rid.as_bytes())?
            .map(|v| Self::from_be_u64(&v))
            .unwrap_or(0))
    }
    pub fn bump_nonce(&self, rid: &str) -> Result<u64> {
        let n = self.get_nonce(rid)?.saturating_add(1);
        self.t_nonce
            .insert(rid.as_bytes(), be_u64(n).to_vec())?;
        Ok(n)
    }
    pub fn set_nonce(&self, rid: &str, value: u64) -> Result<()> {
        self.t_nonce
            .insert(rid.as_bytes(), be_u64(value).to_vec())?;
        Ok(())
    }

    // ===== tx fetch/index =====
    pub fn get_tx(&self, txid: &str) -> Result<Option<StoredTx>> {
        Ok(self
            .t_tx
            .get(txid.as_bytes())?
            .map(|v| serde_json::from_slice(&v))
            .transpose()?)
    }
    pub fn get_tx_height(&self, txid: &str) -> Result<Option<u64>> {
        Ok(self
            .t_txidx
            .get(txid.as_bytes())?
            .map(|v| Self::from_be_u64(&v)))
    }

    /// История аккаунта постранично. Делает scan_prefix по `rid|`.
    pub fn account_txs_page(
        &self,
        rid: &str,
        page: u32,
        per_page: u32,
    ) -> Result<Vec<TxRec>> {
        let per = per_page.clamp(1, 1000) as usize;
        let mut keys: Vec<IVec> = Vec::new();
        for item in self.t_acctx.scan_prefix(rid.as_bytes()) {
            let (k, _) = item?;
            keys.push(k);
        }
        keys.sort_unstable(); // <rid>|<BE height>|<txid>
        let start = (page as usize).saturating_mul(per);
        let end = (start + per).min(keys.len());

        let mut out = Vec::with_capacity(end.saturating_sub(start));
        for k in keys.get(start..end).unwrap_or(&[]) {
            if let Some(pos) = k.as_ref().iter().rposition(|&b| b == b'|') {
                let txid =
                    std::str::from_utf8(&k.as_ref()[pos + 1..]).unwrap_or_default();
                if let Some(stx) = self.get_tx(txid)? {
                    out.push(TxRec {
                        txid: stx.txid.clone(),
                        height: stx.height,
                        from: stx.from,
                        to: stx.to,
                        amount: stx.amount,
                        nonce: stx.nonce,
                        ts: stx.ts,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Простой submit (DEMO): проверка баланса/nonce, применение, индексация.
    pub fn submit_tx_simple(
        &self,
        from: &str,
        to: &str,
        amount: u64,
        nonce: u64,
        memo: Option<&str>,
    ) -> Result<StoredTx> {
        let fb = self.get_balance(from)?;
        if fb < amount as u128 {
            return Err(anyhow!("insufficient_funds"));
        }
        let n = self.get_nonce(from)?;
        if n + 1 != nonce {
            return Err(anyhow!("bad_nonce"));
        }

        self.set_balance(from, fb - amount as u128)?;
        self.set_balance(
            to,
            self.get_balance(to)?.saturating_add(amount as u128),
        )?;
        self.set_nonce(from, nonce)?;

        let h = self.height()?.saturating_add(1);
        self.set_height(h)?;

        // txid = sha256(from|to|amount|nonce|ts)
        let ts = Some(unix_ts());
        let mut hasher = Sha256::new();
        hasher.update(from.as_bytes());
        hasher.update(b"|");
        hasher.update(to.as_bytes());
        hasher.update(b"|");
        hasher.update(&amount.to_be_bytes());
        hasher.update(b"|");
        hasher.update(&nonce.to_be_bytes());
        if let Some(t) = ts {
            hasher.update(&t.to_be_bytes());
        }
        let txid = hex::encode(hasher.finalize());

        let stx = StoredTx {
            txid: txid.clone(),
            height: h,
            from: from.to_string(),
            to: to.to_string(),
            amount,
            nonce,
            memo: memo.map(|s| s.to_string()),
            ts,
        };

        self.t_tx
            .insert(txid.as_bytes(), serde_json::to_vec(&stx)?)?;
        self.t_txidx
            .insert(txid.as_bytes(), be_u64(h).to_vec())?;

        // индекс по аккаунтам: <rid>|<BE height>|<txid>
        let mut kf =
            Vec::with_capacity(from.len() + 1 + 8 + 1 + txid.len());
        kf.extend_from_slice(from.as_bytes());
        kf.push(b'|');
        kf.extend_from_slice(&be_u64(h));
        kf.push(b'|');
        kf.extend_from_slice(txid.as_bytes());
        self.t_acctx.insert(kf, &[])?;

        let mut kt =
            Vec::with_capacity(to.len() + 1 + 8 + 1 + txid.len());
        kt.extend_from_slice(to.as_bytes());
        kt.push(b'|');
        kt.extend_from_slice(&be_u64(h));
        kt.push(b'|');
        kt.extend_from_slice(txid.as_bytes());
        self.t_acctx.insert(kt, &[])?;

        // минимальный BlockMeta (если нужно — обогащаем)
        let meta = BlockMeta {
            height: h,
            block_hash: self.last_block_hash().unwrap_or_default(),
        };
        self.t_bmeta
            .insert(be_u64(h).to_vec(), bincode::serialize(&meta).unwrap())?;

        Ok(stx)
    }

    pub fn get_block_by_height(&self, h: u64) -> Result<BlockMeta> {
        if let Some(v) = self.t_bmeta.get(be_u64(h))? {
            Ok(bincode::deserialize(&v)?)
        } else {
            Err(anyhow!("block_meta_not_found"))
        }
    }

    pub fn set_finalized(&self, _h: u64) -> Result<()> {
        Ok(())
    }

    // ====== заглушки для rcp_engine (совместимость API), делаем no-op ======
    pub fn commit_block_atomic<T>(&self, _b: &T) -> Result<()> {
        Ok(())
    }
    pub fn index_block<T, S>(
        &self,
        _h: u64,
        _block_hash: &str,
        _ts: S,
        _txs: &T,
    ) -> Result<()> {
        Ok(())
    }
}

// ===== little helpers =====
#[inline]
fn be_u64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}
#[inline]
fn be_u128(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

#[inline]
fn unix_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
