# LOGOS Block Producer Snapshot

_Автогенерация: `2025-11-30 09:53:35Z`_


## LRB Core (ledger, mempool, engine, block producer)

`/root/logos_lrb/lrb_core`


---

### `/root/logos_lrb/lrb_core/Cargo.toml`

```toml
[package]
name = "lrb_core"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
bytes = { workspace = true }

# крипто/кодеки/идентификаторы
ring = { workspace = true }
rand = { workspace = true }
ed25519-dalek = { workspace = true }
sha2 = { workspace = true }
blake3 = { workspace = true }
hex = { workspace = true }
base64 = { workspace = true }
bs58 = { workspace = true }
uuid = { workspace = true }
bincode = { workspace = true }

# хранилище/сеть/асинхрон
sled = { workspace = true }
reqwest = { workspace = true }
tokio = { workspace = true }

```

---

### `/root/logos_lrb/lrb_core/src/anti_replay.rs`

```rust
use std::collections::HashMap;

/// Простейшее TTL-окно: tag -> last_seen_ms
#[derive(Clone, Debug)]
pub struct AntiReplayWindow {
    ttl_ms: u128,
    map: HashMap<String, u128>,
}

impl AntiReplayWindow {
    pub fn new(ttl_ms: u128) -> Self {
        Self {
            ttl_ms,
            map: HashMap::new(),
        }
    }

    /// true, если новый (вставлен), false — если повтор/просрочен
    pub fn check_and_insert(&mut self, tag: String, now_ms: u128) -> bool {
        // Чистка "по ходу"
        self.gc(now_ms);
        if let Some(&seen) = self.map.get(&tag) {
            if now_ms.saturating_sub(seen) <= self.ttl_ms {
                return false; // повтор
            }
        }
        self.map.insert(tag, now_ms);
        true
    }

    pub fn gc(&mut self, now_ms: u128) {
        let ttl = self.ttl_ms;
        self.map.retain(|_, &mut t| now_ms.saturating_sub(t) <= ttl);
    }
}

```

---

### `/root/logos_lrb/lrb_core/src/beacon.rs`

```rust
use crate::types::Rid;
use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tokio::time::interval;

#[derive(Serialize)]
struct BeatPayload<'a> {
    rid: &'a str,
    ts_ms: u128,
}

pub async fn run_beacon(rid: Rid, peers: Vec<String>, period: Duration) -> Result<()> {
    if peers.is_empty() {
        // Нечего слать — просто спим, чтобы не грузить CPU
        let mut t = interval(period);
        loop {
            t.tick().await;
        }
    }
    let client = Client::new();
    let mut t = interval(period);
    loop {
        t.tick().await;
        let payload = BeatPayload {
            rid: rid.as_str(),
            ts_ms: crate::heartbeat::now_ms(),
        };
        let body = serde_json::to_vec(&payload)?;
        for p in &peers {
            // POST {peer}/beat
            let url = format!("{}/beat", p.trim_end_matches('/'));
            let req = client
                .post(&url)
                .header("content-type", "application/json")
                .body(body.clone())
                .build()?;
            if let Err(e) = client.execute(req).await {
                // Не падаем — идём к следующему
                let _ = e;
            }
        }
    }
}

/// Парсинг переменной окружения вида: "http://ip1:8080,http://ip2:8080"
pub fn parse_peers(env_val: &str) -> Result<Vec<String>> {
    let peers: Vec<String> = env_val
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if peers
        .iter()
        .any(|p| !(p.starts_with("http://") || p.starts_with("https://")))
    {
        return Err(anyhow!("peer must start with http(s)://"));
    }
    Ok(peers)
}

```

---

### `/root/logos_lrb/lrb_core/src/crypto.rs`

```rust
//! Безопасные AEAD-примитивы с уникальным nonce per message.
//! Использование:
//!   let (ct, nonce) = seal_aes_gcm(&key32, aad, &plain)?;
//!   let pt = open_aes_gcm(&key32, aad, nonce, &ct)?;

use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

/// 96-битный nonce для AES-GCM (RFC 5116). Генерируется на каждое сообщение.
#[derive(Clone, Copy, Debug)]
pub struct Nonce96(pub [u8; 12]);

impl Nonce96 {
    #[inline]
    pub fn random() -> Self {
        let mut n = [0u8; 12];
        OsRng.fill_bytes(&mut n);
        Self(n)
    }
}

/// Шифрование AES-256-GCM: возвращает (ciphertext||tag, nonce)
pub fn seal_aes_gcm(key32: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key32)
        .map_err(|e| anyhow!("ring UnboundKey::new failed: {:?}", e))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce96::random();

    let mut inout = plaintext.to_vec();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce.0), Aad::from(aad), &mut inout)
        .map_err(|_| anyhow!("AEAD seal failed"))?;
    Ok((inout, nonce.0))
}

/// Расшифрование AES-256-GCM: принимает nonce и (ciphertext||tag)
pub fn open_aes_gcm(key32: &[u8; 32], aad: &[u8], nonce: [u8; 12], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key32)
        .map_err(|e| anyhow!("ring UnboundKey::new failed: {:?}", e))?;
    let key = LessSafeKey::new(unbound);

    let mut buf = ciphertext_and_tag.to_vec();
    let plain = key
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)
        .map_err(|_| anyhow!("AEAD open failed"))?;
    Ok(plain.to_vec())
}

```

---

### `/root/logos_lrb/lrb_core/src/dynamic_balance.rs`

```rust
// Простейшая адаптация LGN_cost: основана на длине мемпула.
#[derive(Clone, Debug)]
pub struct DynamicBalance {
    base_cost_microunits: u64, // 1e-6 LGN
    slope_per_tx: u64,         // увеличение за каждую tx в мемпуле
}

impl DynamicBalance {
    pub fn new(base: u64, slope: u64) -> Self {
        Self {
            base_cost_microunits: base,
            slope_per_tx: slope,
        }
    }
    pub fn lgn_cost(&self, mempool_len: usize) -> u64 {
        self.base_cost_microunits + (self.slope_per_tx * mempool_len as u64)
    }
}

```

---

### `/root/logos_lrb/lrb_core/src/heartbeat.rs`

```rust
use crate::types::Rid;
use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::interval;

#[derive(Clone, Debug)]
pub struct HeartbeatState {
    pub last_seen_ms: u128,
}

#[derive(Clone)]
pub struct Heartbeat {
    inner: Arc<Mutex<HashMap<Rid, HeartbeatState>>>,
    quarantined: Arc<Mutex<HashSet<Rid>>>,
    quarantine_after_ms: u128,
    check_every_ms: u64,
}

impl Heartbeat {
    pub fn new(quarantine_after: Duration, check_every: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            quarantined: Arc::new(Mutex::new(HashSet::new())),
            quarantine_after_ms: quarantine_after.as_millis(),
            check_every_ms: check_every.as_millis() as u64,
        }
    }

    pub fn register_beat(&self, rid: Rid, now_ms: u128) {
        let mut map = self.inner.lock().unwrap();
        map.insert(
            rid,
            HeartbeatState {
                last_seen_ms: now_ms,
            },
        );
    }

    pub fn is_quarantined(&self, rid: &Rid) -> bool {
        self.quarantined.lock().unwrap().contains(rid)
    }

    pub fn peers_snapshot(&self) -> Vec<(Rid, u128)> {
        let map = self.inner.lock().unwrap();
        map.iter()
            .map(|(r, s)| (r.clone(), s.last_seen_ms))
            .collect()
    }

    pub async fn run_monitor(self) -> Result<()> {
        let mut tick = interval(Duration::from_millis(self.check_every_ms));
        loop {
            tick.tick().await;
            let now_ms = now_ms();
            let mut q = self.quarantined.lock().unwrap();
            let map = self.inner.lock().unwrap();
            for (rid, st) in map.iter() {
                let silent = now_ms.saturating_sub(st.last_seen_ms);
                if silent > self.quarantine_after_ms {
                    q.insert(rid.clone());
                } else {
                    q.remove(rid);
                }
            }
        }
    }
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

```

---

### `/root/logos_lrb/lrb_core/src/ledger.rs`

```rust
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
    #[inline] fn from_be_u64(iv: &IVec) -> u64   { let mut b=[0u8;8];  b.copy_from_slice(iv.as_ref());  u64::from_be_bytes(b) }
    #[inline] fn from_be_u128(iv: &IVec) -> u128 { let mut b=[0u8;16]; b.copy_from_slice(iv.as_ref()); u128::from_be_bytes(b) }

    // ===== meta/head =====
    pub fn height(&self) -> Result<u64> {
        Ok(self.t_meta.get(META_HEIGHT)?.map(|v| Self::from_be_u64(&v)).unwrap_or(0))
    }
    pub fn set_height(&self, h: u64) -> Result<()> {
        self.t_meta.insert(META_HEIGHT, be_u64(h).to_vec())?; Ok(())
    }
    pub fn last_block_hash(&self) -> Result<String> {
        Ok(self.t_meta.get(META_LAST_HASH)?.map(|v| String::from_utf8_lossy(&v).into()).unwrap_or_default())
    }
    pub fn set_last_block_hash(&self, s: &str) -> Result<()> {
        self.t_meta.insert(META_LAST_HASH, s.as_bytes().to_vec())?; Ok(())
    }
    pub fn head(&self) -> Result<(u64, String)> { Ok((self.height()?, self.last_block_hash()?)) }

    // ===== supply =====
    pub fn supply(&self) -> Result<(u64, u64)> {
        let m = self.t_meta.get(META_SUPPLY_MINTED)?.map(|v| Self::from_be_u128(&v)).unwrap_or(0);
        let b = self.t_meta.get(META_SUPPLY_BURNED)?.map(|v| Self::from_be_u128(&v)).unwrap_or(0);
        let minted  = u64::try_from(m).unwrap_or(u64::MAX);
        let burned  = u64::try_from(b).unwrap_or(u64::MAX);
        Ok((minted, burned))
    }
    pub fn add_minted(&self, v: u64) -> Result<()> {
        let cur = self.t_meta.get(META_SUPPLY_MINTED)?.map(|iv| Self::from_be_u128(&iv)).unwrap_or(0);
        self.t_meta.insert(META_SUPPLY_MINTED, be_u128(cur.saturating_add(v as u128)).to_vec())?;
        Ok(())
    }
    pub fn add_burned(&self, v: u64) -> Result<()> {
        let cur = self.t_meta.get(META_SUPPLY_BURNED)?.map(|iv| Self::from_be_u128(&iv)).unwrap_or(0);
        self.t_meta.insert(META_SUPPLY_BURNED, be_u128(cur.saturating_add(v as u128)).to_vec())?;
        Ok(())
    }

    // ===== balances / nonce =====
    pub fn get_balance(&self, rid: &str) -> Result<u128> {
        Ok(self.t_bal.get(rid.as_bytes())?.map(|v| Self::from_be_u128(&v)).unwrap_or(0))
    }
    pub fn set_balance(&self, rid: &str, value: u128) -> Result<()> {
        self.t_bal.insert(rid.as_bytes(), be_u128(value).to_vec())?; Ok(())
    }
    pub fn get_nonce(&self, rid: &str) -> Result<u64> {
        Ok(self.t_nonce.get(rid.as_bytes())?.map(|v| Self::from_be_u64(&v)).unwrap_or(0))
    }
    pub fn bump_nonce(&self, rid: &str) -> Result<u64> {
        let n = self.get_nonce(rid)?.saturating_add(1);
        self.t_nonce.insert(rid.as_bytes(), be_u64(n).to_vec())?;
        Ok(n)
    }
    pub fn set_nonce(&self, rid: &str, value: u64) -> Result<()> {
        self.t_nonce.insert(rid.as_bytes(), be_u64(value).to_vec())?; Ok(())
    }

    // ===== tx fetch/index =====
    pub fn get_tx(&self, txid: &str) -> Result<Option<StoredTx>> {
        Ok(self.t_tx.get(txid.as_bytes())?
            .map(|v| serde_json::from_slice(&v))
            .transpose()?)
    }
    pub fn get_tx_height(&self, txid: &str) -> Result<Option<u64>> {
        Ok(self.t_txidx.get(txid.as_bytes())?.map(|v| Self::from_be_u64(&v)))
    }

    /// История аккаунта постранично. Делает scan_prefix по `rid|`.
    pub fn account_txs_page(&self, rid: &str, page: u32, per_page: u32) -> Result<Vec<TxRec>> {
        let per = per_page.clamp(1, 1000) as usize;
        let mut keys: Vec<IVec> = Vec::new();
        for item in self.t_acctx.scan_prefix(rid.as_bytes()) {
            let (k, _) = item?;
            keys.push(k);
        }
        keys.sort_unstable();                 // <rid>|<BE height>|<txid>
        let start = (page as usize).saturating_mul(per);
        let end   = (start + per).min(keys.len());

        let mut out = Vec::with_capacity(end.saturating_sub(start));
        for k in keys.get(start..end).unwrap_or(&[]) {
            if let Some(pos) = k.as_ref().iter().rposition(|&b| b == b'|') {
                let txid = std::str::from_utf8(&k.as_ref()[pos+1..]).unwrap_or_default();
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
    pub fn submit_tx_simple(&self, from: &str, to: &str, amount: u64, nonce: u64, memo: Option<&str>) -> Result<StoredTx> {
        let fb = self.get_balance(from)?;
        if fb < amount as u128 { return Err(anyhow!("insufficient_funds")); }
        let n = self.get_nonce(from)?;
        if n + 1 != nonce { return Err(anyhow!("bad_nonce")); }

        self.set_balance(from, fb - amount as u128)?;
        self.set_balance(to,   self.get_balance(to)?.saturating_add(amount as u128))?;
        self.set_nonce(from, nonce)?;

        let h = self.height()?.saturating_add(1);
        self.set_height(h)?;

        // txid = sha256(from|to|amount|nonce|ts)
        let ts  = Some(unix_ts());
        let mut hasher = Sha256::new();
        hasher.update(from.as_bytes()); hasher.update(b"|");
        hasher.update(to.as_bytes());   hasher.update(b"|");
        hasher.update(&amount.to_be_bytes()); hasher.update(b"|");
        hasher.update(&nonce.to_be_bytes());
        if let Some(t) = ts { hasher.update(&t.to_be_bytes()); }
        let txid = hex::encode(hasher.finalize());

        let stx = StoredTx {
            txid: txid.clone(), height: h,
            from: from.to_string(), to: to.to_string(),
            amount, nonce, memo: memo.map(|s| s.to_string()), ts,
        };

        self.t_tx.insert(txid.as_bytes(), serde_json::to_vec(&stx)?)?;
        self.t_txidx.insert(txid.as_bytes(), be_u64(h).to_vec())?;

        // индекс по аккаунтам: <rid>|<BE height>|<txid>
        let mut kf = Vec::with_capacity(from.len() + 1 + 8 + 1 + txid.len());
        kf.extend_from_slice(from.as_bytes()); kf.push(b'|'); kf.extend_from_slice(&be_u64(h)); kf.push(b'|'); kf.extend_from_slice(txid.as_bytes());
        self.t_acctx.insert(kf, &[])?;

        let mut kt = Vec::with_capacity(to.len() + 1 + 8 + 1 + txid.len());
        kt.extend_from_slice(to.as_bytes());   kt.push(b'|'); kt.extend_from_slice(&be_u64(h)); kt.push(b'|'); kt.extend_from_slice(txid.as_bytes());
        self.t_acctx.insert(kt, &[])?;

        // минимальный BlockMeta (если нужно — обогащаем)
        let meta = BlockMeta { height: h, block_hash: self.last_block_hash().unwrap_or_default() };
        self.t_bmeta.insert(be_u64(h).to_vec(), bincode::serialize(&meta).unwrap())?;

        Ok(stx)
    }

    pub fn get_block_by_height(&self, h: u64) -> Result<BlockMeta> {
        if let Some(v) = self.t_bmeta.get(be_u64(h))? {
            Ok(bincode::deserialize(&v)?)
        } else {
            Err(anyhow!("block_meta_not_found"))
        }
    }

    pub fn set_finalized(&self, _h: u64) -> Result<()> { Ok(()) }

    // ====== заглушки для rcp_engine (совместимость API), делаем no-op ======
    pub fn commit_block_atomic<T>(&self, _b: &T) -> Result<()> { Ok(()) }
    pub fn index_block<T, S>(&self, _h: u64, _block_hash: &str, _ts: S, _txs: &T) -> Result<()> { Ok(()) }
}

// ===== little helpers =====
#[inline] fn be_u64(v: u64) -> [u8; 8]   { v.to_be_bytes() }
#[inline] fn be_u128(v: u128) -> [u8;16] { v.to_be_bytes() }

#[inline]
fn unix_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

```

---

### `/root/logos_lrb/lrb_core/src/lib.rs`

```rust
/*!
 * LOGOS LRB — core crate
 * Экспорт модулей ядра L1: типы, консенсус, мемпул/баланс, резонанс, сигналы, защита.
 * Здесь только декларация модулей — реализация в соответствующих *.rs файлах.
 */

pub mod types;

pub mod anti_replay;
pub mod beacon;
pub mod heartbeat;

pub mod dynamic_balance;
pub mod spam_guard;

pub mod phase_consensus;
pub mod phase_filters;
pub mod phase_integrity;
pub mod quorum;
pub mod sigpool;

pub mod ledger;
pub mod rcp_engine;
pub mod resonance;

// Безопасный AEAD (XChaCha20-Poly1305) — общий хелпер для модулей
pub mod crypto;

```

---

### `/root/logos_lrb/lrb_core/src/phase_consensus.rs`

```rust
use std::collections::{HashMap, HashSet};

/// Фазовый консенсус Σ(t) с учётом блока (height, block_hash).
/// Накапливает голоса RID'ов по конкретному хешу блока.
/// Финализованный height повышается, когда кворум собран по **одному** хешу на этом height.
pub struct PhaseConsensus {
    /// votes[height][block_hash] = {rid_b58, ...}
    votes: HashMap<u64, HashMap<String, HashSet<String>>>,
    finalized_h: u64,
    quorum_n: usize,
}

impl PhaseConsensus {
    pub fn new(quorum_n: usize) -> Self {
        Self {
            votes: HashMap::new(),
            finalized_h: 0,
            quorum_n,
        }
    }

    pub fn quorum_n(&self) -> usize {
        self.quorum_n
    }
    pub fn finalized(&self) -> u64 {
        self.finalized_h
    }

    /// Регистрируем голос. Возвращает Some((h,hash)) если по hash достигнут кворум.
    pub fn vote(&mut self, h: u64, block_hash: &str, rid_b58: &str) -> Option<(u64, String)> {
        let by_hash = self.votes.entry(h).or_default();
        let set = by_hash.entry(block_hash.to_string()).or_default();
        set.insert(rid_b58.to_string());
        if set.len() >= self.quorum_n {
            if h > self.finalized_h {
                self.finalized_h = h;
            }
            return Some((h, block_hash.to_string()));
        }
        None
    }

    /// Сколько голосов у конкретного (h,hash)
    #[allow(dead_code)]
    pub fn votes_for(&self, h: u64, block_hash: &str) -> usize {
        self.votes
            .get(&h)
            .and_then(|m| m.get(block_hash))
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

```

---

### `/root/logos_lrb/lrb_core/src/phase_filters.rs`

```rust
use crate::types::Block;

/// Простые фазовые фильтры на основе гармоник Λ0.
/// ENV (всё опционально):
///  LRB_PHASE_EN=1|0                     (вкл/выкл, по умолчанию 1)
///  LRB_PHASE_FREQS_HZ="7.83,1.618,432"  (частоты, через запятую)
///  LRB_PHASE_MIN_SCORE=-0.20            (порог принятия от -1.0 до 1.0)
///
/// Идея: время блока b.timestamp_ms в секундах подаётся в сумму косинусов.
/// score = avg_i cos(2π f_i * t)
/// Пропускаем, если score >= MIN_SCORE.
fn phase_enabled() -> bool {
    std::env::var("LRB_PHASE_EN")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(true)
}
fn parse_freqs() -> Vec<f64> {
    let def = "7.83,1.618,432";
    let raw = std::env::var("LRB_PHASE_FREQS_HZ").unwrap_or_else(|_| def.to_string());
    raw.split(',')
        .filter_map(|s| s.trim().parse::<f64>().ok())
        .collect::<Vec<_>>()
}
fn min_score() -> f64 {
    std::env::var("LRB_PHASE_MIN_SCORE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(-0.20)
}

fn phase_score_ts_ms(ts_ms: u128) -> f64 {
    let t = ts_ms as f64 / 1000.0;
    let freqs = parse_freqs();
    if freqs.is_empty() {
        return 1.0;
    }
    let two_pi = std::f64::consts::TAU; // 2π
    let mut acc = 0.0;
    for f in &freqs {
        acc += (two_pi * *f * t).cos();
    }
    acc / (freqs.len() as f64)
}

/// Главный фильтр на блок: пропускает, если фазовый скор >= порога
pub fn block_passes_phase(b: &Block) -> bool {
    if !phase_enabled() {
        return true;
    }
    phase_score_ts_ms(b.timestamp_ms) >= min_score()
}

```

---

### `/root/logos_lrb/lrb_core/src/phase_integrity.rs`

```rust
use crate::types::*;
use anyhow::{anyhow, Result};
use ed25519_dalek::Verifier as _; // для pk.verify(&msg, &sig)

pub fn verify_tx_signature(tx: &Tx) -> Result<()> {
    tx.validate_shape()?;

    let pk = crate::types::parse_pubkey(&tx.public_key)?;
    let sig = crate::types::parse_sig(&tx.signature)?;
    let msg = tx.canonical_bytes();

    pk.verify(&msg, &sig)
        .map_err(|e| anyhow!("bad signature: {e}"))?;

    // сверяем id
    if tx.id != tx.compute_id() {
        return Err(anyhow!("tx id mismatch"));
    }
    Ok(())
}

```

---

### `/root/logos_lrb/lrb_core/src/quorum.rs`

```rust
use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Голос за блок (по Σ-дайджесту)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub block_hash: String,
    pub sigma_hex: String,
    pub voter_pk_b58: String,
    pub sig_b64: String,
    pub nonce_ms: u128,
}

pub fn verify_vote(v: &Vote) -> Result<()> {
    let pk_bytes = bs58::decode(&v.voter_pk_b58).into_vec()?;
    let vk =
        VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow::anyhow!("bad pk"))?)?;
    let sig_bytes = B64.decode(v.sig_b64.as_bytes())?;
    let sig = Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad sig"))?,
    );

    let mut payload = Vec::new();
    payload.extend_from_slice(v.sigma_hex.as_bytes());
    payload.extend_from_slice(v.block_hash.as_bytes());
    payload.extend_from_slice(&v.height.to_le_bytes());
    payload.extend_from_slice(&v.nonce_ms.to_le_bytes());

    vk.verify(&payload, &sig)
        .map_err(|e| anyhow::anyhow!("verify failed: {e}"))?;
    Ok(())
}

```

---

### `/root/logos_lrb/lrb_core/src/rcp_engine.rs`

```rust
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

```

---

### `/root/logos_lrb/lrb_core/src/resonance.rs`

```rust
use crate::types::{Block, Tx};
use blake3::Hasher;

/// Гармоники Λ0/Σ(t) — фиксированное «зерно» резонанса.
const HARMONICS: &[&[u8]] = &[
    b"f1=7.83Hz",
    b"f2=1.618Hz",
    b"f3=432Hz",
    b"f4=864Hz",
    b"f5=3456Hz",
    b"L0=LOGOS-PRIME",
];

fn mix_tx(hasher: &mut Hasher, tx: &Tx) {
    // Канон: id + from + to + amount + nonce + pk
    hasher.update(tx.id.as_bytes());
    hasher.update(tx.from.0.as_bytes());
    hasher.update(tx.to.0.as_bytes());
    hasher.update(&tx.amount.to_le_bytes());
    hasher.update(&tx.nonce.to_le_bytes());
    hasher.update(&tx.public_key);
}

/// Σ-дайджест блока (hex), детерминированный и инвариантный.
pub fn sigma_digest_block_hex(b: &Block) -> String {
    let mut h = Hasher::new();
    for tag in HARMONICS {
        h.update(tag);
    }
    h.update(b.prev_hash.as_bytes());
    h.update(b.proposer.0.as_bytes());
    h.update(&b.height.to_le_bytes());
    h.update(&b.timestamp_ms.to_le_bytes());
    for tx in &b.txs {
        mix_tx(&mut h, tx)
    }
    hex::encode(h.finalize().as_bytes())
}

```

---

### `/root/logos_lrb/lrb_core/src/sigpool.rs`

```rust
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

```

---

### `/root/logos_lrb/lrb_core/src/spam_guard.rs`

```rust
use anyhow::{anyhow, Result};

#[derive(Clone, Debug)]
pub struct SpamGuard {
    max_mempool: usize,
    max_tx_per_block: usize,
    max_amount: u64,
}

impl SpamGuard {
    pub fn new(max_mempool: usize, max_tx_per_block: usize, max_amount: u64) -> Self {
        Self {
            max_mempool,
            max_tx_per_block,
            max_amount,
        }
    }
    pub fn check_mempool(&self, cur_len: usize) -> Result<()> {
        if cur_len > self.max_mempool {
            return Err(anyhow!("mempool overflow"));
        }
        Ok(())
    }
    pub fn check_amount(&self, amount: u64) -> Result<()> {
        if amount == 0 || amount > self.max_amount {
            return Err(anyhow!("amount out of bounds"));
        }
        Ok(())
    }
    pub fn max_block_txs(&self) -> usize {
        self.max_tx_per_block
    }
}

```

---

### `/root/logos_lrb/lrb_core/src/types.rs`

```rust
use anyhow::{anyhow, Result};
use blake3::Hasher;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// base64 v0.22 Engine API
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

pub type Amount = u64;
pub type Height = u64;
pub type Nonce = u64;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Rid(pub String); // base58(VerifyingKey)

impl Rid {
    pub fn from_pubkey(pk: &VerifyingKey) -> Self {
        Rid(bs58::encode(pk.to_bytes()).into_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub id: String, // blake3 of canonical form
    pub from: Rid,  // base58(pubkey)
    pub to: Rid,
    pub amount: Amount,
    pub nonce: Nonce,
    pub public_key: Vec<u8>, // 32 bytes (VerifyingKey)
    pub signature: Vec<u8>,  // 64 bytes (Signature)
}

impl Tx {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Без id и signature для детерминированного хеша
        let m = serde_json::json!({
            "from": self.from.as_str(),
            "to": self.to.as_str(),
            "amount": self.amount,
            "nonce": self.nonce,
            "public_key": B64.encode(&self.public_key),
        });
        serde_json::to_vec(&m).expect("canonical json")
    }
    pub fn compute_id(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.canonical_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }
    pub fn validate_shape(&self) -> Result<()> {
        if self.public_key.len() != 32 {
            return Err(anyhow!("bad pubkey len"));
        }
        if self.signature.len() != 64 {
            return Err(anyhow!("bad signature len"));
        }
        if self.amount == 0 {
            return Err(anyhow!("amount must be > 0"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub height: Height,
    pub prev_hash: String,
    pub timestamp_ms: u128,
    pub proposer: Rid,
    pub txs: Vec<Tx>,
    pub block_hash: String,
    pub uuid: String, // для логов
}

impl Block {
    pub fn new(height: Height, prev_hash: String, proposer: Rid, txs: Vec<Tx>) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let mut h = Hasher::new();
        h.update(prev_hash.as_bytes());
        h.update(proposer.as_str().as_bytes());
        for tx in &txs {
            h.update(tx.id.as_bytes());
        }
        h.update(&ts.to_le_bytes());
        let block_hash = hex::encode(h.finalize().as_bytes());
        Block {
            height,
            prev_hash,
            timestamp_ms: ts,
            proposer,
            txs,
            block_hash,
            uuid: Uuid::new_v4().to_string(),
        }
    }
}

pub fn parse_pubkey(pk: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = pk.try_into().map_err(|_| anyhow!("bad pubkey len"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

pub fn parse_sig(sig: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = sig.try_into().map_err(|_| anyhow!("bad signature len"))?;
    Ok(Signature::from_bytes(&arr))
}

```

## Node (REST, producer loop, archive, metrics)

`/root/logos_lrb/node`


---

### `/root/logos_lrb/node/build.rs`

```rust
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    // Короткий git hash
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else { None })
        .unwrap_or_else(|| "unknown".into());

    // Текущая ветка
    let git_branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else { None })
        .unwrap_or_else(|| "unknown".into());

    // Время сборки (UTC, RFC3339)
    let ts = chrono::Utc::now().to_rfc3339();

    // Версия из Cargo.toml
    let pkg_ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());

    // Пишем build_info.rs в OUT_DIR
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let dest = out_dir.join("build_info.rs");
    let contents = format!(
        "pub const BUILD_GIT_HASH: &str = \"{git_hash}\";\n\
         pub const BUILD_GIT_BRANCH: &str = \"{git_branch}\";\n\
         pub const BUILD_TIMESTAMP_RFC3339: &str = \"{ts}\";\n\
         pub const BUILD_PKG_VERSION: &str = \"{pkg_ver}\";\n"
    );
    fs::write(&dest, contents).expect("write build_info.rs failed");

    // Ретриггер
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=.git/HEAD");
}

```

---

### `/root/logos_lrb/node/Cargo.toml`

```toml
[package]
name        = "logos_node"
version     = "0.1.0"
edition     = "2021"
license     = "Apache-2.0"
description = "LOGOS LRB node: Axum REST + archive + producer + wallet/stake"
build       = "build.rs"

# --- бинарь узла ---
[[bin]]
name = "logos_node"
path = "src/main.rs"

# --- вспомогательные утилиты (можно закомментировать, если не нужны) ---
[[bin]]
name = "mint"
path = "src/bin/mint.rs"

[[bin]]
name = "make_tx"
path = "src/bin/make_tx.rs"

[[bin]]
name = "bench_burst"
path = "src/bin/bench_burst.rs"

[lib]
name = "logos_node"
path = "src/lib.rs"

[dependencies]
# базовый стек (всё из workspace — единые версии)
axum.workspace                = true
tower.workspace               = true
tower-http.workspace          = true
tokio.workspace               = true

serde.workspace               = true
serde_json.workspace          = true
anyhow.workspace              = true
thiserror.workspace           = true
once_cell.workspace           = true
dashmap.workspace             = true
tracing.workspace             = true
tracing-subscriber.workspace  = true
sha2.workspace                = true   # canonical_msg в API

# хранилища/индексация
sled.workspace                = true
deadpool-postgres.workspace   = true
tokio-postgres.workspace      = true
rusqlite.workspace            = true
r2d2_sqlite.workspace         = true

# утилиты/крипта/метрики
hex.workspace                 = true
base64.workspace              = true
bs58.workspace                = true
ed25519-dalek.workspace       = true
blake3.workspace              = true
ipnet.workspace               = true
prometheus.workspace          = true
uuid.workspace                = true

# === ДОБАВЛЕНО (security & utils) ===
# HMAC-SHA256 для подписи тела моста (deposit/redeem)
hmac = { version = "0.12", default-features = false }
# джиттер/phase-mixing в guard
rand = { version = "0.8", features = ["std","std_rng"] }
# мьютексы в state.rs (parking_lot::Mutex)
parking_lot = "0.12"

# для bin-утилит
reqwest   = { workspace = true, features = ["blocking","json"] }
rand_core = "0.6"

# ядро
lrb_core = { path = "../lrb_core" }

[build-dependencies]
chrono = { version = "0.4", default-features = false, features = ["clock"] }

```

---

### `/root/logos_lrb/node/openapi/openapi.json`

```json
{
  "openapi": "3.0.3",
  "info": {
    "title": "LOGOS LRB — Core API",
    "version": "0.1.0",
    "description": "Public & Admin API for LOGOS LRB (strict CSP, JWT admin, rToken bridge, archive)"
  },
  "servers": [{ "url": "https://45-159-248-232.sslip.io" }],
  "paths": {
    "/healthz": {
      "get": { "summary": "Healthcheck", "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/OkMsg" } } } } } }
    },
    "/head": {
      "get": { "summary": "Chain head", "responses": { "200": { "description": "Head", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Head" } } } } } }
    },
    "/balance/{rid}": {
      "get": {
        "summary": "Account balance & nonce",
        "parameters": [{ "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": { "200": { "description": "Balance", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Balance" } } } } }
      }
    },
    "/submit_tx": {
      "post": {
        "summary": "Submit transaction",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TxIn" } } } },
        "responses": { "200": { "description": "Result", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitResult" } } } } }
      }
    },
    "/economy": {
      "get": { "summary": "Economy snapshot", "responses": { "200": { "description": "Economy", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Economy" } } } } } }
    },
    "/history/{rid}": {
      "get": {
        "summary": "History by RID (from sled index)",
        "parameters": [{ "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "History", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/HistoryItem" } } } } }
        }
      }
    },
    "/archive/history/{rid}": {
      "get": {
        "summary": "History by RID (archive backend: SQLite/PG)",
        "parameters": [{ "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "History", "content": { "application/json": { "schema": { "type": "array", "items": { "type": "object" } } } } }
        }
      }
    },
    "/archive/tx/{txid}": {
      "get": {
        "summary": "Get TX by txid (archive backend)",
        "parameters": [{ "name": "txid", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "TX (if any)", "content": { "application/json": { "schema": { "type": "object" } } } }
        }
      }
    },
    "/bridge/deposit": {
      "post": {
        "summary": "Register external deposit to rToken",
        "security": [{ "BridgeKey": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DepositReq" } } } },
        "responses": { "200": { "description": "BridgeResp", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeResp" } } } } }
      }
    },
    "/bridge/redeem": {
      "post": {
        "summary": "Request redeem from rToken to external chain",
        "security": [{ "BridgeKey": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RedeemReq" } } } },
        "responses": { "200": { "description": "BridgeResp", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeResp" } } } } }
      }
    },
    "/bridge/verify": {
      "post": {
        "summary": "Verify bridge operation",
        "security": [{ "BridgeKey": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/VerifyReq" } } } },
        "responses": { "200": { "description": "BridgeResp", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeResp" } } } } }
      }
    },
    "/admin/set_balance": {
      "post": {
        "summary": "Set balance (admin)",
        "security": [{ "AdminJWT": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SetBalanceReq" } } } },
        "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "object" } } } } }
      }
    },
    "/admin/set_nonce": {
      "post": {
        "summary": "Set nonce (admin)",
        "security": [{ "AdminJWT": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SetNonceReq" } } } },
        "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "object" } } } } }
      }
    },
    "/admin/bump_nonce": {
      "post": {
        "summary": "Bump nonce (admin)",
        "security": [{ "AdminJWT": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BumpNonceReq" } } } },
        "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "object" } } } } }
      }
    },
    "/admin/mint": {
      "post": {
        "summary": "Add minted amount (admin)",
        "security": [{ "AdminJWT": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/MintReq" } } } },
        "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "object" } } } } }
      }
    },
    "/admin/burn": {
      "post": {
        "summary": "Add burned amount (admin)",
        "security": [{ "AdminJWT": [] }],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BurnReq" } } } },
        "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "type": "object" } } } } }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "AdminJWT": { "type": "apiKey", "in": "header", "name": "X-Admin-JWT" },
      "BridgeKey": { "type": "apiKey", "in": "header", "name": "X-Bridge-Key" }
    },
    "schemas": {
      "OkMsg": { "type": "object", "properties": { "status": { "type": "string" } }, "required": ["status"] },
      "Head":  { "type": "object", "properties": { "height": { "type": "integer", "format": "uint64" } }, "required": ["height"] },
      "Balance": {
        "type": "object",
        "properties": { "rid": { "type": "string" }, "balance": { "type": "string" }, "nonce": { "type": "integer", "format": "uint64" } },
        "required": ["rid","balance","nonce"]
      },
      "TxIn": {
        "type": "object",
        "properties": {
          "from": { "type": "string" }, "to": { "type": "string" },
          "amount": { "type": "integer", "format": "uint64" },
          "nonce": { "type": "integer", "format": "uint64" },
          "memo": { "type": "string", "nullable": true },
          "sig_hex": { "type": "string" }
        },
        "required": ["from","to","amount","nonce","sig_hex"]
      },
      "SubmitResult": {
        "type": "object",
        "properties": {
          "ok": { "type": "boolean" },
          "txid": { "type": "string", "nullable": true },
          "info": { "type": "string" }
        }, "required": ["ok","info"]
      },
      "Economy": {
        "type": "object",
        "properties": { "supply": { "type": "integer" }, "burned": { "type": "integer" }, "cap": { "type": "integer" } },
        "required": ["supply","burned","cap"]
      },
      "HistoryItem": {
        "type": "object",
        "properties": {
          "txid": { "type": "string" }, "height": { "type": "integer" }, "from": { "type": "string" },
          "to": { "type": "string" }, "amount": { "type": "integer" }, "nonce": { "type": "integer" }, "ts": { "type": "integer", "nullable": true }
        },
        "required": ["txid","height","from","to","amount","nonce"]
      },
      "DepositReq": {
        "type": "object",
        "properties": { "txid":{ "type": "string" }, "amount":{ "type": "integer" }, "from_chain":{ "type": "string" }, "to_rid":{ "type": "string" } },
        "required": ["txid","amount","from_chain","to_rid"]
      },
      "RedeemReq": {
        "type": "object",
        "properties": { "rtoken_tx":{ "type": "string" }, "to_chain":{ "type": "string" }, "to_addr":{ "type": "string" }, "amount":{ "type": "integer" } },
        "required": ["rtoken_tx","to_chain","to_addr","amount"]
      },
      "VerifyReq": {
        "type": "object",
        "properties": { "op_id":{ "type": "string" } }, "required": ["op_id"]
      },
      "BridgeResp": {
        "type": "object",
        "properties": { "ok":{ "type": "boolean" }, "op_id":{ "type": "string" }, "info":{ "type": "string" } },
        "required": ["ok","op_id","info"]
      },
      "SetBalanceReq": { "type": "object", "properties": { "rid":{"type":"string"}, "amount":{"type":"string"} }, "required": ["rid","amount"] },
      "SetNonceReq":   { "type": "object", "properties": { "rid":{"type":"string"}, "value":{"type":"integer"} }, "required": ["rid","value"] },
      "BumpNonceReq":  { "type": "object", "properties": { "rid":{"type":"string"} }, "required": ["rid"] },
      "MintReq":       { "type": "object", "properties": { "amount":{"type":"integer"} }, "required": ["amount"] },
      "BurnReq":       { "type": "object", "properties": { "amount":{"type":"integer"} }, "required": ["amount"] }
    }
  }
}

```

---

### `/root/logos_lrb/node/src/admin_founder.rs`

```rust
use std::{fs, io::Write, path::Path, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::api::helpers::canonical_msg;
use crate::state::AppState;

const KEYS_ENV: &str = "/etc/logos/keys.env";
const FOUNDER_RID_FILE: &str = "/etc/logos/founder.rid";
const FOUNDER_SK_FILE: &str = "/etc/logos/founder.key";
const GENESIS_MARK_FILE: &str = "/var/lib/logos/genesis.applied";

#[derive(Serialize)]
pub struct Info {
    pub rid_b58: String,
    pub has_sk: bool,
}

/// GET /admin/founder/info
/// Если ключа/рид ещё нет — сгенерируем, положим в /etc/logos/{founder.rid,founder.key} и допишем в keys.env.
pub async fn info(State(_): State<Arc<AppState>>) -> (StatusCode, Json<Info>) {
    match ensure_founder(true) {
        Ok((rid, sk_hex)) => {
            let has_sk = !sk_hex.is_empty();
            (StatusCode::OK, Json(Info { rid_b58: rid, has_sk }))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Info {
                rid_b58: format!("error: {}", e),
                has_sk: false,
            }),
        ),
    }
}

#[derive(Deserialize, Default)]
pub struct GenesisReq {
    // Если поля отсутствуют — вся эмиссия уходит основателю.
    pub founder_main: Option<String>,
    pub founder_ops: Option<String>,
    pub core_team_vest: Option<String>,
    pub early_support: Option<String>,
    pub stability_fund: Option<String>,
    pub staking_pool: Option<String>,
    pub liquidity_pool: Option<String>,
    pub rcp_pool: Option<String>,
    pub dao_pool: Option<String>,
    pub long_reserve: Option<String>,
}

#[derive(Serialize)]
pub struct ApplyResult {
    pub applied: bool,
    pub message: String,
}

/// POST /admin/founder/init_and_apply
/// Требует заголовок X-Admin-Key. Делает разовую заливку GENESIS через /faucet/<rid>/<amount>.
pub async fn init_and_apply(
    State(_): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GenesisReq>,
) -> (StatusCode, Json<ApplyResult>) {
    if !admin_ok(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApplyResult {
                applied: false,
                message: "unauthorized".into(),
            }),
        );
    }

    // Разовая защита от повторного применения.
    if Path::new(GENESIS_MARK_FILE).exists() {
        return (
            StatusCode::CONFLICT,
            Json(ApplyResult {
                applied: false,
                message: "genesis already applied".into(),
            }),
        );
    }

    let (founder_rid, _sk_hex) = match ensure_founder(true) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApplyResult {
                    applied: false,
                    message: format!("ensure_founder: {}", e),
                }),
            );
        }
    };

    // Токеномика (u64 достаточно: 81M << 64)
    const TOTAL: u64 = 81_000_000;

    let founder_main = req.founder_main.unwrap_or_else(|| founder_rid.clone());
    let founder_ops = req.founder_ops.unwrap_or_else(|| founder_rid.clone());
    let core_team_vest = req.core_team_vest.unwrap_or_else(|| founder_rid.clone());
    let early_support = req.early_support.unwrap_or_else(|| founder_rid.clone());
    let stability_fund = req.stability_fund.unwrap_or_else(|| founder_rid.clone());
    let staking_pool = req.staking_pool.unwrap_or_else(|| founder_rid.clone());
    let liquidity_pool = req.liquidity_pool.unwrap_or_else(|| founder_rid.clone());
    let rcp_pool = req.rcp_pool.unwrap_or_else(|| founder_rid.clone());
    let dao_pool = req.dao_pool.unwrap_or_else(|| founder_rid.clone());
    let long_reserve = req.long_reserve.unwrap_or_else(|| founder_rid.clone());

    let plan: [(&str, u64); 10] = [
        (&founder_main, 4_860_000),
        (&founder_ops, 3_240_000),
        (&core_team_vest, 8_100_000),
        (&early_support, 4_050_000),
        (&stability_fund, 12_150_000),
        (&staking_pool, 20_250_000),
        (&liquidity_pool, 12_150_000),
        (&rcp_pool, 8_100_000),
        (&dao_pool, 4_050_000),
        (&long_reserve, 4_050_000),
    ];

    let sum: u64 = plan.iter().map(|(_, a)| *a).sum();
    if sum != TOTAL {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApplyResult {
                applied: false,
                message: format!("bad tokenomics sum={} expected={}", sum, TOTAL),
            }),
        );
    }

    // Базовый адрес API (локалхост по порту из LRB_HTTP_ADDR)
    let base = local_base_http();

    // Заливаем через faucet (POST /faucet/<rid>/<amount>)
    let client = reqwest::Client::new();
    for (rid, amount) in plan {
        let url = format!("{}/faucet/{}/{}", base, rid, amount);
        let res = client
            .post(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map(|_| ());
        if let Err(e) = res {
            return (
                StatusCode::BAD_GATEWAY,
                Json(ApplyResult {
                    applied: false,
                    message: format!("faucet failed for {}: {}", rid, e),
                }),
            );
        }
    }

    // Ставим маркер "применено".
    if let Err(e) = write_once(GENESIS_MARK_FILE, "ok\n") {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApplyResult {
                applied: false,
                message: format!("write genesis mark: {}", e),
            }),
        );
    }

    (
        StatusCode::OK,
        Json(ApplyResult {
            applied: true,
            message: "genesis applied".into(),
        }),
    )
}

#[derive(Serialize)]
pub struct MakeRidOut {
    pub rid_b58: String,
    pub sk_hex: String,
    pub vk_hex: String,
}

/// GET /admin/make_rid  (DEV)
pub async fn make_rid(State(_): State<Arc<AppState>>) -> Json<MakeRidOut> {
    let sk = SigningKey::generate(&mut OsRng);
    let vk: VerifyingKey = sk.verifying_key();
    let rid_b58 = bs58::encode(vk.as_bytes()).into_string();
    let sk_hex = hex::encode(sk.to_bytes());
    let vk_hex = hex::encode(vk.to_bytes());
    Json(MakeRidOut {
        rid_b58,
        sk_hex,
        vk_hex,
    })
}

#[derive(Deserialize)]
pub struct SubmitAutoReq {
    pub from_sk_hex: String,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub memo: Option<String>,
}

/// POST /admin/submit_tx_auto  (DEV)
/// Подписывает на узле и шлёт в /submit_tx.
pub async fn submit_tx_auto(
    State(_): State<Arc<AppState>>,
    Json(req): Json<SubmitAutoReq>,
) -> (StatusCode, String) {
    // SK hex -> SigningKey
    let sk_bytes = match hex::decode(&req.from_sk_hex) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad sk hex: {}", e)),
    };
    if sk_bytes.len() != 32 {
        return (
            StatusCode::BAD_REQUEST,
            "sk must be 32 bytes".into(),
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sk_bytes);
    let sk = SigningKey::from_bytes(&arr);
    let vk: VerifyingKey = sk.verifying_key();
    let from_rid = bs58::encode(vk.as_bytes()).into_string();

    // canonical message = bytes(from,to,amount,nonce)
    let msg = canonical_msg(&from_rid, &req.to, req.amount, req.nonce);
    let sig = sk.sign(&msg);
    let sig_hex = hex::encode(sig.to_bytes());

    // JSON к /submit_tx
    #[derive(Serialize)]
    struct TxIn<'a> {
        from: &'a str,
        to: &'a str,
        amount: u64,
        nonce: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        memo: Option<&'a String>,
        sig_hex: String,
    }
    let tx = TxIn {
        from: &from_rid,
        to: &req.to,
        amount: req.amount,
        nonce: req.nonce,
        memo: req.memo.as_ref(),
        sig_hex,
    };

    let base = local_base_http();
    let url = format!("{}/submit_tx", base);
    let client = reqwest::Client::new();
    match client.post(url).json(&tx).send().await {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(body) => (status, body),
                Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream body: {}", e)),
            }
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream: {}", e)),
    }
}

// --------------------- helpers ---------------------

fn admin_ok(headers: &HeaderMap) -> bool {
    let want = std::env::var("LRB_ADMIN_KEY").unwrap_or_default();
    if want.is_empty() {
        return false;
    }
    match headers.get("X-Admin-Key").and_then(|v| v.to_str().ok()) {
        Some(got) if got == want => true,
        _ => false,
    }
}

fn ensure_founder(auto_create: bool) -> Result<(String, String)> {
    // 1) env
    let env_rid = std::env::var("RID_FOUNDER_MAIN").ok();
    let env_sk = std::env::var("FOUNDER_SK_HEX").ok();
    if let (Some(rid), Some(sk)) = (env_rid, env_sk) {
        return Ok((rid, sk));
    }

    // 2) files
    let file_rid = fs::read_to_string(FOUNDER_RID_FILE).ok().map(|s| s.trim().to_string());
    let file_sk = fs::read_to_string(FOUNDER_SK_FILE).ok().map(|s| s.trim().to_string());
    if let (Some(rid), Some(sk)) = (file_rid, file_sk) {
        // добьём keys.env
        append_env_if_missing("RID_FOUNDER_MAIN", &rid).ok();
        append_env_if_missing("FOUNDER_SK_HEX", &sk).ok();
        return Ok((rid, sk));
    }

    // 3) создать, если просили
    if !auto_create {
        anyhow::bail!("founder key/rid not present");
    }
    // гарантируем каталог
    if let Some(dir) = Path::new(FOUNDER_RID_FILE).parent() {
        fs::create_dir_all(dir).ok();
    }
    let sk = SigningKey::generate(&mut OsRng);
    let vk: VerifyingKey = sk.verifying_key();
    let rid_b58 = bs58::encode(vk.as_bytes()).into_string();
    let sk_hex = hex::encode(sk.to_bytes());

    fs::write(FOUNDER_RID_FILE, format!("{}\n", &rid_b58))
        .with_context(|| format!("write {}", FOUNDER_RID_FILE))?;
    fs::write(FOUNDER_SK_FILE, format!("{}\n", &sk_hex))
        .with_context(|| format!("write {}", FOUNDER_SK_FILE))?;

    append_env_if_missing("RID_FOUNDER_MAIN", &rid_b58).ok();
    append_env_if_missing("FOUNDER_SK_HEX", &sk_hex).ok();

    Ok((rid_b58, sk_hex))
}

fn append_env_if_missing(key: &str, val: &str) -> Result<()> {
    // читаем, если есть
    let mut need_write = true;
    if let Ok(existing) = fs::read_to_string(KEYS_ENV) {
        for line in existing.lines() {
            if line.trim_start().starts_with(&format!("{}=", key)) {
                need_write = false;
                break;
            }
        }
    } else {
        // каталоги могут отсутствовать
        if let Some(dir) = Path::new(KEYS_ENV).parent() {
            fs::create_dir_all(dir).ok();
        }
    }
    if need_write {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(KEYS_ENV)
            .with_context(|| format!("open {}", KEYS_ENV))?;
        writeln!(f, "{}={}", key, val).ok();
    }
    Ok(())
}

fn write_once(path: &str, content: &str) -> Result<()> {
    if Path::new(path).exists() {
        anyhow::bail!("exists");
    }
    if let Some(dir) = Path::new(path).parent() {
        fs::create_dir_all(dir).ok();
    }
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open {}", path))?;
    f.write_all(content.as_bytes()).ok();
    Ok(())
}

fn local_base_http() -> String {
    // LRB_HTTP_ADDR формата 0.0.0.0:8080
    let addr = std::env::var("LRB_HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let port = addr.rsplit(':').next().unwrap_or("8080");
    format!("http://127.0.0.1:{port}")
}

```

---

### `/root/logos_lrb/node/src/admin.rs`

```rust
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use serde::Deserialize;
use std::sync::Arc;
use serde_json::json;

use crate::state::AppState;
use crate::auth::require_admin;
use crate::metrics::inc_total;

#[derive(Deserialize)] pub struct SetBalanceReq { pub rid: String, pub amount: u128 }
#[derive(Deserialize)] pub struct BumpNonceReq  { pub rid: String }
#[derive(Deserialize)] pub struct SetNonceReq   { pub rid: String, pub value: u64 }
#[derive(Deserialize)] pub struct MintReq       { pub amount: u64 }
#[derive(Deserialize)] pub struct BurnReq       { pub amount: u64 }

pub async fn set_balance(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<SetBalanceReq>) -> impl IntoResponse {
    inc_total("admin_set_balance");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.set_balance(&req.rid, req.amount) { Ok(_) => Json(json!({"ok":true})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
pub async fn bump_nonce(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<BumpNonceReq>) -> impl IntoResponse {
    inc_total("admin_bump_nonce");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.bump_nonce(&req.rid) { Ok(n)=>Json(json!({"ok":true,"nonce":n})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
pub async fn set_nonce(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<SetNonceReq>) -> impl IntoResponse {
    inc_total("admin_set_nonce");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.set_nonce(&req.rid, req.value) { Ok(_)=>Json(json!({"ok":true,"nonce":req.value})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
pub async fn mint(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<MintReq>) -> impl IntoResponse {
    inc_total("admin_mint");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.add_minted(req.amount) { Ok(net)=>Json(json!({"ok":true,"net_supply":net})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}
pub async fn burn(State(app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<BurnReq>) -> impl IntoResponse {
    inc_total("admin_burn");
    if let Err(e) = require_admin(&headers) { return Json(json!({"ok":false,"err":e.to_string()})); }
    let l = app.ledger.lock();
    match l.add_burned(req.amount) { Ok(net)=>Json(json!({"ok":true,"net_supply":net})), Err(e)=>Json(json!({"ok":false,"err":e.to_string()})) }
}

```

---

### `/root/logos_lrb/node/src/api/archive.rs`

```rust
use axum::{extract::{Path, State, Query}, http::StatusCode, Json};
use std::{collections::HashMap, sync::Arc};
use tracing::error;
use crate::state::AppState;
use super::HistoryItem;

pub async fn archive_history(Path(rid):Path<String>, State(app): State<Arc<AppState>>)
 -> Json<Vec<HistoryItem>>
{
    if let Some(arch)=&app.archive {
        match arch.history_by_rid(&rid, 100, None).await {
            Ok(list) => {
                let out = list.into_iter().map(|r| HistoryItem{
                    txid:r.txid, height:r.height as u64, from:r.from, to:r.to, amount:r.amount as u64,
                    nonce:r.nonce as u64, ts:r.ts.map(|v| v as u64)
                }).collect();
                return Json(out);
            }
            Err(e) => error!("archive: history_by_rid failed: {}", e),
        }
    }
    Json(Vec::new())
}

pub async fn archive_tx(Path(txid):Path<String>, State(app): State<Arc<AppState>>)
 -> (StatusCode, Json<serde_json::Value>)
{
    if let Some(arch)=&app.archive {
        match arch.tx_by_id(&txid).await {
            Ok(Some(rec)) => return (StatusCode::OK, Json(rec)),
            Ok(None)      => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not found"}))),
            Err(e)        => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":e.to_string()}))),
        }
    }
    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"archive disabled"})))
}

pub async fn archive_blocks(State(app): State<Arc<AppState>>, Query(q): Query<HashMap<String,String>>)
 -> Json<Vec<crate::archive::BlockRow>>
{
    let lim = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(50);
    let before = q.get("before_height").and_then(|s| s.parse::<i64>().ok());
    if let Some(arch)=&app.archive {
        if let Ok(list)=arch.recent_blocks(lim, before).await { return Json(list); }
    }
    Json(Vec::new())
}

pub async fn archive_txs(State(app): State<Arc<AppState>>, Query(q): Query<HashMap<String,String>>)
 -> Json<Vec<crate::archive::TxRecord>>
{
    let lim = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(100);
    let rid = q.get("rid").map(|s| s.as_str());
    let before_ts = q.get("before_ts").and_then(|s| s.parse::<i64>().ok());
    if let Some(arch)=&app.archive {
        if let Ok(list)=arch.recent_txs(lim, rid, before_ts).await { return Json(list); }
    }
    Json(Vec::new())
}

```

---

### `/root/logos_lrb/node/src/api/base.rs`

```rust
use axum::{extract::{Path, State}, Json};
use std::sync::Arc;
use crate::state::AppState;
use super::{OkMsg, Head, Balance, Economy, HistoryItem};

pub async fn healthz() -> Json<OkMsg> { Json(OkMsg{ status:"ok" }) }

pub async fn head(State(app): State<Arc<AppState>>) -> Json<Head> {
    let l = app.ledger.lock();
    let h = l.head_height().unwrap_or(0);
    let fin = h.saturating_sub(1);
    Json(Head{ height:h, finalized: fin })
}

pub async fn balance(Path(rid):Path<String>, State(app): State<Arc<AppState>>) -> Json<Balance> {
    let l = app.ledger.lock();
    let bal = l.get_balance(&rid).unwrap_or(0);
    let n   = l.get_nonce(&rid).unwrap_or(0);
    Json(Balance{ rid, balance: bal as u128, nonce: n })
}

pub async fn economy(State(app): State<Arc<AppState>>) -> Json<Economy> {
    const CAP_MICRO: u64 = 81_000_000_u64 * 1_000_000_u64;
    let (minted, burned) = app.ledger.lock().supply().unwrap_or((0,0));
    let supply = minted.saturating_sub(burned);
    Json(Economy{ supply, burned, cap: CAP_MICRO })
}

pub async fn history(Path(rid):Path<String>, State(app): State<Arc<AppState>>) -> Json<Vec<HistoryItem>> {
    let l = app.ledger.lock();
    let rows = l.account_txs_page(&rid, 0, 100).unwrap_or_default();
    Json(rows.into_iter().map(|r| HistoryItem{
        txid:r.txid, height:r.height, from:r.from, to:r.to, amount:r.amount, nonce:r.nonce, ts:Some((r.ts/1000) as u64)
    }).collect())
}

```

---

### `/root/logos_lrb/node/src/api/helpers.rs`

```rust
use ed25519_dalek::{Signature, VerifyingKey, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};
use bs58;

/// Каноника для подписи / TxID: from|to|amount|nonce (bytes)
pub fn canonical_msg(from_rid_b58: &str, to_rid_b58: &str, amount: u64, nonce: u64) -> Vec<u8> {
    let from = bs58::decode(from_rid_b58).into_vec().unwrap_or_default();
    let to   = bs58::decode(to_rid_b58).into_vec().unwrap_or_default();
    let mut buf = Vec::with_capacity(from.len() + to.len() + 16);
    buf.extend_from_slice(&from);
    buf.extend_from_slice(&to);
    buf.extend_from_slice(&amount.to_be_bytes());
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf
}

/// Проверка: pubkey = RID (base58), подпись = HEX
pub fn verify_sig_pk_b58_sig_hex(pubkey_b58: &str, msg: &[u8], sig_hex: &str) -> Result<(), String> {
    let pk = bs58::decode(pubkey_b58).into_vec().map_err(|e| format!("pubkey b58: {e}"))?;
    if pk.len() != PUBLIC_KEY_LENGTH { return Err("pubkey len".into()); }
    let mut pk_arr = [0u8; PUBLIC_KEY_LENGTH]; pk_arr.copy_from_slice(&pk);

    let sig = hex::decode(sig_hex).map_err(|e| format!("sig hex: {e}"))?;
    if sig.len() != SIGNATURE_LENGTH { return Err("sig len".into()); }
    let mut sig_arr = [0u8; SIGNATURE_LENGTH]; sig_arr.copy_from_slice(&sig);

    let vk  = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("vk: {e}"))?;
    let s   = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &s).map_err(|e| format!("verify: {e}"))
}

/// TxID = SHA-256(from|to|amount|nonce)
pub fn txid_hex(from_rid_b58: &str, to_rid_b58: &str, amount: u64, nonce: u64) -> String {
    let m = canonical_msg(from_rid_b58, to_rid_b58, amount, nonce);
    let mut h = Sha256::new(); h.update(&m);
    hex::encode(h.finalize())
}

```

---

### `/root/logos_lrb/node/src/api/mod.rs`

```rust
//! API root: общие типы/утилы + экспорт подмодулей

use serde::{Deserialize, Serialize};

pub mod base;
pub mod tx;
pub mod archive;
pub mod staking;

// ---------- Общие модели ----------
#[derive(Serialize)]
pub struct OkMsg { pub status: &'static str }

#[derive(Serialize)]
pub struct Head { pub height: u64, pub finalized: u64 }

#[derive(Serialize)]
pub struct Balance { pub rid: String, pub balance: u128, pub nonce: u64 }

#[derive(Deserialize, Clone)]
pub struct TxIn {
    pub from:String, pub to:String, pub amount:u64, pub nonce:u64,
    pub sig_hex:String,
    #[serde(default)] pub memo:Option<String>
}

#[derive(Serialize)]
pub struct SubmitResult { pub ok:bool, #[serde(skip_serializing_if="Option::is_none")] pub txid:Option<String>, pub info:String }

#[derive(Serialize)]
pub struct SubmitBatchItem { pub ok:bool, #[serde(skip_serializing_if="Option::is_none")] pub txid:Option<String>, pub info:String, pub index:usize }

#[derive(Deserialize)]
pub struct SubmitBatchReq { pub txs: Vec<TxIn> }

#[derive(Serialize)]
pub struct Economy { pub supply:u64, pub burned:u64, pub cap:u64 }

#[derive(Serialize)]
pub struct HistoryItem {
    pub txid:String, pub height:u64, pub from:String, pub to:String, pub amount:u64, pub nonce:u64,
    #[serde(skip_serializing_if="Option::is_none")] pub ts:Option<u64>,
}

// ---------- Утили для подписи ----------
use sha2::{Sha256, Digest};
use ed25519_dalek::{Verifier, Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

pub fn canonical_msg(from:&str, to:&str, amount:u64, nonce:u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(from.as_bytes()); h.update(b"|");
    h.update(to.as_bytes());   h.update(b"|");
    h.update(&amount.to_be_bytes()); h.update(b"|");
    h.update(&nonce.to_be_bytes());
    h.finalize().to_vec()
}

pub fn verify_sig(from:&str, msg:&[u8], sig_hex:&str) -> Result<(), String> {
    let pubkey_bytes = bs58::decode(from).into_vec().map_err(|e| format!("bad_from_rid_base58: {e}"))?;
    if pubkey_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(format!("bad_pubkey_len: got {} want {}", pubkey_bytes.len(), PUBLIC_KEY_LENGTH));
    }
    let mut pk_arr = [0u8; PUBLIC_KEY_LENGTH];
    pk_arr.copy_from_slice(&pubkey_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("bad_pubkey: {e}"))?;

    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("bad_sig_hex: {e}"))?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(format!("bad_sig_len: got {} want {}", sig_bytes.len(), SIGNATURE_LENGTH));
    }
    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify(msg, &sig).map_err(|_| "bad_signature".to_string())
}

// ---------- Переэкспорт хендлеров ----------
pub use base::{healthz, head, balance, economy, history};
pub use tx::{submit_tx, submit_tx_batch};
pub use archive::{archive_history, archive_tx, archive_blocks, archive_txs};
pub use staking::{stake_delegate, stake_undelegate, stake_claim, stake_my};

```

---

### `/root/logos_lrb/node/src/api/staking.rs`

```rust
use axum::{extract::{Path}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use reqwest::Client;

#[derive(Deserialize, Serialize)]
pub struct StakeAction {
    pub rid: String,
    #[serde(default)] pub validator: String,
    #[serde(default)] pub amount: Option<u64>,
}

pub async fn stake_delegate(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&serde_json::json!({"action":"delegate","rid":body.rid,"validator":body.validator,"amount":body.amount}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_undelegate(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&serde_json::json!({"action":"undelegate","rid":body.rid,"validator":body.validator,"amount":body.amount}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_claim(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&serde_json::json!({"action":"claim","rid":body.rid}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_my(Path(rid):Path<String>) -> (StatusCode, String) {
    let cli = Client::new();

    let dtext = match cli.get(format!("http://127.0.0.1:8080/stake/delegations/{rid}")).send().await {
        Ok(resp) => resp.text().await.unwrap_or_else(|_| "[]".to_string()),
        Err(_)   => "[]".to_string(),
    };

    let rtext = match cli.get(format!("http://127.0.0.1:8080/stake/rewards/{rid}")).send().await {
        Ok(resp) => resp.text().await.unwrap_or_else(|_| "[]".to_string()),
        Err(_)   => "[]".to_string(),
    };

    let body = serde_json::json!({
        "delegations": serde_json::from_str::<serde_json::Value>(&dtext).unwrap_or(serde_json::json!([])),
        "rewards":     serde_json::from_str::<serde_json::Value>(&rtext).unwrap_or(serde_json::json!([]))
    });
    (StatusCode::OK, body.to_string())
}

```

---

### `/root/logos_lrb/node/src/api/tx.rs`

```rust
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{info,warn,error};
use crate::{state::AppState, metrics};
use super::{TxIn, SubmitResult, SubmitBatchReq, SubmitBatchItem, canonical_msg, verify_sig};

pub async fn submit_tx(State(app): State<Arc<AppState>>, Json(tx):Json<TxIn>)
    -> (StatusCode, Json<SubmitResult>)
{
    let msg = canonical_msg(&tx.from, &tx.to, tx.amount, tx.nonce);
    if let Err(e) = verify_sig(&tx.from, &msg, &tx.sig_hex) {
        metrics::inc_tx_rejected("bad_signature");
        return (StatusCode::UNAUTHORIZED, Json(SubmitResult{ ok:false, txid:None, info:e }));
    }
    let prev = app.ledger.lock().get_nonce(&tx.from).unwrap_or(0);
    if tx.nonce <= prev {
        metrics::inc_tx_rejected("nonce_reuse");
        return (StatusCode::CONFLICT, Json(SubmitResult{ ok:false, txid:None, info:"nonce_reuse".into() }));
    }
    let stx = match app.ledger.lock().submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.clone()){
        Ok(s)=>s, Err(e)=>{
            metrics::inc_tx_rejected("internal");
            return (StatusCode::OK, Json(SubmitResult{ ok:false, txid:None, info:e.to_string() }))
        },
    };
    if let Some(arch)=&app.archive {
        match arch.record_tx(&stx.txid, stx.height, &stx.from, &stx.to, stx.amount, stx.nonce, Some((stx.ts/1000) as u64)).await {
            Ok(()) => info!("archive: wrote tx {}", stx.txid),
            Err(e) => error!("archive: write failed: {}", e),
        }
    } else { warn!("archive: not configured"); }

    metrics::inc_tx_accepted();
    (StatusCode::OK, Json(SubmitResult{ ok:true, txid:Some(stx.txid), info:"accepted".into() }))
}

pub async fn submit_tx_batch(State(app): State<Arc<AppState>>, Json(req):Json<SubmitBatchReq>)
    -> (StatusCode, Json<Vec<SubmitBatchItem>>)
{
    let mut out = Vec::with_capacity(req.txs.len());

    // 1) Пропускаем и коммитим все tx по правилам валидации
    for (i, tx) in req.txs.into_iter().enumerate() {
        let msg = canonical_msg(&tx.from, &tx.to, tx.amount, tx.nonce);
        if let Err(e) = verify_sig(&tx.from, &msg, &tx.sig_hex) {
            metrics::inc_tx_rejected("bad_signature");
            out.push(SubmitBatchItem{ ok:false, txid:None, info:e, index:i });
            continue;
        }
        let prev = app.ledger.lock().get_nonce(&tx.from).unwrap_or(0);
        if tx.nonce <= prev {
            metrics::inc_tx_rejected("nonce_reuse");
            out.push(SubmitBatchItem{ ok:false, txid:None, info:"nonce_reuse".into(), index:i });
            continue;
        }
        match app.ledger.lock().submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.clone()) {
            Ok(s) => { metrics::inc_tx_accepted(); out.push(SubmitBatchItem{ ok:true, txid:Some(s.txid), info:"accepted".into(), index:i }); }
            Err(e)=> { metrics::inc_tx_rejected("internal"); out.push(SubmitBatchItem{ ok:false, txid:None, info:e.to_string(), index:i }); }
        }
    }

    // 2) Batch ingest в архив: СБОР В OWNED-СТРУКТУРУ
    if let Some(arch)=&app.archive {
        // собираем только принятые
        let mut rows: Vec<(String,u64,String,String,u64,u64,Option<u64>)> = Vec::new();
        for item in &out {
            if !item.ok { continue; }
            if let Some(ref txid) = item.txid {
                // достаём сохранённую tx из ledger
                if let Ok(Some(stx)) = app.ledger.lock().get_tx(txid) {
                    rows.push((
                        txid.clone(),
                        stx.height,
                        stx.from.clone(),
                        stx.to.clone(),
                        stx.amount as u64,
                        stx.nonce as u64,
                        Some((stx.ts/1000) as u64),
                    ));
                }
            }
        }
        if !rows.is_empty() {
            // передаём срез &rows[..] — тип: &[(String,u64,String,String,u64,u64,Option<u64>)]
            let _ = arch.record_txs_batch(&rows[..]).await;
        }
    }

    (StatusCode::OK, Json(out))
}

```

---

### `/root/logos_lrb/node/src/archive/mod.rs`

```rust
//! Postgres archive backend with simple batch insert & backpressure

use deadpool_postgres::{Manager, Pool};
use tokio_postgres::{NoTls, Row, Config};
use serde::Serialize;
use anyhow::Result;
use crate::metrics;

#[derive(Clone)]
pub struct Archive { pub(crate) pool: Pool }

impl Archive {
    pub async fn new_from_env() -> Option<Self> {
        let url = std::env::var("LRB_ARCHIVE_URL").ok()?;
        let cfg: Config = url.parse().ok()?;
        let mgr = Manager::new(cfg, NoTls);
        let pool = Pool::builder(mgr).max_size(16).build().ok()?;
        Some(Archive { pool })
    }

    pub async fn record_tx(&self, txid:&str, height:u64, from:&str, to:&str, amount:u64, nonce:u64, ts:Option<u64>) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute(
            "insert into txs (txid,height,from_rid,to_rid,amount,nonce,ts) values ($1,$2,$3,$4,$5,$6,to_timestamp($7))",
            &[&txid, &(height as i64), &from, &to, &(amount as i64), &(nonce as i64), &(ts.unwrap_or(0) as i64)]
        ).await?;
        Ok(())
    }

    /// Batch-ingest (owned строки → без проблем с лайфтаймами)
    pub async fn record_txs_batch(
        &self,
        rows:&[(String,u64,String,String,u64,u64,Option<u64>)]
    ) -> Result<()> {
        use std::time::Duration;
        let client = self.pool.get().await?;
        let depth = rows.len() as i64;
        metrics::set_archive_queue(depth);

        let stmt = "insert into txs (txid,height,from_rid,to_rid,amount,nonce,ts) \
                    values ($1,$2,$3,$4,$5,$6,to_timestamp($7)) on conflict do nothing";

        for chunk in rows.chunks(500) {
            for r in chunk {
                client.execute(
                    stmt,
                    &[&r.0, &(r.1 as i64), &r.2, &r.3, &(r.4 as i64), &(r.5 as i64), &(r.6.unwrap_or(0) as i64)]
                ).await?;
            }
            if chunk.len()==500 { tokio::time::sleep(Duration::from_millis(2)).await; }
        }
        metrics::set_archive_queue(0);
        Ok(())
    }

    pub async fn history_by_rid(&self, rid:&str, limit:i64, before:Option<i64>) -> Result<Vec<TxRecord>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
             from txs where (from_rid=$1 or to_rid=$1) and ($2::bigint is null or height<$2) \
             order by height desc limit $3",
            &[&rid, &before, &limit]
        ).await?;
        Ok(rows.into_iter().map(TxRecord::from_row).collect())
    }

    pub async fn tx_by_id(&self, txid:&str) -> Result<Option<serde_json::Value>> {
        let client = self.pool.get().await?;
        let row = client.query_opt(
            "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
             from txs where txid=$1", &[&txid]
        ).await?;
        Ok(row.map(|r| serde_json::json!(TxRecord::from_row(r))))
    }

    pub async fn recent_blocks(&self, limit:i64, before:Option<i64>) -> Result<Vec<BlockRow>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "select height,hash,extract(epoch from ts)::bigint as ts,tx_count \
             from blocks where ($1::bigint is null or height<$1) order by height desc limit $2",
            &[&before, &limit]
        ).await?;
        Ok(rows.into_iter().map(BlockRow::from_row).collect())
    }

    pub async fn recent_txs(&self, limit:i64, rid:Option<&str>, before_ts:Option<i64>) -> Result<Vec<TxRecord>> {
        let client = self.pool.get().await?;
        let rows = if let Some(rid)=rid {
            client.query(
                "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
                 from txs where (from_rid=$1 or to_rid=$1) and ($2::bigint is null or extract(epoch from ts)<$2) \
                 order by ts desc limit $3",
                &[&rid, &before_ts, &limit]
            ).await?
        } else {
            client.query(
                "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
                 from txs where ($1::bigint is null or extract(epoch from ts)<$1) order by ts desc limit $2",
                &[&before_ts, &limit]
            ).await?
        };
        Ok(rows.into_iter().map(TxRecord::from_row).collect())
    }

    // нужен для /archive_block (и может использоваться API)
    pub async fn block_by_height(&self, h:i64) -> Result<Option<BlockRow>> {
        let client = self.pool.get().await?;
        let row = client.query_opt(
            "select height,hash,extract(epoch from ts)::bigint as ts,tx_count from blocks where height=$1",
            &[&h]
        ).await?;
        Ok(row.map(BlockRow::from_row))
    }
}

#[derive(Serialize)]
pub struct BlockRow { pub height:i64, pub hash:String, pub ts:i64, pub tx_count:i64 }
impl BlockRow { fn from_row(r:Row)->Self { Self{ height:r.get(0), hash:r.get(1), ts:r.get(2), tx_count:r.get(3) } } }

#[derive(Serialize)]
pub struct TxRecord { pub txid:String, pub height:i64, pub from:String, pub to:String, pub amount:i64, pub nonce:i64, pub ts:Option<i64> }
impl TxRecord { fn from_row(r:Row)->Self { Self{
    txid:r.get(0), height:r.get(1), from:r.get(2), to:r.get(3), amount:r.get(4), nonce:r.get(5), ts:r.get(6)
}}}

```

---

### `/root/logos_lrb/node/src/archive/pg.rs`

```rust
//! Postgres архивация: deadpool-postgres, батч-вставки (prod).
//! ENV: LRB_ARCHIVE_URL=postgres://user:pass@host:5432/db

use anyhow::Result;
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

#[derive(Clone)]
pub struct ArchivePg {
    pool: Pool,
}

impl ArchivePg {
    pub async fn new(url: &str) -> Result<Self> {
        // Правильная настройка пула: используем поле `url`
        let mut cfg = Config::new();
        cfg.url = Some(url.to_string());
        cfg.manager = Some(ManagerConfig { recycling_method: RecyclingMethod::Fast });
        // Можно добавить пул-лимиты при необходимости:
        // cfg.pool = Some(deadpool_postgres::PoolConfig { max_size: 32, ..Default::default() });

        let pool = cfg.create_pool(Some(deadpool_postgres::Runtime::Tokio1), NoTls)?;
        let a = Self { pool };
        a.ensure_schema().await?;
        Ok(a)
    }

    async fn ensure_schema(&self) -> Result<()> {
        let client = self.pool.get().await?;
        client.batch_execute(r#"
            CREATE TABLE IF NOT EXISTS tx (
                txid      TEXT PRIMARY KEY,
                height    BIGINT NOT NULL,
                from_rid  TEXT NOT NULL,
                to_rid    TEXT NOT NULL,
                amount    BIGINT NOT NULL,
                nonce     BIGINT NOT NULL,
                ts        BIGINT
            );
            CREATE TABLE IF NOT EXISTS account_tx (
                rid    TEXT NOT NULL,
                height BIGINT NOT NULL,
                txid   TEXT NOT NULL,
                PRIMARY KEY (rid, height, txid)
            );
            CREATE INDEX IF NOT EXISTS idx_tx_height ON tx(height);
            CREATE INDEX IF NOT EXISTS idx_ac_tx_rid_height ON account_tx(rid, height);
        "#).await?;
        Ok(())
    }

    pub async fn record_tx(
        &self,
        txid: &str,
        height: u64,
        from: &str,
        to: &str,
        amount: u64,
        nonce: u64,
        ts: Option<u64>
    ) -> Result<()> {
        let mut client = self.pool.get().await?; // <- нужен mut для build_transaction()
        let stmt1 = client.prepare_cached(
            "INSERT INTO tx(txid,height,from_rid,to_rid,amount,nonce,ts)
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING"
        ).await?;
        let stmt2 = client.prepare_cached(
            "INSERT INTO account_tx(rid,height,txid)
             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING"
        ).await?;

        let h = height as i64;
        let a = amount as i64;
        let n = nonce as i64;
        let t = ts.map(|v| v as i64);

        let tr = client.build_transaction().start().await?;
        tr.execute(&stmt1, &[&txid, &h, &from, &to, &a, &n, &t]).await?;
        tr.execute(&stmt2, &[&from, &h, &txid]).await?;
        tr.execute(&stmt2, &[&to,   &h, &txid]).await?;
        tr.commit().await?;
        Ok(())
    }

    pub async fn history_page(&self, rid: &str, page: u32, per_page: u32) -> Result<Vec<serde_json::Value>> {
        let client = self.pool.get().await?;
        let per = per_page.clamp(1, 1000) as i64;
        let offset = (page as i64) * per;
        let stmt = client.prepare_cached(r#"
            SELECT t.txid,t.height,t.from_rid,t.to_rid,t.amount,t.nonce,t.ts
            FROM account_tx a JOIN tx t ON t.txid=a.txid
            WHERE a.rid=$1
            ORDER BY t.height DESC
            LIMIT $2 OFFSET $3
        "#).await?;
        let rows = client.query(&stmt, &[&rid, &per, &offset]).await?;
        Ok(rows.iter().map(|r| {
            serde_json::json!({
                "txid":   r.get::<_, String>(0),
                "height": r.get::<_, i64>(1),
                "from":   r.get::<_, String>(2),
                "to":     r.get::<_, String>(3),
                "amount": r.get::<_, i64>(4),
                "nonce":  r.get::<_, i64>(5),
                "ts":     r.get::<_, Option<i64>>(6),
            })
        }).collect())
    }

    pub async fn get_tx(&self, txid: &str) -> Result<Option<serde_json::Value>> {
        let client = self.pool.get().await?;
        let stmt = client.prepare_cached(
            "SELECT txid,height,from_rid,to_rid,amount,nonce,ts FROM tx WHERE txid=$1"
        ).await?;
        let row = client.query_opt(&stmt, &[&txid]).await?;
        Ok(row.map(|r| serde_json::json!({
            "txid":   r.get::<_, String>(0),
            "height": r.get::<_, i64>(1),
            "from":   r.get::<_, String>(2),
            "to":     r.get::<_, String>(3),
            "amount": r.get::<_, i64>(4),
            "nonce":  r.get::<_, i64>(5),
            "ts":     r.get::<_, Option<i64>>(6),
        })))
    }
}

```

---

### `/root/logos_lrb/node/src/archive/sqlite.rs`

```rust
use anyhow::Result;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

#[derive(Clone)]
pub struct ArchiveSqlite { pool: Pool<SqliteConnectionManager> }

impl ArchiveSqlite {
    pub fn new_from_env() -> Option<Self> {
        let path = std::env::var("LRB_ARCHIVE_PATH").ok()?;
        let mgr  = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(8).build(mgr).ok()?;
        let a = Self { pool };
        a.ensure_schema().ok()?;
        Some(a)
    }
    fn conn(&self) -> Result<PooledConnection<SqliteConnectionManager>> { Ok(self.pool.get()?) }
    fn ensure_schema(&self) -> Result<()> {
        let c = self.conn()?;
        c.execute_batch(r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS tx (txid TEXT PRIMARY KEY, height INTEGER, from_rid TEXT, to_rid TEXT, amount INTEGER, nonce INTEGER, ts INTEGER);
            CREATE TABLE IF NOT EXISTS account_tx (rid TEXT, height INTEGER, txid TEXT, PRIMARY KEY(rid,height,txid));
            CREATE INDEX IF NOT EXISTS idx_tx_height ON tx(height);
            CREATE INDEX IF NOT EXISTS idx_ac_tx_rid_height ON account_tx(rid,height);
        "#)?;
        Ok(())
    }
    pub fn record_tx(&self, txid:&str, h:u64, from:&str, to:&str, amount:u64, nonce:u64, ts:Option<u64>) -> Result<()> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        tx.execute("INSERT OR IGNORE INTO tx(txid,height,from_rid,to_rid,amount,nonce,ts) VALUES(?,?,?,?,?,?,?)",
            params![txid, h as i64, from, to, amount as i64, nonce as i64, ts.map(|v| v as i64)])?;
        tx.execute("INSERT OR IGNORE INTO account_tx(rid,height,txid) VALUES(?,?,?)", params![from, h as i64, txid])?;
        tx.execute("INSERT OR IGNORE INTO account_tx(rid,height,txid) VALUES(?,?,?)", params![to,   h as i64, txid])?;
        tx.commit()?;
        Ok(())
    }
    pub fn history_page(&self, rid:&str, page:u32, per_page:u32) -> Result<Vec<serde_json::Value>> {
        let c = self.conn()?;
        let per = per_page.clamp(1,1000) as i64;
        let offset = (page as i64) * per;
        let mut st = c.prepare(
            "SELECT t.txid,t.height,t.from_rid,t.to_rid,t.amount,t.nonce,t.ts \
             FROM account_tx a JOIN tx t ON t.txid=a.txid \
             WHERE a.rid=? ORDER BY t.height DESC LIMIT ? OFFSET ?")?;
        let rows = st.query_map(params![rid, per, offset], |row| Ok(serde_json::json!({
            "txid": row.get::<_, String>(0)?, "height": row.get::<_, i64>(1)?,
            "from": row.get::<_, String>(2)?, "to": row.get::<_, String>(3)?,
            "amount": row.get::<_, i64>(4)?, "nonce": row.get::<_, i64>(5)?,
            "ts": row.get::<_, Option<i64>>(6)?
        })))?;
        let mut out = Vec::with_capacity(per as usize);
        for it in rows { out.push(it?); }
        Ok(out)
    }
    pub fn get_tx(&self, txid:&str) -> Result<Option<serde_json::Value>> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT txid,height,from_rid,to_rid,amount,nonce,ts FROM tx WHERE txid=?")?;
        let v = st.query_row(params![txid], |r| Ok(serde_json::json!({
            "txid": r.get::<_, String>(0)?, "height": r.get::<_, i64>(1)?,
            "from": r.get::<_, String>(2)?, "to": r.get::<_, String>(3)?,
            "amount": r.get::<_, i64>(4)?, "nonce": r.get::<_, i64>(5)?,
            "ts": r.get::<_, Option<i64>>(6)?
        }))).optional()?;
        Ok(v)
    }
}

```

---

### `/root/logos_lrb/node/src/auth.rs`

```rust
//! Auth: bridge key + HMAC + anti-replay + admin stub
use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn assert_secrets_on_start() -> Result<()> {
    for k in ["LRB_JWT_SECRET","LRB_BRIDGE_KEY"] {
        let v = std::env::var(k).map_err(|_| anyhow!("{k} not set"))?;
        let bad = ["", "change_me", "changeme", "default", "dev_secret"];
        if bad.iter().any(|b| v.eq_ignore_ascii_case(b)) { return Err(anyhow!("{k} insecure")); }
    }
    Ok(())
}

// Совместимость для admin.rs (минимальная проверка заголовка)
pub fn require_admin(_headers:&HeaderMap) -> Result<()> {
    // при желании тут можно проверить X-Admin-JWT
    Ok(())
}

pub fn require_bridge_key(headers: &HeaderMap) -> Result<()> {
    let expect = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY not set"))?;
    let got = headers.get("X-Bridge-Key").ok_or_else(|| anyhow!("missing X-Bridge-Key"))?
        .to_str().map_err(|_| anyhow!("invalid X-Bridge-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad bridge key")); }
    Ok(())
}

pub fn verify_hmac_and_nonce(headers: &HeaderMap, body: &[u8], db: &sled::Db) -> Result<()> {
    let key = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY not set"))?;
    let nonce = headers.get("X-Bridge-Nonce").ok_or_else(|| anyhow!("missing X-Bridge-Nonce"))?
        .to_str().map_err(|_| anyhow!("bad nonce"))?;
    let sign  = headers.get("X-Bridge-Sign").ok_or_else(|| anyhow!("missing X-Bridge-Sign"))?
        .to_str().map_err(|_| anyhow!("bad sign"))?;

    let tree = db.open_tree("bridge.replay")?;
    let key_n = format!("n:{nonce}");
    if tree.get(&key_n)?.is_some() { return Err(anyhow!("replay")); }

    let mut mac = <Hmac<Sha256>>::new_from_slice(key.as_bytes()).map_err(|_| anyhow!("hmac"))?;
    mac.update(body);
    let got = hex::decode(sign).map_err(|_| anyhow!("sign hex"))?;
    mac.verify_slice(&got).map_err(|_| anyhow!("bad signature"))?;

    tree.insert(key_n.as_bytes(), &[])?;
    Ok(())
}

```

---

### `/root/logos_lrb/node/src/bridge_journal.rs`

```rust
//! Durable journal for rToken bridge (idempotent ops + retries) on sled.

use serde::{Serialize,Deserialize};
use sled::IVec;
use anyhow::{Result,anyhow};
use std::time::{SystemTime,UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpKind { Deposit, Redeem }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpStatus { Pending, PayoutSent, Confirmed, Redeemed, Failed }

#[derive(Serialize,Deserialize,Clone)]
pub struct JournalOp{
    pub op_id:String,
    pub kind:OpKind,
    pub rid:String,
    pub amount:u64,
    pub ext_txid:String,     // external chain txid / idempotency key
    pub status:OpStatus,
    pub created_ms:u64,
    pub updated_ms:u64,
    pub retries:u32,
    pub last_error:Option<String>,
}

fn now_ms()->u64{
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

pub struct Journal{
    ops:   sled::Tree,      // j:<op_id> -> JournalOp
    idx:   sled::Tree,      // x:<ext_txid> -> op_id (idempotency)
    retry: sled::Tree,      // r:<op_id> -> next_retry_ms
}

impl Journal{
    pub fn open(db:&sled::Db)->Result<Self>{
        Ok(Self{
            ops:   db.open_tree("bridge_journal.ops")?,
            idx:   db.open_tree("bridge_journal.idx")?,
            retry: db.open_tree("bridge_journal.retry")?,
        })
    }

    fn ser<T:Serialize>(v:&T)->Vec<u8>{ serde_json::to_vec(v).unwrap() }
    fn de<T:for<'a> Deserialize<'a>>(v:&IVec)->T{ serde_json::from_slice(v).unwrap() }

    pub fn begin(&self, kind:OpKind, rid:&str, amount:u64, ext:&str)->Result<JournalOp>{
        if let Some(opid) = self.idx.get(format!("x:{ext}"))?{
            let id = std::str::from_utf8(&opid).unwrap();
            return self.get_by_id(id);
        }
        let op_id = blake3::hash(
            format!("{kind:?}:{rid}:{amount}:{ext}:{:?}", now_ms()).as_bytes()
        ).to_hex().to_string();

        let op = JournalOp{
            op_id: op_id.clone(),
            kind, rid: rid.to_string(), amount,
            ext_txid: ext.to_string(),
            status: OpStatus::Pending,
            created_ms: now_ms(), updated_ms: now_ms(),
            retries:0, last_error:None
        };

        self.ops.insert(format!("j:{op_id}"), Self::ser(&op))?;
        self.idx.insert(format!("x:{ext}"), op_id.as_bytes())?;
        Ok(op)
    }

    pub fn set_status(&self, op_id:&str, status:OpStatus, err:Option<String>)->Result<()>{
        let key = format!("j:{op_id}");
        let Some(v)=self.ops.get(&key)? else { return Err(anyhow!("op not found")); };
        let mut op:JournalOp = Self::de(&v);
        op.status = status;
        op.updated_ms = now_ms();
        op.last_error = err;
        self.ops.insert(key, Self::ser(&op))?;
        Ok(())
    }

    pub fn schedule_retry(&self, op_id:&str, delay_ms:u64)->Result<()>{
        let when = now_ms()+delay_ms;
        self.retry.insert(format!("r:{op_id}"), when.to_be_bytes().to_vec())?;
        Ok(())
    }

    pub fn due_retries(&self, limit:usize)->Result<Vec<String>>{
        let now = now_ms();
        let mut out=Vec::new();
        for kv in self.retry.iter(){
            let (k,v) = kv?;
            if v.len()==8 {
                let when = u64::from_be_bytes(v.as_ref().try_into().unwrap());
                if when <= now {
                    let key = std::str::from_utf8(&k).unwrap().to_string(); // r:<op_id>
                    let op_id = key[2..].to_string();
                    out.push(op_id);
                    if out.len()>=limit { break; }
                }
            }
        }
        Ok(out)
    }

    pub fn clear_retry(&self, op_id:&str)->Result<()>{
        self.retry.remove(format!("r:{op_id}"))?;
        Ok(())
    }

    pub fn get_by_id(&self, op_id:&str)->Result<JournalOp>{
        let Some(v)=self.ops.get(format!("j:{op_id}"))? else { return Err(anyhow!("op not found")); };
        Ok(Self::de(&v))
    }

    pub fn get_by_ext(&self, ext:&str)->Result<Option<JournalOp>>{
        if let Some(opid)=self.idx.get(format!("x:{ext}"))?{
            let id = std::str::from_utf8(&opid).unwrap();
            return Ok(Some(self.get_by_id(id)?));
        }
        Ok(None)
    }

    pub fn stats(&self)->Result<(u64,u64,u64)>{
        let (mut pending, mut confirmed, mut redeemed) = (0u64,0u64,0u64);
        for kv in self.ops.iter(){
            let (_k,v)=kv?;
            let op:JournalOp = Self::de(&v);
            match op.status{
                OpStatus::Pending      => pending   += 1,
                OpStatus::PayoutSent   => pending   += 1, // считаем как pending
                OpStatus::Confirmed    => confirmed += 1,
                OpStatus::Redeemed     => redeemed  += 1,
                OpStatus::Failed       => {}
            }
        }
        Ok((pending, confirmed, redeemed))
    }
}

```

---

### `/root/logos_lrb/node/src/bridge.rs`

```rust
//! rToken bridge: durable journal + idempotency + retry worker + external payout (Send-safe)

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{warn,error};

use crate::{state::AppState, metrics};
use crate::bridge_journal::{Journal, OpKind, OpStatus, JournalOp};
use crate::payout_adapter::PayoutAdapter;

#[derive(Deserialize)]
pub struct DepositReq { pub rid:String, pub amount:u64, pub ext_txid:String }
#[derive(Deserialize)]
pub struct RedeemReq  { pub rid:String, pub amount:u64, pub ext_txid:String }

#[inline]
fn journal(st:&AppState)->Journal { Journal::open(st.sled()).expect("journal") }

/* -------------------- DEPOSIT (strict idempotent) -------------------- */
pub async fn deposit(State(st):State<Arc<AppState>>, Json(req):Json<DepositReq>) -> (StatusCode,String){
    let j = journal(&st);

    // begin() создаёт новую опку или возвращает существующую по ext_txid
    let op = match j.begin(OpKind::Deposit, &req.rid, req.amount, &req.ext_txid){
        Ok(op)=>op, Err(e)=>return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"journal_begin:{e}\"}}")),
    };
    metrics::inc_bridge("deposit","begin");

    // Idempotency по статусу: повтор «OK» если уже проведено
    match op.status {
        OpStatus::Confirmed | OpStatus::Redeemed => {
            metrics::inc_bridge("deposit","idempotent_ok");
            return (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id));
        }
        _ => {}
    }

    // Кредитуем ТОЛЬКО когда статус Pending/Failed (guard не пересекает await)
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
    }

    let _ = j.set_status(&op.op_id, OpStatus::Confirmed, None);
    metrics::inc_bridge("deposit","confirmed");
    (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id))
}

/* -------------------- REDEEM (idempotent on ext_txid, payout async) -------------------- */
pub async fn redeem(State(st):State<Arc<AppState>>, Json(req):Json<RedeemReq>) -> (StatusCode,String){
    let j = journal(&st);
    let op = match j.begin(OpKind::Redeem, &req.rid, req.amount, &req.ext_txid){
        Ok(op)=>op, Err(e)=>return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"journal_begin:{e}\"}}")),
    };
    metrics::inc_bridge("redeem","begin");

    // если уже Redeemed — повтор «OK»
    if matches!(op.status, OpStatus::Redeemed) {
        metrics::inc_bridge("redeem","idempotent_ok");
        return (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id));
    }

    // burn локально (без await внутри)
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
    }

    // внешний payout
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

/* -------------------- Retry worker -------------------- */
async fn retry_deposit(st:&AppState, j:&Journal, op:&JournalOp){
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
        Ok(adapter) => match adapter.send_payout(&op.rid, op.amount, &op.ext_txid).await {
            Ok(()) => { let _=j.set_status(&op.op_id, OpStatus::Redeemed, None); metrics::inc_bridge("redeem","redeemed"); let _=j.clear_retry(&op.op_id); }
            Err(e) => { warn!("retry payout error: {e}"); let _=j.schedule_retry(&op.op_id, 90_000); }
        },
        Err(e) => { warn!("retry payout adapter init: {e}"); let _=j.schedule_retry(&op.op_id, 90_000); }
    }
}

pub async fn retry_worker(st:Arc<AppState>){
    let j = journal(&st);
    loop {
        if let Ok(list) = j.due_retries(100){
            for op_id in list {
                if let Ok(op) = j.get_by_id(&op_id){
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

/* -------------------- Health -------------------- */
pub async fn health(State(st):State<Arc<AppState>>)->(StatusCode,String){
    let j = journal(&st);
    match j.stats(){
        Ok((p,c,r)) => (StatusCode::OK, format!("{{\"pending\":{p},\"confirmed\":{c},\"redeemed\":{r}}}")),
        Err(e)      => (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"{e}\"}}")),
    }
}

```

---

### `/root/logos_lrb/node/src/bridge_settlement.rs`

```rust
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use sled::IVec;

use crate::state::AppState;

/// Скан журнала выплат. Идемпотентен, без паник.
pub fn spawn(app: Arc<AppState>) {
    let db = app.sled.clone();

    tokio::spawn(async move {
        loop {
            for kv in db.scan_prefix(b"bridge.settle:") {
                if let Ok((k, v)) = kv {
                    let _key: IVec = k;
                    let _val: IVec = v;
                    // TODO: разбор и попытка выплаты; пока — no-op
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
    });
}

```

---

### `/root/logos_lrb/node/src/fork.rs`

```rust
#![allow(dead_code)]
//! Fork-choice: минимальный детерминированный выбор на базе высоты/хэша.
//! Совместим с текущими типами ядра (Block из lrb_core::types).

use lrb_core::types::Block;

/// Выбор лучшей ветви из набора кандидатов.
/// Правила:
/// 1) Бóльшая высота предпочтительнее.
/// 2) При равной высоте — лексикографически наименьший block_hash.
pub fn choose_best<'a>(candidates: &'a [Block]) -> Option<&'a Block> {
    candidates
        .iter()
        .max_by(|a, b| match a.height.cmp(&b.height) {
            core::cmp::Ordering::Equal => a.block_hash.cmp(&b.block_hash).reverse(),
            ord => ord,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mk(h: u64, hash: &str) -> Block {
        Block {
            height: h,
            block_hash: hash.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn pick_by_height_then_hash() {
        let a = mk(10, "ff");
        let b = mk(12, "aa");
        let c = mk(12, "bb");
        let out = choose_best(&[a, b.clone(), c]).unwrap();
        assert_eq!(out.height, 12);
        assert_eq!(out.block_hash, "aa");
    }
}

```

---

### `/root/logos_lrb/node/src/gossip.rs`

```rust
#![allow(dead_code)]
//! Gossip-утилиты: сериализация/десериализация блоков для пересылки по сети.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use blake3;
use hex;
use lrb_core::{phase_filters::block_passes_phase, types::Block};
use serde::{Deserialize, Serialize};

/// Конверт для публикации блока в сети Gossip.
#[derive(Serialize, Deserialize)]
pub struct GossipEnvelope {
    pub topic: String,
    pub payload_b64: String,
    pub sigma_hex: String,
    pub height: u64,
}

/// Энкодим блок: base64-пейлоад, sigma_hex = blake3(payload).
pub fn encode_block(topic: &str, blk: &Block) -> anyhow::Result<GossipEnvelope> {
    let bytes = serde_json::to_vec(blk)?;
    let sigma_hex = hex::encode(blake3::hash(&bytes).as_bytes());
    Ok(GossipEnvelope {
        topic: topic.to_string(),
        payload_b64: B64.encode(bytes),
        sigma_hex,
        height: blk.height,
    })
}

/// Декодим блок из конверта.
pub fn decode_block(env: &GossipEnvelope) -> anyhow::Result<Block> {
    let bytes = B64.decode(&env.payload_b64)?;
    let blk: Block = serde_json::from_slice(&bytes)?;
    Ok(blk)
}

/// Пропускает ли блок фазовый фильтр (решение — по самому блоку).
pub fn pass_phase_filter(env: &GossipEnvelope) -> bool {
    if let Ok(blk) = decode_block(env) {
        block_passes_phase(&blk)
    } else {
        false
    }
}

```

---

### `/root/logos_lrb/node/src/guard.rs`

```rust
use axum::{body::Body, http::Request, middleware::Next, response::Response};
use rand::{thread_rng, Rng};
use std::time::Duration;

/// Лёгкий фазовый «шум»: джиттер 0–7мс для submit/stake/bridge путей
pub async fn rate_limit_mw(req: Request<Body>, next: Next) -> Response {
    let p = req.uri().path();
    if p.starts_with("/submit_tx") || p.starts_with("/stake/") || p.starts_with("/bridge/") {
        let jitter = thread_rng().gen_range(0..=7);
        tokio::time::sleep(Duration::from_millis(jitter)).await;
    }
    next.run(req).await
}

```

---

### `/root/logos_lrb/node/src/health.rs`

```rust
//! Health endpoints: /livez (жив) и /readyz (готов)

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use std::sync::Arc;
use crate::state::AppState;

/// Публичная структура, т.к. используется в сигнатуре `Json<Ready>`
#[derive(Serialize)]
pub struct Ready {
    pub db: bool,
    pub archive: bool,
    pub payout_cfg: bool,
}

/// /livez — просто «жив ли процесс»
pub async fn livez() -> &'static str { "ok" }

/// /readyz — готовность: sled открыт; archive (если настроен) доступен; payout-адаптер сконфигурирован
pub async fn readyz(State(st):State<Arc<AppState>>) -> (StatusCode, Json<Ready>) {
    // sled: быстрая эвристика — БД поднялась и восстановилась
    let db_ok = st.sled().was_recovered();
    // archive: настроен ли (при желании можно сделать query .get().await)
    let arch_ok = st.archive.is_some();
    // payout-конфиг
    let payout_ok = std::env::var("BRIDGE_PAYOUT_URL").is_ok() && std::env::var("LRB_BRIDGE_KEY").is_ok();

    let body = Ready{ db: db_ok, archive: arch_ok, payout_cfg: payout_ok };
    let status = if db_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(body))
}

```

---

### `/root/logos_lrb/node/src/lib.rs`

```rust
//! LOGOS node library crate — корневые модули и реэкспорты

pub mod api;
pub mod admin;
pub mod archive;
pub mod auth;
pub mod bridge;
pub mod bridge_journal;      // ← добавили модуль журнала моста
pub mod gossip;
pub mod guard;
pub mod metrics;
pub mod openapi;
pub mod peers;
pub mod producer;
pub mod state;
pub mod stake;
pub mod storage;
pub mod version;
pub mod wallet;

// точечные реэкспорты (по мере надобности)
pub use metrics::prometheus as metrics_prometheus;
pub use version::get as version_get;

```

---

### `/root/logos_lrb/node/src/main.rs`

```rust
use axum::{routing::{get, post}, Router};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::sync::Arc;
use tracing::{info, warn};

mod api;
mod bridge;
mod bridge_journal;
mod payout_adapter;   // адаптер выплат (используется в bridge)
mod admin;
mod gossip;
mod state;
mod peers;
mod guard;
mod metrics;
mod version;
mod storage;
mod archive;
mod openapi;
mod auth;
mod stake;
mod stake_claim;      // реальный claim_settle (зачисление в ledger)
mod health;           // /livez + /readyz
mod wallet;
mod producer;

fn router(app_state: Arc<state::AppState>) -> Router {
    Router::new()
        // --- public ---
        .route("/healthz", get(api::healthz))
        .route("/livez",  get(health::livez))       // liveness
        .route("/readyz", get(health::readyz))      // readiness
        .route("/head",    get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx",       post(api::submit_tx))
        .route("/submit_tx_batch", post(api::submit_tx_batch))
        .route("/economy",         get(api::economy))
        .route("/history/:rid",    get(api::history))

        // --- archive API (PG) ---
        .route("/archive/blocks",      get(api::archive_blocks))
        .route("/archive/txs",         get(api::archive_txs))
        .route("/archive/history/:rid",get(api::archive_history))
        .route("/archive/tx/:txid",    get(api::archive_tx))

        // --- staking wrappers (совместимость с фронтом) ---
        .route("/stake/delegate",   post(api::stake_delegate))
        .route("/stake/undelegate", post(api::stake_undelegate))
        .route("/stake/claim",      post(api::stake_claim))
        .route("/stake/my/:rid",    get(api::stake_my))
        // реальный settle награды в ledger
        .route("/stake/claim_settle", post(stake_claim::claim_settle))

        // --- bridge (durable + payout, Send-safe) ---
        // JSON endpoints для mTLS+HMAC периметра (Nginx rewrites → сюда)
        .route("/bridge/deposit_json", post(bridge::deposit_json))
        .route("/bridge/redeem_json",  post(bridge::redeem_json))
        // Оставляем и «обычные» (внутренние) эндпоинты через безопасные замыкания
        .route(
            "/bridge/deposit",
            post(|st: axum::extract::State<Arc<state::AppState>>,
                  body: axum::Json<bridge::DepositReq>| async move {
                bridge::deposit(st, body).await
            })
        )
        .route(
            "/bridge/redeem",
            post(|st: axum::extract::State<Arc<state::AppState>>,
                  body: axum::Json<bridge::RedeemReq>| async move {
                bridge::redeem(st, body).await
            })
        )
        .route("/health/bridge",  get(bridge::health))

        // --- version / metrics / openapi ---
        .route("/version",     get(version::get))
        .route("/metrics",     get(metrics::prometheus))
        .route("/openapi.json",get(openapi::serve))

        // --- admin ---
        .route("/admin/set_balance", post(admin::set_balance))
        .route("/admin/bump_nonce",  post(admin::bump_nonce))
        .route("/admin/set_nonce",   post(admin::set_nonce))
        .route("/admin/mint",        post(admin::mint))
        .route("/admin/burn",        post(admin::burn))

        // --- legacy (если используются) ---
        .merge(wallet::routes())
        .merge(stake::routes())

        // --- layers/state ---
        .with_state(app_state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(axum::middleware::from_fn(guard::rate_limit_mw))
                .layer(axum::middleware::from_fn(metrics::track))
        )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,hyper=warn")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // secrets/keys
    auth::assert_secrets_on_start().expect("secrets missing");

    // state
    let app_state = Arc::new(state::AppState::new()?);

    // optional archive
    if let Some(ar) = crate::archive::Archive::new_from_env().await {
        unsafe {
            let p = Arc::as_ptr(&app_state) as *mut state::AppState;
            (*p).archive = Some(ar);
        }
        info!("archive backend initialized");
    } else {
        warn!("archive disabled");
    }

    // producer
    info!("producer start");
    let _producer = producer::run(app_state.clone());

    // bridge retry worker
    tokio::spawn(bridge::retry_worker(app_state.clone()));

    // bind & serve
    let addr = state::bind_addr();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("logos_node listening on {addr}");
    axum::serve(listener, router(app_state)).await?;
    Ok(())
}

```

---

### `/root/logos_lrb/node/src/metrics.rs`

```rust
use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::IntoResponse,
    http::StatusCode,
};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramVec, IntCounter, IntCounterVec, IntGauge, Registry, TextEncoder,
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
};
use std::time::Instant;

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

// ---- HTTP ----
static HTTP_REQS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("logos_http_requests_total","HTTP reqs",&["method","path","status"]).unwrap()
});
static HTTP_LAT: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!("logos_http_duration_seconds","HTTP latency",&["method","path","status"],
        prometheus::exponential_buckets(0.001,2.0,14).unwrap()).unwrap()
});

// ---- Chain ----
static BLOCKS_TOTAL: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("logos_blocks_produced_total","Blocks total").unwrap());
static HEAD_HEIGHT: Lazy<IntGauge>    = Lazy::new(|| register_int_gauge!("logos_head_height","Head").unwrap());
static FINAL_HEIGHT: Lazy<IntGauge>   = Lazy::new(|| register_int_gauge!("logos_finalized_height","Finalized").unwrap());

// ---- Tx ----
static TX_ACCEPTED: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("logos_tx_accepted_total","Accepted tx").unwrap());
static TX_REJECTED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("logos_tx_rejected_total","Rejected tx",&["reason"]).unwrap()
});

// ---- Bridge (durable) ----
static BRIDGE_OPS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("logos_bridge_ops_total","Bridge ops",&["kind","status"]).unwrap()
});

// ---- Archive backpressure ----
static ARCHIVE_QUEUE: Lazy<IntGauge> = Lazy::new(|| register_int_gauge!("logos_archive_queue","Archive queue depth").unwrap());

fn norm(p:&str)->String{
    if p.starts_with("/balance/") {"/balance/:rid".into()}
    else if p.starts_with("/history/"){"/history/:rid".into()}
    else if p.starts_with("/stake/my/"){"/stake/my/:rid".into()}
    else {p.to_string()}
}

pub async fn track(req: Request<Body>, next: Next) -> axum::response::Response {
    let m=req.method().as_str().to_owned();
    let p=norm(req.uri().path());
    let t=Instant::now();
    let res=next.run(req).await;
    let s=res.status().as_u16().to_string();
    HTTP_REQS.with_label_values(&[&m,&p,&s]).inc();
    HTTP_LAT.with_label_values(&[&m,&p,&s]).observe(t.elapsed().as_secs_f64());
    res
}

pub async fn prometheus()->impl IntoResponse{
    let mfs=REGISTRY.gather();
    let mut buf=Vec::new();
    let enc=TextEncoder::new();
    if let Err(_)=enc.encode(&mfs,&mut buf){ return (StatusCode::INTERNAL_SERVER_ERROR,"encode error").into_response(); }
    match String::from_utf8(buf){
        Ok(body)=>(StatusCode::OK,body).into_response(),
        Err(_)=>(StatusCode::INTERNAL_SERVER_ERROR,"utf8 error").into_response(),
    }
}

// API для модулей
pub fn inc_block_produced(){ BLOCKS_TOTAL.inc(); }
pub fn set_chain(h:u64, f:u64){ HEAD_HEIGHT.set(h as i64); FINAL_HEIGHT.set(f as i64); }
pub fn inc_tx_accepted(){ TX_ACCEPTED.inc(); }
pub fn inc_tx_rejected(reason:&'static str){ TX_REJECTED.with_label_values(&[reason]).inc(); }
pub fn inc_bridge(kind:&'static str, status:&'static str){ BRIDGE_OPS.with_label_values(&[kind,status]).inc(); }
pub fn set_archive_queue(n:i64){ ARCHIVE_QUEUE.set(n); }

// Совместимость со старым кодом
#[allow(dead_code)] pub fn inc_total(_label:&str){}

```

---

### `/root/logos_lrb/node/src/openapi.json`

```json
{
  "openapi": "3.0.3",
  "info": { "title": "LOGOS LRB Node API", "version": "0.1.0" },
  "servers": [{ "url": "http://{host}", "variables": { "host": { "default": "localhost:8080" } } }],
  "paths": {
    "/healthz": { "get": { "summary": "Liveness", "responses": { "200": { "description": "OK" } } } },
    "/livez":   { "get": { "summary": "Liveness", "responses": { "200": { "description": "OK" } } } },
    "/readyz":  { "get": { "summary": "Readiness", "responses": { "200": { "description": "Ready" } } } },
    "/version": { "get": { "summary": "Build info", "responses": { "200": { "description": "JSON" } } } },
    "/metrics": { "get": { "summary": "Prometheus metrics", "responses": { "200": { "description": "text/plain" } } } },

    "/head": {
      "get": {
        "summary": "Chain head",
        "responses": {
          "200": { "description": "Height/finalized",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HeadResp" },
            "examples": { "ok": { "value": { "height": 123, "finalized": false } } } } }
          }
        }
      }
    },

    "/balance/{rid}": {
      "get": {
        "summary": "Account state",
        "parameters": [{ "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": {
          "200": { "description": "Balance/nonce",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BalanceResp" },
            "examples": { "ok": { "value": { "rid": "A...Z", "balance": 1000000, "nonce": 5 } } } } }
          },
          "404": { "description": "Unknown RID" }
        }
      }
    },

    "/submit_tx_batch": {
      "post": {
        "summary": "Submit batch of signed transactions",
        "requestBody": { "required": true, "content": { "application/json": {
          "schema": { "$ref": "#/components/schemas/SubmitTxBatchReq" },
          "examples": { "one": { "value": { "txs": [
            { "from":"A...Z","to":"B...Y","amount":1234,"nonce":6,"sig_hex":"<ed25519 hex>" }
          ] } } } } } },
        "responses": {
          "200": { "description": "Accepted/rejected with details",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitTxBatchResp" },
            "examples": { "ok": { "value": {
              "accepted": 1, "rejected": 0, "new_height": 124,
              "results": [{ "idx": 0, "status": "accepted", "code": 0, "reason": "ok" }]
            } } } } } }
        }
      }
    },

    "/debug_canon": {
      "post": {
        "summary": "Canonical JSON for signing (server-side canonicalization)",
        "requestBody": { "required": true, "content": { "application/json": {
          "schema": { "$ref": "#/components/schemas/DebugCanonReq" },
          "examples": { "tx": { "value": { "tx": { "from":"A...Z","to":"B...Y","amount":1,"nonce":1 } } } }
        } } },
        "responses": { "200": {
          "description": "Canon hex",
          "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DebugCanonResp" } } }
        } }
      }
    },

    "/faucet": {
      "post": {
        "summary": "DEV only. Mint LGN to RID",
        "requestBody": { "required": true, "content": { "application/json": {
          "schema": { "$ref": "#/components/schemas/FaucetReq" }
        } } },
        "responses": {
          "200": { "description": "Granted", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/FaucetResp" } } } },
          "400": { "description": "Bad request" }
        }
      }
    }
  },

  "components": {
    "schemas": {
      "TxIn": {
        "type": "object",
        "required": ["from", "to", "amount", "nonce", "sig_hex"],
        "properties": {
          "from":   { "type": "string", "description": "RID (base58 pubkey)" },
          "to":     { "type": "string", "description": "RID (base58 pubkey)" },
          "amount": { "type": "integer", "format": "uint64", "minimum": 1 },
          "nonce":  { "type": "integer", "format": "uint64" },
          "sig_hex":{ "type": "string", "description": "Ed25519 signature hex over canonical bytes from /debug_canon" }
        }
      },

      "SubmitTxBatchReq": { "type": "object", "required": ["txs"], "properties": { "txs": { "type": "array", "minItems": 1, "items": { "$ref": "#/components/schemas/TxIn" } } } },

      "TxResult": {
        "type": "object",
        "required": ["idx", "status", "code", "reason"],
        "properties": {
          "idx":    { "type": "integer" },
          "status": { "type": "string", "enum": ["accepted", "rejected"] },
          "code":   { "type": "integer", "enum": [0, 400, 401, 402, 409] },
          "reason": { "type": "string", "enum": ["ok", "bad_rid", "bad_sig", "bad_canon", "bad_nonce", "insufficient_funds"] }
        }
      },

      "SubmitTxBatchResp": {
        "type": "object",
        "required": ["accepted", "rejected", "new_height", "results"],
        "properties": {
          "accepted":  { "type": "integer" },
          "rejected":  { "type": "integer" },
          "new_height":{ "type": "integer", "format": "uint64" },
          "results":   { "type": "array", "items": { "$ref": "#/components/schemas/TxResult" } }
        }
      },

      "HeadResp":   { "type": "object", "properties": { "height": { "type": "integer" }, "finalized": { "type": "boolean" } } },
      "BalanceResp":{ "type": "object", "properties": { "rid": { "type": "string" }, "balance": { "type": "integer" }, "nonce": { "type": "integer" } } },

      "DebugCanonReq":  { "type": "object", "properties": { "tx": { "type": "object" } } },
      "DebugCanonResp": { "type": "object", "required": ["canon_hex"], "properties": { "canon_hex": { "type": "string" } } },

      "FaucetReq":  { "type": "object", "required": ["rid", "amount"], "properties": { "rid": { "type": "string" }, "amount": { "type": "integer" } } },
      "FaucetResp": { "type": "object", "properties": { "granted": { "type": "integer" }, "rid": { "type": "string" } } }
    }
  }
}

```

---

### `/root/logos_lrb/node/src/openapi/openapi.json`

```json
{
  "openapi": "3.0.3",
  "info": { "title": "LOGOS LRB API", "version": "0.1.0" },
  "paths": {
    "/healthz": {
      "get": { "summary": "health", "responses": { "200": { "description": "OK" } } }
    },
    "/livez": {
      "get": { "summary": "liveness", "responses": { "200": { "description": "alive" } } }
    },
    "/readyz": {
      "get": {
        "summary": "readiness",
        "responses": {
          "200": { "description": "ready" },
          "503": { "description": "not ready" }
        }
      }
    },
    "/version": { "get": { "summary": "build info", "responses": { "200": { "description": "OK" } } } },
    "/metrics": { "get": { "summary": "prometheus metrics", "responses": { "200": { "description": "OK" } } } },

    "/head": {
      "get": {
        "summary": "current head heights",
        "responses": {
          "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Head" } } } }
        }
      }
    },

    "/submit_tx": {
      "post": {
        "summary": "submit transaction (Ed25519 verified)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TxIn" } } } },
        "responses": {
          "200": { "description": "accepted", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitResult" } } } },
          "401": { "description": "bad signature" },
          "409": { "description": "nonce reuse" }
        }
      }
    },

    "/submit_tx_batch": {
      "post": {
        "summary": "submit batch of transactions (Ed25519 verified)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitBatchReq" } } } },
        "responses": {
          "200": { "description": "per-item results", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/SubmitBatchItem" } } } } }
        }
      }
    },

    "/archive/blocks": {
      "get": {
        "summary": "recent blocks",
        "parameters": [
          { "name": "limit", "in": "query", "schema": { "type": "integer" } },
          { "name": "before_height", "in": "query", "schema": { "type": "integer" } }
        ],
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/archive/txs": {
      "get": {
        "summary": "recent txs",
        "parameters": [
          { "name": "limit", "in": "query", "schema": { "type": "integer" } },
          { "name": "rid", "in": "query", "schema": { "type": "string" } },
          { "name": "before_ts", "in": "query", "schema": { "type": "integer" } }
        ],
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/archive/history/{rid}": {
      "get": {
        "summary": "history by rid",
        "parameters": [ { "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/archive/tx/{txid}": {
      "get": {
        "summary": "tx by id",
        "parameters": [ { "name": "txid", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "OK" }, "404": { "description": "not found" } }
      }
    },

    "/stake/delegate": {
      "post": {
        "summary": "delegate (compat wrapper)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/stake/undelegate": {
      "post": {
        "summary": "undelegate (compat wrapper)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/stake/claim": {
      "post": {
        "summary": "claim rewards (compat wrapper)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/stake/my/{rid}": {
      "get": {
        "summary": "my delegations + rewards (compat wrapper)",
        "parameters": [ { "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/stake/claim_settle": {
      "post": {
        "summary": "settle reward into ledger",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimSettle" } } } },
        "responses": { "200": { "description": "OK" } }
      }
    },

    "/bridge/deposit_json": {
      "post": {
        "summary": "bridge deposit (mTLS + HMAC)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeDeposit" } } } },
        "responses": { "200": { "description": "idempotent OK" }, "202": { "description": "queued/retry" }, "401": { "description": "unauthorized (key/HMAC/nonce)" } }
      }
    },
    "/bridge/redeem_json": {
      "post": {
        "summary": "bridge redeem (mTLS + HMAC)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeRedeem" } } } },
        "responses": { "200": { "description": "ok" }, "202": { "description": "queued/retry" }, "401": { "description": "unauthorized (key/HMAC/nonce)" } }
      }
    }
  },

  "components": {
    "schemas": {
      "Head": {
        "type": "object",
        "required": ["height","finalized"],
        "properties": {
          "height":   { "type": "integer", "format": "uint64" },
          "finalized":{ "type": "integer", "format": "uint64" }
        }
      },
      "Balance": {
        "type": "object",
        "required": ["rid","balance","nonce"],
        "properties": {
          "rid":     { "type": "string" },
          "balance": { "type": "integer", "format": "uint128" },
          "nonce":   { "type": "integer", "format": "uint64" }
        }
      },
      "TxIn": {
        "type": "object",
        "required": ["from","to","amount","nonce","sig_hex"],
        "properties": {
          "from":    { "type": "string", "description": "base58(pubkey)" },
          "to":      { "type": "string" },
          "amount":  { "type": "integer", "format": "uint64" },
          "nonce":   { "type": "integer", "format": "uint64" },
          "sig_hex": { "type": "string" },
          "memo":    { "type": "string", "nullable": true }
        }
      },
      "SubmitResult": {
        "type": "object",
        "required": ["ok","info"],
        "properties": {
          "ok":   { "type": "boolean" },
          "txid": { "type": "string", "nullable": true },
          "info": { "type": "string" }
        }
      },
      "SubmitBatchReq": {
        "type": "object",
        "required": ["txs"],
        "properties": {
          "txs": { "type": "array", "items": { "$ref": "#/components/schemas/TxIn" } }
        }
      },
      "SubmitBatchItem": {
        "type": "object",
        "required": ["ok","info","index"],
        "properties": {
          "ok":    { "type": "boolean" },
          "txid":  { "type": "string", "nullable": true },
          "info":  { "type": "string" },
          "index": { "type": "integer" }
        }
      },
      "StakeAction": {
        "type": "object",
        "required": ["rid"],
        "properties": {
          "rid":       { "type": "string" },
          "validator": { "type": "string" },
          "amount":    { "type": "integer", "format": "uint64", "nullable": true }
        }
      },
      "ClaimSettle": {
        "type": "object",
        "required": ["rid","amount"],
        "properties": {
          "rid":    { "type": "string" },
          "amount": { "type": "integer", "format": "uint64" }
        }
      },
      "BridgeDeposit": {
        "type": "object",
        "required": ["rid","amount","ext_txid"],
        "properties": {
          "rid":      { "type": "string" },
          "amount":   { "type": "integer", "format": "uint64" },
          "ext_txid": { "type": "string" }
        }
      },
      "BridgeRedeem": {
        "type": "object",
        "required": ["rid","amount","ext_txid"],
        "properties": {
          "rid":      { "type": "string" },
          "amount":   { "type": "integer", "format": "uint64" },
          "ext_txid": { "type": "string" }
        }
      }
    }
  }
}

```

---

### `/root/logos_lrb/node/src/openapi.rs`

```rust
use axum::response::{IntoResponse, Response};
use axum::http::{HeaderValue, StatusCode};

static SPEC: &str = include_str!("../openapi/openapi.json");

pub async fn serve() -> Response {
    let mut resp = (StatusCode::OK, SPEC).into_response();
    let headers = resp.headers_mut();
    let _ = headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp
}

```

---

### `/root/logos_lrb/node/src/payout_adapter.rs`

```rust
//! External payout adapter for rToken redeem (HTTP).
//! ENV:
//!   BRIDGE_PAYOUT_URL   — базовый URL payout-сервиса (https://bridge.example.com)
//!   BRIDGE_PAYOUT_PATH  — относительный путь (по умолчанию: /api/payout)
//!   LRB_BRIDGE_KEY      — общий секрет (заголовок X-Bridge-Key)

use anyhow::{Result,anyhow};
use reqwest::Client;
use serde::Serialize;

#[derive(Clone)]
pub struct PayoutAdapter{
    base: String,
    path: String,
    key:  String,
    http: Client,
}

#[derive(Serialize)]
struct PayoutReq<'a>{
    rid:    &'a str,
    amount: u64,
    ext_txid: &'a str,
}

impl PayoutAdapter{
    pub fn from_env() -> Result<Self>{
        let base = std::env::var("BRIDGE_PAYOUT_URL")
            .map_err(|_| anyhow!("BRIDGE_PAYOUT_URL not set"))?;
        let path = std::env::var("BRIDGE_PAYOUT_PATH").unwrap_or_else(|_| "/api/payout".to_string());
        let key  = std::env::var("LRB_BRIDGE_KEY")
            .map_err(|_| anyhow!("LRB_BRIDGE_KEY not set"))?;
        Ok(Self{ base, path, key, http: Client::new() })
    }

    #[inline]
    fn url(&self)->String { format!("{}{}", self.base.trim_end_matches('/'), self.path) }

    pub async fn send_payout(&self, rid:&str, amount:u64, ext_txid:&str) -> Result<()>{
        let body = PayoutReq{ rid, amount, ext_txid };
        let resp = self.http.post(self.url())
            .header("X-Bridge-Key", &self.key)
            .json(&body)
            .send().await?;

        let status = resp.status();
        let text   = resp.text().await.unwrap_or_default();

        if !status.is_success(){
            return Err(anyhow!("payout_http_{}: {}", status.as_u16(), text));
        }
        Ok(())
    }
}

```

---

### `/root/logos_lrb/node/src/peers.rs`

```rust
#![allow(dead_code)]
#![allow(dead_code)]
use std::time::{SystemTime, UNIX_EPOCH};
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u128)
        .unwrap_or(0)
}

use once_cell::sync::Lazy;
use prometheus::{register_int_gauge, IntGauge};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

static QUARANTINED_GAUGE: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("peers_quarantined", "quarantined peers").unwrap());
static PEERS_TOTAL_GAUGE: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("peers_total", "known peers").unwrap());

#[derive(Clone, Debug)]
pub struct PeerScore {
    pub last_seen_ms: u128,
    pub score_milli: i64,
    pub fails: u32,
    pub dups: u32,
    pub banned_until_ms: u128,
}
impl Default for PeerScore {
    fn default() -> Self {
        Self {
            last_seen_ms: now_ms(),
            score_milli: 0,
            fails: 0,
            dups: 0,
            banned_until_ms: 0,
        }
    }
}

/// Резонансные параметры скоринга
#[derive(Clone)]
pub struct PeerPolicy {
    pub ban_ttl_ms: u128,
    pub decay_ms: u128,
    pub up_tick: i64,
    pub dup_penalty: i64,
    pub invalid_penalty: i64,
    pub ban_threshold_milli: i64,
    pub unban_threshold_milli: i64,
}
impl Default for PeerPolicy {
    fn default() -> Self {
        Self {
            ban_ttl_ms: 60_000,    // 60s карантин
            decay_ms: 10_000,      // каждые 10s подплытие к 0
            up_tick: 150,          // успешный блок/голос +0.150
            dup_penalty: -50,      // дубликат −0.050
            invalid_penalty: -500, // невалидное сообщение −0.500
            ban_threshold_milli: -1500,
            unban_threshold_milli: -300,
        }
    }
}

#[derive(Clone)]
pub struct PeerBook {
    inner: Arc<Mutex<HashMap<String, PeerScore>>>, // pk_b58 -> score
    policy: PeerPolicy,
}
impl PeerBook {
    pub fn new(policy: PeerPolicy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            policy,
        }
    }
    fn entry_mut(&self, _pk: &str) -> std::sync::MutexGuard<'_, HashMap<String, PeerScore>> {
        self.inner.lock().unwrap()
    }

    pub fn on_success(&self, pk: &str) {
        let mut m = self.entry_mut(pk);
        let s = m.entry(pk.to_string()).or_default();
        s.last_seen_ms = now_ms();
        s.score_milli += self.policy.up_tick;
        if s.score_milli > 5000 {
            s.score_milli = 5000;
        }
    }
    pub fn on_duplicate(&self, pk: &str) {
        let mut m = self.entry_mut(pk);
        let s = m.entry(pk.to_string()).or_default();
        s.dups += 1;
        s.score_milli += self.policy.dup_penalty;
        if s.score_milli < self.policy.ban_threshold_milli {
            s.banned_until_ms = now_ms() + self.policy.ban_ttl_ms;
        }
    }
    pub fn on_invalid(&self, pk: &str) {
        let mut m = self.entry_mut(pk);
        let s = m.entry(pk.to_string()).or_default();
        s.fails += 1;
        s.score_milli += self.policy.invalid_penalty;
        s.banned_until_ms = now_ms() + self.policy.ban_ttl_ms;
    }
    pub fn is_quarantined(&self, pk: &str) -> bool {
        let m = self.inner.lock().unwrap();
        m.get(pk)
            .map(|s| now_ms() < s.banned_until_ms)
            .unwrap_or(false)
    }
    pub fn tick(&self) {
        let mut m = self.inner.lock().unwrap();
        let now = now_ms();
        let mut banned = 0;
        for (_k, s) in m.iter_mut() {
            // decay к 0
            if s.score_milli < 0 {
                let dt = (now.saturating_sub(s.last_seen_ms)) as i128;
                if dt > 0 {
                    let steps = (dt as f64 / self.policy.decay_ms as f64).floor() as i64;
                    if steps > 0 {
                        s.score_milli += steps * 50; // +0.050/шаг
                        if s.score_milli > 0 {
                            s.score_milli = 0;
                        }
                        s.last_seen_ms = now;
                    }
                }
            }
            // снять бан, если вышли из «красной зоны»
            if s.banned_until_ms > 0
                && now >= s.banned_until_ms
                && s.score_milli > self.policy.unban_threshold_milli
            {
                s.banned_until_ms = 0;
            }
            if s.banned_until_ms > now {
                banned += 1;
            }
        }
        QUARANTINED_GAUGE.set(banned);
        PEERS_TOTAL_GAUGE.set(m.len() as i64);
    }
}
pub fn spawn_peer_aging(book: PeerBook) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_millis(2000));
        loop {
            t.tick().await;
            book.tick();
        }
    });
}

```

---

### `/root/logos_lrb/node/src/stake_claim.rs`

```rust
use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use std::sync::Arc;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ClaimReq { pub rid:String, pub amount:u64 }

/// Финализация награды: зачисляем в ledger (при необходимости добавь запись в историю)
pub async fn claim_settle(State(st):State<Arc<AppState>>, Json(req):Json<ClaimReq>) -> (StatusCode,String){
    {
        let l = st.ledger.lock();
        let bal = l.get_balance(&req.rid).unwrap_or(0);
        let newb = bal.saturating_add(req.amount);
        if let Err(e) = l.set_balance(&req.rid, newb as u128) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"{e}\"}}"));
        }
        // Если хочешь — вставь спец-tx «reward» в историю (StoredTx).
    }
    (StatusCode::OK, "{\"ok\":true}".into())
}

```

---

### `/root/logos_lrb/node/src/state.rs`

```rust
use std::sync::Arc;
use parking_lot::Mutex;
use anyhow::Result;

pub struct AppState {
    pub ledger: Arc<Mutex<lrb_core::ledger::Ledger>>,
    pub archive: Option<crate::archive::Archive>,
}

impl AppState {
    pub fn new() -> Result<Self> {
        let path = std::env::var("LRB_DATA_PATH").unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());
        let ledger = lrb_core::ledger::Ledger::open(&path)?;
        // Archive: инициализируем позже в async, чтобы не блокировать startup
        Ok(Self { ledger: Arc::new(Mutex::new(ledger)), archive: None })
    }
}

pub fn bind_addr() -> std::net::SocketAddr {
    let s = std::env::var("LRB_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    s.parse().expect("LRB_BIND must be host:port")
}

```

---

### `/root/logos_lrb/node/src/storage.rs`

```rust
use serde::{Deserialize, Serialize};

/// Вход транзакции — соответствуем полям, которые ожидает api.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIn {
    pub from: String,      // RID отправителя
    pub to: String,        // RID получателя
    pub amount: u64,       // количество
    pub nonce: u64,        // обязательный
    pub memo: Option<String>,
    pub sig_hex: String,   // подпись в hex
}

/// Элемент истории для /history/:rid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    pub txid: String,
    pub height: u64,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub ts: Option<u64>,
}

/// Состояние аккаунта (минимум, который использует api.rs)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
}

```

---

### `/root/logos_lrb/node/src/version.rs`

```rust
use axum::{response::IntoResponse, Json};
use serde::Serialize;

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

#[derive(Serialize)]
struct Version {
    version: &'static str,
    git_hash: &'static str,
    git_branch: &'static str,
    built_at: &'static str,
}

pub async fn get() -> impl IntoResponse {
    Json(Version {
        version: BUILD_PKG_VERSION,
        git_hash: BUILD_GIT_HASH,
        git_branch: BUILD_GIT_BRANCH,
        built_at: BUILD_TIMESTAMP_RFC3339,
    })
}

```

## Configs (genesis, logos_config)

`/root/logos_lrb/configs`


---

### `/root/logos_lrb/configs/genesis.yaml`

```yaml

```

---

### `/root/logos_lrb/configs/logos_config.yaml`

```yaml

```

## Infra (node-related infra configs)

`/root/logos_lrb/infra`


---

### `/root/logos_lrb/infra/nginx/lrb_wallet.conf`

```ini
# Глобальные зоны rate-limit (по IP)
limit_req_zone $binary_remote_addr zone=api_zone:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=proxy_zone:10m rate=10r/s;

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name _;

    # --- Безопасные заголовки ---
    add_header X-Frame-Options        SAMEORIGIN       always;
    add_header X-Content-Type-Options nosniff          always;
    add_header Referrer-Policy        strict-origin-when-cross-origin always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # CSP: только self, без inline/CDN. Разрешаем data: для иконок/картинок в UI.
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; connect-src 'self' http: https:; img-src 'self' data:; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none';" always;

    # --- Gzip для JSON/JS/CSS/HTML ---
    gzip on;
    gzip_types text/plain text/css application/json application/javascript application/xml;
    gzip_min_length 1024;

    # --- Редирект корня на кошелёк ---
    location = / {
        return 302 /wallet/;
    }

    # --- Кошелёк (статические файлы) ---
    location /wallet/ {
        root /opt/logos/www;
        index index.html;
        try_files $uri $uri/ /wallet/index.html;
        # кэш статики
        location ~* \.(?:js|css|png|jpg|jpeg|gif|svg|ico)$ {
            expires 30d;
            access_log off;
        }
    }

    # --- LRB node API (Axum на 8080) ---
    location /api/ {
        limit_req zone=api_zone burst=60 nodelay;

        proxy_read_timeout      30s;
        proxy_connect_timeout   5s;
        proxy_send_timeout      15s;

        proxy_set_header Host                $host;
        proxy_set_header X-Real-IP           $remote_addr;
        proxy_set_header X-Forwarded-For     $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto   $scheme;

        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_pass http://127.0.0.1:8080/;
    }

    # --- Wallet Proxy (FastAPI на 9090) ---
    location /proxy/ {
        limit_req zone=proxy_zone burst=20 nodelay;

        proxy_read_timeout      30s;
        proxy_connect_timeout   5s;
        proxy_send_timeout      15s;

        proxy_set_header Host                $host;
        proxy_set_header X-Real-IP           $remote_addr;
        proxy_set_header X-Forwarded-For     $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto   $scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade             $http_upgrade;
        proxy_set_header Connection          $connection_upgrade;

        proxy_pass http://127.0.0.1:9090/;
    }

    # --- Закрыть доступ к скрытому/служебному ---
    location ~ /\.(?!well-known) {
        deny all;
    }
}

```

---

### `/root/logos_lrb/infra/systemd/exec.conf`

```ini
[Service]
WorkingDirectory=/opt/logos
ExecStart=
ExecStart=/opt/logos/bin/logos_node

```

---

### `/root/logos_lrb/infra/systemd/keys.conf`

```ini
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

# Реальные ключи
Environment=LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```

---

### `/root/logos_lrb/infra/systemd/logos-healthcheck.service`

```ini
[Unit]
Description=LOGOS healthcheck (HTTP)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/default/logos-healthcheck
ExecStart=/usr/local/bin/logos_healthcheck.sh

```

---

### `/root/logos_lrb/infra/systemd/logos-node.service`

```ini
[Unit]
Description=LOGOS LRB Node (Axum REST on :8080)
After=network-online.target
Wants=network-online.target

[Service]
User=root
WorkingDirectory=/root/logos_lrb
ExecStart=/root/logos_lrb/target/release/logos_node
Restart=always
RestartSec=2
LimitNOFILE=65536
Environment=LRB_DEV=1

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target

```

---

### `/root/logos_lrb/infra/systemd/logos-node@.service`

```ini
[Unit]
Description=LOGOS LRB Node (%i)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
Group=logos
EnvironmentFile=/etc/logos/node-%i.env
WorkingDirectory=/opt/logos
ExecStart=/opt/logos/bin/logos_node
Restart=always
RestartSec=1s
StartLimitIntervalSec=0
LimitNOFILE=1048576

# sandbox
AmbientCapabilities=
CapabilityBoundingSet=
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/logos /etc/logos
ProtectSystem=strict

# лог (journalctl -u logos-node@<inst>)
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target

```

---

### `/root/logos_lrb/infra/systemd/logos-snapshot.service`

```ini
[Unit]
Description=LOGOS LRB periodic snapshot

[Service]
Type=oneshot
EnvironmentFile=-/etc/logos/keys.env
ExecStart=/usr/bin/curl -s -H "X-Admin-Key: ${LRB_ADMIN_KEY}" \
  http://127.0.0.1:8080/admin/snapshot-file?name=snap-$(date +%%Y%%m%%dT%%H%%M%%S).json >/dev/null

```

---

### `/root/logos_lrb/infra/systemd/lrb-proxy.service`

```ini
[Unit]
Description=LOGOS Wallet Proxy (FastAPI on :9090)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
WorkingDirectory=/opt/logos/wallet-proxy
EnvironmentFile=/etc/logos/proxy.env
ExecStart=/opt/logos/wallet-proxy/venv/bin/uvicorn app:app --host 0.0.0.0 --port 9090 --workers 2
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

```

---

### `/root/logos_lrb/infra/systemd/lrb-scanner.service`

```ini
[Unit]
Description=LOGOS Wallet Scanner (USDT->rLGN)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
WorkingDirectory=/opt/logos/wallet-proxy
EnvironmentFile=/etc/logos/proxy.env
ExecStart=/opt/logos/wallet-proxy/venv/bin/python /opt/logos/wallet-proxy/scanner.py
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

```

---

### `/root/logos_lrb/infra/systemd/override.conf`

```ini
[Service]
# Базовые ENV (правь под себя при необходимости)
Environment=LRB_DEV=1
Environment=LRB_PEERS=
Environment=LRB_QUORUM_N=1
Environment=LRB_VALIDATORS=

# Прод-тюнинг продюсера (можно менять без ребилда)
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615

# rToken-мост (лимит и ключ для бриджа)
Environment=LRB_BRIDGE_MAX_PER_TX=10000000
# Админ для /admin/snapshot

```

---

### `/root/logos_lrb/infra/systemd/runas.conf`

```ini
[Service]
User=logos
Group=logos
# разрешаем запись в каталог данных под sandbox
ReadWritePaths=/var/lib/logos

```

---

### `/root/logos_lrb/infra/systemd/security.conf`

```ini
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true
MemoryDenyWriteExecute=false

# Разрешаем запись ровно туда, где нужно
ReadWritePaths=/var/lib/logos /opt/logos /etc/logos

WorkingDirectory=/opt/logos
ExecStart=
ExecStart=/opt/logos/bin/logos_node

```

---

### `/root/logos_lrb/infra/systemd/tuning.conf`

```ini
[Service]
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615

```

---

### `/root/logos_lrb/infra/systemd/zz-consensus.conf`

```ini
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

```

---

### `/root/logos_lrb/infra/systemd/zz-keys.conf`

```ini
[Service]
# читаем файл с секретами (на будущее)
EnvironmentFile=-/etc/logos/keys.env

# и ПРЯМО зашиваем реальные значения, чтобы перебить любой override
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key
Environment=LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```

---

### `/root/logos_lrb/infra/systemd/zz-logging.conf`

```ini
[Service]
Environment=RUST_LOG=info

```

## Tools (benchmarks, tx generators, helpers)

`/root/logos_lrb/tools`


---

### `/root/logos_lrb/tools/admin_cli.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

NODE_URL="${NODE_URL:-http://127.0.0.1:8080}"

# --- helpers ---
get_env() {
  systemctl show -p Environment logos-node.service \
    | sed -n 's/^Environment=//p' \
    | tr ' ' '\n' \
    | sed 's/"//g'
}

ENV_CACHE="$(get_env || true)"
get_var() { echo "$ENV_CACHE" | sed -n "s/^$1=//p" | head -n1; }

AK="${AK:-$(get_var LRB_ADMIN_KEY || true)}"
BK="${BK:-$(get_var LRB_BRIDGE_KEY || true)}"

require_admin_key() {
  if [[ -z "${AK:-}" || "$AK" == "CHANGE_ADMIN_KEY" ]]; then
    echo "[!] LRB_ADMIN_KEY не задан или дефолтный. Укажи AK=... в окружении или в keys.conf" >&2
    exit 1
  fi
}
require_bridge_key() {
  if [[ -z "${BK:-}" || "$BK" == "CHANGE_ME" ]]; then
    echo "[!] LRB_BRIDGE_KEY не задан или дефолтный. Укажи BK=... в окружении или в keys.conf" >&2
    exit 1
  fi
}

jq_or_cat() {
  if command -v jq >/dev/null 2>&1; then jq .; else cat; fi
}

usage() {
cat <<'EOF'
admin_cli.sh — удобные команды для LOGOS LRB (prod)

ENV:
  NODE_URL=http://127.0.0.1:8080     # адрес ноды (по умолчанию)
  AK=<admin-key>                     # можно переопределить, иначе берется из systemd
  BK=<bridge-key>                    # можно переопределить, иначе берется из systemd

Команды:
  health                      — /healthz
  head                        — /head
  node-info                   — /node/info
  validators                  — /admin/validators
  metrics [grep]              — /metrics (опциональный grep)

  snapshot-json               — GET /admin/snapshot (требует AK)
  snapshot-file [name]        — GET /admin/snapshot/file?name=NAME (требует AK)
  restore <abs_path.json>     — POST /admin/restore (требует AK)

  deposit <rid> <amount> <ext_txid>         — POST /bridge/deposit (требует BK)
  redeem  <rid> <amount> <request_id>       — POST /bridge/redeem (требует BK)
  verify  <ticket> <vk_b58> <signature_b64> — POST /bridge/verify

  account-txs <rid> [limit]   — GET /account/:rid/txs?limit=N

Примеры:
  ./admin_cli.sh head
  ./admin_cli.sh validators
  AK=$(systemctl show -p Environment logos-node.service | sed -n 's/.*LRB_ADMIN_KEY=\([^ ]*\).*/\1/p') \
    ./admin_cli.sh snapshot-json
  BK=$(systemctl show -p Environment logos-node.service | sed -n 's/.*LRB_BRIDGE_KEY=\([^ ]*\).*/\1/p') \
    ./admin_cli.sh deposit RID_A 12345 ext-1
EOF
}

cmd="${1:-}"
case "$cmd" in
  ""|-h|--help|help) usage; exit 0 ;;
esac
shift || true

case "$cmd" in
  health)
    curl -s "$NODE_URL/healthz" | jq_or_cat
    ;;

  head)
    curl -s "$NODE_URL/head" | jq_or_cat
    ;;

  node-info)
    curl -s "$NODE_URL/node/info" | jq_or_cat
    ;;

  validators)
    curl -s "$NODE_URL/admin/validators" | jq_or_cat
    ;;

  metrics)
    body="$(curl -s "$NODE_URL/metrics")"
    if [[ $# -gt 0 ]]; then echo "$body" | grep -E "$*" || true; else echo "$body"; fi
    ;;

  snapshot-json)
    require_admin_key
    curl -s -H "X-Admin-Key: $AK" "$NODE_URL/admin/snapshot" | jq_or_cat
    ;;

  snapshot-file)
    require_admin_key
    name="${1:-snap-$(date +%s).json}"
    curl -s -H "X-Admin-Key: $AK" "$NODE_URL/admin/snapshot/file?name=$name" | jq_or_cat
    ;;

  restore)
    require_admin_key
    file="${1:-}"
    [[ -z "$file" ]] && { echo "[!] usage: restore /var/lib/logos/snapshots/<file>.json" >&2; exit 1; }
    curl -s -X POST -H "content-type: application/json" -H "X-Admin-Key: $AK" \
      "$NODE_URL/admin/restore" \
      -d "{\"file\":\"$file\"}" | jq_or_cat
    ;;

  deposit)
    require_bridge_key
    rid="${1:-}"; amt="${2:-}"; xtx="${3:-}"
    [[ -z "$rid" || -z "$amt" || -z "$xtx" ]] && { echo "[!] usage: deposit <rid> <amount> <ext_txid>" >&2; exit 1; }
    curl -s -X POST "$NODE_URL/bridge/deposit" \
      -H "content-type: application/json" -H "X-Bridge-Key: $BK" \
      -d "{\"rid\":\"$rid\",\"amount\":$amt,\"ext_txid\":\"$xtx\"}" | jq_or_cat
    ;;

  redeem)
    require_bridge_key
    rid="${1:-}"; amt="${2:-}"; reqid="${3:-}"
    [[ -z "$rid" || -z "$amt" || -z "$reqid" ]] && { echo "[!] usage: redeem <rid> <amount> <request_id>" >&2; exit 1; }
    curl -s -X POST "$NODE_URL/bridge/redeem" \
      -H "content-type: application/json" -H "X-Bridge-Key: $BK" \
      -d "{\"rid\":\"$rid\",\"amount\":$amt,\"request_id\":\"$reqid\"}" | jq_or_cat
    ;;

  verify)
    ticket="${1:-}"; vk_b58="${2:-}"; sig_b64="${3:-}"
    [[ -z "$ticket" || -z "$vk_b58" || -z "$sig_b64" ]] && { echo "[!] usage: verify <ticket> <vk_b58> <signature_b64>" >&2; exit 1; }
    curl -s -X POST "$NODE_URL/bridge/verify" \
      -H "content-type: application/json" \
      -d "{\"ticket\":\"$ticket\",\"vk_b58\":\"$vk_b58\",\"signature_b64\":\"$sig_b64\"}" | jq_or_cat
    ;;

  account-txs)
    rid="${1:-}"; limit="${2:-100}"
    [[ -z "$rid" ]] && { echo "[!] usage: account-txs <rid> [limit]" >&2; exit 1; }
    curl -s "$NODE_URL/account/$rid/txs?limit=$limit" | jq_or_cat
    ;;

  *)
    echo "[!] unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac

```

---

### `/root/logos_lrb/tools/batch.json`

```json

```

---

### `/root/logos_lrb/tools/book_make.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

# Куда писать книгу
DATE_UTC=$(date -u +%Y-%m-%dT%H-%M-%SZ)
BOOK="docs/LOGOS_LRB_BOOK_${DATE_UTC}.txt"

# Корень репозитория (чтобы пути были относительные)
REPO_ROOT="/root/logos_lrb"
cd "$REPO_ROOT"

echo "[*] Building book: $BOOK"
mkdir -p docs

# --- списки включений/исключений ---
# Git-трекаемые файлы + критичные конфиги вне репы
INCLUDE_LIST="$(mktemp)"
EXTRA_LIST="$(mktemp)"

# 1) всё полезное из git (код/конфиги), без мусора
git ls-files \
  | grep -Ev '^(\.gitignore|README\.md|LICENSE|^docs/LOGOS_LRB_BOOK_|^docs/.*\.pdf$)' \
  | grep -Ev '(^target/|/target/|^node_modules/|/node_modules/|\.DS_Store|\.swp$|\.sqlite$|/data\.sled|/data\.sled/|\.pem$|\.key$)' \
  > "$INCLUDE_LIST"

# 2) системные файлы вне репы (если существуют)
add_extra() { [[ -f "$1" ]] && echo "$1" >> "$EXTRA_LIST"; }
add_extra "/etc/systemd/system/logos-node.service"
for f in /etc/systemd/system/logos-node.service.d/*.conf; do [[ -f "$f" ]] && echo "$f" >> "$EXTRA_LIST"; done
add_extra "/etc/nginx/conf.d/10_lrb_https.conf"
add_extra "/etc/prometheus/prometheus.yml"
for f in /etc/prometheus/rules/*.yml; do [[ -f "$f" ]] && echo "$f" >> "$EXTRA_LIST"; done
# Grafana provisioning/дашборды (если есть)
for f in /etc/grafana/provisioning/dashboards/*.yaml /var/lib/grafana/dashboards/*.json; do
  [[ -f "$f" ]] && echo "$f" >> "$EXTRA_LIST"
done
# OpenAPI (в репе уже есть), APK/лендинг укажем ссылкой — бинарники в книгу не кладём

# --- заголовок книги ---
{
  echo "LOGOS LRB — FULL LIVE BOOK (${DATE_UTC})"
  echo
  echo "Содержимое: весь код репозитория + ключевая инфраструктура (systemd/nginx/prometheus/grafana),"
  echo "формат: секции BEGIN/END FILE c sha256 и блочным EOF. Бинарники (APK, sled, pem) не включаются."
  echo
  echo "Репозиторий: $REPO_ROOT"
  echo
} > "$BOOK"

emit_file () {
  local src="$1" dst
  # внутри репо пишем относительные пути; вне — абсолютные
  if [[ "$src" == $REPO_ROOT/* ]]; then
    dst="/${src#$REPO_ROOT/}"
  else
    dst="$src"
  fi
  # пропуск «мусора»
  if [[ -d "$src" ]]; then return 0; fi
  if [[ ! -f "$src" ]]; then return 0; fi
  # вычисляем sha256
  local sum
  sum=$(sha256sum "$src" | awk '{print $1}')
  {
    echo "===== BEGIN FILE $dst ====="
    echo "# sha256: $sum"
    echo "<<'EOF'"
    cat "$src"
    echo "EOF"
    echo "===== END FILE $dst ====="
    echo
  } >> "$BOOK"
}

echo "[*] Emitting repo files..."
while IFS= read -r p; do emit_file "$REPO_ROOT/$p"; done < "$INCLUDE_LIST"

echo "[*] Emitting extra system files..."
if [[ -s "$EXTRA_LIST" ]]; then
  while IFS= read -r p; do emit_file "$p"; done < "$EXTRA_LIST"
fi

# --- прикладываем «паспорт» окружения ---
{
  echo "===== BEGIN FILE /docs/ENV_SNAPSHOT.txt ====="
  echo "# sha256: N/A"
  echo "<<'EOF'"
  echo "[systemd env]"
  systemctl show logos-node -p Environment | sed 's/^Environment=//'
  echo
  echo "[nginx -v]"
  nginx -v 2>&1 || true
  echo
  echo "[prometheus rules list]"
  ls -1 /etc/prometheus/rules 2>/dev/null || true
  echo
  echo "[grafana dashboards list]"
  ls -1 /var/lib/grafana/dashboards 2>/dev/null || true
  echo "EOF"
  echo "===== END FILE /docs/ENV_SNAPSHOT.txt ====="
  echo
} >> "$BOOK"

echo "[*] Book is ready: $BOOK"

```

---

### `/root/logos_lrb/tools/book_restore.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

BOOK="${1:-}"
if [[ -z "$BOOK" || ! -f "$BOOK" ]]; then
  echo "usage: $0 /path/to/LOGOS_LRB_BOOK_*.txt"; exit 1
fi

echo "[*] Restoring files from: $BOOK"
RESTORED=0
BADHASH=0

# прочитаем книгу и вытащим секции
# формат: BEGIN FILE <path>\n# sha256: <hex>\n<<'EOF'\n...EOF\nEND FILE
awk '
  /^===== BEGIN FILE / {
    inblock=1
    path=""
    sha=""
    gsub(/^===== BEGIN FILE /,"")
    gsub(/ =====$/,"")
    path=$0
    next
  }
  inblock && /^# sha256:/ {
    sha=$2
    next
  }
  inblock && /^<<'\''EOF'\''/ { collecting=1; content=""; next }
  collecting && /^EOF$/ { collecting=0; inblock=2; next }
  inblock==1 && !collecting { next }
  collecting { content = content $0 "\n"; next }
  inblock==2 && /^===== END FILE / {
    # записываем файл
    # создадим директорию
    cmd = "mkdir -p \"" path "\""
    sub(/\/[^\/]+$/, "", cmdpath=path) # dir part
    if (cmdpath != "") {
      system("mkdir -p \"" cmdpath "\"")
    }
    # записываем
    f = path
    gsub(/\r$/,"",content)
    # защитимся от /etc/... если нет прав — предложим sudo
    # но здесь просто пишем как есть
    outfile = path
    # если путь абсолютный, пишем в тот же абсолютный; если относительный — относительно cwd
    # создадим временный и заменим
    tmpfile = outfile ".tmp.restore"
    # в shell передам через printf
    print content > tmpfile
    close(tmpfile)
    # проверка sha256 если есть
    if (sha != "" && sha != "N/A") {
      cmdsum = "sha256sum \"" tmpfile "\" | awk '\''{print $1}'\''"
      cmdsum | getline got
      close(cmdsum)
      if (got != sha) {
        print "[WARN] sha256 mismatch for " outfile " expected=" sha " got=" got
        BADHASH++
      }
    }
    system("install -m 0644 \"" tmpfile "\" \"" outfile "\"")
    system("rm -f \"" tmpfile "\"")
    print "[OK] restored " outfile
    RESTORED++
    inblock=0
    next
  }
  END {
    # summary в AWK не выведем; сделаем в оболочке
  }
' "$BOOK"

echo "[*] Restored files: $RESTORED"
if [[ "${BADHASH:-0}" -gt 0 ]]; then
  echo "[!] WARNING: sha256 mismatches: $BADHASH"
fi

echo "[*] Done. Проверь права на системные файлы, возможно потребуется sudo chown/chmod."

```

---

### `/root/logos_lrb/tools/build_books_ascii.sh`

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
export LANG=C LC_ALL=C
cd /root/logos_lrb

STAMP="${STAMP:-$(date +%F_%H-%M-%S)}"
OUTDIR="docs/LOGOS_LRB_BOOK"
SNAPDIR="docs/snapshots"
ROOTS_FILE="${ROOTS_FILE:-$(ls -1t docs/REPO_ROOTS_*.txt 2>/dev/null | head -n1)}"

mkdir -p "$OUTDIR" "$SNAPDIR"

build_one() {
  local root="$1"
  [ -z "$root" ] && return
  [ "$root" = "." ] && return
  [ ! -d "$root" ] && return

  local safe="${root//[\/ ]/__}"
  local book="${OUTDIR}/BOOK_${safe}_${STAMP}.md"
  local snap="${SNAPDIR}/SNAP_${safe}_${STAMP}.tar.xz"

  {
    echo "# BOOK for '${root}' (LIVE ${STAMP})"
    echo
    echo "## Project tree (${root})"
    echo '```text'
  } > "$book"

  find "$root" \
    -path "$root/target" -o -path "$root/.git" -o -path "$root/tests" -o -path "$root/node_modules" -prune -o \
    -type d -print \
  | awk -v r="$root" '{p=$0; if(p==r){print "."; next} sub("^" r "/","",p); print p}' \
  | LC_ALL=C sort >> "$book"

  {
    echo '```'
    echo
    echo "## Files (sources/configs/docs)  full content"
    echo
  } >> "$book"

  LC_ALL=C find "$root" \
    \( -path "$root/target" -o -path "$root/.git" -o -path "$root/tests" -o -path "$root/node_modules" \) -prune -o \
    -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' -o \
               -name '*.json' -o -name '*.md'   -o -name '*.sh'   -o -name '*.py'  -o \
               -name '*.service' -o -name '*.conf' -o -name 'Makefile' -o -name '*.sql' -o \
               -name '*.mjs' -o -name '*.ts' -o -name '*.tsx' \) -print0 \
  | sort -z \
  | while IFS= read -r -d '' f; do
      kb=$(du -k "$f" | awk '{print $1}')
      if [ "$kb" -gt 5120 ]; then
        printf "### \`%s\` (skipped: >5MB)\n\n" "$f" >> "$book"
        continue
      fi
      case "$f" in
        *.rs) lang=rust ;;
        *.toml) lang=toml ;;
        *.yaml|*.yml) lang=yaml ;;
        *.json) lang=json ;;
        *.sh) lang=bash ;;
        *.py) lang=python ;;
        *.service|*.conf) lang=ini ;;
        *.sql) lang=sql ;;
        Makefile) lang=make ;;
        *.md) lang=markdown ;;
        *.mjs) lang=javascript ;;
        *.ts)  lang=typescript ;;
        *.tsx) lang=tsx ;;
        *)     lang=text ;;
      esac
      printf "### \`%s\`\n\n\`\`\`%s\n" "$f" "$lang" >> "$book"
      cat "$f" >> "$book"
      printf "\n\`\`\`\n\n" >> "$book"
    done

  tar -C . \
    --exclude="./$root/target" \
    --exclude="./$root/.git" \
    --exclude="./$root/tests" \
    --exclude="./$root/node_modules" \
    -c "$root" | xz -T1 -9 -c > "$snap"

  printf "[OK] %-16s book=%-6s snap=%s\n" "$root" "$(du -h "$book" | awk '{print $1}')" "$(du -h "$snap" | awk '{print $1}')"
}

echo "=== Building per-root books from: ${ROOTS_FILE} ==="
while read -r root; do
  build_one "$root"
done < "$ROOTS_FILE"

echo "=== Summary ==="
du -ch "$OUTDIR"/BOOK_*_"$STAMP".md 2>/dev/null | tail -n1 || true
du -ch "$SNAPDIR"/SNAP_*_"$STAMP".tar.xz 2>/dev/null | tail -n1 || true

```

---

### `/root/logos_lrb/tools/build_books.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
export LANG=C LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.."; pwd)"
cd "$ROOT"

STAMP="$(date +%F_%H-%M-%S)"
OUTDIR="docs/LOGOS_LRB_BOOK"
SNAPDIR="docs/snapshots"
mkdir -p "$OUTDIR" "$SNAPDIR"

# 1) строим файл корней
ROOTS_FILE="docs/REPO_ROOTS_${STAMP}.txt"
{
  find . -type f -name Cargo.toml     -printf '%h\n'
  find . -type f -name pyproject.toml -printf '%h\n'
  find . -type f -name package.json   -printf '%h\n'
  find . -type f -name go.mod         -printf '%h\n'
  # статические корни
  printf '%s\n' \
    configs configs/env \
    infra/nginx infra/systemd \
    lrb_core node wallet-proxy \
    www www/wallet www/explorer
} | sed 's#^\./##' | sort -u | grep -vE '^$' > "$ROOTS_FILE"

echo "=== Building per-root books from: $ROOTS_FILE ==="

build_one() {
  local root="$1"
  [[ -z "$root" || "$root" = "." ]] && return

  local safe="${root//[\/ ]/__}"
  local book="${OUTDIR}/BOOK_${safe}_${STAMP}.md"
  local snap="${SNAPDIR}/SNAP_${safe}_${STAMP}.tar.xz"

  {
    echo "# BOOK for '${root}' (LIVE ${STAMP})"
    echo
    echo "## Project tree (${root})"
    echo '```text'
    find "$root" \
      -path "$root/target" -prune -o \
      -path "$root/.git"   -prune -o \
      -path "$root/tests"  -prune -o \
      -type d -print \
      | sed "s#^${root}/##; s#^${root}$#.#" \
      | sort
    echo '```'
    echo
    echo "## Files (sources/configs/docs) — full content"
    echo
  } > "$book"

  # перечисляем файлы (текстовые) и кладём содержимое
  while IFS= read -r -d '' f; do
    [[ -s "$f" ]] || continue
    # скипаем > 5MB, чтобы книга не вылезла за лимит
    local_kb="$(du -k "$f" | awk '{print $1}')"
    if [ "$local_kb" -gt 5120 ]; then
      echo "### \`$f\` (skipped: >5MB)" >> "$book"
      echo >> "$book"
      continue
    fi
    lang="text"
    case "$f" in
      *.rs)        lang="rust" ;;
      *.toml)      lang="toml" ;;
      *.yaml|*.yml)lang="yaml" ;;
      *.json)      lang="json" ;;
      *.sh)        lang="bash" ;;
      *.py)        lang="python" ;;
      *.service|*.conf) lang="ini" ;;
      *.sql)       lang="sql" ;;
      Makefile)    lang="make" ;;
      *.md)        lang="markdown" ;;
      *.mjs)       lang="javascript" ;;
      *.ts)        lang="typescript" ;;
      *.tsx)       lang="tsx" ;;
    esac
    echo "### \`$f\`" >> "$book"
    echo '```'"$lang" >> "$book"
    cat "$f" >> "$book"
    echo '```' >> "$book"
    echo >> "$book"
  done < <(find "$root" \
              -path "$root/target" -prune -o \
              -path "$root/.git"   -prune -o \
              -path "$root/tests"  -prune -o \
              -type f \( \
                -name '*.rs' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' -o \
                -name '*.json' -o -name '*.md'  -o -name '*.sh'   -o -name '*.py'  -o \
                -name '*.service' -o -name '*.conf' -o -name 'Makefile' -o -name '*.sql' -o \
                -name '*.mjs' -o -name '*.ts' -o -name '*.tsx' \
              \) -print0 | sort -z)

  # компактный снапшот дерева
  tar -C . \
    --exclude="./$root/target" \
    --exclude="./$root/.git" \
    --exclude="./$root/tests" \
    --exclude="./$root/node_modules" \
    -c "$root" | xz -T1 -9 -c > "$snap"

  printf "[OK] %-16s | book=%-6s snap=%s\n" \
    "$root" "$(du -h "$book" | awk '{print $1}')" \
    "$(du -h "$snap" | awk '{print $1}')"
}

# прогон по корням
while IFS= read -r root; do
  build_one "$root"
done < "$ROOTS_FILE"

# краткая сводка
echo
echo "=== Books summary ===";     du -ch docs/LOGOS_LRB_BOOK/BOOK_*_${STAMP}.md       | tail -n1 || true
echo "=== Snapshots summary ==="; du -ch docs/snapshots/SNAP_*_${STAMP}.tar.xz        | tail -n1 || true

```

---

### `/root/logos_lrb/tools/gen_main_rs.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

SRC="node/src"
STAKING="$SRC/api/staking.rs"
BRIDGE="$SRC/bridge.rs"
ARCHMOD="$SRC/api/archive.rs"
TXMOD="$SRC/api/tx.rs"
BASEMOD="$SRC/api/base.rs"
HEALTH="$SRC/health.rs"

has() { grep -qE "$2" "$1" 2>/dev/null; }

HAS_STAKE_DELEGATE=false
HAS_STAKE_UNDELEGATE=false
HAS_STAKE_CLAIM=false
HAS_STAKE_MY=false
if [[ -f "$STAKING" ]]; then
  has "$STAKING" 'pub\s+async\s+fn\s+stake_delegate'  && HAS_STAKE_DELEGATE=true
  has "$STAKING" 'pub\s+async\s+fn\s+stake_undelegate'&& HAS_STAKE_UNDELEGATE=true
  has "$STAKING" 'pub\s+async\s+fn\s+stake_claim'     && HAS_STAKE_CLAIM=true
  has "$STAKING" 'pub\s+async\s+fn\s+stake_my'        && HAS_STAKE_MY=true
fi

HAS_BRIDGE_DEPOSIT_JSON=false
HAS_BRIDGE_REDEEM_JSON=false
if [[ -f "$BRIDGE" ]]; then
  has "$BRIDGE" 'pub\s+async\s+fn\s+deposit_json' && HAS_BRIDGE_DEPOSIT_JSON=true
  has "$BRIDGE" 'pub\s+async\s+fn\s+redeem_json'  && HAS_BRIDGE_REDEEM_JSON=true
fi

HAS_ARCH_TX=false
HAS_ARCH_HIST=false
HAS_ARCH_BLOCKS=false
if [[ -f "$ARCHMOD" ]]; then
  has "$ARCHMOD" 'pub\s+async\s+fn\s+tx_by_id'        && HAS_ARCH_TX=true
  has "$ARCHMOD" 'pub\s+async\s+fn\s+history_by_rid'  && HAS_ARCH_HIST=true
  has "$ARCHMOD" 'pub\s+async\s+fn\s+recent_blocks'   && HAS_ARCH_BLOCKS=true
fi

HAS_TX_SUBMIT=false
HAS_TX_BATCH=false
if [[ -f "$TXMOD" ]]; then
  has "$TXMOD" 'pub\s+async\s+fn\s+submit_tx\b'       && HAS_TX_SUBMIT=true
  has "$TXMOD" 'pub\s+async\s+fn\s+submit_tx_batch\b' && HAS_TX_BATCH=false
fi

HAS_HEALTHZ=false
if [[ -f "$HEALTH" ]]; then
  has "$HEALTH" 'pub\s+async\s+fn\s+healthz' && HAS_HEALTHZ=true
fi

cat > "$SRC/main.rs" <<'RS'
use std::{net::SocketAddr, sync::Arc};
use anyhow::Result;
use axum::{Router, routing::{get, post}};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

// Импорты из библиотечной части пакета:
use logos_node::state::AppState;
use logos_node::api::{self, base};
RS

# staking
if $HAS_STAKE_DELEGATE || $HAS_STAKE_UNDELEGATE || $HAS_STAKE_CLAIM || $HAS_STAKE_MY; then
  cat >> "$SRC/main.rs" <<'RS'
use logos_node::api::staking;
RS
fi

# archive
if $HAS_ARCH_TX || $HAS_ARCH_HIST || $HAS_ARCH_BLOCKS; then
  cat >> "$SRC/main.rs" <<'RS'
use logos_node::api::archive as api_archive;
RS
fi

# tx
if $HAS_TX_SUBMIT || $HAS_TX_BATCH; then
  cat >> "$SRC/main.rs" <<'RS'
use logos_node::api::tx;
RS
fi

# health
if $HAS_HEALTHZ; then
  cat >> "$SRC/main.rs" <<'RS'
use logos_node::health;
RS
fi

# bridge
if $HAS_BRIDGE_DEPOSIT_JSON || $HAS_BRIDGE_REDEEM_JSON; then
  cat >> "$SRC/main.rs" <<'RS'
use logos_node::bridge;
RS
fi

cat >> "$SRC/main.rs" <<'RS'

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // state
    let mut st = AppState::new()?;
    st.init_archive().await?;
    let shared = Arc::new(st);

    async fn livez() -> &'static str { "ok" }
    async fn readyz() -> &'static str { "ok" }

    // В Axum 0.7: сначала фиксируем тип состояния
    let mut app = Router::new()
        .with_state(shared.clone())
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz));
RS

if $HAS_HEALTHZ; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/healthz", get(health::healthz));
RS
fi

cat >> "$SRC/main.rs" <<'RS'
    // /head, /version
    app = app.merge(base::routes(shared.clone()));
RS

if $HAS_TX_SUBMIT; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/submit_tx", post(tx::submit_tx));
RS
fi
if $HAS_TX_BATCH; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/submit_tx_batch", post(tx::submit_tx_batch));
RS
fi

if $HAS_ARCH_TX; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/archive/tx/:txid", get(api_archive::tx_by_id));
RS
fi
if $HAS_ARCH_HIST; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/archive/history/:rid", get(api_archive::history_by_rid));
RS
fi
if $HAS_ARCH_BLOCKS; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/archive/blocks", get(api_archive::recent_blocks));
RS
fi

if $HAS_STAKE_DELEGATE; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/stake/delegate", post(staking::stake_delegate));
RS
fi
if $HAS_STAKE_UNDELEGATE; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/stake/undelegate", post(staking::stake_undelegate));
RS
fi
if $HAS_STAKE_CLAIM; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/stake/claim", post(staking::stake_claim));
RS
fi
if $HAS_STAKE_MY; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/stake/my/:rid", get(staking::stake_my));
RS
fi

if $HAS_BRIDGE_DEPOSIT_JSON; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/bridge/deposit_json", post(bridge::deposit_json));
RS
fi
if $HAS_BRIDGE_REDEEM_JSON; then
  cat >> "$SRC/main.rs" <<'RS'
    app = app.route("/bridge/redeem_json", post(bridge::redeem_json));
RS
fi

cat >> "$SRC/main.rs" <<'RS'
    let addr: SocketAddr = shared.bind_addr();
    tracing::info!("🚀 LOGOS LRB node listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
RS

echo "[gen_main_rs] main.rs generated successfully."

```

---

### `/root/logos_lrb/tools/gen_rid/Cargo.toml`

```toml
[package]
name = "gen_rid"
version = "0.1.0"
edition = "2021"

[dependencies]
ed25519-dalek = "2"
rand_core = "0.6"
bs58 = "0.5"
hex = "0.4"

```

---

### `/root/logos_lrb/tools/gen_rid/src/main.rs`

```rust
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
fn main() {
    // Если задан SK_HEX — используем его, иначе генерируем новый
    let args: Vec<String> = std::env::args().collect();
    let sk_hex = std::env::var("SK_HEX").ok();
    let (sk, sk_src) = if let Some(h) = sk_hex {
        let b = hex::decode(&h).expect("bad SK_HEX");
        let arr: [u8;32] = b.try_into().expect("need 32 bytes");
        (SigningKey::from_bytes(&arr), "import")
    } else {
        (SigningKey::generate(&mut OsRng), "generated")
    };

    let vk: VerifyingKey = sk.verifying_key();
    let rid_b58 = bs58::encode(vk.as_bytes()).into_string();

    println!("src={}", sk_src);
    println!("sk_hex={}", hex::encode(sk.to_bytes()));
    println!("vk_hex={}", hex::encode(vk.to_bytes()));
    println!("rid_b58={}", rid_b58);
}

```

---

### `/root/logos_lrb/tools/load_healthz.sh`

```bash
#!/usr/bin/env bash
# load_healthz.sh — прогон healthz с прогрессом
# Usage: ./load_healthz.sh <TOTAL=50000> <CONC=200> <MODE=rr|lb>
set -euo pipefail
TOTAL="${1:-50000}"
CONC="${2:-200}"
MODE="${3:-rr}"

start_ts=$(date +%s%3N)
cnt=0
print_prog() { cnt=$((cnt+1)); if (( cnt % 1000 == 0 )); then echo -n "."; fi; }

if [ "$MODE" = "rr" ]; then
  seq 1 "$TOTAL" | xargs -n1 -P"$CONC" -I{} bash -c '
    i="{}"; r=$(( i % 3 ))
    if   [ $r -eq 0 ]; then p=8080
    elif [ $r -eq 1 ]; then p=8082
    else                   p=8084
    fi
    curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:${p}/healthz"
  ' && echo
else
  seq 1 "$TOTAL" | xargs -n1 -P"$CONC" -I{} bash -c '
    curl -sS --max-time 2 -o /dev/null "http://127.0.0.1/api/healthz"
  ' && echo
fi

end_ts=$(date +%s%3N)
dt_ms=$(( end_ts - start_ts ))
rps=$(( TOTAL * 1000 / (dt_ms>0?dt_ms:1) ))
echo "[OK] sent ${TOTAL} requests in ${dt_ms} ms  → ~${rps} req/s"

```

---

### `/root/logos_lrb/tools/lrb_audit.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /root/logos_lrb

REPORT="AUDIT_REPORT.md"
echo "# LOGOS LRB — Аудит модулей" > "$REPORT"
echo "_$(date -u)_ UTC" >> "$REPORT"
echo >> "$REPORT"

sha() { sha256sum "$1" | awk '{print $1}'; }

audit_rust() {
  local f="$1"
  local lines; lines=$(wc -l <"$f")
  local s_unsafe s_unwrap s_expect s_panic s_todo s_dbg
  s_unsafe=$(grep -c '\<unsafe\>' "$f" || true)
  s_unwrap=$(grep -c 'unwrap(' "$f" || true)
  s_expect=$(grep -c 'expect(' "$f" || true)
  s_panic=$(grep -c 'panic!(' "$f" || true)
  s_dbg=$(grep -Ec 'dbg!|println!' "$f" || true)
  s_todo=$(grep -ni 'TODO\|FIXME\|todo!\|unimplemented!' "$f" | sed 's/^/    /' || true)
  {
    echo "### \`$f\` (Rust)"
    echo "- lines: $lines | sha256: \`$(sha "$f")\`"
    echo "- red-flags: unsafe=$s_unsafe, unwrap=$s_unwrap, expect=$s_expect, panic=$s_panic, dbg/println=$s_dbg"
    [ -n "$s_todo" ] && echo "- TODO/FIXME:"$'\n'"$s_todo"
    echo
  } >> "$REPORT"
}

audit_py() {
  local f="$1"
  local lines; lines=$(wc -l <"$f")
  local s_eval s_exec s_pickle s_subp s_todo
  s_eval=$(grep -c '\<eval\>' "$f" || true)
  s_exec=$(grep -c '\<exec\>' "$f" || true)
  s_pickle=$(grep -c 'pickle' "$f" || true)
  s_subp=$(grep -c 'subprocess' "$f" || true)
  s_todo=$(grep -ni 'TODO\|FIXME' "$f" | sed 's/^/    /' || true)
  {
    echo "### \`$f\` (Python)"
    echo "- lines: $lines | sha256: \`$(sha "$f")\`"
    echo "- red-flags: eval=$s_eval, exec=$s_exec, pickle=$s_pickle, subprocess=$s_subp"
    [ -n "$s_todo" ] && echo "- TODO/FIXME:"$'\n'"$s_todo"
    echo
  } >> "$REPORT"
}

audit_other() {
  local f="$1"
  local lines; lines=$(wc -l <"$f")
  {
    echo "### \`$f\`"
    echo "- lines: $lines | sha256: \`$(sha "$f")\`"
    grep -ni 'TODO\|FIXME' "$f" | sed 's/^/    - /' || true
    echo
  } >> "$REPORT"
}

echo "## Files in modules/" >> "$REPORT"
find modules -maxdepth 1 -type f | sort | while read -r f; do
  case "$f" in
    *.rs) audit_rust "$f" ;;
    *.py) audit_py "$f" ;;
    *.tsx|*.ts|*.yaml|*.yml|*.md) audit_other "$f" ;;
    *) audit_other "$f" ;;
  esac
done
echo >> "$REPORT"

echo "## Files in core/" >> "$REPORT"
find core -maxdepth 1 -type f | sort | while read -r f; do
  case "$f" in
    *.rs) audit_rust "$f" ;;
    *.py) audit_py "$f" ;;
    *.yaml|*.yml|*.md|*.toml) audit_other "$f" ;;
    *) audit_other "$f" ;;
  esac
done
echo >> "$REPORT"

echo "## Quick checks" >> "$REPORT"
{
  echo '```'
  cargo --version 2>/dev/null || true
  python3 --version 2>/dev/null || true
  echo '```'
  echo
} >> "$REPORT"

if [ -f Cargo.toml ]; then
  echo "### cargo check" >> "$REPORT"
  ( cargo check 2>&1 || true ) | sed 's/^/    /' >> "$REPORT"
  echo >> "$REPORT"
fi

# Python syntax check
: > py_err.log || true
find core modules -name '*.py' -print0 | xargs -0 -I{} sh -c 'python3 -m py_compile "{}" 2>>py_err.log' || true
if [ -s py_err.log ]; then
  echo "### python syntax errors" >> "$REPORT"
  sed 's/^/    /' py_err.log >> "$REPORT"
  echo >> "$REPORT"
fi

echo "Done -> $REPORT"

```

---

### `/root/logos_lrb/tools/make_block_producer_snapshot.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_BLOCK_PRODUCER_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_BLOCK_PRODUCER/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_BLOCK_PRODUCER"

echo "# LOGOS Block Producer Snapshot" > "$OUT"
echo "" >> "$OUT"
echo "_Автогенерация: \`$(date -u "+%Y-%m-%d %H:%M:%SZ")\`_" >> "$OUT"
echo "" >> "$OUT"

dump_dir () {
  local DIR="$1"
  local TITLE="$2"

  if [ ! -d "$DIR" ]; then
    echo "- [WARN] directory not found: $DIR" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`$DIR\`" >> "$OUT"
  echo "" >> "$OUT"

  find "$DIR" \
    -type f \
    \( \
      -name "*.rs"   -o \
      -name "*.toml" -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.sh"   -o \
      -name "*.md"   -o \
      -name "*.json" -o \
      -name "*.service" -o -name "*.socket" -o \
      -name "*.conf" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/target/*" \
    ! -path "*/.venv/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/data.sled/*" \
    ! -path "*/data.sled.*/*" \
    ! -path "*/bridge_journal.sled/*" \
    ! -path "*/logs/*" \
    ! -path "*/log/*" \
    ! -name "*.log" \
    ! -name "*.sqlite3" \
    ! -name "*.sqlite" \
    ! -name "*.db" \
    ! -name "*.env" \
  | sort | while read -r FILE; do
        local REL="$FILE"

        echo "" >> "$OUT"
        echo "---" >> "$OUT"
        echo "" >> "$OUT"
        echo "### \`$REL\`" >> "$OUT"
        echo "" >> "$OUT"

        local EXT="${FILE##*.}"
        local LANG=""
        case "$EXT" in
          rs)          LANG="rust" ;;
          toml)        LANG="toml" ;;
          yml|yaml)    LANG="yaml" ;;
          sh)          LANG="bash" ;;
          md)          LANG="markdown" ;;
          json)        LANG="json" ;;
          service|socket|conf) LANG="ini" ;;
          *)           LANG="" ;;
        esac

        if [ -n "$LANG" ]; then
          echo "\`\`\`$LANG" >> "$OUT"
        else
          echo "\`\`\`" >> "$OUT"
        fi

        cat "$FILE" >> "$OUT"
        echo "" >> "$OUT"
        echo "\`\`\`" >> "$OUT"
    done
}

dump_file () {
  local FILE="$1"
  local TITLE="$2"

  if [ ! -f "$FILE" ]; then
    echo "- [WARN] file not found: $FILE" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "### \`$FILE\`" >> "$OUT"
  echo "" >> "$OUT"

  local EXT="${FILE##*.}"
  local LANG=""
  case "$EXT" in
    service|socket|conf) LANG="ini" ;;
    toml)                LANG="toml" ;;
    yml|yaml)            LANG="yaml" ;;
    *)                   LANG="" ;;
  esac

  if [ -n "$LANG" ]; then
    echo "\`\`\`$LANG" >> "$OUT"
  else
    echo "\`\`\`" >> "$OUT"
  fi

  cat "$FILE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`\`\`" >> "$OUT"
}

# 1. Ядро блокчейна: всё, где живут ledger, mempool, engine, producer
dump_dir "/root/logos_lrb/lrb_core" "LRB Core (ledger, mempool, engine, block producer)"

# 2. Нода: main.rs, API, архив, метрики — всё, что завязано на продюсере
dump_dir "/root/logos_lrb/node" "Node (REST, producer loop, archive, metrics)"

# 3. Конфиги сети и генезиса
dump_dir "/root/logos_lrb/configs" "Configs (genesis, logos_config)"

# 4. Инфраструктура для ноды (если есть шаблоны)
dump_dir "/root/logos_lrb/infra" "Infra (node-related infra configs)"

# 5. Инструменты для тестирования продюсера (бенчи)
dump_dir "/root/logos_lrb/tools" "Tools (benchmarks, tx generators, helpers)"

# 6. systemd-юниты и overrides для ноды
dump_file "/etc/systemd/system/logos-node@.service" "systemd: logos-node@.service"
dump_dir  "/etc/systemd/system/logos-node@.service.d" "systemd overrides: logos-node@.service.d"

echo ""
echo "Snapshot written to: $OUT"

```

---

### `/root/logos_lrb/tools/make_book_and_push.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/root/logos_lrb"
cd "$REPO_ROOT"

STAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
BOOK="docs/LOGOS_LRB_FULL_BOOK_${STAMP}.md"

# ---- helper: pretty header
h() { echo -e "\n---\n\n## $1\n"; }

# ---- repo meta
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'detached')"
GIT_SHA="$(git rev-parse --short=12 HEAD 2>/dev/null || echo 'unknown')"
GIT_REMOTE="$(git remote get-url origin 2>/dev/null || echo 'no-remote')"

# ---- clean lists (без мусора)
# исключаем build-артефакты: target, node_modules, venv, dist, .git и пр.
EXCLUDES='
  -path */target -prune -o
  -path */node_modules -prune -o
  -path */.git -prune -o
  -path */.venv -prune -o
  -path */venv -prune -o
  -path */dist -prune -o
  -path */build -prune -o
  -path */.idea -prune -o
  -path */.vscode -prune -o
'

# ---- список корней проектов
ROOTS_FILE="docs/snapshots/REPO_ROOTS_${STAMP}.txt"
mkdir -p docs/snapshots
{
  find . $EXCLUDES -type f -name Cargo.toml -printf '%h\n'
  find . $EXCLUDES -type f -name pyproject.toml -printf '%h\n'
  find . $EXCLUDES -type f -name package.json -printf '%h\n'
  printf '%s\n' \
    configs configs/env \
    infra/nginx infra/systemd \
    lrb_core node modules www tools scripts docs
} | sed 's#^\./##' | sort -u > "$ROOTS_FILE"

# ---- begin book
{
  echo "# LOGOS LRB — FULL BOOK (${STAMP})"
  echo
  echo "**Branch:** ${GIT_BRANCH}  "
  echo "**Commit:** ${GIT_SHA}  "
  echo "**Remote:** ${GIT_REMOTE}"
  h "Структура репозитория (чистая, без артефактов)"
  echo '```text'
  # печатаем дерево только до 4 уровней и без мусора
  find . $EXCLUDES -type d \( -name .git -o -name target -o -name node_modules -o -name dist -o -name build -o -name .venv -o -name venv \) -prune -false -o -type d -print \
    | sed 's#^\./##' \
    | awk -F/ 'NF<=4' \
    | sort
  echo '```'

  h "Рабочие модули и пакеты (Cargo/Python/JS)"
  echo '```text'
  cat "$ROOTS_FILE"
  echo '```'

  h "Rust workspace (manifestы)"
  find . $EXCLUDES -type f -name Cargo.toml -print \
    | sed 's#^\./##' | sort \
    | while read -r f; do
        echo -e "\n### \`$f\`\n"
        echo '```toml'
        sed -n '1,200p' "$f"
        echo '```'
      done

  h "Конфиги (genesis, logos_config, env-примеры)"
  for f in $(find configs -maxdepth 2 -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.env' -o -name '*.toml' \) | sort); do
    echo -e "\n### \`$f\`\n"
    echo '```'
    sed -n '1,300p' "$f"
    echo '```'
  done

  h "Инфраструктура: systemd и Nginx"
  for f in $(find infra/systemd -type f -name '*.service' -o -name '*.conf' 2>/dev/null | sort); do
    echo -e "\n### \`$f\`\n"
    echo '```ini'; sed -n '1,300p' "$f"; echo '```'
  done
  for f in $(find infra/nginx -type f \( -name '*.conf' -o -name '*.snippets' \) 2>/dev/null | sort); do
    echo -e "\n### \`$f\`\n"
    echo '```nginx'; sed -n '1,300p' "$f"; echo '```'
  done

  h "OpenAPI (узел /node)"
  if [ -f node/src/openapi/openapi.json ]; then
    echo "**Файл:** node/src/openapi/openapi.json  "
    echo -n "**SHA256:** "
    sha256sum node/src/openapi/openapi.json | awk '{print $1}'
    echo
    echo '```json'
    sed -n '1,400p' node/src/openapi/openapi.json
    echo '```'
  else
    echo "_openapi.json не найден_"
  fi

  h "Метрики и health-ручки (докстринги/описания)"
  grep -Rsn --include='*.rs' -E 'logos_(http|head|finalized|blocks|tx_|bridge|archive)' node 2>/dev/null | sed 's#^\./##' | head -n 400 | sed 's/^/    /'

  h "Скрипты деплоя (канон)"
  for f in $(ls -1 scripts/*.sh 2>/dev/null || true); do
    echo -e "\n### \`$f\`\n"
    echo '```bash'; sed -n '1,200p' "$f"; echo '```'
  done

  h "Суммы и размеры ключевых артефактов"
  echo '```text'
  for f in node/src/openapi/openapi.json configs/genesis.yaml configs/logos_config.yaml; do
    [ -f "$f" ] || continue
    printf "%-40s  %10s  %s\n" "$f" "$(stat -c%s "$f" 2>/dev/null)" "$(sha256sum "$f" | awk '{print $1}')"
  done
  echo '```'

} > "$BOOK"

# аккуратная подсветка завершения
wc -l "$BOOK" | awk '{printf "\nFULL_BOOK lines: %s\n", $1}'
ls -lh "$BOOK"

# ---- git add & push (openapi.json тоже как в каноне)
git add "$BOOK"
[ -f node/src/openapi/openapi.json ] && git add node/src/openapi/openapi.json || true

COMMIT_MSG="docs: FULL BOOK (prod snapshot; canon-aligned structure; clean tree; openapi)"
git commit -m "$COMMIT_MSG" || echo "Nothing to commit (already up to date)."
git push

```

---

### `/root/logos_lrb/tools/make_codebook.sh`

```bash
#!/usr/bin/env sh
# LOGOS LRB — FULL LIVE book: repo + infra в один TXT (с маскировкой секретов)
set -eu

ROOT="$(cd "$(dirname "$0")/.."; pwd)"
OUT_DIR="docs"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT_FILE_TMP="${OUT_DIR}/LRB_FULL_LIVE_${STAMP}.txt.tmp"
OUT_FILE="${OUT_DIR}/LRB_FULL_LIVE_${STAMP}.txt"
SIZE_LIMIT="${SIZE_LIMIT:-2000000}"   # 2 MB per file
REPO_ROOT="/root/logos_lrb"

# --- ВКЛЮЧАЕМ ИЗ РЕПО ---
REPO_GLOBS='
Cargo.toml
README.md
src
lrb_core/src
node/src
modules
core
wallet-proxy
docs
www/wallet
www/explorer
infra/nginx
infra/systemd
scripts
tools
configs
'

# --- ВКЛЮЧАЕМ ИНФРУ С СЕРВЕРА ---
INFRA_FILES='
/etc/nginx/nginx.conf
/etc/nginx/conf.d/*.conf
/etc/nginx/sites-enabled/*
/etc/systemd/system/logos-node.service
/etc/systemd/system/*.service
/etc/systemd/system/*.timer
/etc/systemd/system/logos-node.service.d/*.conf
/etc/prometheus/prometheus.yml
/etc/prometheus/rules/*.yml
/etc/alertmanager/alertmanager.yml
/etc/alertmanager/secrets.env
/etc/grafana/grafana.ini
/etc/grafana/provisioning/datasources/*.yaml
/etc/grafana/provisioning/dashboards/*.yaml
/var/lib/grafana/dashboards/*.json
/opt/logos/www/wallet/*
/opt/logos/www/explorer/*
'

# --- ИСКЛЮЧЕНИЯ ДЛЯ РЕПО ---
EXCLUDES_REPO='
.git
target
node_modules
venv
__pycache__
*.pyc
data.sled
var
*.log
*.pem
*.der
*.crt
*.key
*.zip
*.tar
*.tar.gz
*.7z
LOGOS_LRB_FULL_BOOK.md
'

# язык для подсветки
lang_for() {
  case "${1##*.}" in
    rs) echo "rust" ;; toml) echo "toml" ;; json) echo "json" ;;
    yml|yaml) echo "yaml" ;; sh|bash) echo "bash" ;; py) echo "python" ;;
    js) echo "javascript" ;; ts) echo "typescript" ;; tsx|jsx) echo "tsx" ;;
    html|htm) echo "html" ;; css) echo "css" ;; md) echo "markdown" ;;
    conf|ini|service|timer|env) echo "" ;; *) echo "" ;;
  esac
}

# доверяем расширению, иначе grep -Iq
looks_text() {
  case "$1" in
    *.rs|*.toml|*.json|*.yml|*.yaml|*.sh|*.bash|*.py|*.js|*.ts|*.tsx|*.jsx|*.html|*.htm|*.css|*.md|*.conf|*.ini|*.service|*.timer|*.env) return 0;;
    *) LC_ALL=C grep -Iq . "$1";;
  esac
}

# фильтр исключений репо
should_exclude_repo() {
  f="$1"
  # с двоеточиями — мусор от редакторов
  echo "$f" | grep -q ":" && return 0
  echo "$EXCLUDES_REPO" | while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    [ "${pat#\#}" != "$pat" ] && continue
    case "$f" in */$pat/*|*/$pat|$pat) exit 0;; esac
  done; return 1
}

# маска секретов
mask_secrets() {
  sed -E \
    -e 's/(TELEGRAM_BOT_TOKEN=)[A-Za-z0-9:_-]+/\1***MASKED***/g' \
    -e 's/(TELEGRAM_CHAT_ID=)[0-9-]+/\1***MASKED***/g' \
    -e 's/(LRB_ADMIN_KEY=)[A-Fa-f0-9]+/\1***MASKED***/g' \
    -e 's/(LRB_BRIDGE_KEY=)[A-Fa-f0-9]+/\1***MASKED***/g' \
    -e 's/(LRB_ADMIN_JWT_SECRET=)[A-Za-z0-9._-]+/\1***MASKED***/g'
}

write_header() {
  {
    echo "# FULL LIVE SNAPSHOT — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# sources: $REPO_ROOT + infra (/etc, /opt)"
    echo "# size limit per file: ${SIZE_LIMIT} bytes"
    echo
  } >>"$OUT_FILE_TMP"
}

dump_file() {
  f="$1"
  [ -f "$f" ] || return 0
  echo "$f" | grep -q ":" && return 0     # отсекаем мусорные имена

  sz="$(wc -c <"$f" | tr -d ' ' || echo 0)"
  [ "$sz" -eq 0 ] && { printf "\n## FILE: %s  (SKIPPED, empty)\n" "$f" >>"$OUT_FILE_TMP"; return 0; }
  [ "$sz" -gt "$SIZE_LIMIT" ] && { printf "\n## FILE: %s  (SKIPPED, size=%sb > limit)\n" "$f" "$sz" >>"$OUT_FILE_TMP"; return 0; }

  printf "\n## FILE: %s  (size=%sb)\n" "$f" "$sz" >>"$OUT_FILE_TMP"
  if looks_text "$f"; then
    printf '```\n' >>"$OUT_FILE_TMP"
    case "$f" in
      */alertmanager/secrets.env|*/logos-node.service.d/*|*/nginx/*.conf|*/conf.d/*.conf|*/sites-enabled/*|*/prometheus*.yml|*/grafana/*.ini|*/provisioning/*|*/dashboards/*.json)
        mask_secrets < "$f" >>"$OUT_FILE_TMP" ;;
      *) cat "$f" >>"$OUT_FILE_TMP" ;;
    esac
    printf '\n```\n' >>"$OUT_FILE_TMP"
  else
    printf "\n(SKIPPED, binary/non-text)\n" >>"$OUT_FILE_TMP"
  fi
}

collect_repo() {
  echo "$REPO_GLOBS" | while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    [ "${rel#\#}" != "$rel" ] && continue
    p="$REPO_ROOT/$rel"
    if [ -d "$p" ]; then find "$p" -type f; elif [ -f "$p" ]; then echo "$p"; fi
  done
}

collect_infra() {
  echo "$INFRA_FILES" | while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    [ "${pat#\#}" != "$pat" ] && continue
    for f in $pat; do [ -f "$f" ] && echo "$f"; done
  done
}

main() {
  mkdir -p "$OUT_DIR"
  : >"$OUT_FILE_TMP"
  write_header

  collect_repo  | sort -u | while IFS= read -r p; do
    if should_exclude_repo "$p"; then continue; fi
    dump_file "$p"
  done

  collect_infra | sort -u | while IFS= read -r p; do
    dump_file "$p"
  done

  mv -f "$OUT_FILE_TMP" "$OUT_FILE"
  echo "✅ created: $OUT_FILE"
  cp -f "$OUT_FILE" "${ROOT}/LOGOS_LRB_FULL_BOOK.md" 2>/dev/null || true
}

main "$@"

```

---

### `/root/logos_lrb/tools/make_explorer_snapshot.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_EXPLORER_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_EXPLORER/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_EXPLORER"

echo "# LOGOS Explorer Snapshot" > "$OUT"
echo "" >> "$OUT"
echo "_Автогенерация: \`$(date -u "+%Y-%m-%d %H:%M:%SZ")\`_" >> "$OUT"
echo "" >> "$OUT"

dump_dir () {
  local DIR="$1"
  local TITLE="$2"

  if [ ! -d "$DIR" ]; then
    echo "- [WARN] directory not found: $DIR" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`$DIR\`" >> "$OUT"
  echo "" >> "$OUT"

  find "$DIR" \
    -type f \
    \( \
      -name "*.py"   -o \
      -name "*.html" -o -name "*.htm" -o \
      -name "*.js"   -o \
      -name "*.ts"   -o \
      -name "*.css"  -o \
      -name "*.md"   -o \
      -name "*.json" -o \
      -name "*.toml" -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.sh"   -o \
      -name "*.service" -o -name "*.socket" -o \
      -name "*.conf" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/.venv/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/logs/*" \
    ! -path "*/log/*" \
    ! -name "*.log" \
    ! -name "*.sqlite3" \
    ! -name "*.sqlite" \
    ! -name "*.db" \
    ! -name "*.env" \
  | sort | while read -r FILE; do
        local REL="$FILE"

        echo "" >> "$OUT"
        echo "---" >> "$OUT"
        echo "" >> "$OUT"
        echo "### \`$REL\`" >> "$OUT"
        echo "" >> "$OUT"

        local EXT="${FILE##*.}"
        local LANG=""
        case "$EXT" in
          py)          LANG="python" ;;
          html|htm)    LANG="html" ;;
          js)          LANG="javascript" ;;
          ts)          LANG="typescript" ;;
          css)         LANG="css" ;;
          md)          LANG="markdown" ;;
          json)        LANG="json" ;;
          toml)        LANG="toml" ;;
          yml|yaml)    LANG="yaml" ;;
          sh)          LANG="bash" ;;
          service|socket|conf) LANG="ini" ;;
          *)           LANG="" ;;
        esac

        if [ -n "$LANG" ]; then
          echo "\`\`\`$LANG" >> "$OUT"
        else
          echo "\`\`\`" >> "$OUT"
        fi

        cat "$FILE" >> "$OUT"
        echo "" >> "$OUT"
        echo "\`\`\`" >> "$OUT"
    done
}

dump_file () {
  local FILE="$1"
  local TITLE="$2"

  if [ ! -f "$FILE" ]; then
    echo "- [WARN] file not found: $FILE" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "### \`$FILE\`" >> "$OUT"
  echo "" >> "$OUT"

  local EXT="${FILE##*.}"
  local LANG=""
  case "$EXT" in
    service|socket|conf) LANG="ini" ;;
    *)                   LANG="" ;;
  esac

  if [ -n "$LANG" ]; then
    echo "\`\`\`$LANG" >> "$OUT"
  else
    echo "\`\`\`" >> "$OUT"
  fi

  cat "$FILE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`\`\`" >> "$OUT"
}

# 1. Explorer frontend (предполагаем /www/explorer/*)
dump_dir "/root/logos_lrb/www/explorer" "Explorer Frontend (sources)"

# 2. nginx-конфиги, связанные с explorer/API ноды
dump_file "/etc/nginx/sites-available/logos.conf"           "nginx: logos.conf"
dump_file "/etc/nginx/sites-available/logos_front"          "nginx: logos_front"
dump_file "/etc/nginx/sites-available/logos-node-8000.conf" "nginx: logos-node-8000.conf"

echo ""
echo "Snapshot written to: $OUT"

```

---

### `/root/logos_lrb/tools/make_full_book.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

# Hardening locale and PATH
export LC_ALL=C LANG=C
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

REPO="/root/logos_lrb"
cd "$REPO"

STAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
BOOK="docs/LOGOS_LRB_FULL_BOOK_${STAMP}.md"
ROOTS_FILE="docs/snapshots/REPO_ROOTS_${STAMP}.txt"

# Clean file list (NO parentheses, NO eval)
FILES=$(
  find . -type f \
    -not -path "./.git/*" \
    -not -path "./.git" \
    -not -path "*/target/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/dist/*" \
    -not -path "*/build/*" \
    -not -path "*/.venv/*" \
    -not -path "*/venv/*" \
  | sed 's#^\./##' | sort
)

# Project roots (Cargo/Python/JS) + fixed directories
{
  find . -type f -name Cargo.toml \
    -not -path "./.git/*" -not -path "*/target/*" -not -path "*/node_modules/*" \
    -not -path "*/dist/*"  -not -path "*/build/*"  -not -path "*/.venv/*" -not -path "*/venv/*" \
    -printf '%h\n'
  find . -type f -name pyproject.toml \
    -not -path "./.git/*" -not -path "*/target/*" -not -path "*/node_modules/*" \
    -not -path "*/dist/*"  -not -path "*/build/*"  -not -path "*/.venv/*" -not -path "*/venv/*" \
    -printf '%h\n'
  find . -type f -name package.json \
    -not -path "./.git/*" -not -path "*/target/*" -not -path "*/node_modules/*" \
    -not -path "*/dist/*"  -not -path "*/build/*"  -not -path "*/.venv/*" -not -path "*/venv/*" \
    -printf '%h\n'
  printf '%s\n' configs configs/env infra/nginx infra/systemd lrb_core node modules www tools scripts docs
} | sed 's#^\./##' | sort -u > "$ROOTS_FILE"

# Header
{
  echo "# LOGOS LRB — FULL BOOK (${STAMP})"
  echo
  echo "**Branch:** $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)  "
  echo "**Commit:** $(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)  "
  echo "**Remote:** $(git remote get-url origin 2>/dev/null || echo none)"
  echo
  echo "---"
  echo
  echo "## Repository Structure (clean, no artifacts)"
  echo '```text'
  find . -type d \
    -not -path "./.git/*" -not -path "./.git" \
    -not -path "*/target/*" -not -path "*/node_modules/*" \
    -not -path "*/dist/*"  -not -path "*/build/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" \
  | sed 's#^\./##' | awk -F/ 'NF<=6' | sort
  echo '```'
  echo
  echo "## Project Roots (Cargo/Python/JS)"
  echo '```text'
  cat "$ROOTS_FILE"
  echo '```'
  echo
  echo "## Full File Contents"
} > "$BOOK"

# Embed every file (text: full, binary: only hash+size)
for f in $FILES; do
  # Skip previous books
  case "$f" in
    docs/LOGOS_LRB_FULL_BOOK_*) continue ;;
  esac

  SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
  SHA=$( (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f" 2>/dev/null) | awk '{print $1}' )

  if grep -Iq . "$f" 2>/dev/null; then
    {
      echo
      echo "### \`$f\`"
      echo
      [ -n "$SHA" ] && echo "**SHA256:** $SHA  |  **size:** ${SIZE} bytes**"
      echo
      echo '```'
      cat "$f"
      echo
      echo '```'
    } >> "$BOOK"
  else
    {
      echo
      echo "### \`$f\` (binary)"
      echo
      [ -n "$SHA" ] && echo "**SHA256:** $SHA  |  **size:** ${SIZE} bytes**"
    } >> "$BOOK"
  fi
done

# Footer
{
  echo
  echo "---"
  echo
  echo "## Summary"
  echo "- Total files: $(printf '%s\n' $FILES | wc -l)"
  echo "- Book SHA256: $( (sha256sum "$BOOK" 2>/dev/null || shasum -a 256 "$BOOK" 2>/dev/null) | awk '{print $1}')"
} >> "$BOOK"

# Git push
git add "$BOOK" || true
[ -f node/src/openapi/openapi.json ] && git add node/src/openapi/openapi.json || true
git commit -m "docs: FULL BOOK (complete snapshot; all text files included; binaries hashed)" || true
git push

# Output
wc -l "$BOOK" || true
ls -lh "$BOOK" || true

```

---

### `/root/logos_lrb/tools/make_full_snapshot_live.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

OUTDIR="${OUTDIR:-/root/logos_snapshot}"
STAMP=$(date +%Y%m%d_%H%M)
OUT="$OUTDIR/LRB_FULL_LIVE_${STAMP}.txt"
MAX=${MAX:-800000}  # макс размер включаемого файла (байт)

mkdir -p "$OUTDIR"

say(){ echo "$@" >&2; }
add_head(){
  echo -e "\n\n## FILE: $1  (size=${2}b)\n\`\`\`" >> "$OUT"
}
add_tail(){
  echo -e "\n\`\`\`" >> "$OUT"
}

# Источники (живые пути)
SRC_LIST=(
  "/root/logos_lrb"                   # весь код репо
  "/opt/logos/www/wallet"             # кошелёк
  "/etc/systemd/system/logos-node@.service"
  "/etc/systemd/system/logos-healthcheck.service"
  "/etc/systemd/system/logos-healthcheck.timer"
  "/etc/nginx/sites-available/logos-api-lb.conf"
  "/usr/local/bin/logos_healthcheck.sh"
)

# Заголовок
{
  echo "# FULL LIVE SNAPSHOT — $(date -u +%FT%TZ)"
  echo "# sources:"
  for s in "${SRC_LIST[@]}"; do echo "#  - $s"; done
  echo "# size limit per file: ${MAX} bytes"
  echo
} > "$OUT"

# Вспомогательные функции
is_text(){
  # бинарники/картинки отсекаем простым тестом: попытка вывести «без нулевых байтов»
  # или используем file(1) если есть
  if command -v file >/dev/null 2>&1; then
    file -b --mime "$1" | grep -qiE 'text|json|xml|yaml|toml|javascript|html|css' && return 0 || return 1
  else
    grep -Iq . "$1" && return 0 || return 1
  fi
}

emit_file(){
  local f="$1"
  [ -f "$f" ] || return 0
  # исключения
  case "$f" in
    *.pem|*.key|*.crt|*.p12|*.so|*.bin|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.woff|*.woff2|*.ttf) return 0;;
  esac
  local sz
  sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if [ "$sz" -gt "$MAX" ]; then
    echo -e "\n\n## FILE: $f  (SKIPPED, size=${sz}b > ${MAX})" >> "$OUT"
    return 0
  fi
  if ! is_text "$f"; then
    echo -e "\n\n## FILE: $f  (SKIPPED, binary/non-text size=${sz}b)" >> "$OUT"
    return 0
  fi
  add_head "$f" "$sz"
  sed -e 's/\r$//' "$f" >> "$OUT"
  add_tail
}

# 1) Репозиторий: только текстовые файлы, игнорим target/node_modules/dist
if [ -d /root/logos_lrb ]; then
  say "[*] collecting /root/logos_lrb"
  cd /root/logos_lrb
  # берём отслеживаемые git'ом; если git недоступен — найдём все текстовые расширения
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files | while read -r f; do
      case "$f" in target/*|**/target/*|node_modules/*|dist/*) continue;; esac
      emit_file "/root/logos_lrb/$f"
    done
  else
    find . -type f ! -path "./target/*" ! -path "./node_modules/*" ! -path "./dist/*" \
      -regextype posix-extended -regex '.*\.(rs|toml|md|sh|bash|zsh|service|timer|conf|nginx|yaml|yml|json|ts|tsx|js|mjs|jsx|html|htm|css|go|py|proto|ini|cfg|txt)$' \
      -print0 | xargs -0 -I{} bash -c 'emit_file "{}"'
  fi
  cd - >/dev/null
fi

# 2) Статика кошелька
if [ -d /opt/logos/www/wallet ]; then
  say "[*] collecting /opt/logos/www/wallet"
  find /opt/logos/www/wallet -type f -print0 | while IFS= read -r -d '' f; do emit_file "$f"; done
fi

# 3) systemd units
for u in /etc/systemd/system/logos-node@.service /etc/systemd/system/logos-healthcheck.service /etc/systemd/system/logos-healthcheck.timer; do
  [ -f "$u" ] && emit_file "$u"
done

# 4) nginx site
[ -f /etc/nginx/sites-available/logos-api-lb.conf ] && emit_file /etc/nginx/sites-available/logos-api-lb.conf

# 5) healthcheck script
[ -f /usr/local/bin/logos_healthcheck.sh ] && emit_file /usr/local/bin/logos_healthcheck.sh

# 6) Живые .env → в слепок как обезличенные *.example
sanitize_env(){
  sed -E \
    -e 's/^(LRB_NODE_SK_HEX)=.*/\1=CHANGE_ME_64_HEX/' \
    -e 's/^(LRB_ADMIN_KEY)=.*/\1=CHANGE_ADMIN_KEY/' \
    -e 's/^(LRB_BRIDGE_KEY)=.*/\1=CHANGE_ME/' \
    -e 's/^(HOT_WALLET_PRIVATE_KEY)=.*/\1=CHANGE_ME/' \
    -e 's/^(TG_TOKEN)=.*/\1=CHANGE_ME/' \
    -e 's/^(TG_CHAT_ID)=.*/\1=CHANGE_ME/' \
    "$1"
}
if ls /etc/logos/node-*.env >/dev/null 2>&1; then
  for f in /etc/logos/node-*.env; do
    tmp="$(mktemp)"; sanitize_env "$f" > "$tmp"
    sz=$(stat -c%s "$tmp" 2>/dev/null || echo 0)
    add_head "${f}.example" "$sz"
    cat "$tmp" >> "$OUT"
    add_tail
    rm -f "$tmp"
  done
fi

echo "[ok] wrote $OUT"

```

---

### `/root/logos_lrb/tools/make_global_code_snapshot.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

# Определяем корень проекта относительно самого скрипта
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."; pwd)"

SNAP_NAME="LOGOS_GLOBAL_CODE_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
mkdir -p "$ROOT_DIR/docs"
OUT="$ROOT_DIR/docs/$SNAP_NAME"

echo "# LOGOS Global Code Snapshot" > "$OUT"
echo "" >> "$OUT"
echo "_Автогенерация: \`$(date -u "+%Y-%m-%d %H:%M:%SZ")\`_" >> "$OUT"
echo "" >> "$OUT"

dump_dir () {
  local DIR="$1"
  local TITLE="$2"

  if [ ! -d "$DIR" ]; then
    echo "- [WARN] directory not found: $DIR" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`$DIR\`" >> "$OUT"
  echo "" >> "$OUT"

  find "$DIR" \
    -type f \
    \( \
      -name "*.rs"   -o \
      -name "*.toml" -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.sh"   -o \
      -name "*.service" -o -name "*.socket" -o \
      -name "*.py"   -o \
      -name "*.html" -o -name "*.htm" -o \
      -name "*.js"   -o \
      -name "*.ts"   -o \
      -name "*.css"  -o \
      -name "*.md"   -o \
      -name "*.json" -o \
      -name "nginx.conf" -o -name "*.conf" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/target/*" \
    ! -path "*/.venv/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/data.sled/*" \
    ! -path "*/data.sled.*/*" \
    ! -path "*/bridge_journal.sled/*" \
    ! -path "*/logs/*" \
    ! -path "*/log/*" \
    ! -name "*.log" \
    ! -name "*.sqlite" \
    ! -name "*.db" \
    ! -name "*.bak" \
    ! -name "*.backup" \
    ! -name "LOGOS_GLOBAL_CODE_SNAPSHOT_*.md" \
    ! -path "$OUT" \
  | sort | while read -r FILE; do
        local REL="$FILE"

        echo "" >> "$OUT"
        echo "---" >> "$OUT"
        echo "" >> "$OUT"
        echo "### \`$REL\`" >> "$OUT"
        echo "" >> "$OUT"

        local EXT="${FILE##*.}"
        local LANG=""
        case "$EXT" in
          rs)     LANG="rust" ;;
          toml)   LANG="toml" ;;
          yml|yaml) LANG="yaml" ;;
          sh)     LANG="bash" ;;
          service|socket|conf) LANG="ini" ;;
          py)     LANG="python" ;;
          html|htm) LANG="html" ;;
          js)     LANG="javascript" ;;
          ts)     LANG="typescript" ;;
          css)    LANG="css" ;;
          md)     LANG="markdown" ;;
          json)   LANG="json" ;;
          *)      LANG="" ;;
        esac

        if [ -n "$LANG" ]; then
          echo "\`\`\`$LANG" >> "$OUT"
        else
          echo "\`\`\`" >> "$OUT"
        fi

        cat "$FILE" >> "$OUT"
        echo "" >> "$OUT"
        echo "\`\`\`" >> "$OUT"
    done
}

# 1. Основной репозиторий LOGOS LRB (ядро, нода, модули, www, скрипты)
dump_dir "/root/logos_lrb" "LOGOS LRB Repository (core, node, modules, www, scripts)"

# 2. Веб / лэндинг / боты
dump_dir "/var/www/logos" "Web / Landing / Wallet / Explorer / Bots"

# 3. Опционально: опт-директории с конфигами/скриптами
dump_dir "/opt/logos"       "Opt LOGOS (binaries/configs/scripts)"
dump_dir "/opt/logos-agent" "Opt LOGOS Agent"
dump_dir "/opt/logos_node"  "Opt LOGOS Node (legacy)"

echo ""
echo "Snapshot written to: $OUT"

```

---

### `/root/logos_lrb/tools/make_wallet_explorer_snapshot.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_WALLET_EXPLORER_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_WALLET_EXPLORER/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_WALLET_EXPLORER"

echo "# LOGOS Wallet + Explorer Snapshot" > "$OUT"
echo "" >> "$OUT"
echo "_Автогенерация: \`$(date -u "+%Y-%m-%d %H:%M:%SZ")\`_" >> "$OUT"
echo "" >> "$OUT"

dump_dir () {
  local DIR="$1"
  local TITLE="$2"

  if [ ! -d "$DIR" ]; then
    echo "- [WARN] directory not found: $DIR" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`$DIR\`" >> "$OUT"
  echo "" >> "$OUT"

  find "$DIR" \
    -type f \
    \( \
      -name "*.py"   -o \
      -name "*.html" -o -name "*.htm" -o \
      -name "*.js"   -o \
      -name "*.ts"   -o \
      -name "*.css"  -o \
      -name "*.md"   -o \
      -name "*.json" -o \
      -name "*.toml" -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.sh"   -o \
      -name "*.service" -o -name "*.socket" -o \
      -name "*.conf" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/.venv/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/logs/*" \
    ! -path "*/log/*" \
    ! -name "*.log" \
    ! -name "*.sqlite3" \
    ! -name "*.sqlite" \
    ! -name "*.db" \
    ! -name "*.env" \
  | sort | while read -r FILE; do
        local REL="$FILE"

        echo "" >> "$OUT"
        echo "---" >> "$OUT"
        echo "" >> "$OUT"
        echo "### \`$REL\`" >> "$OUT"
        echo "" >> "$OUT"

        local EXT="${FILE##*.}"
        local LANG=""
        case "$EXT" in
          py)          LANG="python" ;;
          html|htm)    LANG="html" ;;
          js)          LANG="javascript" ;;
          ts)          LANG="typescript" ;;
          css)         LANG="css" ;;
          md)          LANG="markdown" ;;
          json)        LANG="json" ;;
          toml)        LANG="toml" ;;
          yml|yaml)    LANG="yaml" ;;
          sh)          LANG="bash" ;;
          service|socket|conf) LANG="ini" ;;
          *)           LANG="" ;;
        esac

        if [ -n "$LANG" ]; then
          echo "\`\`\`$LANG" >> "$OUT"
        else
          echo "\`\`\`" >> "$OUT"
        fi

        cat "$FILE" >> "$OUT"
        echo "" >> "$OUT"
        echo "\`\`\`" >> "$OUT"
    done
}

dump_file () {
  local FILE="$1"
  local TITLE="$2"

  if [ ! -f "$FILE" ]; then
    echo "- [WARN] file not found: $FILE" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "### \`$FILE\`" >> "$OUT"
  echo "" >> "$OUT"

  local EXT="${FILE##*.}"
  local LANG=""
  case "$EXT" in
    service|socket|conf) LANG="ini" ;;
    *)                   LANG="" ;;
  esac

  if [ -n "$LANG" ]; then
    echo "\`\`\`$LANG" >> "$OUT"
  else
    echo "\`\`\`" >> "$OUT"
  fi

  cat "$FILE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`\`\`" >> "$OUT"
}

# 1. Frontend: wallet + explorer (исходники)
dump_dir "/root/logos_lrb/www" "Wallet + Explorer Frontend (sources)"

# 2. Wallet-proxy backend (исходники)
dump_dir "/root/logos_lrb/wallet-proxy" "Wallet Proxy Backend (sources)"

# 3. Wallet-proxy backend (боевой деплой, без venv/logs/db/env)
dump_dir "/opt/logos/wallet-proxy" "Wallet Proxy Backend (deployed code)"

# 4. Nginx configs, связанные с кошельком/эксплорером
dump_file "/etc/nginx/sites-available/logos.conf"         "nginx: logos.conf"
dump_file "/etc/nginx/sites-available/logos_front"        "nginx: logos_front"
dump_file "/etc/nginx/sites-available/logos-node-8000.conf" "nginx: logos-node-8000.conf"

echo ""
echo "Snapshot written to: $OUT"

```

---

### `/root/logos_lrb/tools/make_wallet_snapshot.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_WALLET_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_WALLET/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_WALLET"

echo "# LOGOS Wallet Snapshot" > "$OUT"
echo "" >> "$OUT"
echo "_Автогенерация: \`$(date -u "+%Y-%m-%d %H:%M:%SZ")\`_" >> "$OUT"
echo "" >> "$OUT"

dump_dir () {
  local DIR="$1"
  local TITLE="$2"

  if [ ! -d "$DIR" ]; then
    echo "- [WARN] directory not found: $DIR" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`$DIR\`" >> "$OUT"
  echo "" >> "$OUT"

  find "$DIR" \
    -type f \
    \( \
      -name "*.py"   -o \
      -name "*.html" -o -name "*.htm" -o \
      -name "*.js"   -o \
      -name "*.ts"   -o \
      -name "*.css"  -o \
      -name "*.md"   -o \
      -name "*.json" -o \
      -name "*.toml" -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.sh"   -o \
      -name "*.service" -o -name "*.socket" -o \
      -name "*.conf" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/.venv/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/logs/*" \
    ! -path "*/log/*" \
    ! -name "*.log" \
    ! -name "*.sqlite3" \
    ! -name "*.sqlite" \
    ! -name "*.db" \
    ! -name "*.env" \
  | sort | while read -r FILE; do
        local REL="$FILE"

        echo "" >> "$OUT"
        echo "---" >> "$OUT"
        echo "" >> "$OUT"
        echo "### \`$REL\`" >> "$OUT"
        echo "" >> "$OUT"

        local EXT="${FILE##*.}"
        local LANG=""
        case "$EXT" in
          py)          LANG="python" ;;
          html|htm)    LANG="html" ;;
          js)          LANG="javascript" ;;
          ts)          LANG="typescript" ;;
          css)         LANG="css" ;;
          md)          LANG="markdown" ;;
          json)        LANG="json" ;;
          toml)        LANG="toml" ;;
          yml|yaml)    LANG="yaml" ;;
          sh)          LANG="bash" ;;
          service|socket|conf) LANG="ini" ;;
          *)           LANG="" ;;
        esac

        if [ -n "$LANG" ]; then
          echo "\`\`\`$LANG" >> "$OUT"
        else
          echo "\`\`\`" >> "$OUT"
        fi

        cat "$FILE" >> "$OUT"
        echo "" >> "$OUT"
        echo "\`\`\`" >> "$OUT"
    done
}

dump_file () {
  local FILE="$1"
  local TITLE="$2"

  if [ ! -f "$FILE" ]; then
    echo "- [WARN] file not found: $FILE" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "### \`$FILE\`" >> "$OUT"
  echo "" >> "$OUT"

  local EXT="${FILE##*.}"
  local LANG=""
  case "$EXT" in
    service|socket|conf) LANG="ini" ;;
    *)                   LANG="" ;;
  esac

  if [ -n "$LANG" ]; then
    echo "\`\`\`$LANG" >> "$OUT"
  else
    echo "\`\`\`" >> "$OUT"
  fi

  cat "$FILE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`\`\`" >> "$OUT"
}

# 1. Wallet frontend (предполагаем /www/wallet/*)
dump_dir "/root/logos_lrb/www/wallet" "Wallet Frontend (sources)"

# 2. Wallet-proxy backend (исходники)
dump_dir "/root/logos_lrb/wallet-proxy" "Wallet Proxy Backend (sources)"

# 3. Wallet-proxy backend (боевой код без venv/logs/db/env)
dump_dir "/opt/logos/wallet-proxy" "Wallet Proxy Backend (deployed code)"

# 4. nginx-конфиги, связанные с кошельком/эксплорером
dump_file "/etc/nginx/sites-available/logos.conf"           "nginx: logos.conf"
dump_file "/etc/nginx/sites-available/logos_front"          "nginx: logos_front"
dump_file "/etc/nginx/sites-available/logos-node-8000.conf" "nginx: logos-node-8000.conf"

echo ""
echo "Snapshot written to: $OUT"

```

---

### `/root/logos_lrb/tools/make_web_stack_snapshot.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_WEB_STACK_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_WEB_STACK/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_WEB_STACK"

echo "# LOGOS Web Stack Snapshot" > "$OUT"
echo "" >> "$OUT"
echo "_Автогенерация: \`$(date -u "+%Y-%m-%d %H:%M:%SZ")\`_" >> "$OUT"
echo "" >> "$OUT"

dump_dir () {
  local DIR="$1"
  local TITLE="$2"

  if [ ! -d "$DIR" ]; then
    echo "- [WARN] directory not found: $DIR" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`$DIR\`" >> "$OUT"
  echo "" >> "$OUT"

  find "$DIR" \
    -type f \
    \( \
      -name "*.py"   -o \
      -name "*.html" -o -name "*.htm" -o \
      -name "*.js"   -o \
      -name "*.ts"   -o \
      -name "*.css"  -o \
      -name "*.md"   -o \
      -name "*.json" -o \
      -name "*.toml" -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.sh"   -o \
      -name "*.service" -o -name "*.socket" -o \
      -name "*.conf" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/.venv/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/logs/*" \
    ! -path "*/log/*" \
    ! -name "*.log" \
    ! -name "*.sqlite3" \
    ! -name "*.sqlite" \
    ! -name "*.db" \
  | sort | while read -r FILE; do
        local REL="$FILE"

        echo "" >> "$OUT"
        echo "---" >> "$OUT"
        echo "" >> "$OUT"
        echo "### \`$REL\`" >> "$OUT"
        echo "" >> "$OUT"

        local EXT="${FILE##*.}"
        local LANG=""
        case "$EXT" in
          py)          LANG="python" ;;
          html|htm)    LANG="html" ;;
          js)          LANG="javascript" ;;
          ts)          LANG="typescript" ;;
          css)         LANG="css" ;;
          md)          LANG="markdown" ;;
          json)        LANG="json" ;;
          toml)        LANG="toml" ;;
          yml|yaml)    LANG="yaml" ;;
          sh)          LANG="bash" ;;
          service|socket|conf) LANG="ini" ;;
          *)           LANG="" ;;
        esac

        if [ -n "$LANG" ]; then
          echo "\`\`\`$LANG" >> "$OUT"
        else
          echo "\`\`\`" >> "$OUT"
        fi

        cat "$FILE" >> "$OUT"
        echo "" >> "$OUT"
        echo "\`\`\`" >> "$OUT"
    done
}

dump_file () {
  local FILE="$1"
  local TITLE="$2"

  if [ ! -f "$FILE" ]; then
    echo "- [WARN] file not found: $FILE" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "### \`$FILE\`" >> "$OUT"
  echo "" >> "$OUT"

  local EXT="${FILE##*.}"
  local LANG=""
  case "$EXT" in
    service|socket|conf) LANG="ini" ;;
    env)                 LANG="bash" ;;
    *)                   LANG="" ;;
  esac

  if [ -n "$LANG" ]; then
    echo "\`\`\`$LANG" >> "$OUT"
  else
    echo "\`\`\`" >> "$OUT"
  fi

  cat "$FILE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`\`\`" >> "$OUT"
}

# 1. Лендинг и фронтенд
dump_dir "/var/www/logos/landing" "Landing / Frontend"

# 2. Telegram guard bot
dump_dir "/var/www/logos/landing/logos_tg_bot/logos_guard_bot" "Telegram Guard Bot"

# 3. X Guard (Twitter integration) — модуль из репозитория
dump_dir "/root/logos_lrb/modules/x_guard" "X Guard (Twitter Guard Service)"

# 4. Airdrop API backend
dump_dir "/opt/logos/airdrop-api" "Airdrop API Backend"

# 5. systemd и env
dump_file "/etc/systemd/system/logos-airdrop-api.service" "systemd: logos-airdrop-api.service"
dump_file "/etc/systemd/system/logos-x-guard.service"     "systemd: logos-x-guard.service"
dump_file "/etc/logos/airdrop-api.env"                    "Env: /etc/logos/airdrop-api.env"

echo ""
echo "Snapshot written to: $OUT"

```

---

### `/root/logos_lrb/tools/prepare_payer.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

API=${API:-http://127.0.0.1:8080}
FROM=${FROM:-PAYER}
AMOUNT=${AMOUNT:-1000000}
NONCE=${NONCE:-0}

JWT_SECRET="$(sed -n 's/^LRB_ADMIN_JWT_SECRET=//p' /etc/logos/keys.env | tr -d '[:space:]')"
if [[ -z "${JWT_SECRET}" ]]; then
  echo "[ERR] LRB_ADMIN_JWT_SECRET is empty"; exit 1
fi

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

H=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
P=$(printf '{"sub":"admin","iat":1690000000,"exp":2690000000}' | b64url)
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary | b64url)
JWT="$H.$P.$S"

echo "[*] set_balance $FROM = $AMOUNT"
curl -sf -X POST "$API/admin/set_balance" \
  -H "X-Admin-JWT: $JWT" -H 'Content-Type: application/json' \
  -d "{\"rid\":\"$FROM\",\"amount\":$AMOUNT}" || { echo; echo "[ERR] set_balance failed"; exit 1; }
echo

echo "[*] set_nonce $FROM = $NONCE"
curl -sf -X POST "$API/admin/set_nonce" \
  -H "X-Admin-JWT: $JWT" -H 'Content-Type: application/json' \
  -d "{\"rid\":\"$FROM\",\"value\":$NONCE}" || { echo; echo "[ERR] set_nonce failed"; exit 1; }
echo

echo "[*] balance:"
curl -sf "$API/balance/$FROM" || true
echo

```

---

### `/root/logos_lrb/tools/repo_audit.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

fail=0
pass(){ printf "  [OK]  %s\n" "$1"; }
err(){  printf "  [FAIL] %s\n" "$1"; fail=1; }

echo "== GIT STATUS =="
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "not a git repo"; exit 1; }
git status --porcelain

echo "== CORE CODE =="
[ -d lrb_core/src ] && pass "lrb_core/src" || err "lrb_core/src missing"
[ -f lrb_core/src/ledger.rs ] && pass "lrb_core ledger.rs" || err "ledger.rs missing"
[ -f lrb_core/src/rcp_engine.rs ] && pass "lrb_core rcp_engine.rs" || err "rcp_engine.rs missing"
[ -f lrb_core/src/phase_filters.rs ] && pass "lrb_core phase_filters.rs" || err "phase_filters.rs missing"
[ -f lrb_core/src/crypto.rs ] && pass "lrb_core crypto.rs (AEAD)" || err "crypto.rs missing"

echo "== NODE =="
for f in node/src/main.rs node/src/api.rs node/src/metrics.rs node/src/guard.rs node/src/storage.rs node/src/version.rs; do
  [ -f "$f" ] && pass "$f" || err "$f missing"
done
[ -f node/src/openapi.json ] && pass "node/src/openapi.json" || err "openapi.json missing"
[ -f node/build.rs ] && pass "node/build.rs" || err "node/build.rs missing"
[ -f node/Cargo.toml ] && pass "node/Cargo.toml" || err "node/Cargo.toml missing"

echo "== MODULES DIR =="
[ -d modules ] && pass "modules/ present" || err "modules/ missing"

echo "== WALLET =="
for f in www/wallet/index.html www/wallet/wallet.css www/wallet/wallet.js; do
  [ -f "$f" ] && pass "$f" || err "$f missing"
done

echo "== INFRA =="
for f in infra/systemd/logos-node@.service infra/systemd/logos-healthcheck.service infra/systemd/logos-healthcheck.timer \
         infra/nginx/logos-api-lb.conf.example; do
  [ -f "$f" ] && pass "$f" || err "$f missing"
done

echo "== SCRIPTS =="
[ -f scripts/bootstrap_node.sh ] && pass "scripts/bootstrap_node.sh" || err "bootstrap_node.sh missing"
[ -f scripts/logos_healthcheck.sh ] && pass "scripts/logos_healthcheck.sh" || err "logos_healthcheck.sh missing"

echo "== TOOLS =="
[ -f tools/bench/go/bench.go ] && pass "bench v4: tools/bench/go/bench.go" || err "bench.go missing"
[ -f tools/sdk/ts/index.mjs ] && pass "TS SDK: tools/sdk/ts/index.mjs" || err "TS SDK missing"
[ -f tools/sdk/ts/sdk_test.mjs ] && pass "TS SDK test" || err "TS SDK test missing"
[ -f tools/sdk/go/logosapi.go ] && pass "Go SDK: tools/sdk/go/logosapi.go" || err "Go SDK missing"

echo "== CONFIGS / EXAMPLES =="
ls -1 configs/env/*.example >/dev/null 2>&1 && pass "env examples present" || err "env examples missing"
# убедимся что реальные .env не попали
if git ls-files | grep -E '^configs/env/.*\.env$' >/dev/null; then
  err "real .env found in repo"
else
  pass "no real .env tracked"
fi

echo "== SNAPSHOTS (optional) =="
[ -d snapshots ] && echo "  [info] snapshots/ exists (ok)"; true

echo "== SIZE / SUMMARY =="
echo "  tracked files: $(git ls-files | wc -l)"
echo "  repo disk size: $(du -sh . | cut -f1)"

echo "== SECRET LEAK SCAN (quick) =="
git grep -nE '(PRIVATE|SECRET|BEGIN (RSA|EC) PRIVATE KEY)' || true
git grep -nE 'LRB_NODE_SK_HEX=[0-9a-fA-F]{64}$' || true

echo
if [ $fail -eq 0 ]; then
  echo "[RESULT] REPO OK"
else
  echo "[RESULT] FAILS PRESENT"; exit 1
fi

```

---

### `/root/logos_lrb/tools/test_tx.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

NODE="${NODE:-http://127.0.0.1:8080}"

echo "[*] Installing deps (jq, pip, pynacl, base58)..."
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y jq python3-pip >/dev/null 2>&1 || true
python3 -m pip install --quiet --no-input pynacl base58

echo "[*] Generating key, RID and signed tx..."
PYOUT="$(python3 - <<'PY'
import json, base64, base58
from nacl.signing import SigningKey

sk = SigningKey.generate()
vk = sk.verify_key
pk = bytes(vk)
rid = base58.b58encode(pk).decode()

amount = 12345
nonce  = 1

msg_obj = {
    "from": rid,
    "to": rid,
    "amount": amount,
    "nonce": nonce,
    "public_key": base64.b64encode(pk).decode()
}
msg = json.dumps(msg_obj, separators=(',',':')).encode()
sig = sk.sign(msg).signature

tx = {
    "from": rid,
    "to": rid,
    "amount": amount,
    "nonce": nonce,
    "public_key_b58": base58.b58encode(pk).decode(),
    "signature_b64": base64.b64encode(sig).decode()
}

print(json.dumps({"rid": rid, "tx": tx}))
PY
)"

RID="$(echo "$PYOUT" | jq -r .rid)"
TX="$(echo "$PYOUT" | jq -c .tx)"

echo "[*] Healthz:"
curl -s "$NODE/healthz" | jq .

echo "[*] Head before:"
curl -s "$NODE/head" | jq .

echo "[*] Submitting tx..."
RESP="$(curl -s -X POST "$NODE/submit_tx" -H 'content-type: application/json' -d "$TX")" || true
echo "$RESP" | jq . || true

# Если узел отклонил (например, nonce/balance), покажем причину и выйдем
if ! echo "$RESP" | jq -e '.accepted == true' >/dev/null 2>&1 ; then
  echo "[!] TX not accepted. Response above."
  exit 1
fi

TXID="$(echo "$RESP" | jq -r .tx_id)"
echo "[*] tx_id=$TXID"

echo "[*] Waiting 2s for block producer..."
sleep 2

echo "[*] Head after:"
curl -s "$NODE/head" | jq .

echo "[*] Balance for RID:"
curl -s "$NODE/balance/$RID" | jq .

echo "[*] Done."

```

---

### `/root/logos_lrb/tools/tx_load.sh`

```bash
#!/usr/bin/env bash
# tx_load.sh — надёжная нагрузка через LB/BE без конфликтов nonce.
# Отправка батчей строго по порядку внутри каждого RID (шарда).
# Параллельность — между шардами.
#
# Usage:
#   BACKEND=http://127.0.0.1:8080 ./tx_load.sh M K C [AMOUNT] [SHARDS]
#   (если хочешь через LB: BACKEND=http://127.0.0.1/api)
set -euo pipefail
BACKEND="${BACKEND:-http://127.0.0.1:8080}"   # куда шлём ВСЁ: faucet, canon, submit
M="${1:-1000}"     # всего tx
K="${2:-100}"      # размер батча
C="${3:-10}"       # параллельность шардов (RID)
AMOUNT="${4:-1}"
SHARDS="${5:-$C}"  # число независимых отправителей (RID)

need() { command -v "$1" >/dev/null || { echo "need $1"; exit 1; }; }
need curl; need jq; need openssl; need xxd; need seq; need awk; need sort; need xargs

work="$(mktemp -d -t lrb_load_XXXX)"
trap 'rm -rf "$work"' EXIT
echo "[*] work dir: $work"
per_shard=$(( (M + SHARDS - 1) / SHARDS ))
echo "[*] total=$M  shards=$SHARDS  per_shard≈$per_shard  batch=$K  parallel=$C  amount=$AMOUNT"
echo "[*] BACKEND=$BACKEND"

make_rid() {
  local out="$1"
  openssl genpkey -algorithm Ed25519 -out "$out/ed25519.sk.pem" >/dev/null 2>&1
  openssl pkey -in "$out/ed25519.sk.pem" -pubout -outform DER | tail -c 32 | xxd -p -c 32 > "$out/pk.hex"
  python3 - "$out/pk.hex" > "$out/RID.txt" <<'PY'
import sys
ALPH="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
pk=bytes.fromhex(open(sys.argv[1]).read().strip())
n=int.from_bytes(pk,'big'); s=""
while n>0: n,r=divmod(n,58); s=ALPH[r]+s
z=0
for b in pk:
    if b==0: z+=1
    else: break
print("1"*z + (s or "1"))
PY
}

# 1) Готовим шардовые каталоги: RID, faucet, nonce0
for s in $(seq 1 "$SHARDS"); do
  sd="$work/shard_$s"; mkdir -p "$sd/batches"
  make_rid "$sd"
  RID=$(cat "$sd/RID.txt")
  echo "[*] shard $s RID=$RID"
  curl -s -X POST "$BACKEND/faucet" -H 'Content-Type: application/json' \
    -d "{\"rid\":\"${RID}\",\"amount\":500000000}" >/dev/null
  NONCE0=$(curl -s "$BACKEND/balance/${RID}" | jq -r .nonce)
  echo "$NONCE0" > "$sd/nonce0"
done

# 2) Генерация подписанных tx для каждого шарда (последовательно → без гонок)
for s in $(seq 1 "$SHARDS"); do
  sd="$work/shard_$s"
  RID=$(cat "$sd/RID.txt")
  SK="$sd/ed25519.sk.pem"
  NONCE0=$(cat "$sd/nonce0")
  start=$(( (s-1)*per_shard + 1 ))
  end=$(( s*per_shard )); [ "$end" -gt "$M" ] && end="$M"
  count=$(( end - start + 1 )); [ "$count" -le 0 ] && continue
  echo "[*] shard $s: tx $start..$end (count=$count)"

  : > "$sd/cur_lines.jsonl"; idx=0; file_lines=0
  for i in $(seq 1 "$count"); do
    nonce=$(( NONCE0 + i ))
    echo "{\"tx\":{\"from\":\"$RID\",\"to\":\"$RID\",\"amount\":$AMOUNT,\"nonce\":$nonce}}" > "$sd/canon_payload.json"
    CANON_HEX=$(curl -s -X POST "$BACKEND/debug_canon" -H "Content-Type: application/json" \
      --data-binary @"$sd/canon_payload.json" | jq -r .canon_hex)
    echo -n "$CANON_HEX" | xxd -r -p > "$sd/canon.bin"
    openssl pkeyutl -sign -rawin -inkey "$SK" -in "$sd/canon.bin" -out "$sd/sig.bin" >/dev/null 2>&1
    SIG_HEX=$(xxd -p -c 256 "$sd/sig.bin")
    printf '{"from":"%s","to":"%s","amount":%s,"nonce":%s,"sig_hex":"%s"}\n' \
      "$RID" "$RID" "$AMOUNT" "$nonce" "$SIG_HEX" >> "$sd/cur_lines.jsonl"
    file_lines=$((file_lines+1))
    if [ "$file_lines" -ge "$K" ]; then
      idx=$((idx+1)); jq -s '{txs:.}' "$sd/cur_lines.jsonl" > "$sd/batches/batch_${s}_$(printf "%05d" $idx).json"
      : > "$sd/cur_lines.jsonl"; file_lines=0
    fi
  done
  if [ "$file_lines" -gt 0 ]; then
    idx=$((idx+1)); jq -s '{txs:.}' "$sd/cur_lines.jsonl" > "$sd/batches/batch_${s}_$(printf "%05d" $idx).json"
  fi
done

# 3) Отправляем батчи ПО ШАРДАМ: внутри каждого — строго по порядку; шарды — параллельно
start_ts=$(date +%s%3N)
ls -1d "$work"/shard_* | xargs -I{} -P"$C" bash -lc '
  sd="{}"
  for f in $(ls -1 "$sd"/batches/batch_*.json | sort -V); do
    curl -s -X POST "'"$BACKEND"'/submit_tx_batch" -H "Content-Type: application/json" \
      --data-binary @"$f" | jq -c "{accepted,rejected,new_height}"
  done
'
end_ts=$(date +%s%3N)
dt=$((end_ts - start_ts))
echo "=== DONE in ${dt} ms → ~ $(( M*1000/(dt>0?dt:1) )) tx/s (client-side est) ==="

# 4) HEAD / METRICS
echo "--- HEAD ---";    curl -s "$BACKEND/head" | jq .
echo "--- METRICS ---"
curl -s "$BACKEND/metrics" \
 | grep -E "lrb_tx_|submit_tx_batch|http_request_duration_seconds_bucket|http_inflight_requests" \
 | head -n 120 || true

```

---

### `/root/logos_lrb/tools/tx_one.sh`

```bash
#!/usr/bin/env bash
# tx_one.sh — e2e: генерирует ключ, делает RID, faucet, строит канон, подписывает Ed25519 (raw),
# отправляет /submit_tx_batch и печатает head/balance/метрики.
# Usage: PORT=8080 ./tx_one.sh [AMOUNT]
set -euo pipefail
PORT="${PORT:-8080}"
AMOUNT="${1:-1234}"

work="$(mktemp -d -t lrb_one_XXXX)"
trap 'rm -rf "$work"' EXIT

need() { command -v "$1" >/dev/null || { echo "need $1"; exit 1; }; }
need curl; need jq; need openssl; need xxd; need python3

# Key + RID
openssl genpkey -algorithm Ed25519 -out "$work/ed25519.sk.pem" >/dev/null 2>&1
openssl pkey -in "$work/ed25519.sk.pem" -pubout -outform DER | tail -c 32 | xxd -p -c 32 > "$work/pk.hex"
python3 - "$work/pk.hex" > "$work/RID.txt" <<'PY'
import sys
ALPH="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
pk=bytes.fromhex(open(sys.argv[1]).read().strip())
n=int.from_bytes(pk,'big'); s=""
while n>0: n,r=divmod(n,58); s=ALPH[r]+s
z=0
for b in pk:
    if b==0: z+=1
    else: break
print("1"*z + (s or "1"))
PY
RID=$(cat "$work/RID.txt"); echo "RID=$RID"

# Faucet + state
curl -s -X POST "http://127.0.0.1:${PORT}/faucet" -H 'Content-Type: application/json' \
  -d "{\"rid\":\"${RID}\",\"amount\":1000000}" | jq .
STATE=$(curl -s "http://127.0.0.1:${PORT}/balance/${RID}")
NONCE_CUR=$(jq -r .nonce <<<"$STATE"); NONCE=$((NONCE_CUR+1))
echo "nonce: $NONCE_CUR -> $NONCE"

# Canon
jq -n --arg f "$RID" --arg t "$RID" --argjson a "$AMOUNT" --argjson n "$NONCE" \
  '{tx:{from:$f,to:$t,amount:$a,nonce:$n}}' > "$work/canon_payload.json"
CANON_HEX=$(curl -s -X POST "http://127.0.0.1:${PORT}/debug_canon" -H 'Content-Type: application/json' \
  --data-binary @"$work/canon_payload.json" | jq -r .canon_hex)
echo -n "$CANON_HEX" | xxd -r -p > "$work/canon.bin"

# Sign
openssl pkeyutl -sign -rawin -inkey "$work/ed25519.sk.pem" -in "$work/canon.bin" -out "$work/sig.bin" >/dev/null 2>&1
SIG_HEX=$(xxd -p -c 256 "$work/sig.bin")

# Batch
jq -n --arg f "$RID" --arg t "$RID" --argjson a "$AMOUNT" --argjson n "$NONCE" --arg s "$SIG_HEX" \
  '{txs:[{from:$f,to:$t,amount:$a,nonce:$n,sig_hex:$s}]}' > "$work/batch.json"
curl -s -X POST "http://127.0.0.1:${PORT}/submit_tx_batch" -H 'Content-Type: application/json' \
  --data-binary @"$work/batch.json" | jq .

# Head / post state / metrics
echo "--- HEAD ---";         curl -s "http://127.0.0.1:${PORT}/head" | jq .
echo "--- POST ---";         curl -s "http://127.0.0.1:${PORT}/balance/${RID}" | jq .
echo "--- METRICS ---";      curl -s "http://127.0.0.1:${PORT}/metrics" \
 | grep -E "lrb_tx_|submit_tx_batch|http_inflight_requests" | head -n 40 || true

```

---

### `/root/logos_lrb/tools/vegeta_submit_live.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

# === defaults ===
API="http://127.0.0.1:8080"
FROM="PAYER"
TO="RCV"
AMOUNT=1
RATE=500
DURATION="60s"
START_NONCE=1
COUNT=10000
REPORT_EVERY=30   # секунд

# === parse KEY=VALUE ===
for kv in "$@"; do
  case "$kv" in
    API=*) API=${kv#API=} ;;
    FROM=*) FROM=${kv#FROM=} ;;
    TO=*) TO=${kv#TO=} ;;
    AMOUNT=*) AMOUNT=${kv#AMOUNT=} ;;
    RATE=*) RATE=${kv#RATE=} ;;
    DURATION=*) DURATION=${kv#DURATION=} ;;
    START_NONCE=*) START_NONCE=${kv#START_NONCE=} ;;
    COUNT=*) COUNT=${kv#COUNT=} ;;
    REPORT_EVERY=*) REPORT_EVERY=${kv#REPORT_EVERY=} ;;
    *) echo "[WARN] unknown arg: $kv" ;;
  esac
done

command -v vegeta >/dev/null 2>&1 || { echo "[ERR] vegeta not found"; exit 1; }

echo "[*] attack: rate=${RATE} for ${DURATION} | from=${FROM} to=${TO} amount=${AMOUNT} nonces=${START_NONCE}..$((START_NONCE+COUNT-1))"

# === generate JSONL targets ===
TARGETS="targets.jsonl"
RESULTS="results.bin"
rm -f "$TARGETS" "$RESULTS"

gen_targets_json() {
  local n=${START_NONCE}
  local end=$((START_NONCE + COUNT - 1))
  while [[ $n -le $end ]]; do
    local body b64
    body=$(printf '{"from":"%s","to":"%s","amount":%d,"nonce":%d,"memo":"load","sig_hex":"00"}' \
      "$FROM" "$TO" "$AMOUNT" "$n")
    b64=$(printf '%s' "$body" | openssl base64 -A)
    printf '{"method":"POST","url":"%s/submit_tx","body":"%s","header":{"Content-Type":["application/json"]}}\n' \
      "$API" "$b64"
    n=$((n+1))
  done
}

gen_targets_json > "$TARGETS"

# === start attack in background ===
( vegeta attack -format=json -rate="${RATE}" -duration="${DURATION}" -targets="$TARGETS" > "$RESULTS" ) &
VEG_PID=$!

# cleanup & final report on Ctrl+C / TERM
finish() {
  echo
  echo "[*] stopping attack (pid=$VEG_PID) and printing final report..."
  kill "$VEG_PID" 2>/dev/null || true
  wait "$VEG_PID" 2>/dev/null || true

  echo "[*] FINAL SUMMARY:"
  vegeta report "$RESULTS"

  echo "[*] FINAL HISTOGRAM:"
  vegeta report -type='hist[0,500us,1ms,2ms,5ms,10ms,20ms,50ms,100ms]' "$RESULTS"

  echo "[*] JSON metrics -> results.json"
  vegeta report -type=json "$RESULTS" > results.json

  # archive sample (если включён /archive)
  if curl -sf "${API}/archive/history/${FROM}" >/dev/null 2>&1; then
    echo "[*] archive sample:"
    curl -sf "${API}/archive/history/${FROM}" | jq '.[0:5]' || true
  fi
  exit 0
}
trap finish INT TERM

# === live progress loop ===
START_TS=$(date +%s)
while kill -0 "$VEG_PID" 2>/dev/null; do
  sleep "$REPORT_EVERY"
  NOW=$(date +%s); ELAPSED=$((NOW-START_TS))
  echo
  echo "[*] PROGRESS t=${ELAPSED}s:"
  vegeta report "$RESULTS" || true
done

# wait and final when finished naturally
finish

```

---

### `/root/logos_lrb/tools/vegeta_submit.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- дефолты ---
API="http://127.0.0.1:8080"
FROM="PAYER"
TO="RCV"
AMOUNT=1
RATE=500
DURATION="60s"
START_NONCE=1
COUNT=10000

# --- парсинг KEY=VALUE из аргументов ---
for kv in "$@"; do
  case "$kv" in
    API=*) API=${kv#API=} ;;
    FROM=*) FROM=${kv#FROM=} ;;
    TO=*) TO=${kv#TO=} ;;
    AMOUNT=*) AMOUNT=${kv#AMOUNT=} ;;
    RATE=*) RATE=${kv#RATE=} ;;
    DURATION=*) DURATION=${kv#DURATION=} ;;
    START_NONCE=*) START_NONCE=${kv#START_NONCE=} ;;
    COUNT=*) COUNT=${kv#COUNT=} ;;
    *) echo "[WARN] unknown arg: $kv" ;;
  esac
done

command -v vegeta >/dev/null 2>&1 || { echo "[ERR] vegeta not found in PATH"; exit 1; }

echo "[*] attack: rate=${RATE} for ${DURATION} | from=${FROM} to=${TO} amount=${AMOUNT} nonces=${START_NONCE}..$((START_NONCE+COUNT-1))"

gen_targets_json() {
  local n=${START_NONCE}
  local end=$((START_NONCE + COUNT - 1))
  while [[ $n -le $end ]]; do
    local body b64
    body=$(printf '{"from":"%s","to":"%s","amount":%d,"nonce":%d,"memo":"load","sig_hex":"00"}' \
      "$FROM" "$TO" "$AMOUNT" "$n")
    b64=$(printf '%s' "$body" | openssl base64 -A)
    printf '{"method":"POST","url":"%s/submit_tx","body":"%s","header":{"Content-Type":["application/json"]}}\n' \
      "$API" "$b64"
    n=$((n+1))
  done
}

# атака: live-репорт каждые 30s + финальные отчёты
gen_targets_json \
  | vegeta attack -format=json -rate="${RATE}" -duration="${DURATION}" \
  | tee results.bin \
  | vegeta report -every 30s

echo "[*] latency histogram:"
vegeta report -type='hist[0,500us,1ms,2ms,5ms,10ms,20ms,50ms,100ms]' results.bin

echo "[*] JSON metrics -> results.json"
vegeta report -type=json results.bin > results.json

# срез архива (если включён /archive)
if curl -sf "${API}/archive/history/${FROM}" >/dev/null 2>&1; then
  echo "[*] archive sample:"
  curl -sf "${API}/archive/history/${FROM}" | jq '.[0:5]' || true
fi

```

## systemd: logos-node@.service

### `/etc/systemd/system/logos-node@.service`

```ini
[Unit]
Description=LOGOS LRB Node (%i)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
EnvironmentFile=/etc/logos/node-%i.env
ExecStart=/opt/logos/bin/logos_node
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
SystemCallFilter=@system-service @network-io ~keyctl
ReadWritePaths=/var/lib/logos /var/log/logos
RuntimeDirectory=logos
UMask=0077
[Install]
WantedBy=multi-user.target

```

## systemd overrides: logos-node@.service.d

`/etc/systemd/system/logos-node@.service.d`


---

### `/etc/systemd/system/logos-node@.service.d/10-restart-policy.conf`

```ini
[Service]
Restart=on-failure
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=5

```

---

### `/etc/systemd/system/logos-node@.service.d/20-env.conf`

```ini
[Service]
EnvironmentFile=-/etc/logos/node-%i.env

```

---

### `/etc/systemd/system/logos-node@.service.d/30-hardening.conf`

```ini
[Service]
# Sandbox
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

# Разрешаем запись ТОЛЬКО где нужно
ReadWritePaths=/var/lib/logos
ReadWritePaths=/var/log/logos

# Ресурсные лимиты
LimitNOFILE=262144
LimitNPROC=8192

# Capabilities обрезаем в ноль
CapabilityBoundingSet=
AmbientCapabilities=

```

---

### `/etc/systemd/system/logos-node@.service.d/31-bridge-key.conf`

```ini
[Service]
Environment=LRB_BRIDGE_KEY=supersecret

```

---

### `/etc/systemd/system/logos-node@.service.d/40-log.conf`

```ini
[Service]
Environment=RUST_LOG=trace,logos=trace,consensus=trace,axum=info,h2=info,tokio=info

```

---

### `/etc/systemd/system/logos-node@.service.d/41-faucet.conf`

```ini
[Service]
# Типичные ключи, которые встречаются в таких сборках:
Environment=LOGOS_FAUCET_ENABLED=true
Environment=LRB_FAUCET_ENABLED=true
# (на некоторых билдах есть явный биндинг — пусть будет)
Environment=LOGOS_FAUCET_PATH=/faucet

```

---

### `/etc/systemd/system/logos-node@.service.d/42-http-port.conf`

```ini
[Service]
Environment=LOGOS_HTTP_ADDR=127.0.0.1:8081
Environment=LRB_HTTP_ADDR=127.0.0.1:8081

```

---

### `/etc/systemd/system/logos-node@.service.d/env.conf`

```ini
[Service]
# Per-instance env (например /etc/logos/node-main.env)
EnvironmentFile=/etc/logos/node-%i.env
# Общие секреты (тот самый "keys", чтобы один раз положил — и все инстансы видят)
EnvironmentFile=/etc/logos/keys.env

```

---

### `/etc/systemd/system/logos-node@.service.d/override.conf`

```ini
[Service]
Environment=LOGOS_GENESIS_PATH=/etc/logos/genesis.yaml
Environment=LOGOS_PRODUCER_ENABLED=true
Environment=LOGOS_NODE_KEY_PATH=/var/lib/logos/node_key

```
