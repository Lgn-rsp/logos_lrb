# LOGOS LRB — FULL BOOK (prod snapshot)

Срез **рабочей прод-версии** LOGOS LRB:
- Axum 0.7 стек
- строгая проверка подписи Ed25519 в /submit_tx
- BLAKE3-хэш блока (prev|height|ts)
- Prometheus-метрики: HTTP, TX (accepted/rejected), blocks, chain (head/final)

Generated (UTC): 2025-09-18T07-58-28Z

## Workspace / Cargo

### Cargo.toml

~~~toml
[workspace]
members  = ["lrb_core", "node"]
resolver = "2"

[workspace.package]
edition      = "2021"
rust-version = "1.78"

[workspace.dependencies]
axum       = { version = "0.7.9", features = ["macros", "json"] }
tower      = "0.4.13"
tower-http = { version = "0.5.2", features = ["trace", "cors", "compression-gzip"] }
tokio      = { version = "1.40", features = ["full"] }
reqwest    = { version = "0.12", default-features = false, features = ["rustls-tls", "http2", "json"] }

serde               = { version = "1.0", features = ["derive"] }
serde_json          = "1.0"
anyhow              = "1.0"
thiserror           = "1.0"
once_cell           = "1.19"
dashmap             = "5.5"
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["env-filter", "fmt"] }
bytes               = "1.6"

hex              = "0.4"
base64           = "0.21"
bs58             = "0.4"
sha2             = "0.10"
blake3           = "1.5"
ed25519-dalek    = { version = "2.2", default-features = false, features = ["rand_core"] }
rand             = "0.8"
ring             = "0.17"
uuid             = { version = "1.8", features = ["v4"] }
bincode          = "1.3"
jsonwebtoken     = "9"

sled             = "0.34"
deadpool-postgres= "0.12"
tokio-postgres   = { version = "0.7", features = ["with-uuid-1"] }
rusqlite         = { version = "0.32", features = ["bundled"] }
r2d2_sqlite      = "0.25"

parking_lot = "0.12"
ipnet       = "2.9"
prometheus  = "0.13"

[profile.release]
opt-level       = 3
lto             = "fat"
codegen-units   = 1
panic           = "abort"
incremental     = false
strip           = "symbols"

~~~

## lrb_core (core)

### lrb_core/Cargo.toml

~~~toml
[package]
name = "lrb_core"
version = "0.1.0"
edition = "2021"
description = "LOGOS LRB core: ledger + engine + types"
license = "Apache-2.0"

[dependencies]
anyhow = "1"
thiserror = "1"

# крипта/хэш
ed25519-dalek = { version = "2.1.1", default-features = false, features = ["std"] }
blake3 = "1.5"
sha2 = "0.10"          # ← НУЖЕН ДЛЯ ledger.rs (txid = sha256)

# кодеки/утилиты
base64 = "0.22"
hex = "0.4"            # ← НУЖЕН ДЛЯ ledger.rs
bs58 = "0.4"
uuid  = { version = "1", features = ["v4"] }

# хранилище/сериализация
sled = "0.34"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
once_cell = "1"

# движок/асинхронщина/логгинг
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time"] }
tracing = "0.1"
parking_lot = "0.12"

~~~

### lrb_core/src/anti_replay.rs

~~~rust
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

~~~

### lrb_core/src/beacon.rs

~~~rust
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

~~~

### lrb_core/src/crypto.rs

~~~rust
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

~~~

### lrb_core/src/dynamic_balance.rs

~~~rust
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

~~~

### lrb_core/src/engine.rs

~~~rust
//! lrb_core/src/engine.rs
//! Mempool per-RID + упорядоченный коммит (nonce == prev+1), события для метрик/узла.
//! Совместимо с types: Rid(String), Nonce(u64), Amount(u64); Transaction{from,to,amount,nonce,sig,ts_ms}.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use tokio::{
    sync::{broadcast, mpsc},
    time::{interval, Duration},
};

use tracing::warn;

use crate::ledger::Ledger;
use crate::types::{Transaction, Rid}; // Amount/Nonce берём из Transaction полей

/// События движка (для метрик узла)
#[derive(Clone, Debug)]
pub enum EngineEvent {
    Committed {
        head_height: u64,
        finalized_height: u64,
        mempool_len: usize,
    },
}

/// Хэндл для подписки на события
#[derive(Clone)]
pub struct EngineHandle {
    ev_tx: broadcast::Sender<EngineEvent>,
}

impl EngineHandle {
    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.ev_tx.subscribe()
    }
}

/// Очередь по одному RID — хранит будущие nonce (> prev), отсортированные.
struct PerRidQueue {
    by_nonce: BTreeMap<u64, Transaction>,
}
impl PerRidQueue {
    fn new() -> Self { Self { by_nonce: BTreeMap::new() } }
    fn insert(&mut self, tx: Transaction) { self.by_nonce.insert(tx.nonce.0, tx); }
    fn len(&self) -> usize { self.by_nonce.len() }

    /// Вернёт следующий по порядку tx при exact nonce==next; иначе None
    fn take_next_sequential(&mut self, next: u64) -> Option<Transaction> {
        if let Some((&n, _)) = self.by_nonce.iter().next() {
            if n == next {
                return self.by_nonce.remove(&n);
            }
        }
        None
    }
}

/// Обёртка движка (sender — это входной канал мемпула)
pub struct Engine;

impl Engine {
    /// Поднимаем мемпул и упорядоченный коммит.
    /// Возвращает (handle, sender в мемпул).
    pub fn spawn(ledger: Arc<Ledger>) -> anyhow::Result<(EngineHandle, mpsc::Sender<Transaction>)> {
        let (tx_sender, mut tx_receiver) = mpsc::channel::<Transaction>(64_000);
        let (ev_tx, _ev_rx) = broadcast::channel::<EngineEvent>(256);

        // фоновая задача движка
        tokio::spawn({
            let ev_tx = ev_tx.clone();
            async move {
                let mut q: HashMap<Rid, PerRidQueue> = HashMap::new();
                let mut slot = interval(Duration::from_millis(200));

                loop {
                    tokio::select! {
                        // Приём входящих транзакций из API
                        maybe_tx = tx_receiver.recv() => {
                            if let Some(tx) = maybe_tx {
                                // мягкая защита: отбрасывать низкие nonce (<= prev)
                                let prev = ledger.get_nonce(&tx.from.0).unwrap_or(0);
                                if tx.nonce.0 <= prev {
                                    warn!("drop low nonce: rid={:?} prev={} got={}", tx.from, prev, tx.nonce.0);
                                    continue;
                                }
                                q.entry(tx.from.clone())
                                    .or_insert_with(PerRidQueue::new)
                                    .insert(tx);
                            } else {
                                break; // канал закрыт
                            }
                        }

                        // Слот: упорядоченный дренаж очередей
                        _ = slot.tick() => {
                            let mut committed_any = false;

                            // Соберём RID отдельно, чтобы не держать заимствование на q
                            let rids: Vec<Rid> = q.keys().cloned().collect();

                            for rid in rids {
                                let prev = ledger.get_nonce(&rid.0).unwrap_or(0);
                                if let Some(queue) = q.get_mut(&rid) {
                                    let mut local_commits = 0u32;
                                    let mut next = prev.saturating_add(1);

                                    // коммитим строго последовательно, начиная с prev+1
                                    while let Some(tx) = queue.take_next_sequential(next) {
                                        // вызываем упрощённый серверный коммит (как в «книжном» API)
                                        if let Err(e) = ledger.submit_tx_simple(
                                            &tx.from.0, &tx.to.0, tx.amount.0, tx.nonce.0, None
                                        ) {
                                            warn!("commit failed (rid={:?}): {}", rid, e);
                                            break;
                                        }
                                        committed_any = true;
                                        local_commits += 1;
                                        next = next.saturating_add(1);

                                        // не даём одному RID монополизировать слот
                                        if local_commits >= 100 { break; }
                                    }

                                    if queue.len() == 0 {
                                        q.remove(&rid);
                                    }
                                }
                            }

                            let mempool_len: usize = q.values().map(|prq| prq.len()).sum();
                            let head = ledger.head_height().unwrap_or(0);
                            // quorum=1 → финализируем «визуально» на 1 назад
                            let finalized = head.saturating_sub(1);
                            let _ = ev_tx.send(EngineEvent::Committed {
                                head_height: head,
                                finalized_height: finalized,
                                mempool_len,
                            });

                            if !committed_any && mempool_len == 0 {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok((EngineHandle { ev_tx }, tx_sender))
    }
}

~~~

### lrb_core/src/heartbeat.rs

~~~rust
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

~~~

### lrb_core/src/ledger.rs

~~~rust
// lrb_core/src/ledger.rs — sled-хранилище, head/supply, account history, tx-simple, index_block.

use std::{convert::TryInto, path::Path, time::{SystemTime, UNIX_EPOCH}};
use sled::{Db, Tree};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use anyhow::Result;

#[allow(unused_imports)]
use crate::types::*;

// helpers
#[inline] fn be64(v: u64) -> [u8; 8] { v.to_be_bytes() }
#[inline] fn be32(v: u32) -> [u8; 4] { v.to_be_bytes() }
#[inline] fn k_bal(r:&str)->Vec<u8>{ format!("bal:{r}").into_bytes() }
#[inline] fn k_nonce(r:&str)->Vec<u8>{ format!("nonce:{r}").into_bytes() }

const K_HEAD:      &[u8] = b"h";    // u64
const K_HEAD_HASH: &[u8] = b"hh";   // utf8
const K_FINAL:     &[u8] = b"fin";  // u64
const K_MINTED:    &[u8] = b"mint"; // u64
const K_BURNED:    &[u8] = b"burn"; // u64

#[derive(Clone)]
pub struct Ledger {
    db: Db,
    // trees
    #[allow(dead_code)]
    lgn:   Tree,   // balances
    head:  Tree,   // head/final/supply
    blocks:Tree,   // b|h -> StoredBlock
    txs:   Tree,   // t|id -> StoredTx
    acct:  Tree,   // a|rid|h|idx -> txid
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredBlock { pub height:u64, pub hash:String, pub ts:u128, pub tx_ids:Vec<String> }

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredTx {
    pub txid:String, pub from:String, pub to:String,
    pub amount:u64, pub nonce:u64, pub height:u64, pub index:u32, pub ts:u128,
}

// ====== открытие / базовые геттеры ======
impl Ledger {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self{
            lgn:    db.open_tree("lgn")?,
            head:   db.open_tree("head")?,
            blocks: db.open_tree("blocks")?,
            txs:    db.open_tree("txs")?,
            acct:   db.open_tree("acct_txs")?,
            db,
        })
    }
    #[inline] pub fn db(&self) -> &sled::Db { &self.db }
}

// ====== время (для tx/block) ======
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64
}

// ====== HEAD / FINAL / HASH ======
impl Ledger {
    pub fn height(&self) -> Result<u64> {
        Ok(self.head.get(K_HEAD)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0))
    }
    pub fn head_height(&self) -> Result<u64> { self.height() }

    pub fn set_head(&self, h:u64, hash:&str) -> Result<()> {
        self.head.insert(K_HEAD, &be64(h))?;
        self.head.insert(K_HEAD_HASH, hash.as_bytes())?;
        Ok(())
    }
    pub fn set_finalized(&self, h:u64) -> Result<()> {
        self.head.insert(K_FINAL, &be64(h))?;
        Ok(())
    }

    pub fn get_block_by_height(&self, h:u64) -> Result<BlockHeaderView> {
        let mut k=Vec::with_capacity(9); k.extend_from_slice(b"b"); k.extend_from_slice(&be64(h));
        if let Some(v) = self.blocks.get(k)? {
            let b: StoredBlock = serde_json::from_slice(&v)?;
            Ok(BlockHeaderView{ block_hash: b.hash })
        } else {
            let hh = self.head.get(K_HEAD_HASH)?
                .map(|v| String::from_utf8(v.to_vec()).unwrap())
                .unwrap_or_default();
            Ok(BlockHeaderView{ block_hash: hh })
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockHeaderView { pub block_hash:String }

// ====== supply ======
impl Ledger {
    pub fn supply(&self) -> Result<(u64,u64)> {
        let minted = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let burned = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        Ok((minted, burned))
    }
    pub fn add_minted(&self, amount:u64) -> Result<u64> {
        let cur = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let newv = cur.saturating_add(amount);
        self.head.insert(K_MINTED, &be64(newv))?; Ok(newv)
    }
    pub fn add_burned(&self, amount:u64) -> Result<u64> {
        let cur = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let newv = cur.saturating_add(amount);
        self.head.insert(K_BURNED, &be64(newv))?; Ok(newv)
    }
}

// ====== балансы / nonce ======
impl Ledger {
    pub fn get_balance(&self, rid:&str) -> Result<u64> {
        Ok(self.db.get(k_bal(rid))?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
            .unwrap_or(0))
    }
    pub fn set_balance(&self, rid:&str, amount_u128:u128) -> Result<()> {
        let amount: u64 = amount_u128.try_into().map_err(|_| anyhow::anyhow!("amount too large"))?;
        self.db.insert(k_bal(rid), &be64(amount))?;
        Ok(())
    }
    pub fn get_nonce(&self, rid:&str) -> Result<u64> {
        Ok(self.db.get(k_nonce(rid))?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
            .unwrap_or(0))
    }
    pub fn set_nonce(&self, rid:&str, value:u64) -> Result<()> {
        self.db.insert(k_nonce(rid), &be64(value))?; Ok(())
    }
    pub fn bump_nonce(&self, rid:&str) -> Result<u64> {
        let cur = self.get_nonce(rid)?; let next = cur.saturating_add(1);
        self.set_nonce(rid, next)?; Ok(next)
    }
}

// ====== простая транзакция для REST (/submit_tx) ======
impl Ledger {
    /// Сохраняем tx-заготовку (height=0,index=0), возвращаем StoredTx с txid/ts
    pub fn submit_tx_simple(&self, from:&str, to:&str, amount:u64, nonce:u64, _memo:Option<String>) -> Result<StoredTx> {
        // txid = sha256(from|to|amount|nonce)
        let mut h=Sha256::new();
        h.update(from.as_bytes()); h.update(b"|");
        h.update(to.as_bytes());   h.update(b"|");
        h.update(&amount.to_be_bytes()); h.update(b"|");
        h.update(&nonce.to_be_bytes());
        let txid = hex::encode(h.finalize());

        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        let stx = StoredTx{ txid:txid.clone(), from:from.into(), to:to.into(), amount, nonce, height:0, index:0, ts };

        // t|id -> StoredTx
        let mut k_tx=Vec::with_capacity(1+txid.len()); k_tx.extend_from_slice(b"t"); k_tx.extend_from_slice(txid.as_bytes());
        self.txs.insert(k_tx, serde_json::to_vec(&stx)?)?;

        // a|from|0|0 -> txid; a|to|0|0 -> txid
        let mut k_af=Vec::new(); k_af.extend_from_slice(b"a"); k_af.extend_from_slice(from.as_bytes()); k_af.push(b'|'); k_af.extend_from_slice(&be64(0)); k_af.extend_from_slice(&be32(0));
        self.acct.insert(k_af, txid.as_bytes())?;
        let mut k_at=Vec::new(); k_at.extend_from_slice(b"a"); k_at.extend_from_slice(to.as_bytes());   k_at.push(b'|'); k_at.extend_from_slice(&be64(0)); k_at.extend_from_slice(&be32(0));
        self.acct.insert(k_at, txid.as_bytes())?;

        Ok(stx)
    }

    /// История аккаунта — постранично (упрощённо: первая страница)
    pub fn account_txs_page(&self, rid:&str, _cursor_usize:usize, limit:usize) -> Result<Vec<StoredTx>> {
        let lim = limit.min(100).max(1);
        let prefix = { let mut k=Vec::new(); k.extend_from_slice(b"a"); k.extend_from_slice(rid.as_bytes()); k.push(b'|'); k };
        let mut out=Vec::new();
        for kv in self.acct.scan_prefix(prefix).take(lim) {
            let (_k, v) = kv?;
            let txid = String::from_utf8(v.to_vec()).unwrap_or_default();
            if let Some(stx) = self.get_tx(&txid)? { out.push(stx); }
        }
        Ok(out)
    }
    pub fn get_tx(&self, txid:&str)-> Result<Option<StoredTx>> {
        let mut k=Vec::with_capacity(1+txid.len()); k.extend_from_slice(b"t"); k.extend_from_slice(txid.as_bytes());
        Ok(self.txs.get(k)?.map(|v| serde_json::from_slice::<StoredTx>(&v)).transpose()?)
    }
}

// ====== индексирование блока (для продюсера/engine) ======
#[derive(Serialize, Deserialize)]
pub struct TransactionView { pub from:String, pub to:String, pub amount:u64, pub nonce:u64 }

impl Ledger {
    /// Индексация блока: запишем заголовок и перелинкуем его tx в обеих индексах
    pub fn index_block(&self, height: u64, hash: &str, ts: u128, txs: &[TransactionView]) -> Result<()> {
        let mut ids = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            let mut h=Sha256::new();
            h.update(tx.from.as_bytes()); h.update(b"|");
            h.update(tx.to.as_bytes());   h.update(b"|");
            h.update(&tx.amount.to_be_bytes()); h.update(b"|");
            h.update(&tx.nonce.to_be_bytes());
            let txid = hex::encode(h.finalize());
            ids.push(txid.clone());

            let stx = StoredTx{
                txid: txid.clone(), from: tx.from.clone(), to: tx.to.clone(),
                amount: tx.amount, nonce: tx.nonce, height, index: i as u32, ts,
            };

            let mut k_tx=Vec::with_capacity(1+txid.len()); k_tx.extend_from_slice(b"t"); k_tx.extend_from_slice(txid.as_bytes());
            self.txs.insert(k_tx, serde_json::to_vec(&stx)?)?;

            let mut k_af=Vec::new(); k_af.extend_from_slice(b"a"); k_af.extend_from_slice(tx.from.as_bytes()); k_af.push(b'|'); k_af.extend_from_slice(&be64(height)); k_af.extend_from_slice(&be32(i as u32));
            self.acct.insert(k_af, txid.as_bytes())?;
            let mut k_at=Vec::new(); k_at.extend_from_slice(b"a"); k_at.extend_from_slice(tx.to.as_bytes());   k_at.push(b'|'); k_at.extend_from_slice(&be64(height)); k_at.extend_from_slice(&be32(i as u32));
            self.acct.insert(k_at, txid.as_bytes())?;
        }

        let mut k_b=Vec::with_capacity(1+8); k_b.extend_from_slice(b"b"); k_b.extend_from_slice(&be64(height));
        let sblk = StoredBlock{ height, hash: hash.to_string(), ts, tx_ids: ids };
        self.blocks.insert(k_b, serde_json::to_vec(&sblk)?)?;
        Ok(())
    }
}

~~~

### lrb_core/src/lib.rs

~~~rust
// lrb_core/src/lib.rs — единая точка экспорта ядра

pub mod types;
pub mod ledger;
pub mod engine;
pub mod phase_filters;

// точечные реэкспорты (без лишних *), чтобы не плодить ambiguous glob re-exports
pub use types::{Rid, Nonce, Amount, Transaction, Block};
pub use ledger::{Ledger, StoredTx, StoredBlock, BlockHeaderView, now_ms};
pub use engine::{Engine, EngineHandle, EngineEvent};
pub use phase_filters::block_passes_phase;

~~~

### lrb_core/src/phase_consensus.rs

~~~rust
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

~~~

### lrb_core/src/phase_integrity.rs

~~~rust
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use hex::FromHex;
use bs58;

use crate::types::Transaction;

/// b"LOGOS|" + pk_from + "|" + pk_to + "|" + amount_be + "|" + nonce_be
fn canonical_message(from_vk: &VerifyingKey, to_vk: &VerifyingKey, amount: u64, nonce: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 32 + 32 + 8 + 8);
    v.extend_from_slice(b"LOGOS|");
    v.extend_from_slice(&from_vk.to_bytes());
    v.push(b'|');
    v.extend_from_slice(&to_vk.to_bytes());
    v.push(b'|');
    v.extend_from_slice(&amount.to_be_bytes());
    v.push(b'|');
    v.extend_from_slice(&nonce.to_be_bytes());
    v
}

pub fn verify_tx_signature(tx: &Transaction) -> Result<()> {
    let from_pk: [u8; 32] = bs58::decode(&tx.from.0).into_vec().map_err(|_| anyhow!("rid decode failed"))?
        .as_slice().try_into().map_err(|_| anyhow!("bad from pk length"))?;
    let to_pk: [u8; 32]   = bs58::decode(&tx.to.0).into_vec().map_err(|_| anyhow!("rid decode failed"))?
        .as_slice().try_into().map_err(|_| anyhow!("bad to pk length"))?;

    let from_vk = VerifyingKey::from_bytes(&from_pk).map_err(|_| anyhow!("bad from pubkey"))?;
    let to_vk   = VerifyingKey::from_bytes(&to_pk).map_err(|_| anyhow!("bad to pubkey"))?;

    let sig_bytes: Vec<u8> = Vec::from_hex(&tx.sig).map_err(|_| anyhow!("sig hex decode"))?;
    let sig = Signature::from_slice(sig_bytes.as_slice().try_into().map_err(|_| anyhow!("bad sig length"))?)
        .map_err(|_| anyhow!("sig parse"))?;

    let msg = canonical_message(&from_vk, &to_vk, tx.amount.0, tx.nonce.0);
    from_vk.verify(&msg, &sig).map_err(|_| anyhow!("signature verify failed"))?;
    Ok(())
}

~~~

### lrb_core/src/quorum.rs

~~~rust
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Голос за блок (по Σ-дайджесту)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub sigma_hex: String,     // Σ-дайджест (hex)
    pub block_hash: String,    // хеш блока (hex/строка)
    pub height: u64,           // высота
    pub voter_pk_b58: String,  // base58(pubkey)
    pub sig_b64: String,       // base64(signature)
    pub nonce_ms: u128,        // анти-реплей, миллисекунды
}

/// Проверка подписи голоса.
/// Каноника сообщения: concat( sigma_hex | block_hash | height(le) | nonce_ms(le) )
pub fn verify_vote(v: &Vote) -> Result<()> {
    // 1) pubkey = base58 → [u8;32] → VerifyingKey
    let pk_bytes = bs58::decode(&v.voter_pk_b58)
        .into_vec()
        .map_err(|_| anyhow!("bad voter pk b58"))?;
    let arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| anyhow!("bad pubkey len"))?;
    let vk = VerifyingKey::from_bytes(&arr)
        .map_err(|_| anyhow!("bad ed25519 pubkey"))?;

    // 2) sig = base64 → [u8;64] → Signature
    let sig_bytes = B64
        .decode(v.sig_b64.as_bytes())
        .map_err(|_| anyhow!("bad sig b64"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("bad sig len"))?;
    let sig = Signature::from_bytes(&sig_arr);

    // 3) payload (строковая каноника + числа в LE)
    let mut payload = Vec::new();
    payload.extend_from_slice(v.sigma_hex.as_bytes());
    payload.extend_from_slice(v.block_hash.as_bytes());
    payload.extend_from_slice(&v.height.to_le_bytes());
    payload.extend_from_slice(&v.nonce_ms.to_le_bytes());

    // 4) verify
    vk.verify(&payload, &sig)
        .map_err(|e| anyhow!("verify failed: {e}"))?;
    Ok(())
}

~~~

### lrb_core/src/rcp_engine.rs

~~~rust
use std::sync::Arc;
use anyhow::Result;
use tokio::time::{sleep, Duration};
use tracing::info;

use crate::ledger::{Block, Ledger, Tx};

pub struct RcpEngine {
    pub ledger: Arc<Ledger>,
    // тут могут быть поля сети/коммуникаций — опущено в этом минимале
}

impl RcpEngine {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }

    pub async fn run(mut self) -> Result<()> {
        // простейший цикл: финализация quorum=1 + тик
        loop {
            self.tick_once().await?;
            sleep(Duration::from_millis(500)).await;
        }
    }

    async fn tick_once(&mut self) -> Result<()> {
        // пример: читаем текущую высоту, проверяем, что блок доступен
        let h = self.ledger.head_height();
        if let Ok(Some(b)) = self.ledger.get_block_by_height(h) {
            // в нашем минимале id блока — «хеш»
            let voted_hash = b.id.clone();
            // финализируем (quorum=1)
            let fin = self.ledger.finalized_height();
            if h > fin {
                self.ledger.set_finalized(h)?;
                info!("finalized #{} id={}", h, voted_hash);
            }
        }
        Ok(())
    }

    /// Коммитим готовый блок (например, собранный из mempool в другом месте)
    pub fn commit_block(&self, txs: Vec<Tx>) -> Result<bool> {
        let b = Block::new_from_txs(&txs);
        self.ledger.commit_block(b)
    }
}

~~~

### lrb_core/src/resonance.rs

~~~rust
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

~~~

### lrb_core/src/sigpool.rs

~~~rust
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

~~~

### lrb_core/src/spam_guard.rs

~~~rust
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

~~~

### lrb_core/src/types.rs

~~~rust
// lrb_core/src/types.rs — минимальный набор типов, совместимый с node/gossip/fork.

use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rid(pub String);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce(pub u64);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(pub u64);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub from: Rid,
    pub to: Rid,
    pub amount: Amount,
    pub nonce: Nonce,
    pub sig: String,
    pub ts_ms: u64,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            from: Rid(String::new()),
            to: Rid(String::new()),
            amount: Amount(0),
            nonce: Nonce(0),
            sig: String::new(),
            ts_ms: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Block {
    pub height: u64,
    pub block_hash: String,
    #[serde(default)]
    pub txs: Vec<Transaction>,
}

~~~

## node (REST + metrics + producer + archive)

### node/Cargo.toml

~~~toml
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
axum.workspace       = true
tower.workspace      = true
tower-http.workspace = true
tokio.workspace      = true

serde.workspace              = true
serde_json.workspace         = true
anyhow.workspace             = true
thiserror.workspace          = true
once_cell.workspace          = true
dashmap.workspace            = true
tracing.workspace            = true
tracing-subscriber.workspace = true
jsonwebtoken.workspace       = true
sha2.workspace               = true          # для canonical_msg в API

# хранилища/индексация
sled.workspace               = true
deadpool-postgres.workspace  = true
tokio-postgres.workspace     = true
rusqlite.workspace           = true
r2d2_sqlite.workspace        = true

# утилиты/крипта/метрики
hex.workspace                = true
base64.workspace             = true
bs58.workspace               = true
ed25519-dalek.workspace      = true
blake3.workspace             = true
parking_lot.workspace        = true
ipnet.workspace              = true
prometheus.workspace         = true
uuid.workspace               = true          # для producer (если останется UUID где-то)

# для bin-утилит
reqwest = { workspace = true, features = ["blocking", "json"] }
rand_core = "0.6"

# ядро
lrb_core = { path = "../lrb_core" }

[build-dependencies]
chrono = { version = "0.4", default-features = false, features = ["clock"] }

~~~

### node/build.rs

~~~rust
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    // короткий git-хеш (если git доступен)
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else { None })
        .unwrap_or_else(|| "unknown".into());

    // текущая ветка
    let git_branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else { None })
        .unwrap_or_else(|| "unknown".into());

    // версия пакета и время сборки
    let pkg_ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let ts = chrono::Utc::now().to_rfc3339();

    // записываем build_info.rs в OUT_DIR
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let dest = out_dir.join("build_info.rs");
    let contents = format!(
        "pub const BUILD_GIT_HASH: &str = \"{git_hash}\";\n\
         pub const BUILD_GIT_BRANCH: &str = \"{git_branch}\";\n\
         pub const BUILD_TIMESTAMP_RFC3339: &str = \"{ts}\";\n\
         pub const BUILD_PKG_VERSION: &str = \"{pkg_ver}\";\n"
    );
    fs::write(&dest, contents).expect("write build_info.rs failed");

    // триггеры пересборки
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=.git/HEAD");
}

~~~

### node/src/lib.rs

~~~rust
//! Единая точка экспорта узла без двусмысленных glob-реэкспортов.

pub mod api;
pub mod admin;
pub mod archive;
pub mod auth;
pub mod bridge;
pub mod guard;
pub mod metrics;
pub mod openapi;
pub mod stake;
pub mod storage;
pub mod version;
pub mod wallet;
pub mod state;
pub mod producer;
// pub mod gossip; // оставь включённым, если нужен; мы уже починили core-экспорты

// Точечные реэкспорты — без конфликтов имён:
pub use metrics::prometheus as metrics_prometheus;
pub use version::get as version_get;

// Если нужно — добавляй точечно:
// pub use api::{healthz, head, submit_tx, balance, economy, history, archive_blocks, archive_txs, archive_history, archive_tx};

~~~

### node/src/main.rs

~~~rust
//! LOGOS node main (Axum 0.7 + producer + archive + metrics)

use axum::{routing::{get, post}, Router};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::sync::Arc;
use tracing::{info, warn};

mod api;
mod bridge;
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
mod wallet;
mod producer;

fn router(app_state: Arc<state::AppState>) -> Router {
    Router::new()
        .route("/healthz", get(api::healthz))
        .route("/head",    get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx", post(api::submit_tx))
        .route("/economy", get(api::economy))
        .route("/history/:rid", get(api::history))
        .route("/archive/blocks", get(api::archive_blocks))
        .route("/archive/txs",    get(api::archive_txs))
        .route("/archive/history/:rid", get(api::archive_history))
        .route("/archive/tx/:txid",     get(api::archive_tx))
        .route("/version", get(version::get))
        .route("/metrics", get(metrics::prometheus))
        .route("/openapi.json", get(openapi::serve))
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem",  post(bridge::redeem))
        .route("/bridge/verify",  post(bridge::verify))
        .route("/admin/set_balance", post(admin::set_balance))
        .route("/admin/bump_nonce",  post(admin::bump_nonce))
        .route("/admin/set_nonce",   post(admin::set_nonce))
        .route("/admin/mint",        post(admin::mint))
        .route("/admin/burn",        post(admin::burn))
        .merge(wallet::routes())
        .merge(stake::routes())
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
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,hyper=warn")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    auth::assert_secrets_on_start().expect("secrets missing");

    let app_state = Arc::new(state::AppState::new()?);

    if let Some(ar) = crate::archive::Archive::new_from_env().await {
        unsafe {
            let p = Arc::as_ptr(&app_state) as *mut state::AppState;
            (*p).archive = Some(ar);
        }
        info!("archive backend initialized");
    } else { warn!("archive disabled"); }

    info!("producer start");
    let _producer = producer::run(app_state.clone());

    let addr = state::bind_addr();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("logos_node listening on {addr}");
    axum::serve(listener, router(app_state)).await?;
    Ok(())
}

~~~

### node/src/api.rs

~~~rust
use axum::{extract::{Path, State, Query}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tracing::{info, warn, error};

use crate::{state::AppState, metrics};
use ed25519_dalek::{Verifier, Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use sha2::{Sha256, Digest};

#[derive(Serialize)] pub struct OkMsg { pub status: &'static str }
#[derive(Serialize)] pub struct Head { pub height: u64 }
#[derive(Serialize)] pub struct Balance { pub rid: String, pub balance: u128, pub nonce: u64 }

#[derive(Deserialize)]
pub struct TxIn {
    pub from:String, pub to:String, pub amount:u64, pub nonce:u64,
    pub sig_hex:String,
    #[serde(default)] pub memo:Option<String>
}

#[derive(Serialize)] pub struct SubmitResult { pub ok:bool, #[serde(skip_serializing_if="Option::is_none")] pub txid:Option<String>, pub info:String }
#[derive(Serialize)] pub struct Economy { pub supply:u64, pub burned:u64, pub cap:u64 }

#[derive(Serialize)]
pub struct HistoryItem {
    pub txid:String, pub height:u64, pub from:String, pub to:String, pub amount:u64, pub nonce:u64,
    #[serde(skip_serializing_if="Option::is_none")] pub ts:Option<u64>,
}

pub async fn healthz() -> Json<OkMsg> { Json(OkMsg{ status:"ok" }) }

pub async fn head(State(app): State<Arc<AppState>>) -> Json<Head> {
    let h = app.ledger.lock().height().unwrap_or(0);
    Json(Head{ height:h })
}

pub async fn balance(Path(rid):Path<String>, State(app): State<Arc<AppState>>) -> Json<Balance> {
    let l = app.ledger.lock();
    let bal = l.get_balance(&rid).unwrap_or(0);
    let n   = l.get_nonce(&rid).unwrap_or(0);
    Json(Balance{ rid, balance: bal as u128, nonce: n })
}

fn canonical_msg(from:&str, to:&str, amount:u64, nonce:u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(from.as_bytes()); h.update(b"|");
    h.update(to.as_bytes());   h.update(b"|");
    h.update(&amount.to_be_bytes()); h.update(b"|");
    h.update(&nonce.to_be_bytes());
    h.finalize().to_vec()
}

fn verify_sig(from:&str, msg:&[u8], sig_hex:&str) -> Result<(), String> {
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

pub async fn submit_tx(State(app): State<Arc<AppState>>, Json(tx):Json<TxIn>) -> (StatusCode, Json<SubmitResult>) {
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
    let stx = match app.ledger.lock().submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.clone()) {
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

/* ---------- Archive API ---------- */

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

// Дополнительный (сейчас не используется в main.rs), оставим и заглушим warning:
#[allow(dead_code)]
pub async fn archive_block(Path(h):Path<i64>, State(app): State<Arc<AppState>>)
 -> (StatusCode, Json<serde_json::Value>)
{
    if let Some(arch)=&app.archive {
        match arch.block_by_height(h).await {
            Ok(Some(b)) => return (StatusCode::OK, Json(serde_json::json!(b))),
            Ok(None)    => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not found"}))),
            Err(e)      => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":e.to_string()}))),
        }
    }
    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"archive disabled"})))
}

~~~

### node/src/metrics.rs

~~~rust
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

// ---- HTTP base ----
static HTTP_REQS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "logos_http_requests_total",
        "HTTP requests total",
        &["method","path","status"]
    ).unwrap()
});
static HTTP_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "logos_http_request_duration_seconds",
        "HTTP request latency (s)",
        &["method","path","status"],
        prometheus::exponential_buckets(0.001, 2.0, 14).unwrap()
    ).unwrap()
});

// ---- Domain metrics ----
static TX_ACCEPTED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("logos_tx_accepted_total", "Accepted transactions").unwrap()
});
static TX_REJECTED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "logos_tx_rejected_total",
        "Rejected transactions by reason",
        &["reason"]
    ).unwrap()
});
static BLOCKS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("logos_blocks_produced_total", "Produced blocks total").unwrap()
});
static HEAD_HEIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("logos_head_height", "Current head height").unwrap()
});
static FINALIZED_HEIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("logos_finalized_height", "Finalized height").unwrap()
});

fn normalize_path(p: &str) -> String {
    if p.starts_with("/balance/") { "/balance/:rid".into() }
    else if p.starts_with("/history/") { "/history/:rid".into() }
    else { p.to_string() }
}

// Axum 0.7: Next без дженериков, Request<Body>
pub async fn track(req: Request<Body>, next: Next) -> axum::response::Response {
    let method = req.method().as_str().to_owned();
    let path = normalize_path(req.uri().path());
    let start = Instant::now();

    let res = next.run(req).await;
    let status = res.status().as_u16().to_string();

    HTTP_REQS.with_label_values(&[&method, &path, &status]).inc();
    HTTP_LATENCY
        .with_label_values(&[&method, &path, &status])
        .observe(start.elapsed().as_secs_f64());
    res
}

pub async fn prometheus() -> impl IntoResponse {
    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    if let Err(_) = encoder.encode(&metric_families, &mut buf) {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode error").into_response();
    }
    match String::from_utf8(buf) {
        Ok(text) => (StatusCode::OK, text).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "utf8 error").into_response(),
    }
}

// ---- API for other modules ----
pub fn inc_tx_accepted() { TX_ACCEPTED.inc(); }
pub fn inc_tx_rejected(reason: &'static str) {
    TX_REJECTED.with_label_values(&[reason]).inc();
}
pub fn inc_block_produced() { BLOCKS_TOTAL.inc(); }
pub fn set_chain(head: u64, finalized: u64) {
    HEAD_HEIGHT.set(head as i64);
    FINALIZED_HEIGHT.set(finalized as i64);
}

// ---- Backward-compat NO-OP (для старых вызовов в admin/bridge) ----
#[allow(dead_code)]
pub fn inc_total(_label: &str) { /* no-op, сохранили совместимость */ }

~~~

### node/src/producer.rs

~~~rust
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};
use blake3::Hasher;
use lrb_core::ledger::now_ms;
use crate::state::AppState;
use crate::metrics;

pub fn run(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let slot_ms: u64 = std::env::var("LRB_SLOT_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(2000);
        loop {
            {
                let l = state.ledger.lock();
                let h_now = l.head_height().unwrap_or(0);
                let next_h = h_now.saturating_add(1);

                let prev = l.get_block_by_height(h_now).ok().map(|v| v.block_hash).unwrap_or_default();
                let ts = now_ms() as u128;

                let mut hasher = Hasher::new();
                hasher.update(prev.as_bytes());
                hasher.update(&next_h.to_be_bytes());
                hasher.update(&ts.to_be_bytes());
                let hash = hasher.finalize().to_hex().to_string();

                if let Err(e) = l.set_head(next_h, &hash) {
                    warn!("producer: set_head failed: {e}");
                } else {
                    let finalized = next_h.saturating_sub(1);
                    if next_h > 1 {
                        if let Err(e) = l.set_finalized(finalized) {
                            warn!("producer: set_finalized failed: {e}");
                        }
                    }
                    metrics::inc_block_produced();
                    metrics::set_chain(next_h, finalized);
                    info!("produced block {next_h} ({hash})");
                }
            }
            sleep(Duration::from_millis(slot_ms)).await;
        }
    })
}

~~~

### node/src/state.rs

~~~rust
use std::{env, net::SocketAddr, str::FromStr};
use std::sync::Arc;
use parking_lot::Mutex;

use lrb_core::ledger::Ledger;

pub struct AppState {
    pub ledger: Arc<Mutex<Ledger>>,
    pub db: sled::Db,
    pub archive: Option<crate::archive::Archive>,
}

impl AppState {
    pub fn new() -> anyhow::Result<Self> {
        // путь из ENV, иначе дефолт
        let data_path = env::var("LRB_DATA_PATH")
            .or_else(|_| env::var("LRB_DATA_DIR").map(|p| format!("{}/data.sled", p)))
            .unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());

        // ВАЖНО: в твоём ядре Ledger::open(path), а не open_default()
        let ledger = Ledger::open(&data_path)?;
        let db = ledger.db().clone();

        Ok(AppState { ledger: Arc::new(Mutex::new(ledger)), db, archive: None })
    }

    #[inline] pub fn sled(&self) -> &sled::Db { &self.db }
}

pub fn bind_addr() -> SocketAddr {
    let raw = env::var("LRB_BIND")
        .or_else(|_| env::var("LRB_NODE_LISTEN"))
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    SocketAddr::from_str(&raw).unwrap_or_else(|_| SocketAddr::from_str("0.0.0.0:8080").unwrap())
}

~~~

### node/src/version.rs

~~~rust
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

~~~

### node/src/auth.rs

~~~rust
//! Auth-модуль: защита bridge/admin. Admin — только JWT (HS256).
//! Обязательные переменные окружения: LRB_BRIDGE_KEY, LRB_JWT_SECRET.

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

fn forbid_default(val: &str) -> Result<()> {
    let low = val.to_lowercase();
    let banned = ["", "change_me", "changeme", "dev_secret", "default", "empty"];
    if banned.iter().any(|b| low == *b) {
        return Err(anyhow!("insecure default key"));
    }
    Ok(())
}

/* ---------------- Bridge (ключ обязателен) ---------------- */

pub fn require_bridge(headers: &HeaderMap) -> Result<()> {
    let expect = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY not set"))?;
    forbid_default(&expect)?;
    let got = headers.get("X-Bridge-Key").ok_or_else(|| anyhow!("missing X-Bridge-Key"))?;
    let got = got.to_str().map_err(|_| anyhow!("invalid X-Bridge-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad bridge key")); }
    Ok(())
}

/* ---------------- Admin (только JWT HS256) ---------------- */

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct AdminClaims {
    sub: String,
    iat: Option<u64>,
    exp: Option<u64>,
}

pub fn require_admin(headers: &HeaderMap) -> Result<()> {
    let token = headers.get("X-Admin-JWT").ok_or_else(|| anyhow!("missing X-Admin-JWT"))?;
    let token = token.to_str().map_err(|_| anyhow!("invalid X-Admin-JWT"))?.to_string();

    let secret = std::env::var("LRB_JWT_SECRET").map_err(|_| anyhow!("LRB_JWT_SECRET not set"))?;
    forbid_default(&secret)?;
    let data = decode::<AdminClaims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256)
    ).map_err(|e| anyhow!("admin jwt invalid: {e}"))?;

    if data.claims.sub != "admin" { return Err(anyhow!("forbidden")); }
    Ok(())
}

/* ---------------- Стартовая проверка секретов ---------------- */

pub fn assert_secrets_on_start() -> Result<()> {
    for (key, _tag) in [("LRB_BRIDGE_KEY","bridge"), ("LRB_JWT_SECRET","jwt")] {
        let v = std::env::var(key).map_err(|_| anyhow!("{key} is not set"))?;
        forbid_default(&v)?;
    }
    Ok(())
}

~~~

### node/src/admin.rs

~~~rust
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

~~~

### node/src/bridge.rs

~~~rust
use axum::{extract::State, response::IntoResponse, Json};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use blake3;

use crate::state::AppState;
use crate::auth::require_bridge;
use crate::metrics::inc_total;

#[derive(Deserialize, Debug)]
pub struct DepositReq {
    pub txid: String,        // внешний tx (например, L1 hash)
    pub amount: u64,         // сумма депозита
    pub from_chain: String,  // сеть-источник (ETH/BTC/…)
    pub to_rid: String,      // RID получателя в LRB
}

#[derive(Deserialize, Debug)]
pub struct RedeemReq  {
    pub rtoken_tx: String,   // внутренняя операция/tx rToken
    pub to_chain: String,    // сеть-назначение
    pub to_addr: String,     // адрес-назначение во внешней сети
    pub amount: u64,         // сумма на вывод
}

#[derive(Deserialize, Debug)]
pub struct VerifyReq  {
    pub op_id: String,       // идентификатор операции для проверки статуса
}

#[derive(Serialize)]
pub struct BridgeResp {
    pub ok: bool,
    pub op_id: String,
    pub info: String,
}

/// Хелпер: стабильный op_id по concat входных полей
fn opid(parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update(b"|");
    }
    h.finalize().to_hex().to_string()
}

pub async fn deposit(State(_app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<DepositReq>) -> impl IntoResponse {
    inc_total("bridge_deposit");
    if let Err(e) = require_bridge(&headers) {
        return Json(BridgeResp { ok: false, op_id: String::new(), info: format!("forbidden: {e}") });
    }
    // используем ВСЕ поля, формируем детерминированный op_id
    let op_id = opid(&[ "deposit", &req.txid, &req.amount.to_string(), &req.from_chain, &req.to_rid ]);
    // TODO: тут можно писать заявку в sled (таблица rbridge_ops), сейчас MVP-ответ
    Json(BridgeResp {
        ok: true,
        op_id,
        info: format!("deposit registered: txid={}, amount={}, from_chain={}, to_rid={}", req.txid, req.amount, req.from_chain, req.to_rid),
    })
}

pub async fn redeem(State(_app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<RedeemReq>) -> impl IntoResponse {
    inc_total("bridge_redeem");
    if let Err(e) = require_bridge(&headers) {
        return Json(BridgeResp { ok: false, op_id: String::new(), info: format!("forbidden: {e}") });
    }
    let op_id = opid(&[ "redeem", &req.rtoken_tx, &req.amount.to_string(), &req.to_chain, &req.to_addr ]);
    // TODO: запись заявки на вывод в sled
    Json(BridgeResp {
        ok: true,
        op_id,
        info: format!("redeem accepted: rtoken_tx={}, amount={}, to_chain={}, to_addr={}", req.rtoken_tx, req.amount, req.to_chain, req.to_addr),
    })
}

pub async fn verify(State(_app): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<VerifyReq>) -> impl IntoResponse {
    inc_total("bridge_verify");
    if let Err(e) = require_bridge(&headers) {
        return Json(BridgeResp { ok: false, op_id: String::new(), info: format!("forbidden: {e}") });
    }
    // TODO: lookup статуса по op_id в sled; пока MVP: echo
    Json(BridgeResp {
        ok: true,
        op_id: req.op_id,
        info: "status: pending (mvp)".into(),
    })
}

~~~

### node/src/openapi.rs

~~~rust
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

~~~

### node/src/guard.rs

~~~rust
//! Rate-limit + ACL middleware для LOGOS Node (Axum 0.7).
//! ENV:
//!   LRB_QPS, LRB_BURST
//!   LRB_RATE_BYPASS_CIDRS="127.0.0.1/32,::1/128"
//!   LRB_ADMIN_ALLOW_CIDRS="127.0.0.1/32,::1/128"

use axum::{body::Body, http::{Request, StatusCode}, middleware::Next, response::IntoResponse};
use dashmap::DashMap;
use ipnet::IpNet;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{net::{IpAddr, Ipv4Addr}, str::FromStr, time::Instant};

static BUCKETS: Lazy<DashMap<IpAddr, Mutex<TokenBucket>>> = Lazy::new(DashMap::new);
static BYPASS:  Lazy<Vec<IpNet>> = Lazy::new(|| parse_cidrs(env_get("LRB_RATE_BYPASS_CIDRS").unwrap_or_else(|| "127.0.0.1/32,::1/128".into())));
static ADMIN:   Lazy<Vec<IpNet>> = Lazy::new(|| parse_cidrs(env_get("LRB_ADMIN_ALLOW_CIDRS").unwrap_or_else(|| "127.0.0.1/32,::1/128".into())));

#[derive(Debug)]
struct TokenBucket { capacity: u64, tokens: f64, qps: f64, last: Instant }
impl TokenBucket {
    fn new(qps: u64, burst: u64) -> Self {
        Self { capacity: burst, tokens: burst as f64, qps: qps as f64, last: Instant::now() }
    }
    fn try_take(&mut self) -> bool {
        let dt = self.last.elapsed(); self.last = Instant::now();
        self.tokens = (self.tokens + self.qps * dt.as_secs_f64()).min(self.capacity as f64);
        if self.tokens >= 1.0 { self.tokens -= 1.0; true } else { false }
    }
}

pub async fn rate_limit_mw(req: Request<Body>, next: Next) -> axum::response::Response {
    let ip = client_ip(&req).unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let path = req.uri().path();

    // 1) Жёсткая ACL для /admin/*
    if path.starts_with("/admin/") {
        if !ip_in(&ip, &*ADMIN) {
            return (StatusCode::FORBIDDEN, "admin denied").into_response();
        }
        // ВАЖНО: /admin/* не лимитируем (чтобы не получать 429)
        return next.run(req).await;
    }

    // 2) Bypass для доверенных сетей
    if !ip_in(&ip, &*BYPASS) {
        let (qps, burst) = load_limits();
        let entry = BUCKETS.entry(ip).or_insert_with(|| Mutex::new(TokenBucket::new(qps, burst)));
        let mut bucket = entry.lock();
        if !bucket.try_take() {
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, "").into_response();
            resp.headers_mut().insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from_static("0.1"));
            return resp;
        }
    }

    next.run(req).await
}

fn env_get(k: &str) -> Option<String> { std::env::var(k).ok() }
fn load_limits() -> (u64, u64) {
    let qps = env_get("LRB_QPS").and_then(|s| s.parse().ok()).unwrap_or(30);
    let burst = env_get("LRB_BURST").and_then(|s| s.parse().ok()).unwrap_or(60);
    (qps, burst)
}
fn parse_cidrs(csv: String) -> Vec<IpNet> {
    csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).filter_map(|s| IpNet::from_str(s).ok()).collect()
}
fn ip_in(ip: &IpAddr, nets: &[IpNet]) -> bool { nets.iter().any(|n| n.contains(ip)) }
fn client_ip(req: &Request<Body>) -> Option<IpAddr> {
    if let Some(xff) = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next().map(|s| s.trim()) { if let Ok(ip) = first.parse() { return Some(ip); } }
    }
    if let Some(xri) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = xri.parse() { return Some(ip); }
    }
    None
}

~~~

### node/src/wallet.rs

~~~rust
use axum::{routing::post, Router, extract::{State}, Json};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterIn { pub rid: String, pub pub_hex: String }

#[derive(serde::Serialize)] pub struct OkResp { pub ok: bool }

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wallet/register", post(register))
}

async fn register(State(app): State<Arc<AppState>>, Json(inp): Json<RegisterIn>) -> Json<OkResp> {
    // сохраняем сопоставление RID -> pubkey (hex) в sled
    // ключ: "pk:<rid>" => pub_hex (bytes)
    let key = format!("pk:{}", inp.rid);
    let db = app.sled();
    db.insert(key.as_bytes(), inp.pub_hex.as_bytes()).ok();
    db.flush_async().await.ok();
    info!("wallet register rid={} pub_hex_len={}", inp.rid, inp.pub_hex.len());
    Json(OkResp{ ok:true })
}

~~~

### node/src/stake.rs

~~~rust
use axum::{routing::{get, post}, Router, extract::{State, Path}, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use crate::state::AppState;

const RATE_NUM: u128 = 1;      // 1 микро-LGN за высоту на каждые RATE_DEN единиц
const RATE_DEN: u128 = 100_000; // тюнимо (пример: 1e5 = 0.000001 за 1e5 делегата/высоту)

#[derive(Deserialize)]
pub struct StakeTxIn {
    pub from: String,
    pub op: String,       // "delegate" | "undelegate" | "claim"
    pub validator: String,
    pub amount: u64,
    pub nonce: u64,
    pub sig_hex: String,
}

#[derive(Serialize)]
pub struct StakeResp { pub ok: bool, pub info: String }

#[derive(Serialize)]
pub struct DelegRow { pub validator:String, pub amount:u64, pub since_height: Option<u64> }

#[derive(Serialize)]
pub struct RewardRow { pub validator:String, pub pending:u64, pub last_height: Option<u64> }

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/stake/submit", post(stake_submit))
        .route("/stake/delegations/:rid", get(delegations))
        .route("/stake/rewards/:rid",     get(rewards))
}

fn build_msg(from:&str, op:&str, validator:&str, amount:u64, nonce:u64) -> Vec<u8> {
    format!("{}|{}|{}|{}|{}", from, op, validator, amount, nonce).into_bytes()
}

fn vk_from_base58_rid(rid:&str) -> anyhow::Result<VerifyingKey> {
    let pk = bs58::decode(rid).into_vec().map_err(|_| anyhow::anyhow!("bad rid b58"))?;
    let arr:[u8;32] = pk.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad pubkey len"))?;
    let vk = VerifyingKey::from_bytes(&arr).map_err(|_| anyhow::anyhow!("bad ed25519 pubkey"))?;
    Ok(vk)
}

// начисление pending по текущей высоте
fn accrue_pending(db:&sled::Db, from:&str, val:&str, now_h:u64) {
    let amt_key   = format!("staking:deleg:{}:{}", from, val);
    let last_key  = format!("staking:last:{}:{}", from, val);
    let pend_key  = format!("staking:pend:{}:{}", from, val);
    let amt = db.get(amt_key.as_bytes()).ok().flatten()
        .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8]))).unwrap_or(0);
    if amt==0 { // нечего начислять
        db.insert(last_key.as_bytes(), &now_h.to_be_bytes()).ok(); return;
    }
    let last = db.get(last_key.as_bytes()).ok().flatten()
        .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8]))).unwrap_or(now_h);
    let delta_h = now_h.saturating_sub(last);
    if delta_h==0 { return; }

    let prev_pending = db.get(pend_key.as_bytes()).ok().flatten()
        .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8]))).unwrap_or(0);
    // простая формула: pending += delta_h * amt * RATE_NUM / RATE_DEN
    let add = ((delta_h as u128) * (amt as u128) * RATE_NUM / RATE_DEN) as u64;
    let new_pending = prev_pending.saturating_add(add);

    db.insert(pend_key.as_bytes(), &new_pending.to_be_bytes()).ok();
    db.insert(last_key.as_bytes(), &now_h.to_be_bytes()).ok();
}

async fn stake_submit(State(app): State<Arc<AppState>>, Json(tx): Json<StakeTxIn>) -> Json<StakeResp> {
    // verify
    let vk = match vk_from_base58_rid(&tx.from) { Ok(v)=>v, Err(e)=>return Json(StakeResp{ok:false,info:format!("bad rid/pubkey: {e}")}) };
    let msg = build_msg(&tx.from,&tx.op,&tx.validator,tx.amount,tx.nonce);
    let sig_bytes = match hex::decode(tx.sig_hex.trim()){ Ok(v)=>v, Err(_)=>return Json(StakeResp{ok:false,info:"bad signature hex".into()}) };
    let sig = match Signature::from_slice(&sig_bytes){ Ok(s)=>s, Err(_)=>return Json(StakeResp{ok:false,info:"bad signature size".into()}) };
    if let Err(e)=vk.verify(&msg,&sig){ warn!("stake verify failed: {e}"); return Json(StakeResp{ok:false,info:"bad signature".into()}); }

    // state
    let db = app.sled();
    let height = app.ledger.lock().height().unwrap_or(0);

    // сначала доначислим pending до текущей высоты
    accrue_pending(&db, &tx.from, &tx.validator, height);

    let amt_key   = format!("staking:deleg:{}:{}", &tx.from, &tx.validator);
    let since_key = format!("staking:since:{}:{}", &tx.from, &tx.validator);
    let pend_key  = format!("staking:pend:{}:{}", &tx.from, &tx.validator);

    let prev_amt = db.get(amt_key.as_bytes()).ok().flatten()
        .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8]))).unwrap_or(0);

    let new_amt = match tx.op.as_str() {
        "delegate"   => prev_amt.saturating_add(tx.amount),
        "undelegate" => prev_amt.saturating_sub(tx.amount),
        "claim"      => {
            // списываем pending в ноль; интеграцию с ledger (зачислить на баланс) добавим следующим патчем
            db.insert(pend_key.as_bytes(), &0u64.to_be_bytes()).ok();
            prev_amt
        },
        _ => return Json(StakeResp{ok:false, info:"bad op".into()}),
    };

    db.insert(amt_key.as_bytes(), &new_amt.to_be_bytes()).ok();
    if tx.op=="delegate" && db.get(since_key.as_bytes()).ok().flatten().is_none() {
        db.insert(since_key.as_bytes(), &height.to_be_bytes()).ok();
    }
    db.flush_async().await.ok();

    info!("stake ok op={} from={} val={} amt={} nonce={} h={}", tx.op, tx.from, tx.validator, tx.amount, tx.nonce, height);
    Json(StakeResp{ ok:true, info:"accepted".into() })
}

async fn delegations(State(app): State<Arc<AppState>>, Path(rid): Path<String>) -> Json<Vec<DelegRow>> {
    let db = app.sled();
    let prefix = format!("staking:deleg:{}:", rid);
    let mut out = Vec::new();
    for kv in db.scan_prefix(prefix.as_bytes()) {
        if let Ok((k,v)) = kv {
            let key_str = String::from_utf8_lossy(k.as_ref());
            let validator = key_str.rsplit(':').next().unwrap_or("").to_string();
            let amount = u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8]));
            let since_key = format!("staking:since:{}:{}", rid, validator);
            let since = db.get(since_key.as_bytes()).ok().flatten()
                .map(|b| u64::from_be_bytes(b.as_ref().try_into().unwrap_or([0u8;8])));
            if amount>0 { out.push(DelegRow{ validator, amount, since_height: since }); }
        }
    }
    Json(out)
}

async fn rewards(State(app): State<Arc<AppState>>, Path(rid): Path<String>) -> Json<Vec<RewardRow>> {
    let db = app.sled();
    let now_h = app.ledger.lock().height().unwrap_or(0);

    // на лету доначислим для всех пар rid:*
    let prefix = format!("staking:deleg:{}:", rid);
    for kv in db.scan_prefix(prefix.as_bytes()) {
        if let Ok((k,_)) = kv {
            let key_str = String::from_utf8_lossy(k.as_ref());
            let validator = key_str.rsplit(':').next().unwrap_or("");
            accrue_pending(&db, &rid, validator, now_h);
        }
    }

    let mut out = Vec::new();
    let pend_prefix = format!("staking:pend:{}:", rid);
    for kv in db.scan_prefix(pend_prefix.as_bytes()) {
        if let Ok((k,v)) = kv {
            let key_str = String::from_utf8_lossy(k.as_ref());
            let validator = key_str.rsplit(':').next().unwrap_or("").to_string();
            let pending = u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8]));
            let last_key = format!("staking:last:{}:{}", rid, validator);
            let last = db.get(last_key.as_bytes()).ok().flatten()
                .map(|b| u64::from_be_bytes(b.as_ref().try_into().unwrap_or([0u8;8])));
            out.push(RewardRow{ validator, pending, last_height: last });
        }
    }
    Json(out)
}

~~~

### node/src/archive/*

### node/src/archive/mod.rs

~~~rust
//! Postgres archive backend (deadpool-postgres 0.12)

use deadpool_postgres::{Manager, Pool};
use tokio_postgres::{NoTls, Row, Config};
use serde::Serialize;
use anyhow::Result;

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
            "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts from txs where txid=$1",
            &[&txid]
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
        let rows = if let Some(rid) = rid {
            client.query(
                "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
                 from txs where (from_rid=$1 or to_rid=$1) and ($2::bigint is null or extract(epoch from ts)<$2) \
                 order by ts desc limit $3",
                &[&rid, &before_ts, &limit]
            ).await?
        } else {
            client.query(
                "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
                 from txs where ($1::bigint is null or extract(epoch from ts)<$1) \
                 order by ts desc limit $2",
                &[&before_ts, &limit]
            ).await?
        };
        Ok(rows.into_iter().map(TxRecord::from_row).collect())
    }

    #[allow(dead_code)]
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

~~~

### node/src/archive/pg.rs

~~~rust
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

~~~

### node/src/archive/sqlite.rs

~~~rust
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

~~~

### node/src/bin/*

### node/src/bin/bench_burst.rs

~~~rust
// node/src/bin/bench_burst.rs — мини-нагрузчик отправки tx
use reqwest::Client;
use serde_json::json;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let from = env::args().nth(1).expect("arg1 = from rid");
    let to   = env::args().nth(2).expect("arg2 = to rid");
    let base_nonce: u64 = env::args().nth(3).unwrap_or_else(|| "1".into()).parse().unwrap();
    let n: usize = env::args().nth(4).unwrap_or_else(|| "1000".into()).parse().unwrap();

    let cli = Client::new();
    let mut handles = Vec::new();

    for i in 0..n {
        let cli = cli.clone();
        let url = url.clone();
        let from = from.clone();
        let to = to.clone();
        let nonce = base_nonce + (i as u64);
        handles.push(tokio::spawn(async move {
            let body = json!({"from": from, "to": to, "amount": 1u64, "nonce": nonce, "sig_hex": "00"});
            let _ = cli.post(format!("{}/submit_tx", url)).json(&body).send().await;
        }));
    }

    for h in handles { let _ = h.await; }
    println!("burst sent: {}", n);
    Ok(())
}

~~~

### node/src/bin/make_tx.rs

~~~rust
// node/src/bin/make_tx.rs — отправка одной транзакции в узел через REST
// Зависимости: reqwest (blocking), serde_json

use reqwest::blocking::Client;
use serde_json::json;
use std::env;

fn main() {
    // Аргументы: FROM TO AMOUNT NONCE  (подпись тут заглушка — в проде подписывает кошелёк)
    let from = env::args().nth(1).expect("arg1 = from RID");
    let to   = env::args().nth(2).expect("arg2 = to RID");
    let amount: u64 = env::args().nth(3).expect("arg3 = amount").parse().expect("u64");
    let nonce:  u64 = env::args().nth(4).unwrap_or_else(|| "1".into()).parse().expect("u64");

    let url = env::var("NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let body = json!({
        "from": from,
        "to": to,
        "amount": amount,
        "nonce": nonce,
        "sig_hex": "00" // заглушка
    });

    let cli = Client::new();
    let resp = cli.post(format!("{}/submit_tx", url))
        .json(&body)
        .send()
        .expect("send");
    println!("{}", resp.text().unwrap_or_default());
}

~~~

### node/src/bin/mint.rs

~~~rust
// node/src/bin/mint.rs — утилита пополнения баланса (dev/admin)
use std::env;
use lrb_core::ledger::Ledger;

fn main() {
    // путь к sled
    let data_path = env::var("LRB_DATA_PATH")
        .or_else(|_| env::var("LRB_DATA_DIR").map(|p| format!("{}/data.sled", p)))
        .unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());

    let ledger = Ledger::open(&data_path).expect("open ledger");

    let rid = env::args().nth(1).expect("arg1 = RID (base58)");
    let amount: u64 = env::args().nth(2).expect("arg2 = amount").parse().expect("u64");

    ledger.set_balance(&rid, amount as u128).expect("set_balance");
    let _ = ledger.add_minted(amount);

    println!("mint ok: rid={} amount={}", rid, amount);
}

~~~

## configs (templates)

### configs/genesis.yaml

~~~yaml
# LOGOS LRB — GENESIS (prod)
l0_symbol: "Λ0"

sigma:
  f1: 7.83
  f2: 1.618
  harmonics: [432, 864, 3456]

emission:
  total_lgn: 81000000            # 81M LGN (человеческая деноминация)
  cap_micro: 81000000000000      # 81_000_000 * 1_000_000 (микро-LGN)
  allocations:
    # пример стартовых аллокаций (замени RID и суммы по необходимости)
    - { rid: "Λ0@7.83Hzφ0.3877", micro: 1000000000 } # 1000.000000 LGN

fees:
  base_lgn_cost_microunits: 100  # 0.000100 LGN
  burn_percent: 10

consensus:
  producer_slot_ms: 1000         # интервал блока (ms)
  quorum: 1
  fork_choice: "deterministic"   # для single-node

bridge:
  max_per_tx_micro: 10000000

guard:
  rate_limit_qps: 500
  rate_limit_burst: 1000

~~~

### configs/logos_config.yaml

~~~yaml
# LOGOS LRB — Node Config (prod)

node:
  listen: "0.0.0.0:8080"
  data_path: "/var/lib/logos/data.sled"
  node_key_path: "/var/lib/logos/node_key"

limits:
  mempool_cap: 200000
  max_block_tx: 20000
  slot_ms: 1000

guard:
  rate_limit_qps: 500
  rate_limit_burst: 1000
  cidr_bypass: ["127.0.0.1/32","::1/128"]

phase:
  enabled: true
  freqs_hz: [7.83, 1.618, 432]
  min_score: -0.2

bridge:
  max_per_tx: 10000000

explorer:
  page_size: 50

~~~

## scripts

### scripts/bootstrap_node.sh

~~~bash
#!/usr/bin/env bash
set -euo pipefail
DOMAIN="${DOMAIN:-example.com}"
INSTANCE="${INSTANCE:-a}"

sudo apt-get update -y
sudo apt-get install -y git curl jq build-essential pkg-config libssl-dev nginx

/usr/bin/id logos >/dev/null 2>&1 || sudo useradd -r -m -d /var/lib/logos -s /usr/sbin/nologin logos
sudo mkdir -p /opt/logos /etc/logos /var/lib/logos /opt/logos/www/wallet

cd "$(dirname "$0")/.."
cargo build --release -p logos_node
sudo cp ./target/release/logos_node /opt/logos/logos_node
sudo chown logos:logos /opt/logos/logos_node
sudo chmod 755 /opt/logos/logos_node

sudo cp ./infra/systemd/logos-node@.service /etc/systemd/system/logos-node@.service
sudo systemctl daemon-reload

sudo cp ./infra/nginx/logos-api-lb.conf.example /etc/nginx/sites-available/logos-api-lb.conf
sudo sed -i "s/YOUR_DOMAIN/${DOMAIN}/" /etc/nginx/sites-available/logos-api-lb.conf
sudo ln -sf /etc/nginx/sites-available/logos-api-lb.conf /etc/nginx/sites-enabled/logos-api-lb.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

sudo cp -r ./www/wallet/* /opt/logos/www/wallet/
sudo chown -R logos:logos /opt/logos/www

if [ ! -f "/etc/logos/node-${INSTANCE}.env" ]; then
  sudo cp ./configs/env/node.env.example "/etc/logos/node-${INSTANCE}.env"
  echo ">>> EDIT /etc/logos/node-${INSTANCE}.env (LRB_NODE_SK_HEX/LRB_ADMIN_KEY/LRB_WALLET_ORIGIN)"
fi

sudo systemctl enable --now "logos-node@${INSTANCE}"
systemctl --no-pager status "logos-node@${INSTANCE}"

echo "API: http://127.0.0.1:8080   Wallet: http://${DOMAIN}/wallet/"

~~~

### scripts/collect_and_push.sh

~~~bash
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="/root/logos_lrb"
GIT_REMOTE="${GIT_REMOTE:-origin}"
GIT_BRANCH="${GIT_BRANCH:-main}"
INCLUDE_SNAPSHOT="${INCLUDE_SNAPSHOT:-0}"

echo "[i] collecting from live system → $REPO_ROOT"
cd "$REPO_ROOT"

# .gitignore (если нет)
[ -f .gitignore ] || cat > .gitignore <<'EOF'
target/
**/target/
node_modules/
dist/
.DS_Store
*.swp
*.swo
/etc/logos/*.env
*.pem
*.key
*.crt
*.p12
/var/lib/logos/
/var/run/logos_health.json
/usr/local/bin/lrb_bench*
/usr/local/bin/logos_healthcheck.sh
/etc/letsencrypt/
*.log
/var/log/nginx/*.log
www/wallet/*.map
tools/**/go/bin/
EOF

# каталоги в репо
mkdir -p configs/env infra/systemd infra/nginx scripts tools/bench/go www/wallet docs

# wallet → www/wallet
if [ -d /opt/logos/www/wallet ]; then
  rsync -a --delete /opt/logos/www/wallet/ www/wallet/
  echo "[i] wallet synced"
fi

# systemd → infra/systemd
[ -f /etc/systemd/system/logos-node@.service ]       && cp -f /etc/systemd/system/logos-node@.service        infra/systemd/
[ -f /etc/systemd/system/logos-healthcheck.service ] && cp -f /etc/systemd/system/logos-healthcheck.service   infra/systemd/
[ -f /etc/systemd/system/logos-healthcheck.timer ]   && cp -f /etc/systemd/system/logos-healthcheck.timer     infra/systemd/

# nginx → infra/nginx (example)
[ -f /etc/nginx/sites-available/logos-api-lb.conf ] && cp -f /etc/nginx/sites-available/logos-api-lb.conf infra/nginx/logos-api-lb.conf.example

# healthcheck → scripts (если установлен в /usr/local/bin)
if [ -f /usr/local/bin/logos_healthcheck.sh ]; then
  cp -f /usr/local/bin/logos_healthcheck.sh scripts/logos_healthcheck.sh
  chmod +x scripts/logos_healthcheck.sh
fi

# env → *.example (обезличиваем секреты)
mkdir -p configs/env
shopt -s nullglob
for f in /etc/logos/node-*.env; do
  bn="$(basename "$f")"
  sed -E \
    -e 's/^(LRB_NODE_SK_HEX)=.*/\1=CHANGE_ME_64_HEX/' \
    -e 's/^(LRB_ADMIN_KEY)=.*/\1=CHANGE_ADMIN_KEY/' \
    -e 's/^(LRB_BRIDGE_KEY)=.*/\1=CHANGE_ME/' \
    "$f" > "configs/env/${bn}.example"
  echo "[i] env example: configs/env/${bn}.example"
done
# общий пример, если ничего не найдено
if [ -z "$(ls -1 configs/env/*.example 2>/dev/null || true)" ]; then
cat > configs/env/node.env.example <<'EEX'
LRB_NODE_SK_HEX=CHANGE_ME_64_HEX
LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
LRB_BRIDGE_KEY=CHANGE_ME
LRB_DATA_DIR=/var/lib/logos
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_WALLET_ORIGIN=http://localhost
LRB_RATE_QPS=20
LRB_RATE_BURST=40
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
LRB_ENABLE_FAUCET=0
LRB_ADMIN_IP_ALLOW=127.0.0.1/32,::1/128
EEX
fi

# snapshots (опционально)
if [ "${INCLUDE_SNAPSHOT}" = "1" ]; then
  mkdir -p snapshots
  cp -f /root/logos_snapshot/*.txt snapshots/ 2>/dev/null || true
fi

# git add/commit/push
git add -A
if ! git diff --cached --quiet; then
  git commit -m "sync(live): full system snapshot (code+infra+wallet+scripts), env → *.example"
else
  echo "[i] nothing to commit"
fi

# пуш
git push "${GIT_REMOTE}" "${GIT_BRANCH}"
echo "[✓] pushed to ${GIT_REMOTE}/${GIT_BRANCH}"

~~~

### scripts/logos_healthcheck.sh

~~~bash
#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
STATE_FILE="/var/run/logos_health.json"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT

# Метрика: время ответа healthz
START=$(date +%s%3N)
if ! curl -sf "$BASE/healthz" -o "$TMP" >/dev/null; then
  MSG="LOGOS: /healthz FAIL at $(date -u +%FT%TZ)"
  logger -t logos_health "$MSG"
  [ -n "${TG_TOKEN:-}" ] && curl -s "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
     -d chat_id="${TG_CHAT_ID}" -d text="$MSG" >/dev/null || true
  exit 1
fi
RT=$(( $(date +%s%3N) - START ))

# Высота
HEAD_JSON=$(curl -sf "$BASE/head")
HEIGHT=$(echo "$HEAD_JSON" | jq -r '.height' 2>/dev/null || echo 0)

LAST_H=0
LAST_TS=0
if [ -f "$STATE_FILE" ]; then
  LAST_H=$(jq -r '.height // 0' "$STATE_FILE" 2>/dev/null || echo 0)
  LAST_TS=$(jq -r '.ts_ms // 0' "$STATE_FILE" 2>/dev/null || echo 0)
fi

TS_MS=$(date +%s%3N)
printf '{"ts_ms":%s,"height":%s,"rt_ms":%s}\n' "$TS_MS" "$HEIGHT" "$RT" > "$STATE_FILE"

# Правила алертов
ALERT=""
[ "$RT" -gt 1500 ] && ALERT="slow healthz: ${RT}ms"
if [ -n "$LAST_TS" ] && [ $((TS_MS - LAST_TS)) -gt 300000 ]; then
  # если 5 минут прошло и высота не менялась (и была >0)
  if [ "$HEIGHT" -eq "$LAST_H" ] && [ "$HEIGHT" -gt 0 ]; then
    ALERT="${ALERT} height stuck at ${HEIGHT}"
  fi
fi

if [ -n "$ALERT" ]; then
  MSG="LOGOS ALERT: ${ALERT} at $(date -u +%FT%TZ)"
  logger -t logos_health "$MSG"
  if [ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHAT_ID:-}" ]; then
    curl -s "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
       -d chat_id="${TG_CHAT_ID}" -d text="$MSG" >/dev/null || true
  fi
fi

exit 0

~~~


---
(конец книги)
