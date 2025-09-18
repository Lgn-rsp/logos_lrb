# LOGOS LRB — FULL BOOK (complete prod snapshot)

Срез **рабочей прод-версии** LOGOS LRB (Axum 0.7, Ed25519 в /submit_tx, BLAKE3 block hash, Prometheus метрики).

Generated (UTC): 2025-09-18T11-37-16Z

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

### README.md

~~~
# LOGOS Resonance Blockchain — Monorepo

Состав:
- `lrb_core/`  — ядро (Rust)
- `node/`      — узел (Axum REST + gossip)
- `modules/`   — модульные компоненты
- `tools/`     — e2e и нагрузочные тесты (Go)
- `www/wallet/` — Web Wallet (MVP)
- `wallet-proxy/` — FastAPI proxy + scanner
- `infra/systemd`, `infra/nginx` — юниты/конфиги (без секретов)
- `configs/*.example` — примеры окружения

## Быстрый старт
1) Rust/Go/Python3.12
2) `cargo build --release -p logos_node`
3) Настрой ENV по `configs/keys.env.example` (секреты не коммить)
4) Подними systemd-юниты из `infra/systemd` (редактируй пути/ENV)
5) Nginx-site из `infra/nginx/lrb_wallet.conf` (wallet + proxy)

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

### lrb_core/src/phase_filters/mod.rs

~~~rust
// lrb_core/src/phase_filters/mod.rs
use crate::types::Block;

/// Проходной фазовый фильтр (место для реальной логики Σ(t)/фаз).
#[inline]
pub fn block_passes_phase(_blk: &Block) -> bool {
    true
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

~~~

### node/src/main.rs

~~~rust
use axum::{routing::{get, post}, Router};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::sync::Arc;
use tracing::{info, warn};

mod api;
mod bridge;
mod bridge_journal;
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
        .route("/submit_tx_batch", post(api::submit_tx_batch))
        .route("/economy", get(api::economy))
        .route("/history/:rid", get(api::history))
        // archive
        .route("/archive/blocks", get(api::archive_blocks))
        .route("/archive/txs",    get(api::archive_txs))
        .route("/archive/history/:rid", get(api::archive_history))
        .route("/archive/tx/:txid",     get(api::archive_tx))
        // staking wrappers
        .route("/stake/delegate",   post(api::stake_delegate))
        .route("/stake/undelegate", post(api::stake_undelegate))
        .route("/stake/claim",      post(api::stake_claim))
        .route("/stake/my/:rid",    get(api::stake_my))
        // bridge (durable)
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem",  post(bridge::redeem))
        .route("/health/bridge",  get(bridge::health))
        // version/metrics/openapi
        .route("/version",     get(version::get))
        .route("/metrics",     get(metrics::prometheus))
        .route("/openapi.json",get(openapi::serve))
        // admin
        .route("/admin/set_balance", post(admin::set_balance))
        .route("/admin/bump_nonce",  post(admin::bump_nonce))
        .route("/admin/set_nonce",   post(admin::set_nonce))
        .route("/admin/mint",        post(admin::mint))
        .route("/admin/burn",        post(admin::burn))
        // legacy routes
        .merge(wallet::routes())
        .merge(stake::routes())
        .with_state(app_state)
        .layer(ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(axum::middleware::from_fn(guard::rate_limit_mw))
            .layer(axum::middleware::from_fn(metrics::track)))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    auth::assert_secrets_on_start().expect("secrets missing");

    let app_state = Arc::new(state::AppState::new()?);

    if let Some(ar) = crate::archive::Archive::new_from_env().await {
        unsafe { let p = Arc::as_ptr(&app_state) as *mut state::AppState; (*p).archive = Some(ar); }
        info!("archive backend initialized");
    } else { warn!("archive disabled"); }

    info!("producer start");
    let _producer = producer::run(app_state.clone());

    // start bridge retry worker
    tokio::spawn(bridge::retry_worker(app_state.clone()));

    let addr = state::bind_addr();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("logos_node listening on {addr}");
    axum::serve(listener, router(app_state)).await?;
    Ok(())
}

~~~

### node/src/api.rs

~~~rust
use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tracing::{info, warn, error};

use crate::{state::AppState, metrics};
use ed25519_dalek::{Verifier, Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use sha2::{Sha256, Digest};

/* ---------- модели ---------- */

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

/* ---------- base ---------- */

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

/* ---------- подпись ---------- */

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

/* ---------- submit tx ---------- */

pub async fn submit_tx(State(app): State<Arc<AppState>>, Json(tx):Json<TxIn>) -> (StatusCode, Json<SubmitResult>) {
    // verify
    let msg = canonical_msg(&tx.from, &tx.to, tx.amount, tx.nonce);
    if let Err(e) = verify_sig(&tx.from, &msg, &tx.sig_hex) {
        metrics::inc_tx_rejected("bad_signature");
        return (StatusCode::UNAUTHORIZED, Json(SubmitResult{ ok:false, txid:None, info:e }));
    }
    // nonce policy
    let prev = app.ledger.lock().get_nonce(&tx.from).unwrap_or(0);
    if tx.nonce <= prev {
        metrics::inc_tx_rejected("nonce_reuse");
        return (StatusCode::CONFLICT, Json(SubmitResult{ ok:false, txid:None, info:"nonce_reuse".into() }));
    }
    // commit
    let stx = match app.ledger.lock().submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.clone()) {
        Ok(s)=>s, Err(e)=>{
            metrics::inc_tx_rejected("internal");
            return (StatusCode::OK, Json(SubmitResult{ ok:false, txid:None, info:e.to_string() }))
        },
    };
    // archive
    if let Some(arch)=&app.archive {
        match arch.record_tx(&stx.txid, stx.height, &stx.from, &stx.to, stx.amount, stx.nonce, Some((stx.ts/1000) as u64)).await {
            Ok(()) => info!("archive: wrote tx {}", stx.txid),
            Err(e) => error!("archive: write failed: {}", e),
        }
    } else { warn!("archive: not configured"); }

    metrics::inc_tx_accepted();
    (StatusCode::OK, Json(SubmitResult{ ok:true, txid:Some(stx.txid), info:"accepted".into() }))
}

/* ---------- submit tx batch ---------- */

pub async fn submit_tx_batch(State(app): State<Arc<AppState>>, Json(req):Json<SubmitBatchReq>)
    -> (StatusCode, Json<Vec<SubmitBatchItem>>)
{
    let mut out = Vec::with_capacity(req.txs.len());
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
    (StatusCode::OK, Json(out))
}

/* ---------- economy/history ---------- */

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

/* ---------- archive ---------- */

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

/* ---------- staking compatibility wrappers ---------- */
/* Эти ручки проксируют в существующие stake::routes() через локальный HTTP */

#[derive(Deserialize, Serialize)]
pub struct StakeAction {
    pub rid: String,
    #[serde(default)] pub validator: String,
    #[serde(default)] pub amount: Option<u64>,
}

pub async fn stake_delegate(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = reqwest::Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&json!({"action":"delegate","rid":body.rid,"validator":body.validator,"amount":body.amount}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_undelegate(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = reqwest::Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&json!({"action":"undelegate","rid":body.rid,"validator":body.validator,"amount":body.amount}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_claim(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = reqwest::Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&json!({"action":"claim","rid":body.rid}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_my(Path(rid):Path<String>) -> (StatusCode, String) {
    use reqwest::Client;

    let cli = Client::new();

    // delegations
    let dtext = match cli
        .get(format!("http://127.0.0.1:8080/stake/delegations/{rid}"))
        .send().await
    {
        Ok(resp) => resp.text().await.unwrap_or_else(|_| "[]".to_string()),
        Err(_)   => "[]".to_string(),
    };

    // rewards
    let rtext = match cli
        .get(format!("http://127.0.0.1:8080/stake/rewards/{rid}"))
        .send().await
    {
        Ok(resp) => resp.text().await.unwrap_or_else(|_| "[]".to_string()),
        Err(_)   => "[]".to_string(),
    };

    let body = serde_json::json!({
        "delegations": serde_json::from_str::<serde_json::Value>(&dtext).unwrap_or(serde_json::json!([])),
        "rewards":     serde_json::from_str::<serde_json::Value>(&rtext).unwrap_or(serde_json::json!([]))
    });

    (StatusCode::OK, body.to_string())
}

/* ---------- future (не используется) ---------- */
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
//! rToken bridge: durable journal + idempotency + retry worker

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{warn,error};

use crate::{state::AppState, metrics};
use crate::bridge_journal::{Journal,OpKind,OpStatus};

#[derive(Deserialize)]
pub struct DepositReq { pub rid:String, pub amount:u64, pub ext_txid:String }   // внешний депозит → кредитуем локально
#[derive(Deserialize)]
pub struct RedeemReq  { pub rid:String, pub amount:u64, pub ext_txid:String }   // локальный вывод → дебетим и платим наружу

#[inline]
fn journal(st:&AppState)->Journal { Journal::open(st.sled()).expect("journal") }

/* -------------------- DEPOSIT (idempotent) -------------------- */
pub async fn deposit(State(st):State<Arc<AppState>>, Json(req):Json<DepositReq>) -> (StatusCode,String){
    let j = journal(&st);
    let op = match j.begin(OpKind::Deposit, &req.rid, req.amount, &req.ext_txid){
        Ok(op) => op,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"journal_begin:{e}\"}}")),
    };
    metrics::inc_bridge("deposit","begin");

    // credit in ledger (idempotent: op уже создан)
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
    drop(l);

    let _ = j.set_status(&op.op_id, OpStatus::Confirmed, None);
    metrics::inc_bridge("deposit","confirmed");
    (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id))
}

/* -------------------- REDEEM (idempotent) -------------------- */
pub async fn redeem(State(st):State<Arc<AppState>>, Json(req):Json<RedeemReq>) -> (StatusCode,String){
    let j = journal(&st);
    let op = match j.begin(OpKind::Redeem, &req.rid, req.amount, &req.ext_txid){
        Ok(op) => op,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"journal_begin:{e}\"}}")),
    };
    metrics::inc_bridge("redeem","begin");

    // debit locally (burn)
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
    drop(l);

    // TODO: вызов внешнего payout-адаптера; по успеху:
    let _ = j.set_status(&op.op_id, OpStatus::Redeemed, None);
    metrics::inc_bridge("redeem","redeemed");
    (StatusCode::OK, format!("{{\"ok\":true,\"op_id\":\"{}\"}}", op.op_id))
}

/* -------------------- RETRY worker (idempotent) -------------------- */
pub async fn retry_worker(st:Arc<AppState>){
    let j = journal(&st);
    loop {
        match j.due_retries(100){
            Ok(list) if !list.is_empty() => {
                for op_id in list {
                    match j.get_by_id(&op_id){
                        Ok(op) => {
                            warn!("bridge retry: op_id={} kind={:?} amount={}", op_id, op.kind, op.amount);
                            // На этом этапе можно повторно выполнить бизнес-операцию.
                            // Пока просто перезапланируем с backoff (демо).
                            let _ = j.set_status(&op_id, OpStatus::Pending, None);
                            let _ = j.schedule_retry(&op_id, 30_000);
                        }
                        Err(_) => { /* пропускаем */ }
                    }
                }
            }
            _ => {}
        }
        tokio::time::sleep(std::time::Duration::from_millis(3_000)).await;
    }
}

/* -------------------- Health (journal stats) -------------------- */
pub async fn health(State(st):State<Arc<AppState>>)->(StatusCode,String){
    let j = journal(&st);
    match j.stats(){
        Ok((pending,confirmed,redeemed)) =>
            (StatusCode::OK, format!("{{\"pending\":{pending},\"confirmed\":{confirmed},\"redeemed\":{redeemed}}}")),
        Err(e) =>
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{{\"error\":\"{e}\"}}")),
    }
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

### node/src/gossip.rs

~~~rust
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

~~~

### node/src/peers.rs

~~~rust
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

~~~

### node/src/storage.rs

~~~rust
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

~~~

### node/src/archive/*

### node/src/archive/mod.rs

~~~rust
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

    pub async fn record_txs_batch(&self, rows:&[(&str,u64,&str,&str,u64,u64,Option<u64>)]) -> Result<()> {
        let client = self.pool.get().await?;
        // backpressure: ограничим размер батча и выставим «глубину»
        let depth = rows.len() as i64;
        metrics::set_archive_queue(depth);
        for chunk in rows.chunks(500) {
            let stmt = "insert into txs (txid,height,from_rid,to_rid,amount,nonce,ts) values ($1,$2,$3,$4,$5,$6,to_timestamp($7)) on conflict do nothing";
            for r in chunk {
                client.execute(stmt, &[&r.0,&(r.1 as i64),&r.2,&r.3,&(r.4 as i64),&(r.5 as i64),&(r.6.unwrap_or(0) as i64)]).await?;
            }
            if chunk.len()==500 { tokio::time::sleep(std::time::Duration::from_millis(2)).await; }
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

    // ← ДОБАВЛЕНО: нужен для /archive_block (и может использоваться API)
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

### node/src/openapi/*

### node/src/openapi/openapi.json

~~~json
{
  "openapi": "3.0.3",
  "info": { "title": "LOGOS LRB API", "version": "0.1.0" },
  "paths": {
    "/healthz": { "get": { "summary": "health", "responses": { "200": { "description": "OK" } } } },
    "/version": { "get": { "summary": "build info", "responses": { "200": { "description": "OK" } } } },

    "/head": {
      "get": {
        "summary": "current head heights",
        "responses": {
          "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Head" } } } }
        }
      }
    },

    "/metrics": { "get": { "summary": "prometheus metrics", "responses": { "200": { "description": "OK" } } } },

    "/submit_tx": {
      "post": {
        "summary": "submit transaction (Ed25519 verified)",
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TxIn" } } }
        },
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
        "requestBody": {
          "required": true,
          "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitBatchReq" } } }
        },
        "responses": {
          "200": {
            "description": "per-item results",
            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/SubmitBatchItem" } } } }
          }
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
        "parameters": [
          { "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": { "200": { "description": "OK" } }
      }
    },

    "/archive/tx/{txid}": {
      "get": {
        "summary": "tx by id",
        "parameters": [
          { "name": "txid", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "OK" },
          "404": { "description": "not found" }
        }
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
        "parameters": [
          { "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": { "200": { "description": "OK" } }
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

      "TxIn": {
        "type": "object",
        "required": ["from","to","amount","nonce","sig_hex"],
        "properties": {
          "from":   { "type": "string", "description": "base58(pubkey)" },
          "to":     { "type": "string" },
          "amount": { "type": "integer", "format": "uint64" },
          "nonce":  { "type": "integer", "format": "uint64" },
          "sig_hex":{ "type": "string" },
          "memo":   { "type": "string", "nullable": true }
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
          "ok":   { "type": "boolean" },
          "txid": { "type": "string", "nullable": true },
          "info": { "type": "string" },
          "index":{ "type": "integer" }
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
      }
    }
  }
}

~~~

## modules/*

### modules/beacon_emitter.rs

~~~rust
use axum::{
    extract::State,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, time::Duration};
use tower::{ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
    timeout::TimeoutLayer,
    limit::{RequestBodyLimitLayer},
};
use tracing_subscriber::{EnvFilter, fmt};
use ed25519_dalek::{SigningKey, VerifyingKey, SignatureError};
use rand_core::OsRng;
use bs58;
use once_cell::sync::OnceCell;
use anyhow::Result;

mod api;
mod admin;
mod bridge;
mod gossip;
mod state;
mod peers;
mod fork;

#[derive(Clone)]
struct AppState {
    signing: SigningKey,
    verifying: VerifyingKey,
    rid_b58: String,
    admin_key: String,
    bridge_key: String,
}

static APP_STATE: OnceCell<AppState> = OnceCell::new();

fn load_signing_key() -> Result<SigningKey> {
    use std::env;
    if let Ok(hex) = env::var("LRB_NODE_SK_HEX") {
        let bytes = hex::decode(hex.trim())?;
        let sk = SigningKey::from_bytes(bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad SK len"))?);
        return Ok(sk);
    }
    if let Ok(path) = env::var("LRB_NODE_SK_PATH") {
        let data = std::fs::read(path)?;
        let sk = SigningKey::from_bytes(data.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad SK len"))?);
        return Ok(sk);
    }
    anyhow::bail!("missing LRB_NODE_SK_HEX or LRB_NODE_SK_PATH");
}

fn rid_from_vk(vk: &VerifyingKey) -> String {
    bs58::encode(vk.as_bytes()).into_string()
}

fn read_env_required(n: &str) -> Result<String> {
    let v = std::env::var(n).map_err(|_| anyhow::anyhow!("missing env {}", n))?;
    Ok(v)
}

fn guard_secret(name: &str, v: &str) -> Result<()> {
    let bad = ["CHANGE_ADMIN_KEY","CHANGE_ME","", "changeme", "default"];
    if bad.iter().any(|b| v.eq_ignore_ascii_case(b)) {
        anyhow::bail!("{} is default/empty; refuse to start", name);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,axum=info"));
    fmt().with_env_filter(filter).init();

    // keys + env
    let sk = load_signing_key()?;
    let vk = VerifyingKey::from(&sk);
    let rid = rid_from_vk(&vk);

    let admin_key = read_env_required("LRB_ADMIN_KEY")?;
    let bridge_key = read_env_required("LRB_BRIDGE_KEY")?;
    guard_secret("LRB_ADMIN_KEY", &admin_key)?;
    guard_secret("LRB_BRIDGE_KEY", &bridge_key)?;

    let state = AppState {
        signing: sk,
        verifying: vk,
        rid_b58: rid.clone(),
        admin_key,
        bridge_key,
    };
    APP_STATE.set(state.clone()).unwrap();

    // CORS
    let cors = {
        let allowed_origin = std::env::var("LRB_WALLET_ORIGIN").unwrap_or_else(|_| String::from("https://wallet.example"));
        CorsLayer::new()
            .allow_origin(allowed_origin.parse::<axum::http::HeaderValue>().unwrap())
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
    };

    // limits/timeout
    let layers = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(RequestBodyLimitLayer::new(512 * 1024)) // 512 KiB
        .layer(cors)
        .into_inner();

    // маршруты
    let app = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/head", get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx", post(api::submit_tx))
        .route("/submit_tx_batch", post(api::submit_tx_batch))
        .route("/debug_canon", post(api::debug_canon))
        .route("/faucet", post(api::faucet)) // dev-only
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem", post(bridge::redeem))
        .route("/bridge/verify", post(bridge::verify))
        .route("/admin/snapshot", post(admin::snapshot))
        .route("/admin/restore", post(admin::restore))
        .route("/node/info", get(admin::node_info))
        .with_state(state)
        .layer(layers);

    let addr: SocketAddr = std::env::var("LRB_NODE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    tracing::info!("logos_node listening on {} (RID={})", addr, rid);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

~~~

### modules/external_phase_broadcaster.rs

~~~rust
//! Внешний широковещатель фаз: AEAD XChaCha20-Poly1305 + Ed25519 подпись.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct PhaseBroadcaster {
    aead: AeadBox,
    self_vk: VerifyingKey,
}

impl PhaseBroadcaster {
    pub fn new(key32: [u8;32], self_vk: VerifyingKey) -> Self {
        Self { aead: AeadBox::from_key(&key32), self_vk }
    }

    pub fn pack(&self, signer: &SigningKey, topic: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(topic.len()+32);
        aad.extend_from_slice(topic);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let sealed = self.aead.seal(&aad, payload);
        let sig = signer.sign(&sealed);

        let mut out = Vec::with_capacity(64 + sealed.len());
        out.extend_from_slice(sig.as_ref());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn unpack(&self, sender_vk: &VerifyingKey, topic: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 64+24+16 { anyhow::bail!("phase_bcast: short"); }
        let (sig_bytes, sealed) = data.split_at(64);
        let sig = Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed, &sig).map_err(|_| anyhow::anyhow!("phase_bcast: bad signature"))?;

        let mut aad = Vec::with_capacity(topic.len()+32);
        aad.extend_from_slice(topic);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let pt = self.aead.open(&aad, sealed)?;
        Ok(pt)
    }
}

~~~

### modules/external_phase_link.rs

~~~rust
//! Безопасная версия external_phase_link без unsafe-кастов.
//! Состояние защищено через RwLock. Однопоточная производительность сохраняется.

use std::sync::{Arc, RwLock};
use anyhow::Result;

#[derive(Default, Clone, Debug)]
pub struct PhaseState {
    pub last_tick_ms: u64,
    pub phase_strength: f32,
}

#[derive(Clone)]
pub struct ExternalPhaseLink {
    state: Arc<RwLock<PhaseState>>,
}

impl ExternalPhaseLink {
    pub fn new() -> Self {
        Self { state: Arc::new(RwLock::new(PhaseState::default())) }
    }

    pub fn tick(&self, now_ms: u64, input_strength: f32) -> Result<()> {
        let mut st = self.state.write().expect("rwlock poisoned");
        st.last_tick_ms = now_ms;
        st.phase_strength = 0.9 * st.phase_strength + 0.1 * input_strength;
        Ok(())
    }

    pub fn snapshot(&self) -> PhaseState {
        self.state.read().expect("rwlock poisoned").clone()
    }
}

~~~

### modules/genesis_fragment_seeds.rs

~~~rust
//! Genesis Fragment Seeds: шифрованное хранение фрагментов seed.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct SeedVault { aead:AeadBox, self_vk:VerifyingKey }

impl SeedVault {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn pack_fragment(&self, signer:&SigningKey, label:&[u8], fragment:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(label.len()+32); aad.extend_from_slice(label); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, fragment); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn unpack_fragment(&self, sender_vk:&VerifyingKey, label:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("seed_vault: short"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("seed_vault: bad sig"))?;
        let mut aad=Vec::with_capacity(label.len()+32); aad.extend_from_slice(label); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}

~~~

### modules/heartbeat_monitor.rs

~~~rust
//! Heartbeat Monitor — безопасные heartbeat-кадры между узлами (AEAD+подпись).

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

#[derive(Clone)]
pub struct HeartbeatMonitor { aead:AeadBox, self_vk:VerifyingKey }

impl HeartbeatMonitor {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn encode_ping(&self, signer:&SigningKey, channel:&[u8], payload:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(channel.len()+32); aad.extend_from_slice(channel); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, payload); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn decode_frame(&self, sender_vk:&VerifyingKey, channel:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("heartbeat: short frame"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("heartbeat: bad signature"))?;
        let mut aad=Vec::with_capacity(channel.len()+32); aad.extend_from_slice(channel); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}

~~~

### modules/legacy_migrator.rs

~~~rust
//! Legacy Migrator: перенос артефактов со шифрованием и подписью.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct LegacyMigrator { aead:AeadBox, self_vk:VerifyingKey }

impl LegacyMigrator {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn wrap_blob(&self, signer:&SigningKey, kind:&[u8], blob:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(kind.len()+32); aad.extend_from_slice(kind); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, blob); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn unwrap_blob(&self, sender_vk:&VerifyingKey, kind:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("legacy_migrator: short"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("legacy_migrator: bad sig"))?;
        let mut aad=Vec::with_capacity(kind.len()+32); aad.extend_from_slice(kind); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}

~~~

### modules/ritual_engine.rs

~~~rust
//! Ritual Engine: доставка «ритуальных» сообщений c фазовой меткой, AEAD+подпись.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct RitualEngine { aead:AeadBox, self_vk:VerifyingKey }

impl RitualEngine {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn send(&self, signer:&SigningKey, phase_id:&[u8], msg:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(phase_id.len()+32); aad.extend_from_slice(phase_id); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, msg); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn recv(&self, sender_vk:&VerifyingKey, phase_id:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("ritual_engine: short"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("ritual_engine: bad sig"))?;
        let mut aad=Vec::with_capacity(phase_id.len()+32); aad.extend_from_slice(phase_id); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}

~~~

### modules/uplink_controller.rs

~~~rust
//! Uplink Controller: надёжная упаковка кадров uplink → core.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct UplinkController {
    aead: AeadBox,
    self_vk: VerifyingKey,
}

impl UplinkController {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self {
        Self { aead:AeadBox::from_key(&key32), self_vk }
    }

    pub fn encode_frame(&self, signer:&SigningKey, channel:&[u8], frame:&[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(channel.len()+32);
        aad.extend_from_slice(channel);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let sealed = self.aead.seal(&aad, frame);
        let sig = signer.sign(&sealed);

        let mut out = Vec::with_capacity(64+sealed.len());
        out.extend_from_slice(sig.as_ref());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn decode_frame(&self, sender_vk:&VerifyingKey, channel:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len() < 64+24+16 { anyhow::bail!("uplink_controller: short"); }
        let (sig_bytes, sealed) = data.split_at(64);
        let sig = Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed, &sig).map_err(|_| anyhow::anyhow!("uplink_controller: bad signature"))?;

        let mut aad = Vec::with_capacity(channel.len()+32);
        aad.extend_from_slice(channel);
        aad.extend_from_slice(self.self_vk.as_bytes());

        Ok(self.aead.open(&aad, sealed)?)
    }
}

~~~

### modules/uplink_router.rs

~~~rust
//! Uplink Router: безопасная пересылка кадров между маршрутами.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct UplinkRouter {
    aead: AeadBox,
    self_vk: VerifyingKey,
}

impl UplinkRouter {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self {
        Self { aead:AeadBox::from_key(&key32), self_vk }
    }

    pub fn wrap(&self, signer:&SigningKey, route:&[u8], payload:&[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(route.len()+32);
        aad.extend_from_slice(route);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let sealed = self.aead.seal(&aad, payload);
        let sig = signer.sign(&sealed);

        let mut out = Vec::with_capacity(64+sealed.len());
        out.extend_from_slice(sig.as_ref());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn unwrap(&self, sender_vk:&VerifyingKey, route:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len() < 64+24+16 { anyhow::bail!("uplink_router: short"); }
        let (sig_bytes, sealed) = data.split_at(64);
        let sig = Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed, &sig).map_err(|_| anyhow::anyhow!("uplink_router: bad signature"))?;

        let mut aad = Vec::with_capacity(route.len()+32);
        aad.extend_from_slice(route);
        aad.extend_from_slice(self.self_vk.as_bytes());

        Ok(self.aead.open(&aad, sealed)?)
    }
}

~~~

### modules/go_to_market.yaml

~~~yaml
yaml
version: 1.1
created: 2025-07-05
authors:
  - LOGOS Core Dev Team

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

launch_phases:
  - name: "Genesis Outreach"
    target: "Ранние сторонники, идеологические участники"
    duration_days: 14
    required_symbol: "Λ0"
    focus:
      - "Ритуальные миссии через ritual_quest.py"
      - "Формирование 81 ключевого RID"
      - "Публичное представление Λ0"
    channels:
      - "Telegram: logos_community_channel"
      - "Discord: logos_resonance_server"
      - "GitHub Issues: logos_network/repo"
    metrics:
      - "Количество валидных RID (rid_builder.py)"
      - "Реакция в resonance_feedback.py"
      - "DAO-активность (community_dao.yaml)"
    test_campaign:
      name: "simulate_genesis_outreach"
      description: "Эмуляция подключения 81 RID"

  - name: "LGN Liquidity Phase"
    target: "DEX и CEX листинг"
    duration_days: 30
    required_symbol: "any"
    focus:
      - "Запуск rLGN_converter.py"
      - "Добавление пары LGN/USDT"
      - "Обратная конвертация через DAO-гранты"
    exchanges:
      - "Uniswap: ERC-20 pair"
      - "MEXC: LGN/USDT"
      - "Gate.io: LGN/USDT"
    metrics:
      - "Объем торговли LGN"
      - "Задержки rLGN → LGN (rLGN_converter.py)"
      - "Количество DAO-кейсов (community_dao.yaml)"
    test_campaign:
      name: "simulate_liquidity_launch"
      description: "Эмуляция листинга на DEX/CEX"

  - name: "Main Resonance"
    target: "Массовый пользователь"
    duration_days: 90
    required_symbol: "any"
    focus:
      - "Образование: resonance_tutor.py"
      - "Фаза доверия: onboarding_ui.py"
      - "Публичные голосования в community_dao.yaml"
    regions:
      - name: "RU"
        languages: ["ru"]
      - name: "EU"
        languages: ["en", "de", "fr"]
      - name: "LATAM"
        languages: ["es", "pt"]
    metrics:
      - "Количество успешных входов в Σ(t) (onboarding_sim.py)"
      - "Активность в rituals (ritual_quest.py)"
      - "Обратная связь (resonance_feedback.py)"
    test_campaign:
      name: "simulate_mass_adoption"
      description: "Эмуляция 1000+ входов пользователей"

education_plan:
  modules:
    - "resonance_tutor.py"
    - "onboarding_ui.py"
    - "logos_ethics.md"
  campaigns:
    - name: "Enter the Phase"
      platform: "YouTube"
      type: "Анимированное видео"
      languages: ["en", "ru", "es"]
    - name: "RID Drop"
      platform: "Twitter"
      type: "Раздача RID с фазовыми квестами"
      languages: ["en", "ru", "es"]

integration_targets:
  wallets:
    - name: "TrustWallet"
      status: "Negotiation"
    - name: "Metamask"
      status: "Planned"
  blockchains:
    - "Ethereum (via symbolic_bridge.rs)"
    - "Polkadot"
    - "Cosmos"
  bridges:
    - "symbolic_bridge.rs"
    - "legacy_migrator.rs"

tracking:
  dashboard: "resonance_analytics_frontend"
  metrics:
    - rid_growth
    - lgn_volume
    - rlg_conversion_rate
    - dao_participation
  log_encryption:
    enabled: true
    encryption_key: "generate_at_runtime"  # AES-256

dao_support:
  proposals_enabled: true
  voting_required: true
  quorum: 0.33
  budget_lgn: 10888.0
  update_frequency_days: 14

~~~

### modules/maintenance_strategy.yaml

~~~yaml
yaml
version: 1.1
created: 2025-07-05
authors:
  - LOGOS Core Dev Team

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

update_channels:
  - name: stable
    description: "Проверенные обновления, подписанные DAO"
    auto_deploy: false
    approval_required: true
    required_symbol: "Λ0"
  - name: beta
    description: "Тестирование новых модулей и интеграций"
    auto_deploy: true
    approval_required: false
    required_symbol: "any"
  - name: dev
    description: "Экспериментальная среда для новых функций"
    auto_deploy: true
    approval_required: false
    required_symbol: "any"

rotation_policy:
  modules:
    restart_interval_sec:
      default: 86400  # 24 часа
      adaptive:
        enabled: true
        network_activity_thresholds:
          low: { value: 172800, activity: 0.5 }  # 48 часов при низкой активности
          high: { value: 43200, activity: 5.0 }  # 12 часов при высокой
    max_failure_before_isolation: 3
    isolation_mode:
      enabled: true
      trigger_modules:
        - "rcp_engine.rs"
        - "phase_scaler.rs"
        - "resonance_analyzer.py"
      test_scenarios:
        - name: "simulate_module_failure"
          description: "Эмуляция отказа 3+ модулей"

lifecycle_hooks:
  pre_restart:
    - "backup_state with phase_backup.rs"
    - "notify_admins via telegram and email"
  post_restart:
    - "verify Σ(t) with phase_integrity.rs"
    - "send heartbeat to dao_monitor via community_dao.yaml"

compatibility_matrix:
  required_versions:
    rust: ">=1.74"
    python: ">=3.10"
    cargo: ">=1.70"
    serde_json: ">=1.0.96"
    ring: ">=0.17"

auto_patch:
  enabled: true
  modules_included:
    - "resonance_feedback.py"
    - "onboarding_ui.py"
    - "symbolic_firewall.rs"
  security_only: false
  max_patches_per_day: 3

release_schedule:
  cadence: "monthly"
  last_release: "2025-06-30"
  next_scheduled: "2025-07-31"
  lgn_budget_reserved: 888.0

logs:
  directory: "logs/maintenance/"
  encrypted: true
  encryption_key: "generate_at_runtime"  # AES-256
  notify_admins:
    channels:
      - telegram: "logos_maintenance_channel"
      - email: "alerts@logos.network"
  backup_to: "phase_backup.rs"

~~~

### modules/resonance_emergency_plan.yaml

~~~yaml
yaml
version: 1.1
created: 2025-07-05
authors:
  - LOGOS Core Dev Team

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

critical_conditions:
  - id: PHASE-DROP
    name: "Резкое падение Σ(t)"
    detection_module: "phase_integrity.rs"
    response:
      - "Заморозить входящие транзакции (tx_spam_guard.rs)"
      - "Активировать phase_stabilizer.rs для восстановления Σ(t)"
      - "Рассылка сигнала Λ0 через beacon_emitter.rs"
    required_symbol: "Λ0"

  - id: BIOSPHERE-ALERT
    name: "Аномалия биосферы"
    detection_module: "biosphere_scanner.rs"
    response:
      - "Отключить усилители в resonance_math.rs"
      - "Снизить частоту вещания до 1.618 Hz"
      - "Сбор данных через resonance_feedback.py"
    required_symbol: "any"

  - id: DISSONANT-SYMBOL-ATTACK
    name: "Фазовая атака через недопустимые символы"
    detection_module: "symbolic_firewall.rs"
    response:
      - "Блокировка offending RID через tx_spam_guard.rs"
      - "Отзыв до 50% LGN через lgn_recall.rs"
      - "Фиксация в logs/emergency_dissonance.json"
    required_symbol: "Λ0"

  - id: NETWORK-OVERCLOCK
    name: "Перегрузка Σ(t) по частоте"
    detection_module: "dynamic_balance.rs"
    response:
      - "Увеличить LGN_cost вдвое в dynamic_balance.rs"
      - "Активация phase_scaler.rs для ребалансировки"
      - "Оповещение DAO через community_dao.yaml"
    required_symbol: "Λ0"

  - id: CRITICAL-CHAOS
    name: "Сбой более 70% узлов"
    detection_module: "phase_intercept_guard.rs"
    response:
      - "Переход в фазу auto_init_from_Λ0.py"
      - "Сброс Σ(t) до базового уровня (7.83 Hz)"
      - "Созыв DAO-кворума с 25% порогом"
    required_symbol: "Λ0"
    test_scenario: "simulate_70_percent_node_failure"

fallback_actions:
  if_logos_core_fails:
    - "Изоляция Λ0 ядра через genesis_fragment_seeds.rs"
    - "Включение аварийной цепочки backup_nodes.json"
    - "Восстановление через phase_backup.rs"
  if_feedback_shows_harm:
    - "Полное торможение Σ(t) в phase_stabilizer.rs"
    - "Миграция в low-resonance режим (1.618 Hz)"
    - "Обратный отчёт в DAO через resonance_feedback.py"

logs:
  directory: "logs/emergency/"
  encrypted: true
  encryption_key: "generate_at_runtime"  # AES-256
  notify_admins:
    channels:
      - telegram: "logos_emergency_channel"
      - email: "alerts@logos.network"

check_interval_sec:
  default: 60
  adaptive:
    enabled: true
    network_activity_thresholds:
      low: { value: 120, activity: 0.5 }
      high: { value: 30, activity: 5.0 }

rcp_override_allowed: false

test_scenarios:
  - name: "simulate_70_percent_node_failure"
    description: "Эмуляция сбоя 70% узлов для проверки CRITICAL-CHAOS"
    module: "phase_intercept_guard.rs"
  - name: "simulate_biosphere_anomaly"
    description: "Эмуляция аномалии биосферы для BIOSPHERE-ALERT"
    module: "biosphere_scanner.rs"

~~~

### modules/resonance_meshmap.yaml

~~~yaml
yaml
version: 1.1
generated: 2025-07-05
source: "phase_scaler.rs"

valid_symbols: ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]

symbol_map:
  Λ0:
    color: "#FFD700"
    role: "Core synchronizer"
  ☉:
    color: "#FFA500"
    role: "Harmonizer"
  ??:
    color: "#FF4500"
    role: "Initiator"
  ♁:
    color: "#33CC33"
    role: "Stabilizer"
  ??:
    color: "#3399FF"
    role: "Flux"
  ??:
    color: "#996633"
    role: "Grounding"
  ??:
    color: "#AAAAAA"
    role: "Air flow"
  ∞:
    color: "#CCCCCC"
    role: "Infinity"

clusters:
  CLUSTER_7.830:
    label: "Schumann Core"
    max_nodes: 144
    active_nodes:
      - rid: "Λ0@7.83Hzφ0.000"
        joined: 2025-07-05T10:00:00Z
      - rid: "☉@7.83Hzφ0.4142"
        joined: 2025-07-05T10:01:03Z
    center_phase: 0.2
    symbol_dominance: "Λ0"
    overload_action: "Activate phase_scaler.rs rebalance"

  CLUSTER_432.000:
    label: "Harmonic Field"
    max_nodes: 288
    active_nodes:
      - rid: "??@432Hzφ-0.618"
        joined: 2025-07-05T10:02:44Z
      - rid: "♁@432Hzφ0.309"
        joined: 2025-07-05T10:04:12Z
    center_phase: -0.14
    symbol_dominance: "??"
    overload_action: "Activate phase_scaler.rs rebalance"

  CLUSTER_1.618:
    label: "Golden Mesh"
    max_nodes: 81
    active_nodes:
      - rid: "??@1.618Hzφ0.707"
        joined: 2025-07-05T10:08:00Z
    center_phase: 0.6
    symbol_dominance: "??"
    overload_action: "Activate phase_scaler.rs rebalance"

summary:
  total_clusters: 3
  total_active_rids: 5
  symbol_distribution:
    Λ0: 1
    ☉: 1
    ??: 1
    ♁: 1
    ??: 1

log_config:
  file: "resonance_meshmap_log.json"
  encrypted: true
  encryption_key: "generate_at_runtime"  # AES-256

update_config:
  enabled: true
  update_interval_sec: 300  # Каждые 5 минут
  modules:
    - "phase_scaler.rs"
    - "resonance_analyzer.py"

~~~

### modules/env_impact_tracker.py

~~~
# LOGOS Environmental Impact Tracker
# Автор: LOGOS Core Dev

import time
import json
import os
import psutil
from cryptography.fernet import Fernet
from typing import Dict
from resonance_analyzer import ResonanceAnalyzer

class EnvImpactTracker:
    def __init__(self):
        self.state_file = "env_impact_state.json"
        self.log_file = "env_impact_log.json"
        self.cipher = Fernet(Fernet.generate_key())
        self.lambda_zero = "Λ0"
        self.valid_symbols = ["☉", "??", "♁", "??", "??", "??", "Λ0", "∞"]
        self.collected: Dict[str, float] = {}
        self.interval_sec = 60
        self.last_record_time = 0
        self.network_activity = 1.0
        self.analyzer = ResonanceAnalyzer()
        self.thresholds = {"cpu": 80.0, "memory": 80.0, "disk": 90.0}
        self.load_state()

    def load_state(self):
        """Загружает состояние с расшифровкой."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "rb") as f:
                    data = self.cipher.decrypt(f.read())
                    self.collected = json.loads(data)
            except Exception as e:
                self.log_event(f"[!] Ошибка загрузки состояния: {e}")
                self.collected = {}

    def validate_symbol(self, symbol: str) -> bool:
        """Проверяет допустимость символа."""
        return symbol in self.valid_symbols

    def update_network_activity(self, activity: float):
        """Обновляет интервал сканирования на основе активности."""
        self.network_activity = max(0.1, min(activity, 10.0))
        self.interval_sec = max(30, min(120, 60 / self.network_activity))
        self.log_event(f"[INFO] Network activity updated: {self.network_activity}, interval={self.interval_sec}s")

    def scan(self, symbol: str = "Λ0") -> bool:
        """Собирает метрики воздействия."""
        now = time.time()
        if now - self.last_record_time < self.interval_sec:
            self.log_event("[!] Слишком частое сканирование")
            return False
        self.last_record_time = now

        if not self.validate_symbol(symbol):
            self.log_event(f"[!] Недопустимый символ: {symbol}")
            return False

        # Сбор метрик
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        net = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        temp = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}

        # Адаптивная коррекция для Λ0
        adjustment = 1.2 if symbol == self.lambda_zero else 1.0

        impact = {
            "timestamp": now,
            "symbol": symbol,
            "cpu": round(cpu * adjustment, 2),
            "memory": round(mem * adjustment, 2),
            "disk": round(disk * adjustment, 2),
            "network_bytes": net,
            "thermal_zones": {k: [round(t.current, 2) for t in v] for k, v in temp.items()} if temp else {}
        }

        # Проверка аномалий
        anomalies = []
        if impact["cpu"] > self.thresholds["cpu"]:
            anomalies.append(f"CPU={impact['cpu']}%")
        if impact["memory"] > self.thresholds["memory"]:
            anomalies.append(f"MEM={impact['memory']}%")
        if impact["disk"] > self.thresholds["disk"]:
            anomalies.append(f"DISK={impact['disk']}%")

        # Интеграция с resonance_analyzer
        resonance = self.analyzer.analyze(symbol, 7.83 if symbol == self.lambda_zero else 1.618, 0.0)
        impact["resonance_score"] = resonance["resonance"]

        self.collected[str(int(now))] = impact
        self.save_state()

        log_message = f"Impact: CPU={impact['cpu']}%, MEM={impact['memory']}%, Symbol={symbol}, Resonance={resonance['resonance']:.4f}"
        if anomalies:
            log_message += f", Anomalies: {', '.join(anomalies)}"
        self.log_event(log_message)
        return True

    def save_state(self):
        """Сохраняет состояние с шифрованием."""
        data = json.dumps(self.collected, indent=2).encode()
        encrypted = self.cipher.encrypt(data)
        with open(self.state_file, "wb") as f:
            f.write(encrypted)

    def log_event(self, message: str):
        """Логирует событие."""
        log = {
            "event": "env_impact",
            "message": message,
            "timestamp": time.time()
        }
        encrypted = self.cipher.encrypt(json.dumps(log).encode() + b"\n")
        with open(self.log_file, "ab") as f:
            f.write(encrypted)

    def get_latest_impact(self) -> Dict:
        """Возвращает последнюю запись."""
        if self.collected:
            return list(self.collected.values())[-1]
        return {}

if __name__ == "__main__":
    tracker = EnvImpactTracker()
    tracker.update_network_activity(2.0)
    if tracker.scan(symbol="Λ0"):
        print("Последнее воздействие:", json.dumps(tracker.get_latest_impact(), indent=2))
    else:
        print("Ожидание интервала между сканами...")

~~~

### modules/resonance_tutor.py

~~~
# LOGOS Resonance Tutor
# Автор: LOGOS Core Dev

import time
import random
import json
import os
from typing import Dict
from cryptography.fernet import Fernet

class ResonanceTutor:
    def __init__(self):
        self.valid_symbols = {
            "☉": "Гармонизатор (Солнце) — баланс и инициатива.",
            "??": "Огонь — активное действие и импульс.",
            "♁": "Материя — плотность, привязка к реальности.",
            "??": "Вода — текучесть, перемены.",
            "??": "Земля — устойчивость и форма.",
            "??": "Воздух — связь и движение.",
            "Λ0": "Центральный символ. Начало всего. Не принадлежит никому.",
            "∞": "Бесконечность. Переход к высшим фазам."
        }
        self.freqs = [7.83, 1.618, 432.0, 864.0]
        self.log_file = "resonance_tutor_log.json"
        self.cipher = Fernet(Fernet.generate_key())
        self.progress = []
        self.run()

    def run(self):
        print("?? Добро пожаловать в обучающую систему LOGOS Resonance Tutor")
        self.log_event("Начало обучения")
        self.pause("Нажмите Enter, чтобы начать...")

        self.explain_symbols()
        self.explain_frequencies()
        self.explain_phase()
        self.explain_rid()
        self.explain_sigma()
        self.run_mini_test()
        self.final_message()

    def explain_symbols(self):
        print("\n?? Символы в LOGOS — это не просто знаки.")
        print("Они — архетипы. Смысловые структуры.")
        for s, desc in self.valid_symbols.items():
            print(f"  {s}: {desc}")
        self.progress.append({"step": "symbols", "completed": True})
        self.log_event("Объяснены символы")
        self.pause("→ Продолжить")

    def explain_frequencies(self):
        print("\n?? Частоты используются в LOGOS вместо хэшей.")
        print("Каждое действие связано с гармоникой:")
        for f in self.freqs:
            label = {
                7.83: "Шуман-резонанс Земли",
                1.618: "Золотое сечение",
                432.0: "Музыкальная гармония",
                864.0: "Частота Солнца"
            }.get(f, "Неизвестно")
            print(f"  {f} Hz — {label}")
        self.progress.append({"step": "frequencies", "completed": True})
        self.log_event("Объяснены частоты")
        self.pause("→ Дальше")

    def explain_phase(self):
        print("\n?? Фаза (φ) — положение во времени.")
        print("Фаза измеряется в радианах от -π до +π.")
        print("Она влияет на то, как ваш RID взаимодействует с Σ(t).")
        self.progress.append({"step": "phase", "completed": True})
        self.log_event("Объяснена фаза")
        self.pause("→ Понял")

    def explain_rid(self):
        symbol = random.choice(list(self.valid_symbols.keys()))
        freq = random.choice(self.freqs)
        phase = round(random.uniform(-3.14, 3.14), 4)
        rid = f"{symbol}@{freq}Hzφ{phase}"
        print("\n?? Ваш резонансный идентификатор (RID) — это:")
        print(f"  {rid}")
        print("RID — это адрес в сети LOGOS, основанный на смысле.")
        self.progress.append({"step": "rid", "completed": True})
        self.log_event(f"Объяснён RID: {rid}")
        self.pause("→ Дальше")

    def explain_sigma(self):
        print("\nΣ(t) — это суммарный резонанс сети.")
        print("Он вычисляется как гармоническая сумма частот и фаз всех RID.")
        print("Ваш вклад в Σ(t) — это ваш резонанс.")
        self.progress.append({"step": "sigma", "completed": True})
        self.log_event("Объяснён Σ(t)")
        self.pause("→ Продолжить")

    def run_mini_test(self):
        print("\n?? Мини-тест: выберите правильную частоту для Λ0")
        options = [7.83, 100.0, 0.0, 5000.0]
        correct = 7.83
        random.shuffle(options)
        for i, opt in enumerate(options, 1):
            print(f"{i}. {opt} Hz")
        choice = int(input("Ваш выбор (1-4): "))
        selected = options[choice - 1]
        if selected == correct:
            print("✅ Правильно! 7.83 Hz — Шуман-резонанс.")
            self.progress.append({"step": "mini_test", "result": "success"})
            self.log_event("Мини-тест пройден успешно")
        else:
            print(f"❌ Неверно. Правильный ответ: 7.83 Hz (Шуман-резонанс).")
            self.progress.append({"step": "mini_test", "result": "failed"})
            self.log_event(f"Мини-тест провален: выбрано {selected} Hz")
        self.pause("→ Завершить")

    def final_message(self):
        print("\n✅ Вы завершили вводный курс.")
        print("Теперь вы можете войти в резонанс через onboarding_sim.py или onboarding_ui.py.")
        print("?? Увидимся в Σ(t).")
        self.log_event("Обучение завершено")
        print("Для практики запустите: python onboarding_sim.py")

    def log_event(self, message: str):
        """Логирует событие в файл."""
        log_entry = {
            "event": "resonance_tutor",
            "message": message,
            "timestamp": time.time()
        }
        encrypted = self.cipher.encrypt(json.dumps(log_entry).encode() + b"\n")
        with open(self.log_file, "ab") as f:
            f.write(encrypted)

    def pause(self, prompt: str):
        input(f"\n{prompt}")

if __name__ == "__main__":
    ResonanceTutor()

~~~

### modules/symbolic_parser.py

~~~
# LOGOS Symbolic Parser
# Автор: LOGOS Core Dev

import re
import math
from typing import List, Dict, Optional
from cryptography.fernet import Fernet
import json
import time

class SymbolicParser:
    def __init__(self):
        self.valid_symbols = ["Λ0", "☉", "??", "♁", "??", "??", "??", "∞"]
        self.lambda_zero = "Λ0"
        self.pattern = re.compile(r"(?P<symbol>[☉??♁??????Λ0∞])@(?P<freq>[0-9\.]+)Hzφ(?P<phase>[-0-9\.]+)")
        self.log_file = "symbolic_parser_log.json"
        self.cipher = Fernet(Fernet.generate_key())
        self.rid_cache: Dict[str, Dict] = {}  # Кэш для RID

    def extract_rids(self, text: str) -> List[str]:
        """Находит все валидные RID в тексте."""
        matches = self.pattern.findall(text)
        rids = [f"{m[0]}@{m[1]}Hzφ{m[2]}" for m in matches if m[0] in self.valid_symbols]
        self.log_event(f"[EXTRACT] Найдено {len(rids)} RID: {rids}")
        return rids

    def parse_rid(self, rid: str) -> Optional[Dict]:
        """Парсит одиночный RID в структуру."""
        # Проверка кэша
        if rid in self.rid_cache:
            self.log_event(f"[CACHE] RID {rid} из кэша")
            return self.rid_cache[rid]

        try:
            match = self.pattern.match(rid)
            if not match:
                self.log_event(f"[!] Неверный формат RID: {rid}")
                return None

            symbol = match.group("symbol")
            if symbol not in self.valid_symbols:
                self.log_event(f"[!] Недопустимый символ: {symbol}")
                return None

            freq = float(match.group("freq"))
            phase = float(match.group("phase"))

            # Проверка диапазонов
            if not (0.1 <= freq <= 10000.0):
                self.log_event(f"[!] Недопустимая частота: {freq}")
                return None
            if not (-math.pi <= phase <= math.pi):
                self.log_event(f"[!] Недопустимая фаза: {phase}")
                return None

            # Проверка через RCP (заглушка)
            if not self.validate_with_rcp(symbol, freq, phase):
                self.log_event(f"[!] RCP не подтвердил RID: {rid}")
                return None

            result = {
                "symbol": symbol,
                "frequency": freq,
                "phase": phase,
                "is_lambda_zero": symbol == self.lambda_zero
            }
            self.rid_cache[rid] = result
            self.log_event(f"[PARSE] Успешно разобран RID: {rid}")
            return result
        except Exception as e:
            self.log_event(f"[!] Ошибка разбора RID: {e}")
            return None

    def extract_symbols(self, text: str) -> List[str]:
        """Извлекает все допустимые символы в тексте."""
        symbols = [s for s in text if s in self.valid_symbols]
        if self.lambda_zero in symbols:
            symbols.insert(0, symbols.pop(symbols.index(self.lambda_zero)))  # Приоритет Λ0
        self.log_event(f"[EXTRACT] Найдено {len(symbols)} символов: {symbols}")
        return symbols

    def validate_rid_format(self, rid: str) -> bool:
        """Проверяет соответствие RID формату."""
        result = bool(self.parse_rid(rid))
        self.log_event(f"[VALIDATE] RID {rid} {'валиден' if result else 'невалиден'}")
        return result

    def validate_with_rcp(self, symbol: str, freq: float, phase: float) -> bool:
        """Заглушка для проверки через rcp_engine.rs."""
        return symbol == self.lambda_zero or (abs(freq - 7.83) < 0.1 and abs(phase) < 0.05)

    def log_event(self, message: str):
        """Логирует событие с шифрованием."""
        entry = {
            "event": "symbolic_parser",
            "message": message,
            "timestamp": time.time()
        }
        encrypted = self.cipher.encrypt(json.dumps(entry).encode() + b"\n")
        with open(self.log_file, "ab") as f:
            f.write(encrypted)

if __name__ == "__main__":
    parser = SymbolicParser()
    test = "Пример: ☉@432.0Hzφ0.618, Λ0@7.83Hzφ0.0 и ♁@1.618Hzφ-0.314"
    rids = parser.extract_rids(test)
    print("Найденные RID:", rids)
    for r in rids:
        parsed = parser.parse_rid(r)
        print("Разбор:", parsed)

~~~

## www/wallet (static)

### www/wallet/app.html

~~~html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>LOGOS Wallet — Кошелёк</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b0c10;color:#e6edf3}
    header{padding:16px 20px;background:#11151a;border-bottom:1px solid #1e242c;position:sticky;top:0}
    h1{font-size:18px;margin:0}
    main{max-width:1024px;margin:24px auto;padding:0 16px}
    section{background:#11151a;margin:16px 0;border-radius:12px;padding:16px;border:1px solid #1e242c}
    label{display:block;margin:8px 0 6px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    @media (max-width:900px){.grid{grid-template-columns:1fr}}
    input,button,textarea{width:100%;padding:10px;border-radius:10px;border:1px solid #2a313a;background:#0b0f14;color:#e6edf3}
    button{cursor:pointer;border:1px solid #3b7ddd;background:#1665c1}
    button.secondary{background:#1b2129}
    .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
    small{opacity:.8}
  </style>
</head>
<body>
<header>
  <h1>LOGOS Wallet — Кошелёк</h1>
</header>
<main>
  <section>
    <div class="grid">
      <div>
        <h3>Твой RID / Публичный ключ</h3>
        <textarea id="pub" class="mono" rows="4" readonly></textarea>
        <div style="display:flex;gap:10px;margin-top:10px">
          <button id="btn-lock" class="secondary">Выйти (заблокировать)</button>
          <button id="btn-nonce" class="secondary">Получить nonce</button>
        </div>
        <p><small>Ключ в памяти. Закроешь вкладку — понадобится пароль на странице входа.</small></p>
      </div>
      <div>
        <h3>Баланс</h3>
        <div class="grid">
          <div><label>RID</label><input id="rid-balance" class="mono" placeholder="RID (base58)"/></div>
          <div><label>&nbsp;</label><button id="btn-balance">Показать баланс</button></div>
        </div>
        <pre id="out-balance" class="mono" style="margin-top:12px"></pre>
      </div>
    </div>
  </section>

  <section>
    <h3>Подпись и отправка (batch)</h3>
    <div class="grid">
      <div><label>Получатель (RID)</label><input id="to" class="mono" placeholder="RID получателя"/></div>
      <div><label>Сумма (LGN)</label><input id="amount" type="number" min="1" step="1" value="1"/></div>
    </div>
    <div class="grid">
      <div><label>Nonce</label><input id="nonce" type="number" min="1" step="1" placeholder="нажми 'Получить nonce'"/></div>
      <div><label>&nbsp;</label><button id="btn-send">Подписать и отправить</button></div>
    </div>
    <pre id="out-send" class="mono" style="margin-top:12px"></pre>
  </section>

  <section>
    <h3>Мост rToken (депозит, демо)</h3>
    <div class="grid">
      <div><label>ext_txid</label><input id="ext" class="mono" placeholder="например eth_txid_0xabc"/></div>
      <div><label>&nbsp;</label><button id="btn-deposit">Deposit rLGN</button></div>
    </div>
    <pre id="out-bridge" class="mono" style="margin-top:12px"></pre>
  </section>
</main>
<script src="./app.js?v=20250906_01" defer></script>
</body>
</html>

~~~

### www/wallet/index.html

~~~html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <!-- Жёсткое отключение кэша на уровне страницы -->
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate"/>
  <meta http-equiv="Pragma" content="no-cache"/>
  <meta http-equiv="Expires" content="0"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'">
  <title>LOGOS Wallet</title>
  <style>
    body{font-family:system-ui,Roboto,Arial,sans-serif;background:#0b0e11;color:#e6e6e6;margin:0}
    header{padding:12px 20px;background:#12161a;border-bottom:1px solid #1b2026}
    main{padding:20px}
    h3{margin:0;font-size:18px}
    section{margin-bottom:20px}
    input,button{padding:8px 10px;border-radius:6px;border:none;font-size:14px}
    button{background:#2d6cdf;color:white;cursor:pointer;margin:4px 2px}
    button:hover{background:#1b4fb5}
    .out{margin-top:10px;font-family:monospace;font-size:13px;white-space:pre-wrap}
  </style>
  <script>
    // Кардинально: на входе очищаем SW и Cache API,
    // чтобы ни одна старая версия не мешала.
    (async ()=>{
      try{
        if ('serviceWorker' in navigator) {
          const regs = await navigator.serviceWorker.getRegistrations();
          for (const r of regs) { try { await r.unregister(); } catch{} }
        }
        if (window.caches) {
          const keys = await caches.keys();
          for (const k of keys) { try { await caches.delete(k); } catch{} }
        }
        // Стираем старые версии из localStorage/sessionStorage, кроме наших полей
        const keep = new Set(['logos_pass','logos_rid']);
        for (const k of Object.keys(localStorage)) if (!keep.has(k)) localStorage.removeItem(k);
        for (const k of Object.keys(sessionStorage)) if (!keep.has(k)) sessionStorage.removeItem(k);
      }catch(e){}
    })();
  </script>
</head>
<body>
  <header>
    <h3>LOGOS Wallet</h3>
    <div id="node-info" class="muted">node: <span id="node-url"></span> | head: <span id="head"></span></div>
  </header>
  <main>
    <section>
      <h4>Настройки</h4>
      <div>RID: <span id="rid"></span></div>
      <div>Баланс: <span id="balance"></span> | Nonce: <span id="nonce-show"></span></div>
      <input id="rid-balance" placeholder="RID для проверки"/>
      <button id="btn-balance">Баланс</button>
      <div id="out-balance" class="out"></div>
    </section>

    <section>
      <h4>Отправка</h4>
      <input id="to" placeholder="RID получателя"/>
      <input id="amount" type="number" placeholder="Сумма (микро-LGN)"/>
      <input id="nonce" type="number" placeholder="Nonce"/>
      <button id="btn-nonce">NONCE</button>
      <button id="btn-send">Отправить</button>
      <div id="out-send" class="out"></div>
    </section>

    <section>
      <h4>Стейкинг</h4>
      <input id="validator" placeholder="RID валидатора"/>
      <input id="stake-amount" type="number" placeholder="Сумма (микро-LGN)"/>
      <button id="btn-delegate">Delegate</button>
      <button id="btn-undelegate">Undelegate</button>
      <button id="btn-claim">Claim</button>
      <button id="btn-my">Мои делегации</button>
      <div id="out-stake" class="out"></div>
      <div id="out-my" class="out"></div>
    </section>
  </main>

  <!-- новый js с версией (cache-buster) -->
  <script src="app.v3.js?v=3"></script>
  <script>
    document.getElementById('node-url').textContent = location.origin;
    async function updHead(){
      try{
        const r=await fetch(location.origin+'/api/head');
        const j=await r.json();
        document.getElementById('head').textContent=j.height;
        const rid=sessionStorage.getItem('logos_rid');
        if(rid){
          const br=await fetch(location.origin+'/api/balance/'+encodeURIComponent(rid));
          const bj=await br.json();
          document.getElementById('rid').textContent = rid;
          document.getElementById('balance').textContent = bj.balance;
          document.getElementById('nonce-show').textContent = bj.nonce;
        }
      }catch(e){}
    }
    setInterval(updHead,1500); updHead();
  </script>
</body>
</html>

~~~

### www/wallet/login.html

~~~html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>LOGOS Wallet — Вход</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b0c10;color:#e6edf3}
    header{padding:16px 20px;background:#11151a;border-bottom:1px solid #1e242c}
    h1{font-size:18px;margin:0}
    main{max-width:720px;margin:48px auto;padding:0 16px}
    section{background:#11151a;margin:16px 0;border-radius:12px;padding:16px;border:1px solid #1e242c}
    label{display:block;margin:8px 0 6px}
    input,button{width:100%;padding:12px;border-radius:10px;border:1px solid #2a313a;background:#0b0f14;color:#e6edf3}
    button{cursor:pointer;border:1px solid #3b7ddd;background:#1665c1}
    button.secondary{background:#1b2129}
    small{opacity:.8}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    @media (max-width:720px){.grid{grid-template-columns:1fr}}
    .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
    ul{list-style:none;padding:0;margin:8px 0}
    li{padding:8px;border:1px solid #2a313a;border-radius:8px;margin-bottom:6px;cursor:pointer;background:#0b0f14}
  </style>
</head>
<body>
<header><h1>LOGOS Wallet — Secure (WebCrypto + IndexedDB)</h1></header>
<main>
  <section>
    <h3>Вход в аккаунт</h3>
    <label>Логин (RID)</label>
    <input id="loginRid" class="mono" placeholder="Вставь RID (base58) или выбери из списка ниже"/>
    <label>Пароль</label>
    <input id="pass" type="password" placeholder="Пароль для шифрования ключа"/>

    <div class="grid" style="margin-top:12px">
      <button id="btn-login">Войти по RID + пароль</button>
      <button id="btn-create">Создать новый RID</button>
    </div>

    <div style="margin-top:12px">
      <button id="btn-list" class="secondary">Показать сохранённые RID</button>
      <button id="btn-reset" class="secondary">Сбросить все аккаунты (DEV)</button>
    </div>

    <div id="listWrap" style="display:none;margin-top:10px">
      <small>Сохранённые на этом устройстве RID (тапни, чтобы подставить):</small>
      <ul id="ridList"></ul>
    </div>

    <p><small>Ключ Ed25519 хранится зашифрованным AES-GCM (PBKDF2) в IndexedDB. Ничего не уходит в сеть.</small></p>
    <pre id="out" class="mono"></pre>
  </section>
</main>
<script src="./auth.js?v=20250906_03" defer></script>
</body>
</html>

~~~

### www/wallet/app.js

~~~javascript
// === БАЗА ===
const API = location.origin + '/api/';     // ГАРАНТИРОВАННЫЙ префикс
const enc = new TextEncoder();

const $ = s => document.querySelector(s);
const toHex   = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex = h => new Uint8Array((h.match(/.{1,2}/g)||[]).map(x=>parseInt(x,16)));

function u64le(n){ const b=new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; }
async function sha256(bytes){ const d=await crypto.subtle.digest('SHA-256', bytes); return new Uint8Array(d); }

// === НАДЁЖНЫЙ fetchJSON: ВСЕГДА JSON (даже при ошибке) ===
async function fetchJSON(url, opts) {
  const r = await fetch(url, opts);
  const text = await r.text();
  try {
    const json = text ? JSON.parse(text) : {};
    if (!r.ok) throw json;
    return json;
  } catch(e) {
    // если прилетел текст/HTML — упакуем в JSON с сообщением
    throw { ok:false, error: (typeof e==='object' && e.error) ? e.error : (text || 'not json') };
  }
}

// === КЛЮЧИ/SESSION ===
const PASS = sessionStorage.getItem('logos_pass');
const RID  = sessionStorage.getItem('logos_rid');
if (!PASS || !RID) { location.replace('./login.html'); throw new Error('locked'); }

const DB_NAME='logos_wallet_v2', STORE='keys';
function idb(){ return new Promise((res,rej)=>{ const r=indexedDB.open(DB_NAME,1); r.onupgradeneeded=()=>r.result.createObjectStore(STORE); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
async function idbGet(k){ const db=await idb(); return new Promise((res,rej)=>{ const tx=db.transaction(STORE,'readonly'); const st=tx.objectStore(STORE); const rq=st.get(k); rq.onsuccess=()=>res(rq.result||null); rq.onerror=()=>rej(rq.error); }); }
async function deriveKey(pass,salt){ const km=await crypto.subtle.importKey('raw', enc.encode(pass), {name:'PBKDF2'}, false, ['deriveKey']); return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:120000}, km, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']); }
async function aesDecrypt(aesKey,iv,ct){ return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv}, aesKey, ct)); }
async function importKey(pass, meta){
  const aesKey = await deriveKey(pass, new Uint8Array(meta.salt));
  const pkcs8  = await aesDecrypt(aesKey, new Uint8Array(meta.iv_priv), new Uint8Array(meta.priv));
  const pubraw = await aesDecrypt(aesKey, new Uint8Array(meta.iv_pub),  new Uint8Array(meta.pub));
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, {name:'Ed25519'}, false, ['sign']);
  const publicKey  = await crypto.subtle.importKey('raw',   pubraw, {name:'Ed25519'}, true,  ['verify']);
  return { privateKey, publicKey, pub_hex: toHex(pubraw) };
}

let KEYS=null, META=null;
(async ()=>{
  META = await idbGet('acct:'+RID);
  if (!META) { sessionStorage.clear(); location.replace('./login.html'); return; }
  KEYS = await importKey(PASS, META);
  $('#pub') && ($('#pub').value = `RID: ${RID}\npub: ${KEYS.pub_hex}`);
  $('#rid-balance') && ($('#rid-balance').value = RID);
})();

// === КАНОНИКА/ПОДПИСЬ ===
async function canonHex(from_rid,to_rid,amount,nonce,pubkey_hex){
  const parts=[enc.encode(from_rid),enc.encode(to_rid),u64le(Number(amount)),u64le(Number(nonce)),enc.encode(pubkey_hex)];
  const buf=new Uint8Array(parts.reduce((s,p)=>s+p.length,0)); let o=0; for(const p of parts){ buf.set(p,o); o+=p.length; }
  return toHex(await sha256(buf));
}
async function signCanon(privateKey, canonHexStr){
  const msg = fromHex(canonHexStr);
  const sig = await crypto.subtle.sign('Ed25519', privateKey, msg);
  return toHex(sig);
}

// === API HELPERS ===
async function getBalance(rid){ return fetchJSON(`${API}balance/${encodeURIComponent(rid)}`); }
async function submitTxBatch(txs){
  return fetchJSON(`${API}submit_tx_batch`, {
    method:'POST', headers:{'content-type':'application/json'},
    body: JSON.stringify({ txs })
  });
}
async function stakeDelegate(delegator, validator, amount){
  return fetchJSON(`${API}stake/delegate`, {
    method:'POST', headers:{'content-type':'application/json'},
    body: JSON.stringify({ delegator, validator, amount:Number(amount) })
  });
}
async function stakeUndelegate(delegator, validator, amount){
  return fetchJSON(`${API}stake/undelegate`, {
    method:'POST', headers:{'content-type':'application/json'},
    body: JSON.stringify({ delegator, validator, amount:Number(amount) })
  });
}
async function stakeClaim(delegator, validator){
  return fetchJSON(`${API}stake/claim`, {
    method:'POST', headers:{'content-type':'application/json'},
    body: JSON.stringify({ delegator, validator, amount:0 })
  });
}
async function stakeMy(rid){ return fetchJSON(`${API}stake/my/${encodeURIComponent(rid)}`); }

// === UI ===
$('#btn-balance')?.addEventListener('click', async ()=>{
  try{ const rid = ($('#rid-balance')?.value || RID).trim(); const j=await getBalance(rid); $('#out-balance') && ($('#out-balance').textContent=JSON.stringify(j)); }
  catch(e){ alert(`ERR: ${JSON.stringify(e)}`); }
});

$('#btn-send')?.addEventListener('click', async ()=>{
  try{
    const to     = $('#to')?.value.trim();
    const amount = $('#amount')?.value.trim();
    const nonce  = $('#nonce')?.value.trim();
    if (!to || !amount || !nonce) throw {error:'fill to/amount/nonce'};
    const ch = await canonHex(RID, to, amount, nonce, KEYS.pub_hex);
    const sigHex = await signCanon(KEYS.privateKey, ch);
    const tx = { from_rid:RID, to_rid:to, amount:Number(amount), nonce:Number(nonce), pubkey_hex:KEYS.pub_hex, sig_hex:sigHex };
    const res = await submitTxBatch([tx]);
    $('#out-send') && ($('#out-send').textContent = JSON.stringify(res,null,2));
  }catch(e){ $('#out-send') && ($('#out-send').textContent = `ERR: ${JSON.stringify(e)}`); }
});

$('#btn-delegate')?.addEventListener('click', async ()=>{
  try{
    const val = ($('#validator')?.value || RID).trim();
    const amount = ($('#stake-amount')?.value || '').trim() || ($('#amount')?.value || '').trim();
    const res = await stakeDelegate(RID, val, amount);
    $('#out-stake') && ($('#out-stake').textContent = JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent = `ERR: ${JSON.stringify(e)}`); }
});
$('#btn-undelegate')?.addEventListener('click', async ()=>{
  try{
    const val = ($('#validator')?.value || RID).trim();
    const amount = ($('#stake-amount')?.value || '').trim() || ($('#amount')?.value || '').trim();
    const res = await stakeUndelegate(RID, val, amount);
    $('#out-stake') && ($('#out-stake').textContent = JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent = `ERR: ${JSON.stringify(e)}`); }
});
$('#btn-claim')?.addEventListener('click', async ()=>{
  try{
    const val = ($('#validator')?.value || RID).trim();
    const res = await stakeClaim(RID, val);
    $('#out-stake') && ($('#out-stake').textContent = JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent = `ERR: ${JSON.stringify(e)}`); }
});
$('#btn-my')?.addEventListener('click', async ()=>{
  try{
    const res = await stakeMy(RID);
    $('#out-my') && ($('#out-my').textContent = JSON.stringify(res));
  }catch(e){ $('#out-my') && ($('#out-my').textContent = `ERR: ${JSON.stringify(e)}`); }
});

// кнопка NONCE (если есть)
$('#btn-nonce')?.addEventListener('click', async ()=>{
  try{ const j=await getBalance(RID); $('#nonce') && ($('#nonce').value = String(j.nonce||0)); }
  catch(e){ alert(`ERR: ${JSON.stringify(e)}`); }
});

~~~

### www/wallet/app.v2.js

~~~javascript
// == CONFIG ==
const API = location.origin + '/api/';
const enc = new TextEncoder();

// == utils ==
const $ = s => document.querySelector(s);
const toHex   = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex = h => new Uint8Array((h.match(/.{1,2}/g)||[]).map(x=>parseInt(x,16)));
function u64le(n){ const b=new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; }
async function sha256(bytes){ const d=await crypto.subtle.digest('SHA-256', bytes); return new Uint8Array(d); }

// == robust fetch: always JSON ==
async function fetchJSON(url, opts){
  try{
    const r = await fetch(url, opts);
    const text = await r.text();
    try {
      const js = text ? JSON.parse(text) : {};
      if(!r.ok) throw js;
      return js;
    } catch(parseErr){
      throw { ok:false, error:(text||'not json'), status:r.status||0 };
    }
  }catch(netErr){
    throw { ok:false, error:(netErr?.message||'network error') };
  }
}

// == session/keys ==
const PASS = sessionStorage.getItem('logos_pass');
const RID  = sessionStorage.getItem('logos_rid');
if (!PASS || !RID) { location.replace('./login.html'); throw new Error('locked'); }

const DB_NAME='logos_wallet_v2', STORE='keys';
function idb(){ return new Promise((res,rej)=>{ const r=indexedDB.open(DB_NAME,1); r.onupgradeneeded=()=>r.result.createObjectStore(STORE); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
async function idbGet(k){ const db=await idb(); return new Promise((res,rej)=>{ const tx=db.transaction(STORE,'readonly'); const st=tx.objectStore(STORE); const rq=st.get(k); rq.onsuccess=()=>res(rq.result||null); rq.onerror=()=>rej(rq.error); }); }
async function deriveKey(pass,salt){ const km=await crypto.subtle.importKey('raw', enc.encode(pass), {name:'PBKDF2'}, false, ['deriveKey']); return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:120000}, km, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']); }
async function aesDecrypt(aesKey,iv,ct){ return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv}, aesKey, ct)); }
async function importKey(pass, meta){
  const aesKey=await deriveKey(pass,new Uint8Array(meta.salt));
  const pkcs8 =await aesDecrypt(aesKey,new Uint8Array(meta.iv_priv),new Uint8Array(meta.priv));
  const pubraw=await aesDecrypt(aesKey,new Uint8Array(meta.iv_pub), new Uint8Array(meta.pub));
  const privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'Ed25519'},false,['sign']);
  const publicKey =await crypto.subtle.importKey('raw',  pubraw,{name:'Ed25519'},true, ['verify']);
  return { privateKey, publicKey, pub_hex: toHex(pubraw) };
}
let KEYS=null, META=null;
(async()=>{
  META=await idbGet('acct:'+RID);
  if(!META){ sessionStorage.clear(); location.replace('./login.html'); return; }
  KEYS=await importKey(PASS, META);
  $('#pub') && ($('#pub').value=`RID: ${RID}\npub: ${KEYS.pub_hex}`);
  ($('#rid-balance')||{}).value = RID;
})();

// == canonical/sign ==
async function canonHex(from_rid,to_rid,amount,nonce,pubkey_hex){
  const parts=[enc.encode(from_rid),enc.encode(to_rid),u64le(Number(amount)),u64le(Number(nonce)),enc.encode(pubkey_hex)];
  const buf=new Uint8Array(parts.reduce((s,p)=>s+p.length,0)); let o=0; for(const p of parts){ buf.set(p,o); o+=p.length; }
  return toHex(await sha256(buf));
}
async function signCanon(priv, canonHexStr){
  const msg = fromHex(canonHexStr);
  const sig = await crypto.subtle.sign('Ed25519', priv, msg);
  return toHex(sig);
}

// == API wrappers ==
async function getBalance(rid){ return fetchJSON(`${API}balance/${encodeURIComponent(rid)}`); }
async function submitTxBatch(txs){
  return fetchJSON(`${API}submit_tx_batch`, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ txs }) });
}
async function stakeDelegate(delegator,validator,amount){
  return fetchJSON(`${API}stake/delegate`, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({delegator,validator,amount:Number(amount)}) });
}
async function stakeUndelegate(delegator,validator,amount){
  return fetchJSON(`${API}stake/undelegate`, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({delegator,validator,amount:Number(amount)}) });
}
async function stakeClaim(delegator,validator){
  return fetchJSON(`${API}stake/claim`, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({delegator,validator,amount:0}) });
}
async function stakeMy(rid){ return fetchJSON(`${API}stake/my/${encodeURIComponent(rid)}`); }

// == UI handlers ==
$('#btn-balance')?.addEventListener('click', async ()=>{
  try{ const rid=($('#rid-balance')?.value||RID).trim(); const j=await getBalance(rid); $('#out-balance') && ($('#out-balance').textContent=JSON.stringify(j)); }
  catch(e){ $('#out-balance') && ($('#out-balance').textContent=`ERR: ${JSON.stringify(e)}`); }
});

$('#btn-send')?.addEventListener('click', async ()=>{
  try{
    const to = ($('#to')||$('#rid-to'))?.value.trim();
    const amount = ($('#amount')||$('#sum')||$('#stake-amount'))?.value.trim();
    const nonce  = ($('#nonce')||$('#tx-nonce'))?.value.trim();
    if(!to||!amount||!nonce) throw {error:'fill to/amount/nonce'};
    const ch = await canonHex(RID, to, amount, nonce, KEYS.pub_hex);
    const sigHex = await signCanon(KEYS.privateKey, ch);
    const tx = { from_rid:RID, to_rid:to, amount:Number(amount), nonce:Number(nonce), pubkey_hex:KEYS.pub_hex, sig_hex:sigHex };
    const res = await submitTxBatch([tx]);
    $('#out-send') && ($('#out-send').textContent = JSON.stringify(res,null,2));
  }catch(e){ $('#out-send') && ($('#out-send').textContent = `ERR: ${JSON.stringify(e)}`); }
});

$('#btn-delegate')?.addEventListener('click', async ()=>{
  try{
    const val = ($('#validator')||$('#val')||$('#rid-validator'))?.value.trim() || RID;
    const amount = ($('#stake-amount')||$('#amount')||$('#sum'))?.value.trim();
    const res = await stakeDelegate(RID, val, amount);
    $('#out-stake') && ($('#out-stake').textContent = JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent = `ERR: ${JSON.stringify(e)}`); }
});
$('#btn-undelegate')?.addEventListener('click', async ()=>{
  try{
    const val = ($('#validator')||$('#val')||$('#rid-validator'))?.value.trim() || RID;
    const amount = ($('#stake-amount')||$('#amount')||$('#sum'))?.value.trim();
    const res = await stakeUndelegate(RID, val, amount);
    $('#out-stake') && ($('#out-stake').textContent = JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent = `ERR: ${JSON.stringify(e)}`); }
});
$('#btn-claim')?.addEventListener('click', async ()=>{
  try{
    const val = ($('#validator')||$('#val')||$('#rid-validator'))?.value.trim() || RID;
    const res = await stakeClaim(RID, val);
    $('#out-stake') && ($('#out-stake').textContent = JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent = `ERR: ${JSON.stringify(e)}`); }
});
$('#btn-my')?.addEventListener('click', async ()=>{
  try{ const res = await stakeMy(RID); $('#out-my') && ($('#out-my').textContent = JSON.stringify(res)); }
  catch(e){ $('#out-my') && ($('#out-my').textContent = `ERR: ${JSON.stringify(e)}`); }
});

// nonce helper
$('#btn-nonce')?.addEventListener('click', async ()=>{
  try{ const j=await getBalance(RID); ($('#nonce')||$('#tx-nonce')) && ((($('#nonce')||$('#tx-nonce')).value)=String(j.nonce||0)); }
  catch(e){ /* ignore */ }
});

~~~

### www/wallet/app.v3.js

~~~javascript
const API = location.origin + '/api/';
const enc = new TextEncoder();

// utils
const $ = s => document.querySelector(s);
const toHex   = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex = h => new Uint8Array((h.match(/.{1,2}/g)||[]).map(x=>parseInt(x,16)));
function u64le(n){ const b=new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; }
async function sha256(bytes){ const d=await crypto.subtle.digest('SHA-256', bytes); return new Uint8Array(d); }

// robust fetch → всегда JSON
async function fetchJSON(url, opts){
  const r = await fetch(url, opts);
  const text = await r.text();
  try {
    const js = text ? JSON.parse(text) : {};
    if (!r.ok) throw js;
    return js;
  } catch(e) {
    throw { ok:false, error:(typeof e==='object'&&e.error)?e.error:(text||'not json'), status:r.status||0 };
  }
}

// session/keys
const PASS = sessionStorage.getItem('logos_pass');
const RID  = sessionStorage.getItem('logos_rid');
if (!PASS || !RID) { location.replace('./login.html'); throw new Error('locked'); }

const DB_NAME='logos_wallet_v2', STORE='keys';
function idb(){ return new Promise((res,rej)=>{ const r=indexedDB.open(DB_NAME,1); r.onupgradeneeded=()=>r.result.createObjectStore(STORE); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
async function idbGet(k){ const db=await idb(); return new Promise((res,rej)=>{ const tx=db.transaction(STORE,'readonly'); const st=tx.objectStore(STORE); const rq=st.get(k); rq.onsuccess=()=>res(rq.result||null); rq.onerror=()=>rej(rq.error); }); }
async function deriveKey(pass,salt){ const km=await crypto.subtle.importKey('raw', enc.encode(pass), {name:'PBKDF2'}, false, ['deriveKey']); return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:120000}, km, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']); }
async function aesDecrypt(aesKey,iv,ct){ return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv}, aesKey, ct)); }
async function importKey(pass, meta){
  const aesKey=await deriveKey(pass,new Uint8Array(meta.salt));
  const pkcs8 =await aesDecrypt(aesKey,new Uint8Array(meta.iv_priv),new Uint8Array(meta.priv));
  const pubraw=await aesDecrypt(aesKey,new Uint8Array(meta.iv_pub), new Uint8Array(meta.pub));
  const privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'Ed25519'},false,['sign']);
  const publicKey =await crypto.subtle.importKey('raw',  pubraw,{name:'Ed25519'},true, ['verify']);
  return { privateKey, publicKey, pub_hex: toHex(pubraw) };
}
let KEYS=null, META=null;
(async()=>{
  META=await idbGet('acct:'+RID);
  if(!META){ sessionStorage.clear(); location.replace('./login.html'); return; }
  KEYS=await importKey(PASS, META);
  const pubEl=$('#pub'); if(pubEl) pubEl.value=`RID: ${RID}\npub: ${KEYS.pub_hex}`;
  const rb=$('#rid-balance'); if(rb) rb.value=RID;
})();

// canonical+sign
async function canonHex(from_rid,to_rid,amount,nonce,pubkey_hex){
  const parts=[enc.encode(from_rid),enc.encode(to_rid),u64le(Number(amount)),u64le(Number(nonce)),enc.encode(pubkey_hex)];
  const buf=new Uint8Array(parts.reduce((s,p)=>s+p.length,0)); let o=0; for(const p of parts){ buf.set(p,o); o+=p.length; }
  return toHex(await sha256(buf));
}
async function signCanon(priv, canonHexStr){
  const msg = fromHex(canonHexStr);
  const sig = await crypto.subtle.sign('Ed25519', priv, msg);
  return toHex(sig);
}

// API wrappers
const getBalance = (rid)=>fetchJSON(`${API}balance/${encodeURIComponent(rid)}`);
const submitTxBatch = (txs)=>fetchJSON(`${API}submit_tx_batch`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({txs})});
const stakeDelegate   = (delegator,validator,amount)=>fetchJSON(`${API}stake/delegate`,  {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({delegator,validator,amount:Number(amount)})});
const stakeUndelegate = (delegator,validator,amount)=>fetchJSON(`${API}stake/undelegate`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({delegator,validator,amount:Number(amount)})});
const stakeClaim      = (delegator,validator)=>fetchJSON(`${API}stake/claim`,            {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({delegator,validator,amount:0})});
const stakeMy         = (rid)=>fetchJSON(`${API}stake/my/${encodeURIComponent(rid)}`);

// UI handlers
$('#btn-balance')?.addEventListener('click', async ()=>{
  try{ const rid=($('#rid-balance')?.value||RID).trim(); const j=await getBalance(rid); $('#out-balance') && ($('#out-balance').textContent=JSON.stringify(j)); }
  catch(e){ $('#out-balance') && ($('#out-balance').textContent=`ERR: ${JSON.stringify(e)}`); }
});

$('#btn-nonce')?.addEventListener('click', async ()=>{
  try{ const j=await getBalance(RID); const n=($('#nonce')); if(n) n.value=String(j.nonce||0); } catch(e){}
});

$('#btn-send')?.addEventListener('click', async ()=>{
  try{
    const to=$('#to')?.value.trim(); const amount=$('#amount')?.value.trim(); const nonce=$('#nonce')?.value.trim();
    if(!to||!amount||!nonce) throw {error:'fill to/amount/nonce'};
    const ch=await canonHex(RID,to,amount,nonce,KEYS.pub_hex);
    const sig=await signCanon(KEYS.privateKey,ch);
    const tx={from_rid:RID,to_rid:to,amount:Number(amount),nonce:Number(nonce),pubkey_hex:KEYS.pub_hex,sig_hex:sig};
    const res=await submitTxBatch([tx]);
    $('#out-send') && ($('#out-send').textContent=JSON.stringify(res,null,2));
  }catch(e){ $('#out-send') && ($('#out-send').textContent=`ERR: ${JSON.stringify(e)}`); }
});

$('#btn-delegate')?.addEventListener('click', async ()=>{
  try{
    const val=($('#validator')?.value||RID).trim(); const amount=$('#stake-amount')?.value.trim();
    const res=await stakeDelegate(RID,val,amount);
    $('#out-stake') && ($('#out-stake').textContent=JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent=`ERR: ${JSON.stringify(e)}`); }
});
$('#btn-undelegate')?.addEventListener('click', async ()=>{
  try{
    const val=($('#validator')?.value||RID).trim(); const amount=$('#stake-amount')?.value.trim();
    const res=await stakeUndelegate(RID,val,amount);
    $('#out-stake') && ($('#out-stake').textContent=JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent=`ERR: ${JSON.stringify(e)}`); }
});
$('#btn-claim')?.addEventListener('click', async ()=>{
  try{
    const val=($('#validator')?.value||RID).trim();
    const res=await stakeClaim(RID,val);
    $('#out-stake') && ($('#out-stake').textContent=JSON.stringify(res));
  }catch(e){ $('#out-stake') && ($('#out-stake').textContent=`ERR: ${JSON.stringify(e)}`); }
});
$('#btn-my')?.addEventListener('click', async ()=>{
  try{ const res=await stakeMy(RID); $('#out-my') && ($('#out-my').textContent=JSON.stringify(res)); }
  catch(e){ $('#out-my') && ($('#out-my').textContent=`ERR: ${JSON.stringify(e)}`); }
});

~~~

### www/wallet/auth.js

~~~javascript
// AUTH v3: RID + пароль. Сохраняем под "acct:<RID>".
// Фичи: авто-подстановка last_rid, кликабельный список, чистка всех пробелов/переносов в RID.

const DB_NAME='logos_wallet_v2', STORE='keys', enc=new TextEncoder();
const $ = s => document.querySelector(s);
const out = msg => { const el=$('#out'); if(el) el.textContent=String(msg); };

function normRid(s){ return (s||'').replace(/\s+/g,'').trim(); } // убираем все пробелы/переносы

function ensureEnv() {
  if (!window.isSecureContext) throw new Error('Нужен HTTPS (secure context)');
  if (!window.indexedDB) throw new Error('IndexedDB недоступен');
  if (!crypto || !crypto.subtle) throw new Error('WebCrypto недоступен');
}

const idb=()=>new Promise((res,rej)=>{const r=indexedDB.open(DB_NAME,1);r.onupgradeneeded=()=>r.result.createObjectStore(STORE);r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});
const idbGet=async k=>{const db=await idb();return new Promise((res,rej)=>{const t=db.transaction(STORE,'readonly').objectStore(STORE).get(k);t.onsuccess=()=>res(t.result||null);t.onerror=()=>rej(t.error);});};
const idbSet=async (k,v)=>{const db=await idb();return new Promise((res,rej)=>{const t=db.transaction(STORE,'readwrite').objectStore(STORE).put(v,k);t.onsuccess=()=>res(true);t.onerror=()=>rej(t.error);});};
const idbDel=async k=>{const db=await idb();return new Promise((res,rej)=>{const t=db.transaction(STORE,'readwrite').objectStore(STORE).delete(k);t.onsuccess=()=>res(true);t.onerror=()=>rej(t.error);});};

async function deriveKey(pass,salt){
  const keyMat=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:120000,hash:'SHA-256'},keyMat,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function aesEncrypt(aesKey,data){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},aesKey,data);return{iv:Array.from(iv),ct:Array.from(new Uint8Array(ct))}}
async function aesDecrypt(aesKey,iv,ct){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(iv)},aesKey,new Uint8Array(ct)))}

function b58(bytes){
  const ALPH="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const hex=[...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join('');
  let x=BigInt('0x'+hex), out=''; while(x>0n){ out=ALPH[Number(x%58n)]+out; x/=58n; } return out||'1';
}

async function addAccount(rid){ const list=(await idbGet('accounts'))||[]; if(!list.includes(rid)){ list.push(rid); await idbSet('accounts',list); } }
async function listAccounts(){ return (await idbGet('accounts'))||[]; }

async function createAccount(pass){
  ensureEnv();
  if(!pass || pass.length<6) throw new Error('Пароль ≥6 символов');

  out('Создаём ключ…');
  const kp=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
  const rawPub=new Uint8Array(await crypto.subtle.exportKey('raw',kp.publicKey));
  const rid=b58(rawPub);
  const pkcs8=new Uint8Array(await crypto.subtle.exportKey('pkcs8',kp.privateKey));
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const aes=await deriveKey(pass,salt);
  const {iv,ct}=await aesEncrypt(aes,pkcs8);
  const meta={rid,pub:Array.from(rawPub),salt:Array.from(salt),iv,priv:ct};

  await idbSet('acct:'+rid,meta);
  await addAccount(rid);
  await idbSet('last_rid', rid);

  sessionStorage.setItem('logos_pass',pass);
  sessionStorage.setItem('logos_rid',rid);
  out('RID создан: '+rid+' → вход…');
  location.href='./app.html';
}

async function loginAccount(rid, pass){
  ensureEnv();
  rid = normRid(rid);
  if(!rid) throw new Error('Укажи RID');
  if(!pass || pass.length<6) throw new Error('Пароль ≥6 символов');

  const meta=await idbGet('acct:'+rid);
  if(!meta){
    const list=await listAccounts();
    throw new Error('RID не найден на этом устройстве. Сохранённые RID:\n'+(list.length?list.join('\n'):'—'));
  }
  const aes=await deriveKey(pass,new Uint8Array(meta.salt));
  try{ await aesDecrypt(aes,meta.iv,meta.priv); } catch(e){ throw new Error('Неверный пароль'); }

  sessionStorage.setItem('logos_pass',pass);
  sessionStorage.setItem('logos_rid',rid);
  await idbSet('last_rid', rid);
  out('Вход…'); location.href='./app.html';
}

async function resetAll(){
  const list=await listAccounts();
  for(const rid of list){ await idbDel('acct:'+rid); }
  await idbDel('accounts'); await idbDel('last_rid');
  sessionStorage.clear();
  out('Все аккаунты удалены (DEV).');
}

function renderRidList(list){
  const wrap=$('#listWrap'), ul=$('#ridList'); ul.innerHTML='';
  if(!list.length){ wrap.style.display='block'; ul.innerHTML='<li>— пусто —</li>'; return; }
  wrap.style.display='block';
  list.forEach(rid=>{
    const li=document.createElement('li'); li.textContent=rid;
    li.addEventListener('click', ()=>{ $('#loginRid').value=rid; out('RID подставлен'); });
    ul.appendChild(li);
  });
}

// авто-подстановка last_rid при загрузке
(async ()=>{
  const last=await idbGet('last_rid'); if(last){ $('#loginRid').value=last; }
})();

// wire UI
$('#btn-login').addEventListener('click', async ()=>{
  const rid=$('#loginRid').value; const pass=$('#pass').value;
  try{ await loginAccount(rid,pass); }catch(e){ out('ERR: '+(e&&e.message?e.message:e)); }
});
$('#btn-create').addEventListener('click', async ()=>{
  const pass=$('#pass').value;
  try{ await createAccount(pass); }catch(e){ out('ERR: '+(e&&e.message?e.message:e)); }
});
$('#btn-list').addEventListener('click', async ()=>{
  try{ renderRidList(await listAccounts()); }catch(e){ out('ERR: '+e); }
});
$('#btn-reset').addEventListener('click', resetAll);

~~~

### www/wallet/staking.js

~~~javascript
// LOGOS Wallet — staking (prod)
async function stakeSign(op, validator, amount, nonce){
  const msg = `${session.rid}|${op}|${validator}|${amount||0}|${nonce}`;
  return await crypto.subtle.sign('Ed25519', session.privKey, new TextEncoder().encode(msg)).then(buf=>{
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  });
}
document.getElementById('btnDelegate').onclick = async ()=>{
  try{
    const b=await (await fetch(`${location.origin + '/api'}/balance/${encodeURIComponent(session.rid)}`)).json();
    const validator=document.getElementById('valRid').value.trim();
    const amount=Number(document.getElementById('stakeAmt').value);
    const nonce=(b.nonce??0)+1;
    const sig_hex=await stakeSign('delegate',validator,amount,nonce);
    const r=await fetch(`${location.origin + '/api'}/stake/submit`,{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({from:session.rid,op:'delegate',validator,amount,nonce,sig_hex})});
    const j=await r.json(); document.getElementById('stakeStatus').textContent = j.ok?'Delegate OK':'ERR '+j.info;
  }catch(e){ document.getElementById('stakeStatus').textContent='Ошибка delegate'; }
};
document.getElementById('btnUndelegate').onclick = async ()=>{
  try{
    const b=await (await fetch(`${location.origin + '/api'}/balance/${encodeURIComponent(session.rid)}`)).json();
    const validator=document.getElementById('valRid').value.trim();
    const amount=Number(document.getElementById('stakeAmt').value);
    const nonce=(b.nonce??0)+1;
    const sig_hex=await stakeSign('undelegate',validator,amount,nonce);
    const r=await fetch(`${location.origin + '/api'}/stake/submit`,{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({from:session.rid,op:'undelegate',validator,amount,nonce,sig_hex})});
    const j=await r.json(); document.getElementById('stakeStatus').textContent = j.ok?'Undelegate OK':'ERR '+j.info;
  }catch(e){ document.getElementById('stakeStatus').textContent='Ошибка undelegate'; }
};
document.getElementById('btnClaim').onclick = async ()=>{
  try{
    const b=await (await fetch(`${location.origin + '/api'}/balance/${encodeURIComponent(session.rid)}`)).json();
    const validator=document.getElementById('valRid').value.trim();
    const nonce=(b.nonce??0)+1;
    const sig_hex=await stakeSign('claim',validator,0,nonce);
    const r=await fetch(`${location.origin + '/api'}/stake/submit`,{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({from:session.rid,op:'claim',validator,amount:0,nonce,sig_hex})});
    const j=await r.json(); document.getElementById('stakeStatus').textContent = j.ok?'Claim OK':'ERR '+j.info;
  }catch(e){ document.getElementById('stakeStatus').textContent='Ошибка claim'; }
};

~~~

### www/wallet/wallet.js

~~~javascript
// LOGOS Wallet core — PROD
// Подключение к API через /api (nginx proxy)
const BASE = location.origin + '/api';

// ===== IndexedDB =====
const DB_NAME='logos_wallet', DB_STORE='keys';
function idbOpen(){return new Promise((res,rej)=>{const r=indexedDB.open(DB_NAME,1);r.onupgradeneeded=e=>{const db=e.target.result;if(!db.objectStoreNames.contains(DB_STORE))db.createObjectStore(DB_STORE,{keyPath:'rid'})};r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});}
async function idbPut(rec){const db=await idbOpen();await new Promise((res,rej)=>{const tx=db.transaction(DB_STORE,'readwrite');tx.objectStore(DB_STORE).put(rec);tx.oncomplete=res;tx.onerror=()=>rej(tx.error)});db.close();}
async function idbGet(rid){const db=await idbOpen();return await new Promise((res,rej)=>{const tx=db.transaction(DB_STORE,'readonly');const rq=tx.objectStore(DB_STORE).get(rid);rq.onsuccess=()=>res(rq.result||null);rq.onerror=()=>rej(rq.error);tx.oncomplete=()=>db.close()});}

// ===== UI refs =====
const ui={
  loginRid:document.getElementById('loginRid'), loginPass:document.getElementById('loginPass'),
  btnLogin:document.getElementById('btnLogin'), loginStatus:document.getElementById('loginStatus'),
  newPass:document.getElementById('newPass'), btnCreate:document.getElementById('btnCreate'), createStatus:document.getElementById('createStatus'),
  panel:document.getElementById('walletPanel'),
  ridView:document.getElementById('ridView'), balView:document.getElementById('balView'), nonceView:document.getElementById('nonceView'),
  toRid:document.getElementById('toRid'), amount:document.getElementById('amount'), btnSend:document.getElementById('btnSend'), sendStatus:document.getElementById('sendStatus'),
  ridStake:document.getElementById('ridStake'),
  histBody:document.getElementById('histBody'), btnMoreHist:document.getElementById('btnMoreHist'),
  tabs:[...document.querySelectorAll('.tab')],
  btnExport:document.getElementById('btnExport'), btnImport:document.getElementById('btnImport'), impFile:document.getElementById('impFile'),
  settingsInfo:document.getElementById('settingsInfo'), exportStatus:document.getElementById('exportStatus')
};

// ===== WebCrypto helpers =====
function hex(buf){return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');}
async function sha256(s){const h=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return hex(h);}
async function pbkdf2(pass,salt,iters=300000){const key=await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2', hash:'SHA-256', salt, iterations:iters}, key, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);}
async function signHex(bytes){const sig=await crypto.subtle.sign('Ed25519', session.privKey, bytes); return hex(sig);}

// ===== Anti-bot PoW (на создание) =====
async function powCreate(){const ts=Date.now().toString();let n=0;for(;;){const h=await sha256(ts+'|'+n);if(h.startsWith('00000'))return{ts,nonce:n,h};n++; if(n%5000===0) await new Promise(r=>setTimeout(r));}}

// ===== Session =====
let session={rid:null, privKey:null, pubKeyRaw:null};

// ===== Balance/nonce =====
async function refreshBalance(){
  const enc=encodeURIComponent(session.rid);
  const r=await fetch(`${BASE}/balance/${enc}`); const j=await r.json();
  ui.balView.textContent=j.balance??0; ui.nonceView.textContent=j.nonce??0;
  return j;
}

// ===== Create wallet =====
ui.btnCreate.onclick = async ()=>{
  try{
    ui.createStatus.textContent='Генерация…';
    const pass = ui.newPass.value.trim();
    if(pass.length<8){ ui.createStatus.textContent='Сложнее пароль'; return; }
    await powCreate();

    const kp = await crypto.subtle.generateKey({name:'Ed25519'}, true, ['sign','verify']);
    const pubRaw = await crypto.subtle.exportKey('raw', kp.publicKey);
    const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);

    const rid = 'Λ0@7.83Hzφ' + (await sha256(hex(pubRaw))).slice(0,6);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const aek  = await pbkdf2(pass, salt);
    const enc  = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aek, privRaw);

    await idbPut({ rid, pub_hex: hex(pubRaw), enc_priv_b64: btoa(String.fromCharCode(...new Uint8Array(enc))), salt_hex: hex(salt), iv_hex: hex(iv) });

    ui.loginRid.value = rid; ui.loginPass.value = pass;
    ui.createStatus.textContent='OK — кошелёк создан';
  }catch(e){ console.error(e); ui.createStatus.textContent='Ошибка создания'; }
};

// ===== Login =====
ui.btnLogin.onclick = async ()=>{
  try{
    ui.loginStatus.textContent = 'Поиск…';
    const rid = ui.loginRid.value.trim(), pass = ui.loginPass.value.trim();
    const rec = await idbGet(rid);
    if(!rec){ ui.loginStatus.textContent = 'RID не найден в этом браузере'; return; }

    const salt = Uint8Array.from(rec.salt_hex.match(/.{2}/g).map(h=>parseInt(h,16)));
    const iv   = Uint8Array.from(rec.iv_hex.match(/.{2}/g).map(h=>parseInt(h,16)));
    const enc  = Uint8Array.from(atob(rec.enc_priv_b64), c=>c.charCodeAt(0));
    const aek  = await pbkdf2(pass, salt);
    const privRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv}, aek, enc);
    const privKey = await crypto.subtle.importKey('pkcs8', privRaw, {name:'Ed25519'}, false, ['sign']);

    session = { rid, privKey, pubKeyRaw: Uint8Array.from(rec.pub_hex.match(/.{2}/g).map(h=>parseInt(h,16))).buffer };

    // UI
    document.getElementById('walletPanel').style.display='';
    document.getElementById('ridView').textContent = rid;
    document.getElementById('ridStake').textContent = rid;
    ui.loginStatus.textContent='OK';

    await refreshBalance();
    histCursor=null; ui.histBody.innerHTML=''; await loadHistoryPage();
  }catch(e){ console.error(e); ui.loginStatus.textContent='Ошибка входа'; }
};

// ===== Send TX =====
ui.btnSend.onclick = async ()=>{
  try{
    ui.sendStatus.textContent='Отправка…';
    const b=await refreshBalance();
    const to=ui.toRid.value.trim();
    const amt=Number(ui.amount.value);
    const nonce=(b.nonce??0)+1;

    const msg=`${session.rid}|${to}|${amt}|${nonce}`;
    const sig_hex = await signHex(new TextEncoder().encode(msg));

    // Лёгкий локальный троттлинг (anti-bot throttle)
    await new Promise(r=>setTimeout(r, 300 + Math.random()*500));

    const res = await fetch(`${BASE}/submit_tx`,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({from:session.rid,to,amount:amt,nonce,sig_hex})
    });
    const j=await res.json();
    ui.sendStatus.textContent = j.ok ? ('OK: '+(j.txid||'')) : ('ERR: '+j.info);
    await refreshBalance();
  }catch(e){ console.error(e); ui.sendStatus.textContent='Ошибка'; }
};

// ===== History (пагинация by height) =====
let histCursor=null;
async function loadHistoryPage(){
  const enc=encodeURIComponent(session.rid);
  let url=`${BASE}/archive/history/${enc}`; if(histCursor!=null) url+=`?before_height=${histCursor}`;
  const r=await fetch(url); const list=await r.json(); if(!Array.isArray(list) || list.length===0) return;
  histCursor = Number(list[list.length-1].height) - 1;
  const frag=document.createDocumentFragment();
  for(const t of list){
    const tr=document.createElement('tr');
    tr.innerHTML=`<td class="mono">${String(t.txid).slice(0,16)}…</td><td class="mono">${t.from}</td><td class="mono">${t.to}</td><td>${t.amount}</td><td>${t.height}</td><td>${t.ts??''}</td>`;
    ui.histBody.appendChild(tr);
  }
}
ui.btnMoreHist.onclick = ()=> loadHistoryPage();

// ===== Tabs =====
ui.tabs.forEach(tab=>{
  tab.onclick=()=>{
    ui.tabs.forEach(t=>t.classList.remove('active')); tab.classList.add('active');
    const name=tab.dataset.tab;
    document.getElementById('tab-send').classList.toggle('hide', name!=='send');
    document.getElementById('tab-stake').classList.toggle('hide', name!=='stake');
    document.getElementById('tab-history').classList.toggle('hide', name!=='history');
    document.getElementById('tab-settings').classList.toggle('hide', name!=='settings');
  };
});

// ===== Export / Import =====
ui.btnExport.onclick = async ()=>{
  const rec = await idbGet(session.rid);
  const blob = new Blob([JSON.stringify(rec)], {type:'application/json'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `logos_wallet_${session.rid}.json`; a.click();
  ui.exportStatus.textContent='Экспортирован зашифрованный бэкап';
};
ui.btnImport.onclick = ()=> ui.impFile.click();
ui.impFile.onchange = async (e)=>{
  try{
    const f=e.target.files[0]; const text=await f.text(); const rec=JSON.parse(text);
    if(!rec.rid || !rec.enc_priv_b64) throw new Error('bad backup');
    await idbPut(rec); ui.exportStatus.textContent='Импорт OK';
  }catch(err){ ui.exportStatus.textContent='Ошибка импорта'; }
};

~~~

### www/wallet/wallet.css

~~~css
:root {
  --bg: #0e1116;
  --fg: #e6edf3;
  --muted: #9aa4ae;
  --card: #161b22;
  --border: #2d333b;
  --accent: #2f81f7;
  --accent-2: #7ee787;
  --warn: #f0883e;
  --error: #ff6b6b;
  --mono: ui-monospace, SFMono-Regular, Menlo, monospace;
  --sans: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, sans-serif;
}
html[data-theme="light"] {
  --bg: #f6f8fa;
  --fg: #0b1117;
  --muted: #57606a;
  --card: #ffffff;
  --border: #d0d7de;
  --accent: #0969da;
  --accent-2: #1a7f37;
  --warn: #9a6700;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font-family: var(--sans); }
a { color: var(--accent); text-decoration: none; }
.topbar {
  position: sticky; top: 0; z-index: 10;
  display: flex; align-items: center; gap: 8px;
  padding: 10px 14px; border-bottom: 1px solid var(--border); background: var(--card);
}
.brand { font-weight: 700; }
.spacer { flex: 1; }
.endpoint { font-size: 12px; color: var(--muted); }
.container { max-width: 980px; margin: 16px auto; padding: 0 12px; display: grid; gap: 16px; }
.card {
  border: 1px solid var(--border); border-radius: 10px;
  background: var(--card); padding: 14px;
}
h2 { margin: 0 0 10px 0; font-size: 18px; }
.row { display: flex; gap: 8px; align-items: center; }
.wrap { flex-wrap: wrap; }
.grid2 { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 8px; }
.mt8 { margin-top: 8px; }
.input {
  border: 1px solid var(--border); background: transparent; color: var(--fg);
  padding: 8px 10px; border-radius: 8px; outline: none;
}
.input:focus { border-color: var(--accent); }
.grow { flex: 1; min-width: 260px; }
.w100 { width: 100px; }
.w120 { width: 120px; }
.btn {
  border: 1px solid var(--border); background: var(--accent); color: #fff;
  padding: 8px 12px; border-radius: 8px; cursor: pointer;
}
.btn.secondary { background: transparent; color: var(--fg); }
.btn.warn { background: var(--warn); color: #111; }
.btn:disabled { opacity: .6; cursor: not-allowed; }
.mono { font-family: var(--mono); }
.log {
  font-family: var(--mono); background: transparent; border: 1px dashed var(--border);
  border-radius: 8px; padding: 8px; min-height: 40px; white-space: pre-wrap;
}
.statusbar {
  position: sticky; bottom: 0; margin-top: 12px; padding: 8px 14px;
  border-top: 1px solid var(--border); background: var(--card); color: var(--muted);
}

/* auto-theming для системной темы, если юзер не переключал вручную */
@media (prefers-color-scheme: light) {
  html[data-theme="auto"] { --bg: #f6f8fa; --fg: #0b1117; --muted:#57606a; --card:#fff; --border:#d0d7de; --accent:#0969da; --accent-2:#1a7f37; --warn:#9a6700; }
}

~~~

## www/explorer (static)

### www/explorer/index.html

~~~html
<!doctype html><html lang="ru"><head>
<meta charset="utf-8"/>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'">
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>LOGOS Explorer</title>
<style>
body{font-family:system-ui,Roboto,Arial,sans-serif;background:#0b0e11;color:#e6e6e6;margin:0}
header{padding:16px 20px;background:#12161a;border-bottom:1px solid #1b2026}
main{padding:20px}
table{width:100%;border-collapse:collapse}
th,td{padding:8px 10px;border-bottom:1px solid #1b2026;font-size:14px}
th{text-align:left;color:#a6a6a6}.muted{color:#8c8c8c;font-size:12px}
</style></head><body>
<header><h3>LOGOS Explorer</h3><div class="muted" id="head"></div></header>
<main>
  <h4>Последние блоки</h4>
  <table><thead><tr><th>Высота</th><th>Хеш</th><th>Tx</th><th>Время</th></tr></thead><tbody id="blocks"></tbody></table>
</main>
<script>
async function getHead(){ return (await fetch('/api/head')).json(); }
async function getBlocks(){ return (await fetch('/api/archive/blocks?limit=50')).json(); }
function fmtTs(ts){ const d=new Date((ts||0)*1000); return isNaN(d)?'-':d.toLocaleString(); }
async function tick(){
  try{
    const h=await getHead();
    document.getElementById('head').textContent=`head.height=${h.height} (finalized=${h.finalized})`;
    const data=await getBlocks();
    const rows=(data.blocks||[]).map(b=>{
      const hash=b.hash||b.block_hash||''; const ts=b.ts||b.ts_sec||0; const txc=b.tx_count??b.txs??0;
      return `<tr><td>${b.height}</td><td class="muted">${String(hash).slice(0,16)}…</td><td>${txc}</td><td>${fmtTs(ts)}</td></tr>`;
    }).join('');
    document.getElementById('blocks').innerHTML=rows;
  }catch(e){ console.error(e); }
}
setInterval(tick,1500); tick();
</script></body></html>

~~~

### www/explorer/explorer.js

~~~javascript
// LOGOS Explorer – history debug + stable fill
const API = location.origin + "/api";
const $  = s => document.querySelector(s);
const out= (id,v)=>{$(id).textContent=(typeof v==="string")?v:JSON.stringify(v,null,2)};
const fmtNum=n=>Number(n).toLocaleString("ru-RU");
const fmtTs =ms=>isFinite(ms)?new Date(Number(ms)).toLocaleString("ru-RU"):"";

async function jget(path){
  const r=await fetch(API+path,{cache:"no-store"});
  if(!r.ok) throw new Error(r.status+" "+(await r.text()).slice(0,400));
  return r.json();
}

// status
document.addEventListener("DOMContentLoaded",()=>{ const s=$("#jsStat"); if(s){ s.style.color="#0bd464"; s.textContent="js: готов"; }});

// HEAD / ECONOMY
let autoTimer=null;
async function fetchHead(){ try{ out("out-head", await jget("/head")); }catch(e){ out("out-head","ERR: "+e.message); } }
async function fetchEconomy(){ try{ out("out-economy", await jget("/economy")); }catch(e){ out("out-economy","ERR: "+e.message); } }
function toggleAuto(){
  if(autoTimer){ clearInterval(autoTimer); autoTimer=null; $("#btn-auto").textContent="Автообновление: выключено"; return; }
  const tick=async()=>{ await fetchHead(); await fetchEconomy(); };
  tick(); autoTimer=setInterval(tick,5000);
  $("#btn-auto").textContent="Автообновление: включено";
}

// BLOCK / MIX
async function fetchBlock(){
  const h=Number($("#inp-height").value); if(!h){ alert("Укажи высоту"); return; }
  try{ out("out-block", await jget("/block/"+h)); }catch(e){ out("out-block","ERR: "+e.message); }
}
async function fetchMix(){
  const h=Number($("#inp-height").value); if(!h){ alert("Укажи высоту"); return; }
  try{ out("out-block", await jget(`/block/${h}/mix`)); }catch(e){ out("out-block","ERR: "+e.message); }
}

// HISTORY
let histRid="", limit=20, fromNonce=0, nextFrom=null, prevStack=[];
function renderHistory(arr){
  const tb=$("#tbl-history tbody"); tb.innerHTML="";
  if(!arr || arr.length===0){
    const tr=document.createElement("tr");
    tr.innerHTML=`<td colspan="6" style="opacity:.8">0 записей</td>`;
    tb.appendChild(tr);
  } else {
    arr.forEach(tx=>{
      const tr=document.createElement("tr");
      tr.innerHTML=`<td>${tx.nonce??""}</td><td>${tx.from??""}</td><td>${tx.to??""}</td>`+
                   `<td>${fmtNum(tx.amount??0)}</td><td>${tx.height??""}</td><td>${fmtTs(tx.ts_ms)}</td>`;
      tb.appendChild(tr);
    });
  }
  $("#hist-info").textContent=`RID=${histRid} · from=${fromNonce} · limit=${limit} · next=${nextFrom??"-"}`;
  $("#btn-prev").disabled = (prevStack.length===0);
  $("#btn-next").disabled = (nextFrom==null);
}

async function pageHistory(rid, from, lim){
  const q=new URLSearchParams({from:String(from||0),limit:String(lim||20)});
  const j=await jget(`/history/${rid}?`+q.toString());
  // DEBUG: покажем сырой ответ под таблицей
  out("out-history", j); $("#out-history").style.display="block";
  const arr=j.items || j.txs || [];
  nextFrom=(typeof j.next_from!=="undefined")?j.next_from:null;
  renderHistory(arr);
}

async function fetchHistory(){
  histRid=($("#inp-rid").value||"").trim();
  limit=Math.max(1, Number($("#inp-limit").value)||20);
  if(!histRid){ alert("Укажи RID"); return; }
  fromNonce=0; nextFrom=null; prevStack=[];
  try{ await pageHistory(histRid, fromNonce, limit); }catch(e){ alert("ERR: "+e.message); }
}
async function prevPage(){ if(prevStack.length===0) return; fromNonce=prevStack.pop(); await pageHistory(histRid, fromNonce, limit); }
async function nextPage(){ if(nextFrom==null) return; prevStack.push(fromNonce); fromNonce=nextFrom; await pageHistory(histRid, fromNonce, limit); }

// экспорт под onclick
window.fetchHead=fetchHead; window.fetchEconomy=fetchEconomy; window.toggleAuto=toggleAuto;
window.fetchBlock=fetchBlock; window.fetchMix=fetchMix;
window.fetchHistory=fetchHistory; window.prevPage=prevPage; window.nextPage=nextPage;

~~~

### www/explorer/explorer.css

~~~css
body { font-family: system-ui, sans-serif; margin: 0; background: #0b0c10; color: #e6edf3; }
header { padding: 12px; background: #11151a; border-bottom: 1px solid #1e242c; display:flex; justify-content:space-between; }
main { padding: 12px; display: grid; gap: 20px; }
section { background: #141a21; padding: 12px; border-radius: 10px; }
button { padding: 10px 14px; border-radius: 8px; border: none; margin: 4px; cursor: pointer; background: #1665c1; color: #fff; font-weight: 600; }
button:hover { background: #1f77d0; }
input { padding: 8px; margin: 4px; border-radius: 6px; border: 1px solid #333; background: #0b0c10; color: #e6edf3; width: 100%; max-width: 380px; }
pre { background: #0e1116; padding: 8px; border-radius: 6px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { padding: 6px 8px; border-bottom: 1px solid #333; font-size: 13px; }

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

## configs/env (examples)

### configs/env/node-a.env.example

~~~
LRB_NODE_SK_HEX=CHANGE_ME_64_HEX
LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
LRB_BRIDGE_KEY=CHANGE_ME
LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_DATA_DIR=/var/lib/logos-a
RUST_LOG=info
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

~~~

### configs/env/node-b.env.example

~~~
LRB_NODE_SK_HEX=CHANGE_ME_64_HEX
LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
LRB_BRIDGE_KEY=CHANGE_ME
LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io
LRB_NODE_LISTEN=0.0.0.0:8082
LRB_DATA_DIR=/var/lib/logos-b
RUST_LOG=info
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

~~~

### configs/env/node-c.env.example

~~~
LRB_NODE_SK_HEX=CHANGE_ME_64_HEX
LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
LRB_BRIDGE_KEY=CHANGE_ME
LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io
LRB_NODE_LISTEN=0.0.0.0:8084
LRB_DATA_DIR=/var/lib/logos-c
RUST_LOG=info
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

~~~

### configs/env/node.env.example

~~~
# LOGOS LRB – universal node env example
LRB_NODE_SK_HEX=CHANGE_ME_64_HEX
LRB_JWT_SECRET=CHANGE_ME
LRB_BRIDGE_KEY=CHANGE_ME
LRB_DATA_DIR=/var/lib/logos
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_WALLET_ORIGIN=http://localhost
LRB_QPS=30
LRB_BURST=60
LRB_RATE_BYPASS_CIDRS=127.0.0.1/32,::1/128
RUST_LOG=info

~~~

### configs/env/node.env.example

~~~
# LOGOS LRB – universal node env example
LRB_NODE_SK_HEX=CHANGE_ME_64_HEX
LRB_JWT_SECRET=CHANGE_ME
LRB_BRIDGE_KEY=CHANGE_ME
LRB_DATA_DIR=/var/lib/logos
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_WALLET_ORIGIN=http://localhost
LRB_QPS=30
LRB_BURST=60
LRB_RATE_BYPASS_CIDRS=127.0.0.1/32,::1/128
RUST_LOG=info

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

## infra/systemd (templates)

### infra/systemd/logos-healthcheck.service

~~~conf
[Unit]
Description=LOGOS healthcheck (HTTP)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/default/logos-healthcheck
ExecStart=/usr/local/bin/logos_healthcheck.sh

~~~

### infra/systemd/logos-node.service

~~~conf
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

~~~

### infra/systemd/logos-node@.service

~~~conf
[Unit]
Description=LOGOS LRB Node (%i)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos
ExecStart=/opt/logos/logos_node
EnvironmentFile=/etc/logos/node-%i.env

# sandbox
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=/var/lib/logos-%i
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target

~~~

### infra/systemd/logos-snapshot.service

~~~conf
[Unit]
Description=LOGOS LRB periodic snapshot

[Service]
Type=oneshot
EnvironmentFile=-/etc/logos/keys.env
ExecStart=/usr/bin/curl -s -H "X-Admin-Key: ${LRB_ADMIN_KEY}" \
  http://127.0.0.1:8080/admin/snapshot-file?name=snap-$(date +%%Y%%m%%dT%%H%%M%%S).json >/dev/null

~~~

### infra/systemd/lrb-proxy.service

~~~conf
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

~~~

### infra/systemd/lrb-scanner.service

~~~conf
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

~~~

### infra/systemd/exec.conf

~~~conf
[Service]
WorkingDirectory=/opt/logos
ExecStart=
ExecStart=/opt/logos/bin/logos_node

~~~

### infra/systemd/keys.conf

~~~conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

# Реальные ключи
Environment=LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
Environment=LRB_BRIDGE_KEY=CHANGE_ME

~~~

### infra/systemd/override.conf

~~~conf
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

~~~

### infra/systemd/runas.conf

~~~conf
[Service]
User=logos
Group=logos
# разрешаем запись в каталог данных под sandbox
ReadWritePaths=/var/lib/logos

~~~

### infra/systemd/security.conf

~~~conf
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

~~~

### infra/systemd/tuning.conf

~~~conf
[Service]
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615

~~~

### infra/systemd/zz-consensus.conf

~~~conf
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

~~~

### infra/systemd/zz-keys.conf

~~~conf
[Service]
# читаем файл с секретами (на будущее)
EnvironmentFile=-/etc/logos/keys.env

# и ПРЯМО зашиваем реальные значения, чтобы перебить любой override
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key
Environment=LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
Environment=LRB_BRIDGE_KEY=CHANGE_ME

~~~

### infra/systemd/zz-logging.conf

~~~conf
[Service]
Environment=RUST_LOG=info

~~~

### infra/systemd/logos-healthcheck.timer

~~~conf
[Unit]
Description=LOGOS healthcheck timer (every 1 min)

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=logos-healthcheck.service

[Install]
WantedBy=timers.target

~~~

### infra/systemd/logos-snapshot.timer

~~~conf
[Unit]
Description=Run LOGOS snapshot every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Unit=logos-snapshot.service

[Install]
WantedBy=timers.target

~~~

## infra/nginx (templates)

### infra/nginx/lrb_wallet.conf

~~~conf
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

~~~


---
(конец книги)
