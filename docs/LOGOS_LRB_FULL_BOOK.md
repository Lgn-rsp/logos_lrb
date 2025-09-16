# LOGOS LRB — Полная книга системы

**Сборка:** 2025-09-10T05:32:11+01:00  
**Репозиторий:** /root/logos_lrb

Эта книга содержит *весь код и конфиги* системы LOGOS LRB, а также инструкции «по канону».
Секреты заменены на **CHANGE_ME**.

---

# 1. Введение и канон


## Что это
LOGOS LRB — L1 с резонансным ядром: ledger/mempool/Σ(t), фазовые фильтры, slot-продюсер (quorum=1),
мост rToken, Explorer (Postgres), Web Wallet (IndexedDB/WebCrypto).

## Канон работы
```bash
cd /root/logos_lrb/<путь_к_модулю>
rm -f <file.rs|.html|.json|.conf|.service>
nano <file>
# → Вставляешь боевой код целиком (прод-уровень)
#   Ctrl+O → Enter → Ctrl+X

cd /root/logos_lrb
cargo build --release -p logos_node
sudo systemctl stop logos-node
install -m 0755 target/release/logos_node /opt/logos/bin/logos_node
sudo chown logos:logos /opt/logos/bin/logos_node
sudo systemctl daemon-reload
sudo systemctl restart logos-node
sleep 1
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo
```

---

# 2. Версии и окружение



=== rustc --version ===

```text
rustc 1.89.0 (29483883e 2025-08-04)

```


=== cargo --version ===

```text
cargo 1.89.0 (c24e10642 2025-06-23)

```


=== nginx -v ===

```text
nginx version: nginx/1.24.0 (Ubuntu)

```


=== psql --version ===

```text
psql (PostgreSQL) 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)

```


=== systemd env ===

```text
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos
LRB_WALLET_ORIGIN=http://127.0.0.1
LRB_DATA_PATH=/var/lib/logos/data.sled
LRB_ENABLE_FAUCET=1
RUST_LOG=info
LRB_NODE_KEY_PATH=/var/lib/logos/node_key
LRB_PHASEMIX_ENABLE=1
LRB_RATE_QPS=20
LRB_RATE_BURST=40
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_DATA_DIR=/var/lib/logos
LRB_SLOT_MS=200
LRB_MAX_BLOCK_TX=10000
LRB_MEMPOOL_CAP=100000
LRB_MAX_AMOUNT=18446744073709551615
LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
LRB_QUORUM_N=1
LRB_JWT_SECRET=CHANGE_ME
LRB_BRIDGE_KEY=CHANGE_ME

```


---

# 3. Cargo workspace



=== /root/logos_lrb/Cargo.toml ===

```toml
[workspace]
members  = ["lrb_core", "node"]
resolver = "2"

[workspace.package]
edition      = "2021"
rust-version = "1.78"

[workspace.dependencies]
# web / async
axum       = { version = "0.7.9", features = ["macros", "json"] }
tower      = "0.4.13"
tower-http = { version = "0.5.2", features = ["trace", "cors", "compression-gzip"] }
tokio      = { version = "1.40", features = ["full"] }
reqwest    = { version = "0.12", default-features = false, features = ["rustls-tls", "http2", "json"] }

# utils / serde / logging
serde               = { version = "1.0", features = ["derive"] }
serde_json          = "1.0"
anyhow              = "1.0"
thiserror           = "1.0"
once_cell           = "1.19"
dashmap             = "5.5"
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["env-filter", "fmt"] }
bytes               = "1.6"

# crypto / hash / codecs
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

# storage / sql / pg
sled             = "0.34"
deadpool-postgres= "0.12"
tokio-postgres   = { version = "0.7", features = ["with-uuid-1"] }
rusqlite         = { version = "0.32", features = ["bundled"] }
r2d2_sqlite      = "0.25"

# sync / net / metrics
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

```


---

# 4. lrb_core (исходники + Cargo)



=== /root/logos_lrb/lrb_core/Cargo.toml ===

```toml
[package]
name        = "lrb_core"
version     = "0.1.0"
edition     = "2021"
license     = "Apache-2.0"
description = "LOGOS LRB core (ledger, mempool, filters, RCP engine)"

[lib]
name = "lrb_core"
path = "src/lib.rs"

[dependencies]
# из workspace
serde.workspace        = true
serde_json.workspace   = true
anyhow.workspace       = true
thiserror.workspace    = true
once_cell.workspace    = true

tokio.workspace        = true
reqwest.workspace      = true
bytes.workspace        = true

hex.workspace          = true
base64.workspace       = true
bs58.workspace         = true
sha2.workspace         = true
blake3.workspace       = true
ed25519-dalek.workspace= true
rand.workspace         = true
ring.workspace         = true
uuid.workspace         = true
bincode.workspace      = true

sled.workspace         = true

```


=== /root/logos_lrb/lrb_core/src/anti_replay.rs ===

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


=== /root/logos_lrb/lrb_core/src/beacon.rs ===

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


=== /root/logos_lrb/lrb_core/src/crypto.rs ===

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


=== /root/logos_lrb/lrb_core/src/dynamic_balance.rs ===

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


=== /root/logos_lrb/lrb_core/src/heartbeat.rs ===

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


=== /root/logos_lrb/lrb_core/src/ledger.rs ===

```rust
use sled::{Db, Tree};
use std::{convert::TryInto, path::Path, time::{SystemTime, UNIX_EPOCH}};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};

use crate::types::*;

// helpers
#[inline] fn be64(v: u64) -> [u8; 8] { v.to_be_bytes() }
#[inline] fn be32(v: u32) -> [u8; 4] { v.to_be_bytes() }
#[inline] fn k_bal(r:&str)->Vec<u8>{format!("bal:{r}").into_bytes()}
#[inline] fn k_nonce(r:&str)->Vec<u8>{format!("nonce:{r}").into_bytes()}

const K_HEAD:      &[u8] = b"h";    // u64
const K_HEAD_HASH: &[u8] = b"hh";   // utf8
const K_FINAL:     &[u8] = b"fin";  // u64
const K_MINTED:    &[u8] = b"mint"; // u64
const K_BURNED:    &[u8] = b"burn"; // u64

#[derive(Clone)]
pub struct Ledger {
    db: Db,
    // trees
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

impl Ledger {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
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

    /// Доступ к sled::Db для сервисных модулей узла
    #[inline] pub fn db(&self) -> &sled::Db { &self.db }

    // ====== ожидаемые узлом методы ======
    pub fn height(&self) -> anyhow::Result<u64> {
        Ok(self.head.get(K_HEAD)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0))
    }
    pub fn head(&self) -> anyhow::Result<(u64, String)> {
        let h  = self.height().unwrap_or(0);
        let hh = self.head.get(K_HEAD_HASH)?.map(|v| String::from_utf8(v.to_vec()).unwrap()).unwrap_or_default();
        Ok((h, hh))
    }
    pub fn set_head(&self, height:u64, hash:&str) -> anyhow::Result<()> {
        self.head.insert(K_HEAD, &be64(height))?;
        self.head.insert(K_HEAD_HASH, hash.as_bytes())?;
        Ok(())
    }
    pub fn set_finalized(&self, height:u64) -> anyhow::Result<()> {
        self.head.insert(K_FINAL, &be64(height))?; Ok(())
    }

    pub fn supply(&self) -> anyhow::Result<(u64,u64)> {
        let minted = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let burned = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        Ok((minted, burned))
    }
    pub fn add_minted(&self, amount:u64) -> anyhow::Result<u64> {
        let cur = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let newv = cur.saturating_add(amount);
        self.head.insert(K_MINTED, &be64(newv))?; Ok(newv)
    }
    pub fn add_burned(&self, amount:u64) -> anyhow::Result<u64> {
        let cur = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let newv = cur.saturating_add(amount);
        self.head.insert(K_BURNED, &be64(newv))?; Ok(newv)
    }

    pub fn get_balance(&self, rid:&str) -> anyhow::Result<u64> {
        Ok(self.db.get(k_bal(rid))?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
            .unwrap_or(0))
    }
    pub fn set_balance(&self, rid:&str, amount_u128:u128) -> anyhow::Result<()> {
        let amount: u64 = amount_u128.try_into().map_err(|_| anyhow::anyhow!("amount too large"))?;
        self.db.insert(k_bal(rid), &be64(amount))?; Ok(())
    }

    pub fn get_nonce(&self, rid:&str) -> anyhow::Result<u64> {
        Ok(self.db.get(k_nonce(rid))?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
            .unwrap_or(0))
    }
    pub fn set_nonce(&self, rid:&str, value:u64) -> anyhow::Result<()> {
        self.db.insert(k_nonce(rid), &be64(value))?; Ok(())
    }
    pub fn bump_nonce(&self, rid:&str) -> anyhow::Result<u64> {
        let cur = self.get_nonce(rid)?;
        let next = cur.saturating_add(1);
        self.set_nonce(rid, next)?; Ok(next)
    }

    /// Упрощённый перевод для REST `/submit_tx`
    pub fn submit_tx_simple(&self, from:&str, to:&str, amount:u64, nonce:u64, _memo:Option<String>) -> anyhow::Result<StoredTx> {
        let from_bal = self.get_balance(from)?;
        if from_bal < amount { anyhow::bail!("insufficient funds"); }
        let to_bal = self.get_balance(to)?;

        self.set_balance(from, (from_bal - amount) as u128)?;
        self.set_balance(to,   to_bal.saturating_add(amount) as u128)?;
        self.set_nonce(from, nonce)?;

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

    /// История аккаунта — возвращаем сразу `Vec<StoredTx>`
    pub fn account_txs_page(&self, rid:&str, _cursor_usize:usize, limit:usize) -> anyhow::Result<Vec<StoredTx>> {
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

    pub fn get_tx(&self, txid:&str)-> anyhow::Result<Option<StoredTx>> {
        let mut k=Vec::with_capacity(1+txid.len()); k.extend_from_slice(b"t"); k.extend_from_slice(txid.as_bytes());
        Ok(self.txs.get(k)?.map(|v| serde_json::from_slice::<StoredTx>(&v)).transpose()?)
    }

    // ====== для rcp_engine.rs ======
    pub fn index_block(&self, height: u64, hash: &str, ts: u128, txs: &[Tx]) -> anyhow::Result<()> {
        let mut ids = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            let mut h=Sha256::new();
            h.update(tx.from.0.as_bytes()); h.update(b"|");
            h.update(tx.to.0.as_bytes());   h.update(b"|");
            h.update(&tx.amount.to_be_bytes()); h.update(b"|");
            h.update(&tx.nonce.to_be_bytes());
            let txid = hex::encode(h.finalize());
            ids.push(txid.clone());

            let stx = StoredTx{
                txid: txid.clone(), from: tx.from.0.clone(), to: tx.to.0.clone(),
                amount: tx.amount, nonce: tx.nonce, height, index: i as u32, ts,
            };

            let mut k_tx=Vec::with_capacity(1+txid.len()); k_tx.extend_from_slice(b"t"); k_tx.extend_from_slice(txid.as_bytes());
            self.txs.insert(k_tx, serde_json::to_vec(&stx)?)?;

            let mut k_af=Vec::new(); k_af.extend_from_slice(b"a"); k_af.extend_from_slice(tx.from.0.as_bytes()); k_af.push(b'|'); k_af.extend_from_slice(&be64(height)); k_af.extend_from_slice(&be32(i as u32));
            self.acct.insert(k_af, txid.as_bytes())?;
            let mut k_at=Vec::new(); k_at.extend_from_slice(b"a"); k_at.extend_from_slice(tx.to.0.as_bytes());   k_at.push(b'|'); k_at.extend_from_slice(&be64(height)); k_at.extend_from_slice(&be32(i as u32));
            self.acct.insert(k_at, txid.as_bytes())?;
        }

        let mut k_b=Vec::with_capacity(1+8); k_b.extend_from_slice(b"b"); k_b.extend_from_slice(&be64(height));
        let sblk = StoredBlock{ height, hash: hash.to_string(), ts, tx_ids: ids };
        self.blocks.insert(k_b, serde_json::to_vec(&sblk)?)?;
        Ok(())
    }

    pub fn commit_block_atomic(&self, blk: &Block) -> anyhow::Result<()> {
        for tx in blk.txs.iter() {
            let fb = self.get_balance(&tx.from.0)?;
            if fb < tx.amount { anyhow::bail!("insufficient funds"); }
            let tb = self.get_balance(&tx.to.0)?;
            self.set_balance(&tx.from.0, (fb - tx.amount) as u128)?;
            self.set_balance(&tx.to.0,   tb.saturating_add(tx.amount) as u128)?;
            self.set_nonce(&tx.from.0, tx.nonce)?;
        }
        self.set_head(blk.height, &blk.block_hash)?;
        Ok(())
    }

    pub fn get_block_by_height(&self, h:u64) -> anyhow::Result<BlockHeaderView> {
        let mut k=Vec::with_capacity(9); k.extend_from_slice(b"b"); k.extend_from_slice(&be64(h));
        if let Some(v) = self.blocks.get(k)? {
            let b: StoredBlock = serde_json::from_slice(&v)?;
            Ok(BlockHeaderView{ block_hash: b.hash })
        } else {
            let hh = self.head.get(K_HEAD_HASH)?.map(|v| String::from_utf8(v.to_vec()).unwrap()).unwrap_or_default();
            Ok(BlockHeaderView{ block_hash: hh })
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockHeaderView { pub block_hash:String }

```


=== /root/logos_lrb/lrb_core/src/lib.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_consensus.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_filters.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_integrity.rs ===

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


=== /root/logos_lrb/lrb_core/src/quorum.rs ===

```rust
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

```


=== /root/logos_lrb/lrb_core/src/rcp_engine.rs ===

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


=== /root/logos_lrb/lrb_core/src/resonance.rs ===

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


=== /root/logos_lrb/lrb_core/src/sigpool.rs ===

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


=== /root/logos_lrb/lrb_core/src/spam_guard.rs ===

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


=== /root/logos_lrb/lrb_core/src/types.rs ===

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
pub type Nonce  = u64;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Rid(pub String); // base58(VerifyingKey)

impl Rid {
    pub fn from_pubkey(pk: &VerifyingKey) -> Self {
        Rid(bs58::encode(pk.to_bytes()).into_string())
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub id: String,        // blake3 of canonical form
    pub from: Rid,         // base58(pubkey)
    pub to: Rid,
    pub amount: Amount,
    pub nonce: Nonce,
    pub public_key: Vec<u8>, // 32 bytes (VerifyingKey)
    pub signature: Vec<u8>,  // 64 bytes (Signature)
}

impl Tx {
    /// Каноническое сообщение (без id и signature)
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let m = serde_json::json!({
            "from": self.from.as_str(),
            "to":   self.to.as_str(),
            "amount": self.amount,
            "nonce":  self.nonce,
            "public_key": B64.encode(&self.public_key),
        });
        serde_json::to_vec(&m).expect("canonical json")
    }

    pub fn compute_id(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.canonical_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Быстрая валидация формы (длины, нулевые значения)
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
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let mut h = Hasher::new();
        h.update(prev_hash.as_bytes());
        h.update(proposer.as_str().as_bytes());
        for tx in &txs { h.update(tx.id.as_bytes()); }
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

/// VerifyingKey из 32 байт (не пропускаем ошибку dalek наружу)
pub fn parse_pubkey(pk: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = pk.try_into().map_err(|_| anyhow!("bad pubkey len"))?;
    let vk = VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("bad ed25519 pubkey"))?;
    Ok(vk)
}

/// Signature из 64 байт
pub fn parse_sig(sig: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = sig.try_into().map_err(|_| anyhow!("bad signature len"))?;
    // В ed25519-dalek v2 Signature::from_bytes(&[u8;64]) -> Signature
    Ok(Signature::from_bytes(&arr))
}

```


---

# 5. node (исходники + Cargo)



=== /root/logos_lrb/node/build.rs ===

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


=== /root/logos_lrb/node/Cargo.toml ===

```toml
[package]
name        = "logos_node"
version     = "0.1.0"
edition     = "2021"
license     = "Apache-2.0"
description = "LOGOS LRB node: Axum REST + archive + producer + wallet/stake"
build       = "build.rs"

[[bin]]
name = "logos_node"
path = "src/main.rs"

[lib]
name = "logos_node"
path = "src/lib.rs"

[dependencies]
# web / runtime
axum.workspace       = true
tower.workspace      = true
tower-http.workspace = true
tokio.workspace      = true

# utils / serde / logging
serde.workspace              = true
serde_json.workspace         = true
anyhow.workspace             = true
thiserror.workspace          = true
once_cell.workspace          = true
dashmap.workspace            = true
tracing.workspace            = true
tracing-subscriber.workspace = true

# auth
jsonwebtoken.workspace       = true

# storage
sled.workspace               = true
deadpool-postgres.workspace  = true
tokio-postgres.workspace     = true
rusqlite.workspace           = true
r2d2_sqlite.workspace        = true

# crypto / codecs
hex.workspace                = true
base64.workspace             = true
bs58.workspace               = true
ed25519-dalek.workspace      = true
blake3.workspace             = true    # <— ДОБАВЛЕНО: bridge/gossip/producer используют blake3

# sync / net / metrics
parking_lot.workspace        = true
ipnet.workspace              = true
prometheus.workspace         = true

# локальное ядро L1
lrb_core = { path = "../lrb_core" }

[build-dependencies]
chrono = { version = "0.4", default-features = false, features = ["clock"] }

```


=== /root/logos_lrb/node/src/admin.rs ===

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


=== /root/logos_lrb/node/src/api.rs ===

```rust
//! LOGOS LRB — Public API (prod, Axum 0.7)

use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tracing::{info, warn, error};

use crate::state::AppState;

#[derive(Serialize)] pub struct OkMsg { pub status: &'static str }
#[derive(Serialize)] pub struct Head { pub height: u64 }
#[derive(Serialize)] pub struct Balance { pub rid: String, pub balance: u128, pub nonce: u64 }

#[derive(Deserialize)]
pub struct TxIn { pub from:String, pub to:String, pub amount:u64, pub nonce:u64, pub sig_hex:String, #[serde(default)] pub memo:Option<String> }

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

pub async fn submit_tx(State(app): State<Arc<AppState>>, Json(tx):Json<TxIn>) -> (StatusCode, Json<SubmitResult>) {
    let stx = match app.ledger.lock().submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.clone()) {
        Ok(s)=>s, Err(e)=>return (StatusCode::OK, Json(SubmitResult{ ok:false, txid:None, info:e.to_string() })),
    };
    if let Some(arch)=&app.archive {
        match arch.record_tx(&stx.txid, stx.height, &stx.from, &stx.to, stx.amount, stx.nonce, Some((stx.ts/1000) as u64)).await {
            Ok(()) => info!("archive: wrote tx {}", stx.txid),
            Err(e) => error!("archive: write failed: {}", e),
        }
    } else { warn!("archive: not configured"); }
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

// ---- Archive API ----
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

```


=== /root/logos_lrb/node/src/archive/mod.rs ===

```rust
//! LOGOS LRB — Archive (Postgres, prod-ready)
//! Env: LRB_ARCHIVE_URL=postgres://user:pass@host:5432/db
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;
use serde::Serialize;
use std::env;

#[derive(Clone)]
pub struct Archive { pool: Pool }

#[derive(Serialize)]
pub struct TxRecord {
    pub txid: String,
    pub height: i64,
    pub from: String,
    pub to: String,
    pub amount: i64,
    pub nonce: i64,
    pub ts: Option<i64>, // seconds
}

#[derive(Serialize)]
pub struct BlockRow {
    pub height: i64,
    pub hash: String,
    pub ts: i64,
    pub tx_count: i32,
}

impl Archive {
    pub async fn new_from_env() -> Option<Self> {
        let url = env::var("LRB_ARCHIVE_URL").ok()?;
        let mgr = Manager::from_config(url.parse().ok()?, NoTls, ManagerConfig{ recycling_method: RecyclingMethod::Fast });
        let pool = Pool::builder(mgr).max_size(16).build().ok()?;
        if pool.get().await.is_err() { return None; }
        Some(Self{ pool })
    }

    pub async fn record_block(&self, height:i64, hash:&str, ts:i64, tx_count:i32) -> anyhow::Result<()> {
        let c = self.pool.get().await?;
        c.execute(
            "INSERT INTO blocks(height,hash,ts_sec,tx_count)
             VALUES($1,$2,$3,$4)
             ON CONFLICT (height) DO UPDATE
             SET hash=EXCLUDED.hash, ts_sec=EXCLUDED.ts_sec, tx_count=EXCLUDED.tx_count",
            &[&height,&hash,&ts,&tx_count]).await?;
        Ok(())
    }

    pub async fn record_tx(&self, txid:&str, height:u64, from:&str, to:&str, amount:u64, nonce:u64, ts:Option<u64>) -> anyhow::Result<()> {
        let c = self.pool.get().await?;
        let ts_i: Option<i64> = ts.map(|v| v as i64);
        c.execute(
            "INSERT INTO tx(txid,height,rid_from,rid_to,amount,nonce,ts_sec)
             VALUES($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (txid) DO NOTHING",
            &[&txid,&(height as i64),&from,&to,&(amount as i64),&(nonce as i64),&ts_i]).await?;
        Ok(())
    }

    /// История по RID c пагинацией по высоте
    pub async fn history_by_rid(&self, rid:&str, limit:i64, before_height: Option<i64>) -> anyhow::Result<Vec<TxRecord>> {
        let c = self.pool.get().await?;
        let lim = if limit <= 0 { 100 } else { limit.min(500) };
        let rows = if let Some(bh) = before_height {
            c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE (rid_from=$1 OR rid_to=$1) AND height < $2
                 ORDER BY height DESC, ts_sec DESC NULLS LAST
                 LIMIT $3",
                &[&rid, &bh, &lim]
            ).await?
        } else {
            c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE rid_from=$1 OR rid_to=$1
                 ORDER BY height DESC, ts_sec DESC NULLS LAST
                 LIMIT $2",
                &[&rid, &lim]
            ).await?
        };
        Ok(rows.into_iter().map(|r| TxRecord{
            txid:   r.get(0),
            height: r.get(1),
            from:   r.get(2),
            to:     r.get(3),
            amount: r.get(4),
            nonce:  r.get(5),
            ts:     r.get(6),
        }).collect())
    }

    pub async fn recent_blocks(&self, limit:i64, before_height: Option<i64>) -> anyhow::Result<Vec<BlockRow>> {
        let c = self.pool.get().await?;
        let lim = if limit <= 0 { 50 } else { limit.min(200) };
        let rows = if let Some(bh) = before_height {
            c.query(
                "SELECT height,hash,ts_sec,tx_count
                 FROM blocks WHERE height < $1
                 ORDER BY height DESC
                 LIMIT $2",
                &[&bh,&lim]
            ).await?
        } else {
            c.query(
                "SELECT height,hash,ts_sec,tx_count
                 FROM blocks
                 ORDER BY height DESC
                 LIMIT $1",
                &[&lim]
            ).await?
        };
        Ok(rows.into_iter().map(|r| BlockRow{
            height: r.get(0),
            hash:   r.get(1),
            ts:     r.get(2),
            tx_count:r.get(3),
        }).collect())
    }

    pub async fn recent_txs(&self, limit:i64, rid: Option<&str>, before_ts: Option<i64>) -> anyhow::Result<Vec<TxRecord>> {
        let c = self.pool.get().await?;
        let lim = if limit <= 0 { 100 } else { limit.min(500) };
        let rows = match (rid,before_ts) {
            (Some(r),Some(ts)) => c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE (rid_from=$1 OR rid_to=$1) AND (ts_sec IS NULL OR ts_sec<$2)
                 ORDER BY ts_sec DESC NULLS LAST, height DESC LIMIT $3",
                &[&r,&ts,&lim]
            ).await?,
            (Some(r),None) => c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE rid_from=$1 OR rid_to=$1
                 ORDER BY ts_sec DESC NULLS LAST, height DESC LIMIT $2",
                &[&r,&lim]
            ).await?,
            (None,Some(ts)) => c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE (ts_sec IS NULL OR ts_sec<$1)
                 ORDER BY ts_sec DESC NULLS LAST, height DESC LIMIT $2",
                &[&ts,&lim]
            ).await?,
            (None,None) => c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx
                 ORDER BY ts_sec DESC NULLS LAST, height DESC LIMIT $1",
                &[&lim]
            ).await?,
        };
        Ok(rows.into_iter().map(|r| TxRecord{
            txid:   r.get(0),
            height: r.get(1),
            from:   r.get(2),
            to:     r.get(3),
            amount: r.get(4),
            nonce:  r.get(5),
            ts:     r.get(6),
        }).collect())
    }

    pub async fn tx_by_id(&self, txid:&str) -> anyhow::Result<Option<serde_json::Value>> {
        let c = self.pool.get().await?;
        let row = c.query_opt(
            "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
             FROM tx WHERE txid=$1",
            &[&txid]).await?;
        Ok(row.map(|r| serde_json::json!({
            "txid": r.get::<_,String>(0),
            "height": r.get::<_,i64>(1),
            "from": r.get::<_,String>(2),
            "to":   r.get::<_,String>(3),
            "amount": r.get::<_,i64>(4),
            "nonce":  r.get::<_,i64>(5),
            "ts":     r.get::<_,Option<i64>>(6),
        })))
    }

    pub async fn block_by_height(&self, h:i64) -> anyhow::Result<Option<BlockRow>> {
        let c = self.pool.get().await?;
        let row = c.query_opt(
            "SELECT height,hash,ts_sec,tx_count FROM blocks WHERE height=$1",
            &[&h]).await?;
        Ok(row.map(|r| BlockRow{
            height:r.get(0), hash:r.get(1), ts:r.get(2), tx_count:r.get(3)
        }))
    }
}

```


=== /root/logos_lrb/node/src/archive/pg.rs ===

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


=== /root/logos_lrb/node/src/archive/sqlite.rs ===

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


=== /root/logos_lrb/node/src/auth.rs ===

```rust
//! Auth-модуль: защита bridge/admin. Admin — только JWT (HS256). Bridge — X-Bridge-Key.
//! Обязательные переменные окружения: LRB_BRIDGE_KEY, LRB_JWT_SECRET.

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

fn forbid_default(val: &str) -> Result<()> {
    let low = val.to_lowercase();
    let banned = ["", "change_me", "changeme", "dev_secret", "default", "empty", "test", "123"];
    if banned.iter().any(|b| low == *b) {
        return Err(anyhow!("insecure default key"));
    }
    Ok(())
}

/* ---------------- Bridge (ключ обязателен) ---------------- */

pub fn require_bridge(headers: &HeaderMap) -> Result<()> {
    let expect = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY CHANGE_ME not set"))?;
    forbid_default(&expect)?;
    let got = headers
        .get("X-Bridge-Key")
        .ok_or_else(|| anyhow!("missing X-Bridge-Key"))?
        .to_str()
        .map_err(|_| anyhow!("invalid X-Bridge-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad bridge key")); }
    Ok(())
}

/* ---------------- Admin (только JWT HS256) ---------------- */

#[derive(Debug, Deserialize)]
struct AdminClaims {
    sub: String,
    iat: Option<u64>,
    exp: Option<u64>,
}

pub fn require_admin(headers: &HeaderMap) -> Result<()> {
    let token = headers
        .get("X-Admin-JWT")
        .ok_or_else(|| anyhow!("missing X-Admin-JWT"))?
        .to_str()
        .map_err(|_| anyhow!("invalid X-Admin-JWT"))?
        .to_string();

    let secret = std::env::var("LRB_JWT_SECRET").map_err(|_| anyhow!("LRB_JWT_SECRET CHANGE_ME not set"))?;
    forbid_default(&secret)?;

    let data = decode::<AdminClaims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| anyhow!("admin jwt invalid: {e}"))?;

    if data.claims.sub != "admin" {
        return Err(anyhow!("forbidden"));
    }
    Ok(())
}

/* ---------------- Стартовая проверка секретов ---------------- */

pub fn assert_secrets_on_start() -> Result<()> {
    // Bridge/JWT обязаны быть заданы. Если пусты — валим процесс.
    for (key, val) in [("LRB_BRIDGE_KEY","bridge"), ("LRB_JWT_SECRET","jwt")] {
        let v = std::env::var(key).map_err(|_| anyhow!("{key} is not set"))?;
        forbid_default(&v)?;
    }
    Ok(())
}

```


=== /root/logos_lrb/node/src/bridge.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/fork.rs ===

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


=== /root/logos_lrb/node/src/gossip.rs ===

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


=== /root/logos_lrb/node/src/guard.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/lib.rs ===

```rust
//! Библиотечная часть узла LOGOS: экспортируем AppState, auth и archive.
//! Нужна для случаев, когда crate собирается как `lib`.

pub mod state;
pub use state::AppState;

pub mod auth;
pub use auth::require_bridge;

// ВАЖНО: подключаем архив, чтобы `crate::archive::...` существовал и в lib-сборке.
pub mod archive;

```


=== /root/logos_lrb/node/src/main.rs ===

```rust
//! LOGOS LRB — node main (prod)
//! Axum REST + guard + metrics + archive (PG) + single-node producer + wallet/stake.

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
mod stake;     // <— стейкинг (submit/delegations/rewards)
mod wallet;    // <— регистрация pubkey (RID→pub_hex)
mod producer;  // <— single-node block producer (quorum=1)

fn router(app_state: Arc<state::AppState>) -> Router {
    Router::new()
        // --- public ---
        .route("/healthz", get(api::healthz))
        .route("/head",    get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx",    post(api::submit_tx))
        .route("/economy",      get(api::economy))
        .route("/history/:rid", get(api::history))
        // --- archive API (PG) ---
        .route("/archive/blocks", get(api::archive_blocks))
        .route("/archive/txs",    get(api::archive_txs))
        .route("/archive/history/:rid", get(api::archive_history))
        .route("/archive/tx/:txid",     get(api::archive_tx))
        // --- version / metrics / openapi ---
        .route("/version",     get(version::get))
        .route("/metrics",     get(metrics::prometheus))
        .route("/openapi.json",get(openapi::serve))
        // --- bridge (rTokens) ---
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem",  post(bridge::redeem))
        .route("/bridge/verify",  post(bridge::verify))
        // --- admin ---
        .route("/admin/set_balance", post(admin::set_balance))
        .route("/admin/bump_nonce",  post(admin::bump_nonce))
        .route("/admin/set_nonce",   post(admin::set_nonce))
        .route("/admin/mint",        post(admin::mint))
        .route("/admin/burn",        post(admin::burn))
        // --- wallet/stake (НОВОЕ) ---
        .merge(wallet::routes())
        .merge(stake::routes())
        // --- state & layers ---
        .with_state(app_state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(axum::middleware::from_fn(guard::rate_limit_mw)) // лимитер
                .layer(axum::middleware::from_fn(metrics::track))        // метрики
        )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ---- logging/tracing ----
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,axum::rejection=trace"))
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // ---- secrets sanity ----
    auth::assert_secrets_on_start().expect("unsafe or missing secrets");

    // ---- state ----
    let app_state = Arc::new(state::AppState::new()?);

    // ---- archive backend (PG/SQLite) ----
    if let Some(ar) = crate::archive::Archive::new_from_env().await {
        unsafe {
            let p = Arc::as_ptr(&app_state) as *mut state::AppState;
            (*p).archive = Some(ar);
        }
        info!("archive backend initialized");
    } else {
        warn!("archive disabled (no LRB_ARCHIVE_URL / LRB_ARCHIVE_PATH)");
    }

    // ---- single-node producer ----
    info!("producer: start");
    let _producer = producer::run(app_state.clone());

    // ---- bind / serve ----
    let addr = state::bind_addr();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("logos_node listening on {}", addr);
    axum::serve(listener, router(app_state)).await?;
    Ok(())
}

```


=== /root/logos_lrb/node/src/metrics.rs ===

```rust
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramVec, IntCounterVec, Registry, TextEncoder, register_histogram_vec, register_int_counter_vec,
};
use std::time::Instant;

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

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
        prometheus::exponential_buckets(0.001, 2.0, 14).unwrap() // 1ms..~16s
    ).unwrap()
});

/// Нормализация пути (убираем динамику)
fn normalize_path(p: &str) -> String {
    if p.starts_with("/balance/") { return "/balance/:rid".into(); }
    if p.starts_with("/history/") { return "/history/:rid".into(); }
    p.to_string()
}

/// Axum-middleware: считает per-route счётчики и latency
pub async fn track(req: Request<Body>, next: Next) -> axum::response::Response {
    let method = req.method().as_str().to_owned();
    let path = normalize_path(req.uri().path());
    let start = Instant::now();

    let res = next.run(req).await;
    let status = res.status().as_u16().to_string();

    HTTP_REQS.with_label_values(&[&method, &path, &status]).inc();
    HTTP_LATENCY.with_label_values(&[&method, &path, &status]).observe(start.elapsed().as_secs_f64());

    res
}

/// Exporter для Prometheus
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

/// Совместимость: старый inc_total был заглушкой — оставим no-op
pub fn inc_total(_label: &str) {}

```


=== /root/logos_lrb/node/src/openapi.rs ===

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


=== /root/logos_lrb/node/src/peers.rs ===

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


=== /root/logos_lrb/node/src/producer.rs ===

```rust
//! LOGOS LRB — single-node block producer (prod)
//! Slot-произведение блоков с детерминированным fork-choice (quorum=1):
//! - каждые SLOT_MS (env: LRB_SLOT_MS, по умолчанию 1000 мс) увеличиваем height на 1,
//! - new_hash = blake3(prev_hash | now_sec | height),
//! - set_head(height, hash) + set_finalized(height),
//! - если архив включён — пишем блок в PG (tx_count=0, ts_sec=now).
use std::{sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tokio::{task::JoinHandle, time::{self, Duration}};
use blake3::Hasher;
use tracing::{info, warn, error};

use crate::state::AppState;

fn slot_ms_from_env() -> u64 {
    std::env::var("LRB_SLOT_MS").ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&ms| ms >= 100)
        .unwrap_or(1000)
}

fn new_hash(prev_hash: &str, height: u64, now_sec: u64) -> String {
    let mut h = Hasher::new();
    h.update(prev_hash.as_bytes());
    h.update(&height.to_be_bytes());
    h.update(&now_sec.to_be_bytes());
    hex::encode(h.finalize().as_bytes())
}

pub fn run(app: Arc<AppState>) -> JoinHandle<()> {
    let slot = slot_ms_from_env();
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_millis(slot));
        loop {
            ticker.tick().await;

            // текущее время (секунды)
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // 1) читаем head
            let (cur_h, prev_hash) = {
                let l = app.ledger.lock();
                l.head().unwrap_or((0, String::new()))
            };

            // 2) детерминированный выбор и расчёт нового блока
            let next_h = cur_h.saturating_add(1);
            let prev = if prev_hash.is_empty() { "genesis" } else { &prev_hash };
            let hash = new_hash(prev, next_h, now_sec as u64);

            // 3) коммит head + финализация
            {
                let l = app.ledger.lock();
                if let Err(e) = l.set_head(next_h, &hash) {
                    error!("producer: set_head failed: {}", e);
                    continue;
                }
                if let Err(e) = l.set_finalized(next_h) {
                    warn!("producer: set_finalized failed: {}", e);
                }
            }

            // 4) запись блока в архив (PG)
            if let Some(arch) = &app.archive {
                if let Err(e) = arch.record_block(next_h as i64, &hash, now_sec as i64, 0).await {
                    warn!("producer: archive record_block failed: {}", e);
                }
            }

            info!("producer: new block height={} hash={}", next_h, &hash[..16]);
        }
    })
}

```


=== /root/logos_lrb/node/src/stake.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/state.rs ===

```rust
use std::{env, net::SocketAddr, str::FromStr};
use std::sync::Arc;
use parking_lot::Mutex;

use lrb_core::ledger::Ledger;

pub struct AppState {
    pub ledger: Arc<Mutex<Ledger>>,           // совместимо с api/admin
    pub db: sled::Db,                         // быстрый доступ сервисам
    pub archive: Option<crate::archive::Archive>,
}

impl AppState {
    pub fn new() -> anyhow::Result<Self> {
        let data_path = env::var("LRB_DATA_PATH")
            .or_else(|_| env::var("LRB_DATA_DIR").map(|p| format!("{}/data.sled", p)))
            .unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());

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

```


=== /root/logos_lrb/node/src/storage.rs ===

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


=== /root/logos_lrb/node/src/version.rs ===

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


=== /root/logos_lrb/node/src/wallet.rs ===

```rust
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

```


---

# 6. Web Wallet (PWA)



=== /root/logos_lrb/www/wallet/index.html ===

```html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>LOGOS Wallet</title>
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0"/>
  <style>
    :root{--bg:#0b0f14;--card:#0f1720;--line:#1f2a36;--txt:#e6edf3;--muted:#8aa0b8;--acc:#1d4ed8}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.45 system-ui,Inter,Arial}
    header{padding:18px;border-bottom:1px solid var(--line);font-weight:700}
    .wrap{max-width:980px;margin:18px auto;padding:0 16px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
    h2{margin:0 0 10px 0;font-size:16px}
    label{display:block;margin:10px 0 6px 2px;color:var(--muted);font-size:12px}
    input,button{height:40px;border-radius:10px;border:1px solid var(--line);background:#0c121a;color:var(--txt);padding:0 10px}
    button{cursor:pointer;background:#132037}
    .row{display:flex;gap:8px;align-items:center}
    .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
    .tabs{display:flex;gap:8px;margin-bottom:10px}
    .tab{padding:8px 12px;border:1px solid var(--line);border-radius:10px;background:#0c121a;cursor:pointer}
    .tab.active{background:#16263f}
    .hide{display:none}
    .ok{color:#30c175}.err{color:#f86a6a}
  </style>
</head>
<body>
<header class="wrap">LOGOS Wallet</header>

<div class="wrap">
  <!-- АВТОРИЗАЦИЯ + СОЗДАНИЕ -->
  <div class="grid">
    <section class="card">
      <h2>Вход в кошелёк</h2>
      <label>RID</label>
      <input id="loginRid" placeholder="Λ0@7.83Hzφ..."/>
      <label>Пароль (для расшифровки ключа)</label>
      <input id="loginPass" type="password" placeholder="••••••••"/>
      <div class="row" style="margin-top:10px">
        <button id="btnLogin">Войти</button>
        <span id="loginStatus" class="mono"></span>
      </div>
    </section>

    <section class="card">
      <h2>Создать новый кошелёк</h2>
      <label>Пароль (защита приватного ключа)</label>
      <input id="newPass" type="password" placeholder="мин. 8 символов"/>
      <div class="row" style="margin-top:10px">
        <button id="btnCreate">Создать</button>
        <span id="createStatus" class="mono"></span>
      </div>
      <small>Ключ хранится локально (IndexedDB + AES-GCM/PBKDF2). Данные не покидают устройство.</small>
    </section>
  </div>

  <!-- ПАНЕЛЬ КОШЕЛЬКА -->
  <section class="card" id="walletPanel" style="margin-top:16px;display:none">
    <div class="tabs">
      <div class="tab active" data-tab="send">Отправка</div>
      <div class="tab" data-tab="stake">Стейкинг</div>
      <div class="tab" data-tab="history">История</div>
      <div class="tab" data-tab="settings">Настройки</div>
    </div>

    <!-- SEND -->
    <div id="tab-send">
      <div class="row mono" style="margin-bottom:10px">
        <span>RID: <span id="ridView"></span></span>
        <span style="margin-left:auto">Баланс: <span id="balView">0</span></span>
        <span>Nonce: <span id="nonceView">0</span></span>
      </div>
      <label>Получатель (RID)</label>
      <input id="toRid" placeholder="RID получателя"/>
      <label>Сумма (микро-LGN)</label>
      <input id="amount" type="number" min="1" value="1234"/>
      <div class="row" style="margin-top:10px">
        <button id="btnSend">Отправить</button>
        <span id="sendStatus" class="mono"></span>
      </div>
    </div>

    <!-- STAKING -->
    <div id="tab-stake" class="hide">
      <div class="row mono" style="margin-bottom:10px">RID: <span id="ridStake"></span></div>
      <label>Валидатор (RID)</label>
      <input id="valRid" placeholder="RID валидатора"/>
      <label>Сумма (микро-LGN)</label>
      <input id="stakeAmt" type="number" min="1" value="100000"/>
      <div class="row" style="margin-top:8px">
        <button id="btnDelegate">Delegate</button>
        <button id="btnUndelegate">Undelegate</button>
        <button id="btnClaim">Claim</button>
      </div>
      <div class="mono" id="stakeStatus" style="margin-top:10px"></div>
    </div>

    <!-- HISTORY -->
    <div id="tab-history" class="hide">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr><th class="mono">txid</th><th class="mono">from</th><th class="mono">to</th><th>amt</th><th>height</th><th>ts</th></tr></thead>
        <tbody id="histBody"></tbody>
      </table>
      <div class="row" style="justify-content:center;margin-top:8px"><button id="btnMoreHist">Ещё</button></div>
    </div>

    <!-- SETTINGS -->
    <div id="tab-settings" class="hide">
      <div class="mono" id="settingsInfo"></div>
      <div class="row" style="margin-top:10px">
        <button id="btnExport">Экспорт (зашифр.)</button>
        <input type="file" id="impFile" style="display:none"/>
        <button id="btnImport">Импорт</button>
      </div>
      <div class="mono" id="exportStatus" style="margin-top:10px"></div>
    </div>
  </section>
</div>

<!-- Скрипты (CSP: только 'self') -->
<script src="wallet.js" defer></script>
<script src="staking.js" defer></script>
</body>
</html>

```


=== /root/logos_lrb/www/wallet/wallet.css ===

```css
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

```


=== /root/logos_lrb/www/wallet/wallet.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/staking.js ===

```javascript
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

```


---

# 7. Explorer



=== /root/logos_lrb/www/explorer/index.html ===

```html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>LOGOS LRB — Explorer</title>
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0"/>
  <style>
    :root{--bg:#0b0f14;--card:#0f1720;--line:#1f2a36;--muted:#8aa0b8;--txt:#e6edf3}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.45 system-ui,Inter,Arial}
    header{display:flex;gap:10px;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--line)}
    .pill{background:#0d1520;border:1px solid var(--line);border-radius:999px;padding:6px 10px}
    .wrap{max-width:1240px;margin:18px auto;padding:0 16px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{padding:10px;border-bottom:1px solid #1e2a3a;white-space:nowrap}
    thead th{background:#0f1723;color:#a8bdd9}
    .row{display:flex;gap:10px;align-items:center}
    .mono{font-family:ui-monospace,Menlo,Consolas,"SF Mono",monospace}
    .hash{max-width:220px;overflow:hidden;text-overflow:ellipsis}
    .btn{padding:6px 10px;border:1px solid var(--line);background:#0e1623;border-radius:10px;cursor:pointer}
    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    footer{max-width:1240px;color:var(--muted);margin:14px auto 24px;padding:0 16px}
    @media (max-width:1200px){ .wrap{grid-template-columns:1fr 1fr} }
    @media (max-width:760px){ .wrap{grid-template-columns:1fr} }
  </style>
</head>
<body>
<header>
  <strong>LOGOS LRB — Explorer</strong>
  <span class="pill">head: <span id="head">…</span></span>
  <span class="pill">tps: <span id="tps">0</span></span>
  <span class="pill">bps: <span id="bps">0</span></span>
</header>

<div class="wrap">

  <section class="card" style="grid-column:1/3">
    <h2>Последние блоки</h2>
    <table id="blocks"><thead><tr><th>height</th><th class="mono hash" title="hash">hash</th><th>txs</th><th>ts</th></tr></thead><tbody></tbody></table>
    <div class="row" style="justify-content:center;margin-top:8px"><button class="btn" id="moreBlocks">Ещё блоки</button></div>
  </section>

  <section class="card" style="grid-column:3/4">
    <h2>Экономика</h2>
    <div class="row mono" style="flex-wrap:wrap">
      <span>Cap:&nbsp;<span id="cap">0</span></span>
      <span>Minted:&nbsp;<span id="minted">0</span></span>
      <span>Burned:&nbsp;<span id="burned">0</span></span>
      <span>Supply:&nbsp;<span id="supply">0</span></span>
    </div>
    <div style="margin-top:12px;color:#9fb2ca">Обновляется при загрузке страницы</div>
  </section>

  <section class="card" style="grid-column:1/3">
    <h2>Последние транзакции</h2>
    <table id="txs"><thead><tr><th class="mono">txid</th><th class="mono">from</th><th class="mono">to</th><th>amt</th><th>height</th><th>ts</th></tr></thead><tbody></tbody></table>
    <div class="row" style="justify-content:center;margin-top:8px"><button class="btn" id="moreTxs">Ещё транзакции</button></div>
  </section>

  <section class="card">
    <h2>История адреса</h2>
    <div class="row"><input id="rid" placeholder="вставь RID" style="flex:1"/><button id="loadRid" class="btn">Загрузить</button></div>
    <table id="hist"><thead><tr><th class="mono">txid</th><th class="mono">from</th><th class="mono">to</th><th>amt</th><th>height</th><th>ts</th></tr></thead><tbody></tbody></table>
    <div class="row" style="justify-content:center;margin-top:8px"><button class="btn" id="moreHist">Ещё для RID</button></div>
  </section>

  <section class="card" style="grid-column:1/4">
    <h2>Поиск / карточки</h2>
    <div class="grid2">
      <div>
        <div class="row"><input id="txid" placeholder="txid" style="flex:1"/><button id="findTx" class="btn">Найти</button></div>
        <pre id="txView" class="mono" style="white-space:pre-wrap"></pre>
      </div>
      <div>
        <div class="row"><input id="height" placeholder="height" style="flex:1"/><button id="findBlock" class="btn">Показать</button></div>
        <pre id="blockView" class="mono" style="white-space:pre-wrap"></pre>
      </div>
    </div>
  </section>

</div>

<footer>
  <small>Подсказки: обновление head/tps/bps раз в 1 секунду; <span class="mono">RID/txid/height</span> работают из поиска.</small>
</footer>

<script>
const BASE = location.origin + '/api';
const S = {
  head:  document.getElementById('head'),
  tpsEl: document.getElementById('tps'),
  bpsEl: document.getElementById('bps'),
  blocksT: document.getElementById('blocks').querySelector('tbody'),
  txsT:    document.getElementById('txs').querySelector('tbody'),
  histT:   document.getElementById('hist').querySelector('tbody'),
  moreBlocks: document.getElementById('moreBlocks'),
  moreTxs:    document.getElementById('moreTxs'),
  moreHist:   document.getElementById('moreHist'),
  rid:   document.getElementById('rid'), loadRid: document.getElementById('loadRid'),
  txid:  document.getElementById('txid'),  findTx:  document.getElementById('findTx'),
  height:document.getElementById('height'),findBlock:document.getElementById('findBlock'),
  txView:document.getElementById('txView'), blockView:document.getElementById('blockView')
};

function ts(s){ if(s==null) return ''; const d=new Date(s*1000); return d.toISOString().replace('T',' ').slice(0,19); }
function mono(s,cut=18){ s=String(s); return s.length>cut ? s.slice(0,cut)+'…' : s; }

let curBlocks=null, curTxs=null, curHist=null;
let lastTxCount=0, lastBlocksHeight=0, lastTs=Date.now();

async function refreshHead(){
  try{
    const j = await (await fetch(`${BASE}/head`)).json();
    S.head.textContent = j.height ?? '??';
    const dt = (Date.now()-lastTs)/1000; if(dt<1) return;
    const curr = Number(j.height||0);
    const added = Math.max(0, curr - lastBlocksHeight);
    S.bpsEl.textContent = added.toFixed(0);
    lastBlocksHeight = curr;
    lastTs = Date.now();
  }catch(e){ S.head.textContent='?'; }
}

async function loadBlocksPage(){
  let url = `${BASE}/archive/blocks?limit=20`;
  if(curBlocks!=null) url += `&before_height=${curBlocks}`;
  const list = await (await fetch(url)).json();
  if(!Array.isArray(list) || list.length===0) return;
  curBlocks = Number(list[list.length-1].height) - 1;
  const frag = document.createDocumentFragment();
  for(const b of list){
    const tr=document.createElement('tr');
    tr.innerHTML = `<td class="mono">${b.height}</td><td class="mono hash" title="${b.block_hash}">${mono(b.block_hash,22)}</td><td>${b.tx_count}</td><td>${ts(b.ts_sec)}</td>`;
    frag.appendChild(tr);
  }
  S.blocksT.appendChild(frag);
}

async function loadTxsPage(){
  let url = `${BASE}/archive/txs?limit=25`;
  if(curTxs!=null) url += `&before_ts=${curTxs}`;
  const list = await (await fetch(url)).json();
  if(!Array.isArray(list) || list.length===0) return;
  curTxs = list[list.length-1].ts ?? curTxs;
  const frag = document.createDocumentFragment();
  for(const t of list){
    const tr=document.createElement('tr');
    tr.innerHTML = `<td class="mono hash" title="${t.txid}">${mono(t.txid,22)}</td><td class="mono">${t.from}</td><td class="mono">${t.to}</td><td>${t.amount}</td><td>${t.height}</td><td>${ts(t.ts)}</td>`;
    frag.appendChild(tr);
  }
  S.txsT.appendChild(frag);
}

async function loadHistoryPage(rid){
  let url = `${BASE}/archive/history/${encodeURIComponent(rid)}`;
  if(curHist!=null) url += `?before_height=${curHist}`;
  const list = await (await fetch(url)).json();
  if(!Array.isArray(list) || list.length===0) return;
  curHist = Number(list[list.length-1].height) - 1;
  const frag = document.createDocumentFragment();
  for(const t of list){
    const tr=document.createElement('tr');
    tr.innerHTML = `<td class="mono hash" title="${t.txid}">${mono(t.txid,22)}</td><td class="mono">${t.from}</td><td class="mono">${t.to}</td><td>${t.amount}</td><td>${t.height}</td><td>${ts(t.ts)}</td>`;
    frag.appendChild(tr);
  }
  S.histT.appendChild(frag);
}

S.loadRid.onclick = ()=>{ S.histT.innerHTML=''; curHist=null; const v=S.rid.value.trim(); if(v) loadHistoryPage(v); };
S.findTx.onclick  = async ()=>{ const id=S.txid.value.trim(); if(!id) return; S.txView.textContent = JSON.stringify(await (await fetch(`${BASE}/archive/tx/${encodeURIComponent(id)}`)).json(), null, 2); };
S.findBlock.onclick = async ()=>{ const h=Number(S.height.value.trim()); if(!h) return; S.blockView.textContent = JSON.stringify(await (await fetch(`${BASE}/archive/block/${h}`)).json(), null, 2); };
S.moreBlocks.onclick = ()=> loadBlocksPage();
S.moreTxs.onclick    = ()=> loadTxsPage();
S.moreHist.onclick   = ()=>{ const v=S.rid.value.trim(); if(v) loadHistoryPage(v); };

async function econ(){
  try{
    const j = await (await fetch(`${BASE}/economy`)).json();
    (document.getElementById('cap')||{}).textContent    = j.cap ?? 0;
    (document.getElementById('minted')||{}).textContent = j.minted ?? 0;
    (document.getElementById('burned')||{}).textContent = j.burned ?? 0;
    (document.getElementById('supply')||{}).textContent = j.supply ?? 0;
  }catch{}
}

async function bootstrap(){
  await econ();
  await loadBlocksPage();
  await loadTxsPage();
  setInterval(refreshHead, 1000);
}
bootstrap();
</script>
</body>
</html>

```


---

# 8. Nginx конфиг



=== /etc/nginx/conf.d/logos.conf ===

```nginx
server { listen 80; server_name _; return 301 https://$host$request_uri; }

server {
  listen 443 ssl http2;
  server_name 45-159-248-232.sslip.io;

  ssl_certificate     /etc/letsencrypt/live/<YOUR_DOMAIN>/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/<YOUR_DOMAIN>/privkey.pem;

  root /opt/logos/www; index index.html;

  # --- API ---
  location /api/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
  }

  # --- Wallet (PWA) ---
  location /wallet/ {
    try_files $uri /wallet/index.html;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'self';" always;
    add_header Cache-Control "no-store" always;
  }

  # --- Explorer (ОДИН блок, без дублей) ---
  location /explorer/ {
    try_files $uri /explorer/index.html;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self';" always;
    add_header Cache-Control "no-store" always;
  }

  # статика (не кэшируем при разработке)
  location ~* \.(?:css|js|ico|png|jpg|jpeg|svg|woff2?)$ {
    try_files $uri =404;
    add_header Cache-Control "no-store" always;
  }

  location / {
    try_files $uri /index.html;
    add_header Cache-Control "no-store" always;
  }
}

```


---

# 9. Systemd (unit + drop-ins)



=== systemctl cat logos-node ===

```text
# /etc/systemd/system/logos-node.service
[Unit]
Description=LOGOS LRB Node (Axum REST on :8080)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos
ExecStart=/opt/logos/bin/logos_node
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/logos-node.service.d/archive.conf
[Service]
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos

# /etc/systemd/system/logos-node.service.d/cors.conf
[Service]
Environment=LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io

# /etc/systemd/system/logos-node.service.d/data.conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled

# /etc/systemd/system/logos-node.service.d/exec.conf
[Service]
ExecStart=
ExecStart=/opt/logos/bin/logos_node
WorkingDirectory=/opt/logos

# /etc/systemd/system/logos-node.service.d/faucet.conf
[Service]
Environment=LRB_ENABLE_FAUCET=1

# /etc/systemd/system/logos-node.service.d/hardening.conf
[Service]
# Ресурсы
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
MemoryMax=2G
CPUQuota=200%

# Sandbox/защиты
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service @network-io

# /etc/systemd/system/logos-node.service.d/keys.conf
[Service]
EnvironmentFile=/etc/logos/keys.env

# /etc/systemd/system/logos-node.service.d/loglevel.conf
[Service]
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/paths.conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

# /etc/systemd/system/logos-node.service.d/phasemix.conf
[Service]
Environment=LRB_PHASEMIX_ENABLE=1

# /etc/systemd/system/logos-node.service.d/ratelimit.conf
[Service]
Environment=LRB_RATE_QPS=30
Environment=LRB_RATE_BURST=60
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

# /etc/systemd/system/logos-node.service.d/ratelimit_bypass.conf
[Service]
Environment=LRB_RATE_BYPASS_CIDR=0.0.0.0/0

# /etc/systemd/system/logos-node.service.d/runas.conf
[Service]
User=logos
Group=logos
# Разрешаем запись туда, где нужно (данные/секреты)
ReadWritePaths=/var/lib/logos /etc/logos

# /etc/systemd/system/logos-node.service.d/security.conf
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true

# /etc/systemd/system/logos-node.service.d/tuning.conf
[Service]
Environment=LRB_NODE_LISTEN=0.0.0.0:8080
Environment=LRB_DATA_DIR=/var/lib/logos
Environment=LRB_WALLET_ORIGIN=http://127.0.0.1
Environment=LRB_RATE_QPS=20
Environment=LRB_RATE_BURST=40
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/zz-consensus.conf
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

# /etc/systemd/system/logos-node.service.d/zz-logging.conf
[Service]
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


=== /etc/systemd/system/logos-node.service.d/archive.conf ===

```nginx
[Service]
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos

```


=== /etc/systemd/system/logos-node.service.d/cors.conf ===

```nginx
[Service]
Environment=LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io

```


=== /etc/systemd/system/logos-node.service.d/data.conf ===

```nginx
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled

```


=== /etc/systemd/system/logos-node.service.d/exec.conf ===

```nginx
[Service]
ExecStart=
ExecStart=/opt/logos/bin/logos_node
WorkingDirectory=/opt/logos

```


=== /etc/systemd/system/logos-node.service.d/faucet.conf ===

```nginx
[Service]
Environment=LRB_ENABLE_FAUCET=1

```


=== /etc/systemd/system/logos-node.service.d/hardening.conf ===

```nginx
[Service]
# Ресурсы
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
MemoryMax=2G
CPUQuota=200%

# Sandbox/защиты
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service @network-io

```


=== /etc/systemd/system/logos-node.service.d/keys.conf ===

```nginx
[Service]
EnvironmentFile=/etc/logos/keys.env

```


=== /etc/systemd/system/logos-node.service.d/loglevel.conf ===

```nginx
[Service]
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/paths.conf ===

```nginx
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

```


=== /etc/systemd/system/logos-node.service.d/phasemix.conf ===

```nginx
[Service]
Environment=LRB_PHASEMIX_ENABLE=1

```


=== /etc/systemd/system/logos-node.service.d/ratelimit_bypass.conf ===

```nginx
[Service]
Environment=LRB_RATE_BYPASS_CIDR=0.0.0.0/0

```


=== /etc/systemd/system/logos-node.service.d/ratelimit.conf ===

```nginx
[Service]
Environment=LRB_RATE_QPS=30
Environment=LRB_RATE_BURST=60
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

```


=== /etc/systemd/system/logos-node.service.d/runas.conf ===

```nginx
[Service]
User=logos
Group=logos
# Разрешаем запись туда, где нужно (данные/секреты)
ReadWritePaths=/var/lib/logos /etc/logos

```


=== /etc/systemd/system/logos-node.service.d/security.conf ===

```nginx
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true

```


=== /etc/systemd/system/logos-node.service.d/tuning.conf ===

```nginx
[Service]
Environment=LRB_NODE_LISTEN=0.0.0.0:8080
Environment=LRB_DATA_DIR=/var/lib/logos
Environment=LRB_WALLET_ORIGIN=http://127.0.0.1
Environment=LRB_RATE_QPS=20
Environment=LRB_RATE_BURST=40
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/zz-consensus.conf ===

```nginx
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

```


=== /etc/systemd/system/logos-node.service.d/zz-keys.conf.disabled ===

```text
[Service]
# Читаем файл с секретами (на будущее, если захочешь использовать keys.env)
EnvironmentFile=-/etc/logos/keys.env

# Узловые параметры (жёстко, чтобы сервис точно стартовал)
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_SK_HEX=31962399e9b0e278af3b328bc6e30bbd17d90c700a5f6c7ad3c4d4418ed8fd83
Environment=LRB_ADMIN_KEY=0448012cf1738fd048b154a1c367cb7cb42e3fee4ab26fb04268ab91e09fb475
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


=== /etc/systemd/system/logos-node.service.d/zz-logging.conf ===

```nginx
[Service]
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf ===

```nginx
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


---

# 10. Бэкап sled



=== /usr/local/bin/logos-sled-backup.sh ===

```bash
#!/usr/bin/env bash
set -euo pipefail

SRC="/var/lib/logos/data.sled"
DST="/root/sled_backups"
KEEP=96          # ~24 часа при шаге 15 минут
MAX_GB=20        # общий лимит в гигабайтах

TS="$(date -Iseconds)"
mkdir -p "$DST"

# 1) инкрементальный снапшот (rsync в новую папку)
rsync -a --delete "$SRC/" "$DST/data.sled.$TS.bak/"

# 2) ротация по количеству
mapfile -t LIST < <(ls -1dt "$DST"/data.sled.*.bak 2>/dev/null || true)
if (( ${#LIST[@]} > KEEP )); then
  for d in "${LIST[@]:$KEEP}"; do
    rm -rf -- "$d" || true
  done
fi

# 3) ротация по общему размеру
du_mb() { du -sm "$DST" | awk '{print $1}'; }
while (( $(du_mb) > MAX_GB*1024 )); do
  OLDEST="$(ls -1dt "$DST"/data.sled.*.bak | tail -n 1 || true)"
  [[ -n "$OLDEST" ]] || break
  rm -rf -- "$OLDEST" || true
done

```


=== /etc/systemd/system/logos-sled-backup.service ===

```ini
[Unit]
Description=Backup sled to /root/sled_backups

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/logos-sled-backup.sh

```


=== /etc/systemd/system/logos-sled-backup.timer ===

```ini
[Unit]
Description=Run sled backup every 15 minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
Unit=logos-sled-backup.service

[Install]
WantedBy=timers.target

```


---

# 11. Prometheus/Grafana (alerts)



=== /etc/prometheus/rules/logos_alerts.yml ===

```yaml
groups:
- name: logos-runtime
  rules:
  - alert: HeightStuck
    expr: increase(logos_head_height[5m]) == 0
    for: 3m
    labels: { severity: critical }
    annotations: { summary: "Head не растёт 5 минут" }

  - alert: HighLatencyP99
    expr: histogram_quantile(0.99, sum(rate(http_request_duration_ms_bucket[5m])) by (le)) > 120
    for: 2m
    labels: { severity: warning }
    annotations: { summary: "p99 HTTP > 120 ms" }

  - alert: TLSExpirySoon
    expr: (probe_ssl_earliest_cert_expiry - time()) < 14*24*3600
    for: 10m
    labels: { severity: warning }
    annotations: { summary: "TLS сертификат истекает < 14 дней" }

```


---

# 12. Конфиги



=== /root/logos_lrb/configs/genesis.yaml ===

```yaml
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

```


=== /root/logos_lrb/configs/logos_config.yaml ===

```yaml
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

```


---

# 13. OpenAPI контракт



=== GET /openapi.json ===

```text
{
  "openapi": "3.0.3",
  "info": { "title": "LOGOS LRB — Core API", "version": "0.1.0", "description": "Public & Admin API for LOGOS LRB (strict CSP, JWT admin, rTokens, staking)." },
  "servers": [{ "url": "https://45-159-248-232.sslip.io" }],
  "paths": {
    "/healthz": { "get": { "summary": "Healthcheck", "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/OkMsg" }}}}}}},
    "/head":    { "get": { "summary": "Chain head",  "responses": { "200": { "description": "Head", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Head" }}}}}}},
    "/balance/{rid}": {
      "get": {
        "summary": "Account balance & nonce",
        "parameters": [{ "name":"rid","in":"path","required":true,"schema":{"type":"string"}}],
        "responses": { "200": { "description": "Balance", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Balance" }}}}}
      }
    },
    "/submit_tx": {
      "post": {
        "summary": "Submit transaction",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref":"#/components/schemas/TxIn" }}}},
        "responses": { "200": { "description": "Result", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitResult" }}}}}
      }
    },
    "/economy": { "get": { "summary": "Economy snapshot", "responses": { "200": { "description": "Economy", "content": { "application/json": { "schema": { "$ref":"#/components/schemas/Economy" }}}}}}},
    "/history/{rid}": {
      "get": {
        "summary": "History by RID (sled index)",
        "parameters": [{ "name":"rid","in":"path","required":true,"schema":{"type":"string"}}],
        "responses": { "200": { "description": "History", "content": { "application/json": { "schema": { "type":"array","items":{"$ref":"#/components/schemas/HistoryItem"} }}}}}
      }
    },

    "/stake/submit":      { "post": { "summary":"Submit staking op", "requestBody":{ "required":true, "content":{"application/json":{"schema":{"$ref":"#/components/schemas/StakeTxIn"}}}}, "responses":{ "200":{ "description":"Result", "content":{ "application/json":{ "schema":{"$ref":"#/components/schemas/SubmitResult"}}}}}}},
    "/stake/validators":  { "get":  { "summary":"List validators", "responses":{ "200":{ "description":"OK", "content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/ValidatorInfo"}}}}}}}},
    "/stake/delegations/{rid}": { "get": { "summary":"Delegations of RID", "parameters":[{ "name":"rid","in":"path","required":true,"schema":{"type":"string"}}], "responses":{ "200":{ "description":"OK", "content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/DelegationInfo"}}}}}}}},
    "/stake/rewards/{rid}":     { "get": { "summary":"Rewards of RID",     "parameters":[{ "name":"rid","in":"path","required":true,"schema":{"type":"string"}}], "responses":{ "200":{ "description":"OK", "content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/RewardInfo"}}}}}}}},
    "/stake/params":      { "get":  { "summary":"Stake parameters", "responses":{ "200":{ "description":"OK", "content":{"application/json":{"schema":{"$ref":"#/components/schemas/StakeParams"}}}}}}},

    "/admin/set_balance": { "post": { "summary":"Set balance (admin)", "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/SetBalanceReq"}}}}, "responses":{"200":{"description":"OK"}}}},
    "/admin/set_nonce":   { "post": { "summary":"Set nonce (admin)",   "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/SetNonceReq"}}}},   "responses":{"200":{"description":"OK"}}}},
    "/admin/bump_nonce":  { "post": { "summary":"Bump nonce (admin)",  "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/BumpNonceReq"}}}}, "responses":{"200":{"description":"OK"}}}},
    "/admin/mint":        { "post": { "summary":"Add minted amount (admin)", "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/MintReq"}}}}, "responses":{"200":{"description":"OK"}}}},
    "/admin/burn":        { "post": { "summary":"Add burned amount (admin)", "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/BurnReq"}}}}, "responses":{"200":{"description":"OK"}}}}
  },
  "components": {
    "securitySchemes": {
      "AdminJWT":  { "type":"apiKey", "in":"header", "name":"X-Admin-JWT" },
      "BridgeKey": { "type":"apiKey", "in":"header", "name":"X-Bridge-Key" }
    },
    "schemas": {
      "OkMsg": { "type":"object", "properties": { "status": { "type":"string" } } },
      "Head":  { "type":"object", "properties": { "height": { "type":"integer" } }, "required": ["height"] },
      "Balance": { "type":"object", "properties": { "rid":{"type":"string"}, "balance":{"type":"string"}, "nonce":{"type":"integer"} }, "required":["rid","balance","nonce"] },
      "TxIn": { "type":"object", "properties": { "from":{"type":"string"}, "to":{"type":"string"}, "amount":{"type":"integer","format":"uint64"}, "nonce":{"type":"integer","format":"uint64"}, "memo":{"type":"string","nullable":true}, "sig_hex":{"type":"string"} }, "required":["from","to","amount","nonce","sig_hex"] },
      "SubmitResult": { "type":"object", "properties": { "ok":{"type":"boolean"}, "txid":{"type":"string","nullable":true}, "info":{"type":"string"} }, "required":["ok","info"] },
      "Economy": { "type":"object", "properties": { "supply":{"type":"integer"}, "burned":{"type":"integer"}, "cap":{"type":"integer"} }, "required":["supply","burned","cap"] },
      "HistoryItem": { "type":"object", "properties": { "txid":{"type":"string"}, "height":{"type":"integer"}, "from":{"type":"string"}, "to":{"type":"string"}, "amount":{"type":"integer"}, "nonce":{"type":"integer"} }, "required":["txid","height","from","to","amount","nonce"] },

      "StakeTxIn": { "type":"object", "required":["from","op","nonce","sig_hex"], "properties": { "from":{"type":"string"}, "op":{"type":"string","enum":["delegate","undelegate","claim"]}, "validator":{"type":"string"}, "amount":{"type":"integer","format":"uint64"}, "nonce":{"type":"integer","format":"uint64"}, "sig_hex":{"type":"string"}, "memo":{"type":"string"} } },
      "ValidatorInfo": { "type":"object", "properties": { "rid":{"type":"string"}, "commission_bps":{"type":"integer"}, "self_bond":{"type":"integer"}, "voting_power":{"type":"integer"}, "status":{"type":"string"} } },
      "DelegationInfo": { "type":"object", "properties": { "validator":{"type":"string"}, "amount":{"type":"integer"}, "since_height":{"type":"integer"} } },
      "RewardInfo": { "type":"object", "properties": { "validator":{"type":"string"}, "pending":{"type":"integer"}, "last_height":{"type":"integer"} } },
      "StakeParams": { "type":"object", "properties": { "min_delegate":{"type":"integer"}, "unbond_period_blocks":{"type":"integer"}, "apr_estimate_bps":{"type":"integer"} } },

      "SetBalanceReq": { "type":"object", "properties": { "rid":{"type":"string"}, "amount":{"type":"integer"} }, "required":["rid","amount"] },
      "SetNonceReq":   { "type":"object", "properties": { "rid":{"type":"string"}, "value":{"type":"integer"} }, "required":["rid","value"] },
      "BumpNonceReq":  { "type":"object", "properties": { "rid":{"type":"string"} }, "required":["rid"] },
      "MintReq":       { "type":"object", "properties": { "amount":{"type":"integer"} }, "required":["amount"] },
      "BurnReq":       { "type":"object", "properties": { "amount":{"type":"integer"} }, "required":["amount"] }
    }
  }
}

```


---

# 14. Bootstrap на новом сервере (шаги)


### Ubuntu 22.04/24.04 (root)
```bash
apt update && apt install -y curl git jq build-essential pkg-config libssl-dev \
  nginx postgresql postgresql-contrib rsync

curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. $HOME/.cargo/env

git clone https://github.com/Lgn-rsp/logos_lrb.git /root/logos_lrb
cd /root/logos_lrb

# По канону вставляем файлы из этой книги (см. главы 3–13):
# cd → rm -f → nano → вставить контент блока === <path> === → сохранить

sudo mkdir -p /etc/systemd/system/logos-node.service.d
sudo tee /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf >/dev/null <<EOF
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME
EOF
sudo tee /etc/systemd/system/logos-node.service.d/paths.conf >/dev/null <<EOF
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key
EOF
sudo systemctl daemon-reload

cargo build --release -p logos_node
install -m 0755 target/release/logos_node /opt/logos/bin/logos_node
sudo chown logos:logos /opt/logos/bin/logos_node
sudo systemctl restart logos-node
sleep 1
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo

nginx -t && systemctl reload nginx
```

---

# 15. Канон проверки


```bash
journalctl -u logos-node -n 120 --no-pager | egrep -i "listening|panic|error" || true
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo
curl -s http://127.0.0.1:8080/economy | jq
curl -s "http://127.0.0.1:8080/archive/blocks?limit=3" | jq
curl -s "http://127.0.0.1:8080/archive/txs?limit=3"    | jq
```

---

# Конец книги



---

# 2. Версии и окружение



=== rustc --version ===

```text
rustc 1.89.0 (29483883e 2025-08-04)

```


=== cargo --version ===

```text
cargo 1.89.0 (c24e10642 2025-06-23)

```


=== nginx -v ===

```text
nginx version: nginx/1.24.0 (Ubuntu)

```


=== psql --version ===

```text
psql (PostgreSQL) 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)

```


=== systemd env ===

```text
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos
LRB_WALLET_ORIGIN=http://127.0.0.1
LRB_DATA_PATH=/var/lib/logos/data.sled
LRB_ENABLE_FAUCET=1
RUST_LOG=info
LRB_NODE_KEY_PATH=/var/lib/logos/node_key
LRB_PHASEMIX_ENABLE=1
LRB_RATE_QPS=20
LRB_RATE_BURST=40
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_DATA_DIR=/var/lib/logos
LRB_SLOT_MS=200
LRB_MAX_BLOCK_TX=10000
LRB_MEMPOOL_CAP=100000
LRB_MAX_AMOUNT=18446744073709551615
LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
LRB_QUORUM_N=1
LRB_JWT_SECRET=CHANGE_ME
LRB_BRIDGE_KEY=CHANGE_ME

```


---

# 3. Cargo workspace



=== /root/logos_lrb/Cargo.toml ===

```toml
[workspace]
members  = ["lrb_core", "node"]
resolver = "2"

[workspace.package]
edition      = "2021"
rust-version = "1.78"

[workspace.dependencies]
# web / async
axum       = { version = "0.7.9", features = ["macros", "json"] }
tower      = "0.4.13"
tower-http = { version = "0.5.2", features = ["trace", "cors", "compression-gzip"] }
tokio      = { version = "1.40", features = ["full"] }
reqwest    = { version = "0.12", default-features = false, features = ["rustls-tls", "http2", "json"] }

# utils / serde / logging
serde               = { version = "1.0", features = ["derive"] }
serde_json          = "1.0"
anyhow              = "1.0"
thiserror           = "1.0"
once_cell           = "1.19"
dashmap             = "5.5"
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["env-filter", "fmt"] }
bytes               = "1.6"

# crypto / hash / codecs
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

# storage / sql / pg
sled             = "0.34"
deadpool-postgres= "0.12"
tokio-postgres   = { version = "0.7", features = ["with-uuid-1"] }
rusqlite         = { version = "0.32", features = ["bundled"] }
r2d2_sqlite      = "0.25"

# sync / net / metrics
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

```


---

# 4. lrb_core (исходники + Cargo)



=== /root/logos_lrb/lrb_core/Cargo.toml ===

```toml
[package]
name        = "lrb_core"
version     = "0.1.0"
edition     = "2021"
license     = "Apache-2.0"
description = "LOGOS LRB core (ledger, mempool, filters, RCP engine)"

[lib]
name = "lrb_core"
path = "src/lib.rs"

[dependencies]
# из workspace
serde.workspace        = true
serde_json.workspace   = true
anyhow.workspace       = true
thiserror.workspace    = true
once_cell.workspace    = true

tokio.workspace        = true
reqwest.workspace      = true
bytes.workspace        = true

hex.workspace          = true
base64.workspace       = true
bs58.workspace         = true
sha2.workspace         = true
blake3.workspace       = true
ed25519-dalek.workspace= true
rand.workspace         = true
ring.workspace         = true
uuid.workspace         = true
bincode.workspace      = true

sled.workspace         = true

```


=== /root/logos_lrb/lrb_core/src/anti_replay.rs ===

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


=== /root/logos_lrb/lrb_core/src/beacon.rs ===

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


=== /root/logos_lrb/lrb_core/src/crypto.rs ===

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


=== /root/logos_lrb/lrb_core/src/dynamic_balance.rs ===

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


=== /root/logos_lrb/lrb_core/src/heartbeat.rs ===

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


=== /root/logos_lrb/lrb_core/src/ledger.rs ===

```rust
use sled::{Db, Tree};
use std::{convert::TryInto, path::Path, time::{SystemTime, UNIX_EPOCH}};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};

use crate::types::*;

// helpers
#[inline] fn be64(v: u64) -> [u8; 8] { v.to_be_bytes() }
#[inline] fn be32(v: u32) -> [u8; 4] { v.to_be_bytes() }
#[inline] fn k_bal(r:&str)->Vec<u8>{format!("bal:{r}").into_bytes()}
#[inline] fn k_nonce(r:&str)->Vec<u8>{format!("nonce:{r}").into_bytes()}

const K_HEAD:      &[u8] = b"h";    // u64
const K_HEAD_HASH: &[u8] = b"hh";   // utf8
const K_FINAL:     &[u8] = b"fin";  // u64
const K_MINTED:    &[u8] = b"mint"; // u64
const K_BURNED:    &[u8] = b"burn"; // u64

#[derive(Clone)]
pub struct Ledger {
    db: Db,
    // trees
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

impl Ledger {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
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

    /// Доступ к sled::Db для сервисных модулей узла
    #[inline] pub fn db(&self) -> &sled::Db { &self.db }

    // ====== ожидаемые узлом методы ======
    pub fn height(&self) -> anyhow::Result<u64> {
        Ok(self.head.get(K_HEAD)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0))
    }
    pub fn head(&self) -> anyhow::Result<(u64, String)> {
        let h  = self.height().unwrap_or(0);
        let hh = self.head.get(K_HEAD_HASH)?.map(|v| String::from_utf8(v.to_vec()).unwrap()).unwrap_or_default();
        Ok((h, hh))
    }
    pub fn set_head(&self, height:u64, hash:&str) -> anyhow::Result<()> {
        self.head.insert(K_HEAD, &be64(height))?;
        self.head.insert(K_HEAD_HASH, hash.as_bytes())?;
        Ok(())
    }
    pub fn set_finalized(&self, height:u64) -> anyhow::Result<()> {
        self.head.insert(K_FINAL, &be64(height))?; Ok(())
    }

    pub fn supply(&self) -> anyhow::Result<(u64,u64)> {
        let minted = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let burned = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        Ok((minted, burned))
    }
    pub fn add_minted(&self, amount:u64) -> anyhow::Result<u64> {
        let cur = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let newv = cur.saturating_add(amount);
        self.head.insert(K_MINTED, &be64(newv))?; Ok(newv)
    }
    pub fn add_burned(&self, amount:u64) -> anyhow::Result<u64> {
        let cur = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let newv = cur.saturating_add(amount);
        self.head.insert(K_BURNED, &be64(newv))?; Ok(newv)
    }

    pub fn get_balance(&self, rid:&str) -> anyhow::Result<u64> {
        Ok(self.db.get(k_bal(rid))?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
            .unwrap_or(0))
    }
    pub fn set_balance(&self, rid:&str, amount_u128:u128) -> anyhow::Result<()> {
        let amount: u64 = amount_u128.try_into().map_err(|_| anyhow::anyhow!("amount too large"))?;
        self.db.insert(k_bal(rid), &be64(amount))?; Ok(())
    }

    pub fn get_nonce(&self, rid:&str) -> anyhow::Result<u64> {
        Ok(self.db.get(k_nonce(rid))?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
            .unwrap_or(0))
    }
    pub fn set_nonce(&self, rid:&str, value:u64) -> anyhow::Result<()> {
        self.db.insert(k_nonce(rid), &be64(value))?; Ok(())
    }
    pub fn bump_nonce(&self, rid:&str) -> anyhow::Result<u64> {
        let cur = self.get_nonce(rid)?;
        let next = cur.saturating_add(1);
        self.set_nonce(rid, next)?; Ok(next)
    }

    /// Упрощённый перевод для REST `/submit_tx`
    pub fn submit_tx_simple(&self, from:&str, to:&str, amount:u64, nonce:u64, _memo:Option<String>) -> anyhow::Result<StoredTx> {
        let from_bal = self.get_balance(from)?;
        if from_bal < amount { anyhow::bail!("insufficient funds"); }
        let to_bal = self.get_balance(to)?;

        self.set_balance(from, (from_bal - amount) as u128)?;
        self.set_balance(to,   to_bal.saturating_add(amount) as u128)?;
        self.set_nonce(from, nonce)?;

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

    /// История аккаунта — возвращаем сразу `Vec<StoredTx>`
    pub fn account_txs_page(&self, rid:&str, _cursor_usize:usize, limit:usize) -> anyhow::Result<Vec<StoredTx>> {
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

    pub fn get_tx(&self, txid:&str)-> anyhow::Result<Option<StoredTx>> {
        let mut k=Vec::with_capacity(1+txid.len()); k.extend_from_slice(b"t"); k.extend_from_slice(txid.as_bytes());
        Ok(self.txs.get(k)?.map(|v| serde_json::from_slice::<StoredTx>(&v)).transpose()?)
    }

    // ====== для rcp_engine.rs ======
    pub fn index_block(&self, height: u64, hash: &str, ts: u128, txs: &[Tx]) -> anyhow::Result<()> {
        let mut ids = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            let mut h=Sha256::new();
            h.update(tx.from.0.as_bytes()); h.update(b"|");
            h.update(tx.to.0.as_bytes());   h.update(b"|");
            h.update(&tx.amount.to_be_bytes()); h.update(b"|");
            h.update(&tx.nonce.to_be_bytes());
            let txid = hex::encode(h.finalize());
            ids.push(txid.clone());

            let stx = StoredTx{
                txid: txid.clone(), from: tx.from.0.clone(), to: tx.to.0.clone(),
                amount: tx.amount, nonce: tx.nonce, height, index: i as u32, ts,
            };

            let mut k_tx=Vec::with_capacity(1+txid.len()); k_tx.extend_from_slice(b"t"); k_tx.extend_from_slice(txid.as_bytes());
            self.txs.insert(k_tx, serde_json::to_vec(&stx)?)?;

            let mut k_af=Vec::new(); k_af.extend_from_slice(b"a"); k_af.extend_from_slice(tx.from.0.as_bytes()); k_af.push(b'|'); k_af.extend_from_slice(&be64(height)); k_af.extend_from_slice(&be32(i as u32));
            self.acct.insert(k_af, txid.as_bytes())?;
            let mut k_at=Vec::new(); k_at.extend_from_slice(b"a"); k_at.extend_from_slice(tx.to.0.as_bytes());   k_at.push(b'|'); k_at.extend_from_slice(&be64(height)); k_at.extend_from_slice(&be32(i as u32));
            self.acct.insert(k_at, txid.as_bytes())?;
        }

        let mut k_b=Vec::with_capacity(1+8); k_b.extend_from_slice(b"b"); k_b.extend_from_slice(&be64(height));
        let sblk = StoredBlock{ height, hash: hash.to_string(), ts, tx_ids: ids };
        self.blocks.insert(k_b, serde_json::to_vec(&sblk)?)?;
        Ok(())
    }

    pub fn commit_block_atomic(&self, blk: &Block) -> anyhow::Result<()> {
        for tx in blk.txs.iter() {
            let fb = self.get_balance(&tx.from.0)?;
            if fb < tx.amount { anyhow::bail!("insufficient funds"); }
            let tb = self.get_balance(&tx.to.0)?;
            self.set_balance(&tx.from.0, (fb - tx.amount) as u128)?;
            self.set_balance(&tx.to.0,   tb.saturating_add(tx.amount) as u128)?;
            self.set_nonce(&tx.from.0, tx.nonce)?;
        }
        self.set_head(blk.height, &blk.block_hash)?;
        Ok(())
    }

    pub fn get_block_by_height(&self, h:u64) -> anyhow::Result<BlockHeaderView> {
        let mut k=Vec::with_capacity(9); k.extend_from_slice(b"b"); k.extend_from_slice(&be64(h));
        if let Some(v) = self.blocks.get(k)? {
            let b: StoredBlock = serde_json::from_slice(&v)?;
            Ok(BlockHeaderView{ block_hash: b.hash })
        } else {
            let hh = self.head.get(K_HEAD_HASH)?.map(|v| String::from_utf8(v.to_vec()).unwrap()).unwrap_or_default();
            Ok(BlockHeaderView{ block_hash: hh })
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockHeaderView { pub block_hash:String }

```


=== /root/logos_lrb/lrb_core/src/lib.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_consensus.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_filters.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_integrity.rs ===

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


=== /root/logos_lrb/lrb_core/src/quorum.rs ===

```rust
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

```


=== /root/logos_lrb/lrb_core/src/rcp_engine.rs ===

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


=== /root/logos_lrb/lrb_core/src/resonance.rs ===

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


=== /root/logos_lrb/lrb_core/src/sigpool.rs ===

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


=== /root/logos_lrb/lrb_core/src/spam_guard.rs ===

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


=== /root/logos_lrb/lrb_core/src/types.rs ===

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
pub type Nonce  = u64;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Rid(pub String); // base58(VerifyingKey)

impl Rid {
    pub fn from_pubkey(pk: &VerifyingKey) -> Self {
        Rid(bs58::encode(pk.to_bytes()).into_string())
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub id: String,        // blake3 of canonical form
    pub from: Rid,         // base58(pubkey)
    pub to: Rid,
    pub amount: Amount,
    pub nonce: Nonce,
    pub public_key: Vec<u8>, // 32 bytes (VerifyingKey)
    pub signature: Vec<u8>,  // 64 bytes (Signature)
}

impl Tx {
    /// Каноническое сообщение (без id и signature)
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let m = serde_json::json!({
            "from": self.from.as_str(),
            "to":   self.to.as_str(),
            "amount": self.amount,
            "nonce":  self.nonce,
            "public_key": B64.encode(&self.public_key),
        });
        serde_json::to_vec(&m).expect("canonical json")
    }

    pub fn compute_id(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.canonical_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Быстрая валидация формы (длины, нулевые значения)
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
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let mut h = Hasher::new();
        h.update(prev_hash.as_bytes());
        h.update(proposer.as_str().as_bytes());
        for tx in &txs { h.update(tx.id.as_bytes()); }
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

/// VerifyingKey из 32 байт (не пропускаем ошибку dalek наружу)
pub fn parse_pubkey(pk: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = pk.try_into().map_err(|_| anyhow!("bad pubkey len"))?;
    let vk = VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("bad ed25519 pubkey"))?;
    Ok(vk)
}

/// Signature из 64 байт
pub fn parse_sig(sig: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = sig.try_into().map_err(|_| anyhow!("bad signature len"))?;
    // В ed25519-dalek v2 Signature::from_bytes(&[u8;64]) -> Signature
    Ok(Signature::from_bytes(&arr))
}

```


---

# 5. node (исходники + Cargo)



=== /root/logos_lrb/node/build.rs ===

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


=== /root/logos_lrb/node/Cargo.toml ===

```toml
[package]
name        = "logos_node"
version     = "0.1.0"
edition     = "2021"
license     = "Apache-2.0"
description = "LOGOS LRB node: Axum REST + archive + producer + wallet/stake"
build       = "build.rs"

[[bin]]
name = "logos_node"
path = "src/main.rs"

[lib]
name = "logos_node"
path = "src/lib.rs"

[dependencies]
# web / runtime
axum.workspace       = true
tower.workspace      = true
tower-http.workspace = true
tokio.workspace      = true

# utils / serde / logging
serde.workspace              = true
serde_json.workspace         = true
anyhow.workspace             = true
thiserror.workspace          = true
once_cell.workspace          = true
dashmap.workspace            = true
tracing.workspace            = true
tracing-subscriber.workspace = true

# auth
jsonwebtoken.workspace       = true

# storage
sled.workspace               = true
deadpool-postgres.workspace  = true
tokio-postgres.workspace     = true
rusqlite.workspace           = true
r2d2_sqlite.workspace        = true

# crypto / codecs
hex.workspace                = true
base64.workspace             = true
bs58.workspace               = true
ed25519-dalek.workspace      = true
blake3.workspace             = true    # <— ДОБАВЛЕНО: bridge/gossip/producer используют blake3

# sync / net / metrics
parking_lot.workspace        = true
ipnet.workspace              = true
prometheus.workspace         = true

# локальное ядро L1
lrb_core = { path = "../lrb_core" }

[build-dependencies]
chrono = { version = "0.4", default-features = false, features = ["clock"] }

```


=== /root/logos_lrb/node/src/admin.rs ===

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


=== /root/logos_lrb/node/src/api.rs ===

```rust
//! LOGOS LRB — Public API (prod, Axum 0.7)

use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tracing::{info, warn, error};

use crate::state::AppState;

#[derive(Serialize)] pub struct OkMsg { pub status: &'static str }
#[derive(Serialize)] pub struct Head { pub height: u64 }
#[derive(Serialize)] pub struct Balance { pub rid: String, pub balance: u128, pub nonce: u64 }

#[derive(Deserialize)]
pub struct TxIn { pub from:String, pub to:String, pub amount:u64, pub nonce:u64, pub sig_hex:String, #[serde(default)] pub memo:Option<String> }

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

pub async fn submit_tx(State(app): State<Arc<AppState>>, Json(tx):Json<TxIn>) -> (StatusCode, Json<SubmitResult>) {
    let stx = match app.ledger.lock().submit_tx_simple(&tx.from, &tx.to, tx.amount, tx.nonce, tx.memo.clone()) {
        Ok(s)=>s, Err(e)=>return (StatusCode::OK, Json(SubmitResult{ ok:false, txid:None, info:e.to_string() })),
    };
    if let Some(arch)=&app.archive {
        match arch.record_tx(&stx.txid, stx.height, &stx.from, &stx.to, stx.amount, stx.nonce, Some((stx.ts/1000) as u64)).await {
            Ok(()) => info!("archive: wrote tx {}", stx.txid),
            Err(e) => error!("archive: write failed: {}", e),
        }
    } else { warn!("archive: not configured"); }
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

// ---- Archive API ----
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

```


=== /root/logos_lrb/node/src/archive/mod.rs ===

```rust
//! LOGOS LRB — Archive (Postgres, prod-ready)
//! Env: LRB_ARCHIVE_URL=postgres://user:pass@host:5432/db
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;
use serde::Serialize;
use std::env;

#[derive(Clone)]
pub struct Archive { pool: Pool }

#[derive(Serialize)]
pub struct TxRecord {
    pub txid: String,
    pub height: i64,
    pub from: String,
    pub to: String,
    pub amount: i64,
    pub nonce: i64,
    pub ts: Option<i64>, // seconds
}

#[derive(Serialize)]
pub struct BlockRow {
    pub height: i64,
    pub hash: String,
    pub ts: i64,
    pub tx_count: i32,
}

impl Archive {
    pub async fn new_from_env() -> Option<Self> {
        let url = env::var("LRB_ARCHIVE_URL").ok()?;
        let mgr = Manager::from_config(url.parse().ok()?, NoTls, ManagerConfig{ recycling_method: RecyclingMethod::Fast });
        let pool = Pool::builder(mgr).max_size(16).build().ok()?;
        if pool.get().await.is_err() { return None; }
        Some(Self{ pool })
    }

    pub async fn record_block(&self, height:i64, hash:&str, ts:i64, tx_count:i32) -> anyhow::Result<()> {
        let c = self.pool.get().await?;
        c.execute(
            "INSERT INTO blocks(height,hash,ts_sec,tx_count)
             VALUES($1,$2,$3,$4)
             ON CONFLICT (height) DO UPDATE
             SET hash=EXCLUDED.hash, ts_sec=EXCLUDED.ts_sec, tx_count=EXCLUDED.tx_count",
            &[&height,&hash,&ts,&tx_count]).await?;
        Ok(())
    }

    pub async fn record_tx(&self, txid:&str, height:u64, from:&str, to:&str, amount:u64, nonce:u64, ts:Option<u64>) -> anyhow::Result<()> {
        let c = self.pool.get().await?;
        let ts_i: Option<i64> = ts.map(|v| v as i64);
        c.execute(
            "INSERT INTO tx(txid,height,rid_from,rid_to,amount,nonce,ts_sec)
             VALUES($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (txid) DO NOTHING",
            &[&txid,&(height as i64),&from,&to,&(amount as i64),&(nonce as i64),&ts_i]).await?;
        Ok(())
    }

    /// История по RID c пагинацией по высоте
    pub async fn history_by_rid(&self, rid:&str, limit:i64, before_height: Option<i64>) -> anyhow::Result<Vec<TxRecord>> {
        let c = self.pool.get().await?;
        let lim = if limit <= 0 { 100 } else { limit.min(500) };
        let rows = if let Some(bh) = before_height {
            c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE (rid_from=$1 OR rid_to=$1) AND height < $2
                 ORDER BY height DESC, ts_sec DESC NULLS LAST
                 LIMIT $3",
                &[&rid, &bh, &lim]
            ).await?
        } else {
            c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE rid_from=$1 OR rid_to=$1
                 ORDER BY height DESC, ts_sec DESC NULLS LAST
                 LIMIT $2",
                &[&rid, &lim]
            ).await?
        };
        Ok(rows.into_iter().map(|r| TxRecord{
            txid:   r.get(0),
            height: r.get(1),
            from:   r.get(2),
            to:     r.get(3),
            amount: r.get(4),
            nonce:  r.get(5),
            ts:     r.get(6),
        }).collect())
    }

    pub async fn recent_blocks(&self, limit:i64, before_height: Option<i64>) -> anyhow::Result<Vec<BlockRow>> {
        let c = self.pool.get().await?;
        let lim = if limit <= 0 { 50 } else { limit.min(200) };
        let rows = if let Some(bh) = before_height {
            c.query(
                "SELECT height,hash,ts_sec,tx_count
                 FROM blocks WHERE height < $1
                 ORDER BY height DESC
                 LIMIT $2",
                &[&bh,&lim]
            ).await?
        } else {
            c.query(
                "SELECT height,hash,ts_sec,tx_count
                 FROM blocks
                 ORDER BY height DESC
                 LIMIT $1",
                &[&lim]
            ).await?
        };
        Ok(rows.into_iter().map(|r| BlockRow{
            height: r.get(0),
            hash:   r.get(1),
            ts:     r.get(2),
            tx_count:r.get(3),
        }).collect())
    }

    pub async fn recent_txs(&self, limit:i64, rid: Option<&str>, before_ts: Option<i64>) -> anyhow::Result<Vec<TxRecord>> {
        let c = self.pool.get().await?;
        let lim = if limit <= 0 { 100 } else { limit.min(500) };
        let rows = match (rid,before_ts) {
            (Some(r),Some(ts)) => c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE (rid_from=$1 OR rid_to=$1) AND (ts_sec IS NULL OR ts_sec<$2)
                 ORDER BY ts_sec DESC NULLS LAST, height DESC LIMIT $3",
                &[&r,&ts,&lim]
            ).await?,
            (Some(r),None) => c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE rid_from=$1 OR rid_to=$1
                 ORDER BY ts_sec DESC NULLS LAST, height DESC LIMIT $2",
                &[&r,&lim]
            ).await?,
            (None,Some(ts)) => c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx WHERE (ts_sec IS NULL OR ts_sec<$1)
                 ORDER BY ts_sec DESC NULLS LAST, height DESC LIMIT $2",
                &[&ts,&lim]
            ).await?,
            (None,None) => c.query(
                "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
                 FROM tx
                 ORDER BY ts_sec DESC NULLS LAST, height DESC LIMIT $1",
                &[&lim]
            ).await?,
        };
        Ok(rows.into_iter().map(|r| TxRecord{
            txid:   r.get(0),
            height: r.get(1),
            from:   r.get(2),
            to:     r.get(3),
            amount: r.get(4),
            nonce:  r.get(5),
            ts:     r.get(6),
        }).collect())
    }

    pub async fn tx_by_id(&self, txid:&str) -> anyhow::Result<Option<serde_json::Value>> {
        let c = self.pool.get().await?;
        let row = c.query_opt(
            "SELECT txid,height,rid_from,rid_to,amount,nonce,ts_sec
             FROM tx WHERE txid=$1",
            &[&txid]).await?;
        Ok(row.map(|r| serde_json::json!({
            "txid": r.get::<_,String>(0),
            "height": r.get::<_,i64>(1),
            "from": r.get::<_,String>(2),
            "to":   r.get::<_,String>(3),
            "amount": r.get::<_,i64>(4),
            "nonce":  r.get::<_,i64>(5),
            "ts":     r.get::<_,Option<i64>>(6),
        })))
    }

    pub async fn block_by_height(&self, h:i64) -> anyhow::Result<Option<BlockRow>> {
        let c = self.pool.get().await?;
        let row = c.query_opt(
            "SELECT height,hash,ts_sec,tx_count FROM blocks WHERE height=$1",
            &[&h]).await?;
        Ok(row.map(|r| BlockRow{
            height:r.get(0), hash:r.get(1), ts:r.get(2), tx_count:r.get(3)
        }))
    }
}

```


=== /root/logos_lrb/node/src/archive/pg.rs ===

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


=== /root/logos_lrb/node/src/archive/sqlite.rs ===

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


=== /root/logos_lrb/node/src/auth.rs ===

```rust
//! Auth-модуль: защита bridge/admin. Admin — только JWT (HS256). Bridge — X-Bridge-Key.
//! Обязательные переменные окружения: LRB_BRIDGE_KEY, LRB_JWT_SECRET.

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

fn forbid_default(val: &str) -> Result<()> {
    let low = val.to_lowercase();
    let banned = ["", "change_me", "changeme", "dev_secret", "default", "empty", "test", "123"];
    if banned.iter().any(|b| low == *b) {
        return Err(anyhow!("insecure default key"));
    }
    Ok(())
}

/* ---------------- Bridge (ключ обязателен) ---------------- */

pub fn require_bridge(headers: &HeaderMap) -> Result<()> {
    let expect = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY CHANGE_ME not set"))?;
    forbid_default(&expect)?;
    let got = headers
        .get("X-Bridge-Key")
        .ok_or_else(|| anyhow!("missing X-Bridge-Key"))?
        .to_str()
        .map_err(|_| anyhow!("invalid X-Bridge-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad bridge key")); }
    Ok(())
}

/* ---------------- Admin (только JWT HS256) ---------------- */

#[derive(Debug, Deserialize)]
struct AdminClaims {
    sub: String,
    iat: Option<u64>,
    exp: Option<u64>,
}

pub fn require_admin(headers: &HeaderMap) -> Result<()> {
    let token = headers
        .get("X-Admin-JWT")
        .ok_or_else(|| anyhow!("missing X-Admin-JWT"))?
        .to_str()
        .map_err(|_| anyhow!("invalid X-Admin-JWT"))?
        .to_string();

    let secret = std::env::var("LRB_JWT_SECRET").map_err(|_| anyhow!("LRB_JWT_SECRET CHANGE_ME not set"))?;
    forbid_default(&secret)?;

    let data = decode::<AdminClaims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| anyhow!("admin jwt invalid: {e}"))?;

    if data.claims.sub != "admin" {
        return Err(anyhow!("forbidden"));
    }
    Ok(())
}

/* ---------------- Стартовая проверка секретов ---------------- */

pub fn assert_secrets_on_start() -> Result<()> {
    // Bridge/JWT обязаны быть заданы. Если пусты — валим процесс.
    for (key, val) in [("LRB_BRIDGE_KEY","bridge"), ("LRB_JWT_SECRET","jwt")] {
        let v = std::env::var(key).map_err(|_| anyhow!("{key} is not set"))?;
        forbid_default(&v)?;
    }
    Ok(())
}

```


=== /root/logos_lrb/node/src/bridge.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/fork.rs ===

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


=== /root/logos_lrb/node/src/gossip.rs ===

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


=== /root/logos_lrb/node/src/guard.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/lib.rs ===

```rust
//! Библиотечная часть узла LOGOS: экспортируем AppState, auth и archive.
//! Нужна для случаев, когда crate собирается как `lib`.

pub mod state;
pub use state::AppState;

pub mod auth;
pub use auth::require_bridge;

// ВАЖНО: подключаем архив, чтобы `crate::archive::...` существовал и в lib-сборке.
pub mod archive;

```


=== /root/logos_lrb/node/src/main.rs ===

```rust
//! LOGOS LRB — node main (prod)
//! Axum REST + guard + metrics + archive (PG) + single-node producer + wallet/stake.

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
mod stake;     // <— стейкинг (submit/delegations/rewards)
mod wallet;    // <— регистрация pubkey (RID→pub_hex)
mod producer;  // <— single-node block producer (quorum=1)

fn router(app_state: Arc<state::AppState>) -> Router {
    Router::new()
        // --- public ---
        .route("/healthz", get(api::healthz))
        .route("/head",    get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx",    post(api::submit_tx))
        .route("/economy",      get(api::economy))
        .route("/history/:rid", get(api::history))
        // --- archive API (PG) ---
        .route("/archive/blocks", get(api::archive_blocks))
        .route("/archive/txs",    get(api::archive_txs))
        .route("/archive/history/:rid", get(api::archive_history))
        .route("/archive/tx/:txid",     get(api::archive_tx))
        // --- version / metrics / openapi ---
        .route("/version",     get(version::get))
        .route("/metrics",     get(metrics::prometheus))
        .route("/openapi.json",get(openapi::serve))
        // --- bridge (rTokens) ---
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem",  post(bridge::redeem))
        .route("/bridge/verify",  post(bridge::verify))
        // --- admin ---
        .route("/admin/set_balance", post(admin::set_balance))
        .route("/admin/bump_nonce",  post(admin::bump_nonce))
        .route("/admin/set_nonce",   post(admin::set_nonce))
        .route("/admin/mint",        post(admin::mint))
        .route("/admin/burn",        post(admin::burn))
        // --- wallet/stake (НОВОЕ) ---
        .merge(wallet::routes())
        .merge(stake::routes())
        // --- state & layers ---
        .with_state(app_state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(axum::middleware::from_fn(guard::rate_limit_mw)) // лимитер
                .layer(axum::middleware::from_fn(metrics::track))        // метрики
        )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ---- logging/tracing ----
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,axum::rejection=trace"))
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // ---- secrets sanity ----
    auth::assert_secrets_on_start().expect("unsafe or missing secrets");

    // ---- state ----
    let app_state = Arc::new(state::AppState::new()?);

    // ---- archive backend (PG/SQLite) ----
    if let Some(ar) = crate::archive::Archive::new_from_env().await {
        unsafe {
            let p = Arc::as_ptr(&app_state) as *mut state::AppState;
            (*p).archive = Some(ar);
        }
        info!("archive backend initialized");
    } else {
        warn!("archive disabled (no LRB_ARCHIVE_URL / LRB_ARCHIVE_PATH)");
    }

    // ---- single-node producer ----
    info!("producer: start");
    let _producer = producer::run(app_state.clone());

    // ---- bind / serve ----
    let addr = state::bind_addr();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("logos_node listening on {}", addr);
    axum::serve(listener, router(app_state)).await?;
    Ok(())
}

```


=== /root/logos_lrb/node/src/metrics.rs ===

```rust
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramVec, IntCounterVec, Registry, TextEncoder, register_histogram_vec, register_int_counter_vec,
};
use std::time::Instant;

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

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
        prometheus::exponential_buckets(0.001, 2.0, 14).unwrap() // 1ms..~16s
    ).unwrap()
});

/// Нормализация пути (убираем динамику)
fn normalize_path(p: &str) -> String {
    if p.starts_with("/balance/") { return "/balance/:rid".into(); }
    if p.starts_with("/history/") { return "/history/:rid".into(); }
    p.to_string()
}

/// Axum-middleware: считает per-route счётчики и latency
pub async fn track(req: Request<Body>, next: Next) -> axum::response::Response {
    let method = req.method().as_str().to_owned();
    let path = normalize_path(req.uri().path());
    let start = Instant::now();

    let res = next.run(req).await;
    let status = res.status().as_u16().to_string();

    HTTP_REQS.with_label_values(&[&method, &path, &status]).inc();
    HTTP_LATENCY.with_label_values(&[&method, &path, &status]).observe(start.elapsed().as_secs_f64());

    res
}

/// Exporter для Prometheus
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

/// Совместимость: старый inc_total был заглушкой — оставим no-op
pub fn inc_total(_label: &str) {}

```


=== /root/logos_lrb/node/src/openapi.rs ===

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


=== /root/logos_lrb/node/src/peers.rs ===

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


=== /root/logos_lrb/node/src/producer.rs ===

```rust
//! LOGOS LRB — single-node block producer (prod)
//! Slot-произведение блоков с детерминированным fork-choice (quorum=1):
//! - каждые SLOT_MS (env: LRB_SLOT_MS, по умолчанию 1000 мс) увеличиваем height на 1,
//! - new_hash = blake3(prev_hash | now_sec | height),
//! - set_head(height, hash) + set_finalized(height),
//! - если архив включён — пишем блок в PG (tx_count=0, ts_sec=now).
use std::{sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tokio::{task::JoinHandle, time::{self, Duration}};
use blake3::Hasher;
use tracing::{info, warn, error};

use crate::state::AppState;

fn slot_ms_from_env() -> u64 {
    std::env::var("LRB_SLOT_MS").ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&ms| ms >= 100)
        .unwrap_or(1000)
}

fn new_hash(prev_hash: &str, height: u64, now_sec: u64) -> String {
    let mut h = Hasher::new();
    h.update(prev_hash.as_bytes());
    h.update(&height.to_be_bytes());
    h.update(&now_sec.to_be_bytes());
    hex::encode(h.finalize().as_bytes())
}

pub fn run(app: Arc<AppState>) -> JoinHandle<()> {
    let slot = slot_ms_from_env();
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_millis(slot));
        loop {
            ticker.tick().await;

            // текущее время (секунды)
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // 1) читаем head
            let (cur_h, prev_hash) = {
                let l = app.ledger.lock();
                l.head().unwrap_or((0, String::new()))
            };

            // 2) детерминированный выбор и расчёт нового блока
            let next_h = cur_h.saturating_add(1);
            let prev = if prev_hash.is_empty() { "genesis" } else { &prev_hash };
            let hash = new_hash(prev, next_h, now_sec as u64);

            // 3) коммит head + финализация
            {
                let l = app.ledger.lock();
                if let Err(e) = l.set_head(next_h, &hash) {
                    error!("producer: set_head failed: {}", e);
                    continue;
                }
                if let Err(e) = l.set_finalized(next_h) {
                    warn!("producer: set_finalized failed: {}", e);
                }
            }

            // 4) запись блока в архив (PG)
            if let Some(arch) = &app.archive {
                if let Err(e) = arch.record_block(next_h as i64, &hash, now_sec as i64, 0).await {
                    warn!("producer: archive record_block failed: {}", e);
                }
            }

            info!("producer: new block height={} hash={}", next_h, &hash[..16]);
        }
    })
}

```


=== /root/logos_lrb/node/src/stake.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/state.rs ===

```rust
use std::{env, net::SocketAddr, str::FromStr};
use std::sync::Arc;
use parking_lot::Mutex;

use lrb_core::ledger::Ledger;

pub struct AppState {
    pub ledger: Arc<Mutex<Ledger>>,           // совместимо с api/admin
    pub db: sled::Db,                         // быстрый доступ сервисам
    pub archive: Option<crate::archive::Archive>,
}

impl AppState {
    pub fn new() -> anyhow::Result<Self> {
        let data_path = env::var("LRB_DATA_PATH")
            .or_else(|_| env::var("LRB_DATA_DIR").map(|p| format!("{}/data.sled", p)))
            .unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());

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

```


=== /root/logos_lrb/node/src/storage.rs ===

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


=== /root/logos_lrb/node/src/version.rs ===

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


=== /root/logos_lrb/node/src/wallet.rs ===

```rust
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

```


---

# 6. Web Wallet



=== /root/logos_lrb/www/wallet/app.html ===

```html
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

```


=== /root/logos_lrb/www/wallet/app.js ===

```javascript
// APP: ключи в памяти; RID неизменен — берём из sessionStorage, meta из acct:<RID>
const API = location.origin + '/api';
const DB_NAME='logos_wallet_v2', STORE='keys', enc=new TextEncoder();
const ALPH="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const $=s=>document.querySelector(s);
const toHex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex=h=>new Uint8Array(h.match(/.{1,2}/g).map(x=>parseInt(x,16)));
const b58=bytes=>{const h=[...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join('');let x=BigInt('0x'+h),o='';while(x>0n){o=ALPH[Number(x%58n)]+o;x/=58n;}return o||'1';};

const idb=()=>new Promise((res,rej)=>{const r=indexedDB.open(DB_NAME,1);r.onupgradeneeded=()=>r.result.createObjectStore(STORE);r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});
const idbGet=async k=>{const db=await idb();return new Promise((res,rej)=>{const t=db.transaction(STORE,'readonly').objectStore(STORE).get(k);t.onsuccess=()=>res(t.result||null);t.onerror=()=>rej(t.error);});};

async function deriveKey(pass,salt){const keyMat=await crypto.subtle.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:120000,hash:'SHA-256'},keyMat,{name:'AES-GCM',length:256},false,['decrypt']);}
async function aesDecrypt(aesKey,iv,ct){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(iv)},aesKey,new Uint8Array(ct)))}
async function importKey(pass, meta){
  const aes=await deriveKey(pass,new Uint8Array(meta.salt));
  const pkcs8=await aesDecrypt(aes,meta.iv,meta.priv);
  const privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'Ed25519'},true,['sign']);
  const publicKey =await crypto.subtle.importKey('raw',new Uint8Array(meta.pub),{name:'Ed25519'},true,['verify']);
  return {privateKey, publicKey};
}

// Session guard
const PASS=sessionStorage.getItem('logos_pass');
const RID =sessionStorage.getItem('logos_rid');
if(!PASS || !RID){ location.replace('./login.html'); throw new Error('locked'); }

let KEYS=null, META=null;

(async ()=>{
  META=await idbGet('acct:'+RID);
  if(!META){ sessionStorage.clear(); location.replace('./login.html'); return; }
  KEYS=await importKey(PASS,META);
  document.getElementById('pub').value=`RID: ${RID}\nPUB (hex): ${toHex(new Uint8Array(META.pub))}`;
  document.getElementById('rid-balance').value=RID;
})();

document.getElementById('btn-lock').addEventListener('click', ()=>{ sessionStorage.clear(); location.replace('./login.html'); });

// API helpers
async function getJSON(url, body){
  const r = await fetch(url, body ? {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)} : {});
  if(!r.ok){ throw new Error(`${r.status} ${await r.text()}`); }
  return r.json();
}
async function getNonce(rid){ const j=await getJSON(`${API}/balance/${rid}`); return j.nonce||0; }
async function canonHex(from,to,amount,nonce){
  const r=await fetch(`${API}/debug_canon`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tx:{from,to,amount:Number(amount),nonce:Number(nonce)}})});
  if(!r.ok){ throw new Error(`/debug_canon ${r.status}`); }
  return (await r.json()).canon_hex;
}
async function submitBatch(txs){
  const r=await fetch(`${API}/submit_tx_batch`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({txs})});
  if(!r.ok){ throw new Error(`/submit_tx_batch ${r.status}`); }
  return r.json();
}
async function deposit(rid, amount, ext){
  const r=await fetch(`${API}/bridge/deposit`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rid,amount:Number(amount),ext_txid:ext})});
  return {status:r.status, text:await r.text()};
}
async function signCanon(privateKey, canonHex){
  const msg=fromHex(canonHex);
  const sig=await crypto.subtle.sign('Ed25519', privateKey, msg);
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

// Buttons
document.getElementById('btn-nonce').addEventListener('click', async ()=>{
  try{ const n=await getNonce(RID); document.getElementById('nonce').value=String(n+1); }
  catch(e){ alert('ERR '+e); }
});

document.getElementById('btn-balance').addEventListener('click', async ()=>{
  try{ const rid=document.getElementById('rid-balance').value.trim(); const j=await getJSON(`${API}/balance/${rid}`); document.getElementById('out-balance').textContent=JSON.stringify(j,null,2); }
  catch(e){ document.getElementById('out-balance').textContent=String(e); }
});

document.getElementById('btn-send').addEventListener('click', async ()=>{
  const to=document.getElementById('to').value.trim();
  const amount=document.getElementById('amount').value;
  const nonce=document.getElementById('nonce').value;
  const out=document.getElementById('out-send');
  try{
    const ch = await canonHex(RID,to,amount,nonce);
    const sig= await signCanon(KEYS.privateKey,ch);
    const res= await submitBatch([{from:RID,to,amount:Number(amount),nonce:Number(nonce),sig_hex:sig}]);
    out.textContent=JSON.stringify(res,null,2);
  }catch(e){ out.textContent=String(e); }
});

document.getElementById('btn-deposit').addEventListener('click', async ()=>{
  const ext=document.getElementById('ext').value.trim()||'eth_txid_demo';
  const r=await deposit(RID,123,ext);
  document.getElementById('out-bridge').textContent=`HTTP ${r.status}\n${r.text}`;
});

```


=== /root/logos_lrb/www/wallet/auth.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/index.html ===

```html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>LOGOS Wallet</title>
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0"/>
  <style>
    :root{--bg:#0b0f14;--card:#0f1720;--line:#1f2a36;--txt:#e6edf3;--muted:#8aa0b8;--acc:#1d4ed8}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.45 system-ui,Inter,Arial}
    header{padding:18px;border-bottom:1px solid var(--line);font-weight:700}
    .wrap{max-width:980px;margin:18px auto;padding:0 16px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
    h2{margin:0 0 10px 0;font-size:16px}
    label{display:block;margin:10px 0 6px 2px;color:var(--muted);font-size:12px}
    input,button{height:40px;border-radius:10px;border:1px solid var(--line);background:#0c121a;color:var(--txt);padding:0 10px}
    button{cursor:pointer;background:#132037}
    .row{display:flex;gap:8px;align-items:center}
    .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
    .tabs{display:flex;gap:8px;margin-bottom:10px}
    .tab{padding:8px 12px;border:1px solid var(--line);border-radius:10px;background:#0c121a;cursor:pointer}
    .tab.active{background:#16263f}
    .hide{display:none}
    .ok{color:#30c175}.err{color:#f86a6a}
  </style>
</head>
<body>
<header class="wrap">LOGOS Wallet</header>

<div class="wrap">
  <!-- АВТОРИЗАЦИЯ + СОЗДАНИЕ -->
  <div class="grid">
    <section class="card">
      <h2>Вход в кошелёк</h2>
      <label>RID</label>
      <input id="loginRid" placeholder="Λ0@7.83Hzφ..."/>
      <label>Пароль (для расшифровки ключа)</label>
      <input id="loginPass" type="password" placeholder="••••••••"/>
      <div class="row" style="margin-top:10px">
        <button id="btnLogin">Войти</button>
        <span id="loginStatus" class="mono"></span>
      </div>
    </section>

    <section class="card">
      <h2>Создать новый кошелёк</h2>
      <label>Пароль (защита приватного ключа)</label>
      <input id="newPass" type="password" placeholder="мин. 8 символов"/>
      <div class="row" style="margin-top:10px">
        <button id="btnCreate">Создать</button>
        <span id="createStatus" class="mono"></span>
      </div>
      <small>Ключ хранится локально (IndexedDB + AES-GCM/PBKDF2). Данные не покидают устройство.</small>
    </section>
  </div>

  <!-- ПАНЕЛЬ КОШЕЛЬКА -->
  <section class="card" id="walletPanel" style="margin-top:16px;display:none">
    <div class="tabs">
      <div class="tab active" data-tab="send">Отправка</div>
      <div class="tab" data-tab="stake">Стейкинг</div>
      <div class="tab" data-tab="history">История</div>
      <div class="tab" data-tab="settings">Настройки</div>
    </div>

    <!-- SEND -->
    <div id="tab-send">
      <div class="row mono" style="margin-bottom:10px">
        <span>RID: <span id="ridView"></span></span>
        <span style="margin-left:auto">Баланс: <span id="balView">0</span></span>
        <span>Nonce: <span id="nonceView">0</span></span>
      </div>
      <label>Получатель (RID)</label>
      <input id="toRid" placeholder="RID получателя"/>
      <label>Сумма (микро-LGN)</label>
      <input id="amount" type="number" min="1" value="1234"/>
      <div class="row" style="margin-top:10px">
        <button id="btnSend">Отправить</button>
        <span id="sendStatus" class="mono"></span>
      </div>
    </div>

    <!-- STAKING -->
    <div id="tab-stake" class="hide">
      <div class="row mono" style="margin-bottom:10px">RID: <span id="ridStake"></span></div>
      <label>Валидатор (RID)</label>
      <input id="valRid" placeholder="RID валидатора"/>
      <label>Сумма (микро-LGN)</label>
      <input id="stakeAmt" type="number" min="1" value="100000"/>
      <div class="row" style="margin-top:8px">
        <button id="btnDelegate">Delegate</button>
        <button id="btnUndelegate">Undelegate</button>
        <button id="btnClaim">Claim</button>
      </div>
      <div class="mono" id="stakeStatus" style="margin-top:10px"></div>
    </div>

    <!-- HISTORY -->
    <div id="tab-history" class="hide">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr><th class="mono">txid</th><th class="mono">from</th><th class="mono">to</th><th>amt</th><th>height</th><th>ts</th></tr></thead>
        <tbody id="histBody"></tbody>
      </table>
      <div class="row" style="justify-content:center;margin-top:8px"><button id="btnMoreHist">Ещё</button></div>
    </div>

    <!-- SETTINGS -->
    <div id="tab-settings" class="hide">
      <div class="mono" id="settingsInfo"></div>
      <div class="row" style="margin-top:10px">
        <button id="btnExport">Экспорт (зашифр.)</button>
        <input type="file" id="impFile" style="display:none"/>
        <button id="btnImport">Импорт</button>
      </div>
      <div class="mono" id="exportStatus" style="margin-top:10px"></div>
    </div>
  </section>
</div>

<!-- Скрипты (CSP: только 'self') -->
<script src="wallet.js" defer></script>
<script src="staking.js" defer></script>
</body>
</html>

```


=== /root/logos_lrb/www/wallet/login.html ===

```html
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

```


=== /root/logos_lrb/www/wallet/staking.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/wallet.css ===

```css
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

```


=== /root/logos_lrb/www/wallet/wallet.js ===

```javascript
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

```


---

# 7. Explorer



=== /root/logos_lrb/www/explorer/index.html ===

```html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>LOGOS LRB — Explorer</title>
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0"/>
  <style>
    :root{--bg:#0b0f14;--card:#0f1720;--line:#1f2a36;--muted:#8aa0b8;--txt:#e6edf3}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.45 system-ui,Inter,Arial}
    header{display:flex;gap:10px;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--line)}
    .pill{background:#0d1520;border:1px solid var(--line);border-radius:999px;padding:6px 10px}
    .wrap{max-width:1240px;margin:18px auto;padding:0 16px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{padding:10px;border-bottom:1px solid #1e2a3a;white-space:nowrap}
    thead th{background:#0f1723;color:#a8bdd9}
    .row{display:flex;gap:10px;align-items:center}
    .mono{font-family:ui-monospace,Menlo,Consolas,"SF Mono",monospace}
    .hash{max-width:220px;overflow:hidden;text-overflow:ellipsis}
    .btn{padding:6px 10px;border:1px solid var(--line);background:#0e1623;border-radius:10px;cursor:pointer}
    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    footer{max-width:1240px;color:var(--muted);margin:14px auto 24px;padding:0 16px}
    @media (max-width:1200px){ .wrap{grid-template-columns:1fr 1fr} }
    @media (max-width:760px){ .wrap{grid-template-columns:1fr} }
  </style>
</head>
<body>
<header>
  <strong>LOGOS LRB — Explorer</strong>
  <span class="pill">head: <span id="head">…</span></span>
  <span class="pill">tps: <span id="tps">0</span></span>
  <span class="pill">bps: <span id="bps">0</span></span>
</header>

<div class="wrap">

  <section class="card" style="grid-column:1/3">
    <h2>Последние блоки</h2>
    <table id="blocks"><thead><tr><th>height</th><th class="mono hash" title="hash">hash</th><th>txs</th><th>ts</th></tr></thead><tbody></tbody></table>
    <div class="row" style="justify-content:center;margin-top:8px"><button class="btn" id="moreBlocks">Ещё блоки</button></div>
  </section>

  <section class="card" style="grid-column:3/4">
    <h2>Экономика</h2>
    <div class="row mono" style="flex-wrap:wrap">
      <span>Cap:&nbsp;<span id="cap">0</span></span>
      <span>Minted:&nbsp;<span id="minted">0</span></span>
      <span>Burned:&nbsp;<span id="burned">0</span></span>
      <span>Supply:&nbsp;<span id="supply">0</span></span>
    </div>
    <div style="margin-top:12px;color:#9fb2ca">Обновляется при загрузке страницы</div>
  </section>

  <section class="card" style="grid-column:1/3">
    <h2>Последние транзакции</h2>
    <table id="txs"><thead><tr><th class="mono">txid</th><th class="mono">from</th><th class="mono">to</th><th>amt</th><th>height</th><th>ts</th></tr></thead><tbody></tbody></table>
    <div class="row" style="justify-content:center;margin-top:8px"><button class="btn" id="moreTxs">Ещё транзакции</button></div>
  </section>

  <section class="card">
    <h2>История адреса</h2>
    <div class="row"><input id="rid" placeholder="вставь RID" style="flex:1"/><button id="loadRid" class="btn">Загрузить</button></div>
    <table id="hist"><thead><tr><th class="mono">txid</th><th class="mono">from</th><th class="mono">to</th><th>amt</th><th>height</th><th>ts</th></tr></thead><tbody></tbody></table>
    <div class="row" style="justify-content:center;margin-top:8px"><button class="btn" id="moreHist">Ещё для RID</button></div>
  </section>

  <section class="card" style="grid-column:1/4">
    <h2>Поиск / карточки</h2>
    <div class="grid2">
      <div>
        <div class="row"><input id="txid" placeholder="txid" style="flex:1"/><button id="findTx" class="btn">Найти</button></div>
        <pre id="txView" class="mono" style="white-space:pre-wrap"></pre>
      </div>
      <div>
        <div class="row"><input id="height" placeholder="height" style="flex:1"/><button id="findBlock" class="btn">Показать</button></div>
        <pre id="blockView" class="mono" style="white-space:pre-wrap"></pre>
      </div>
    </div>
  </section>

</div>

<footer>
  <small>Подсказки: обновление head/tps/bps раз в 1 секунду; <span class="mono">RID/txid/height</span> работают из поиска.</small>
</footer>

<script>
const BASE = location.origin + '/api';
const S = {
  head:  document.getElementById('head'),
  tpsEl: document.getElementById('tps'),
  bpsEl: document.getElementById('bps'),
  blocksT: document.getElementById('blocks').querySelector('tbody'),
  txsT:    document.getElementById('txs').querySelector('tbody'),
  histT:   document.getElementById('hist').querySelector('tbody'),
  moreBlocks: document.getElementById('moreBlocks'),
  moreTxs:    document.getElementById('moreTxs'),
  moreHist:   document.getElementById('moreHist'),
  rid:   document.getElementById('rid'), loadRid: document.getElementById('loadRid'),
  txid:  document.getElementById('txid'),  findTx:  document.getElementById('findTx'),
  height:document.getElementById('height'),findBlock:document.getElementById('findBlock'),
  txView:document.getElementById('txView'), blockView:document.getElementById('blockView')
};

function ts(s){ if(s==null) return ''; const d=new Date(s*1000); return d.toISOString().replace('T',' ').slice(0,19); }
function mono(s,cut=18){ s=String(s); return s.length>cut ? s.slice(0,cut)+'…' : s; }

let curBlocks=null, curTxs=null, curHist=null;
let lastTxCount=0, lastBlocksHeight=0, lastTs=Date.now();

async function refreshHead(){
  try{
    const j = await (await fetch(`${BASE}/head`)).json();
    S.head.textContent = j.height ?? '??';
    const dt = (Date.now()-lastTs)/1000; if(dt<1) return;
    const curr = Number(j.height||0);
    const added = Math.max(0, curr - lastBlocksHeight);
    S.bpsEl.textContent = added.toFixed(0);
    lastBlocksHeight = curr;
    lastTs = Date.now();
  }catch(e){ S.head.textContent='?'; }
}

async function loadBlocksPage(){
  let url = `${BASE}/archive/blocks?limit=20`;
  if(curBlocks!=null) url += `&before_height=${curBlocks}`;
  const list = await (await fetch(url)).json();
  if(!Array.isArray(list) || list.length===0) return;
  curBlocks = Number(list[list.length-1].height) - 1;
  const frag = document.createDocumentFragment();
  for(const b of list){
    const tr=document.createElement('tr');
    tr.innerHTML = `<td class="mono">${b.height}</td><td class="mono hash" title="${b.block_hash}">${mono(b.block_hash,22)}</td><td>${b.tx_count}</td><td>${ts(b.ts_sec)}</td>`;
    frag.appendChild(tr);
  }
  S.blocksT.appendChild(frag);
}

async function loadTxsPage(){
  let url = `${BASE}/archive/txs?limit=25`;
  if(curTxs!=null) url += `&before_ts=${curTxs}`;
  const list = await (await fetch(url)).json();
  if(!Array.isArray(list) || list.length===0) return;
  curTxs = list[list.length-1].ts ?? curTxs;
  const frag = document.createDocumentFragment();
  for(const t of list){
    const tr=document.createElement('tr');
    tr.innerHTML = `<td class="mono hash" title="${t.txid}">${mono(t.txid,22)}</td><td class="mono">${t.from}</td><td class="mono">${t.to}</td><td>${t.amount}</td><td>${t.height}</td><td>${ts(t.ts)}</td>`;
    frag.appendChild(tr);
  }
  S.txsT.appendChild(frag);
}

async function loadHistoryPage(rid){
  let url = `${BASE}/archive/history/${encodeURIComponent(rid)}`;
  if(curHist!=null) url += `?before_height=${curHist}`;
  const list = await (await fetch(url)).json();
  if(!Array.isArray(list) || list.length===0) return;
  curHist = Number(list[list.length-1].height) - 1;
  const frag = document.createDocumentFragment();
  for(const t of list){
    const tr=document.createElement('tr');
    tr.innerHTML = `<td class="mono hash" title="${t.txid}">${mono(t.txid,22)}</td><td class="mono">${t.from}</td><td class="mono">${t.to}</td><td>${t.amount}</td><td>${t.height}</td><td>${ts(t.ts)}</td>`;
    frag.appendChild(tr);
  }
  S.histT.appendChild(frag);
}

S.loadRid.onclick = ()=>{ S.histT.innerHTML=''; curHist=null; const v=S.rid.value.trim(); if(v) loadHistoryPage(v); };
S.findTx.onclick  = async ()=>{ const id=S.txid.value.trim(); if(!id) return; S.txView.textContent = JSON.stringify(await (await fetch(`${BASE}/archive/tx/${encodeURIComponent(id)}`)).json(), null, 2); };
S.findBlock.onclick = async ()=>{ const h=Number(S.height.value.trim()); if(!h) return; S.blockView.textContent = JSON.stringify(await (await fetch(`${BASE}/archive/block/${h}`)).json(), null, 2); };
S.moreBlocks.onclick = ()=> loadBlocksPage();
S.moreTxs.onclick    = ()=> loadTxsPage();
S.moreHist.onclick   = ()=>{ const v=S.rid.value.trim(); if(v) loadHistoryPage(v); };

async function econ(){
  try{
    const j = await (await fetch(`${BASE}/economy`)).json();
    (document.getElementById('cap')||{}).textContent    = j.cap ?? 0;
    (document.getElementById('minted')||{}).textContent = j.minted ?? 0;
    (document.getElementById('burned')||{}).textContent = j.burned ?? 0;
    (document.getElementById('supply')||{}).textContent = j.supply ?? 0;
  }catch{}
}

async function bootstrap(){
  await econ();
  await loadBlocksPage();
  await loadTxsPage();
  setInterval(refreshHead, 1000);
}
bootstrap();
</script>
</body>
</html>

```


---

# 8. Nginx конфиги



=== /etc/nginx/conf.d/logos.conf ===

```nginx
server { listen 80; server_name _; return 301 https://$host$request_uri; }

server {
  listen 443 ssl http2;
  server_name 45-159-248-232.sslip.io;

  ssl_certificate     /etc/letsencrypt/live/<YOUR_DOMAIN>/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/<YOUR_DOMAIN>/privkey.pem;

  root /opt/logos/www; index index.html;

  # --- API ---
  location /api/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
  }

  # --- Wallet (PWA) ---
  location /wallet/ {
    try_files $uri /wallet/index.html;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'self';" always;
    add_header Cache-Control "no-store" always;
  }

  # --- Explorer (ОДИН блок, без дублей) ---
  location /explorer/ {
    try_files $uri /explorer/index.html;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self';" always;
    add_header Cache-Control "no-store" always;
  }

  # статика (не кэшируем при разработке)
  location ~* \.(?:css|js|ico|png|jpg|jpeg|svg|woff2?)$ {
    try_files $uri =404;
    add_header Cache-Control "no-store" always;
  }

  location / {
    try_files $uri /index.html;
    add_header Cache-Control "no-store" always;
  }
}

```


---

# 9. Systemd (unit + drop-ins)



=== systemctl cat logos-node ===

```text
# /etc/systemd/system/logos-node.service
[Unit]
Description=LOGOS LRB Node (Axum REST on :8080)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos
ExecStart=/opt/logos/bin/logos_node
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/logos-node.service.d/archive.conf
[Service]
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos

# /etc/systemd/system/logos-node.service.d/cors.conf
[Service]
Environment=LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io

# /etc/systemd/system/logos-node.service.d/data.conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled

# /etc/systemd/system/logos-node.service.d/exec.conf
[Service]
ExecStart=
ExecStart=/opt/logos/bin/logos_node
WorkingDirectory=/opt/logos

# /etc/systemd/system/logos-node.service.d/faucet.conf
[Service]
Environment=LRB_ENABLE_FAUCET=1

# /etc/systemd/system/logos-node.service.d/hardening.conf
[Service]
# Ресурсы
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
MemoryMax=2G
CPUQuota=200%

# Sandbox/защиты
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service @network-io

# /etc/systemd/system/logos-node.service.d/keys.conf
[Service]
EnvironmentFile=/etc/logos/keys.env

# /etc/systemd/system/logos-node.service.d/loglevel.conf
[Service]
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/paths.conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

# /etc/systemd/system/logos-node.service.d/phasemix.conf
[Service]
Environment=LRB_PHASEMIX_ENABLE=1

# /etc/systemd/system/logos-node.service.d/ratelimit.conf
[Service]
Environment=LRB_RATE_QPS=30
Environment=LRB_RATE_BURST=60
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

# /etc/systemd/system/logos-node.service.d/ratelimit_bypass.conf
[Service]
Environment=LRB_RATE_BYPASS_CIDR=0.0.0.0/0

# /etc/systemd/system/logos-node.service.d/runas.conf
[Service]
User=logos
Group=logos
# Разрешаем запись туда, где нужно (данные/секреты)
ReadWritePaths=/var/lib/logos /etc/logos

# /etc/systemd/system/logos-node.service.d/security.conf
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true

# /etc/systemd/system/logos-node.service.d/tuning.conf
[Service]
Environment=LRB_NODE_LISTEN=0.0.0.0:8080
Environment=LRB_DATA_DIR=/var/lib/logos
Environment=LRB_WALLET_ORIGIN=http://127.0.0.1
Environment=LRB_RATE_QPS=20
Environment=LRB_RATE_BURST=40
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/zz-consensus.conf
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

# /etc/systemd/system/logos-node.service.d/zz-logging.conf
[Service]
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


=== /etc/systemd/system/logos-node.service.d/archive.conf ===

```nginx
[Service]
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos

```


=== /etc/systemd/system/logos-node.service.d/cors.conf ===

```nginx
[Service]
Environment=LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io

```


=== /etc/systemd/system/logos-node.service.d/data.conf ===

```nginx
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled

```


=== /etc/systemd/system/logos-node.service.d/exec.conf ===

```nginx
[Service]
ExecStart=
ExecStart=/opt/logos/bin/logos_node
WorkingDirectory=/opt/logos

```


=== /etc/systemd/system/logos-node.service.d/faucet.conf ===

```nginx
[Service]
Environment=LRB_ENABLE_FAUCET=1

```


=== /etc/systemd/system/logos-node.service.d/hardening.conf ===

```nginx
[Service]
# Ресурсы
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
MemoryMax=2G
CPUQuota=200%

# Sandbox/защиты
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service @network-io

```


=== /etc/systemd/system/logos-node.service.d/keys.conf ===

```nginx
[Service]
EnvironmentFile=/etc/logos/keys.env

```


=== /etc/systemd/system/logos-node.service.d/loglevel.conf ===

```nginx
[Service]
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/paths.conf ===

```nginx
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

```


=== /etc/systemd/system/logos-node.service.d/phasemix.conf ===

```nginx
[Service]
Environment=LRB_PHASEMIX_ENABLE=1

```


=== /etc/systemd/system/logos-node.service.d/ratelimit_bypass.conf ===

```nginx
[Service]
Environment=LRB_RATE_BYPASS_CIDR=0.0.0.0/0

```


=== /etc/systemd/system/logos-node.service.d/ratelimit.conf ===

```nginx
[Service]
Environment=LRB_RATE_QPS=30
Environment=LRB_RATE_BURST=60
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

```


=== /etc/systemd/system/logos-node.service.d/runas.conf ===

```nginx
[Service]
User=logos
Group=logos
# Разрешаем запись туда, где нужно (данные/секреты)
ReadWritePaths=/var/lib/logos /etc/logos

```


=== /etc/systemd/system/logos-node.service.d/security.conf ===

```nginx
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true

```


=== /etc/systemd/system/logos-node.service.d/tuning.conf ===

```nginx
[Service]
Environment=LRB_NODE_LISTEN=0.0.0.0:8080
Environment=LRB_DATA_DIR=/var/lib/logos
Environment=LRB_WALLET_ORIGIN=http://127.0.0.1
Environment=LRB_RATE_QPS=20
Environment=LRB_RATE_BURST=40
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/zz-consensus.conf ===

```nginx
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

```


=== /etc/systemd/system/logos-node.service.d/zz-keys.conf.disabled ===

```text
[Service]
# Читаем файл с секретами (на будущее, если захочешь использовать keys.env)
EnvironmentFile=-/etc/logos/keys.env

# Узловые параметры (жёстко, чтобы сервис точно стартовал)
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_SK_HEX=31962399e9b0e278af3b328bc6e30bbd17d90c700a5f6c7ad3c4d4418ed8fd83
Environment=LRB_ADMIN_KEY=0448012cf1738fd048b154a1c367cb7cb42e3fee4ab26fb04268ab91e09fb475
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


=== /etc/systemd/system/logos-node.service.d/zz-logging.conf ===

```nginx
[Service]
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf ===

```nginx
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


---

# 10. Бэкап sled



=== /usr/local/bin/logos-sled-backup.sh ===

```bash
#!/usr/bin/env bash
set -euo pipefail

SRC="/var/lib/logos/data.sled"
DST="/root/sled_backups"
KEEP=96          # ~24 часа при шаге 15 минут
MAX_GB=20        # общий лимит в гигабайтах

TS="$(date -Iseconds)"
mkdir -p "$DST"

# 1) инкрементальный снапшот (rsync в новую папку)
rsync -a --delete "$SRC/" "$DST/data.sled.$TS.bak/"

# 2) ротация по количеству
mapfile -t LIST < <(ls -1dt "$DST"/data.sled.*.bak 2>/dev/null || true)
if (( ${#LIST[@]} > KEEP )); then
  for d in "${LIST[@]:$KEEP}"; do
    rm -rf -- "$d" || true
  done
fi

# 3) ротация по общему размеру
du_mb() { du -sm "$DST" | awk '{print $1}'; }
while (( $(du_mb) > MAX_GB*1024 )); do
  OLDEST="$(ls -1dt "$DST"/data.sled.*.bak | tail -n 1 || true)"
  [[ -n "$OLDEST" ]] || break
  rm -rf -- "$OLDEST" || true
done

```


=== /etc/systemd/system/logos-sled-backup.service ===

```ini
[Unit]
Description=Backup sled to /root/sled_backups

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/logos-sled-backup.sh

```


=== /etc/systemd/system/logos-sled-backup.timer ===

```ini
[Unit]
Description=Run sled backup every 15 minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
Unit=logos-sled-backup.service

[Install]
WantedBy=timers.target

```


---

# 11. Prometheus/Grafana (alerts)



=== /etc/prometheus/rules/logos_alerts.yml ===

```yaml
groups:
- name: logos-runtime
  rules:
  - alert: HeightStuck
    expr: increase(logos_head_height[5m]) == 0
    for: 3m
    labels: { severity: critical }
    annotations: { summary: "Head не растёт 5 минут" }

  - alert: HighLatencyP99
    expr: histogram_quantile(0.99, sum(rate(http_request_duration_ms_bucket[5m])) by (le)) > 120
    for: 2m
    labels: { severity: warning }
    annotations: { summary: "p99 HTTP > 120 ms" }

  - alert: TLSExpirySoon
    expr: (probe_ssl_earliest_cert_expiry - time()) < 14*24*3600
    for: 10m
    labels: { severity: warning }
    annotations: { summary: "TLS сертификат истекает < 14 дней" }

```


---

# 12. Конфиги



=== /root/logos_lrb/configs/genesis.yaml ===

```yaml
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

```


=== /root/logos_lrb/configs/logos_config.yaml ===

```yaml
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

```


---

# 13. OpenAPI контракт



=== GET /openapi.json ===

```text
{
  "openapi": "3.0.3",
  "info": { "title": "LOGOS LRB — Core API", "version": "0.1.0", "description": "Public & Admin API for LOGOS LRB (strict CSP, JWT admin, rTokens, staking)." },
  "servers": [{ "url": "https://45-159-248-232.sslip.io" }],
  "paths": {
    "/healthz": { "get": { "summary": "Healthcheck", "responses": { "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/OkMsg" }}}}}}},
    "/head":    { "get": { "summary": "Chain head",  "responses": { "200": { "description": "Head", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Head" }}}}}}},
    "/balance/{rid}": {
      "get": {
        "summary": "Account balance & nonce",
        "parameters": [{ "name":"rid","in":"path","required":true,"schema":{"type":"string"}}],
        "responses": { "200": { "description": "Balance", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Balance" }}}}}
      }
    },
    "/submit_tx": {
      "post": {
        "summary": "Submit transaction",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref":"#/components/schemas/TxIn" }}}},
        "responses": { "200": { "description": "Result", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitResult" }}}}}
      }
    },
    "/economy": { "get": { "summary": "Economy snapshot", "responses": { "200": { "description": "Economy", "content": { "application/json": { "schema": { "$ref":"#/components/schemas/Economy" }}}}}}},
    "/history/{rid}": {
      "get": {
        "summary": "History by RID (sled index)",
        "parameters": [{ "name":"rid","in":"path","required":true,"schema":{"type":"string"}}],
        "responses": { "200": { "description": "History", "content": { "application/json": { "schema": { "type":"array","items":{"$ref":"#/components/schemas/HistoryItem"} }}}}}
      }
    },

    "/stake/submit":      { "post": { "summary":"Submit staking op", "requestBody":{ "required":true, "content":{"application/json":{"schema":{"$ref":"#/components/schemas/StakeTxIn"}}}}, "responses":{ "200":{ "description":"Result", "content":{ "application/json":{ "schema":{"$ref":"#/components/schemas/SubmitResult"}}}}}}},
    "/stake/validators":  { "get":  { "summary":"List validators", "responses":{ "200":{ "description":"OK", "content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/ValidatorInfo"}}}}}}}},
    "/stake/delegations/{rid}": { "get": { "summary":"Delegations of RID", "parameters":[{ "name":"rid","in":"path","required":true,"schema":{"type":"string"}}], "responses":{ "200":{ "description":"OK", "content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/DelegationInfo"}}}}}}}},
    "/stake/rewards/{rid}":     { "get": { "summary":"Rewards of RID",     "parameters":[{ "name":"rid","in":"path","required":true,"schema":{"type":"string"}}], "responses":{ "200":{ "description":"OK", "content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/RewardInfo"}}}}}}}},
    "/stake/params":      { "get":  { "summary":"Stake parameters", "responses":{ "200":{ "description":"OK", "content":{"application/json":{"schema":{"$ref":"#/components/schemas/StakeParams"}}}}}}},

    "/admin/set_balance": { "post": { "summary":"Set balance (admin)", "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/SetBalanceReq"}}}}, "responses":{"200":{"description":"OK"}}}},
    "/admin/set_nonce":   { "post": { "summary":"Set nonce (admin)",   "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/SetNonceReq"}}}},   "responses":{"200":{"description":"OK"}}}},
    "/admin/bump_nonce":  { "post": { "summary":"Bump nonce (admin)",  "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/BumpNonceReq"}}}}, "responses":{"200":{"description":"OK"}}}},
    "/admin/mint":        { "post": { "summary":"Add minted amount (admin)", "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/MintReq"}}}}, "responses":{"200":{"description":"OK"}}}},
    "/admin/burn":        { "post": { "summary":"Add burned amount (admin)", "security":[{"AdminJWT":[]}], "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/BurnReq"}}}}, "responses":{"200":{"description":"OK"}}}}
  },
  "components": {
    "securitySchemes": {
      "AdminJWT":  { "type":"apiKey", "in":"header", "name":"X-Admin-JWT" },
      "BridgeKey": { "type":"apiKey", "in":"header", "name":"X-Bridge-Key" }
    },
    "schemas": {
      "OkMsg": { "type":"object", "properties": { "status": { "type":"string" } } },
      "Head":  { "type":"object", "properties": { "height": { "type":"integer" } }, "required": ["height"] },
      "Balance": { "type":"object", "properties": { "rid":{"type":"string"}, "balance":{"type":"string"}, "nonce":{"type":"integer"} }, "required":["rid","balance","nonce"] },
      "TxIn": { "type":"object", "properties": { "from":{"type":"string"}, "to":{"type":"string"}, "amount":{"type":"integer","format":"uint64"}, "nonce":{"type":"integer","format":"uint64"}, "memo":{"type":"string","nullable":true}, "sig_hex":{"type":"string"} }, "required":["from","to","amount","nonce","sig_hex"] },
      "SubmitResult": { "type":"object", "properties": { "ok":{"type":"boolean"}, "txid":{"type":"string","nullable":true}, "info":{"type":"string"} }, "required":["ok","info"] },
      "Economy": { "type":"object", "properties": { "supply":{"type":"integer"}, "burned":{"type":"integer"}, "cap":{"type":"integer"} }, "required":["supply","burned","cap"] },
      "HistoryItem": { "type":"object", "properties": { "txid":{"type":"string"}, "height":{"type":"integer"}, "from":{"type":"string"}, "to":{"type":"string"}, "amount":{"type":"integer"}, "nonce":{"type":"integer"} }, "required":["txid","height","from","to","amount","nonce"] },

      "StakeTxIn": { "type":"object", "required":["from","op","nonce","sig_hex"], "properties": { "from":{"type":"string"}, "op":{"type":"string","enum":["delegate","undelegate","claim"]}, "validator":{"type":"string"}, "amount":{"type":"integer","format":"uint64"}, "nonce":{"type":"integer","format":"uint64"}, "sig_hex":{"type":"string"}, "memo":{"type":"string"} } },
      "ValidatorInfo": { "type":"object", "properties": { "rid":{"type":"string"}, "commission_bps":{"type":"integer"}, "self_bond":{"type":"integer"}, "voting_power":{"type":"integer"}, "status":{"type":"string"} } },
      "DelegationInfo": { "type":"object", "properties": { "validator":{"type":"string"}, "amount":{"type":"integer"}, "since_height":{"type":"integer"} } },
      "RewardInfo": { "type":"object", "properties": { "validator":{"type":"string"}, "pending":{"type":"integer"}, "last_height":{"type":"integer"} } },
      "StakeParams": { "type":"object", "properties": { "min_delegate":{"type":"integer"}, "unbond_period_blocks":{"type":"integer"}, "apr_estimate_bps":{"type":"integer"} } },

      "SetBalanceReq": { "type":"object", "properties": { "rid":{"type":"string"}, "amount":{"type":"integer"} }, "required":["rid","amount"] },
      "SetNonceReq":   { "type":"object", "properties": { "rid":{"type":"string"}, "value":{"type":"integer"} }, "required":["rid","value"] },
      "BumpNonceReq":  { "type":"object", "properties": { "rid":{"type":"string"} }, "required":["rid"] },
      "MintReq":       { "type":"object", "properties": { "amount":{"type":"integer"} }, "required":["amount"] },
      "BurnReq":       { "type":"object", "properties": { "amount":{"type":"integer"} }, "required":["amount"] }
    }
  }
}

```


---

# 14. Bootstrap на новом сервере (шаги)


### Ubuntu 22.04/24.04 (root)
```bash
apt update && apt install -y curl git jq build-essential pkg-config libssl-dev \
  nginx postgresql postgresql-contrib rsync

# Rust
curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. $HOME/.cargo/env

# Клонируем проект
git clone https://github.com/Lgn-rsp/logos_lrb.git /root/logos_lrb
cd /root/logos_lrb

# По канону вставляем файлы из этой книги (см. главы 3–13):
# cd → rm -f → nano → вставить контент блока === <path> === → сохранить

# Systemd drop-ins — ЗАМЕНИТЬ CHANGE_ME на реальные секреты
sudo mkdir -p /etc/systemd/system/logos-node.service.d
sudo tee /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf >/dev/null <<EOF
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME
EOF
sudo tee /etc/systemd/system/logos-node.service.d/paths.conf >/dev/null <<EOF
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key
EOF
sudo systemctl daemon-reload

# Сборка/деплой
cargo build --release -p logos_node
install -m 0755 target/release/logos_node /opt/logos/bin/logos_node
sudo chown logos:logos /opt/logos/bin/logos_node
sudo systemctl restart logos-node
sleep 1
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo

# Nginx
nginx -t && systemctl reload nginx
```

---

# 15. Канон проверки


```bash
journalctl -u logos-node -n 120 --no-pager | egrep -i "listening|panic|error" || true
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo
curl -s http://127.0.0.1:8080/economy | jq
curl -s "http://127.0.0.1:8080/archive/blocks?limit=3" | jq
curl -s "http://127.0.0.1:8080/archive/txs?limit=3"    | jq
```

---

# Конец книги



---

# 2. Версии и окружение



=== rustc --version ===

```text
rustc 1.89.0 (29483883e 2025-08-04)

```


=== cargo --version ===

```text
cargo 1.89.0 (c24e10642 2025-06-23)

```


=== nginx -v ===

```text
nginx version: nginx/1.24.0 (Ubuntu)

```


=== psql --version ===

```text
psql (PostgreSQL) 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)

```


=== systemd env ===

```text
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos
LRB_WALLET_ORIGIN=http://127.0.0.1
LRB_DATA_PATH=/var/lib/logos/data.sled
LRB_ENABLE_FAUCET=1
RUST_LOG=info
LRB_NODE_KEY_PATH=/var/lib/logos/node_key
LRB_PHASEMIX_ENABLE=1
LRB_RATE_QPS=20
LRB_RATE_BURST=40
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_DATA_DIR=/var/lib/logos
LRB_SLOT_MS=200
LRB_MAX_BLOCK_TX=10000
LRB_MEMPOOL_CAP=100000
LRB_MAX_AMOUNT=18446744073709551615
LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
LRB_QUORUM_N=1
LRB_JWT_SECRET=CHANGE_ME
LRB_BRIDGE_KEY=CHANGE_ME

```


---

# 3. Cargo workspace



=== /root/logos_lrb/Cargo.toml ===

```toml
[workspace]
members = ["node", "lrb_core"]
resolver = "2"

[patch.crates-io]
axum        = "=0.6.20"
axum-core   = "=0.3.4"
hyper       = "=0.14.32"
http        = "=0.2.12"
http-body   = "=0.4.6"
headers     = "=0.3.9"
tower       = "=0.4.13"
tower-http  = "=0.4.4"
h2          = "=0.3.27"
sync_wrapper= "=0.1.2"
pin-project = "=1.1.10"

[workspace.dependencies]
# утилиты/сериализация
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
serde_repr   = "0.1"
anyhow       = "1"
thiserror    = "1"
once_cell    = "1.19"

# веб-стек (AXUM 0.6 + HYPER 0.14)
axum         = { version = "0.6.20", features = ["macros","http1","http2"] }
hyper        = { version = "0.14.32", features = ["full"] }
tokio        = { version = "1.40", features = ["full"] }
tower        = "0.4.13"
tower-http   = { version = "0.4.4", features = ["trace","cors","compression-gzip","decompression-gzip"] }

# крипто/кодеки
ed25519-dalek = "2"
sha2          = "0.10"
blake3        = "1.5"
hex           = "0.4"
rand          = "0.8"
base64        = "0.22"
bs58          = "0.5"
bytes         = "1.6"

# HTTP-клиент (совместим с hyper 0.14)
reqwest       = { version = "0.11", default-features = false, features = ["json","stream","gzip","brotli","deflate","rustls-tls"] }

# JWT / время
jsonwebtoken  = "9"
time          = { version = "0.3", features = ["serde","parsing"] }
chrono        = { version = "0.4", features = ["clock","std"] }

# метрики/логи
prometheus    = "0.13"
tracing       = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter","fmt","time"] }

# Postgres / архив
deadpool-postgres = "0.14"
tokio-postgres    = { version = "0.7", features = ["with-uuid-1","with-serde_json-1"] }
postgres-types    = { version = "0.2", features = ["derive","with-serde_json-1"] }

# конфиги
dotenv      = "0.15"
headers     = "0.3.9"

# локальное KV
sled        = "0.34"
bincode     = "1.3"

```


---

# 4. lrb_core (исходники + Cargo)



=== /root/logos_lrb/lrb_core/Cargo.toml ===

```toml
[package]
name        = "lrb_core"
version     = "0.1.0"
edition     = "2021"
license     = "Apache-2.0"
description = "LOGOS LRB core (ledger, mempool, filters, RCP engine)"

[lib]
name = "lrb_core"
path = "src/lib.rs"

[dependencies]
# из workspace
serde.workspace        = true
serde_json.workspace   = true
anyhow.workspace       = true
thiserror.workspace    = true
once_cell.workspace    = true

tokio.workspace        = true
reqwest.workspace      = true
bytes.workspace        = true

hex.workspace          = true
base64.workspace       = true
bs58.workspace         = true
sha2.workspace         = true
blake3.workspace       = true
ed25519-dalek.workspace= true
rand.workspace         = true
ring.workspace         = true
uuid.workspace         = true
bincode.workspace      = true

sled.workspace         = true

```


=== /root/logos_lrb/lrb_core/src/anti_replay.rs ===

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


=== /root/logos_lrb/lrb_core/src/beacon.rs ===

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


=== /root/logos_lrb/lrb_core/src/crypto.rs ===

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


=== /root/logos_lrb/lrb_core/src/dynamic_balance.rs ===

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


=== /root/logos_lrb/lrb_core/src/heartbeat.rs ===

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


=== /root/logos_lrb/lrb_core/src/ledger.rs ===

```rust
use sled::{Db, Tree};
use std::{convert::TryInto, path::Path, time::{SystemTime, UNIX_EPOCH}};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};

use crate::types::*;

// helpers
#[inline] fn be64(v: u64) -> [u8; 8] { v.to_be_bytes() }
#[inline] fn be32(v: u32) -> [u8; 4] { v.to_be_bytes() }
#[inline] fn k_bal(r:&str)->Vec<u8>{format!("bal:{r}").into_bytes()}
#[inline] fn k_nonce(r:&str)->Vec<u8>{format!("nonce:{r}").into_bytes()}

const K_HEAD:      &[u8] = b"h";    // u64
const K_HEAD_HASH: &[u8] = b"hh";   // utf8
const K_FINAL:     &[u8] = b"fin";  // u64
const K_MINTED:    &[u8] = b"mint"; // u64
const K_BURNED:    &[u8] = b"burn"; // u64

#[derive(Clone)]
pub struct Ledger {
    db: Db,
    // trees
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

impl Ledger {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
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

    /// Доступ к sled::Db для сервисных модулей узла
    #[inline] pub fn db(&self) -> &sled::Db { &self.db }

    // ====== ожидаемые узлом методы ======
    pub fn height(&self) -> anyhow::Result<u64> {
        Ok(self.head.get(K_HEAD)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0))
    }
    pub fn head(&self) -> anyhow::Result<(u64, String)> {
        let h  = self.height().unwrap_or(0);
        let hh = self.head.get(K_HEAD_HASH)?.map(|v| String::from_utf8(v.to_vec()).unwrap()).unwrap_or_default();
        Ok((h, hh))
    }
    pub fn set_head(&self, height:u64, hash:&str) -> anyhow::Result<()> {
        self.head.insert(K_HEAD, &be64(height))?;
        self.head.insert(K_HEAD_HASH, hash.as_bytes())?;
        Ok(())
    }
    pub fn set_finalized(&self, height:u64) -> anyhow::Result<()> {
        self.head.insert(K_FINAL, &be64(height))?; Ok(())
    }

    pub fn supply(&self) -> anyhow::Result<(u64,u64)> {
        let minted = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let burned = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        Ok((minted, burned))
    }
    pub fn add_minted(&self, amount:u64) -> anyhow::Result<u64> {
        let cur = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let newv = cur.saturating_add(amount);
        self.head.insert(K_MINTED, &be64(newv))?; Ok(newv)
    }
    pub fn add_burned(&self, amount:u64) -> anyhow::Result<u64> {
        let cur = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
        let newv = cur.saturating_add(amount);
        self.head.insert(K_BURNED, &be64(newv))?; Ok(newv)
    }

    pub fn get_balance(&self, rid:&str) -> anyhow::Result<u64> {
        Ok(self.db.get(k_bal(rid))?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
            .unwrap_or(0))
    }
    pub fn set_balance(&self, rid:&str, amount_u128:u128) -> anyhow::Result<()> {
        let amount: u64 = amount_u128.try_into().map_err(|_| anyhow::anyhow!("amount too large"))?;
        self.db.insert(k_bal(rid), &be64(amount))?; Ok(())
    }

    pub fn get_nonce(&self, rid:&str) -> anyhow::Result<u64> {
        Ok(self.db.get(k_nonce(rid))?
            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
            .unwrap_or(0))
    }
    pub fn set_nonce(&self, rid:&str, value:u64) -> anyhow::Result<()> {
        self.db.insert(k_nonce(rid), &be64(value))?; Ok(())
    }
    pub fn bump_nonce(&self, rid:&str) -> anyhow::Result<u64> {
        let cur = self.get_nonce(rid)?;
        let next = cur.saturating_add(1);
        self.set_nonce(rid, next)?; Ok(next)
    }

    /// Упрощённый перевод для REST `/submit_tx`
    pub fn submit_tx_simple(&self, from:&str, to:&str, amount:u64, nonce:u64, _memo:Option<String>) -> anyhow::Result<StoredTx> {
        let from_bal = self.get_balance(from)?;
        if from_bal < amount { anyhow::bail!("insufficient funds"); }
        let to_bal = self.get_balance(to)?;

        self.set_balance(from, (from_bal - amount) as u128)?;
        self.set_balance(to,   to_bal.saturating_add(amount) as u128)?;
        self.set_nonce(from, nonce)?;

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

    /// История аккаунта — возвращаем сразу `Vec<StoredTx>`
    pub fn account_txs_page(&self, rid:&str, _cursor_usize:usize, limit:usize) -> anyhow::Result<Vec<StoredTx>> {
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

    pub fn get_tx(&self, txid:&str)-> anyhow::Result<Option<StoredTx>> {
        let mut k=Vec::with_capacity(1+txid.len()); k.extend_from_slice(b"t"); k.extend_from_slice(txid.as_bytes());
        Ok(self.txs.get(k)?.map(|v| serde_json::from_slice::<StoredTx>(&v)).transpose()?)
    }

    // ====== для rcp_engine.rs ======
    pub fn index_block(&self, height: u64, hash: &str, ts: u128, txs: &[Tx]) -> anyhow::Result<()> {
        let mut ids = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            let mut h=Sha256::new();
            h.update(tx.from.0.as_bytes()); h.update(b"|");
            h.update(tx.to.0.as_bytes());   h.update(b"|");
            h.update(&tx.amount.to_be_bytes()); h.update(b"|");
            h.update(&tx.nonce.to_be_bytes());
            let txid = hex::encode(h.finalize());
            ids.push(txid.clone());

            let stx = StoredTx{
                txid: txid.clone(), from: tx.from.0.clone(), to: tx.to.0.clone(),
                amount: tx.amount, nonce: tx.nonce, height, index: i as u32, ts,
            };

            let mut k_tx=Vec::with_capacity(1+txid.len()); k_tx.extend_from_slice(b"t"); k_tx.extend_from_slice(txid.as_bytes());
            self.txs.insert(k_tx, serde_json::to_vec(&stx)?)?;

            let mut k_af=Vec::new(); k_af.extend_from_slice(b"a"); k_af.extend_from_slice(tx.from.0.as_bytes()); k_af.push(b'|'); k_af.extend_from_slice(&be64(height)); k_af.extend_from_slice(&be32(i as u32));
            self.acct.insert(k_af, txid.as_bytes())?;
            let mut k_at=Vec::new(); k_at.extend_from_slice(b"a"); k_at.extend_from_slice(tx.to.0.as_bytes());   k_at.push(b'|'); k_at.extend_from_slice(&be64(height)); k_at.extend_from_slice(&be32(i as u32));
            self.acct.insert(k_at, txid.as_bytes())?;
        }

        let mut k_b=Vec::with_capacity(1+8); k_b.extend_from_slice(b"b"); k_b.extend_from_slice(&be64(height));
        let sblk = StoredBlock{ height, hash: hash.to_string(), ts, tx_ids: ids };
        self.blocks.insert(k_b, serde_json::to_vec(&sblk)?)?;
        Ok(())
    }

    pub fn commit_block_atomic(&self, blk: &Block) -> anyhow::Result<()> {
        for tx in blk.txs.iter() {
            let fb = self.get_balance(&tx.from.0)?;
            if fb < tx.amount { anyhow::bail!("insufficient funds"); }
            let tb = self.get_balance(&tx.to.0)?;
            self.set_balance(&tx.from.0, (fb - tx.amount) as u128)?;
            self.set_balance(&tx.to.0,   tb.saturating_add(tx.amount) as u128)?;
            self.set_nonce(&tx.from.0, tx.nonce)?;
        }
        self.set_head(blk.height, &blk.block_hash)?;
        Ok(())
    }

    pub fn get_block_by_height(&self, h:u64) -> anyhow::Result<BlockHeaderView> {
        let mut k=Vec::with_capacity(9); k.extend_from_slice(b"b"); k.extend_from_slice(&be64(h));
        if let Some(v) = self.blocks.get(k)? {
            let b: StoredBlock = serde_json::from_slice(&v)?;
            Ok(BlockHeaderView{ block_hash: b.hash })
        } else {
            let hh = self.head.get(K_HEAD_HASH)?.map(|v| String::from_utf8(v.to_vec()).unwrap()).unwrap_or_default();
            Ok(BlockHeaderView{ block_hash: hh })
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BlockHeaderView { pub block_hash:String }

```


=== /root/logos_lrb/lrb_core/src/lib.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_consensus.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_filters.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_integrity.rs ===

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


=== /root/logos_lrb/lrb_core/src/quorum.rs ===

```rust
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

```


=== /root/logos_lrb/lrb_core/src/rcp_engine.rs ===

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


=== /root/logos_lrb/lrb_core/src/resonance.rs ===

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


=== /root/logos_lrb/lrb_core/src/sigpool.rs ===

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


=== /root/logos_lrb/lrb_core/src/spam_guard.rs ===

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


=== /root/logos_lrb/lrb_core/src/types.rs ===

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
pub type Nonce  = u64;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Rid(pub String); // base58(VerifyingKey)

impl Rid {
    pub fn from_pubkey(pk: &VerifyingKey) -> Self {
        Rid(bs58::encode(pk.to_bytes()).into_string())
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub id: String,        // blake3 of canonical form
    pub from: Rid,         // base58(pubkey)
    pub to: Rid,
    pub amount: Amount,
    pub nonce: Nonce,
    pub public_key: Vec<u8>, // 32 bytes (VerifyingKey)
    pub signature: Vec<u8>,  // 64 bytes (Signature)
}

impl Tx {
    /// Каноническое сообщение (без id и signature)
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let m = serde_json::json!({
            "from": self.from.as_str(),
            "to":   self.to.as_str(),
            "amount": self.amount,
            "nonce":  self.nonce,
            "public_key": B64.encode(&self.public_key),
        });
        serde_json::to_vec(&m).expect("canonical json")
    }

    pub fn compute_id(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.canonical_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Быстрая валидация формы (длины, нулевые значения)
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
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let mut h = Hasher::new();
        h.update(prev_hash.as_bytes());
        h.update(proposer.as_str().as_bytes());
        for tx in &txs { h.update(tx.id.as_bytes()); }
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

/// VerifyingKey из 32 байт (не пропускаем ошибку dalek наружу)
pub fn parse_pubkey(pk: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = pk.try_into().map_err(|_| anyhow!("bad pubkey len"))?;
    let vk = VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("bad ed25519 pubkey"))?;
    Ok(vk)
}

/// Signature из 64 байт
pub fn parse_sig(sig: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = sig.try_into().map_err(|_| anyhow!("bad signature len"))?;
    // В ed25519-dalek v2 Signature::from_bytes(&[u8;64]) -> Signature
    Ok(Signature::from_bytes(&arr))
}

```


---

# 5. node (исходники + Cargo)



=== /root/logos_lrb/node/build.rs ===

```rust
// build.rs — боевой: проставляет переменные окружения для бинаря
// LOGOS_BUILD_TS (RFC3339), LOGOS_GIT_HASH, LOGOS_PKG_VER
use std::process::Command;

fn main() {
    // 1) версия пакета из Cargo
    let pkg_ver = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    println!("cargo:rustc-env=LOGOS_PKG_VER={}", pkg_ver);

    // 2) git hash (короткий)
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "nogit".into());
    println!("cargo:rustc-env=LOGOS_GIT_HASH={}", git_hash);

    // 3) timestamp RFC3339 (через chrono)
    let ts = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=LOGOS_BUILD_TS={}", ts);

    // При изменении .git/HEAD — пересоберём
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
}

```


=== /root/logos_lrb/node/Cargo.toml ===

```toml
[package]
name        = "logos_node"
version     = "0.1.0"
edition     = "2021"
build       = "build.rs"

[dependencies]
lrb_core = { path = "../lrb_core" }

# === СТАБИЛЬНЫЙ ВЕБ-СТЕК (AXUM 0.6 + HYPER 0.14) ===
axum        = { version = "0.6.20", features = ["macros","http1","http2"] }
hyper       = { version = "0.14.32", features = ["http1","http2","server","tcp"] }
tokio       = { version = "1.40", features = ["full"] }
tower       = "0.4.13"
tower-http  = { version = "0.4.4", features = ["trace","cors","compression-gzip","decompression-gzip"] }

# === УТИЛИТЫ/СЕРИАЛИЗАЦИЯ ===
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
serde_repr  = "0.1"
anyhow      = "1"
thiserror   = "1"
once_cell   = "1.19"

# === КРИПТО/КОДЕКИ ===
ed25519-dalek = "2"
sha2   = "0.10"
blake3 = "1.5"
hex    = "0.4"
rand   = "0.8"
base64 = "0.22"

# === JWT/ВРЕМЯ ===
jsonwebtoken = "9"
time   = { version = "0.3", features = ["serde","parsing"] }
chrono = { version = "0.4", features = ["clock","std"] }

# === МЕТРИКИ/ЛОГИ ===
prometheus          = "0.13"
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["env-filter","fmt","time"] }

# === Postgres-АРХИВ ===
deadpool-postgres = "0.14"
tokio-postgres    = { version = "0.7", features = ["with-uuid-1","with-serde_json-1"] }
postgres-types    = { version = "0.2", features = ["derive","with-serde_json-1"] }

# === КОНФИГИ ===
dotenvy  = "0.15"
headers  = "0.3.9"

# === ЛОКАЛЬНОЕ KV ===
sled    = "0.34"
bincode = "1.3"

[build-dependencies]
chrono = { version = "0.4", default-features = false, features = ["clock","std"] }

```


=== /root/logos_lrb/node/src/admin.rs ===

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


=== /root/logos_lrb/node/src/api.rs ===

```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::Utc;
use serde::Serialize;

use crate::state::{SharedState, SignedTx, SignedTxBatch};
use crate::staking; // router стейкинга

// ---------- Публичные типы ответов ----------
#[derive(Serialize)]
pub struct HeadResp { pub finalized: u64, pub height: u64 }

#[derive(Serialize)]
pub struct SubmitResp { pub ok: bool, pub tx_id: String }

#[derive(Serialize)]
pub struct SubmitBatchResp(pub Vec<SubmitResp>);

#[derive(Serialize)]
pub struct BalanceResp { pub rid: String, pub balance: String, pub nonce: u64 }

// ---------- Главный роутер API (Router<SharedState>) ----------
pub fn router(state: SharedState) -> Router<SharedState> {
    Router::new()
        .route("/api/healthz",          get(healthz))
        .route("/api/head",             get(head))
        .route("/api/balance/:rid",     get(balance))
        .route("/api/submit_tx_batch",  axum::routing::post(submit_tx_batch))
        .merge(staking::router(state.clone()))      // стейкинг-роуты
        .with_state(state)
}

// ---------- healthz ----------
pub async fn healthz() -> &'static str { "ok" }

// ---------- head ----------
pub async fn head(State(state): State<SharedState>) -> Json<HeadResp> {
    let h = *state.head_height.read().await;
    Json(HeadResp { finalized: h, height: h + 1 })
}

// ---------- balance ----------
pub async fn balance(
    State(state): State<SharedState>,
    Path(rid): Path<String>,
) -> Json<BalanceResp> {
    let acc = state.accounts.get(&rid).await;
    Json(BalanceResp { rid, balance: acc.balance.to_string(), nonce: acc.nonce })
}

// ---------- запись в Postgres-архив (best-effort) ----------
async fn archive_insert_batch(state:&SharedState, txs:&[SignedTx], ids:&[String]) {
    let ts_sec = Utc::now().timestamp();
    let client = match state.archive.get().await {
        Ok(c) => c,
        Err(e) => { tracing::warn!("archive conn error: {e}"); return; }
    };

    for (i, tx) in txs.iter().enumerate() {
        let txid       = ids.get(i).cloned().unwrap_or_else(|| "unknown".to_string());
        let amount_i64 = tx.amount as i64;
        let nonce_i64  = tx.nonce  as i64;

        if let Err(e) = client.execute(
            "INSERT INTO tx(txid, rid_from, rid_to, amount, nonce, ts_sec, height)
             VALUES ($1,$2,$3,$4,$5,$6,NULL)
             ON CONFLICT (txid) DO NOTHING",
            &[&txid, &tx.from_rid, &tx.to_rid, &amount_i64, &nonce_i64, &ts_sec]
        ).await {
            tracing::warn!("archive insert error: {e}");
        }
    }
}

// ---------- submit_tx_batch ----------
pub async fn submit_tx_batch(
    State(state): State<SharedState>,
    Json(batch): Json<SignedTxBatch>,
) -> Result<Json<SubmitBatchResp>, (StatusCode, String)> {

    // TODO: серверная валидация Ed25519/каноники
    let mut resps = Vec::with_capacity(batch.txs.len());

    for tx in &batch.txs {
        // простая каноника → bytes (по желанию замени на sha256 каноники)
        let bytes = format!("{}:{}:{}:{}", tx.from_rid, tx.to_rid, tx.amount, tx.nonce).into_bytes();
        // blake3 → hex
        let tx_id = blake3::hash(&bytes).to_hex().to_string();

        // TODO: учёт в mempool/ledger (дебет/кредит/nonce++)
        resps.push(SubmitResp { ok: true, tx_id });
    }

    // запись в архив (best-effort)
    let ids: Vec<String> = resps.iter().map(|r| r.tx_id.clone()).collect();
    archive_insert_batch(&state, &batch.txs, &ids).await;

    Ok(Json(SubmitBatchResp(resps)))
}

```


=== /root/logos_lrb/node/src/archive_ingest.rs ===

```rust
use crate::state::SharedState;
use chrono::Utc;

/// Асинхронная запись tx в Postgres (fire-and-forget).
/// Без паник — ошибки только в лог.
pub async fn insert_tx(
    state: SharedState,
    tx_id: String,
    from_rid: String,
    to_rid: String,
    amount: i64,
    nonce: i64,
    height: Option<i64>,
) {
    let pool = state.archive.clone();
    // получаем клиент
    let client = match pool.get().await {
        Ok(c) => c,
        Err(e) => { tracing::warn!("archive: get conn err: {e}"); return; }
    };

    // ts_sec берём по времени узла; height даём приблизительный (финализация у тебя quorum=1 — ок).
    let ts_sec = Utc::now().timestamp();
    let h = height.unwrap_or_else(|| state.metrics.head_height.get() as i64);

    // upsert по txid
    if let Err(e) = client.execute(
        "INSERT INTO tx (txid, rid_from, rid_to, amount, nonce, ts_sec, height)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (txid) DO NOTHING",
        &[&tx_id, &from_rid, &to_rid, &amount, &nonce, &ts_sec, &h],
    ).await {
        tracing::warn!("archive: insert err: {e}");
    }
}

```


=== /root/logos_lrb/node/src/archive/pg.rs ===

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


=== /root/logos_lrb/node/src/archive.rs ===

```rust
use axum::{extract::{Path, Query, State}, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_postgres::Row;
use crate::state::SharedState;

#[derive(Serialize)]
struct TxRec {
    tx_id: String,
    from_rid: String,
    to_rid: String,
    amount: i64,
    ts_sec: i64,
}

#[derive(Deserialize)]
pub struct HistParams { pub limit: Option<i64> }

/// GET /api/archive/history/:rid?limit=50
pub async fn history(
    State(state): State<SharedState>,
    Path(rid): Path<String>,
    Query(params): Query<HistParams>,
) -> impl IntoResponse {
    let limit: i64 = params.limit.unwrap_or(50).clamp(1, 500);

    let client = match state.archive.get().await {
        Ok(c) => c,
        Err(e) => return Json(json!({"ok":false,"error":format!("db conn error: {e}")})),
    };

    // Читаем из стандартизированного VIEW tx_std
    let rows: Vec<Row> = match client.query(
        "SELECT tx_id, from_rid, to_rid, amount, ts_sec
         FROM tx_std
         WHERE from_rid=$1 OR to_rid=$1
         ORDER BY height DESC NULLS LAST, ts_sec DESC
         LIMIT $2::bigint",
        &[&rid.as_str(), &limit],
    ).await {
        Ok(r) => r,
        Err(e) => return Json(json!({"ok":false,"error":format!("db query error: {e}")})),
    };

    let history: Vec<TxRec> = rows.into_iter().map(|r| TxRec{
        tx_id:    r.get(0),
        from_rid: r.get(1),
        to_rid:   r.get(2),
        amount:   r.get(3),
        ts_sec:   r.get(4),
    }).collect();

    Json(json!({"ok":true,"history":history}))
}

/// GET /api/archive/tx/:tx_id
pub async fn tx(
    State(state): State<SharedState>,
    Path(tx_id): Path<String>,
) -> impl IntoResponse {
    let client = match state.archive.get().await {
        Ok(c) => c,
        Err(e) => return Json(json!({"ok":false,"error":format!("db conn error: {e}")})),
    };

    let row_opt = match client.query_opt(
        "SELECT tx_id, from_rid, to_rid, amount, ts_sec
         FROM tx_std
         WHERE tx_id=$1",
        &[&tx_id],
    ).await {
        Ok(r) => r,
        Err(e) => return Json(json!({"ok":false,"error":format!("db query error: {e}")})),
    };

    if let Some(r) = row_opt {
        let rec = TxRec{
            tx_id:    r.get(0),
            from_rid: r.get(1),
            to_rid:   r.get(2),
            amount:   r.get(3),
            ts_sec:   r.get(4),
        };
        return Json(json!({"ok":true,"tx":rec}));
    }
    Json(json!({"ok":true,"tx":null}))
}

```


=== /root/logos_lrb/node/src/archive/sqlite.rs ===

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


=== /root/logos_lrb/node/src/auth.rs ===

```rust
//! Auth-модуль: защита bridge/admin. Admin — только JWT (HS256). Bridge — X-Bridge-Key.
//! Обязательные переменные окружения: LRB_BRIDGE_KEY, LRB_JWT_SECRET.

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

fn forbid_default(val: &str) -> Result<()> {
    let low = val.to_lowercase();
    let banned = ["", "change_me", "changeme", "dev_secret", "default", "empty", "test", "123"];
    if banned.iter().any(|b| low == *b) {
        return Err(anyhow!("insecure default key"));
    }
    Ok(())
}

/* ---------------- Bridge (ключ обязателен) ---------------- */

pub fn require_bridge(headers: &HeaderMap) -> Result<()> {
    let expect = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY CHANGE_ME not set"))?;
    forbid_default(&expect)?;
    let got = headers
        .get("X-Bridge-Key")
        .ok_or_else(|| anyhow!("missing X-Bridge-Key"))?
        .to_str()
        .map_err(|_| anyhow!("invalid X-Bridge-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad bridge key")); }
    Ok(())
}

/* ---------------- Admin (только JWT HS256) ---------------- */

#[derive(Debug, Deserialize)]
struct AdminClaims {
    sub: String,
    iat: Option<u64>,
    exp: Option<u64>,
}

pub fn require_admin(headers: &HeaderMap) -> Result<()> {
    let token = headers
        .get("X-Admin-JWT")
        .ok_or_else(|| anyhow!("missing X-Admin-JWT"))?
        .to_str()
        .map_err(|_| anyhow!("invalid X-Admin-JWT"))?
        .to_string();

    let secret = std::env::var("LRB_JWT_SECRET").map_err(|_| anyhow!("LRB_JWT_SECRET CHANGE_ME not set"))?;
    forbid_default(&secret)?;

    let data = decode::<AdminClaims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| anyhow!("admin jwt invalid: {e}"))?;

    if data.claims.sub != "admin" {
        return Err(anyhow!("forbidden"));
    }
    Ok(())
}

/* ---------------- Стартовая проверка секретов ---------------- */

pub fn assert_secrets_on_start() -> Result<()> {
    // Bridge/JWT обязаны быть заданы. Если пусты — валим процесс.
    for (key, val) in [("LRB_BRIDGE_KEY","bridge"), ("LRB_JWT_SECRET","jwt")] {
        let v = std::env::var(key).map_err(|_| anyhow!("{key} is not set"))?;
        forbid_default(&v)?;
    }
    Ok(())
}

```


=== /root/logos_lrb/node/src/bridge.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/fork.rs ===

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


=== /root/logos_lrb/node/src/gossip.rs ===

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


=== /root/logos_lrb/node/src/guard.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/lib.rs ===

```rust
//! LOGOS node library modules (lib target).
pub mod state;   pub use state::AppState;
pub mod auth;
pub mod archive;
pub mod staking;
pub mod api;

```


=== /root/logos_lrb/node/src/main.rs ===

```rust
mod state;
mod producer;
mod metrics;
mod api;
mod archive;
mod staking;

use crate::state::AppState;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::get, Router};
use axum::{http::StatusCode, response::IntoResponse, Json};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{EnvFilter, fmt};
use serde_json::json;

async fn json_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({"ok":false,"error":"not found"})))
}

#[tokio::main]
async fn main() {
    // Логи
    fmt().with_env_filter(
        EnvFilter::from_default_env().add_directive("info".parse().unwrap())
    ).init();

    // Конфиги
    let slot_ms: u64 = std::env::var("LRB_SLOT_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(500);
    let data_path     = std::env::var("LRB_DATA_PATH").unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());
    let db            = sled::open(&data_path).expect("open sled");

    // Postgres pool (архив)
    let archive_url = std::env::var("LRB_ARCHIVE_URL").expect("LRB_ARCHIVE_URL not set");
    let cfg: tokio_postgres::Config = archive_url.parse().expect("bad LRB_ARCHIVE_URL");
    let mgr  = deadpool_postgres::Manager::new(cfg, tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(mgr).max_size(32).build().expect("pg pool");

    // Состояние
    let state = Arc::new(AppState::new(slot_ms, db, pool));

    // Продюсер
    let st = state.clone();
    tokio::spawn(async move { producer::run_block_producer(st).await; });

    // API (включая /api/stake/* и /api/submit_tx_batch)
    let api_router: Router<Arc<AppState>> = api::router(state.clone());

    // Итоговый Router
    let app: Router<Arc<AppState>> = Router::new()
        .merge(api_router)
        .route("/metrics", get({
            let s = state.clone();
            move || metrics::metrics_handler(s.clone())
        }))
        .fallback(json_404)
        .layer(TraceLayer::new_for_http());

    // HTTP
    let port: u16 = std::env::var("LRB_HTTP_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8080);
    let addr: SocketAddr = SocketAddr::from(([0,0,0,0], port));

    tracing::info!("logos-node on http://{addr}, slot_ms={slot_ms}");

    // Axum 0.6: стабильный запуск (без make_service танцев)
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("serve");
}

```


=== /root/logos_lrb/node/src/metrics.rs ===

```rust
use axum::response::IntoResponse;
use crate::state::SharedState;

pub async fn metrics_handler(state: SharedState)->impl IntoResponse{
    let body=state.metrics.render();
    ([(axum::http::header::CONTENT_TYPE,"text/plain; version=0.0.4")], body)
}

```


=== /root/logos_lrb/node/src/openapi.rs ===

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


=== /root/logos_lrb/node/src/peers.rs ===

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


=== /root/logos_lrb/node/src/producer.rs ===

```rust
use crate::state::{SharedState, SignedTx};
use tokio::time::{interval, Duration};
use sha2::{Sha256, Digest};

pub async fn run_block_producer(state: SharedState){
    let mut ticker=interval(Duration::from_millis(state.slot_ms));
    let mut prev_h: u64 = 0;
    loop{
        ticker.tick().await;
        state.metrics.mempool_depth.set(state.mempool.depth().await as i64);

        let txs:Vec<SignedTx>=state.mempool.drain_for_block(10_000).await;

        let mut hasher=Sha256::new();
        for t in &txs{
            hasher.update(t.from_rid.as_bytes());
            hasher.update(t.to_rid.as_bytes());
            hasher.update(t.amount.to_le_bytes());
            hasher.update(t.nonce.to_le_bytes());
            hasher.update(hex::decode(&t.pubkey_hex).unwrap_or_default());
            hasher.update(hex::decode(&t.sig_hex).unwrap_or_default());
        }
        let block_hash_hex=hex::encode(hasher.finalize());

        {
            let mut hh=state.head_height.write().await;
            *hh += 1;
            state.metrics.head_height.set(*hh as i64);
            let dh=*hh - prev_h; prev_h=*hh;
            let bps=(dh as f64)/(state.slot_ms as f64/1000.0);
            state.metrics.bps.set(bps.round() as i64);
        }

        {
            let mut t=state.last_block_time.write().await;
            *t=std::time::Instant::now();
        }

        tracing::info!(txs=txs.len(), head=state.metrics.head_height.get(), "block produced {}", block_hash_hex);
        // Здесь можно вызвать архив/ledger-пайплайн для записи блока/tx.
    }
}

```


=== /root/logos_lrb/node/src/stake.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/staking.rs ===

```rust
use axum::{Router, Json, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use chrono::Utc;
use axum::http::StatusCode;
use crate::state::{SharedState, Delegation};

#[derive(Deserialize)]
pub struct StakeReq { pub delegator:String, pub validator:String, pub amount:u128 }

#[derive(Serialize)]
pub struct OkResp { pub ok: bool }

#[derive(Serialize)]
pub struct MyList { pub ok: bool, pub list: Vec<Delegation> }

pub fn router(state: SharedState) -> Router<SharedState> {
    Router::new()
        .route("/api/stake/delegate",   post(delegate))
        .route("/api/stake/undelegate", post(undelegate))
        .route("/api/stake/claim",      post(claim))
        .route("/api/stake/my/:rid",    axum::routing::get(my))
        .with_state(state)
}

async fn delegate(State(state):State<SharedState>, Json(req):Json<StakeReq>)
    -> Result<Json<OkResp>,(StatusCode,String)>
{
    if req.amount==0 { return Err((StatusCode::BAD_REQUEST,"amount=0".into())); }
    state.accounts.debit_checked(&req.delegator, req.amount).await
        .map_err(|e|(StatusCode::BAD_REQUEST,e.to_string()))?;
    let d = Delegation{ validator:req.validator.clone(), amount:req.amount, since:Utc::now().timestamp() as u64 };
    state.staking.add(&req.delegator, d).await;
    Ok(Json(OkResp{ok:true}))
}

async fn undelegate(State(state):State<SharedState>, Json(req):Json<StakeReq>)
    -> Result<Json<OkResp>,(StatusCode,String)>
{
    if req.amount==0 { return Err((StatusCode::BAD_REQUEST,"amount=0".into())); }
    state.staking.remove(&req.delegator,&req.validator,req.amount).await
        .map_err(|e|(StatusCode::BAD_REQUEST,e.to_string()))?;
    state.accounts.credit(&req.delegator, req.amount).await;
    Ok(Json(OkResp{ok:true}))
}

async fn claim(State(_state):State<SharedState>, Json(_req):Json<StakeReq>)
    -> Result<Json<OkResp>,(StatusCode,String)>
{
    // mock начислений — ok:true
    Ok(Json(OkResp{ok:true}))
}

async fn my(State(state):State<SharedState>, axum::extract::Path(rid):axum::extract::Path<String>)
    -> Json<MyList>
{
    let list = state.staking.list(&rid).await;
    Json(MyList{ ok:true, list })
}

```


=== /root/logos_lrb/node/src/state.rs ===

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Instant;
use std::collections::HashMap;

use prometheus::{Registry, IntGauge, IntGaugeVec, Encoder, TextEncoder, IntCounter};
use serde::{Serialize, Deserialize};
use sled::{Db, Tree};
use deadpool_postgres::Pool; // <— ПУЛ PG

// ================== Метрики ==================
#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub head_height: IntGauge,
    pub bps: IntGauge,
    pub mempool_depth: IntGauge,
    pub http_reqs: IntCounter,
    pub http_codes: IntGaugeVec,
}
impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let head_height = IntGauge::new("logos_head_height","Current finalized head height").unwrap();
        let bps = IntGauge::new("logos_bps","Estimated blocks per second").unwrap();
        let mempool_depth = IntGauge::new("logos_mempool_depth","Txs waiting in mempool").unwrap();
        let http_reqs = IntCounter::new("logos_http_requests_total","HTTP requests total").unwrap();
        let http_codes = IntGaugeVec::new(
            prometheus::Opts::new("logos_http_codes","HTTP codes by path"),
            &["path","code"]
        ).unwrap();
        for m in [&head_height,&bps,&mempool_depth] { registry.register(Box::new(m.clone())).ok(); }
        registry.register(Box::new(http_reqs.clone())).ok();
        registry.register(Box::new(http_codes.clone())).ok();
        Self{ registry, head_height, bps, mempool_depth, http_reqs, http_codes }
    }
    pub fn render(&self)->String{
        let mut buf=Vec::new(); let enc=TextEncoder::new(); let mf=self.registry.gather();
        enc.encode(&mf,&mut buf).ok(); String::from_utf8_lossy(&buf).to_string()
    }
}

// ================== Tx типы ==================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTx{
    pub from_rid:String,
    pub to_rid:String,
    pub amount:u64,
    pub nonce:u64,
    pub pubkey_hex:String,
    pub sig_hex:String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTxBatch{ pub txs:Vec<SignedTx> }

// ================== Аккаунты (sled) ==================
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account { pub balance: u128, pub nonce: u64 }
#[derive(Clone)]
pub struct Accounts { tree: Tree }
impl Accounts {
    pub fn new(db:&Db) -> Self { Self{ tree: db.open_tree("accounts").expect("accounts tree") } }
    fn load(&self, rid:&str) -> Account {
        match self.tree.get(rid.as_bytes()).ok().flatten() {
            Some(ivec) => bincode::deserialize(&ivec).unwrap_or_default(),
            None => Account::default(),
        }
    }
    fn store(&self, rid:&str, acc:&Account) {
        let bytes = bincode::serialize(acc).expect("encode account");
        self.tree.insert(rid.as_bytes(), bytes).expect("store account");
    }
    pub async fn get(&self, rid:&str) -> Account { self.load(rid) }
    pub async fn credit(&self, rid:&str, amount:u128) {
        let mut acc = self.load(rid); acc.balance = acc.balance.saturating_add(amount);
        self.store(rid, &acc);
    }
    pub async fn debit_checked(&self, rid:&str, amount:u128) -> Result<(), &'static str> {
        let mut acc = self.load(rid); if acc.balance < amount { return Err("insufficient"); }
        acc.balance -= amount; self.store(rid, &acc); Ok(())
    }
    pub async fn expect_and_inc_nonce(&self, rid:&str, want:u64) -> Result<(), &'static str> {
        let mut acc = self.load(rid); let next = acc.nonce.saturating_add(1);
        if want != next { return Err("bad nonce"); } acc.nonce = next; self.store(rid, &acc); Ok(())
    }
}

// ================== Стейкинг (RAM) ==================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation { pub validator:String, pub amount:u128, pub since:u64 }
#[derive(Clone, Default)]
pub struct Staking { inner: Arc<RwLock<HashMap<String, Vec<Delegation>>>> }
impl Staking {
    pub async fn list(&self, delegator:&str) -> Vec<Delegation> {
        self.inner.read().await.get(delegator).cloned().unwrap_or_default()
    }
    pub async fn add(&self, delegator:&str, d:Delegation) {
        self.inner.write().await.entry(delegator.to_string()).or_default().push(d);
    }
    pub async fn remove(&self, delegator:&str, validator:&str, amount:u128) -> Result<(), &'static str> {
        let mut m=self.inner.write().await; let v=m.entry(delegator.to_string()).or_default();
        let mut left=amount;
        for dg in v.iter_mut() {
            if dg.validator==validator && dg.amount>0 {
                let take = dg.amount.min(left); dg.amount -= take; left -= take; if left==0 { break; }
            }
        }
        if left>0 { return Err("not enough delegated"); }
        v.retain(|dg| dg.amount>0);
        Ok(())
    }
}

// ================== Mempool ==================
#[derive(Clone)]
pub struct Mempool{ inner: Arc<RwLock<Vec<SignedTx>>> }
impl Mempool{
    pub fn new()->Self{ Self{ inner:Arc::new(RwLock::new(Vec::new())) } }
    pub async fn push(&self, tx:SignedTx){ self.inner.write().await.push(tx); }
    pub async fn push_many(&self, txs:Vec<SignedTx>){ self.inner.write().await.extend(txs); }
    pub async fn drain_for_block(&self, max:usize)->Vec<SignedTx>{
        let mut w=self.inner.write().await; let take=max.min(w.len()); w.drain(0..take).collect()
    }
    pub async fn depth(&self)->usize{ self.inner.read().await.len() }
}

// ================== AppState ==================
pub struct AppState{
    pub metrics: Metrics,
    pub mempool: Mempool,
    pub accounts: Accounts,
    pub staking: Staking,
    pub slot_ms: u64,
    pub last_block_time: Arc<RwLock<Instant>>,
    pub head_height: Arc<RwLock<u64>>,
    pub db: Db,
    pub archive: Pool,  // <— ПУЛ PG ДЛЯ ИСТОРИИ
}
impl AppState{
    pub fn new(slot_ms:u64, db:Db, archive:Pool)->Self{
        let accounts = Accounts::new(&db);
        Self{
            metrics: Metrics::new(),
            mempool: Mempool::new(),
            accounts,
            staking: Staking::default(),
            slot_ms,
            last_block_time: Arc::new(RwLock::new(Instant::now())),
            head_height: Arc::new(RwLock::new(0)),
            db,
            archive,
        }
    }
}
pub type SharedState = Arc<AppState>;

```


=== /root/logos_lrb/node/src/storage.rs ===

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


=== /root/logos_lrb/node/src/version.rs ===

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


=== /root/logos_lrb/node/src/wallet.rs ===

```rust
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

```


---

# 6. Web Wallet



=== /root/logos_lrb/www/wallet/app.html ===

```html
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

```


=== /root/logos_lrb/www/wallet/app.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/app.v2.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/app.v3.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/auth.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/index.html ===

```html
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

```


=== /root/logos_lrb/www/wallet/login.html ===

```html
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

```


=== /root/logos_lrb/www/wallet/staking.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/wallet.css ===

```css
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

```


=== /root/logos_lrb/www/wallet/wallet.js ===

```javascript
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

```


---

# 7. Explorer



=== /root/logos_lrb/www/explorer/index.html ===

```html
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

```


---

# 8. Nginx конфиги



=== /etc/nginx/conf.d/logos.conf ===

```nginx
server { listen 80; server_name _; return 301 https://$host$request_uri; }

server {
  listen 443 ssl http2;
  server_name 45-159-248-232.sslip.io;

  ssl_certificate     /etc/letsencrypt/live/<YOUR_DOMAIN>/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/<YOUR_DOMAIN>/privkey.pem;

  root /opt/logos/www; index index.html;

  # --- API ---
  location /api/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
  }

  # --- Wallet (PWA) ---
  location /wallet/ {
    try_files $uri /wallet/index.html;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'self';" always;
    add_header Cache-Control "no-store" always;
  }

  # --- Explorer (ОДИН блок, без дублей) ---
  location /explorer/ {
    try_files $uri /explorer/index.html;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self';" always;
    add_header Cache-Control "no-store" always;
  }

  # статика (не кэшируем при разработке)
  location ~* \.(?:css|js|ico|png|jpg|jpeg|svg|woff2?)$ {
    try_files $uri =404;
    add_header Cache-Control "no-store" always;
  }

  location / {
    try_files $uri /index.html;
    add_header Cache-Control "no-store" always;
  }
}

```


---

# 9. Systemd (unit + drop-ins)



=== systemctl cat logos-node ===

```text
# /etc/systemd/system/logos-node.service
[Unit]
Description=LOGOS LRB Node (Axum REST on :8080)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos
ExecStart=/opt/logos/bin/logos_node
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/logos-node.service.d/archive.conf
[Service]
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos

# /etc/systemd/system/logos-node.service.d/cors.conf
[Service]
Environment=LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io

# /etc/systemd/system/logos-node.service.d/data.conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled

# /etc/systemd/system/logos-node.service.d/exec.conf
[Service]
ExecStart=
ExecStart=/opt/logos/bin/logos_node
WorkingDirectory=/opt/logos

# /etc/systemd/system/logos-node.service.d/faucet.conf
[Service]
Environment=LRB_ENABLE_FAUCET=1

# /etc/systemd/system/logos-node.service.d/hardening.conf
[Service]
# Ресурсы
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
MemoryMax=2G
CPUQuota=200%

# Sandbox/защиты
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service @network-io

# /etc/systemd/system/logos-node.service.d/keys.conf
[Service]
EnvironmentFile=/etc/logos/keys.env

# /etc/systemd/system/logos-node.service.d/loglevel.conf
[Service]
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/paths.conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

# /etc/systemd/system/logos-node.service.d/phasemix.conf
[Service]
Environment=LRB_PHASEMIX_ENABLE=1

# /etc/systemd/system/logos-node.service.d/ratelimit.conf
[Service]
Environment=LRB_RATE_QPS=30
Environment=LRB_RATE_BURST=60
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

# /etc/systemd/system/logos-node.service.d/runas.conf
[Service]
User=logos
Group=logos
# Разрешаем запись туда, где нужно (данные/секреты)
ReadWritePaths=/var/lib/logos /etc/logos

# /etc/systemd/system/logos-node.service.d/security.conf
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true

# /etc/systemd/system/logos-node.service.d/tuning.conf
[Service]
Environment=LRB_NODE_LISTEN=0.0.0.0:8080
Environment=LRB_DATA_DIR=/var/lib/logos
Environment=LRB_WALLET_ORIGIN=http://127.0.0.1
Environment=LRB_RATE_QPS=20
Environment=LRB_RATE_BURST=40
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/zz-consensus.conf
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

# /etc/systemd/system/logos-node.service.d/zz-logging.conf
[Service]
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


=== /etc/systemd/system/logos-node.service.d/archive.conf ===

```nginx
[Service]
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos

```


=== /etc/systemd/system/logos-node.service.d/cors.conf ===

```nginx
[Service]
Environment=LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io

```


=== /etc/systemd/system/logos-node.service.d/data.conf ===

```nginx
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled

```


=== /etc/systemd/system/logos-node.service.d/exec.conf ===

```nginx
[Service]
ExecStart=
ExecStart=/opt/logos/bin/logos_node
WorkingDirectory=/opt/logos

```


=== /etc/systemd/system/logos-node.service.d/faucet.conf ===

```nginx
[Service]
Environment=LRB_ENABLE_FAUCET=1

```


=== /etc/systemd/system/logos-node.service.d/hardening.conf ===

```nginx
[Service]
# Ресурсы
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
MemoryMax=2G
CPUQuota=200%

# Sandbox/защиты
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service @network-io

```


=== /etc/systemd/system/logos-node.service.d/keys.conf ===

```nginx
[Service]
EnvironmentFile=/etc/logos/keys.env

```


=== /etc/systemd/system/logos-node.service.d/loglevel.conf ===

```nginx
[Service]
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/paths.conf ===

```nginx
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

```


=== /etc/systemd/system/logos-node.service.d/phasemix.conf ===

```nginx
[Service]
Environment=LRB_PHASEMIX_ENABLE=1

```


=== /etc/systemd/system/logos-node.service.d/ratelimit.conf ===

```nginx
[Service]
Environment=LRB_RATE_QPS=30
Environment=LRB_RATE_BURST=60
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

```


=== /etc/systemd/system/logos-node.service.d/runas.conf ===

```nginx
[Service]
User=logos
Group=logos
# Разрешаем запись туда, где нужно (данные/секреты)
ReadWritePaths=/var/lib/logos /etc/logos

```


=== /etc/systemd/system/logos-node.service.d/security.conf ===

```nginx
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true

```


=== /etc/systemd/system/logos-node.service.d/tuning.conf ===

```nginx
[Service]
Environment=LRB_NODE_LISTEN=0.0.0.0:8080
Environment=LRB_DATA_DIR=/var/lib/logos
Environment=LRB_WALLET_ORIGIN=http://127.0.0.1
Environment=LRB_RATE_QPS=20
Environment=LRB_RATE_BURST=40
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/zz-consensus.conf ===

```nginx
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

```


=== /etc/systemd/system/logos-node.service.d/zz-keys.conf.disabled ===

```text
[Service]
# Читаем файл с секретами (на будущее, если захочешь использовать keys.env)
EnvironmentFile=-/etc/logos/keys.env

# Узловые параметры (жёстко, чтобы сервис точно стартовал)
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_SK_HEX=31962399e9b0e278af3b328bc6e30bbd17d90c700a5f6c7ad3c4d4418ed8fd83
Environment=LRB_ADMIN_KEY=0448012cf1738fd048b154a1c367cb7cb42e3fee4ab26fb04268ab91e09fb475
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


=== /etc/systemd/system/logos-node.service.d/zz-logging.conf ===

```nginx
[Service]
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf ===

```nginx
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


---

# 10. Бэкап sled



=== /usr/local/bin/logos-sled-backup.sh ===

```bash
#!/usr/bin/env bash
set -euo pipefail

SRC="/var/lib/logos/data.sled"
DST="/root/sled_backups"
KEEP=96          # ~24 часа при шаге 15 минут
MAX_GB=20        # общий лимит в гигабайтах

TS="$(date -Iseconds)"
mkdir -p "$DST"

# 1) инкрементальный снапшот (rsync в новую папку)
rsync -a --delete "$SRC/" "$DST/data.sled.$TS.bak/"

# 2) ротация по количеству
mapfile -t LIST < <(ls -1dt "$DST"/data.sled.*.bak 2>/dev/null || true)
if (( ${#LIST[@]} > KEEP )); then
  for d in "${LIST[@]:$KEEP}"; do
    rm -rf -- "$d" || true
  done
fi

# 3) ротация по общему размеру
du_mb() { du -sm "$DST" | awk '{print $1}'; }
while (( $(du_mb) > MAX_GB*1024 )); do
  OLDEST="$(ls -1dt "$DST"/data.sled.*.bak | tail -n 1 || true)"
  [[ -n "$OLDEST" ]] || break
  rm -rf -- "$OLDEST" || true
done

```


=== /etc/systemd/system/logos-sled-backup.service ===

```ini
[Unit]
Description=Backup sled to /root/sled_backups

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/logos-sled-backup.sh

```


=== /etc/systemd/system/logos-sled-backup.timer ===

```ini
[Unit]
Description=Run sled backup every 15 minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
Unit=logos-sled-backup.service

[Install]
WantedBy=timers.target

```


---

# 11. Prometheus/Grafana (alerts)



=== /etc/prometheus/rules/logos_alerts.yml ===

```yaml
groups:
- name: logos-runtime
  rules:
  - alert: HeightStuck
    expr: increase(logos_head_height[5m]) == 0
    for: 3m
    labels: { severity: critical }
    annotations: { summary: "Head не растёт 5 минут" }

  - alert: HighLatencyP99
    expr: histogram_quantile(0.99, sum(rate(http_request_duration_ms_bucket[5m])) by (le)) > 120
    for: 2m
    labels: { severity: warning }
    annotations: { summary: "p99 HTTP > 120 ms" }

  - alert: TLSExpirySoon
    expr: (probe_ssl_earliest_cert_expiry - time()) < 14*24*3600
    for: 10m
    labels: { severity: warning }
    annotations: { summary: "TLS сертификат истекает < 14 дней" }

```


---

# 12. Конфиги



=== /root/logos_lrb/configs/genesis.yaml ===

```yaml
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

```


=== /root/logos_lrb/configs/logos_config.yaml ===

```yaml
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

```


---

# 13. OpenAPI контракт



=== GET /openapi.json ===

```text
{"error":"not found","ok":false}
```


---

# 14. Bootstrap на новом сервере (шаги)


### Ubuntu 22.04/24.04 (root)
```bash
apt update && apt install -y curl git jq build-essential pkg-config libssl-dev \
  nginx postgresql postgresql-contrib rsync

# Rust
curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. $HOME/.cargo/env

# Клонируем проект
git clone https://github.com/Lgn-rsp/logos_lrb.git /root/logos_lrb
cd /root/logos_lrb

# По канону вставляем файлы из этой книги (см. главы 3–13):
# cd → rm -f → nano → вставить контент блока === <path> === → сохранить

# Systemd drop-ins — ЗАМЕНИТЬ CHANGE_ME на реальные секреты
sudo mkdir -p /etc/systemd/system/logos-node.service.d
sudo tee /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf >/dev/null <<EOF
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME
EOF
sudo tee /etc/systemd/system/logos-node.service.d/paths.conf >/dev/null <<EOF
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key
EOF
sudo systemctl daemon-reload

# Сборка/деплой
cargo build --release -p logos_node
install -m 0755 target/release/logos_node /opt/logos/bin/logos_node
sudo chown logos:logos /opt/logos/bin/logos_node
sudo systemctl restart logos-node
sleep 1
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo

# Nginx
nginx -t && systemctl reload nginx
```

---

# 15. Канон проверки


```bash
journalctl -u logos-node -n 120 --no-pager | egrep -i "listening|panic|error" || true
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo
curl -s http://127.0.0.1:8080/economy | jq
curl -s "http://127.0.0.1:8080/archive/blocks?limit=3" | jq
curl -s "http://127.0.0.1:8080/archive/txs?limit=3"    | jq
```

---

# Конец книги



---

# 2. Версии и окружение



=== rustc --version ===

```text
rustc 1.89.0 (29483883e 2025-08-04)

```


=== cargo --version ===

```text
cargo 1.89.0 (c24e10642 2025-06-23)

```


=== nginx -v ===

```text
nginx version: nginx/1.24.0 (Ubuntu)

```


=== psql --version ===

```text
psql (PostgreSQL) 16.10 (Ubuntu 16.10-0ubuntu0.24.04.1)

```


=== systemd env ===

```text
Environment=RUST_LOG=info
LOGOS_PG_DSN=/etc:LOGOS_PG_DSN%
LRB_JWT_SECRET=CHANGE_ME
LRB_BRIDGE_KEY=CHANGE_ME
LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos
LRB_WALLET_ORIGIN=http://127.0.0.1
LRB_DATA_PATH=/var/lib/logos/data.sled
LRB_ENABLE_FAUCET=1
LRB_NODE_KEY_PATH=/var/lib/logos/node_key
LRB_PHASEMIX_ENABLE=1
LRB_RATE_QPS=20
LRB_RATE_BURST=40
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_DATA_DIR=/var/lib/logos
LRB_SLOT_MS=200
LRB_MAX_BLOCK_TX=10000
LRB_MEMPOOL_CAP=100000
LRB_MAX_AMOUNT=18446744073709551615
LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
LRB_QUORUM_N=1

```


---

# 3. Cargo workspace



=== /root/logos_lrb/Cargo.toml ===

```toml
[workspace]
members = [
    "lrb_core",
    "node",
    "tools/seed_balance",
]
resolver = "2"

[workspace.dependencies]
# базовые
anyhow = "1.0.89"
thiserror = "1.0.63"

# async/логирование
tokio = { version = "1.39", features = ["rt-multi-thread", "macros", "time", "signal", "net"] }
futures = "0.3"
tracing = "0.1.40"
tracing-subscriber = { version = "0.3.18", features = ["fmt", "env-filter"] }

# serde
serde = { version = "1.0.210", features = ["derive"] }
serde_json = "1.0.128"
serde_repr = "0.1.19"

# http-стек (Axum 0.7 / Hyper 1.x)
axum = { version = "0.7.9", features = ["macros", "json", "tokio"] }
hyper = { version = "1.4", features = ["http1", "http2", "server", "client"] }
hyper-util = "0.1.17"
http = "1.1"
http-body-util = "0.1.2"
tower = { version = "0.4.13", features = ["make"] }   # ← ВАЖНО: включили feature "make"
tower-http = { version = "0.5.2", features = ["trace", "cors", "limit", "util", "compression-full"] }
bytes = "1.6.0"

# крипто/кодеки
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
bs58 = "0.5"
hex = "0.4"
base64 = "0.22"
blake3 = "1.5"
ring = "0.17.8"
rand = "0.8"

# хранилища/время
sled = "0.34"
time = "0.3.36"
lazy_static = "1.5"
tokio-util = "0.7"

# Postgres (архив)
tokio-postgres = { version = "0.7", features = ["with-uuid-1"] }

# сеть/утилиты
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
uuid = { version = "1.10", features = ["v4", "serde"] }
bincode = "1.3"

# auth/метрики
jsonwebtoken = "9.3"
prometheus = "0.13.4"

[profile.release]
lto = "thin"
codegen-units = 1
panic = "abort"
opt-level = "z"

[workspace.lints.rust]
unsafe_code = "forbid"
unused_imports = "deny"

```


---

# 4. lrb_core (исходники + Cargo)



=== /root/logos_lrb/lrb_core/Cargo.toml ===

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
bytes = { workspace = true }
uuid = { workspace = true }
sled = { workspace = true }
time = { workspace = true }
ed25519-dalek = { workspace = true }
rand = { workspace = true }
bs58 = { workspace = true }
tracing = { workspace = true }
hex = { workspace = true }
tokio = { workspace = true }
# добивка под ошибки
blake3 = { workspace = true }
base64 = { workspace = true }
ring = { workspace = true }
reqwest = { workspace = true }

```


=== /root/logos_lrb/lrb_core/src/anti_replay.rs ===

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


=== /root/logos_lrb/lrb_core/src/beacon.rs ===

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


=== /root/logos_lrb/lrb_core/src/crypto.rs ===

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


=== /root/logos_lrb/lrb_core/src/dynamic_balance.rs ===

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


=== /root/logos_lrb/lrb_core/src/heartbeat.rs ===

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


=== /root/logos_lrb/lrb_core/src/ledger.rs ===

```rust
use anyhow::Result;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sled::Db;
use uuid::Uuid;

// нужно для base64 decode (Engine::decode)
use base64::Engine;

#[derive(Clone)]
pub struct Ledger {
    db: Db,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub sig: String, // HEX или BASE64
}

impl Tx {
    pub fn id_string(&self) -> String {
        format!("{}-{}", Uuid::new_v4(), self.nonce)
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(128);
        v.extend(self.from.as_bytes());
        v.push(b'|');
        v.extend(self.to.as_bytes());
        v.push(b'|');
        v.extend(self.amount.to_be_bytes());
        v.push(b'|');
        v.extend(self.nonce.to_be_bytes());
        v
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub id: String,
    pub txs: Vec<Tx>,
}

impl Block {
    pub fn new_from_txs(txs: &[Tx]) -> Self {
        let id = format!("blk-{}", Uuid::new_v4());
        Self { height: 0, id, txs: txs.to_vec() }
    }
}

#[derive(Debug)]
pub enum VerifyResult { Ok, BadSig, Malformed, Replay, Insufficient }

impl Ledger {
    // ---------- открытие/служебное ----------
    pub fn open_default(path: &str) -> Result<Self> {
        Ok(Self { db: sled::open(path)? })
    }

    pub fn head_height(&self) -> u64 {
        self.db.get("head").ok().flatten().map(|iv| {
            let mut arr=[0u8;8]; arr.copy_from_slice(&iv); u64::from_be_bytes(arr)
        }).unwrap_or(0)
    }
    pub fn set_head(&self, h: u64) -> Result<()> {
        self.db.insert("head", h.to_be_bytes().to_vec())?; Ok(())
    }

    pub fn finalized_height(&self) -> u64 {
        self.db.get("finalized").ok().flatten().map(|iv| {
            let mut arr=[0u8;8]; arr.copy_from_slice(&iv); u64::from_be_bytes(arr)
        }).unwrap_or(0)
    }
    pub fn set_finalized(&self, h: u64) -> Result<()> {
        self.db.insert("finalized", h.to_be_bytes().to_vec())?; Ok(())
    }

    // ---------- баланс ----------
    pub fn balance_of(&self, rid: &str) -> Option<u64> {
        self.db.get(format!("bal:{rid}")).ok().flatten().map(|iv| {
            let mut arr=[0u8;8]; arr.copy_from_slice(&iv); u64::from_be_bytes(arr)
        })
    }
    fn set_balance(&self, rid: &str, v: u64) -> Result<()> {
        self.db.insert(format!("bal:{rid}"), v.to_be_bytes().to_vec())?; Ok(())
    }
    /// публичное зачисление
    pub fn credit(&self, rid: &str, amount: u64) -> Result<()> {
        let cur = self.balance_of(rid).unwrap_or(0);
        self.set_balance(rid, cur.saturating_add(amount))
    }
    /// публичное списание при достаточном балансе
    pub fn debit_if_possible(&self, rid: &str, amount: u64) -> Result<bool> {
        let cur = self.balance_of(rid).unwrap_or(0);
        if cur < amount { return Ok(false); }
        self.set_balance(rid, cur - amount)?; Ok(true)
    }

    // ---------- nonce ----------
    pub fn last_nonce_of(&self, rid: &str) -> u64 {
        self.db.get(format!("nonce:{rid}")).ok().flatten().map(|iv| {
            let mut arr=[0u8;8]; arr.copy_from_slice(&iv); u64::from_be_bytes(arr)
        }).unwrap_or(0)
    }
    pub fn next_nonce_of(&self, rid: &str) -> u64 {
        self.last_nonce_of(rid) + 1
    }

    // ---------- блоки ----------
    pub fn get_block_by_height(&self, h: u64) -> Result<Option<Block>> {
        if let Some(raw) = self.db.get(format!("blk:{h}"))? {
            Ok(Some(serde_json::from_slice(&raw)?))
        } else { Ok(None) }
    }

    // ---------- верификация TX ----------
    pub fn verify_tx(&self, tx: &Tx) -> VerifyResult {
        if tx.amount == 0 || tx.from.is_empty() || tx.to.is_empty() {
            return VerifyResult::Malformed;
        }
        // anti-replay
        let last_nonce = self.last_nonce_of(&tx.from);
        if tx.nonce <= last_nonce { return VerifyResult::Replay; }

        // Ed25519: from=bs58(pk32)
        let pk_bytes = match bs58::decode(&tx.from).into_vec() {
            Ok(v) if v.len()==32 => v,
            _ => return VerifyResult::Malformed,
        };
        let Ok(vk) = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()) else {
            return VerifyResult::Malformed;
        };

        // сигнатура: HEX или BASE64
        let sig_bytes = match hex::decode(&tx.sig) {
            Ok(v) => v,
            Err(_) => match base64::engine::general_purpose::STANDARD.decode(&tx.sig) {
                Ok(v) => v,
                Err(_) => return VerifyResult::Malformed,
            }
        };
        let Ok(sig) = Signature::from_slice(&sig_bytes) else { return VerifyResult::Malformed; };
        if vk.verify_strict(&tx.canonical_bytes(), &sig).is_err() {
            return VerifyResult::BadSig;
        }

        // баланс
        let bal = self.balance_of(&tx.from).unwrap_or(0);
        if bal < tx.amount { return VerifyResult::Insufficient; }
        VerifyResult::Ok
    }

    // ---------- коммит блока (tx -> балансы + история) ----------
    pub fn commit_block(&self, mut b: Block) -> Result<bool> {
        let h = self.head_height() + 1;
        b.height = h;

        for t in &b.txs {
            // перенос средств
            let from_b = self.balance_of(&t.from).unwrap_or(0);
            let to_b   = self.balance_of(&t.to).unwrap_or(0);
            self.set_balance(&t.from, from_b.saturating_sub(t.amount))?;
            self.set_balance(&t.to,   to_b.saturating_add(t.amount))?;
            self.db.insert(format!("nonce:{}", t.from), t.nonce.to_be_bytes().to_vec())?;

            let txid = t.id_string();
            self.db.insert(format!("tx:{txid}"), b"id".to_vec())?;

            // история переводов (для from и to)
            let evt_from = serde_json::json!({
                "type":"transfer","dir":"out","to":t.to,"amount":t.amount,"nonce":t.nonce,"height":h,"tx":txid
            });
            let evt_to = serde_json::json!({
                "type":"transfer","dir":"in","from":t.from,"amount":t.amount,"nonce":t.nonce,"height":h,"tx":evt_from["tx"]
            });
            self.db.insert(format!("hist:{}:{}", t.from, evt_from["tx"].as_str().unwrap()), serde_json::to_vec(&evt_from)?)?;
            self.db.insert(format!("hist:{}:{}", t.to,   evt_to["tx"].as_str().unwrap()),   serde_json::to_vec(&evt_to)?)?;
        }

        self.db.insert(format!("blk:{h}"), serde_json::to_vec(&b)?)?;
        self.set_head(h)?;
        if h > self.finalized_height() { self.set_finalized(h)?; }
        Ok(true)
    }

    /// Итерация по префиксу (для истории/эксплорера)
    pub fn iter_prefix<'a>(
        &'a self,
        pfx: &'a [u8],
    ) -> impl Iterator<Item = sled::Result<(sled::IVec, sled::IVec)>> + 'a {
        self.db.scan_prefix(pfx)
    }

    // ---------- stake (pending -> claim -> balance) + история ----------
    pub fn stake_pending_of(&self, rid: &str) -> u64 {
        self.db.get(format!("stake:pending:{rid}")).ok().flatten().map(|iv| {
            let mut arr=[0u8;8]; arr.copy_from_slice(&iv); u64::from_be_bytes(arr)
        }).unwrap_or(0)
    }
    fn set_stake_pending(&self, rid: &str, v: u64) -> Result<()> {
        self.db.insert(format!("stake:pending:{rid}"), v.to_be_bytes().to_vec())?; Ok(())
    }
    pub fn stake_delegate(&self, rid: &str, amount: u64) -> Result<bool> {
        if !self.debit_if_possible(rid, amount)? { return Ok(false); }
        let cur = self.stake_pending_of(rid);
        self.set_stake_pending(rid, cur.saturating_add(amount))?;
        let evt_id = format!("stake:{}", Uuid::new_v4());
        let evt = serde_json::json!({"type":"stake_delegate","rid":rid,"amount":amount,"pending_after":cur.saturating_add(amount)});
        self.db.insert(format!("hist:{}:{}", rid, evt_id), serde_json::to_vec(&evt)?)?;
        Ok(true)
    }
    pub fn stake_undelegate(&self, rid: &str, amount: u64) -> Result<bool> {
        let cur = self.stake_pending_of(rid);
        if cur < amount { return Ok(false); }
        self.set_stake_pending(rid, cur - amount)?;
        self.credit(rid, amount)?;
        let evt_id = format!("stake:{}", Uuid::new_v4());
        let evt = serde_json::json!({"type":"stake_undelegate","rid":rid,"amount":amount,"pending_after":cur - amount});
        self.db.insert(format!("hist:{}:{}", rid, evt_id), serde_json::to_vec(&evt)?)?;
        Ok(true)
    }
    pub fn stake_claim(&self, rid: &str) -> Result<u64> {
        let cur = self.stake_pending_of(rid);
        if cur == 0 { return Ok(0); }
        self.set_stake_pending(rid, 0)?;
        self.credit(rid, cur)?;
        let evt_id = format!("stake:{}", Uuid::new_v4());
        let evt = serde_json::json!({"type":"stake_claim","rid":rid,"claimed":cur,"pending_after":0});
        self.db.insert(format!("hist:{}:{}", rid, evt_id), serde_json::to_vec(&evt)?)?;
        Ok(cur)
    }
}

```


=== /root/logos_lrb/lrb_core/src/lib.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_consensus.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_filters.rs ===

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


=== /root/logos_lrb/lrb_core/src/phase_integrity.rs ===

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


=== /root/logos_lrb/lrb_core/src/quorum.rs ===

```rust
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

```


=== /root/logos_lrb/lrb_core/src/rcp_engine.rs ===

```rust
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

```


=== /root/logos_lrb/lrb_core/src/resonance.rs ===

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


=== /root/logos_lrb/lrb_core/src/sigpool.rs ===

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


=== /root/logos_lrb/lrb_core/src/spam_guard.rs ===

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


=== /root/logos_lrb/lrb_core/src/types.rs ===

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
pub type Nonce  = u64;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Rid(pub String); // base58(VerifyingKey)

impl Rid {
    pub fn from_pubkey(pk: &VerifyingKey) -> Self {
        Rid(bs58::encode(pk.to_bytes()).into_string())
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub id: String,        // blake3 of canonical form
    pub from: Rid,         // base58(pubkey)
    pub to: Rid,
    pub amount: Amount,
    pub nonce: Nonce,
    pub public_key: Vec<u8>, // 32 bytes (VerifyingKey)
    pub signature: Vec<u8>,  // 64 bytes (Signature)
}

impl Tx {
    /// Каноническое сообщение (без id и signature)
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let m = serde_json::json!({
            "from": self.from.as_str(),
            "to":   self.to.as_str(),
            "amount": self.amount,
            "nonce":  self.nonce,
            "public_key": B64.encode(&self.public_key),
        });
        serde_json::to_vec(&m).expect("canonical json")
    }

    pub fn compute_id(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.canonical_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Быстрая валидация формы (длины, нулевые значения)
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
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let mut h = Hasher::new();
        h.update(prev_hash.as_bytes());
        h.update(proposer.as_str().as_bytes());
        for tx in &txs { h.update(tx.id.as_bytes()); }
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

/// VerifyingKey из 32 байт (не пропускаем ошибку dalek наружу)
pub fn parse_pubkey(pk: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = pk.try_into().map_err(|_| anyhow!("bad pubkey len"))?;
    let vk = VerifyingKey::from_bytes(&arr).map_err(|_| anyhow!("bad ed25519 pubkey"))?;
    Ok(vk)
}

/// Signature из 64 байт
pub fn parse_sig(sig: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = sig.try_into().map_err(|_| anyhow!("bad signature len"))?;
    // В ed25519-dalek v2 Signature::from_bytes(&[u8;64]) -> Signature
    Ok(Signature::from_bytes(&arr))
}

```


---

# 5. node (исходники + Cargo)



=== /root/logos_lrb/node/build.rs ===

```rust
fn main() {
    // Версия пакета из Cargo.toml
    let pkg_version = env!("CARGO_PKG_VERSION");

    // Текущий UNIX timestamp (секунды)
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    println!("cargo:rustc-env=LOGOS_VERSION={}", pkg_version);
    println!("cargo:rustc-env=LOGOS_BUILD_TS={}", ts);
}

```


=== /root/logos_lrb/node/Cargo.toml ===

```toml
[package]
name = "logos_node"
version = "0.1.0"
edition = "2021"

[dependencies]
# локальный core
lrb_core          = { path = "../lrb_core" }

# наследуем всё критичное из workspace
anyhow            = { workspace = true }
thiserror         = { workspace = true }

tokio             = { workspace = true }
futures           = { workspace = true }
tracing           = { workspace = true }
tracing-subscriber = { workspace = true }

axum              = { workspace = true }
hyper             = { workspace = true }
hyper-util        = { workspace = true }   # ← ВАЖНО: добавили
http              = { workspace = true }
http-body-util    = { workspace = true }
tower             = { workspace = true }
tower-http        = { workspace = true }
bytes             = { workspace = true }

serde             = { workspace = true }
serde_json        = { workspace = true }
serde_repr        = { workspace = true }

ed25519-dalek     = { workspace = true }
bs58              = { workspace = true }
hex               = { workspace = true }
base64            = { workspace = true }
blake3            = { workspace = true }
ring              = { workspace = true }
rand              = { workspace = true }

sled              = { workspace = true }
time              = { workspace = true }
lazy_static       = { workspace = true }
tokio-util        = { workspace = true }

tokio-postgres    = { workspace = true }

reqwest           = { workspace = true }
uuid              = { workspace = true }
bincode           = { workspace = true }

jsonwebtoken      = { workspace = true }
prometheus        = { workspace = true }

```


=== /root/logos_lrb/node/src/admin.rs ===

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


=== /root/logos_lrb/node/src/api_extra.rs ===

```rust
use axum::{extract::State, Json};
use serde_json::{json, Value};
use crate::{AppState, types::ApiSubmitTx};
use lrb_core::ledger::{Tx, VerifyResult};

fn to_vec_txs(v:&Value)->Vec<ApiSubmitTx>{
    if let Some(arr)=v.as_array(){ return arr.iter().filter_map(|x| serde_json::from_value(x.clone()).ok()).collect(); }
    if let Some(o)=v.as_object(){
        for k in ["items","batch","txs","list"] {
            if let Some(arr)=o.get(k).and_then(|x|x.as_array()){
                return arr.iter().filter_map(|x| serde_json::from_value(x.clone()).ok()).collect();
            }
        }
    }
    serde_json::from_value(v.clone()).ok().map(|x| vec![x]).unwrap_or_default()
}
pub async fn submit_tx_batch(State(st): State<AppState>, Json(body): Json<Value>) -> Json<Value> {
    let txs = to_vec_txs(&body);
    if txs.is_empty(){ return Json(json!({"ok":false,"error":"empty_or_bad_payload"})); }
    let mut out=Vec::with_capacity(txs.len());
    for it in txs {
        let tx = Tx{ from:it.from, to:it.to, amount:it.amount, nonce:it.nonce, sig:it.sig };
        let res=match st.ledger.verify_tx(&tx){
            VerifyResult::Ok => { let _ = st.mempool_tx.send(tx.clone()).await; json!({"ok":true,"id":tx.id_string()}) },
            VerifyResult::BadSig => json!({"ok":false,"err":"bad_signature"}),
            VerifyResult::Malformed => json!({"ok":false,"err":"malformed"}),
            VerifyResult::Replay => json!({"ok":false,"err":"replay"}),
            VerifyResult::Insufficient => json!({"ok":false,"err":"insufficient"}),
        };
        out.push(res);
    }
    Json(json!({"ok":true,"results":out}))
}
pub async fn debug_canon(Json(it): Json<ApiSubmitTx>) -> Json<Value> {
    let tx = Tx{ from:it.from, to:it.to, amount:it.amount, nonce:it.nonce, sig:it.sig };
    Json(json!({ "canon_hex": hex::encode(tx.canonical_bytes()), "id_preview": tx.id_string() }))
}

```


=== /root/logos_lrb/node/src/api.rs ===

```rust
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::AppState;
use crate::verify::{verify_ed25519, VerifyErr};
use lrb_core::ledger::{Tx, VerifyResult};

#[derive(Debug, Deserialize)]
pub struct ApiSubmitTx {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub sig: String,
}

#[derive(Debug, Serialize)]
pub struct ApiTxId {
    pub id: String,
    pub status: String,
}

/// Собираем таблицу маршрутов ТИПИЗИРОВАННУЮ на AppState (state значение подставится в main).
pub fn router() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/healthz", get(healthz))
        .route("/head",    get(head))
        .route("/balance/:rid", get(balance))
        .route("/submit_tx",    post(submit_tx))
}

async fn healthz() -> &'static str { "OK" }

async fn head(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "height": st.ledger.head_height(),
        "finalized": st.ledger.finalized_height(),
    }))
}

async fn balance(
    State(st): State<AppState>,
    Path(rid): Path<String>,
) -> Json<serde_json::Value> {
    Json(json!({ "rid": rid, "balance": st.ledger.balance_of(&rid).unwrap_or(0) }))
}

async fn submit_tx(
    State(st): State<AppState>,
    Json(p): Json<ApiSubmitTx>,
) -> Result<Json<ApiTxId>, (axum::http::StatusCode, String)> {
    match verify_ed25519(&p.from, &p.to, p.amount, p.nonce, &p.sig) {
        Ok(_) => {}
        Err(VerifyErr::Malformed) => return Err((axum::http::StatusCode::BAD_REQUEST, "malformed".into())),
        Err(VerifyErr::BadSig)    => return Err((axum::http::StatusCode::BAD_REQUEST, "bad_signature".into())),
    }

    let tx = Tx { from: p.from, to: p.to, amount: p.amount, nonce: p.nonce, sig: p.sig };
    match st.ledger.verify_tx(&tx) {
        VerifyResult::Ok            => {}
        VerifyResult::Malformed     => return Err((axum::http::StatusCode::BAD_REQUEST, "malformed".into())),
        VerifyResult::BadSig        => return Err((axum::http::StatusCode::BAD_REQUEST, "bad_signature".into())),
        VerifyResult::Replay        => return Err((axum::http::StatusCode::CONFLICT, "replay".into())),
        VerifyResult::Insufficient  => return Err((axum::http::StatusCode::PAYMENT_REQUIRED, "insufficient".into())),
    }

    st.c_txs_in.inc();
    st.mempool_tx.send(tx.clone()).await
        .map_err(|_| (axum::http::StatusCode::SERVICE_UNAVAILABLE, "mempool busy".into()))?;

    Ok(Json(ApiTxId { id: tx.id_string(), status: "queued".into() }))
}

```


=== /root/logos_lrb/node/src/archive_ingest.rs ===

```rust
use crate::state::SharedState;
use chrono::Utc;

/// Асинхронная запись tx в Postgres (fire-and-forget).
/// Без паник — ошибки только в лог.
pub async fn insert_tx(
    state: SharedState,
    tx_id: String,
    from_rid: String,
    to_rid: String,
    amount: i64,
    nonce: i64,
    height: Option<i64>,
) {
    let pool = state.archive.clone();
    // получаем клиент
    let client = match pool.get().await {
        Ok(c) => c,
        Err(e) => { tracing::warn!("archive: get conn err: {e}"); return; }
    };

    // ts_sec берём по времени узла; height даём приблизительный (финализация у тебя quorum=1 — ок).
    let ts_sec = Utc::now().timestamp();
    let h = height.unwrap_or_else(|| state.metrics.head_height.get() as i64);

    // upsert по txid
    if let Err(e) = client.execute(
        "INSERT INTO tx (txid, rid_from, rid_to, amount, nonce, ts_sec, height)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (txid) DO NOTHING",
        &[&tx_id, &from_rid, &to_rid, &amount, &nonce, &ts_sec, &h],
    ).await {
        tracing::warn!("archive: insert err: {e}");
    }
}

```


=== /root/logos_lrb/node/src/archive/pg.rs ===

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


=== /root/logos_lrb/node/src/archive_pg.rs ===

```rust
use anyhow::Result;
use tokio_postgres::{NoTls, Client};

use lrb_core::ledger::Block;

/// Тип "пула" для продюсера — используем один Client, подключение держим в отдельной таске.
pub type PgPoolLike = Client;

/// Создаём клиент из DSN в LOGOS_PG_DSN и запускаем соединение в фоне.
/// Пример DSN: "host=127.0.0.1 user=logos dbname=logos password=logos_pwd"
pub async fn maybe_pool_from_env() -> Option<PgPoolLike> {
    let dsn = std::env::var("LOGOS_PG_DSN").ok()?;
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls).await.ok()?;
    // Соединение держим в фоне
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("[pg] connection error: {e:?}");
        }
    });
    Some(client)
}

/// Индексируем блок: upsert в blocks и txs (без транзакции — на один сервер достаточно)
pub async fn index_block(client: &PgPoolLike, b: &Block) -> Result<()> {
    // блок
    client
        .execute(
            "insert into blocks(height, id) values ($1, $2)
             on conflict (height) do nothing",
            &[&(b.height as i64), &b.id],
        )
        .await?;

    // все tx
    for t in &b.txs {
        client
            .execute(
                "insert into txs(id, height, rid_from, rid_to, amount, nonce)
                 values ($1,$2,$3,$4,$5,$6)
                 on conflict (id) do nothing",
                &[
                    &t.id_string(),
                    &(b.height as i64),
                    &t.from,
                    &t.to,
                    &(t.amount as i64),
                    &(t.nonce as i64),
                ],
            )
            .await?;
    }

    Ok(())
}

```


=== /root/logos_lrb/node/src/archive/sqlite.rs ===

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


=== /root/logos_lrb/node/src/auth.rs ===

```rust
//! Auth-модуль: защита bridge/admin. Admin — только JWT (HS256). Bridge — X-Bridge-Key.
//! Обязательные переменные окружения: LRB_BRIDGE_KEY, LRB_JWT_SECRET.

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

fn forbid_default(val: &str) -> Result<()> {
    let low = val.to_lowercase();
    let banned = ["", "change_me", "changeme", "dev_secret", "default", "empty", "test", "123"];
    if banned.iter().any(|b| low == *b) {
        return Err(anyhow!("insecure default key"));
    }
    Ok(())
}

/* ---------------- Bridge (ключ обязателен) ---------------- */

pub fn require_bridge(headers: &HeaderMap) -> Result<()> {
    let expect = std::env::var("LRB_BRIDGE_KEY").map_err(|_| anyhow!("LRB_BRIDGE_KEY CHANGE_ME not set"))?;
    forbid_default(&expect)?;
    let got = headers
        .get("X-Bridge-Key")
        .ok_or_else(|| anyhow!("missing X-Bridge-Key"))?
        .to_str()
        .map_err(|_| anyhow!("invalid X-Bridge-Key"))?;
    if got != expect { return Err(anyhow!("forbidden: bad bridge key")); }
    Ok(())
}

/* ---------------- Admin (только JWT HS256) ---------------- */

#[derive(Debug, Deserialize)]
struct AdminClaims {
    sub: String,
    iat: Option<u64>,
    exp: Option<u64>,
}

pub fn require_admin(headers: &HeaderMap) -> Result<()> {
    let token = headers
        .get("X-Admin-JWT")
        .ok_or_else(|| anyhow!("missing X-Admin-JWT"))?
        .to_str()
        .map_err(|_| anyhow!("invalid X-Admin-JWT"))?
        .to_string();

    let secret = std::env::var("LRB_JWT_SECRET").map_err(|_| anyhow!("LRB_JWT_SECRET CHANGE_ME not set"))?;
    forbid_default(&secret)?;

    let data = decode::<AdminClaims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| anyhow!("admin jwt invalid: {e}"))?;

    if data.claims.sub != "admin" {
        return Err(anyhow!("forbidden"));
    }
    Ok(())
}

/* ---------------- Стартовая проверка секретов ---------------- */

pub fn assert_secrets_on_start() -> Result<()> {
    // Bridge/JWT обязаны быть заданы. Если пусты — валим процесс.
    for (key, _val) in [("LRB_BRIDGE_KEY","bridge"), ("LRB_JWT_SECRET","jwt")] {
        let v = std::env::var(key).map_err(|_| anyhow!("{key} is not set"))?;
        forbid_default(&v)?;
    }
    Ok(())
}

```


=== /root/logos_lrb/node/src/bridge.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/fork.rs ===

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


=== /root/logos_lrb/node/src/gossip.rs ===

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


=== /root/logos_lrb/node/src/guard.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/history_sled.rs ===

```rust
use axum::{extract::{Path, Query, State}, Json};
use serde::Deserialize;
use serde_json::Value;

use crate::AppState;

#[derive(Deserialize)]
pub struct HistQ { pub limit: Option<usize> }

pub async fn history_by_rid(
    State(st): State<AppState>,
    Path(rid): Path<String>,
    Query(q): Query<HistQ>,
) -> Json<Value> {
    let prefix = format!("hist:{rid}:").into_bytes();
    let mut tmp: Vec<(String, Value)> = Vec::new();
    for kv in st.ledger.iter_prefix(&prefix) {
        if let Ok((k, v)) = kv {
            let key = String::from_utf8_lossy(k.as_ref()).to_string();
            let evt: Value = serde_json::from_slice(v.as_ref()).unwrap_or(Value::Null);
            tmp.push((key, evt));
            if tmp.len() >= 10_000 { break; }
        }
    }
    tmp.sort_by(|a,b| a.0.cmp(&b.0));
    let take = q.limit.unwrap_or(200).min(1000);
    let items: Vec<_> = tmp.into_iter().rev().take(take)
        .map(|(k,v)| serde_json::json!({"key":k, "evt":v})).collect();
    Json(serde_json::json!({ "rid": rid, "items": items }))
}

```


=== /root/logos_lrb/node/src/lib.rs ===

```rust
pub mod state;
pub mod verify;
pub mod producer;
pub mod archive_pg;
pub mod api;

```


=== /root/logos_lrb/node/src/main.rs ===

```rust
use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::Router;
use axum::routing::IntoMakeService; // ← ВАЖНО: этот трейт даёт .into_make_service()
use lrb_core::ledger::Ledger;
use prometheus::{IntCounter, IntGauge};
use tokio::sync::mpsc;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info, Level};

mod producer;
mod archive_pg;
mod api;
mod verify;
mod state;

use state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(true)
        .init();

    // Ledger
    let ledger = Arc::new(Ledger::open_default("/var/lib/logos/data.sled")?);

    // Mempool
    let (tx, rx) = mpsc::channel::<lrb_core::ledger::Tx>(10_000);

    // Метрики
    let g_head = IntGauge::new("logos_head_height", "Current head height").unwrap();
    let c_txs_in = IntCounter::new("logos_txs_in_total", "Incoming tx accepted (API)").unwrap();
    let _ = prometheus::default_registry().register(Box::new(g_head.clone()));
    let _ = prometheus::default_registry().register(Box::new(c_txs_in.clone()));

    let state = AppState {
        ledger: ledger.clone(),
        mempool_tx: tx.clone(),
        g_head: g_head.clone(),
        c_txs_in: c_txs_in.clone(),
    };

    // Продюсер
    producer::Producer::register_metrics();
    let pg_pool = archive_pg::maybe_pool_from_env().await;
    let st_for_producer = state.clone();
    tokio::spawn(async move {
        let p = producer::Producer { ledger: st_for_producer.ledger.clone(), rx, pg: pg_pool };
        if let Err(e) = p.run().await { error!("producer error: {e:?}"); }
    });

    // Роутер типизирован на AppState; state подставляем здесь
    let app: Router<AppState> = api::router()
        .layer(CompressionLayer::new())
        .layer(CorsLayer::very_permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Axum 0.7: в serve подаём make_service и await-им future
    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("listening on {addr}");

    let make_svc = app.into_make_service(); // ← теперь метод в скоупе
    axum::serve(listener, make_svc).await?;
    Ok(())
}

```


=== /root/logos_lrb/node/src/metrics.rs ===

```rust
use axum::response::IntoResponse;
use crate::state::SharedState;

pub async fn metrics_handler(state: SharedState)->impl IntoResponse{
    let body=state.metrics.render();
    ([(axum::http::header::CONTENT_TYPE,"text/plain; version=0.0.4")], body)
}

```


=== /root/logos_lrb/node/src/openapi.rs ===

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


=== /root/logos_lrb/node/src/peers.rs ===

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


=== /root/logos_lrb/node/src/producer.rs ===

```rust
use std::time::{Duration, Instant};
use anyhow::Result;
use lrb_core::ledger::{Ledger, Tx, Block};
use prometheus::{IntCounter, IntGauge};
use tokio::sync::mpsc::Receiver;
use tracing::{info, warn};

use crate::archive_pg::PgPoolLike;

lazy_static::lazy_static! {
    static ref C_BLOCKS: IntCounter = prometheus::IntCounter::new("logos_blocks_total", "Blocks produced").unwrap();
    static ref C_TXS_IN_BLOCKS: IntCounter = prometheus::IntCounter::new("logos_block_txs_total", "Txs included in blocks").unwrap();
    static ref G_MEMPOOL_DEPTH: IntGauge = prometheus::IntGauge::new("logos_mempool_depth", "Mempool depth (queued tx)").unwrap();
    static ref G_HEAD: IntGauge = prometheus::IntGauge::new("logos_head_height", "Head height").unwrap();
    static ref G_BPS: IntGauge = prometheus::IntGauge::new("logos_bps", "Blocks per second (approx)").unwrap();
}

pub struct Producer {
    pub ledger: std::sync::Arc<Ledger>,
    pub rx: Receiver<Tx>,
    pub pg: Option<PgPoolLike>,
}

impl Producer {
    pub fn register_metrics() {
        let _ = prometheus::default_registry().register(Box::new(C_BLOCKS.clone()));
        let _ = prometheus::default_registry().register(Box::new(C_TXS_IN_BLOCKS.clone()));
        let _ = prometheus::default_registry().register(Box::new(G_MEMPOOL_DEPTH.clone()));
        let _ = prometheus::default_registry().register(Box::new(G_HEAD.clone()));
        let _ = prometheus::default_registry().register(Box::new(G_BPS.clone()));
    }

    pub async fn run(mut self) -> Result<()> {
        let mut buf: Vec<Tx> = Vec::with_capacity(10_000);
        let mut last_block = Instant::now();
        loop {
            // собираем пакет ~250мс или до 5000 tx
            let timeout = tokio::time::sleep(Duration::from_millis(250));
            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    _ = &mut timeout => break,
                    maybe_tx = self.rx.recv() => {
                        if let Some(tx) = maybe_tx {
                            buf.push(tx);
                            G_MEMPOOL_DEPTH.set(buf.len() as i64);
                            if buf.len() >= 5_000 { break; }
                        } else {
                            break;
                        }
                    }
                }
            }

            if buf.is_empty() {
                // обновляем только head/bps
                let h = self.ledger.head_height();
                G_HEAD.set(h as i64);
                continue;
            }

            let block = Block::new_from_txs(&buf);
            match self.ledger.commit_block(block.clone()) {
                Ok(_) => {
                    C_BLOCKS.inc();
                    C_TXS_IN_BLOCKS.inc_by(block.txs.len() as u64);
                    let h = self.ledger.head_height();
                    G_HEAD.set(h as i64);
                    // bps
                    let dt = last_block.elapsed().as_secs_f64();
                    if dt > 0.0 { G_BPS.set((1.0 / dt).round() as i64); }
                    last_block = Instant::now();

                    // индекс в PG
                    if let Some(pool) = &self.pg {
                        if let Err(e) = crate::archive_pg::index_block(pool, &block).await {
                            warn!("pg index failed: {e:?}");
                        }
                    }
                }
                Err(e) => warn!("commit block failed: {e:?}"),
            }

            buf.clear();
            G_MEMPOOL_DEPTH.set(0);
            info!("block committed; txs={}", 0);
        }
    }
}

```


=== /root/logos_lrb/node/src/stake_api.rs ===

```rust
use axum::{extract::State, Json};
use serde_json::Value;
use crate::AppState;

fn parse_req(v:&Value)->Option<(String,u64)>{
    let o=v.as_object()?;
    let rid = o.get("rid").or_else(||o.get("validator")).and_then(|x|x.as_str()).unwrap_or("").to_string();
    let amt = o.get("amount").and_then(|x|x.as_u64()).or_else(||o.get("value").and_then(|x|x.as_u64())).unwrap_or(0);
    if rid.is_empty() || amt==0 { return None; }
    Some((rid,amt))
}

pub async fn stake_pending(State(st): State<AppState>, axum::extract::Path(rid): axum::extract::Path<String>) -> Json<Value> {
    Json(serde_json::json!({"rid":rid,"pending":st.ledger.stake_pending_of(&rid)}))
}
pub async fn delegate(State(st): State<AppState>, Json(body): Json<Value>) -> Json<Value> {
    if let Some((rid,amount)) = parse_req(&body) {
        let ok = st.ledger.stake_delegate(&rid, amount).unwrap_or(false);
        return Json(serde_json::json!({"ok":ok,"rid":rid,"amount":amount}));
    }
    Json(serde_json::json!({"ok":false,"error":"bad_request"}))
}
pub async fn undelegate(State(st): State<AppState>, Json(body): Json<Value>) -> Json<Value> {
    if let Some((rid,amount)) = parse_req(&body) {
        let ok = st.ledger.stake_undelegate(&rid, amount).unwrap_or(false);
        return Json(serde_json::json!({"ok":ok,"rid":rid,"amount":amount}));
    }
    Json(serde_json::json!({"ok":false,"error":"bad_request"}))
}
pub async fn claim(State(st): State<AppState>, Json(body): Json<Value>) -> Json<Value> {
    let rid = body.get("rid").or_else(||body.get("validator")).and_then(|x|x.as_str()).unwrap_or("").to_string();
    if rid.is_empty(){ return Json(serde_json::json!({"ok":false,"error":"bad_request"})); }
    let claimed = st.ledger.stake_claim(&rid).unwrap_or(0);
    Json(serde_json::json!({"ok":claimed>0,"rid":rid,"claimed":claimed}))
}
pub async fn summary(State(st): State<AppState>, axum::extract::Path(rid): axum::extract::Path<String>) -> Json<Value> {
    let delegated = st.ledger.stake_pending_of(&rid);
    let prefix = format!("hist:{rid}:").into_bytes();
    let mut entries:u64 = 0; let mut after_claim=true;
    for kv in st.ledger.iter_prefix(&prefix) {
        if let Ok((_k,v)) = kv {
            if let Ok(evt) = serde_json::from_slice::<Value>(v.as_ref()) {
                match evt.get("type").and_then(|x|x.as_str()) {
                    Some("stake_claim") => { entries=0; after_claim=true; }
                    Some("stake_delegate") if after_claim => entries+=1,
                    _ => {}
                }
            }
        }
    }
    Json(serde_json::json!({ "rid":rid, "delegated":delegated, "entries":entries, "claimable":delegated }))
}

```


=== /root/logos_lrb/node/src/stake.rs ===

```rust
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

```


=== /root/logos_lrb/node/src/staking.rs ===

```rust
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub fn utc_now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "n/a".into())
}

// остальные функции стейкинга можешь оставить, главное — не тянуть chrono

```


=== /root/logos_lrb/node/src/state.rs ===

```rust
use std::sync::Arc;
use prometheus::{IntCounter, IntGauge};
use tokio::sync::mpsc;
use lrb_core::ledger::{Ledger, Tx};

/// Глобальное состояние для Axum. ДОЛЖНО быть Clone.
#[derive(Clone)]
pub struct AppState {
    pub ledger: Arc<Ledger>,
    pub mempool_tx: mpsc::Sender<Tx>,
    pub g_head: IntGauge,
    pub c_txs_in: IntCounter,
}

```


=== /root/logos_lrb/node/src/storage.rs ===

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


=== /root/logos_lrb/node/src/types.rs ===

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ApiSubmitTx {
    pub from: String,   // base58 RID
    pub to: String,     // base58 RID
    pub amount: u64,
    pub nonce: u64,
    pub sig: String,    // base64/hex сигнатура Ed25519 (как в кошельке)
}

#[derive(Debug, Serialize)]
pub struct ApiTxId {
    pub id: String,
    pub status: String,
}

```


=== /root/logos_lrb/node/src/verify.rs ===

```rust
use ed25519_dalek::{Signature, VerifyingKey};
// ВАЖНО: трейт Engine для .decode() в base64 v0.22
use base64::Engine;

#[inline]
fn canon_bytes(from: &str, to: &str, amount: u64, nonce: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(from.as_bytes());
    v.push(b'|');
    v.extend_from_slice(to.as_bytes());
    v.push(b'|');
    v.extend_from_slice(&amount.to_be_bytes());
    v.push(b'|');
    v.extend_from_slice(&nonce.to_be_bytes());
    v
}

#[derive(Debug)]
pub enum VerifyErr { Malformed, BadSig }

#[inline]
fn try_decode_sig(sig: &str) -> Option<Vec<u8>> {
    // HEX
    if let Ok(v) = hex::decode(sig) { return Some(v); }
    // Base64 (STANDARD или URL_SAFE)
    base64::engine::general_purpose::STANDARD
        .decode(sig)
        .ok()
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(sig).ok())
}

pub fn verify_ed25519(from_bs58: &str, to: &str, amount: u64, nonce: u64, sig_str: &str)
    -> Result<(), VerifyErr>
{
    // from = bs58(pubkey32)
    let pk_bytes = bs58::decode(from_bs58).into_vec().map_err(|_| VerifyErr::Malformed)?;
    if pk_bytes.len() != 32 { return Err(VerifyErr::Malformed); }
    let vk = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().map_err(|_| VerifyErr::Malformed)?)
        .map_err(|_| VerifyErr::Malformed)?;

    let sig_raw = try_decode_sig(sig_str).ok_or(VerifyErr::Malformed)?;
    let sig = Signature::from_slice(&sig_raw).map_err(|_| VerifyErr::Malformed)?;

    let msg = canon_bytes(from_bs58, to, amount, nonce);
    vk.verify_strict(&msg, &sig).map_err(|_| VerifyErr::BadSig)
}

```


=== /root/logos_lrb/node/src/version.rs ===

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


=== /root/logos_lrb/node/src/wallet.rs ===

```rust
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

```


---

# 6. Web Wallet



=== /root/logos_lrb/www/wallet/app.html ===

```html
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

```


=== /root/logos_lrb/www/wallet/app.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/app.v2.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/app.v3.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/auth.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/index.html ===

```html
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

```


=== /root/logos_lrb/www/wallet/login.html ===

```html
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

```


=== /root/logos_lrb/www/wallet/staking.js ===

```javascript
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

```


=== /root/logos_lrb/www/wallet/wallet.css ===

```css
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

```


=== /root/logos_lrb/www/wallet/wallet.js ===

```javascript
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

```


---

# 7. Explorer



=== /root/logos_lrb/www/explorer/index.html ===

```html
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

```


---

# 8. Nginx конфиги



---

# 9. Systemd (unit + drop-ins)



=== systemctl cat logos-node ===

```text
# /etc/systemd/system/logos-node.service
[Unit]
Description=LOGOS LRB Node
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=logos
Group=logos
ExecStart=/opt/logos/bin/logos_node
Restart=on-failure
RestartSec=2
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/logos
Environment=RUST_LOG=info
Environment=LOGOS_PG_DSN=%E:LOGOS_PG_DSN%
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/logos-node.service.d/archive.conf
[Service]
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos

# /etc/systemd/system/logos-node.service.d/cors.conf
[Service]
Environment=LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io

# /etc/systemd/system/logos-node.service.d/data.conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled

# /etc/systemd/system/logos-node.service.d/exec.conf
[Service]
ExecStart=
ExecStart=/opt/logos/bin/logos_node
WorkingDirectory=/opt/logos

# /etc/systemd/system/logos-node.service.d/faucet.conf
[Service]
Environment=LRB_ENABLE_FAUCET=1

# /etc/systemd/system/logos-node.service.d/hardening.conf
[Service]
# Ресурсы
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
MemoryMax=2G
CPUQuota=200%

# Sandbox/защиты
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service @network-io

# /etc/systemd/system/logos-node.service.d/keys.conf
[Service]
EnvironmentFile=/etc/logos/keys.env

# /etc/systemd/system/logos-node.service.d/loglevel.conf
[Service]
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/paths.conf
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

# /etc/systemd/system/logos-node.service.d/phasemix.conf
[Service]
Environment=LRB_PHASEMIX_ENABLE=1

# /etc/systemd/system/logos-node.service.d/ratelimit.conf
[Service]
Environment=LRB_RATE_QPS=30
Environment=LRB_RATE_BURST=60
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

# /etc/systemd/system/logos-node.service.d/runas.conf
[Service]
User=logos
Group=logos
# Разрешаем запись туда, где нужно (данные/секреты)
ReadWritePaths=/var/lib/logos /etc/logos

# /etc/systemd/system/logos-node.service.d/security.conf
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true

# /etc/systemd/system/logos-node.service.d/tuning.conf
[Service]
Environment=LRB_NODE_LISTEN=0.0.0.0:8080
Environment=LRB_DATA_DIR=/var/lib/logos
Environment=LRB_WALLET_ORIGIN=http://127.0.0.1
Environment=LRB_RATE_QPS=20
Environment=LRB_RATE_BURST=40
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/zz-consensus.conf
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

# /etc/systemd/system/logos-node.service.d/zz-logging.conf
[Service]
Environment=RUST_LOG=info

# /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


=== /etc/systemd/system/logos-node.service.d/archive.conf ===

```nginx
[Service]
Environment=LRB_ARCHIVE_URL=postgres://logos:StrongPass123@127.0.0.1:5432/logos

```


=== /etc/systemd/system/logos-node.service.d/cors.conf ===

```nginx
[Service]
Environment=LRB_WALLET_ORIGIN=https://45-159-248-232.sslip.io

```


=== /etc/systemd/system/logos-node.service.d/data.conf ===

```nginx
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled

```


=== /etc/systemd/system/logos-node.service.d/exec.conf ===

```nginx
[Service]
ExecStart=
ExecStart=/opt/logos/bin/logos_node
WorkingDirectory=/opt/logos

```


=== /etc/systemd/system/logos-node.service.d/faucet.conf ===

```nginx
[Service]
Environment=LRB_ENABLE_FAUCET=1

```


=== /etc/systemd/system/logos-node.service.d/hardening.conf ===

```nginx
[Service]
# Ресурсы
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0
MemoryMax=2G
CPUQuota=200%

# Sandbox/защиты
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallFilter=@system-service @network-io

```


=== /etc/systemd/system/logos-node.service.d/keys.conf ===

```nginx
[Service]
EnvironmentFile=/etc/logos/keys.env

```


=== /etc/systemd/system/logos-node.service.d/loglevel.conf ===

```nginx
[Service]
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/paths.conf ===

```nginx
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

```


=== /etc/systemd/system/logos-node.service.d/phasemix.conf ===

```nginx
[Service]
Environment=LRB_PHASEMIX_ENABLE=1

```


=== /etc/systemd/system/logos-node.service.d/ratelimit.conf ===

```nginx
[Service]
Environment=LRB_RATE_QPS=30
Environment=LRB_RATE_BURST=60
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128

```


=== /etc/systemd/system/logos-node.service.d/runas.conf ===

```nginx
[Service]
User=logos
Group=logos
# Разрешаем запись туда, где нужно (данные/секреты)
ReadWritePaths=/var/lib/logos /etc/logos

```


=== /etc/systemd/system/logos-node.service.d/security.conf ===

```nginx
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true

```


=== /etc/systemd/system/logos-node.service.d/tuning.conf ===

```nginx
[Service]
Environment=LRB_NODE_LISTEN=0.0.0.0:8080
Environment=LRB_DATA_DIR=/var/lib/logos
Environment=LRB_WALLET_ORIGIN=http://127.0.0.1
Environment=LRB_RATE_QPS=20
Environment=LRB_RATE_BURST=40
Environment=LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/zz-consensus.conf ===

```nginx
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

```


=== /etc/systemd/system/logos-node.service.d/zz-keys.conf.disabled ===

```text
[Service]
# Читаем файл с секретами (на будущее, если захочешь использовать keys.env)
EnvironmentFile=-/etc/logos/keys.env

# Узловые параметры (жёстко, чтобы сервис точно стартовал)
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_SK_HEX=31962399e9b0e278af3b328bc6e30bbd17d90c700a5f6c7ad3c4d4418ed8fd83
Environment=LRB_ADMIN_KEY=0448012cf1738fd048b154a1c367cb7cb42e3fee4ab26fb04268ab91e09fb475
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


=== /etc/systemd/system/logos-node.service.d/zz-logging.conf ===

```nginx
[Service]
Environment=RUST_LOG=info

```


=== /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf ===

```nginx
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```


---

# 10. Бэкап sled



=== /usr/local/bin/logos-sled-backup.sh ===

```bash
#!/usr/bin/env bash
set -euo pipefail

SRC="/var/lib/logos/data.sled"
DST="/root/sled_backups"
KEEP=96          # ~24 часа при шаге 15 минут
MAX_GB=20        # общий лимит в гигабайтах

TS="$(date -Iseconds)"
mkdir -p "$DST"

# 1) инкрементальный снапшот (rsync в новую папку)
rsync -a --delete "$SRC/" "$DST/data.sled.$TS.bak/"

# 2) ротация по количеству
mapfile -t LIST < <(ls -1dt "$DST"/data.sled.*.bak 2>/dev/null || true)
if (( ${#LIST[@]} > KEEP )); then
  for d in "${LIST[@]:$KEEP}"; do
    rm -rf -- "$d" || true
  done
fi

# 3) ротация по общему размеру
du_mb() { du -sm "$DST" | awk '{print $1}'; }
while (( $(du_mb) > MAX_GB*1024 )); do
  OLDEST="$(ls -1dt "$DST"/data.sled.*.bak | tail -n 1 || true)"
  [[ -n "$OLDEST" ]] || break
  rm -rf -- "$OLDEST" || true
done

```


=== /etc/systemd/system/logos-sled-backup.service ===

```ini
[Unit]
Description=Backup sled to /root/sled_backups

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/logos-sled-backup.sh

```


=== /etc/systemd/system/logos-sled-backup.timer ===

```ini
[Unit]
Description=Run sled backup every 15 minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
Unit=logos-sled-backup.service

[Install]
WantedBy=timers.target

```


---

# 11. Prometheus/Grafana (alerts)



=== /etc/prometheus/rules/logos_alerts.yml ===

```yaml
groups:
- name: logos-runtime
  rules:
  - alert: HeightStuck
    expr: increase(logos_head_height[5m]) == 0
    for: 3m
    labels: { severity: critical }
    annotations: { summary: "Head не растёт 5 минут" }

  - alert: HighLatencyP99
    expr: histogram_quantile(0.99, sum(rate(http_request_duration_ms_bucket[5m])) by (le)) > 120
    for: 2m
    labels: { severity: warning }
    annotations: { summary: "p99 HTTP > 120 ms" }

  - alert: TLSExpirySoon
    expr: (probe_ssl_earliest_cert_expiry - time()) < 14*24*3600
    for: 10m
    labels: { severity: warning }
    annotations: { summary: "TLS сертификат истекает < 14 дней" }

```


---

# 12. Конфиги



=== /root/logos_lrb/configs/genesis.yaml ===

```yaml
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

```


=== /root/logos_lrb/configs/logos_config.yaml ===

```yaml
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

```


---

# 13. OpenAPI контракт



=== GET /openapi.json ===

```text

```


---

# 14. Bootstrap на новом сервере (шаги)


### Ubuntu 22.04/24.04 (root)
```bash
apt update && apt install -y curl git jq build-essential pkg-config libssl-dev \
  nginx postgresql postgresql-contrib rsync

# Rust
curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. $HOME/.cargo/env

# Клонируем проект
git clone https://github.com/Lgn-rsp/logos_lrb.git /root/logos_lrb
cd /root/logos_lrb

# По канону вставляем файлы из этой книги (см. главы 3–13):
# cd → rm -f → nano → вставить контент блока === <path> === → сохранить

# Systemd drop-ins — ЗАМЕНИТЬ CHANGE_ME на реальные секреты
sudo mkdir -p /etc/systemd/system/logos-node.service.d
sudo tee /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf >/dev/null <<EOF
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME
EOF
sudo tee /etc/systemd/system/logos-node.service.d/paths.conf >/dev/null <<EOF
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key
EOF
sudo systemctl daemon-reload

# Сборка/деплой
cargo build --release -p logos_node
install -m 0755 target/release/logos_node /opt/logos/bin/logos_node
sudo chown logos:logos /opt/logos/bin/logos_node
sudo systemctl restart logos-node
sleep 1
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo

# Nginx
nginx -t && systemctl reload nginx
```

---

# 15. Канон проверки


```bash
journalctl -u logos-node -n 120 --no-pager | egrep -i "listening|panic|error" || true
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo
curl -s http://127.0.0.1:8080/economy | jq
curl -s "http://127.0.0.1:8080/archive/blocks?limit=3" | jq
curl -s "http://127.0.0.1:8080/archive/txs?limit=3"    | jq
```

---

# Конец книги

