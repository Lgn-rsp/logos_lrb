use std::{collections::{HashMap, HashSet}, sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}};
use ed25519_dalek::{SigningKey, VerifyingKey};
use once_cell::sync::Lazy;
use prometheus::{register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge};
use reqwest::Client;
use lrb_core::Engine;

pub fn now_ms() -> u128 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() }

/* ---- метрики (как у тебя) ---- */
pub static TX_SUBMITTED:    Lazy<IntCounter> = Lazy::new(|| register_int_counter!("tx_submitted_total","submitted tx").unwrap());
pub static TX_APPLIED:      Lazy<IntCounter> = Lazy::new(|| register_int_counter!("tx_applied_total",  "applied tx").unwrap());
pub static GOSSIP_BLK_SENT: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("gossip_block_sent_total","gossip blocks sent").unwrap());
pub static GOSSIP_BLK_RECV: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("gossip_block_recv_total","gossip blocks recv").unwrap());
pub static GOSSIP_VOTE_SENT:Lazy<IntCounter> = Lazy::new(|| register_int_counter!("gossip_vote_sent_total","gossip votes sent").unwrap());
pub static GOSSIP_VOTE_RECV:Lazy<IntCounter> = Lazy::new(|| register_int_counter!("gossip_vote_recv_total","gossip votes recv").unwrap());
pub static CONS_VOTES:      Lazy<IntCounter> = Lazy::new(|| register_int_counter!("consensus_votes_total","accepted consensus votes").unwrap());
pub static HEIGHT_GAUGE:    Lazy<IntGauge>   = Lazy::new(|| register_int_gauge!("chain_height","current height").unwrap());
pub static FINAL_GAUGE:     Lazy<IntGauge>   = Lazy::new(|| register_int_gauge!("chain_finalized","finalized height").unwrap());
pub static MEMPOOL_GAUGE:   Lazy<IntGauge>   = Lazy::new(|| register_int_gauge!("mempool_len","mempool length").unwrap());
pub static SLOT_TXS_GAUGE:  Lazy<IntGauge>   = Lazy::new(|| register_int_gauge!("slot_tx_count","tx in last committed block").unwrap());
pub static BR_DEPOSIT:      Lazy<IntCounter> = Lazy::new(|| register_int_counter!("bridge_deposit_total","bridge deposits").unwrap());
pub static BR_REDEEM:       Lazy<IntCounter> = Lazy::new(|| register_int_counter!("bridge_redeem_total","bridge redeems").unwrap());
pub static PHASE_BLOCK_ACCEPTED: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("phase_block_accepted_total","blocks passed phase filter").unwrap());
pub static PHASE_BLOCK_REJECTED: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("phase_block_rejected_total","blocks rejected by phase filter").unwrap());
pub static SLOT_LAT_HIST:   Lazy<Histogram>  = Lazy::new(|| {
    register_histogram!("slot_latency_ms_hist","slot latency histogram (ms)",
        vec![10.0,25.0,50.0,100.0,250.0,500.0,750.0,1000.0,1500.0,2000.0,3000.0]).unwrap()
});
pub static SLOT_TXS_HIST:   Lazy<Histogram>  = Lazy::new(|| {
    register_histogram!("slot_tx_count_hist","tx per block histogram",
        vec![10.0,50.0,100.0,500.0,1000.0,2000.0,5000.0,10000.0,20000.0]).unwrap()
});

/* ---- Anti-replay окно ---- */
#[derive(Default, Clone)]
pub struct ReplayWindow {
    map: Arc<Mutex<HashMap<String,u128>>>,
    pub ttl_ms: u128,
    pub max_items: usize,
}
impl ReplayWindow {
    pub fn new(ttl_ms: u128, max_items: usize) -> Self { Self { map: Arc::new(Mutex::new(HashMap::new())), ttl_ms, max_items } }
    pub fn check_and_note(&self, key: String, ts_ms: u128) -> bool {
        let mut m = self.map.lock().unwrap();
        if m.len() > self.max_items {
            let cutoff = now_ms().saturating_sub(self.ttl_ms);
            m.retain(|_, &mut t| t >= cutoff);
        }
        if let Some(prev) = m.get(&key) { if ts_ms <= *prev + self.ttl_ms { return false; } }
        m.insert(key, ts_ms);
        true
    }
}

/* ---- Токен-бакет ---- */
#[derive(Clone)]
pub struct TokenBucket { inner: Arc<Mutex<BucketInner>>, }
#[derive(Debug)]
struct BucketInner { capacity:u64, tokens:u64, refill_per_ms:f64, last_ms:u128 }
impl TokenBucket {
    pub fn new(capacity:u64, refill_per_sec:u64) -> Self {
        let now = now_ms();
        Self { inner: Arc::new(Mutex::new(BucketInner{
            capacity, tokens: capacity, refill_per_ms: refill_per_sec as f64 / 1000.0, last_ms: now
        })) }
    }
    pub fn try_take(&self, n:u64) -> bool {
        let now = now_ms();
        let mut b = self.inner.lock().unwrap();
        let elapsed = (now - b.last_ms) as f64;
        let refill = (elapsed * b.refill_per_ms) as u64;
        if refill > 0 { b.tokens = (b.tokens + refill).min(b.capacity); b.last_ms = now; }
        if b.tokens >= n { b.tokens -= n; true } else { false }
    }
}

/* ---- AppState ---- */
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub http: Client,
    pub dev_mode: bool,
    pub peers: Vec<String>,

    pub self_vk: VerifyingKey,
    pub sk: Arc<SigningKey>,

    // gossip/кворум
    pub seen_blocks: Arc<Mutex<HashSet<String>>>,
    pub vote_seen: Arc<Mutex<HashSet<String>>>,
    pub vote_tally: Arc<Mutex<HashMap<(u64,String), HashSet<String>>>>,
    pub validators: Arc<HashSet<String>>,
    pub quorum_n: usize,

    // anti-replay
    pub replay_blk: ReplayWindow,
    pub replay_vote: ReplayWindow,

    // rate-limit
    pub rl_submit: TokenBucket,
    pub rl_admin:  TokenBucket,     // NEW: лимит на админ-ручки

    // peer scoring
    pub peerbook: crate::peers::PeerBook,

    // bridge
    pub rl_bridge: TokenBucket,
    pub replay_bridge: ReplayWindow,
    pub bridge_max_per_tx: u64,
    pub bridge_key: Option<String>,
}
