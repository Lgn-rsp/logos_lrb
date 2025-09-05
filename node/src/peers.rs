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
