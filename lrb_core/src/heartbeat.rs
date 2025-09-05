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
