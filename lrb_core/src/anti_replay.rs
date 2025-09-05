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
