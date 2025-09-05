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
