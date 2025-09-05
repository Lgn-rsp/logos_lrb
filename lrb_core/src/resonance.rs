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
