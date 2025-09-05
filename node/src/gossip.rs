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
