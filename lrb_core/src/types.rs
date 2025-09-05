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
pub type Nonce = u64;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Rid(pub String); // base58(VerifyingKey)

impl Rid {
    pub fn from_pubkey(pk: &VerifyingKey) -> Self {
        Rid(bs58::encode(pk.to_bytes()).into_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub id: String, // blake3 of canonical form
    pub from: Rid,  // base58(pubkey)
    pub to: Rid,
    pub amount: Amount,
    pub nonce: Nonce,
    pub public_key: Vec<u8>, // 32 bytes (VerifyingKey)
    pub signature: Vec<u8>,  // 64 bytes (Signature)
}

impl Tx {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Без id и signature для детерминированного хеша
        let m = serde_json::json!({
            "from": self.from.as_str(),
            "to": self.to.as_str(),
            "amount": self.amount,
            "nonce": self.nonce,
            "public_key": B64.encode(&self.public_key),
        });
        serde_json::to_vec(&m).expect("canonical json")
    }
    pub fn compute_id(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.canonical_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }
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
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let mut h = Hasher::new();
        h.update(prev_hash.as_bytes());
        h.update(proposer.as_str().as_bytes());
        for tx in &txs {
            h.update(tx.id.as_bytes());
        }
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

pub fn parse_pubkey(pk: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = pk.try_into().map_err(|_| anyhow!("bad pubkey len"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

pub fn parse_sig(sig: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = sig.try_into().map_err(|_| anyhow!("bad signature len"))?;
    Ok(Signature::from_bytes(&arr))
}
