//! API root: общие типы/утилы + экспорт подмодулей

use serde::{Deserialize, Serialize};

pub mod base;
pub mod tx;
pub mod archive;
pub mod staking;

// ---------- Общие модели ----------
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

// ---------- Утили для подписи ----------
use sha2::{Sha256, Digest};
use ed25519_dalek::{Verifier, Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

pub fn canonical_msg(from:&str, to:&str, amount:u64, nonce:u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(from.as_bytes()); h.update(b"|");
    h.update(to.as_bytes());   h.update(b"|");
    h.update(&amount.to_be_bytes()); h.update(b"|");
    h.update(&nonce.to_be_bytes());
    h.finalize().to_vec()
}

pub fn verify_sig(from:&str, msg:&[u8], sig_hex:&str) -> Result<(), String> {
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

// ---------- Переэкспорт хендлеров ----------
pub use base::{healthz, head, balance, economy, history};
pub use tx::{submit_tx, submit_tx_batch};
pub use archive::{archive_history, archive_tx, archive_blocks, archive_txs};
pub use staking::{stake_delegate, stake_undelegate, stake_claim, stake_my};
