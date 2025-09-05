use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Голос за блок (по Σ-дайджесту)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub block_hash: String,
    pub sigma_hex: String,
    pub voter_pk_b58: String,
    pub sig_b64: String,
    pub nonce_ms: u128,
}

pub fn verify_vote(v: &Vote) -> Result<()> {
    let pk_bytes = bs58::decode(&v.voter_pk_b58).into_vec()?;
    let vk =
        VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow::anyhow!("bad pk"))?)?;
    let sig_bytes = B64.decode(v.sig_b64.as_bytes())?;
    let sig = Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad sig"))?,
    );

    let mut payload = Vec::new();
    payload.extend_from_slice(v.sigma_hex.as_bytes());
    payload.extend_from_slice(v.block_hash.as_bytes());
    payload.extend_from_slice(&v.height.to_le_bytes());
    payload.extend_from_slice(&v.nonce_ms.to_le_bytes());

    vk.verify(&payload, &sig)
        .map_err(|e| anyhow::anyhow!("verify failed: {e}"))?;
    Ok(())
}
