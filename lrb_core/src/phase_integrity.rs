use crate::types::*;
use anyhow::{anyhow, Result};
use ed25519_dalek::Verifier as _; // для pk.verify(&msg, &sig)

pub fn verify_tx_signature(tx: &Tx) -> Result<()> {
    tx.validate_shape()?;

    let pk = crate::types::parse_pubkey(&tx.public_key)?;
    let sig = crate::types::parse_sig(&tx.signature)?;
    let msg = tx.canonical_bytes();

    pk.verify(&msg, &sig)
        .map_err(|e| anyhow!("bad signature: {e}"))?;

    // сверяем id
    if tx.id != tx.compute_id() {
        return Err(anyhow!("tx id mismatch"));
    }
    Ok(())
}
