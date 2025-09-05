//! Точка-точка фазовая связка: AEAD XChaCha20-Poly1305 + Ed25519 подпись.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct PhaseLink {
    aead: AeadBox,
    self_vk: VerifyingKey,
    peer_vk: VerifyingKey,
}

impl PhaseLink {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey, peer_vk:VerifyingKey) -> Self {
        Self { aead:AeadBox::from_key(&key32), self_vk, peer_vk }
    }

    pub fn encode(&self, signer:&SigningKey, channel:&[u8], frame:&[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(channel.len()+64);
        aad.extend_from_slice(channel);
        aad.extend_from_slice(self.self_vk.as_bytes());
        aad.extend_from_slice(self.peer_vk.as_bytes());

        let sealed = self.aead.seal(&aad, frame);
        let sig = signer.sign(&sealed);

        let mut out = Vec::with_capacity(64+sealed.len());
        out.extend_from_slice(sig.as_ref());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn decode(&self, sender_vk:&VerifyingKey, channel:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len() < 64+24+16 { anyhow::bail!("phase_link: short"); }
        let (sig_bytes, sealed) = data.split_at(64);
        let sig = Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed, &sig).map_err(|_| anyhow::anyhow!("phase_link: bad signature"))?;

        let mut aad = Vec::with_capacity(channel.len()+64);
        aad.extend_from_slice(channel);
        aad.extend_from_slice(self.self_vk.as_bytes());
        aad.extend_from_slice(self.peer_vk.as_bytes());

        Ok(self.aead.open(&aad, sealed)?)
    }
}
