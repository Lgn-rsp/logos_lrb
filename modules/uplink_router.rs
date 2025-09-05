//! Uplink Router: безопасная пересылка кадров между маршрутами.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct UplinkRouter {
    aead: AeadBox,
    self_vk: VerifyingKey,
}

impl UplinkRouter {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self {
        Self { aead:AeadBox::from_key(&key32), self_vk }
    }

    pub fn wrap(&self, signer:&SigningKey, route:&[u8], payload:&[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(route.len()+32);
        aad.extend_from_slice(route);
        aad.extend_from_slice(self.self_vk.as_bytes());

        let sealed = self.aead.seal(&aad, payload);
        let sig = signer.sign(&sealed);

        let mut out = Vec::with_capacity(64+sealed.len());
        out.extend_from_slice(sig.as_ref());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn unwrap(&self, sender_vk:&VerifyingKey, route:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len() < 64+24+16 { anyhow::bail!("uplink_router: short"); }
        let (sig_bytes, sealed) = data.split_at(64);
        let sig = Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed, &sig).map_err(|_| anyhow::anyhow!("uplink_router: bad signature"))?;

        let mut aad = Vec::with_capacity(route.len()+32);
        aad.extend_from_slice(route);
        aad.extend_from_slice(self.self_vk.as_bytes());

        Ok(self.aead.open(&aad, sealed)?)
    }
}
