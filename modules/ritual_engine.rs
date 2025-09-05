//! Ritual Engine: доставка «ритуальных» сообщений c фазовой меткой, AEAD+подпись.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct RitualEngine { aead:AeadBox, self_vk:VerifyingKey }

impl RitualEngine {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn send(&self, signer:&SigningKey, phase_id:&[u8], msg:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(phase_id.len()+32); aad.extend_from_slice(phase_id); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, msg); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn recv(&self, sender_vk:&VerifyingKey, phase_id:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("ritual_engine: short"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("ritual_engine: bad sig"))?;
        let mut aad=Vec::with_capacity(phase_id.len()+32); aad.extend_from_slice(phase_id); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}
