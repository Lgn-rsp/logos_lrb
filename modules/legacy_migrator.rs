//! Legacy Migrator: перенос артефактов со шифрованием и подписью.

use lrb_core::crypto::AeadBox;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use anyhow::Result;

pub struct LegacyMigrator { aead:AeadBox, self_vk:VerifyingKey }

impl LegacyMigrator {
    pub fn new(key32:[u8;32], self_vk:VerifyingKey) -> Self { Self{ aead:AeadBox::from_key(&key32), self_vk } }

    pub fn wrap_blob(&self, signer:&SigningKey, kind:&[u8], blob:&[u8]) -> Result<Vec<u8>> {
        let mut aad=Vec::with_capacity(kind.len()+32); aad.extend_from_slice(kind); aad.extend_from_slice(self.self_vk.as_bytes());
        let sealed=self.aead.seal(&aad, blob); let sig=signer.sign(&sealed);
        let mut out=Vec::with_capacity(64+sealed.len()); out.extend_from_slice(sig.as_ref()); out.extend_from_slice(&sealed); Ok(out)
    }

    pub fn unwrap_blob(&self, sender_vk:&VerifyingKey, kind:&[u8], data:&[u8]) -> Result<Vec<u8>> {
        if data.len()<64+24+16 { anyhow::bail!("legacy_migrator: short"); }
        let(sig_bytes,sealed)=data.split_at(64); let sig=Signature::from_bytes(sig_bytes)?;
        sender_vk.verify_strict(sealed,&sig).map_err(|_|anyhow::anyhow!("legacy_migrator: bad sig"))?;
        let mut aad=Vec::with_capacity(kind.len()+32); aad.extend_from_slice(kind); aad.extend_from_slice(self.self_vk.as_bytes());
        Ok(self.aead.open(&aad, sealed)?)
    }
}
