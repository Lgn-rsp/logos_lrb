// Безопасный AEAD: XChaCha20-Poly1305 с уникальным nonce.
// Формат шифротекста: [24-байт nonce || ciphertext+tag]

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};

pub struct AeadBox {
    key: Key,
}

impl AeadBox {
    pub fn from_key(key_bytes: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_bytes);
        Self { key: *key }
    }

    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&self.key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 24 байта
        let mut out = Vec::with_capacity(24 + plaintext.len() + 16);
        out.extend_from_slice(&nonce);
        let ct = cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("AEAD encrypt failed");
        out.extend_from_slice(&ct);
        out
    }

    pub fn open(&self, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 24 + 16 {
            anyhow::bail!("AEAD: buffer too short");
        }
        let (nonce_bytes, ct) = data.split_at(24);
        let cipher = XChaCha20Poly1305::new(&self.key);
        let nonce = XNonce::from_slice(nonce_bytes);
        let pt = cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ct, aad })
            .map_err(|_| anyhow::anyhow!("AEAD decrypt failed"))?;
        Ok(pt)
    }
}
