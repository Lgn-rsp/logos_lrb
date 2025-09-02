
// LOGOS Resonance — анализ и фильтрация резонансных сигналов
// Автор: LOGOS Core Dev Team

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use crate::utils::math::calculate_sigma;
use crate::utils::types::ResonanceMode;

pub struct Resonance {
    pub valid_symbols: HashSet<String>,
    pub log_file: String,
    pub cipher_key: Vec<u8>,
}

impl Resonance {
    pub fn new() -> Self {
        let mut valid_symbols = HashSet::new();
        valid_symbols.insert("Λ0".to_string());
        valid_symbols.insert("☉".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("♁".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("∞".to_string());

        Resonance {
            valid_symbols,
            log_file: "resonance_log.enc".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
        }
    }

    pub fn analyze_signal(&self, rid: &str, t: f64, symbol: &str, mode: ResonanceMode) -> bool {
        if !self.valid_symbols.contains(symbol) {
            self.log_event(&format!("[DROP] Неверный символ: {}", symbol));
            return false;
        }

        let sigma = calculate_sigma(t);
        match mode {
            ResonanceMode::Passive => {
                self.log_event(&format!("[PASSIVE] RID {}: sigma={:?}", rid, sigma));
            }
            ResonanceMode::Amplified => {
                self.log_event(&format!("[AMPLIFIED] RID {}: sigma={:?}", rid, sigma));
            }
            ResonanceMode::SelfAdjusting => {
                self.log_event(&format!("[ADJUST] RID {}: sigma={:?}", rid, sigma));
            }
            ResonanceMode::Chaotic => {
                self.log_event(&format!("[CHAOTIC] RID {}: sigma={:?}", rid, sigma));
            }
        }

        true
    }

    fn log_event(&self, msg: &str) {
        let entry = format!(
            "{{\"event\": \"resonance\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            msg,
            Self::now()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let key = LessSafeKey::new(key);
        let mut buf = entry.as_bytes().to_vec();
        if key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file)
            {
                let _ = file.write_all(&buf);
            }
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
