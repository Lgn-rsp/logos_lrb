
// LOGOS Self — самоизменение и защита от хаоса
// Автор: LOGOS Core Dev Team

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use crate::utils::types::ResonanceMode;

pub struct LogosSelf {
    pub valid_symbols: HashSet<String>,
    pub entropy_log: String,
    pub cipher_key: Vec<u8>,
}

impl LogosSelf {
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

        LogosSelf {
            valid_symbols,
            entropy_log: "logos_self_log.enc".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
        }
    }

    pub fn auto_init(&self, symbol: &str, mode: ResonanceMode) -> bool {
        if !self.valid_symbols.contains(symbol) {
            self.log_event(&format!("[DROP] Неверный символ для инициализации: {}", symbol));
            return false;
        }

        self.log_event(&format!("[INIT] Автоинициализация Λ0 в режиме {:?}", mode));
        true
    }

    pub fn track_entropy(&self, entropy: f64) -> bool {
        if entropy < 0.0 {
            self.log_event(&format!("[DROP] Неверная энтропия: {}", entropy));
            return false;
        }
        self.log_event(&format!("[ENTROPY] Уровень энтропии: {:.2}", entropy));
        true
    }

    fn log_event(&self, msg: &str) {
        let entry = format!(
            "{{\"event\": \"logos_self\", \"message\": \"{}\", \"timestamp\": {}}}\n",
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
                .open(&self.entropy_log)
            {
                let _ = file.write_all(&buf);
            }
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
