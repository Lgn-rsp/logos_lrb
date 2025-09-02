
// LOGOS Transaction Spam Guard
// Автор: LOGOS Core Dev Team

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

pub struct TxSpamGuard {
    pub violation_count: HashMap<String, u32>,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub log_file: String,
    pub cipher_key: Vec<u8>,
}

impl TxSpamGuard {
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

        TxSpamGuard {
            violation_count: HashMap::new(),
            valid_symbols,
            lambda_zero: "Λ0".to_string(),
            log_file: "tx_spam_guard_log.enc".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
        }
    }

    pub fn validate_rid(&self, rid: &str) -> bool {
        !rid.is_empty() && rid.chars().any(|c| self.valid_symbols.contains(&c.to_string()))
    }

    pub fn check_spam(&mut self, rid: &str, symbol: &str) -> bool {
        if !self.validate_rid(rid) || !self.valid_symbols.contains(symbol) {
            self.log_event(&format!("[DROP] Недопустимый RID или символ: {}, {}", rid, symbol));
            return false;
        }

        let violations = *self.violation_count.entry(rid.to_string()).or_insert(0);
        let new_violations = violations + 1;
        self.violation_count.insert(rid.to_string(), new_violations);
        self.log_event(&format!("[CHECK] RID {}: {} нарушений", rid, new_violations));

        if new_violations >= 3 {
            self.log_event(&format!("[SPAM] RID {} заблокирован", rid));
            return false;
        }

        true
    }

    pub fn is_tx_spam(&self, rid: &str) -> bool {
        self.violation_count.get(rid).map_or(false, |&count| count >= 3)
    }

    fn log_event(&self, msg: &str) {
        let entry = format!(
            "{{\"event\": \"tx_spam_guard\", \"message\": \"{}\", \"timestamp\": {}}}\n",
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

