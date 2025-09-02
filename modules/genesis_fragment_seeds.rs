rust
// LOGOS Genesis Fragment Seeds
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Write, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use serde_json;
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};
use shamirsecretsharing::{split_secret, recover_secret};

#[derive(Debug, Serialize, Deserialize)]
pub struct SeedFragment {
    pub node_id: String,
    pub fragment: Vec<u8>,
    pub timestamp: u64,
    pub symbol: String, // Связь с Λ0
}

pub struct GenesisFragmentSeeds {
    pub fragments: HashMap<String, SeedFragment>,
    pub required_shares: usize,
    pub total_shares: usize,
    pub original_seed: Vec<u8>,
    pub log_file: String,
    pub state_file: String,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub store_timestamps: HashMap<String, u64>, // node_id -> last store time
    pub cipher_key: Vec<u8>, // Ключ для AES-256
}

impl GenesisFragmentSeeds {
    pub fn new(seed: Vec<u8>, total: usize, required: usize) -> Self {
        let mut valid_symbols = HashSet::new();
        valid_symbols.insert("☉".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("♁".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("Λ0".to_string());
        valid_symbols.insert("∞".to_string());

        GenesisFragmentSeeds {
            fragments: HashMap::new(),
            required_shares: required,
            total_shares: total,
            original_seed: seed,
            log_file: "genesis_fragment_log.json".to_string(),
            state_file: "genesis_fragment_state.json".to_string(),
            valid_symbols,
            lambda_zero: "Λ0".to_string(),
            store_timestamps: HashMap::new(),
            cipher_key: vec![0u8; 32], // Заглушка, в продакшене безопасный ключ
        }
    }

    pub fn validate_node_id_and_symbol(&self, node_id: &str, symbol: &str) -> bool {
        node_id.contains(|c: char| self.valid_symbols.contains(&c.to_string())) &&
        self.valid_symbols.contains(symbol)
    }

    pub fn generate_shards(&mut self) -> Vec<(usize, Vec<u8>)> {
        let shards = split_secret(self.total_shares, self.required_shares, &self.original_seed)
            .expect("Ошибка при фрагментации Λ0");
        self.log_event("[FRAG] Сгенерированы фрагменты ядра");
        shards
    }

    pub fn store_fragment(&mut self, node_id: &str, fragment: Vec<u8>, symbol: &str) -> bool {
        let now = Self::current_time();

        // Ограничение частоты
        let last_store = self.store_timestamps.get(node_id).cloned().unwrap_or(0);
        if now - last_store < 60 {
            self.log_event(&format!("[!] Слишком частое сохранение от {}", node_id));
            return false;
        }
        self.store_timestamps.insert(node_id.to_string(), now);

        // Валидация node_id и symbol
        if !self.validate_node_id_and_symbol(node_id, symbol) {
            self.log_event(&format!("[!] Недопустимый node_id или символ: {}, {}", node_id, symbol));
            return false;
        }

        // Проверка связи с Λ0 (заглушка для resonance_analyzer.py)
        if symbol != self.lambda_zero && !self.validate_with_analyzer(node_id, symbol) {
            self.log_event(&format!("[!] Символ {} не связан с Λ0", symbol));
            return false;
        }

        let entry = SeedFragment {
            node_id: node_id.to_string(),
            fragment,
            timestamp: now,
            symbol: symbol.to_string(),
        };
        self.fragments.insert(node_id.to_string(), entry);
        self.save_state();
        self.log_event(&format!("[STORE] Фрагмент принят от {} (symbol: {})", node_id, symbol));
        true
    }

    pub fn recover_seed(&self) -> Option<Vec<u8>> {
        if self.fragments.len() < self.required_shares {
            self.log_event(&format!(
                "[WARN] Недостаточно фрагментов: {}/{}",
                self.fragments.len(), self.required_shares
            ));
            return None;
        }

        let shares: Vec<(usize, Vec<u8>)> = self
            .fragments
            .iter()
            .take(self.required_shares)
            .enumerate()
            .map(|(i, (_, frag))| (i + 1, frag.fragment.clone()))
            .collect();

        match recover_secret(&shares) {
            Ok(seed) => {
                self.log_event("[SUCCESS] Λ0 восстановлен из фрагментов");
                Some(seed)
            }
            Err(e) => {
                self.log_event(&format!("[FAIL] Ошибка восстановления Λ0: {}", e));
                None
            }
        }
    }

    fn validate_with_analyzer(&self, _node_id: &str, symbol: &str) -> bool {
        // Заглушка для проверки через resonance_analyzer.py
        symbol == self.lambda_zero
    }

    fn save_state(&self) {
        let state = serde_json::to_string(&self.fragments).unwrap_or_default();
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut in_out = state.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut in_out).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.state_file)
            {
                let _ = file.write_all(&in_out);
            }
        }
    }

    fn log_event(&self, msg: &str) {
        let entry = format!(
            "{{\"event\": \"genesis_fragment\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            msg,
            Self::current_time()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut in_out = entry.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut in_out).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file)
            {
                let _ = file.write_all(&in_out);
            }
        }
    }

    pub fn current_time() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
