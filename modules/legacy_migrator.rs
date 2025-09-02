// LOGOS Legacy Blockchain Migrator
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Write, Read};
use serde::{Deserialize, Serialize};
use serde_json;
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};

#[derive(Debug, Serialize, Deserialize)]
pub struct LegacyTx {
    pub origin_chain: String,
    pub legacy_address: String,
    pub tx_hash: String,
    pub amount: f64,
    pub timestamp: u64,
    pub symbol_hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigratedTx {
    pub rid: String,
    pub symbol: String,
    pub frequency: f64,
    pub phase: f64,
    pub amount: f64,
    pub migrated_from: String,
    pub original_tx_hash: String,
    pub timestamp: u64,
}

pub struct LegacyMigrator {
    pub migration_log: String,
    pub symbol_map: HashMap<String, String>,
    pub frequency_map: HashMap<String, f64>,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub cipher_key: Vec<u8>, // Ключ для AES-256
}

impl LegacyMigrator {
    pub fn new() -> Self {
        let mut symbol_map = HashMap::new();
        symbol_map.insert("ethereum".to_string(), "☉".to_string());
        symbol_map.insert("cosmos".to_string(), "??".to_string());
        symbol_map.insert("polkadot".to_string(), "♁".to_string());

        let mut frequency_map = HashMap::new();
        frequency_map.insert("ethereum".to_string(), 432.0);
        frequency_map.insert("cosmos".to_string(), 7.83);
        frequency_map.insert("polkadot".to_string(), 1.618);

        let mut valid_symbols = HashSet::new();
        valid_symbols.insert("☉".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("♁".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("Λ0".to_string());
        valid_symbols.insert("∞".to_string());

        LegacyMigrator {
            migration_log: "legacy_migration_log.json".to_string(),
            symbol_map,
            frequency_map,
            valid_symbols,
            lambda_zero: "Λ0".to_string(),
            cipher_key: vec![0u8; 32], // Заглушка, в продакшене безопасный ключ
        }
    }

    pub fn validate_tx(&self, tx: &LegacyTx) -> bool {
        // Проверка данных транзакции
        !tx.origin_chain.is_empty() &&
        !tx.legacy_address.is_empty() &&
        !tx.tx_hash.is_empty() &&
        tx.amount > 0.0 &&
        tx.timestamp > 0 &&
        tx.symbol_hint.as_ref().map_or(true, |s| self.valid_symbols.contains(s))
    }

    pub fn migrate(&self, legacy_tx: LegacyTx) -> Option<MigratedTx> {
        if !self.validate_tx(&legacy_tx) {
            self.log_migration_event(&format!(
                "[!] Недопустимая транзакция: chain={}, amount={}",
                legacy_tx.origin_chain, legacy_tx.amount
            ));
            return None;
        }

        let chain = legacy_tx.origin_chain.to_lowercase();
        let symbol = legacy_tx.symbol_hint.clone().unwrap_or_else(|| {
            self.symbol_map.get(&chain).cloned().unwrap_or(self.lambda_zero.clone())
        });

        if !self.valid_symbols.contains(&symbol) {
            self.log_migration_event(&format!("[!] Недопустимый символ: {}", symbol));
            return None;
        }

        let freq = self.frequency_map.get(&chain).cloned().unwrap_or(7.83);
        let phase = self.estimate_phase(&legacy_tx);

        // Проверка фазы через RCP (заглушка)
        if !self.validate_with_rcp(&symbol, freq, phase) {
            self.log_migration_event(&format!(
                "[!] RCP не подтвердил: {} @ {} Hz, φ={:.4}",
                symbol, freq, phase
            ));
            return None;
        }

        let rid = format!("{}@{}Hzφ{:.4}", symbol, freq, phase);

        let migrated = MigratedTx {
            rid: rid.clone(),
            symbol,
            frequency: freq,
            phase,
            amount: legacy_tx.amount,
            migrated_from: legacy_tx.origin_chain.clone(),
            original_tx_hash: legacy_tx.tx_hash.clone(),
            timestamp: legacy_tx.timestamp,
        };

        self.log_migration(&migrated);
        Some(migrated)
    }

    fn validate_with_rcp(&self, symbol: &str, frequency: f64, phase: f64) -> bool {
        // Заглушка для проверки через rcp_engine.rs
        symbol == self.lambda_zero || (frequency - 7.83).abs() < 0.1
    }

    fn estimate_phase(&self, tx: &LegacyTx) -> f64 {
        let h = tx.tx_hash.bytes().fold(0u64, |acc, b| acc.wrapping_add(b as u64));
        let phase = ((h % 6283) as f64 / 1000.0) - std::f64::consts::PI;
        phase
    }

    fn log_migration(&self, migrated: &MigratedTx) {
        let json = serde_json::to_string(migrated).unwrap_or_default();
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap(); // Заглушка для nonce
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut in_out = json.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut in_out).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.migration_log)
            {
                let _ = writeln!(file, "{}", String::from_utf8_lossy(&in_out));
            }
        }
    }

    fn log_migration_event(&self, message: &str) {
        let log_entry = format!(
            "{{\"event\": \"legacy_migration\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            message,
            Self::current_time()
        );
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.migration_log)
        {
            let _ = file.write_all(log_entry.as_bytes());
        }
    }

    pub fn load_legacy_batch(&self, path: &str) -> Vec<LegacyTx> {
        if let Ok(mut f) = File::open(path) {
            let mut contents = String::new();
            if f.read_to_string(&mut contents).is_ok() {
                if let Ok(list) = serde_json::from_str::<Vec<LegacyTx>>(&contents) {
                    return list.into_iter().filter(|tx| self.validate_tx(tx)).collect();
                }
            }
        }
        self.log_migration_event(&format!("[!] Ошибка загрузки батча: {}", path));
        vec![]
    }

    pub fn current_time() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
