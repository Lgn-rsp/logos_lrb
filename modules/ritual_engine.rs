rust
// LOGOS Ritual Engine
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_json;
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};

#[derive(Debug, Serialize, Deserialize)]
pub struct RitualAction {
    pub rid: String,
    pub symbol: String,
    pub frequency: f64,
    pub phase: f64,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RitualDefinition {
    pub id: String,
    pub title: String,
    pub required_symbol: String,
    pub required_frequency: f64,
    pub required_phase: Option<f64>,
    pub min_phase: Option<f64>,
    pub max_phase: Option<f64>,
    pub reward_lgn: f64,
    pub repeatable: bool,
}

pub struct RitualEngine {
    pub rituals: HashMap<String, RitualDefinition>,
    pub completed: HashMap<String, Vec<String>>, // RID -> list of ritual IDs
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub log_file: String,
    pub action_timestamps: HashMap<String, u64>, // RID -> last action time
    pub cipher_key: Vec<u8>, // Ключ для AES-256
}

impl RitualEngine {
    pub fn new() -> Self {
        let mut valid_symbols = HashSet::new();
        valid_symbols.insert("☉".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("♁".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("Λ0".to_string());
        valid_symbols.insert("∞".to_string());

        RitualEngine {
            rituals: HashMap::new(),
            completed: HashMap::new(),
            valid_symbols,
            lambda_zero: "Λ0".to_string(),
            log_file: "ritual_engine_log.json".to_string(),
            action_timestamps: HashMap::new(),
            cipher_key: vec![0u8; 32], // Заглушка, в продакшене безопасный ключ
        }
    }

    pub fn validate_rid_and_symbol(&self, rid: &str, symbol: &str) -> bool {
        !rid.is_empty() &&
        rid.chars().any(|c| self.valid_symbols.contains(&c.to_string())) &&
        self.valid_symbols.contains(symbol)
    }

    pub fn load_rituals(&mut self, path: &str) {
        if let Ok(file) = std::fs::read_to_string(path) {
            if let Ok(map) = serde_json::from_str::<Vec<RitualDefinition>>(&file) {
                for r in map {
                    if self.valid_symbols.contains(&r.required_symbol) {
                        self.rituals.insert(r.id.clone(), r);
                    } else {
                        self.log_event(&format!("[!] Недопустимый символ в ритуале: {}", r.required_symbol));
                    }
                }
                self.log_event("[INFO] Загружены ритуалы");
            } else {
                self.log_event("[!] Ошибка парсинга ритуалов");
            }
        } else {
            self.log_event(&format!("[!] Ошибка чтения файла ритуалов: {}", path));
        }
    }

    pub fn submit_action(&mut self, action: RitualAction) -> Option<f64> {
        let now = Self::current_time();

        // Проверка частоты действий
        let last_action = self.action_timestamps.get(&action.rid).cloned().unwrap_or(0);
        if now - last_action < 60 {
            self.log_event(&format!("[!] Слишком частое действие от RID {}", action.rid));
            return None;
        }
        self.action_timestamps.insert(action.rid.clone(), now);

        // Валидация RID и символа
        if !self.validate_rid_and_symbol(&action.rid, &action.symbol) {
            self.log_event(&format!("[!] Недопустимый RID или символ: {}, {}", action.rid, action.symbol));
            return None;
        }

        // Проверка параметров
        if action.frequency <= 0.0 || action.frequency > 10000.0 ||
           !(-std::f64::consts::PI..=std::f64::consts::PI).contains(&action.phase) {
            self.log_event(&format!(
                "[!] Недопустимые параметры: f={}, φ={:.4}",
                action.frequency, action.phase
            ));
            return None;
        }

        // Проверка через RCP (заглушка)
        if !self.validate_with_rcp(&action) {
            self.log_event(&format!(
                "[!] RCP не подтвердил: {} @ {}Hz φ={:.4}",
                action.symbol, action.frequency, action.phase
            ));
            return None;
        }

        for (id, ritual) in self.rituals.iter() {
            if !ritual.repeatable && self.completed.get(&action.rid).map_or(false, |r| r.contains(id)) {
                continue;
            }

            if ritual.required_symbol != action.symbol {
                continue;
            }

            if (ritual.required_frequency - action.frequency).abs() > 0.1 {
                continue;
            }

            if let Some(req_phase) = ritual.required_phase {
                if (req_phase - action.phase).abs() > 0.05 {
                    continue;
                }
            }

            if let Some(min) = ritual.min_phase {
                if action.phase < min {
                    continue;
                }
            }

            if let Some(max) = ritual.max_phase {
                if action.phase > max {
                    continue;
                }
            }

            let reward = if action.symbol == self.lambda_zero {
                ritual.reward_lgn * 1.2 // Бонус для Λ0
            } else {
                ritual.reward_lgn
            };

            self.completed
                .entry(action.rid.clone())
                .or_default()
                .push(ritual.id.clone());

            self.log_event(&format!(
                "[RITUAL] RID {} выполнил ритуал {}: {} (+{} LGN)",
                action.rid, ritual.id, ritual.title, reward
            ));
            return Some(reward);
        }

        self.log_event(&format!("[MISS] RID {} не активировал ни один ритуал", action.rid));
        None
    }

    fn validate_with_rcp(&self, action: &RitualAction) -> bool {
        // Заглушка для проверки через rcp_engine.rs
        action.symbol == self.lambda_zero || (action.frequency - 7.83).abs() < 0.1
    }

    fn log_event(&self, message: &str) {
        let entry = format!(
            "{{\"event\": \"ritual_engine\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            message,
            Self::current_time()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut in_out = entry.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut in_out).is_ok() {
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file)
            {
                let _ = f.write_all(&in_out);
            }
        }
    }

    pub fn current_time() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
