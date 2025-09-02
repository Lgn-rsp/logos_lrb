
// LOGOS Phase — управление фазами сети
// Автор: LOGOS Core Dev Team

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use crate::utils::frequency::validate_frequency;
use crate::utils::types::ResonanceMode;

#[derive(Debug, Serialize, Deserialize)]
pub struct PhaseSignal {
    pub rid: String,
    pub symbol: String,
    pub frequency: f64,
    pub phase: f64,
    pub timestamp: u64,
}

pub struct Phase {
    pub clusters: HashMap<String, Vec<PhaseSignal>>, // Для масштабирования
    pub phase_data: HashMap<String, PhaseSignal>,    // Для стабилизации
    pub blocked_rids: HashSet<String>,               // Для фильтрации
    pub history: VecDeque<PhaseSignal>,              // Для восстановления
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub log_file: String,
    pub cipher_key: Vec<u8>,
    pub max_history: usize,
}

impl Phase {
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

        Phase {
            clusters: HashMap::new(),
            phase_data: HashMap::new(),
            blocked_rids: HashSet::new(),
            history: VecDeque::new(),
            valid_symbols,
            lambda_zero: "Λ0".to_string(),
            log_file: "phase_log.enc".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
            max_history: 1000,
        }
    }

    pub fn process_signal(&mut self, signal: PhaseSignal, mode: ResonanceMode) -> bool {
        if !self.valid_symbols.contains(&signal.symbol) || !validate_frequency(signal.frequency) {
            self.log_event(&format!("[DROP] Неверный символ или частота: {}, {}", signal.symbol, signal.frequency));
            return false;
        }

        if self.blocked_rids.contains(&signal.rid) {
            self.log_event(&format!("[DROP] RID {} заблокирован", signal.rid));
            return false;
        }

        match mode {
            ResonanceMode::Passive => {
                self.phase_data.insert(signal.rid.clone(), signal.clone());
                self.log_event(&format!("[PASSIVE] RID {} принят: freq={:.2}, phase={:.2}", signal.rid, signal.frequency, signal.phase));
            }
            ResonanceMode::Amplified => {
                let cluster = self.clusters.entry(signal.symbol.clone()).or_insert(Vec::new());
                cluster.push(signal.clone());
                self.log_event(&format!("[AMPLIFIED] RID {} добавлен в кластер: {}", signal.rid, signal.symbol));
            }
            ResonanceMode::SelfAdjusting => {
                let adjusted_phase = if signal.symbol == self.lambda_zero { signal.phase * 0.9 } else { signal.phase };
                let adjusted_signal = PhaseSignal {
                    phase: adjusted_phase,
                    ..signal.clone()
                };
                self.phase_data.insert(signal.rid.clone(), adjusted_signal);
                self.log_event(&format!("[ADJUST] RID {} скорректирован: phase={:.2}", signal.rid, adjusted_phase));
            }
            ResonanceMode::Chaotic => {
                self.history.push_back(signal.clone());
                if self.history.len() > self.max_history {
                    self.history.pop_front();
                }
                self.log_event(&format!("[CHAOTIC] RID {} добавлен в историю", signal.rid));
            }
        }

        true
    }

    pub fn backup(&self) {
        let state = serde_json::to_string(&self.phase_data).unwrap_or_default();
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let key = LessSafeKey::new(key);
        let mut buf = state.as_bytes().to_vec();
        if key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open("phase_backup.enc")
            {
                let _ = file.write_all(&buf);
            }
        }
        self.log_event("[BACKUP] Состояние фаз сохранено");
    }

    fn log_event(&self, msg: &str) {
        let entry = format!(
            "{{\"event\": \"phase\", \"message\": \"{}\", \"timestamp\": {}}}\n",
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
