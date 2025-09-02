rust
// LOGOS External Phase Link — Bridge to External Phase Sources
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_json;
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalPhase {
    pub rid: String,            // Добавлено для идентификации узла
    pub source: String,
    pub symbol: String,
    pub frequency: f64,
    pub phase: f64,
    pub timestamp: u64,
    pub confidence: f64,        // Оценка достоверности [0.0 - 1.0]
}

pub struct ExternalPhaseLink {
    pub accepted_sources: HashSet<String>,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub log_file: String,
    pub state_file: String,
    pub cipher_key: Vec<u8>,
    pub min_confidence: f64,
    pub network_activity: f64,
    pub last_received: HashMap<String, u64>, // source -> timestamp
    pub min_receive_interval: u64,
}

impl ExternalPhaseLink {
    pub fn new() -> Self {
        let mut sources = HashSet::new();
        sources.insert("external_device".to_string());
        sources.insert("oracle_feed".to_string());
        sources.insert("bio_input".to_string());

        let mut symbols = HashSet::new();
        symbols.insert("Λ0".to_string());
        symbols.insert("☉".to_string());
        symbols.insert("??".to_string());
        symbols.insert("♁".to_string());
        symbols.insert("??".to_string());
        symbols.insert("??".to_string());
        symbols.insert("??".to_string());
        symbols.insert("∞".to_string());

        ExternalPhaseLink {
            accepted_sources: sources,
            valid_symbols: symbols,
            lambda_zero: "Λ0".to_string(),
            log_file: "external_phase_link_log.json".to_string(),
            state_file: "external_phase_link_state.json".to_string(),
            cipher_key: vec![0u8; 32], // Заменить на реальный ключ
            min_confidence: 0.6,
            network_activity: 1.0,
            last_received: HashMap::new(),
            min_receive_interval: 60,
        }
    }

    pub fn update_network_activity(&mut self, activity: f64) {
        // Адаптивный порог достоверности
        self.network_activity = activity.clamp(0.1, 10.0);
        self.min_confidence = (0.6 / self.network_activity).clamp(0.4, 0.8);
        self.log_event(&format!(
            "[INFO] Network activity updated: {:.2}, min_confidence={:.2}",
            self.network_activity, self.min_confidence
        ));
    }

    pub fn validate_rid(&self, rid: &str) -> bool {
        !rid.is_empty() && rid.chars().any(|c| self.valid_symbols.contains(&c.to_string()))
    }

    pub fn validate_input(&self, ep: &ExternalPhase) -> bool {
        self.accepted_sources.contains(&ep.source) &&
        self.valid_symbols.contains(&ep.symbol) &&
        (0.1..=10000.0).contains(&ep.frequency) &&
        (-std::f64::consts::PI..=std::f64::consts::PI).contains(&ep.phase) &&
        ep.confidence >= self.min_confidence &&
        self.validate_rid(&ep.rid)
    }

    pub fn forward_phase(&self, ep: ExternalPhase) -> bool {
        let now = Self::current_time();

        // Проверка частоты приёма
        let last = self.last_received.get(&ep.source).cloned().unwrap_or(0);
        let adjusted_interval = if ep.symbol == self.lambda_zero {
            self.min_receive_interval / 2 // Меньший интервал для Λ0
        } else {
            self.min_receive_interval
        };
        if now - last < adjusted_interval {
            self.log_event(&format!("[DROP] Слишком частый приём от '{}'", ep.source));
            return false;
        }

        // Валидация
        if !self.validate_input(&ep) {
            self.log_event(&format!("[DROP] Неверный сигнал от '{}': RID={}, symbol={}, conf={:.2}",
                ep.source, ep.rid, ep.symbol, ep.confidence));
            return false;
        }

        // Проверка через RCP и resonance_analyzer (заглушка)
        if !self.validate_with_rcp_and_analyzer(&ep) {
            self.log_event(&format!("[REJECT] RCP/analyzer отклонил фазу от '{}'", ep.source));
            return false;
        }

        // Сохранение состояния
        let mutable_self = unsafe { &mut *(self as *const Self as *mut Self) };
        mutable_self.last_received.insert(ep.source.clone(), now);
        self.save_state(&ep);

        self.log_event(&format!(
            "[LINK] Принята внешняя фаза от {}: RID={} {} @ {:.3}Hz φ={:.4}, conf={:.2}",
            ep.source, ep.rid, ep.symbol, ep.frequency, ep.phase, ep.confidence
        ));
        true
    }

    pub fn validate_with_rcp_and_analyzer(&self, ep: &ExternalPhase) -> bool {
        // Заглушка для проверки через rcp_engine.rs и resonance_analyzer.py
        ep.symbol == self.lambda_zero || (ep.frequency - 7.83).abs() < 0.1
    }

    fn save_state(&self, ep: &ExternalPhase) {
        let state = serde_json::to_string(ep).unwrap_or_default();
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut in_out = state.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut in_out).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.state_file)
            {
                let _ = file.write_all(&in_out);
                let _ = file.write_all(b"\n");
            }
        }
    }

    fn log_event(&self, message: &str) {
        let entry = format!(
            "{{\"event\": \"external_phase_link\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            message,
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

