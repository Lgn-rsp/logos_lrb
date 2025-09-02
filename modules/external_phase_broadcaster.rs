rust
// LOGOS External Phase Broadcaster
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use serde_json;
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BroadcastPhase {
    pub rid: String,            // Добавлено для идентификации узла
    pub symbol: String,
    pub frequency: f64,
    pub phase: f64,
    pub confidence: f64,
    pub timestamp: u64,
    pub destination: String,    // "file", "sound", "radio", "ble"
}

pub struct ExternalPhaseBroadcaster {
    pub valid_symbols: HashSet<String>,
    pub supported_channels: HashSet<String>,
    pub lambda_zero: String,
    pub min_confidence: f64,
    pub log_file: String,
    pub state_file: String,
    pub last_broadcast: HashMap<String, u64>, // destination -> timestamp
    pub last_broadcast_rid: HashMap<String, u64>, // rid -> timestamp
    pub min_interval_sec: u64,
    pub cipher_key: Vec<u8>,
}

impl ExternalPhaseBroadcaster {
    pub fn new() -> Self {
        let mut symbols = HashSet::new();
        symbols.insert("Λ0".to_string());
        symbols.insert("☉".to_string());
        symbols.insert("??".to_string());
        symbols.insert("♁".to_string());
        symbols.insert("??".to_string());
        symbols.insert("??".to_string());
        symbols.insert("??".to_string());
        symbols.insert("∞".to_string());

        let mut channels = HashSet::new();
        channels.insert("file".to_string());
        channels.insert("sound".to_string());
        channels.insert("radio".to_string());
        channels.insert("ble".to_string());

        ExternalPhaseBroadcaster {
            valid_symbols: symbols,
            supported_channels: channels,
            lambda_zero: "Λ0".to_string(),
            min_confidence: 0.6,
            log_file: "external_phase_broadcast_log.json".to_string(),
            state_file: "external_phase_broadcast_state.json".to_string(),
            last_broadcast: HashMap::new(),
            last_broadcast_rid: HashMap::new(),
            min_interval_sec: 30,
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
        }
    }

    pub fn validate_rid(&self, rid: &str) -> bool {
        !rid.is_empty() && rid.chars().any(|c| self.valid_symbols.contains(&c.to_string()))
    }

    pub fn validate(&self, phase: &BroadcastPhase) -> bool {
        self.valid_symbols.contains(&phase.symbol) &&
        self.supported_channels.contains(&phase.destination) &&
        (0.1..=10000.0).contains(&phase.frequency) &&
        (-std::f64::consts::PI..=std::f64::consts::PI).contains(&phase.phase) &&
        phase.confidence >= self.min_confidence &&
        self.validate_rid(&phase.rid)
    }

    pub fn broadcast(&mut self, phase: BroadcastPhase) -> bool {
        let now = Self::current_time();

        // Проверка частоты по каналу
        let last = self.last_broadcast.get(&phase.destination).cloned().unwrap_or(0);
        let adjusted_interval = if phase.symbol == self.lambda_zero {
            self.min_interval_sec / 2 // Меньший интервал для Λ0
        } else {
            self.min_interval_sec
        };
        if now - last < adjusted_interval {
            self.log_event(&phase, "[SKIP] Слишком частая рассылка по каналу");
            return false;
        }

        // Проверка частоты по RID
        let last_rid = self.last_broadcast_rid.get(&phase.rid).cloned().unwrap_or(0);
        if now - last_rid < adjusted_interval {
            self.log_event(&phase, "[SKIP] Слишком частая рассылка от RID");
            return false;
        }

        // Валидация
        if !self.validate(&phase) {
            self.log_event(&phase, "[DROP] Неверная фаза, confidence или RID");
            return false;
        }

        // Проверка через resonance_analyzer (заглушка)
        if !self.validate_with_analyzer(&phase) {
            self.log_event(&phase, "[DROP] Analyzer отклонил фазу");
            return false;
        }

        match phase.destination.as_str() {
            "file" => self.write_to_file(&phase),
            "stdout" => println!("[PHASE] {} @ {:.2}Hz φ={:.3} conf={:.2} (RID: {})", 
                phase.symbol, phase.frequency, phase.phase, phase.confidence, phase.rid),
            "sound" => self.emit_sound(&phase),
            "radio" => self.emit_radio(&phase),
            "ble" => self.emit_ble(&phase),
            _ => self.log_event(&phase, "[WARN] Неизвестный канал"),
        }

        self.last_broadcast.insert(phase.destination.clone(), now);
        self.last_broadcast_rid.insert(phase.rid.clone(), now);
        self.save_state();
        self.log_event(&phase, "[BROADCAST] Фаза отправлена");
        true
    }

    fn validate_with_analyzer(&self, phase: &BroadcastPhase) -> bool {
        // Заглушка для проверки через resonance_analyzer.py
        phase.symbol == self.lambda_zero || (phase.frequency - 7.83).abs() < 0.1
    }

    fn write_to_file(&self, phase: &BroadcastPhase) {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("broadcast_phase_output.txt")
        {
            let _ = writeln!(file, "[PHASE] {} @ {:.2}Hz φ={:.3} conf={:.2} RID={} [{}]", 
                phase.symbol, phase.frequency, phase.phase, phase.confidence, phase.rid, phase.timestamp);
        }
    }

    fn emit_sound(&self, phase: &BroadcastPhase) {
        self.log_event(phase, "[SOUND] Эмиссия (не реализовано)");
    }

    fn emit_radio(&self, phase: &BroadcastPhase) {
        self.log_event(phase, "[RADIO] Эмиссия (не реализовано)");
    }

    fn emit_ble(&self, phase: &BroadcastPhase) {
        self.log_event(phase, "[BLE] Эмиссия (не реализовано)");
    }

    fn save_state(&self) {
        let state = serde_json::to_string(&self.last_broadcast).unwrap_or_default();
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut buf = state.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut buf).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.state_file)
            {
                let _ = file.write_all(&buf);
            }
        }
    }

    fn log_event(&self, phase: &BroadcastPhase, message: &str) {
        let entry = format!(
            "{{\"event\": \"external_phase_broadcast\", \"symbol\": \"{}\", \"freq\": {:.2}, \"phase\": {:.3}, \"conf\": {:.2}, \"rid\": \"{}\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            phase.symbol, phase.frequency, phase.phase, phase.confidence, phase.rid, message, Self::current_time()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut buf = entry.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut buf).is_ok() {
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file)
            {
                let _ = f.write_all(&buf);
            }
        }
    }

    pub fn current_time() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

