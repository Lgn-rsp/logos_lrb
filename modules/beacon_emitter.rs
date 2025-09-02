// LOGOS Beacon Emitter — Λ0 Signal Broadcaster
// Автор: LOGOS Core Dev

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use serde_json;
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};

#[derive(Debug, Serialize, Deserialize)]
pub struct BeaconSignal {
    pub symbol: String,
    pub frequency: f64,
    pub phase: f64,
    pub timestamp: u64,
    pub channel: String, // "file", "radio", "json", "stdout", "lora", "ble", "satellite"
}

pub struct BeaconEmitter {
    pub default_symbol: String,
    pub default_freq: f64,
    pub default_phase: f64,
    pub channels: Vec<String>,
    pub log_file: String,
    pub last_emit_time: u64,
    pub min_interval_sec: u64,
    pub valid_symbols: HashSet<String>,
    pub cipher_key: Vec<u8>, // Ключ для AES-256
}

impl BeaconEmitter {
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

        BeaconEmitter {
            default_symbol: "Λ0".to_string(),
            default_freq: 7.83,
            default_phase: 0.0,
            channels: vec!["file".to_string(), "stdout".to_string(), "lora".to_string(), "ble".to_string(), "satellite".to_string()],
            log_file: "beacon_emitter_log.json".to_string(),
            last_emit_time: 0,
            min_interval_sec: 60,
            valid_symbols,
            cipher_key: vec![0u8; 32], // Заглушка, в продакшене безопасный ключ
        }
    }

    pub fn validate_parameters(&self, symbol: &str, frequency: f64, phase: f64) -> bool {
        // Проверка символа, частоты и фазы
        self.valid_symbols.contains(symbol) &&
        (0.1 <= frequency && frequency <= 10000.0) &&
        (-std::f64::consts::PI..=std::f64::consts::PI).contains(&phase)
    }

    pub fn emit(&mut self) -> bool {
        let now = Self::current_time();
        if now - self.last_emit_time < self.min_interval_sec {
            self.log_event("[SKIP] Beacon too frequent");
            return false;
        }

        // Проверка параметров
        if !self.validate_parameters(&self.default_symbol, self.default_freq, self.default_phase) {
            self.log_event(&format!(
                "[!] Недопустимые параметры: symbol={}, freq={}, phase={}",
                self.default_symbol, self.default_freq, self.default_phase
            ));
            return false;
        }

        // Проверка через RCP (заглушка)
        if !self.validate_with_rcp() {
            self.log_event("[!] RCP не подтвердил сигнал");
            return false;
        }

        for ch in &self.channels {
            let signal = BeaconSignal {
                symbol: self.default_symbol.clone(),
                frequency: self.default_freq,
                phase: self.default_phase,
                timestamp: now,
                channel: ch.clone(),
            };

            match ch.as_str() {
                "file" => self.write_to_file(&signal),
                "stdout" => println!("[BEACON] {} @ {}Hz φ = {:.4}", signal.symbol, signal.frequency, signal.phase),
                "json" => self.export_to_json(&signal),
                "lora" => self.emit_to_lora(&signal), // Заглушка для LoRa
                "ble" => self.emit_to_ble(&signal),   // Заглушка для BLE
                "satellite" => self.emit_to_satellite(&signal), // Заглушка для satellite
                _ => self.log_event(&format!("[WARN] Unsupported channel: {}", ch)),
            }
        }

        self.last_emit_time = now;
        self.log_event(&format!(
            "[BEACON] Emitted: {} @ {}Hz φ={:.4} on channels: {:?}", 
            self.default_symbol, self.default_freq, self.default_phase, self.channels
        ));
        true
    }

    fn validate_with_rcp(&self) -> bool {
        // Заглушка для проверки через rcp_engine.rs
        self.default_symbol == "Λ0" && (self.default_freq - 7.83).abs() < 0.1
    }

    fn write_to_file(&self, signal: &BeaconSignal) {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("beacon_emitter_out.txt")
        {
            let _ = writeln!(
                file,
                "[BEACON] {} @ {}Hz φ={:.4} [{}]",
                signal.symbol, signal.frequency, signal.phase, signal.timestamp
            );
        }
    }

    fn export_to_json(&self, signal: &BeaconSignal) {
        let json = serde_json::to_string_pretty(signal).unwrap_or_default();
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut in_out = json.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut in_out).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open("beacon_emitter_out.json")
            {
                let _ = file.write_all(&in_out);
            }
        }
    }

    fn emit_to_lora(&self, signal: &BeaconSignal) {
        // Заглушка для LoRa
        self.log_event(&format!("[LORA] Emit: {} @ {}Hz φ={:.4} (not implemented)", 
            signal.symbol, signal.frequency, signal.phase));
    }

    fn emit_to_ble(&self, signal: &BeaconSignal) {
        // Заглушка для BLE
        self.log_event(&format!("[BLE] Emit: {} @ {}Hz φ={:.4} (not implemented)", 
            signal.symbol, signal.frequency, signal.phase));
    }

    fn emit_to_satellite(&self, signal: &BeaconSignal) {
        // Заглушка для satellite
        self.log_event(&format!("[SATELLITE] Emit: {} @ {}Hz φ={:.4} (not implemented)", 
            signal.symbol, signal.frequency, signal.phase));
    }

    fn log_event(&self, msg: &str) {
        let entry = format!(
            "{{\"event\": \"beacon_emitter\", \"message\": \"{}\", \"timestamp\": {}}}\n",
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
