rust
// LOGOS Uplink Controller — External Uplink & Relay Orchestrator
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::fs::{OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};

#[derive(Debug, Serialize, Deserialize)]
pub struct UplinkEvent {
    pub symbol: String,
    pub channel: String, // "lora", "ble", "satellite", "sound", "qr"
    pub status: String,  // "emitted", "received", "failed"
    pub payload: String,
    pub timestamp: u64,
}

pub struct UplinkController {
    pub supported_channels: HashSet<String>,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub cipher_key: Vec<u8>,
    pub log_file: String,
    pub emit_timestamps: HashMap<String, u64>, // channel -> last emit time
    pub min_emit_interval: u64, // Минимальный интервал в секундах
}

impl UplinkController {
    pub fn new() -> Self {
        let mut channels = HashSet::new();
        channels.insert("lora".to_string());
        channels.insert("ble".to_string());
        channels.insert("satellite".to_string());
        channels.insert("sound".to_string());
        channels.insert("qr".to_string());

        let mut symbols = HashSet::new();
        symbols.insert("Λ0".to_string());
        symbols.insert("☉".to_string());
        symbols.insert("??".to_string());
        symbols.insert("♁".to_string());
        symbols.insert("??".to_string());
        symbols.insert("??".to_string());
        symbols.insert("??".to_string());
        symbols.insert("∞".to_string());

        UplinkController {
            supported_channels: channels,
            valid_symbols: symbols,
            lambda_zero: "Λ0".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
            log_file: "uplink_log.json".to_string(),
            emit_timestamps: HashMap::new(),
            min_emit_interval: 60, // 1 минута
        }
    }

    pub fn validate_symbol(&self, symbol: &str) -> bool {
        self.valid_symbols.contains(symbol)
    }

    pub fn validate_channel(&self, channel: &str) -> bool {
        self.supported_channels.contains(channel)
    }

    pub fn validate_payload(&self, payload: &str) -> bool {
        // Проверка размера и формата payload
        !payload.is_empty() && payload.len() <= 1024 && payload.chars().all(|c| c.is_ascii() || self.valid_symbols.contains(&c.to_string()))
    }

    pub fn emit(&self, symbol: &str, channel: &str, payload: &str) -> bool {
        let now = Self::current_time();

        // Проверка частоты эмиссии
        let last_emit = self.emit_timestamps.get(channel).cloned().unwrap_or(0);
        let adjusted_interval = if symbol == self.lambda_zero {
            self.min_emit_interval / 2 // Меньший интервал для Λ0
        } else {
            self.min_emit_interval
        };
        if now - last_emit < adjusted_interval {
            self.log_event(UplinkEvent {
                symbol: symbol.to_string(),
                channel: channel.to_string(),
                status: "failed".to_string(),
                payload: payload.to_string(),
                timestamp: now,
            }, "Слишком частая эмиссия");
            return false;
        }

        // Валидация
        if !self.validate_symbol(symbol) {
            self.log_event(UplinkEvent {
                symbol: symbol.to_string(),
                channel: channel.to_string(),
                status: "failed".to_string(),
                payload: payload.to_string(),
                timestamp: now,
            }, "Недопустимый символ");
            return false;
        }

        if !self.validate_channel(channel) {
            self.log_event(UplinkEvent {
                symbol: symbol.to_string(),
                channel: channel.to_string(),
                status: "failed".to_string(),
                payload: payload.to_string(),
                timestamp: now,
            }, "Недопустимый канал");
            return false;
        }

        if !self.validate_payload(payload) {
            self.log_event(UplinkEvent {
                symbol: symbol.to_string(),
                channel: channel.to_string(),
                status: "failed".to_string(),
                payload: payload.to_string(),
                timestamp: now,
            }, "Недопустимый payload");
            return false;
        }

        // Реализация каналов
        let event = UplinkEvent {
            symbol: symbol.to_string(),
            channel: channel.to_string(),
            status: "emitted".to_string(),
            payload: payload.to_string(),
            timestamp: now,
        };

        match channel {
            "lora" => self.emit_to_lora(&event),
            "ble" => self.emit_to_ble(&event),
            "satellite" => self.emit_to_satellite(&event),
            "sound" => self.emit_to_sound(&event),
            "qr" => self.emit_to_qr(&event),
            _ => {
                self.log_event(event.clone(), &format!("[WARN] Unsupported channel: {}", channel));
                return false;
            }
        }

        // Обновление времени эмиссии
        let mutable_self = unsafe { &mut *(self as *const Self as *mut Self) };
        mutable_self.emit_timestamps.insert(channel.to_string(), now);
        self.log_event(event, "Успешная эмиссия");
        true
    }

    fn emit_to_lora(&self, event: &UplinkEvent) {
        // Заглушка для LoRa
        self.log_event(event.clone(), "[LORA] Эмиссия (не реализовано)");
    }

    fn emit_to_ble(&self, event: &UplinkEvent) {
        // Заглушка для BLE
        self.log_event(event.clone(), "[BLE] Эмиссия (не реализовано)");
    }

    fn emit_to_satellite(&self, event: &UplinkEvent) {
        // Заглушка для satellite
        self.log_event(event.clone(), "[SATELLITE] Эмиссия (не реализовано)");
    }

    fn emit_to_sound(&self, event: &UplinkEvent) {
        // Заглушка для sound
        self.log_event(event.clone(), "[SOUND] Эмиссия (не реализовано)");
    }

    fn emit_to_qr(&self, event: &UplinkEvent) {
        // Заглушка для QR
        self.log_event(event.clone(), "[QR] Эмиссия (не реализовано)");
    }

    fn log_event(&self, event: UplinkEvent, message: &str) {
        let json = serde_json::to_string(&event).unwrap_or_default();
        let log_entry = format!(
            "{{\"event\": \"uplink_controller\", \"message\": \"{}\", \"data\": {}, \"timestamp\": {}}}\n",
            message, json, Self::current_time()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut buffer = log_entry.as_bytes().to_vec();

        if aead.seal_in_place_append_tag(nonce, &[], &mut buffer).is_ok() {
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file)
            {
                let _ = f.write_all(&buffer);
            }
        }
    }

    pub fn current_time() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

