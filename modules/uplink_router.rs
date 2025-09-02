rust
// LOGOS Uplink Router — External Signal Receiver
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::fs::{OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use serde_json;
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};

#[derive(Debug, Serialize, Deserialize)]
pub struct UplinkSignal {
    pub rid: String, // Добавлено для идентификации узла
    pub channel: String,
    pub symbol: String,
    pub frequency: f64,
    pub phase: f64,
    pub payload: String,
    pub timestamp: u64,
}

pub struct UplinkRouter {
    pub valid_channels: HashSet<String>,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub log_file: String,
    pub state_file: String,
    pub cipher_key: Vec<u8>,
    pub last_received: HashMap<String, u64>, // channel -> timestamp
    pub last_received_rid: HashMap<String, u64>, // rid -> timestamp
    pub min_receive_interval: u64,
}

impl UplinkRouter {
    pub fn new() -> Self {
        let mut channels = HashSet::new();
        channels.insert("lora".to_string());
        channels.insert("ble".to_string());
        channels.insert("sound".to_string());
        channels.insert("satellite".to_string());
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

        UplinkRouter {
            valid_channels: channels,
            valid_symbols: symbols,
            lambda_zero: "Λ0".to_string(),
            log_file: "uplink_router_log.json".to_string(),
            state_file: "uplink_router_state.json".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
            last_received: HashMap::new(),
            last_received_rid: HashMap::new(),
            min_receive_interval: 10,
        }
    }

    pub fn validate_rid(&self, rid: &str) -> bool {
        !rid.is_empty() && rid.chars().any(|c| self.valid_symbols.contains(&c.to_string()))
    }

    pub fn validate_payload(&self, payload: &str) -> bool {
        !payload.is_empty() && payload.len() <= 1024 && payload.chars().all(|c| c.is_ascii() || self.valid_symbols.contains(&c.to_string()))
    }

    pub fn receive(&mut self, signal: UplinkSignal) -> bool {
        let now = Self::current_time();

        // Проверка частоты приёма по каналу
        let last_channel = self.last_received.get(&signal.channel).cloned().unwrap_or(0);
        let adjusted_interval = if signal.symbol == self.lambda_zero {
            self.min_receive_interval / 2 // Меньший интервал для Λ0
        } else {
            self.min_receive_interval
        };
        if now - last_channel < adjusted_interval {
            self.log_event(&signal, "[DROP] Слишком частый приём по каналу");
            return false;
        }

        // Проверка частоты приёма по RID
        let last_rid = self.last_received_rid.get(&signal.rid).cloned().unwrap_or(0);
        if now - last_rid < adjusted_interval {
            self.log_event(&signal, "[DROP] Слишком частый приём от RID");
            return false;
        }

        // Валидация RID
        if !self.validate_rid(&signal.rid) {
            self.log_event(&signal, "[DROP] Недопустимый RID");
            return false;
        }

        // Валидация символа и канала
        if !self.valid_symbols.contains(&signal.symbol) {
            self.log_event(&signal, "[DROP] Недопустимый символ");
            return false;
        }
        if !self.valid_channels.contains(&signal.channel) {
            self.log_event(&signal, "[DROP] Недопустимый канал");
            return false;
        }

        // Проверка частоты/фазы
        if signal.frequency <= 0.0 || signal.frequency > 10000.0 || !(-std::f64::consts::PI..=std::f64::consts::PI).contains(&signal.phase) {
            self.log_event(&signal, "[DROP] Неверная частота или фаза");
            return false;
        }

        // Проверка payload
        if !self.validate_payload(&signal.payload) {
            self.log_event(&signal, "[DROP] Недопустимый payload");
            return false;
        }

        // Проверка через RCP и resonance_analyzer (заглушка)
        if !self.validate_with_rcp_and_analyzer(&signal) {
            self.log_event(&signal, "[DROP] RCP или analyzer отклонил сигнал");
            return false;
        }

        self.last_received.insert(signal.channel.clone(), now);
        self.last_received_rid.insert(signal.rid.clone(), now);
        self.save_state();
        self.log_event(&signal, "[OK] Сигнал принят");
        true
    }

    pub fn validate_with_rcp_and_analyzer(&self, signal: &UplinkSignal) -> bool {
        // Заглушка для проверки через rcp_engine.rs и resonance_analyzer.py
        signal.symbol == self.lambda_zero || (signal.frequency - 7.83).abs() < 0.1
    }

    fn save_state(&self) {
        let state = serde_json::to_string(&self.last_received).unwrap_or_default();
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

    fn log_event(&self, signal: &UplinkSignal, msg: &str) {
        let entry = format!(
            "{{\"event\":\"uplink_router\",\"message\":\"{}\",\"rid\":\"{}\",\"channel\":\"{}\",\"symbol\":\"{}\",\"frequency\":{},\"phase\":{},\"timestamp\":{}}}\n",
            msg, signal.rid, signal.channel, signal.symbol, signal.frequency, signal.phase, Self::current_time()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut buf = entry.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut buf).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file)
            {
                let _ = file.write_all(&buf);
            }
        }
    }

    pub fn current_time() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

