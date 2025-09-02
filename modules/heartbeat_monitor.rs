rust
// LOGOS Network Heartbeat Monitor
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::fs::{OpenOptions, File};
use std::io::{Write, Read};
use std::net::{UdpSocket, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};
use serde_json;

#[derive(Debug, Serialize, Deserialize)]
pub struct Heartbeat {
    pub rid: String,
    pub timestamp: u64,
    pub symbol: String,
    pub Σ_t: f64,
}

pub struct HeartbeatMonitor {
    pub active_nodes: HashMap<String, Heartbeat>,
    pub timeout_sec: u64,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub log_file: String,
    pub state_file: String,
    pub cipher_key: Vec<u8>,
    pub udp_port: u16,
    pub heartbeat_timestamps: HashMap<String, u64>, // RID -> last heartbeat time
}

impl HeartbeatMonitor {
    pub fn new(port: u16, timeout: u64) -> Self {
        let mut valid_symbols = HashSet::new();
        valid_symbols.insert("Λ0".to_string());
        valid_symbols.insert("☉".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("♁".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("∞".to_string());

        HeartbeatMonitor {
            active_nodes: HashMap::new(),
            timeout_sec: timeout,
            valid_symbols,
            lambda_zero: "Λ0".to_string(),
            log_file: "heartbeat_log.json".to_string(),
            state_file: "heartbeat_state.json".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
            udp_port: port,
            heartbeat_timestamps: HashMap::new(),
        }
    }

    pub fn validate_rid(&self, rid: &str) -> bool {
        !rid.is_empty() && rid.chars().any(|c| self.valid_symbols.contains(&c.to_string()))
    }

    pub fn listen(&mut self) {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", self.udp_port)).expect("Не удалось привязать сокет");
        let mut buf = [0u8; 1024];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    let raw = &buf[..len];
                    if let Some(hb) = self.parse_heartbeat(raw) {
                        self.register_heartbeat(hb, addr);
                    }
                }
                Err(e) => {
                    self.log_event(&format!("[ERR] UDP receive error: {}", e));
                }
            }
        }
    }

    pub fn parse_heartbeat(&self, raw: &[u8]) -> Option<Heartbeat> {
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut raw_buf = raw.to_vec();
        if let Ok(decrypted) = aead.open_in_place(nonce, &[], &mut raw_buf) {
            if let Ok(hb) = serde_json::from_slice::<Heartbeat>(decrypted) {
                if self.validate_heartbeat(&hb) {
                    return Some(hb);
                }
            }
        }
        self.log_event("[ERR] Ошибка парсинга или валидации heartbeat");
        None
    }

    pub fn validate_heartbeat(&self, hb: &Heartbeat) -> bool {
        // Проверка RID, символа и Σ(t)
        let valid = self.validate_rid(&hb.rid) &&
                    self.valid_symbols.contains(&hb.symbol) &&
                    hb.Σ_t.is_finite() &&
                    // Проверка Λ0
                    (hb.symbol == self.lambda_zero || (hb.Σ_t.abs() < 10.0)); // Более мягкие условия для Λ0
        if !valid {
            self.log_event(&format!("[!] Недопустимый heartbeat от RID {}: symbol={}, Σ(t)={}", 
                hb.rid, hb.symbol, hb.Σ_t));
        }
        valid
    }

    pub fn register_heartbeat(&mut self, hb: Heartbeat, addr: SocketAddr) {
        let now = Self::current_time();

        // Проверка частоты heartbeat
        let last_heartbeat = self.heartbeat_timestamps.get(&hb.rid).cloned().unwrap_or(0);
        let adjusted_timeout = if hb.symbol == self.lambda_zero {
            self.timeout_sec * 2 // Увеличенный таймаут для Λ0
        } else {
            self.timeout_sec
        };
        if now - last_heartbeat < adjusted_timeout / 10 {
            self.log_event(&format!("[!] Слишком частый heartbeat от RID {}", hb.rid));
            return;
        }
        self.heartbeat_timestamps.insert(hb.rid.clone(), now);

        // Проверка через RCP (заглушка)
        if !self.validate_with_rcp(&hb) {
            self.log_event(&format!("[!] RCP не подтвердил heartbeat от RID {}", hb.rid));
            return;
        }

        self.active_nodes.insert(hb.rid.clone(), hb.clone());
        self.save_state();
        self.log_event(&format!(
            "[HEARTBEAT] RID {} — Σ(t) = {:.4} @ {} (from {})",
            hb.rid, hb.Σ_t, hb.timestamp, addr
        ));
    }

    pub fn validate_with_rcp(&self, _hb: &Heartbeat) -> bool {
        // Заглушка для проверки через rcp_engine.rs
        true // TODO: Реализовать
    }

    pub fn purge_inactive(&mut self) {
        let now = Self::current_time();
        self.active_nodes.retain(|rid, hb| {
            let adjusted_timeout = if hb.symbol == self.lambda_zero {
                self.timeout_sec * 2
            } else {
                self.timeout_sec
            };
            if now - hb.timestamp <= adjusted_timeout {
                true
            } else {
                self.log_event(&format!("[CLEANUP] Удалён неактивный RID {}", rid));
                false
            }
        });
        self.save_state();
        self.log_event("[CLEANUP] Удалены неактивные узлы");
    }

    fn save_state(&self) {
        let state = serde_json::to_string(&self.active_nodes).unwrap_or_default();
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

    fn log_event(&self, message: &str) {
        let log_entry = format!(
            "{{\"event\": \"heartbeat\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            message,
            Self::current_time()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut in_out = log_entry.as_bytes().to_vec();
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

