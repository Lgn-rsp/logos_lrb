
// LOGOS AI Signal Listener — приём внешних импульсов
// Автор: LOGOS Core Dev Team

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use serde::{Serialize, Deserialize};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SystemRandom, SecureRandom};
use serde_json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingSignal {
    pub source: String,
    pub symbol: String,
    pub intensity: f64,
    pub frequency: f64,
    pub timestamp: u64,
}

pub struct AISignalListener {
    pub accepted_symbols: HashSet<String>,
    pub last_received: Arc<Mutex<HashMap<String, u64>>>,
    pub log_file: String,
    pub state_file: String,
    pub cipher_key: Vec<u8>,
    pub nonce_source: SystemRandom,
    pub min_interval: u64,
    pub lambda_zero: String,
}

impl AISignalListener {
    pub fn new() -> Self {
        let mut key = vec![0u8; 32];
        let rng = SystemRandom::new();
        rng.fill(&mut key).unwrap();

        let mut accepted = HashSet::new();
        accepted.insert("Λ0".to_string());
        accepted.insert("☉".to_string());
        accepted.insert("??".to_string());
        accepted.insert("♁".to_string());
        accepted.insert("??".to_string());
        accepted.insert("??".to_string());
        accepted.insert("??".to_string());
        accepted.insert("∞".to_string());

        AISignalListener {
            accepted_symbols: accepted,
            last_received: Arc::new(Mutex::new(HashMap::new())),
            log_file: "ai_signal_log.enc".to_string(),
            state_file: "ai_signal_state.enc".to_string(),
            cipher_key: key,
            nonce_source: rng,
            min_interval: 1, // 1 секунда
            lambda_zero: "Λ0".to_string(),
        }
    }

    pub fn validate_signal(&self, signal: &IncomingSignal) -> bool {
        !signal.source.is_empty() &&
        self.accepted_symbols.contains(&signal.symbol) &&
        (0.0..=1.0).contains(&signal.intensity) &&
        (0.1..=10000.0).contains(&signal.frequency) &&
        signal.timestamp > 0
    }

    pub fn handle(&self, signal: IncomingSignal) -> bool {
        let now = Self::now();

        // Проверка частоты приёма
        let mut last = self.last_received.lock().unwrap();
        let last_time = last.get(&signal.source).cloned().unwrap_or(0);
        let adjusted_interval = if signal.symbol == self.lambda_zero {
            self.min_interval / 2 // Меньший интервал для Λ0
        } else {
            self.min_interval
        };
        if now - last_time < adjusted_interval {
            self.log(&format!("[DROP] Слишком частый сигнал от {}", signal.source));
            return false;
        }

        // Валидация сигнала
        if !self.validate_signal(&signal) {
            self.log(&format!("[DROP] Неверный сигнал от {}: symbol={}, intensity={:.2}, freq={:.2}",
                signal.source, signal.symbol, signal.intensity, signal.frequency));
            return false;
        }

        // Проверка через resonance_analyzer (заглушка)
        if !self.validate_with_analyzer(&signal) {
            self.log(&format!("[DROP] Analyzer отклонил сигнал от {}", signal.source));
            return false;
        }

        last.insert(signal.source.clone(), now);
        self.save_state();
        self.log_signal(&signal);
        true
    }

    fn validate_with_analyzer(&self, signal: &IncomingSignal) -> bool {
        // Заглушка для resonance_analyzer.py
        signal.symbol == self.lambda_zero || (signal.frequency - 7.83).abs() < 0.1
    }

    fn log_signal(&self, signal: &IncomingSignal) {
        let json = serde_json::to_string(signal).unwrap_or_default();
        let mut nonce_bytes = [0u8; 12];
        self.nonce_source.fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let mut data = json.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data).unwrap();
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.log_file) {
            let _ = file.write_all(&data);
        }
    }

    fn log(&self, msg: &str) {
        let entry = format!(
            "{{\"event\": \"ai_signal_listener\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            msg,
            Self::now()
        );
        let mut nonce_bytes = [0u8; 12];
        self.nonce_source.fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let mut data = entry.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data).unwrap();
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.log_file) {
            let _ = file.write_all(&data);
        }
    }

    fn save_state(&self) {
        let state = serde_json::to_string(&*self.last_received.lock().unwrap()).unwrap_or_default();
        let mut nonce_bytes = [0u8; 12];
        self.nonce_source.fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let mut data = state.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data).unwrap();
        if let Ok(mut file) = OpenOptions::new().create(true).write(true).truncate(true).open(&self.state_file) {
            let _ = file.write_all(&data);
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

fn main() {
    println!("[AI_SIGNAL] Запуск на 0.0.0.0:38500");
    let listener = TcpListener::bind("0.0.0.0:38500").expect("Не удалось открыть порт");
    listener.set_nonblocking(true).unwrap();
    let handler = Arc::new(AISignalListener::new());
    let shared = Arc::clone(&handler);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = [0u8; 512];
                match stream.read(&mut buf) {
                    Ok(size) => {
                        let input = match std::str::from_utf8(&buf[..size]) {
                            Ok(s) => s,
                            Err(e) => {
                                shared.log(&format!("[ERR] Неверный UTF-8: {}", e));
                                let _ = stream.write_all(b"INVALID");
                                continue;
                            }
                        };
                        let parts: Vec<&str> = input.trim().split(',').collect();
                        if parts.len() == 4 {
                            let source = parts[0].to_string();
                            let symbol = parts[1].to_string();
                            let intensity = parts[2].parse::<f64>().unwrap_or(0.0);
                            let frequency = parts[3].parse::<f64>().unwrap_or(0.0);
                            let signal = IncomingSignal {
                                source,
                                symbol,
                                intensity,
                                frequency,
                                timestamp: AISignalListener::now(),
                            };
                            let accepted = shared.handle(signal);
                            let _ = stream.write_all(if accepted { b"OK" } else { b"REJECT" });
                        } else {
                            shared.log("[ERR] Неверный формат запроса");
                            let _ = stream.write_all(b"INVALID");
                        }
                    }
                    Err(e) => {
                        shared.log(&format!("[ERR] Ошибка чтения: {}", e));
                        let _ = stream.write_all(b"ERROR");
                    }
                }
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

