rust
// LOGOS Resonance Sync — удалённая синхронизация фаз Σ(t)
// Автор: LOGOS Core Dev Team

use std::collections::{HashMap, HashSet};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Serialize, Deserialize};
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};
use std::fs::OpenOptions;
use crate::sigma_t::calculate_sigma;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemotePhasePacket {
    pub source_id: String,
    pub timestamp: u64,
    pub phase_vector: Vec<f64>,
    pub trust_score: f64,
    pub symbol: String, // Для связи с Λ0
}

pub struct ResonanceSync {
    pub listener: TcpListener,
    pub known_sources: Arc<Mutex<HashMap<String, f64>>>,
    pub local_phase: Arc<Mutex<Vec<f64>>>,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub log_file: String,
    pub cipher_key: Vec<u8>,
    pub send_timestamps: Arc<Mutex<HashMap<String, u64>>>, // source_id -> last send time
    pub min_send_interval: u64,
}

impl ResonanceSync {
    pub fn new(bind_addr: &str) -> Self {
        let listener = TcpListener::bind(bind_addr).expect("Не удалось привязать порт TCP");
        listener.set_nonblocking(true).expect("Не удалось установить неблокирующий режим");

        let mut valid_symbols = HashSet::new();
        valid_symbols.insert("Λ0".to_string());
        valid_symbols.insert("☉".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("♁".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("∞".to_string());

        ResonanceSync {
            listener,
            known_sources: Arc::new(Mutex::new(HashMap::new())),
            local_phase: Arc::new(Mutex::new(vec![0.0; 3])),
            valid_symbols,
            lambda_zero: "Λ0".to_string(),
            log_file: "resonance_sync_log.json".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
            send_timestamps: Arc::new(Mutex::new(HashMap::new())),
            min_send_interval: 1, // 1 секунда
        }
    }

    pub fn validate_source_id(&self, source_id: &str, symbol: &str) -> bool {
        !source_id.is_empty() &&
        source_id.chars().any(|c| self.valid_symbols.contains(&c.to_string())) &&
        self.valid_symbols.contains(symbol) &&
        (0.0..=1.0).contains(&self.known_sources.lock().unwrap().get(source_id).cloned().unwrap_or(0.5))
    }

    pub fn start_listening(&self) {
        let listener = self.listener.try_clone().unwrap();
        let known_sources = Arc::clone(&self.known_sources);
        let local_phase = Arc::clone(&self.local_phase);
        let valid_symbols = self.valid_symbols.clone();
        let lambda_zero = self.lambda_zero.clone();
        let log_file = self.log_file.clone();
        let cipher_key = self.cipher_key.clone();

        thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                match listener.incoming() {
                    Ok(stream) => match stream {
                        Ok(mut stream) => {
                            if let Ok(size) = stream.read(&mut buf) {
                                let data = &buf[..size];
                                let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
                                let key = UnboundKey::new(&AES_256_GCM, &cipher_key).unwrap();
                                let mut aead = key.bind::<AES_256_GCM>();
                                let mut decrypted = data.to_vec();
                                if let Ok(decrypted_data) = aead.open_in_place(nonce, &[], &mut decrypted) {
                                    if let Ok(packet) = serde_json::from_slice::<RemotePhasePacket>(decrypted_data) {
                                        let mut sources = known_sources.lock().unwrap();
                                        let trust = sources.get(&packet.source_id).cloned().unwrap_or(0.5);
                                        if trust < 0.3 || !valid_symbols.contains(&packet.symbol) {
                                            Self::log_event_static(&log_file, &cipher_key, 
                                                &format!("[DROP] Низкое доверие или неверный символ: {}, trust={:.2}", 
                                                    packet.source_id, trust));
                                            continue;
                                        }

                                        let mut phase = local_phase.lock().unwrap();
                                        let weight = if packet.symbol == lambda_zero { 1.2 } else { 1.0 }; // Приоритет Λ0
                                        for i in 0..phase.len().min(packet.phase_vector.len()) {
                                            phase[i] = (phase[i] + packet.phase_vector[i] * trust * weight) / (1.0 + trust * weight);
                                        }
                                        Self::log_event_static(&log_file, &cipher_key, 
                                            &format!("[RECEIVE] Фаза от {} (symbol: {}, trust: {:.2})", 
                                                packet.source_id, packet.symbol, trust));
                                    } else {
                                        Self::log_event_static(&log_file, &cipher_key, "[ERR] Ошибка десериализации пакета");
                                    }
                                } else {
                                    Self::log_event_static(&log_file, &cipher_key, "[ERR] Ошибка расшифровки пакета");
                                }
                            }
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(100));
                        }
                    },
                    Err(_) => {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });
    }

    pub fn send_phase(&self, addr: &str, source_id: &str, trust_score: f64, symbol: &str) -> bool {
        let now = Self::now();

        // Проверка частоты отправки
        let mut timestamps = self.send_timestamps.lock().unwrap();
        let last_send = timestamps.get(source_id).cloned().unwrap_or(0);
        let adjusted_interval = if symbol == self.lambda_zero { self.min_send_interval / 2 } else { self.min_send_interval };
        if now - last_send < adjusted_interval {
            self.log_event(&format!("[SKIP] Слишком частая отправка от {}", source_id));
            return false;
        }

        // Валидация
        if !self.validate_source_id(source_id, symbol) || !(0.0..=1.0).contains(&trust_score) {
            self.log_event(&format!("[DROP] Недопустимый source_id или символ: {}, trust={:.2}", source_id, trust_score));
            return false;
        }

        let mut stream = match TcpStream::connect(addr) {
            Ok(s) => s,
            Err(e) => {
                self.log_event(&format!("[ERR] Не удалось подключиться к {}: {}", addr, e));
                return false;
            }
        };

        let phase_vector = {
            let lp = self.local_phase.lock().unwrap();
            lp.clone()
        };

        let packet = RemotePhasePacket {
            source_id: source_id.to_string(),
            timestamp: now,
            phase_vector,
            trust_score,
            symbol: symbol.to_string(),
        };

        let encoded = serde_json::to_vec(&packet).unwrap();
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut encrypted = encoded.clone();
        if aead.seal_in_place_append_tag(nonce, &[], &mut encrypted).is_err() {
            self.log_event(&format!("[ERR] Ошибка шифрования пакета для {}", source_id));
            return false;
        }

        if stream.write_all(&encrypted).is_ok() {
            timestamps.insert(source_id.to_string(), now);
            self.log_event(&format!("[SEND] Фаза отправлена {} (symbol: {}, trust: {:.2})", source_id, symbol, trust_score));
            true
        } else {
            self.log_event(&format!("[ERR] Ошибка отправки фазы для {}", source_id));
            false
        }
    }

    pub fn update_local_phase(&self, t: f64) {
        let mut phase = self.local_phase.lock().unwrap();
        *phase = calculate_sigma(t);
        self.log_event(&format!("[UPDATE] Локальная фаза обновлена: {:?}", *phase));
    }

    pub fn set_trust(&self, source_id: &str, score: f64) {
        let mut sources = self.known_sources.lock().unwrap();
        sources.insert(source_id.to_string(), score.clamp(0.0, 1.0));
        self.log_event(&format!("[TRUST] Установлен trust_score={:.2} для {}", score, source_id));
    }

    fn log_event(&self, message: &str) {
        let entry = format!(
            "{{\"event\": \"resonance_sync\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            message,
            Self::now()
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

    fn log_event_static(log_file: &str, cipher_key: &[u8], message: &str) {
        let entry = format!(
            "{{\"event\": \"resonance_sync\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            message,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut buf = entry.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &mut buf).is_ok() {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)
            {
                let _ = file.write_all(&buf);
            }
        }
    }

    pub fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

