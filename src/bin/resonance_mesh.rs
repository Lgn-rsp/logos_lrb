rust
// LOGOS Resonance Mesh — Local Node-to-Node Resonance Sync
// Автор: LOGOS Core Dev Team

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Serialize, Deserialize};
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};
use std::fs::OpenOptions;
use std::io::Write;
use crate::sigma_t::calculate_sigma;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSignal {
    pub node_id: String,
    pub timestamp: u64,
    pub phase_vector: Vec<f64>,
    pub symbol: String, // Для Λ0 и других символов
}

pub struct ResonanceMesh {
    pub mesh_socket: UdpSocket,
    pub known_nodes: Arc<Mutex<HashSet<SocketAddr>>>,
    pub local_phase: Arc<Mutex<Vec<f64>>>,
    pub valid_symbols: HashSet<String>,
    pub lambda_zero: String,
    pub log_file: String,
    pub cipher_key: Vec<u8>,
    pub broadcast_timestamps: Arc<Mutex<HashMap<String, u64>>>, // node_id -> last broadcast
    pub min_broadcast_interval: u64,
}

impl ResonanceMesh {
    pub fn new(bind_addr: &str) -> Self {
        let socket = UdpSocket::bind(bind_addr).expect("Не удалось привязать сокет");
        socket.set_nonblocking(true).expect("Не удалось установить неблокирующий режим");

        let mut valid_symbols = HashSet::new();
        valid_symbols.insert("Λ0".to_string());
        valid_symbols.insert("☉".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("♁".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("??".to_string());
        valid_symbols.insert("∞".to_string());

        ResonanceMesh {
            mesh_socket: socket,
            known_nodes: Arc::new(Mutex::new(HashSet::new())),
            local_phase: Arc::new(Mutex::new(vec![0.0; 3])), // f₁, f₂, f₃
            valid_symbols,
            lambda_zero: "Λ0".to_string(),
            log_file: "resonance_mesh_log.json".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
            broadcast_timestamps: Arc::new(Mutex::new(HashMap::new())),
            min_broadcast_interval: 1, // 1 секунда
        }
    }

    pub fn validate_node_id(&self, node_id: &str, symbol: &str) -> bool {
        !node_id.is_empty() &&
        node_id.chars().any(|c| self.valid_symbols.contains(&c.to_string())) &&
        self.valid_symbols.contains(symbol)
    }

    pub fn broadcast_phase(&self, node_id: &str, symbol: &str) -> bool {
        let now = Self::current_time();

        // Проверка частоты вещания
        let mut timestamps = self.broadcast_timestamps.lock().unwrap();
        let last_broadcast = timestamps.get(node_id).cloned().unwrap_or(0);
        let adjusted_interval = if symbol == self.lambda_zero {
            self.min_broadcast_interval / 2 // Меньший интервал для Λ0
        } else {
            self.min_broadcast_interval
        };
        if now - last_broadcast < adjusted_interval {
            self.log_event(&format!("[SKIP] Слишком частое вещание от {}", node_id));
            return false;
        }

        // Валидация
        if !self.validate_node_id(node_id, symbol) {
            self.log_event(&format!("[DROP] Недопустимый node_id или символ: {}, {}", node_id, symbol));
            return false;
        }

        let timestamp = now;
        let phase_vector = {
            let lp = self.local_phase.lock().unwrap();
            lp.clone()
        };

        let signal = MeshSignal {
            node_id: node_id.to_string(),
            timestamp,
            phase_vector,
            symbol: symbol.to_string(),
        };

        let packet = serde_json::to_vec(&signal).unwrap();
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut encrypted_packet = packet.clone();
        if aead.seal_in_place_append_tag(nonce, &[], &mut encrypted_packet).is_err() {
            self.log_event(&format!("[ERR] Ошибка шифрования сигнала для {}", node_id));
            return false;
        }

        let nodes = self.known_nodes.lock().unwrap();
        for addr in nodes.iter() {
            let _ = self.mesh_socket.send_to(&encrypted_packet, addr);
        }

        timestamps.insert(node_id.to_string(), now);
        self.log_event(&format!("[BROADCAST] Фаза отправлена от {} (symbol: {})", node_id, symbol));
        true
    }

    pub fn listen(&self) {
        let socket = self.mesh_socket.try_clone().unwrap();
        let local_phase = Arc::clone(&self.local_phase);
        let known_nodes = Arc::clone(&self.known_nodes);

        thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((size, src)) => {
                        let data = &buf[..size];
                        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
                        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
                        let mut aead = key.bind::<AES_256_GCM>();
                        let mut decrypted_data = data.to_vec();
                        if let Ok(decrypted) = aead.open_in_place(nonce, &[], &mut decrypted_data) {
                            if let Ok(signal) = serde_json::from_slice::<MeshSignal>(decrypted) {
                                let mut nodes = known_nodes.lock().unwrap();
                                nodes.insert(src);

                                let mut phase = local_phase.lock().unwrap();
                                let weight = if signal.symbol == "Λ0" { 1.2 } else { 1.0 }; // Приоритет Λ0
                                for i in 0..phase.len().min(signal.phase_vector.len()) {
                                    phase[i] = (phase[i] + signal.phase_vector[i] * weight) / (1.0 + weight);
                                }
                            } else {
                                println!("[ERR] Ошибка десериализации сигнала");
                            }
                        } else {
                            println!("[ERR] Ошибка расшифровки сигнала");
                        }
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });
    }

    pub fn update_local_phase(&self, t: f64) {
        let mut phase = self.local_phase.lock().unwrap();
        *phase = calculate_sigma(t);
        self.log_event(&format!("[UPDATE] Локальная фаза обновлена: {:?}", *phase));
    }

    fn log_event(&self, message: &str) {
        let entry = format!(
            "{{\"event\": \"resonance_mesh\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            message,
            Self::current_time()
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

