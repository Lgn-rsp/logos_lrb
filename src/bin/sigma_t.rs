
// LOGOS Sigma T — вычисление резонансной суммы Σ(t)
// Автор: LOGOS Core Dev Team

use std::f64::consts::PI;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde_json;

pub struct SigmaT {
    pub frequencies: Vec<f64>,
    pub amplitudes: Vec<f64>,
    pub lambda_zero: String,
    pub network_activity: f64,
    pub log_file: String,
    pub cipher_key: Vec<u8>,
}

impl SigmaT {
    pub fn new() -> Self {
        SigmaT {
            frequencies: vec![7.83, 1.618, 432.0, 864.0, 3456.0], // Шуман, золотое сечение, гармоники
            amplitudes: vec![1.0, 0.8, 0.5, 0.3, 0.1], // Базовые амплитуды
            lambda_zero: "Λ0".to_string(),
            network_activity: 1.0,
            log_file: "sigma_t_log.enc".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
        }
    }

    pub fn validate_frequencies(&self) -> bool {
        self.frequencies.iter().all(|&f| (0.1..=10000.0).contains(&f))
    }

    pub fn update_network_activity(&mut self, activity: f64) {
        self.network_activity = activity.clamp(0.1, 10.0);
        for (i, amp) in self.amplitudes.iter_mut().enumerate() {
            *amp = (*amp * (1.0 / self.network_activity)).clamp(0.05, 2.0);
            if i == 0 && self.frequencies[i] == 7.83 { // Усиление для Λ0
                *amp *= 1.2;
            }
        }
        self.log_event(&format!("[INFO] Network activity updated: {:.2}, amplitudes: {:?}", self.network_activity, self.amplitudes));
    }

    pub fn calculate_sigma(&self, t: f64) -> Vec<f64> {
        if !self.validate_frequencies() {
            self.log_event("[ERROR] Недопустимые частоты");
            return vec![0.0; self.frequencies.len()];
        }

        let sigma: Vec<f64> = self.frequencies.iter().enumerate().map(|(i, &f)| {
            let amp = self.amplitudes[i];
            let s = amp * (2.0 * PI * f * t).sin();
            if i == 0 && f == 7.83 { // Усиление для Λ0
                s * 1.2
            } else {
                s
            }
        }).collect();

        self.log_event(&format!("[SIGMA] t={} → Σ(t)={:?}", t, sigma));
        sigma
    }

    fn log_event(&self, msg: &str) {
        let entry = format!(
            "{{\"event\": \"sigma_t\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            msg,
            Self::now()
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let key = LessSafeKey::new(key); // Исправлено для ring 0.17.x
        let mut buf = entry.as_bytes().to_vec();
        if key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).is_ok() { // Исправлено для ring 0.17.x
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

fn main() {
    let sigma_t = SigmaT::new();
    for t in 0..5 {
        let sigma = sigma_t.calculate_sigma(t as f64);
        println!("t = {} → Σ(t) = {:?}", t, sigma);
    }
}

