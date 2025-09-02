rust
// LOGOS Orchestration Control — центральный контрольный контур LOGOS
// Автор: LOGOS Core Dev Team

use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::process::{Command, Stdio};
use std::fs::OpenOptions;
use std::io::Write;
use serde_json;
use ring::aead::{Aead, Nonce, UnboundKey, AES_256_GCM};
use crate::sigma_t::calculate_sigma;

pub struct OrchestrationControl {
    pub module_status: HashMap<String, bool>,
    pub valid_modules: HashSet<String>,
    pub log_file: String,
    pub state_file: String,
    pub cipher_key: Vec<u8>,
    pub restart_threshold: f64,
    pub lambda_zero: String,
    pub restart_timestamps: HashMap<String, u64>, // module -> last restart time
    pub min_restart_interval: u64,
}

impl OrchestrationControl {
    pub fn new() -> Self {
        let mut valid_modules = HashSet::new();
        valid_modules.insert("rcp_engine".to_string());
        valid_modules.insert("resonance_mesh".to_string());
        valid_modules.insert("resonance_sync".to_string());
        valid_modules.insert("ai_signal_listener".to_string());
        valid_modules.insert("uplink_controller".to_string());
        valid_modules.insert("uplink_router".to_string());

        OrchestrationControl {
            module_status: HashMap::new(),
            valid_modules,
            log_file: "orchestration_log.json".to_string(),
            state_file: "orchestration_state.json".to_string(),
            cipher_key: vec![0u8; 32], // Продакшн-ключ заменить
            restart_threshold: 0.7,
            lambda_zero: "Λ0".to_string(),
            restart_timestamps: HashMap::new(),
            min_restart_interval: 60, // 1 минута
        }
    }

    pub fn monitor(&mut self) {
        let modules = vec![
            "rcp_engine",
            "resonance_mesh",
            "resonance_sync",
            "ai_signal_listener",
            "uplink_controller",
            "uplink_router",
        ];

        for m in &modules {
            if self.valid_modules.contains(*m) {
                self.module_status.insert(m.to_string(), true);
            }
        }

        loop {
            for (module, status) in self.module_status.clone() {
                if !self.valid_modules.contains(&module) {
                    self.log_event(&format!("[ERROR] Недопустимый модуль: {}", module));
                    continue;
                }

                if !self.health_check(&module) {
                    self.module_status.insert(module.clone(), false);
                    self.restart_module(&module);
                } else {
                    self.module_status.insert(module.clone(), true);
                }
            }

            let t = Self::now() as f64;
            let sigma = calculate_sigma(t);
            if Self::is_resonance_unstable(&sigma, self.restart_threshold) {
                self.log_event(&format!("[ALERT] Нестабильность Σ(t): {:?}", sigma));
                // Проверка через resonance_analyzer (заглушка)
                if !self.validate_with_analyzer(&sigma) {
                    self.log_event("[ALERT] Analyzer отклонил Σ(t), требуется вмешательство");
                }
            }

            self.save_state();
            thread::sleep(Duration::from_secs(10));
        }
    }

    fn validate_with_analyzer(&self, sigma: &Vec<f64>) -> bool {
        // Заглушка для resonance_analyzer.py
        sigma.iter().all(|&f| f.abs() <= 1.0)
    }

    fn health_check(&self, module: &str) -> bool {
        let output = Command::new("pgrep")
            .arg(module)
            .stdout(Stdio::null())
            .status();

        let is_alive = output.map(|s| s.success()).unwrap_or(false);
        if !is_alive {
            self.log_event(&format!("[FAIL] {} не отвечает", module));
        }
        is_alive
    }

    fn restart_module(&self, module: &str) -> bool {
        let now = Self::now();
        let last_restart = self.restart_timestamps.get(module).cloned().unwrap_or(0);
        let adjusted_interval = if module == "rcp_engine" { // Приоритет для Λ0-ассоциированного модуля
            self.min_restart_interval / 2
        } else {
            self.min_restart_interval
        };

        if now - last_restart < adjusted_interval {
            self.log_event(&format!("[SKIP] Слишком частый перезапуск {}", module));
            return false;
        }

        let restart_cmd = format!("./restart_{}.sh", module);
        let status = Command::new("sh")
            .arg("-c")
            .arg(&restart_cmd)
            .spawn();

        if status.is_ok() {
            let mutable_self = unsafe { &mut *(self as *const Self as *mut Self) };
            mutable_self.restart_timestamps.insert(module.to_string(), now);
            self.log_event(&format!("[RESTART] Перезапуск {}", module));
            true
        } else {
            self.log_event(&format!("[ERROR] Ошибка перезапуска {}", module));
            false
        }
    }

    fn save_state(&self) {
        let state = serde_json::to_string(&self.module_status).unwrap_or_default();
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

    fn log_event(&self, msg: &str) {
        let timestamp = Self::now();
        let entry = format!(
            "{{\"event\":\"orchestration\",\"timestamp\":{},\"msg\":\"{}\"}}",
            timestamp, msg
        );
        let nonce = Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
        let key = UnboundKey::new(&AES_256_GCM, &self.cipher_key).unwrap();
        let mut aead = key.bind::<AES_256_GCM>();
        let mut buf = entry.as_bytes().to_vec();
        if aead.seal_in_place_append_tag(nonce, &[], &buf).is_ok() {
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file)
            {
                let _ = f.write_all(&buf);
            }
        }
    }

    fn is_resonance_unstable(sigma: &Vec<f64>, threshold: f64) -> bool {
        sigma.iter().any(|&f| f.abs() > threshold)
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

