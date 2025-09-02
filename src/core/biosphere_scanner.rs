// LOGOS Biosphere Scanner
// Автор: LOGOS Core Dev

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json;

pub struct BiosphereScanner {
    pub sensor_data: VecDeque<f64>,
    pub max_samples: usize,
    pub threshold: f64,
    pub scan_interval_sec: u64,
    pub log_file: String,
    pub state_file: String,
    pub last_scan_time: u64,
    pub network_activity: f64, // Уровень активности сети
    pub lambda_zero: String,   // Центральный символ
    pub cipher_key: String,    // Ключ шифрования (заглушка для AES)
}

impl BiosphereScanner {
    pub fn new(max_samples: usize, threshold: f64, scan_interval_sec: u64) -> Self {
        BiosphereScanner {
            sensor_data: VecDeque::with_capacity(max_samples),
            max_samples,
            threshold,
            scan_interval_sec,
            log_file: "biosphere_log.json".to_string(),
            state_file: "biosphere_state.json".to_string(),
            last_scan_time: 0,
            network_activity: 1.0,
            lambda_zero: "Λ0".to_string(),
            cipher_key: "generate_at_runtime".to_string(), // Заглушка для AES
        }
    }

    pub fn update_network_activity(&mut self, activity: f64) {
        // Динамическая корректировка порога
        self.network_activity = activity.clamp(0.1, 10.0);
        self.threshold = self.threshold * (1.0 / self.network_activity).clamp(0.5, 2.0);
        self.log_event(&format!(
            "Network activity updated: Activity={:.2}, Threshold={:.4}",
            self.network_activity, self.threshold
        ));
    }

    pub fn scan(&mut self, sample: f64, symbol: &str) -> bool {
        let now = Self::current_time();

        // Проверка интервала сканирования
        if now - self.last_scan_time < self.scan_interval_sec {
            self.log_event(&format!("[!] Слишком частое сканирование: Time={}", now));
            return false;
        }
        self.last_scan_time = now;

        // Валидация данных
        if !self.validate_sample(sample) {
            self.log_event(&format!("[!] Недопустимое значение: Sample={:.4}", sample));
            return false;
        }

        // Проверка связи с Λ0
        let adjusted_threshold = if symbol == self.lambda_zero {
            self.threshold * 1.5 // Увеличенный порог для Λ0
        } else {
            self.threshold
        };

        if self.sensor_data.len() >= self.max_samples {
            self.sensor_data.pop_front();
        }
        self.sensor_data.push_back(sample);
        self.save_state();

        let avg = self.compute_average();
        let delta = (sample - avg).abs();

        if delta > adjusted_threshold {
            self.log_event(&format!(
                "[!] Аномалия в биосфере: Δ = {:.4}, Sample = {:.4}, Avg = {:.4}, Symbol = {}",
                delta, sample, avg, symbol
            ));
            return false;
        } else {
            self.log_event(&format!(
                "[SCAN] Sample = {:.4}, Avg = {:.4}, Δ = {:.4}, Symbol = {}",
                sample, avg, delta, symbol
            ));
            return true;
        }
    }

    fn validate_sample(&self, sample: f64) -> bool {
        // Проверка диапазона (например, для Шумана и других биосферных частот)
        0.0 <= sample && sample <= 1000.0
    }

    fn compute_average(&self) -> f64 {
        if self.sensor_data.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.sensor_data.iter().sum();
        sum / self.sensor_data.len() as f64
    }

    fn save_state(&self) {
        // Сохранение состояния в файл
        let state = serde_json::json!({
            "sensor_data": self.sensor_data.iter().collect::<Vec<_>>(),
            "last_scan_time": self.last_scan_time
        });
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.state_file)
        {
            let _ = file.write_all(state.to_string().as_bytes());
        }
    }

    fn log_event(&self, message: &str) {
        // Логирование с заглушкой для шифрования
        let entry = format!(
            "{{\"event\": \"biosphere_scan\", \"message\": \"{}\", \"timestamp\": {}}}\n",
            message,
            Self::current_time()
        );
        // TODO: Реализовать шифрование логов с cipher_key
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
        {
            let _ = file.write_all(entry.as_bytes());
        }
    }

    pub fn current_time() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
fn main() {
    println!("biosphere_scanner запущен");
}
