// LOGOS Resonance Consensus Protocol (RCP)
// Автор: LOGOS Core Dev

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct PhaseSignal {
    pub sender: String,
    pub frequency: f64,
    pub phase: f64,
    pub symbol: String,
    pub timestamp: u64,
}

pub struct RcpEngine {
    pub known_nodes: HashSet<String>,
    pub phase_buffer: Vec<PhaseSignal>,
    pub phase_tolerance: f64,
    pub symbol_set: HashSet<String>,
    pub sender_rate: HashMap<String, u32>,
    pub lambda_zero: String,
}

impl RcpEngine {
    pub fn new() -> Self {
        let mut symbol_set = HashSet::new();
        // Добавляем допустимые символы
        symbol_set.insert("☉".to_string());
        symbol_set.insert("??".to_string());
        symbol_set.insert("♁".to_string());
        symbol_set.insert("☿".to_string());
        symbol_set.insert("Λ0".to_string());

        RcpEngine {
            known_nodes: HashSet::new(),
            phase_buffer: Vec::new(),
            phase_tolerance: 0.03,
            symbol_set,
            sender_rate: HashMap::new(),
            lambda_zero: "Λ0".to_string(),
        }
    }

    pub fn register_node(&mut self, rid: String) {
        self.known_nodes.insert(rid.clone());
        self.sender_rate.insert(rid, 0);
    }

    pub fn submit_phase(&mut self, signal: PhaseSignal) -> bool {
        // Проверка существования узла
        if !self.known_nodes.contains(&signal.sender) {
            return false;
        }

        // Проверка валидности символа
        if !self.validate_symbol(&signal.symbol) {
            return false;
        }

        // Проверка соответствия Λ0
        if !self.check_lambda_zero(&signal) {
            return false;
        }

        // Защита от спама: не более 10 сигналов в секунду от одного RID
        let rate = self.sender_rate.entry(signal.sender.clone()).or_insert(0);
        *rate += 1;
        if *rate > 10 {
            return false;
        }

        // Проверка фазы
        let consensus_phase = self.compute_consensus_phase(signal.frequency);
        if (signal.phase - consensus_phase).abs() < self.phase_tolerance {
            self.phase_buffer.push(signal);
            self.log_phase(&self.phase_buffer.last().unwrap());
            true
        } else {
            false
        }
    }

    fn validate_symbol(&self, symbol: &str) -> bool {
        self.symbol_set.contains(symbol)
    }

    fn check_lambda_zero(&self, signal: &PhaseSignal) -> bool {
        // Проверяем, что символ или частота связаны с Λ0
        signal.symbol == self.lambda_zero || (signal.frequency - 7.83).abs() < 0.001
    }

    fn compute_consensus_phase(&self, frequency: f64) -> f64 {
        let filtered: Vec<&PhaseSignal> = self.phase_buffer.iter()
            .filter(|s| (s.frequency - frequency).abs() < 0.001)
            .collect();

        if filtered.is_empty() {
            return 0.0;
        }

        let sum_phase: f64 = filtered.iter().map(|s| s.phase).sum();
        sum_phase / (filtered.len() as f64)
    }

    pub fn clear_old_signals(&mut self) {
        let now = Self::time_now();
        self.phase_buffer.retain(|s| now - s.timestamp < 10);
        // Сбрасываем счетчики спама каждые 10 секунд
        for rate in self.sender_rate.values_mut() {
            *rate = 0;
        }
    }

    fn log_phase(&self, signal: &PhaseSignal) {
        // Логирование фазы для анализа (вывод в resonance_analyzer.py)
        println!(
            "Phase logged: RID={}, Symbol={}, Freq={}, Phase={}, Time={}",
            signal.sender, signal.symbol, signal.frequency, signal.phase, signal.timestamp
        );
    }

    pub fn time_now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
fn main() {
    println!("rcp_engine запущен");
}
