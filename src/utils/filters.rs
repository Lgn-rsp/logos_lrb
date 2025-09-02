
// LOGOS Filters Utils — фильтрация сигналов
// Автор: LOGOS Core Dev Team

use std::collections::HashSet;

pub fn validate_symbol(symbol: &str, valid_symbols: &HashSet<String>) -> bool {
    valid_symbols.contains(symbol)
}

pub fn filter_signal(signal: f64) -> bool {
    signal.abs() <= 1.0
}
