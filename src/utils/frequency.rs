
// LOGOS Frequency Utils — обработка частот
// Автор: LOGOS Core Dev Team

pub fn validate_frequency(frequency: f64) -> bool {
    frequency >= 0.1 && frequency <= 10000.0
}

pub fn adjust_frequency(frequency: f64, symbol: &str) -> f64 {
    if symbol == "Λ0" {
        frequency * 1.1 // Усиление для Λ0
    } else {
        frequency
    }
}
