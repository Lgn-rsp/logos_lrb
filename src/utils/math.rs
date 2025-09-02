
// LOGOS Math Utils — вычисления резонанса
// Автор: LOGOS Core Dev Team

pub fn calculate_sigma(t: f64) -> Vec<f64> {
    let freqs = vec![7.83, 1.618, 432.0, 864.0, 3456.0];
    let amps = vec![1.0, 0.8, 0.5, 0.3, 0.1];
    freqs
        .iter()
        .zip(amps.iter())
        .map(|(&f, &a)| a * (2.0 * std::f64::consts::PI * f * t).sin())
        .collect()
}
