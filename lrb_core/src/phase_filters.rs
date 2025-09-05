use crate::types::Block;

/// Простые фазовые фильтры на основе гармоник Λ0.
/// ENV (всё опционально):
///  LRB_PHASE_EN=1|0                     (вкл/выкл, по умолчанию 1)
///  LRB_PHASE_FREQS_HZ="7.83,1.618,432"  (частоты, через запятую)
///  LRB_PHASE_MIN_SCORE=-0.20            (порог принятия от -1.0 до 1.0)
///
/// Идея: время блока b.timestamp_ms в секундах подаётся в сумму косинусов.
/// score = avg_i cos(2π f_i * t)
/// Пропускаем, если score >= MIN_SCORE.
fn phase_enabled() -> bool {
    std::env::var("LRB_PHASE_EN")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(true)
}
fn parse_freqs() -> Vec<f64> {
    let def = "7.83,1.618,432";
    let raw = std::env::var("LRB_PHASE_FREQS_HZ").unwrap_or_else(|_| def.to_string());
    raw.split(',')
        .filter_map(|s| s.trim().parse::<f64>().ok())
        .collect::<Vec<_>>()
}
fn min_score() -> f64 {
    std::env::var("LRB_PHASE_MIN_SCORE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(-0.20)
}

fn phase_score_ts_ms(ts_ms: u128) -> f64 {
    let t = ts_ms as f64 / 1000.0;
    let freqs = parse_freqs();
    if freqs.is_empty() {
        return 1.0;
    }
    let two_pi = std::f64::consts::TAU; // 2π
    let mut acc = 0.0;
    for f in &freqs {
        acc += (two_pi * *f * t).cos();
    }
    acc / (freqs.len() as f64)
}

/// Главный фильтр на блок: пропускает, если фазовый скор >= порога
pub fn block_passes_phase(b: &Block) -> bool {
    if !phase_enabled() {
        return true;
    }
    phase_score_ts_ms(b.timestamp_ms) >= min_score()
}
