use anyhow::Result;
use lrb_core::Block;
use crate::state::AppState;

/// Временная реализация: делаем вид, что реорг не требуется.
/// Когда включим полноценный fork-choice, сюда добавим сравнение sigma/weight.
pub fn apply_or_reorg_deep(_st: &AppState, _incoming: &Block, _sigma_hex: &str, _prev_hash: &str) -> Result<()> {
    Ok(())
}
