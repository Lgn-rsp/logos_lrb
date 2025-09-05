#![allow(dead_code)]
//! Fork-choice: минимальный детерминированный выбор на базе высоты/хэша.
//! Совместим с текущими типами ядра (Block из lrb_core::types).

use lrb_core::types::Block;

/// Выбор лучшей ветви из набора кандидатов.
/// Правила:
/// 1) Бóльшая высота предпочтительнее.
/// 2) При равной высоте — лексикографически наименьший block_hash.
pub fn choose_best<'a>(candidates: &'a [Block]) -> Option<&'a Block> {
    candidates
        .iter()
        .max_by(|a, b| match a.height.cmp(&b.height) {
            core::cmp::Ordering::Equal => a.block_hash.cmp(&b.block_hash).reverse(),
            ord => ord,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mk(h: u64, hash: &str) -> Block {
        Block {
            height: h,
            block_hash: hash.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn pick_by_height_then_hash() {
        let a = mk(10, "ff");
        let b = mk(12, "aa");
        let c = mk(12, "bb");
        let out = choose_best(&[a, b.clone(), c]).unwrap();
        assert_eq!(out.height, 12);
        assert_eq!(out.block_hash, "aa");
    }
}
