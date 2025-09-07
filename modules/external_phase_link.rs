//! Безопасная версия external_phase_link без unsafe-кастов.
//! Состояние защищено через RwLock. Однопоточная производительность сохраняется.

use std::sync::{Arc, RwLock};
use anyhow::Result;

#[derive(Default, Clone, Debug)]
pub struct PhaseState {
    pub last_tick_ms: u64,
    pub phase_strength: f32,
}

#[derive(Clone)]
pub struct ExternalPhaseLink {
    state: Arc<RwLock<PhaseState>>,
}

impl ExternalPhaseLink {
    pub fn new() -> Self {
        Self { state: Arc::new(RwLock::new(PhaseState::default())) }
    }

    pub fn tick(&self, now_ms: u64, input_strength: f32) -> Result<()> {
        let mut st = self.state.write().expect("rwlock poisoned");
        st.last_tick_ms = now_ms;
        st.phase_strength = 0.9 * st.phase_strength + 0.1 * input_strength;
        Ok(())
    }

    pub fn snapshot(&self) -> PhaseState {
        self.state.read().expect("rwlock poisoned").clone()
    }
}
