// Простейшая адаптация LGN_cost: основана на длине мемпула.
#[derive(Clone, Debug)]
pub struct DynamicBalance {
    base_cost_microunits: u64, // 1e-6 LGN
    slope_per_tx: u64,         // увеличение за каждую tx в мемпуле
}

impl DynamicBalance {
    pub fn new(base: u64, slope: u64) -> Self {
        Self {
            base_cost_microunits: base,
            slope_per_tx: slope,
        }
    }
    pub fn lgn_cost(&self, mempool_len: usize) -> u64 {
        self.base_cost_microunits + (self.slope_per_tx * mempool_len as u64)
    }
}
