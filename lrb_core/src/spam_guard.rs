use anyhow::{anyhow, Result};

#[derive(Clone, Debug)]
pub struct SpamGuard {
    max_mempool: usize,
    max_tx_per_block: usize,
    max_amount: u64,
}

impl SpamGuard {
    pub fn new(max_mempool: usize, max_tx_per_block: usize, max_amount: u64) -> Self {
        Self {
            max_mempool,
            max_tx_per_block,
            max_amount,
        }
    }
    pub fn check_mempool(&self, cur_len: usize) -> Result<()> {
        if cur_len > self.max_mempool {
            return Err(anyhow!("mempool overflow"));
        }
        Ok(())
    }
    pub fn check_amount(&self, amount: u64) -> Result<()> {
        if amount == 0 || amount > self.max_amount {
            return Err(anyhow!("amount out of bounds"));
        }
        Ok(())
    }
    pub fn max_block_txs(&self) -> usize {
        self.max_tx_per_block
    }
}
