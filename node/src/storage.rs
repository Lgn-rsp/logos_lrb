use serde::{Deserialize, Serialize};

/// Вход транзакции — соответствуем полям, которые ожидает api.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIn {
    pub from: String,      // RID отправителя
    pub to: String,        // RID получателя
    pub amount: u64,       // количество
    pub nonce: u64,        // обязательный
    pub memo: Option<String>,
    pub sig_hex: String,   // подпись в hex
}

/// Элемент истории для /history/:rid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    pub txid: String,
    pub height: u64,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub nonce: u64,
    pub ts: Option<u64>,
}

/// Состояние аккаунта (минимум, который использует api.rs)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
}
