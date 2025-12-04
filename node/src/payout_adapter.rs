//! External payout adapter for rToken redeem (HTTP).
//! ENV:
//!   BRIDGE_PAYOUT_URL   — базовый URL payout-сервиса (https://bridge.example.com)
//!   BRIDGE_PAYOUT_PATH  — относительный путь (по умолчанию: /api/payout)
//!   LRB_BRIDGE_KEY      — общий секрет (заголовок X-Bridge-Key)

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::Serialize;

#[derive(Clone)]
pub struct PayoutAdapter {
    base: String,
    path: String,
    key:  String,
    http: Client,
}

#[derive(Serialize)]
struct PayoutReq<'a> {
    rid:     &'a str,
    amount:  u64,
    ext_txid: &'a str,
}

impl PayoutAdapter {
    /// Инициализация из ENV. Если переменных нет — валимся с понятной ошибкой.
    pub fn from_env() -> Result<Self> {
        let base = std::env::var("BRIDGE_PAYOUT_URL")
            .map_err(|_| anyhow!("BRIDGE_PAYOUT_URL not set"))?;
        let path = std::env::var("BRIDGE_PAYOUT_PATH")
            .unwrap_or_else(|_| "/api/payout".to_string());
        let key  = std::env::var("LRB_BRIDGE_KEY")
            .map_err(|_| anyhow!("LRB_BRIDGE_KEY not set"))?;

        Ok(Self {
            base,
            path,
            key,
            http: Client::new(),
        })
    }

    #[inline]
    fn url(&self) -> String {
        format!("{}{}", self.base.trim_end_matches('/'), self.path)
    }

    /// Отправка HTTP‑запроса на выплату.
    pub async fn send_payout(&self, rid: &str, amount: u64, ext_txid: &str) -> Result<()> {
        let body = PayoutReq { rid, amount, ext_txid };

        let resp = self.http
            .post(self.url())
            .header("X-Bridge-Key", &self.key)
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let text   = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(anyhow!("payout_http_{}: {}", status.as_u16(), text));
        }

        Ok(())
    }
}
