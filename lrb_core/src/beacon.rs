use crate::types::Rid;
use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tokio::time::interval;

#[derive(Serialize)]
struct BeatPayload<'a> {
    rid: &'a str,
    ts_ms: u128,
}

pub async fn run_beacon(rid: Rid, peers: Vec<String>, period: Duration) -> Result<()> {
    if peers.is_empty() {
        // Нечего слать — просто спим, чтобы не грузить CPU
        let mut t = interval(period);
        loop {
            t.tick().await;
        }
    }
    let client = Client::new();
    let mut t = interval(period);
    loop {
        t.tick().await;
        let payload = BeatPayload {
            rid: rid.as_str(),
            ts_ms: crate::heartbeat::now_ms(),
        };
        let body = serde_json::to_vec(&payload)?;
        for p in &peers {
            // POST {peer}/beat
            let url = format!("{}/beat", p.trim_end_matches('/'));
            let req = client
                .post(&url)
                .header("content-type", "application/json")
                .body(body.clone())
                .build()?;
            if let Err(e) = client.execute(req).await {
                // Не падаем — идём к следующему
                let _ = e;
            }
        }
    }
}

/// Парсинг переменной окружения вида: "http://ip1:8080,http://ip2:8080"
pub fn parse_peers(env_val: &str) -> Result<Vec<String>> {
    let peers: Vec<String> = env_val
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if peers
        .iter()
        .any(|p| !(p.starts_with("http://") || p.starts_with("https://")))
    {
        return Err(anyhow!("peer must start with http(s)://"));
    }
    Ok(peers)
}
