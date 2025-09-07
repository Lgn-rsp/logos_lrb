use std::sync::Arc;
use parking_lot::Mutex;
use anyhow::Result;

pub struct AppState {
    pub ledger: Arc<Mutex<lrb_core::ledger::Ledger>>,
    pub archive: Option<crate::archive::Archive>,
}

impl AppState {
    pub fn new() -> Result<Self> {
        let path = std::env::var("LRB_DATA_PATH").unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());
        let ledger = lrb_core::ledger::Ledger::open(&path)?;
        // Archive: инициализируем позже в async, чтобы не блокировать startup
        Ok(Self { ledger: Arc::new(Mutex::new(ledger)), archive: None })
    }
}

pub fn bind_addr() -> std::net::SocketAddr {
    let s = std::env::var("LRB_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    s.parse().expect("LRB_BIND must be host:port")
}
