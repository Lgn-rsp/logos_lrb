use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;
use sled::Db;

use lrb_core::ledger::Ledger;

use crate::archive::Archive;

/// Глобальное состояние ноды.
///
/// db        — открытая sled-база;
/// ledger    — обёртка над db с балансами/tx;
/// archive   — опциональный Postgres-архив.
pub struct AppState {
    pub sled_db: Db,
    pub ledger: Arc<Mutex<Ledger>>,
    pub archive: Option<Archive>,
}

impl AppState {
    /// Открытие sled + Ledger.
    ///
    /// Путь берём из LRB_DATA_PATH или по умолчанию
    /// `/var/lib/logos/data.sled`.
    pub fn new() -> Result<Self> {
        let path = env::var("LRB_DATA_PATH")
            .unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());

        let db = sled::open(&path)?;
        let ledger = Ledger::from_db(db.clone());

        Ok(AppState {
            sled_db: db,
            ledger: Arc::new(Mutex::new(ledger)),
            archive: None,
        })
    }

    /// Доступ к sled для health/bridge_journal.
    pub fn sled(&self) -> &Db {
        &self.sled_db
    }
}

/// Адрес бинда HTTP-сервера.
/// LRB_BIND="0.0.0.0:8080" или дефолт 0.0.0.0:8080.
pub fn bind_addr() -> Result<SocketAddr> {
    let bind = env::var("LRB_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    Ok(bind.parse()?)
}
