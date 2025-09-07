//! Архиватор (фасад): PG при LRB_ARCHIVE_URL, иначе SQLite при LRB_ARCHIVE_PATH.

use anyhow::Result;

mod pg;
mod sqlite;

pub use pg::ArchivePg;
pub use sqlite::ArchiveSqlite;

#[derive(Clone)]
pub enum Archive {
    Pg(ArchivePg),
    Sqlite(ArchiveSqlite),
}

impl Archive {
    pub async fn new_from_env() -> Option<Self> {
        if let Ok(url) = std::env::var("LRB_ARCHIVE_URL") {
            match ArchivePg::new(&url).await {
                Ok(pg) => return Some(Archive::Pg(pg)),
                Err(e) => {
                    tracing::error!("archive pg init failed: {e}");
                    // не падаем; попробуем SQLite если указан путь
                }
            }
        }
        if let Ok(_path) = std::env::var("LRB_ARCHIVE_PATH") {
            return ArchiveSqlite::new_from_env().map(Archive::Sqlite);
        }
        None
    }

    pub async fn record_tx(&self, txid:&str, height:u64, from:&str, to:&str, amount:u64, nonce:u64, ts:Option<u64>) -> Result<()> {
        match self {
            Archive::Pg(pg)     => pg.record_tx(txid,height,from,to,amount,nonce,ts).await,
            Archive::Sqlite(sq) => sq.record_tx(txid,height,from,to,amount,nonce,ts),
        }
    }

    pub async fn history_page(&self, rid:&str, page:u32, per_page:u32) -> Result<Vec<serde_json::Value>> {
        match self {
            Archive::Pg(pg)     => pg.history_page(rid,page,per_page).await,
            Archive::Sqlite(sq) => sq.history_page(rid,page,per_page),
        }
    }

    pub async fn get_tx(&self, txid:&str) -> Result<Option<serde_json::Value>> {
        match self {
            Archive::Pg(pg)     => pg.get_tx(txid).await,
            Archive::Sqlite(sq) => sq.get_tx(txid),
        }
    }
}
