//! Postgres archive backend with simple batch insert & backpressure

use deadpool_postgres::{Manager, Pool};
use tokio_postgres::{NoTls, Row, Config};
use serde::Serialize;
use anyhow::Result;
use crate::metrics;

#[derive(Clone)]
pub struct Archive { pub(crate) pool: Pool }

impl Archive {
    pub async fn new_from_env() -> Option<Self> {
        let url = std::env::var("LRB_ARCHIVE_URL").ok()?;
        let cfg: Config = url.parse().ok()?;
        let mgr = Manager::new(cfg, NoTls);
        let pool = Pool::builder(mgr).max_size(16).build().ok()?;
        Some(Archive { pool })
    }

    pub async fn record_tx(&self, txid:&str, height:u64, from:&str, to:&str, amount:u64, nonce:u64, ts:Option<u64>) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute(
            "insert into txs (txid,height,from_rid,to_rid,amount,nonce,ts) values ($1,$2,$3,$4,$5,$6,to_timestamp($7))",
            &[&txid, &(height as i64), &from, &to, &(amount as i64), &(nonce as i64), &(ts.unwrap_or(0) as i64)]
        ).await?;
        Ok(())
    }

    /// Batch-ingest (owned строки → без проблем с лайфтаймами)
    pub async fn record_txs_batch(
        &self,
        rows:&[(String,u64,String,String,u64,u64,Option<u64>)]
    ) -> Result<()> {
        use std::time::Duration;
        let client = self.pool.get().await?;
        let depth = rows.len() as i64;
        metrics::set_archive_queue(depth);

        let stmt = "insert into txs (txid,height,from_rid,to_rid,amount,nonce,ts) \
                    values ($1,$2,$3,$4,$5,$6,to_timestamp($7)) on conflict do nothing";

        for chunk in rows.chunks(500) {
            for r in chunk {
                client.execute(
                    stmt,
                    &[&r.0, &(r.1 as i64), &r.2, &r.3, &(r.4 as i64), &(r.5 as i64), &(r.6.unwrap_or(0) as i64)]
                ).await?;
            }
            if chunk.len()==500 { tokio::time::sleep(Duration::from_millis(2)).await; }
        }
        metrics::set_archive_queue(0);
        Ok(())
    }

    pub async fn history_by_rid(&self, rid:&str, limit:i64, before:Option<i64>) -> Result<Vec<TxRecord>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
             from txs where (from_rid=$1 or to_rid=$1) and ($2::bigint is null or height<$2) \
             order by height desc limit $3",
            &[&rid, &before, &limit]
        ).await?;
        Ok(rows.into_iter().map(TxRecord::from_row).collect())
    }

    pub async fn tx_by_id(&self, txid:&str) -> Result<Option<serde_json::Value>> {
        let client = self.pool.get().await?;
        let row = client.query_opt(
            "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
             from txs where txid=$1", &[&txid]
        ).await?;
        Ok(row.map(|r| serde_json::json!(TxRecord::from_row(r))))
    }

    pub async fn recent_blocks(&self, limit:i64, before:Option<i64>) -> Result<Vec<BlockRow>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "select height,hash,extract(epoch from ts)::bigint as ts,tx_count \
             from blocks where ($1::bigint is null or height<$1) order by height desc limit $2",
            &[&before, &limit]
        ).await?;
        Ok(rows.into_iter().map(BlockRow::from_row).collect())
    }

    pub async fn recent_txs(&self, limit:i64, rid:Option<&str>, before_ts:Option<i64>) -> Result<Vec<TxRecord>> {
        let client = self.pool.get().await?;
        let rows = if let Some(rid)=rid {
            client.query(
                "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
                 from txs where (from_rid=$1 or to_rid=$1) and ($2::bigint is null or extract(epoch from ts)<$2) \
                 order by ts desc limit $3",
                &[&rid, &before_ts, &limit]
            ).await?
        } else {
            client.query(
                "select txid,height,from_rid,to_rid,amount,nonce,extract(epoch from ts)::bigint as ts \
                 from txs where ($1::bigint is null or extract(epoch from ts)<$1) order by ts desc limit $2",
                &[&before_ts, &limit]
            ).await?
        };
        Ok(rows.into_iter().map(TxRecord::from_row).collect())
    }

    // нужен для /archive_block (и может использоваться API)
    pub async fn block_by_height(&self, h:i64) -> Result<Option<BlockRow>> {
        let client = self.pool.get().await?;
        let row = client.query_opt(
            "select height,hash,extract(epoch from ts)::bigint as ts,tx_count from blocks where height=$1",
            &[&h]
        ).await?;
        Ok(row.map(BlockRow::from_row))
    }
}

#[derive(Serialize)]
pub struct BlockRow { pub height:i64, pub hash:String, pub ts:i64, pub tx_count:i64 }
impl BlockRow { fn from_row(r:Row)->Self { Self{ height:r.get(0), hash:r.get(1), ts:r.get(2), tx_count:r.get(3) } } }

#[derive(Serialize)]
pub struct TxRecord { pub txid:String, pub height:i64, pub from:String, pub to:String, pub amount:i64, pub nonce:i64, pub ts:Option<i64> }
impl TxRecord { fn from_row(r:Row)->Self { Self{
    txid:r.get(0), height:r.get(1), from:r.get(2), to:r.get(3), amount:r.get(4), nonce:r.get(5), ts:r.get(6)
}}}
