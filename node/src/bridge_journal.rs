//! Durable journal for rToken bridge (idempotent ops + retries) on sled.

use serde::{Serialize,Deserialize};
use sled::IVec;
use anyhow::{Result,anyhow};
use std::time::{SystemTime,UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpKind { Deposit, Redeem }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpStatus { Pending, PayoutSent, Confirmed, Redeemed, Failed }

#[derive(Serialize,Deserialize,Clone)]
pub struct JournalOp{
    pub op_id:String,
    pub kind:OpKind,
    pub rid:String,
    pub amount:u64,
    pub ext_txid:String,     // external chain txid / idempotency key
    pub status:OpStatus,
    pub created_ms:u64,
    pub updated_ms:u64,
    pub retries:u32,
    pub last_error:Option<String>,
}

fn now_ms()->u64{
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

pub struct Journal{
    ops:   sled::Tree,      // j:<op_id> -> JournalOp
    idx:   sled::Tree,      // x:<ext_txid> -> op_id (idempotency)
    retry: sled::Tree,      // r:<op_id> -> next_retry_ms
}

impl Journal{
    pub fn open(db:&sled::Db)->Result<Self>{
        Ok(Self{
            ops:   db.open_tree("bridge_journal.ops")?,
            idx:   db.open_tree("bridge_journal.idx")?,
            retry: db.open_tree("bridge_journal.retry")?,
        })
    }

    fn ser<T:Serialize>(v:&T)->Vec<u8>{ serde_json::to_vec(v).unwrap() }
    fn de<T:for<'a> Deserialize<'a>>(v:&IVec)->T{ serde_json::from_slice(v).unwrap() }

    pub fn begin(&self, kind:OpKind, rid:&str, amount:u64, ext:&str)->Result<JournalOp>{
        if let Some(opid) = self.idx.get(format!("x:{ext}"))?{
            let id = std::str::from_utf8(&opid).unwrap();
            return self.get_by_id(id);
        }
        let op_id = blake3::hash(
            format!("{kind:?}:{rid}:{amount}:{ext}:{:?}", now_ms()).as_bytes()
        ).to_hex().to_string();

        let op = JournalOp{
            op_id: op_id.clone(),
            kind, rid: rid.to_string(), amount,
            ext_txid: ext.to_string(),
            status: OpStatus::Pending,
            created_ms: now_ms(), updated_ms: now_ms(),
            retries:0, last_error:None
        };

        self.ops.insert(format!("j:{op_id}"), Self::ser(&op))?;
        self.idx.insert(format!("x:{ext}"), op_id.as_bytes())?;
        Ok(op)
    }

    pub fn set_status(&self, op_id:&str, status:OpStatus, err:Option<String>)->Result<()>{
        let key = format!("j:{op_id}");
        let Some(v)=self.ops.get(&key)? else { return Err(anyhow!("op not found")); };
        let mut op:JournalOp = Self::de(&v);
        op.status = status;
        op.updated_ms = now_ms();
        op.last_error = err;
        self.ops.insert(key, Self::ser(&op))?;
        Ok(())
    }

    pub fn schedule_retry(&self, op_id:&str, delay_ms:u64)->Result<()>{
        let when = now_ms()+delay_ms;
        self.retry.insert(format!("r:{op_id}"), when.to_be_bytes().to_vec())?;
        Ok(())
    }

    pub fn due_retries(&self, limit:usize)->Result<Vec<String>>{
        let now = now_ms();
        let mut out=Vec::new();
        for kv in self.retry.iter(){
            let (k,v) = kv?;
            if v.len()==8 {
                let when = u64::from_be_bytes(v.as_ref().try_into().unwrap());
                if when <= now {
                    let key = std::str::from_utf8(&k).unwrap().to_string(); // r:<op_id>
                    let op_id = key[2..].to_string();
                    out.push(op_id);
                    if out.len()>=limit { break; }
                }
            }
        }
        Ok(out)
    }

    pub fn clear_retry(&self, op_id:&str)->Result<()>{
        self.retry.remove(format!("r:{op_id}"))?;
        Ok(())
    }

    pub fn get_by_id(&self, op_id:&str)->Result<JournalOp>{
        let Some(v)=self.ops.get(format!("j:{op_id}"))? else { return Err(anyhow!("op not found")); };
        Ok(Self::de(&v))
    }

    pub fn get_by_ext(&self, ext:&str)->Result<Option<JournalOp>>{
        if let Some(opid)=self.idx.get(format!("x:{ext}"))?{
            let id = std::str::from_utf8(&opid).unwrap();
            return Ok(Some(self.get_by_id(id)?));
        }
        Ok(None)
    }

    pub fn stats(&self)->Result<(u64,u64,u64)>{
        let (mut pending, mut confirmed, mut redeemed) = (0u64,0u64,0u64);
        for kv in self.ops.iter(){
            let (_k,v)=kv?;
            let op:JournalOp = Self::de(&v);
            match op.status{
                OpStatus::Pending      => pending   += 1,
                OpStatus::PayoutSent   => pending   += 1, // считаем как pending
                OpStatus::Confirmed    => confirmed += 1,
                OpStatus::Redeemed     => redeemed  += 1,
                OpStatus::Failed       => {}
            }
        }
        Ok((pending, confirmed, redeemed))
    }
}
