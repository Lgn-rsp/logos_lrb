// (весь файл целиком — актуальная версия с прошлой правки + set_nonce)
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sled::{Db, IVec, Tree};
use std::path::Path;

const META_HEIGHT: &[u8] = b"height";
const META_SUPPLY_MINTED: &[u8] = b"supply_minted";
const META_SUPPLY_BURNED: &[u8] = b"supply_burned";
const META_LAST_HASH: &[u8] = b"last_block_hash";

#[derive(Clone)]
pub struct Ledger {
    db: Db,
    t_meta: Tree,
    t_bal: Tree,
    t_nonce: Tree,
    t_tx: Tree,
    t_txidx: Tree,
    t_acctx: Tree,
    t_bmeta: Tree,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTx {
    pub txid: String, pub height: u64, pub from: String, pub to: String,
    pub amount: u64, pub nonce: u64, pub memo: Option<String>, pub ts: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRec {
    pub txid: String, pub height: u64, pub from: String, pub to: String,
    pub amount: u64, pub nonce: u64, pub ts: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMeta { pub height: u64, pub block_hash: String }

impl Ledger {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)?;
        let t_meta  = db.open_tree("meta")?;
        let t_bal   = db.open_tree("bal")?;
        let t_nonce = db.open_tree("nonce")?;
        let t_tx    = db.open_tree("tx")?;
        let t_txidx = db.open_tree("txidx")?;
        let t_acctx = db.open_tree("acctx")?;
        let t_bmeta = db.open_tree("bmeta")?;
        if t_meta.get(META_HEIGHT)?.is_none()         { let z=0u64.to_be_bytes(); t_meta.insert(META_HEIGHT,&z)?; }
        if t_meta.get(META_SUPPLY_MINTED)?.is_none()  { let z=0u64.to_be_bytes(); t_meta.insert(META_SUPPLY_MINTED,&z)?; }
        if t_meta.get(META_SUPPLY_BURNED)?.is_none()  { let z=0u64.to_be_bytes(); t_meta.insert(META_SUPPLY_BURNED,&z)?; }
        if t_meta.get(META_LAST_HASH)?.is_none()      { t_meta.insert(META_LAST_HASH, b"")?; }
        Ok(Self{ db,t_meta,t_bal,t_nonce,t_tx,t_txidx,t_acctx,t_bmeta })
    }

    #[inline] fn be_u64(v:u64)->[u8;8]{ v.to_be_bytes() }
    #[inline] fn be_u128(v:u128)->[u8;16]{ v.to_be_bytes() }
    #[inline] fn from_be_u64(iv:&IVec)->u64{ let mut b=[0u8;8]; b.copy_from_slice(iv.as_ref()); u64::from_be_bytes(b) }
    #[inline] fn from_be_u128(iv:&IVec)->u128{ let mut b=[0u8;16]; b.copy_from_slice(iv.as_ref()); u128::from_be_bytes(b) }

    // meta/head
    pub fn height(&self)->Result<u64>{ Ok(Self::from_be_u64(&self.t_meta.get(META_HEIGHT)?.ok_or_else(||anyhow!("no height"))?)) }
    fn set_height(&self,h:u64)->Result<()> { let be=Self::be_u64(h); self.t_meta.insert(META_HEIGHT,&be)?; Ok(()) }
    fn last_block_hash(&self)->Result<String>{ Ok(self.t_meta.get(META_LAST_HASH)?.map(|v|String::from_utf8_lossy(v.as_ref()).to_string()).unwrap_or_default()) }
    fn set_last_block_hash(&self,s:&str)->Result<()> { self.t_meta.insert(META_LAST_HASH,s.as_bytes())?; Ok(()) }
    pub fn head(&self)->Result<(u64,String)>{ Ok((self.height().unwrap_or(0), self.last_block_hash().unwrap_or_default())) }

    // supply
    pub fn supply(&self)->Result<(u64,u64)>{
        let m=self.t_meta.get(META_SUPPLY_MINTED)?.map(|v|Self::from_be_u64(&v)).unwrap_or(0);
        let b=self.t_meta.get(META_SUPPLY_BURNED)?.map(|v|Self::from_be_u64(&v)).unwrap_or(0);
        Ok((m,b))
    }
    pub fn add_minted(&self,v:u64)->Result<u64>{ let (m,b)=self.supply()?; let nm=m.saturating_add(v); let be=Self::be_u64(nm); self.t_meta.insert(META_SUPPLY_MINTED,&be)?; Ok(nm-b) }
    pub fn add_burned(&self,v:u64)->Result<u64>{ let (m,b)=self.supply()?; let nb=b.saturating_add(v); let be=Self::be_u64(nb); self.t_meta.insert(META_SUPPLY_BURNED,&be)?; Ok(m-nb) }

    // balances / nonce
    pub fn get_balance(&self,rid:&str)->Result<u128>{ Ok(self.t_bal.get(rid.as_bytes())?.map(|v|Self::from_be_u128(&v)).unwrap_or(0)) }
    pub fn set_balance(&self,rid:&str,amount:u128)->Result<()> { let be=Self::be_u128(amount); self.t_bal.insert(rid.as_bytes(),&be)?; Ok(()) }
    pub fn get_nonce(&self,rid:&str)->Result<u64>{ Ok(self.t_nonce.get(rid.as_bytes())?.map(|v|Self::from_be_u64(&v)).unwrap_or(0)) }
    pub fn bump_nonce(&self,rid:&str)->Result<u64>{ let n=self.get_nonce(rid)?; let nn=n.saturating_add(1); let be=Self::be_u64(nn); self.t_nonce.insert(rid.as_bytes(),&be)?; Ok(nn) }
    pub fn set_nonce(&self,rid:&str,value:u64)->Result<()> { let be=Self::be_u64(value); self.t_nonce.insert(rid.as_bytes(),&be)?; Ok(()) }

    // history
    pub fn get_tx_height(&self,txid:&str)->Result<Option<u64>>{ Ok(self.t_txidx.get(txid.as_bytes())?.map(|v|Self::from_be_u64(&v))) }
    pub fn account_txs_page(&self,rid:&str,page:u32,per_page:u32)->Result<Vec<TxRec>>{
        let per=per_page.clamp(1,1000);
        let mut start=Vec::with_capacity(rid.len()+1+8);
        start.extend_from_slice(rid.as_bytes()); start.push(b'|');
        let h=self.height().unwrap_or(0);
        let start_h=h.saturating_sub(page as u64 * per as u64);
        start.extend_from_slice(&start_h.to_be_bytes());
        let mut out=Vec::with_capacity(per as usize);
        for item in self.t_acctx.range(start..){ let (_k,v)=item?; let rec:TxRec=bincode::deserialize(v.as_ref())?; out.push(rec); if out.len()>=per as usize{break;} }
        Ok(out)
    }

    // submit_tx SIMPLE
    pub fn submit_tx_simple(&self, from:&str,to:&str,amount:u64,nonce:u64,memo:Option<String>)->Result<StoredTx>{
        let fb=self.get_balance(from)?; if fb < amount as u128 { return Err(anyhow!("insufficient funds")); }
        let n=self.get_nonce(from)?; if nonce != n.saturating_add(1) { return Err(anyhow!("bad nonce")); }
        self.set_balance(from, fb - amount as u128)?; let tb=self.get_balance(to)?; self.set_balance(to, tb.saturating_add(amount as u128))?;
        self.bump_nonce(from)?;
        let h=self.height().unwrap_or(0).saturating_add(1); self.set_height(h)?;
        use sha2::{Digest,Sha256};
        let mut hasher=Sha256::new(); hasher.update(from.as_bytes()); hasher.update(to.as_bytes());
        hasher.update(&amount.to_be_bytes()); hasher.update(&nonce.to_be_bytes()); hasher.update(&h.to_be_bytes());
        let txid=hex::encode(hasher.finalize());
        let mut h2=Sha256::new(); h2.update(&h.to_be_bytes()); h2.update(txid.as_bytes()); let block_hash=hex::encode(h2.finalize());
        self.set_last_block_hash(&block_hash)?;
        let stx=StoredTx{txid:txid.clone(),height:h,from:from.into(),to:to.into(),amount,nonce,memo,ts:Some(Self::unix_ts())};
        self.t_tx.insert(txid.as_bytes(), serde_json::to_vec(&stx)?)?;
        let bhe=Self::be_u64(h); self.t_txidx.insert(txid.as_bytes(), &bhe)?;
        let rec=TxRec{txid:stx.txid.clone(),height:stx.height,from:stx.from.clone(),to:stx.to.clone(),amount:stx.amount,nonce:stx.nonce,ts:stx.ts};
        let mut kf=Vec::with_capacity(from.len()+1+8); kf.extend_from_slice(from.as_bytes()); kf.push(b'|'); kf.extend_from_slice(&h.to_be_bytes());
        self.t_acctx.insert(kf, bincode::serialize(&rec)?)?;
        let mut kt=Vec::with_capacity(to.len()+1+8); kt.extend_from_slice(to.as_bytes()); kt.push(b'|'); kt.extend_from_slice(&h.to_be_bytes());
        self.t_acctx.insert(kt, bincode::serialize(&rec)?)?;
        let meta=BlockMeta{height:h,block_hash:block_hash.clone()};
        self.t_bmeta.insert(h.to_be_bytes(), bincode::serialize(&meta)?)?;
        Ok(stx)
    }

    // совместимость rcp_engine
    pub fn get_block_by_height(&self,h:u64)->Result<BlockMeta>{
        match self.t_bmeta.get(h.to_be_bytes())?{ Some(v)=>Ok(bincode::deserialize::<BlockMeta>(v.as_ref())?), None=>Ok(BlockMeta{height:h,block_hash:String::new()}) }
    }
    pub fn commit_block_atomic<T>(&self,_b:&T)->Result<()> { Ok(()) }
    pub fn index_block<T>(&self,h:u64,hash:&str,_ts:u128,_txs:&T)->Result<()>{
        self.set_last_block_hash(hash)?; let meta=BlockMeta{height:h,block_hash:hash.to_string()};
        self.t_bmeta.insert(h.to_be_bytes(), bincode::serialize(&meta)?)?; Ok(())
    }
    pub fn set_finalized(&self,_h:u64)->Result<()> { Ok(()) }

    #[inline] fn unix_ts()->u64{ use std::time::{SystemTime,UNIX_EPOCH}; SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
}
