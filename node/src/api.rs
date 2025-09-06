use axum::{extract::{Path, Query, State}, http::StatusCode, Json};
use hex;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::metrics::{inc_total, Timer};
use crate::storage::TxIn;
use crate::AppState;

use bs58;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/* ========= liveness / readiness ========= */
#[derive(Serialize)] pub struct Healthz{ pub status: &'static str }
pub async fn healthz()->Json<Healthz>{ Json(Healthz{status:"ok"}) }
pub async fn livez()->Json<Healthz>{ Json(Healthz{status:"ok"}) }
pub async fn readyz(State(_st):State<AppState>)->Result<Json<Healthz>,StatusCode>{
    let t=Timer::new("/readyz","GET"); inc_total("/readyz","GET",StatusCode::OK); t.observe(); Ok(Json(Healthz{status:"ready"}))
}

/* ========= helpers ========= */
#[derive(Serialize,Deserialize,Clone)]
struct CanonTx<'a>{ from:&'a str,to:&'a str,amount:u64,nonce:u64 }
fn canon_bytes(tx:&TxIn)->Result<Vec<u8>,StatusCode>{
    let c=CanonTx{from:&tx.from,to:&tx.to,amount:tx.amount,nonce:tx.nonce};
    serde_json::to_vec(&c).map_err(|_|StatusCode::BAD_REQUEST)
}
fn vk_from_rid(rid:&str)->Result<VerifyingKey,StatusCode>{
    let b=bs58::decode(rid).into_vec().map_err(|_|StatusCode::BAD_REQUEST)?; if b.len()!=32 {return Err(StatusCode::BAD_REQUEST);}
    VerifyingKey::from_bytes(b.as_slice().try_into().unwrap()).map_err(|_|StatusCode::BAD_REQUEST)
}
fn sig_from_hex(h:&str)->Result<Signature,StatusCode>{
    let raw=hex::decode(h).map_err(|_|StatusCode::BAD_REQUEST)?; let arr:[u8;64]=raw.as_slice().try_into().map_err(|_|StatusCode::BAD_REQUEST)?;
    Ok(Signature::from_bytes(&arr))
}

/* ========= head / balance ========= */
#[derive(Serialize)] pub struct HeadResp{ pub height:u64, pub finalized:bool }
pub async fn head(State(st):State<AppState>)->Json<HeadResp>{
    let t=Timer::new("/head","GET"); let h=st.store.get_height().unwrap_or(0); inc_total("/head","GET",StatusCode::OK); t.observe();
    Json(HeadResp{height:h,finalized:false})
}
#[derive(Serialize)] pub struct BalanceResp{ pub rid:String, pub balance:u64, pub nonce:u64 }
pub async fn balance(State(st):State<AppState>,Path(rid):Path<String>)->Json<BalanceResp>{
    let t=Timer::new("/balance/:rid","GET"); let a=st.store.get_account(&rid).unwrap_or_default(); inc_total("/balance/:rid","GET",StatusCode::OK); t.observe();
    Json(BalanceResp{rid, balance:a.balance, nonce:a.nonce})
}

/* ========= history / block ========= */
#[derive(Deserialize)] pub struct HistoryQuery{ #[serde(default)] pub from:u64, #[serde(default="def_limit")] pub limit:usize }
fn def_limit()->usize{20}
#[derive(Serialize)] pub struct HistoryResp{ pub rid:String, pub from:u64, pub limit:usize, pub next_from:Option<u64>, pub items:Vec<crate::storage::HistoryItem> }
pub async fn history(State(st):State<AppState>, Path(rid):Path<String>, Query(q):Query<HistoryQuery>)->Result<Json<HistoryResp>,StatusCode>{
    let t=Timer::new("/history/:rid","GET");
    let (items,next_from)=st.store.history_page(&rid,q.from,q.limit.min(1000)).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?;
    inc_total("/history/:rid","GET",StatusCode::OK); t.observe();
    Ok(Json(HistoryResp{rid,from:q.from,limit:q.limit,next_from,items}))
}
#[derive(Serialize)] pub struct BlockResp{ pub height:u64,pub ts_ms:u64,pub txs:Vec<TxIn> }
pub async fn block(State(st):State<AppState>,Path(h):Path<u64>)->Result<Json<BlockResp>,StatusCode>{
    let t=Timer::new("/block/:height","GET"); let br=st.store.get_block(h).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?; let br=br.ok_or(StatusCode::NOT_FOUND)?;
    inc_total("/block/:height","GET",StatusCode::OK); t.observe(); Ok(Json(BlockResp{height:br.height, ts_ms:br.ts_ms, txs:br.txs}))
}

/* ========= block mix (PhaseMix v1) ========= */
#[derive(Serialize)] pub struct MixResp{ pub height:u64, pub ts_ms:u64, pub deltas:Vec<(String,i128)> }
pub async fn block_mix(State(st):State<AppState>,Path(h):Path<u64>)->Result<Json<MixResp>,StatusCode>{
    let t=Timer::new("/block/:height/mix","GET");
    let m = st.store.get_mix(h).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?;
    let m = m.ok_or(StatusCode::NOT_FOUND)?;
    inc_total("/block/:height/mix","GET",StatusCode::OK); t.observe();
    Ok(Json(MixResp{height:m.height, ts_ms:m.ts_ms, deltas:m.deltas}))
}

/* ========= submit_tx / batch ========= */
#[derive(Deserialize)] pub struct SubmitTxBatchReq{ #[serde(default)] pub txs:Vec<TxIn> }
#[derive(Serialize)]   pub struct TxResult{ pub idx:usize, pub status:&'static str, pub code:u16, pub reason:&'static str }
#[derive(Serialize)]   pub struct SubmitTxBatchResp{ pub accepted:usize, pub rejected:usize, pub new_height:u64, pub results:Vec<TxResult> }

pub async fn submit_tx_batch(State(st):State<AppState>, Json(req):Json<SubmitTxBatchReq>)
 -> Result<Json<SubmitTxBatchResp>,StatusCode>{
    let t=Timer::new("/submit_tx_batch","POST");
    if req.txs.is_empty(){ inc_total("/submit_tx_batch","POST",StatusCode::BAD_REQUEST); t.observe(); return Err(StatusCode::BAD_REQUEST); }
    let mut by_sender:BTreeMap<String,Vec<(usize,TxIn)>>=BTreeMap::new();
    for (i,tx) in req.txs.into_iter().enumerate(){ by_sender.entry(tx.from.clone()).or_default().push((i,tx)); }
    let mut results=Vec::new(); let mut acc_total=0usize; let mut rej_total=0usize; let mut last_h=st.store.get_height().unwrap_or(0);
    let mut cache:HashMap<String, crate::storage::AccountState>=HashMap::new();
    for (from,mut items) in by_sender.into_iter() {
        items.sort_by_key(|(_,tx)| tx.nonce);
        let lk = st.locks.entry(from.clone()).or_insert_with(||Arc::new(Mutex::new(()))).clone();
        let _g = lk.lock();
        let mut next = st.store.get_account(&from).unwrap_or_default().nonce;
        let mut valid:Vec<TxIn>=Vec::new();
        for (idx,tx) in items.into_iter(){
            let vk = match vk_from_rid(&tx.from){ Ok(v)=>v, Err(_)=>{ rej_total+=1; results.push(TxResult{idx,status:"rejected",code:400,reason:"bad_rid"}); continue; } };
            let sig= match sig_from_hex(&tx.sig_hex){ Ok(s)=>s, Err(_)=>{ rej_total+=1; results.push(TxResult{idx,status:"rejected",code:401,reason:"bad_sig"}); continue; } };
            let msg= match canon_bytes(&tx){ Ok(m)=>m, Err(_)=>{ rej_total+=1; results.push(TxResult{idx,status:"rejected",code:400,reason:"bad_canon"}); continue; } };
            if vk.verify(&msg,&sig).is_err(){ rej_total+=1; results.push(TxResult{idx,status:"rejected",code:401,reason:"bad_sig"}); continue; }
            if tx.nonce != next.saturating_add(1){ rej_total+=1; results.push(TxResult{idx,status:"rejected",code:409,reason:"bad_nonce"}); continue; }
            let fs = cache.get(&tx.from).cloned().unwrap_or_else(|| st.store.get_account(&tx.from).unwrap_or_default());
            let ts = cache.get(&tx.to).cloned().unwrap_or_else(|| st.store.get_account(&tx.to).unwrap_or_default());
            if tx.from != tx.to && fs.balance < tx.amount { rej_total+=1; results.push(TxResult{idx,status:"rejected",code:402,reason:"insufficient_funds"}); continue; }
            // simulate in cache
            let mut nf=fs; let mut nt=ts; next = next.saturating_add(1); nf.nonce = next;
            if tx.from != tx.to { nf.balance = nf.balance.saturating_sub(tx.amount); nt.balance = nt.balance.saturating_add(tx.amount); }
            cache.insert(tx.from.clone(), nf); cache.insert(tx.to.clone(), nt);
            valid.push(tx); acc_total+=1; results.push(TxResult{idx,status:"accepted",code:0,reason:"ok"});
        }
        if !valid.is_empty(){ last_h = st.store.apply_batch(&valid).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?; }
    }
    let resp=SubmitTxBatchResp{accepted:acc_total,rejected:rej_total,new_height:last_h,results};
    inc_total("/submit_tx_batch","POST",StatusCode::OK); t.observe(); Ok(Json(resp))
}
#[inline] fn inc_tx_err(){}

/* ========= одиночная submit_tx ========= */
#[derive(Deserialize)] pub struct SubmitTxReq{ #[serde(default)] pub _payload:serde_json::Value }
#[derive(Serialize)]   pub struct SubmitTxResp{ pub status:&'static str }
pub async fn submit_tx(State(_st):State<AppState>, Json(_req):Json<SubmitTxReq>) -> Result<Json<SubmitTxResp>,StatusCode>{
    let t=Timer::new("/submit_tx","POST"); inc_total("/submit_tx","POST",StatusCode::OK); t.observe(); Ok(Json(SubmitTxResp{status:"accepted"}))
}

/* ========= debug_canon ========= */
#[derive(Deserialize)] pub struct DebugCanonReq{ #[serde(default)] pub tx:serde_json::Value }
#[derive(Serialize)]   pub struct DebugCanonResp{ pub canon_hex:String }
pub async fn debug_canon(Json(req):Json<DebugCanonReq>) -> Result<Json<DebugCanonResp>,StatusCode>{
    let t=Timer::new("/debug_canon","POST");
    let from=req.tx.get("from").and_then(|v|v.as_str()).ok_or(StatusCode::BAD_REQUEST)?;
    let to  =req.tx.get("to").and_then(|v|v.as_str()).ok_or(StatusCode::BAD_REQUEST)?;
    let amount=req.tx.get("amount").and_then(|v|v.as_u64()).ok_or(StatusCode::BAD_REQUEST)?;
    let nonce =req.tx.get("nonce").and_then(|v|v.as_u64()).ok_or(StatusCode::BAD_REQUEST)?;
    let c=CanonTx{from,to,amount,nonce}; let bytes=serde_json::to_vec(&c).map_err(|_|StatusCode::BAD_REQUEST)?;
    let canon_hex=hex::encode(bytes);
    inc_total("/debug_canon","POST",StatusCode::OK); t.observe(); Ok(Json(DebugCanonResp{canon_hex}))
}

/* ========= faucet (DEV) ========= */
#[derive(Deserialize)] pub struct FaucetReq{ #[serde(default)] pub rid:String, #[serde(default)] pub amount:u64 }
#[derive(Serialize)]   pub struct FaucetResp{ pub granted:u64, pub rid:String }
pub async fn faucet(State(st):State<AppState>, Json(req):Json<FaucetReq>) -> Result<Json<FaucetResp>,StatusCode>{
    if std::env::var("LRB_ENABLE_FAUCET").ok().as_deref()!=Some("1"){ return Err(StatusCode::FORBIDDEN); }
    let t=Timer::new("/faucet","POST");
    if req.rid.is_empty() || req.amount==0 { inc_total("/faucet","POST",StatusCode::BAD_REQUEST); t.observe(); return Err(StatusCode::BAD_REQUEST);}
    let _st = st.store.faucet(&req.rid, req.amount).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?;
    inc_total("/faucet","POST",StatusCode::OK); t.observe(); Ok(Json(FaucetResp{granted:req.amount, rid:req.rid}))
}

/* ========= economy ========= */
#[derive(Serialize)] pub struct EconomyResp{ pub cap:u64, pub minted:u64, pub burned:u64, pub supply:u64 }
pub async fn economy(State(st):State<AppState>) -> Result<Json<EconomyResp>,StatusCode>{
    let snap = st.store.economy_snapshot().map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(EconomyResp{cap:snap.cap, minted:snap.minted, burned:snap.burned, supply:snap.supply}))
}
