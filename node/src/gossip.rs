use anyhow::Result;
use axum::{extract::Extension, Json};
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use lrb_core::{Block, resonance, phase_filters::block_passes_phase};
use crate::state::{AppState, now_ms, GOSSIP_BLK_SENT, GOSSIP_BLK_RECV, GOSSIP_VOTE_SENT, GOSSIP_VOTE_RECV, CONS_VOTES, PHASE_BLOCK_ACCEPTED, PHASE_BLOCK_REJECTED};

#[derive(Serialize, Deserialize, Clone)]
pub struct GossipHeader { pub height:u64, pub prev_hash:String, pub block_hash:String, pub proposer_rid:String, pub timestamp_ms:u128, pub sigma_hex:String }
#[derive(Serialize, Deserialize, Clone)]
pub struct GossipBlockMsg { pub header:GossipHeader, pub block:Block, pub sender_pk_b58:String, pub sig_b64:String, pub nonce_ms:u128 }
#[derive(Serialize, Deserialize, Clone)]
pub struct VoteMsg { pub height:u64, pub block_hash:String, pub sigma_hex:String, pub voter_pk_b58:String, pub sig_b64:String, pub nonce_ms:u128 }

fn verify_gossip_sig(msg: &GossipBlockMsg) -> Result<()> {
    let pk_bytes = bs58::decode(&msg.sender_pk_b58).into_vec()?;
    let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow::anyhow!("bad pk"))?)?;
    let sig_bytes = B64.decode(msg.sig_b64.as_bytes())?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow::anyhow!("bad sig"))?);
    let mut payload = Vec::new();
    payload.extend_from_slice(msg.header.sigma_hex.as_bytes());
    payload.extend_from_slice(msg.header.block_hash.as_bytes());
    payload.extend_from_slice(&msg.nonce_ms.to_le_bytes());
    vk.verify(&payload, &sig).map_err(|e| anyhow::anyhow!("verify failed: {e}"))?;
    Ok(())
}

pub async fn send_block(peers:&[String], st:&AppState, block:&Block) {
    let sigma_hex = resonance::sigma_digest_block_hex(block);
    let nonce_ms = now_ms();
    let mut pl = Vec::new();
    pl.extend_from_slice(sigma_hex.as_bytes());
    pl.extend_from_slice(block.block_hash.as_bytes());
    pl.extend_from_slice(&nonce_ms.to_le_bytes());
    let sig_b64 = B64.encode(st.sk.sign(&pl).to_bytes());
    let header = GossipHeader {
        height:block.height, prev_hash:block.prev_hash.clone(), block_hash:block.block_hash.clone(),
        proposer_rid:block.proposer.0.clone(), timestamp_ms:block.timestamp_ms, sigma_hex:sigma_hex.clone()
    };
    let msg = GossipBlockMsg {
        header, block:block.clone(),
        sender_pk_b58: bs58::encode(st.self_vk.to_bytes()).into_string(),
        sig_b64, nonce_ms
    };
    for p in peers {
        let _ = st.http.post(&format!("{}/gossip/block", p.trim_end_matches('/'))).json(&msg).send().await;
        GOSSIP_BLK_SENT.inc();
    }

    let vote_nonce = now_ms();
    let mut pv = Vec::new();
    pv.extend_from_slice(sigma_hex.as_bytes());
    pv.extend_from_slice(block.block_hash.as_bytes());
    pv.extend_from_slice(&block.height.to_le_bytes());
    pv.extend_from_slice(&vote_nonce.to_le_bytes());
    let vote_sig_b64 = B64.encode(st.sk.sign(&pv).to_bytes());
    let vmsg = VoteMsg {
        height:block.height, block_hash:block.block_hash.clone(), sigma_hex: sigma_hex.clone(),
        voter_pk_b58: bs58::encode(st.self_vk.to_bytes()).into_string(), sig_b64: vote_sig_b64, nonce_ms: vote_nonce
    };
    for p in peers { let _ = st.http.post(&format!("{}/gossip/vote", p.trim_end_matches('/'))).json(&vmsg).send().await; GOSSIP_VOTE_SENT.inc(); }
}

pub async fn gossip_block(Extension(st): Extension<AppState>, Json(msg): Json<GossipBlockMsg>)
-> Result<Json<serde_json::value::Value>, StatusCode> {
    GOSSIP_BLK_RECV.inc();

    let local_sigma = resonance::sigma_digest_block_hex(&msg.block);
    if local_sigma != msg.header.sigma_hex { return Err(StatusCode::UNPROCESSABLE_ENTITY); }
    if verify_gossip_sig(&msg).is_err() { return Err(StatusCode::UNPROCESSABLE_ENTITY); }

    // фазовый фильтр: блоки вне фазы не принимаем
    if !block_passes_phase(&msg.block) {
        PHASE_BLOCK_REJECTED.inc();
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    PHASE_BLOCK_ACCEPTED.inc();

    crate::fork::apply_or_reorg_deep(&st, &msg.block, &msg.header.sigma_hex, &msg.header.prev_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn gossip_vote(Extension(st): Extension<AppState>, Json(v): Json<VoteMsg>)
-> Result<Json<serde_json::value::Value>, StatusCode> {
    if !st.validators.is_empty() && !st.validators.contains(&v.voter_pk_b58) { return Err(StatusCode::FORBIDDEN); }
    GOSSIP_VOTE_RECV.inc();
    let vv = lrb_core::quorum::Vote {
        height: v.height, block_hash: v.block_hash.clone(), sigma_hex: v.sigma_hex.clone(),
        voter_pk_b58: v.voter_pk_b58.clone(), sig_b64: v.sig_b64.clone(), nonce_ms: v.nonce_ms
    };
    if let Err(_) = lrb_core::quorum::verify_vote(&vv) { return Err(StatusCode::UNPROCESSABLE_ENTITY); }
    if st.engine.register_vote(v.height, &v.block_hash, &v.voter_pk_b58) { CONS_VOTES.inc(); }
    Ok(Json(serde_json::json!({"ok": true})))
}
