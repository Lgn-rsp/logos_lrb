use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::IntoResponse,
    http::StatusCode,
};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramVec, IntCounter, IntCounterVec, IntGauge, Registry, TextEncoder,
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
};
use std::time::Instant;

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

// ---- HTTP ----
static HTTP_REQS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("logos_http_requests_total","HTTP reqs",&["method","path","status"]).unwrap()
});
static HTTP_LAT: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!("logos_http_duration_seconds","HTTP latency",&["method","path","status"],
        prometheus::exponential_buckets(0.001,2.0,14).unwrap()).unwrap()
});

// ---- Chain ----
static BLOCKS_TOTAL: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("logos_blocks_produced_total","Blocks total").unwrap());
static HEAD_HEIGHT: Lazy<IntGauge>    = Lazy::new(|| register_int_gauge!("logos_head_height","Head").unwrap());
static FINAL_HEIGHT: Lazy<IntGauge>   = Lazy::new(|| register_int_gauge!("logos_finalized_height","Finalized").unwrap());

// ---- Tx ----
static TX_ACCEPTED: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("logos_tx_accepted_total","Accepted tx").unwrap());
static TX_REJECTED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("logos_tx_rejected_total","Rejected tx",&["reason"]).unwrap()
});

// ---- Bridge (durable) ----
static BRIDGE_OPS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("logos_bridge_ops_total","Bridge ops",&["kind","status"]).unwrap()
});

// ---- Archive backpressure ----
static ARCHIVE_QUEUE: Lazy<IntGauge> = Lazy::new(|| register_int_gauge!("logos_archive_queue","Archive queue depth").unwrap());

fn norm(p:&str)->String{
    if p.starts_with("/balance/") {"/balance/:rid".into()}
    else if p.starts_with("/history/"){"/history/:rid".into()}
    else if p.starts_with("/stake/my/"){"/stake/my/:rid".into()}
    else {p.to_string()}
}

pub async fn track(req: Request<Body>, next: Next) -> axum::response::Response {
    let m=req.method().as_str().to_owned();
    let p=norm(req.uri().path());
    let t=Instant::now();
    let res=next.run(req).await;
    let s=res.status().as_u16().to_string();
    HTTP_REQS.with_label_values(&[&m,&p,&s]).inc();
    HTTP_LAT.with_label_values(&[&m,&p,&s]).observe(t.elapsed().as_secs_f64());
    res
}

pub async fn prometheus()->impl IntoResponse{
    let mfs=REGISTRY.gather();
    let mut buf=Vec::new();
    let enc=TextEncoder::new();
    if let Err(_)=enc.encode(&mfs,&mut buf){ return (StatusCode::INTERNAL_SERVER_ERROR,"encode error").into_response(); }
    match String::from_utf8(buf){
        Ok(body)=>(StatusCode::OK,body).into_response(),
        Err(_)=>(StatusCode::INTERNAL_SERVER_ERROR,"utf8 error").into_response(),
    }
}

// API для модулей
pub fn inc_block_produced(){ BLOCKS_TOTAL.inc(); }
pub fn set_chain(h:u64, f:u64){ HEAD_HEIGHT.set(h as i64); FINAL_HEIGHT.set(f as i64); }
pub fn inc_tx_accepted(){ TX_ACCEPTED.inc(); }
pub fn inc_tx_rejected(reason:&'static str){ TX_REJECTED.with_label_values(&[reason]).inc(); }
pub fn inc_bridge(kind:&'static str, status:&'static str){ BRIDGE_OPS.with_label_values(&[kind,status]).inc(); }
pub fn set_archive_queue(n:i64){ ARCHIVE_QUEUE.set(n); }

// Совместимость со старым кодом
#[allow(dead_code)] pub fn inc_total(_label:&str){}
