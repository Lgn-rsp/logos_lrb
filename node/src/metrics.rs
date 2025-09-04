use axum::http::{HeaderMap, HeaderValue};
use prometheus::{Encoder, TextEncoder};

pub async fn metrics_handler() -> (HeaderMap, Vec<u8>) {
    let mut buffer = Vec::<u8>::new();
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4"));
    (headers, buffer)
}
