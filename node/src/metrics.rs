use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramVec, IntCounterVec, Registry, TextEncoder, register_histogram_vec, register_int_counter_vec,
};
use std::time::Instant;

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

static HTTP_REQS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "logos_http_requests_total",
        "HTTP requests total",
        &["method","path","status"]
    ).unwrap()
});

static HTTP_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "logos_http_request_duration_seconds",
        "HTTP request latency (s)",
        &["method","path","status"],
        prometheus::exponential_buckets(0.001, 2.0, 14).unwrap() // 1ms..~16s
    ).unwrap()
});

/// Нормализация пути (убираем динамику)
fn normalize_path(p: &str) -> String {
    if p.starts_with("/balance/") { return "/balance/:rid".into(); }
    if p.starts_with("/history/") { return "/history/:rid".into(); }
    p.to_string()
}

/// Axum-middleware: считает per-route счётчики и latency
pub async fn track(req: Request<Body>, next: Next) -> axum::response::Response {
    let method = req.method().as_str().to_owned();
    let path = normalize_path(req.uri().path());
    let start = Instant::now();

    let res = next.run(req).await;
    let status = res.status().as_u16().to_string();

    HTTP_REQS.with_label_values(&[&method, &path, &status]).inc();
    HTTP_LATENCY.with_label_values(&[&method, &path, &status]).observe(start.elapsed().as_secs_f64());

    res
}

/// Exporter для Prometheus
pub async fn prometheus() -> impl IntoResponse {
    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    if let Err(_) = encoder.encode(&metric_families, &mut buf) {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode error").into_response();
    }
    match String::from_utf8(buf) {
        Ok(text) => (StatusCode::OK, text).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "utf8 error").into_response(),
    }
}

/// Совместимость: старый inc_total был заглушкой — оставим no-op
pub fn inc_total(_label: &str) {}
