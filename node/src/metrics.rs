use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use once_cell::sync::Lazy;
use prometheus::{
    histogram_opts, opts, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_with_registry, Encoder,
    HistogramVec, IntCounterVec, IntGauge, Registry, TextEncoder,
};
use std::time::Instant;

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static HTTP_REQ_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        opts!("http_requests_total", "Total HTTP requests"),
        &["endpoint", "method", "status"],
        &REGISTRY
    )
    .unwrap()
});
pub static HTTP_REQ_DUR: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!("http_request_duration_seconds", "HTTP duration").buckets(vec![
            0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.100, 0.200, 0.500, 1.0, 2.0, 5.0
        ]),
        &["endpoint", "method"],
        &REGISTRY
    )
    .unwrap()
});
pub static INFLIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge_with_registry!(opts!("http_inflight_requests", "In-flight"), &REGISTRY)
        .unwrap()
});

// New app metrics
pub static HIST_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        opts!("lrb_history_requests_total", "History requests"),
        &["status"],
        &REGISTRY
    )
    .unwrap()
});
pub static BLOCKS_SERVED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        opts!("lrb_blocks_served_total", "Blocks served"),
        &["status"],
        &REGISTRY
    )
    .unwrap()
});

pub struct Timer {
    start: Instant,
    endpoint: &'static str,
    method: &'static str,
}
impl Timer {
    pub fn new(endpoint: &'static str, method: &'static str) -> Self {
        INFLIGHT.inc();
        Self {
            start: Instant::now(),
            endpoint,
            method,
        }
    }
    pub fn observe(self) {
        let dt = self.start.elapsed().as_secs_f64();
        HTTP_REQ_DUR
            .with_label_values(&[self.endpoint, self.method])
            .observe(dt);
        INFLIGHT.dec();
    }
}
pub fn inc_total(endpoint: &'static str, method: &'static str, status: StatusCode) {
    HTTP_REQ_TOTAL
        .with_label_values(&[endpoint, method, status.as_str()])
        .inc();
}
pub async fn metrics_handler() -> Response {
    let mf = REGISTRY.gather();
    let mut buf = Vec::with_capacity(64 * 1024);
    let enc = TextEncoder::new();
    if let Err(e) = enc.encode(&mf, &mut buf) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode error: {e}"),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [("Content-Type", enc.format_type().to_string())],
        buf,
    )
        .into_response()
}
