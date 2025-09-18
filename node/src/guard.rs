use axum::{body::Body, http::Request, middleware::Next, response::Response};
use rand::{thread_rng, Rng};
use std::time::Duration;

/// Лёгкий фазовый «шум»: джиттер 0–7мс для submit/stake/bridge путей
pub async fn rate_limit_mw(req: Request<Body>, next: Next) -> Response {
    let p = req.uri().path();
    if p.starts_with("/submit_tx") || p.starts_with("/stake/") || p.starts_with("/bridge/") {
        let jitter = thread_rng().gen_range(0..=7);
        tokio::time::sleep(Duration::from_millis(jitter)).await;
    }
    next.run(req).await
}
