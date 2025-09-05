use axum::{http::StatusCode, response::IntoResponse};

pub async fn spec() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "application/json")],
        include_str!("openapi.json"),
    )
}
