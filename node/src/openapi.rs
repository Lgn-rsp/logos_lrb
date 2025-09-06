use axum::{response::IntoResponse, http::StatusCode};

pub async fn spec() -> impl IntoResponse {
    // Компилируем JSON внутрь бинаря — стабильность и скорость
    const SPEC: &str = include_str!("../openapi/openapi.json");
    (StatusCode::OK, [("Content-Type", "application/json")], SPEC)
}
