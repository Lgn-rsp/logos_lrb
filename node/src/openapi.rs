use axum::response::{IntoResponse, Response};
use axum::http::{HeaderValue, StatusCode};

static SPEC: &str = include_str!("../openapi/openapi.json");

pub async fn serve() -> Response {
    let mut resp = (StatusCode::OK, SPEC).into_response();
    let headers = resp.headers_mut();
    let _ = headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp
}
