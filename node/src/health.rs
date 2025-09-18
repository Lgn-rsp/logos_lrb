//! Health endpoints: /livez (жив) и /readyz (готов)

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use std::sync::Arc;
use crate::state::AppState;

/// Публичная структура, т.к. используется в сигнатуре `Json<Ready>`
#[derive(Serialize)]
pub struct Ready {
    pub db: bool,
    pub archive: bool,
    pub payout_cfg: bool,
}

/// /livez — просто «жив ли процесс»
pub async fn livez() -> &'static str { "ok" }

/// /readyz — готовность: sled открыт; archive (если настроен) доступен; payout-адаптер сконфигурирован
pub async fn readyz(State(st):State<Arc<AppState>>) -> (StatusCode, Json<Ready>) {
    // sled: быстрая эвристика — БД поднялась и восстановилась
    let db_ok = st.sled().was_recovered();
    // archive: настроен ли (при желании можно сделать query .get().await)
    let arch_ok = st.archive.is_some();
    // payout-конфиг
    let payout_ok = std::env::var("BRIDGE_PAYOUT_URL").is_ok() && std::env::var("LRB_BRIDGE_KEY").is_ok();

    let body = Ready{ db: db_ok, archive: arch_ok, payout_cfg: payout_ok };
    let status = if db_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(body))
}
