//! Админ-ручки: snapshot/restore и node_info.
//! Доступ защищается через заголовок X-Admin-Key = LRB_ADMIN_KEY.

use crate::AppState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

fn check_admin(st: &AppState, headers: &axum::http::HeaderMap) -> Result<(), StatusCode> {
    let got = headers
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if got == st.admin_key {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[derive(Serialize)]
pub struct NodeInfo {
    pub rid: String,
    pub height: u64,
    pub finalized: bool,
}

pub async fn node_info(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<NodeInfo>, StatusCode> {
    check_admin(&st, &headers)?;
    Ok(Json(NodeInfo {
        rid: st.rid_b58.clone(),
        height: 0,
        finalized: false,
    }))
}

#[derive(Serialize)]
pub struct SnapshotResp {
    pub status: &'static str,
}

pub async fn snapshot(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<SnapshotResp>, StatusCode> {
    check_admin(&st, &headers)?;
    Ok(Json(SnapshotResp { status: "ok" }))
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct RestoreReq {
    #[serde(default)]
    pub path: String,
}

pub async fn restore(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(_req): Json<RestoreReq>,
) -> Result<Json<SnapshotResp>, StatusCode> {
    check_admin(&st, &headers)?;
    Ok(Json(SnapshotResp { status: "ok" }))
}
