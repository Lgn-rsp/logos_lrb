#![allow(dead_code)]
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize)]
pub struct DepositReq {
    pub rid: String,
    pub amount: u64,
    #[serde(default)]
    pub txid: String,
}

#[derive(Serialize)]
pub struct DepositResp {
    pub status: &'static str,
    pub rid: String,
    pub credited: u64,
}

pub async fn deposit(
    State(_st): State<AppState>,
    Json(req): Json<DepositReq>,
) -> Result<Json<DepositResp>, StatusCode> {
    // TODO(след. пачка): валидация квитка/квоты и зачисление rToken
    Ok(Json(DepositResp {
        status: "accepted",
        rid: req.rid,
        credited: req.amount,
    }))
}

#[derive(Deserialize)]
pub struct RedeemReq {
    pub rid: String,
    pub amount: u64,
    #[serde(default)]
    pub target_chain: String,
    #[serde(default)]
    pub target_address: String,
}

#[derive(Serialize)]
pub struct RedeemResp {
    pub status: &'static str,
    pub rid: String,
    pub debited: u64,
}

pub async fn redeem(
    State(_st): State<AppState>,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, StatusCode> {
    // TODO(след. пачка): резерв/списание rToken и квиток на вывод
    Ok(Json(RedeemResp {
        status: "accepted",
        rid: req.rid,
        debited: req.amount,
    }))
}

#[derive(Deserialize)]
pub struct VerifyReq {
    #[serde(default)]
    pub ticket: String,
}

#[derive(Serialize)]
pub struct VerifyResp {
    pub status: &'static str,
    #[serde(default)]
    pub ok: bool,
}

pub async fn verify(
    State(_st): State<AppState>,
    Json(_req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, StatusCode> {
    // TODO(след. пачка): проверка подписи/кворума
    Ok(Json(VerifyResp {
        status: "ok",
        ok: true,
    }))
}
