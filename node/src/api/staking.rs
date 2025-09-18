use axum::{extract::{Path}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use reqwest::Client;

#[derive(Deserialize, Serialize)]
pub struct StakeAction {
    pub rid: String,
    #[serde(default)] pub validator: String,
    #[serde(default)] pub amount: Option<u64>,
}

pub async fn stake_delegate(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&serde_json::json!({"action":"delegate","rid":body.rid,"validator":body.validator,"amount":body.amount}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_undelegate(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&serde_json::json!({"action":"undelegate","rid":body.rid,"validator":body.validator,"amount":body.amount}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_claim(Json(body):Json<StakeAction>) -> (StatusCode, String) {
    let cli = Client::new();
    let resp = cli.post("http://127.0.0.1:8080/stake/submit")
        .json(&serde_json::json!({"action":"claim","rid":body.rid}))
        .send().await;
    match resp {
        Ok(r) => (StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::OK), r.text().await.unwrap_or_default()),
        Err(e)=> (StatusCode::BAD_GATEWAY, format!("proxy_error: {e}")),
    }
}

pub async fn stake_my(Path(rid):Path<String>) -> (StatusCode, String) {
    let cli = Client::new();

    let dtext = match cli.get(format!("http://127.0.0.1:8080/stake/delegations/{rid}")).send().await {
        Ok(resp) => resp.text().await.unwrap_or_else(|_| "[]".to_string()),
        Err(_)   => "[]".to_string(),
    };

    let rtext = match cli.get(format!("http://127.0.0.1:8080/stake/rewards/{rid}")).send().await {
        Ok(resp) => resp.text().await.unwrap_or_else(|_| "[]".to_string()),
        Err(_)   => "[]".to_string(),
    };

    let body = serde_json::json!({
        "delegations": serde_json::from_str::<serde_json::Value>(&dtext).unwrap_or(serde_json::json!([])),
        "rewards":     serde_json::from_str::<serde_json::Value>(&rtext).unwrap_or(serde_json::json!([]))
    });
    (StatusCode::OK, body.to_string())
}
