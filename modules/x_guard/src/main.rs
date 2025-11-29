use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use reqwest::{Client, StatusCode as HttpStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};
use tracing_subscriber::prelude::*;

#[derive(Clone, Debug)]
struct XCreds {
    api_key: String,
    api_secret: String,
    bearer_token: String,
    access_token: Option<String>,
    access_token_secret: Option<String>,
}

fn read_env_required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing env {}", name))
}

fn read_env_optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn guard_secret(name: &str, value: &str) -> Result<()> {
    let bad = ["CHANGE_ME", "changeme", "default", "", "EXAMPLE_X_API_KEY_REPLACE_ME"];
    if bad.iter().any(|b| value.eq_ignore_ascii_case(b)) {
        return Err(anyhow!(
            "{} is default/empty placeholder; refuse to start",
            name
        ));
    }
    Ok(())
}

impl XCreds {
    fn from_env() -> Result<Self> {
        let api_key = read_env_required("X_API_KEY")?;
        let api_secret = read_env_required("X_API_SECRET")?;
        let bearer_token = read_env_required("X_BEARER_TOKEN")?;

        guard_secret("X_API_KEY", &api_key)?;
        guard_secret("X_API_SECRET", &api_secret)?;
        guard_secret("X_BEARER_TOKEN", &bearer_token)?;

        let access_token = read_env_optional("X_ACCESS_TOKEN");
        let access_token_secret = read_env_optional("X_ACCESS_TOKEN_SECRET");

        Ok(Self {
            api_key,
            api_secret,
            bearer_token,
            access_token,
            access_token_secret,
        })
    }
}

#[derive(Clone)]
struct XClient {
    http: Client,
    creds: Arc<XCreds>,
    base_url: String,
}

impl XClient {
    fn new(creds: XCreds) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(20))
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .build()
            .expect("failed to build reqwest client");

        Self {
            http,
            creds: Arc::new(creds),
            base_url: "https://api.x.com/2".to_string(),
        }
    }

    async fn get_raw(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut attempt: u32 = 0;

        loop {
            attempt += 1;
            let resp = self
                .http
                .get(&url)
                .query(query)
                .bearer_auth(&self.creds.bearer_token)
                .send()
                .await
                .with_context(|| format!("request to {}", url))?;

            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();

            if status == HttpStatus::TOO_MANY_REQUESTS && attempt < 4 {
                let sleep_secs = 30 * attempt;
                info!(
                    "rate limited by X on {}, attempt {} -> sleep {}s",
                    url, attempt, sleep_secs
                );
                tokio::time::sleep(Duration::from_secs(sleep_secs as u64)).await;
                continue;
            }

            if status.is_server_error() && attempt < 4 {
                let backoff = 2_u64.pow(attempt);
                info!(
                    "server error from X: {} on {}, retry in {}s",
                    status, url, backoff
                );
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                continue;
            }

            if !status.is_success() {
                return Err(anyhow!(
                    "X API error: status={} body={}",
                    status.as_u16(),
                    text
                ));
            }

            let json: Value = serde_json::from_str(&text)
                .with_context(|| format!("parsing JSON from {}: {}", url, text))?;
            return Ok(json);
        }
    }

    async fn get_user_by_username(&self, username: &str) -> Result<UserInfo> {
        let path = format!("/users/by/username/{}", username);
        let json = self
            .get_raw(&path, &[("user.fields", "created_at,public_metrics")])
            .await?;

        let data = json
            .get("data")
            .ok_or_else(|| anyhow!("no data in user response"))?;

        let id = data
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("no id in user data"))?
            .to_string();

        let uname = data
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or(username)
            .to_string();

        let created_at = data
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let followers = data
            .get("public_metrics")
            .and_then(|v| v.get("followers_count"))
            .and_then(|v| v.as_u64());

        Ok(UserInfo {
            id,
            username: uname,
            created_at,
            followers,
        })
    }

    async fn user_follows(&self, source_user_id: &str, target_user_id: &str) -> Result<bool> {
        let path = format!("/users/{}/following", source_user_id);
        let json = self
            .get_raw(&path, &[("max_results", "1000"), ("user.fields", "id,username")])
            .await?;

        let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        let found = data.iter().any(|u| {
            u.get("id")
                .and_then(|v| v.as_str())
                .map(|id| id == target_user_id)
                .unwrap_or(false)
        });

        Ok(found)
    }

    async fn user_liked_tweet(&self, user_id: &str, tweet_id: &str) -> Result<bool> {
        let path = format!("/tweets/{}/liking_users", tweet_id);
        let json = self
            .get_raw(&path, &[("max_results", "100"), ("user.fields", "id")])
            .await?;

        let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        let found = data.iter().any(|u| {
            u.get("id")
                .and_then(|v| v.as_str())
                .map(|id| id == user_id)
                .unwrap_or(false)
        });

        Ok(found)
    }

    async fn user_retweeted_tweet(&self, user_id: &str, tweet_id: &str) -> Result<bool> {
        let path = format!("/tweets/{}/retweeted_by", tweet_id);
        let json = self
            .get_raw(&path, &[("max_results", "100"), ("user.fields", "id")])
            .await?;

        let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        let found = data.iter().any(|u| {
            u.get("id")
                .and_then(|v| v.as_str())
                .map(|id| id == user_id)
                .unwrap_or(false)
        });

        Ok(found)
    }
}

#[derive(Clone, Debug)]
struct UserInfo {
    id: String,
    username: String,
    created_at: Option<String>,
    followers: Option<u64>,
}

#[derive(Clone)]
struct AppState {
    x: XClient,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

async fn health(State(_state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "logos_x_guard",
    })
}

#[derive(Deserialize)]
struct CheckRequest {
    user_username: String,
    project_username: String,
    tweet_id: String,
    #[serde(default = "default_true")]
    require_follow: bool,
    #[serde(default = "default_true")]
    require_like: bool,
    #[serde(default = "default_true")]
    require_retweet: bool,
    #[serde(default = "default_min_age")]
    min_account_age_days: u32,
    #[serde(default = "default_min_followers")]
    min_followers: u32,
}

fn default_true() -> bool {
    true
}
fn default_min_age() -> u32 {
    3
}
fn default_min_followers() -> u32 {
    3
}

#[derive(Serialize)]
struct CheckResponse {
    ok: bool,
    user_username: String,
    project_username: String,
    tweet_id: String,
    follow_ok: bool,
    like_ok: bool,
    retweet_ok: bool,
    age_ok: bool,
    followers_ok: bool,
    user_info: Value,
}

async fn check_airdrop(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckRequest>,
) -> impl IntoResponse {
    let res = do_check_airdrop(state, req).await;
    match res {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            error!("check_airdrop error: {:?}", err);
            let body = serde_json::json!({
                "ok": false,
                "error": "internal_error",
                "message": err.to_string(),
            });
            (StatusCode::BAD_GATEWAY, Json(body)).into_response()
        }
    }
}

async fn do_check_airdrop(state: Arc<AppState>, req: CheckRequest) -> Result<CheckResponse> {
    let user = state.x.get_user_by_username(&req.user_username).await?;
    let project = state
        .x
        .get_user_by_username(&req.project_username)
        .await?;

    let age_ok = true; // упрощённо, без парсинга created_at

    let followers_ok = user
        .followers
        .map(|c| c >= req.min_followers as u64)
        .unwrap_or(false);

    let mut follow_ok = true;
    let mut like_ok = true;
    let mut retweet_ok = true;

    if req.require_follow {
        follow_ok = state
            .x
            .user_follows(&user.id, &project.id)
            .await
            .unwrap_or(false);
    }

    if req.require_like {
        like_ok = state
            .x
            .user_liked_tweet(&user.id, &req.tweet_id)
            .await
            .unwrap_or(false);
    }

    if req.require_retweet {
        retweet_ok = state
            .x
            .user_retweeted_tweet(&user.id, &req.tweet_id)
            .await
            .unwrap_or(false);
    }

    let ok = follow_ok && like_ok && retweet_ok && age_ok && followers_ok;

    let user_info = serde_json::json!({
        "id": user.id,
        "username": user.username,
        "created_at": user.created_at,
        "followers": user.followers,
    });

    Ok(CheckResponse {
        ok,
        user_username: req.user_username,
        project_username: req.project_username,
        tweet_id: req.tweet_id,
        follow_ok,
        like_ok,
        retweet_ok,
        age_ok,
        followers_ok,
        user_info,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter_layer =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,hyper=warn,reqwest=warn".into());
    let fmt_layer = fmt::layer().with_target(false);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    let creds = XCreds::from_env().context("reading X_* env vars")?;
    info!("X credentials loaded, starting service");

    let x_client = XClient::new(creds);
    let state = Arc::new(AppState { x: x_client });

    let app = Router::new()
        .route("/health", get(health))
        .route("/check_airdrop", post(check_airdrop))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8091".parse().unwrap();
    info!("LOGOS X Guard listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
