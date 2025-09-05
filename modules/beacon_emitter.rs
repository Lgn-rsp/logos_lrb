use axum::{
    extract::State,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, time::Duration};
use tower::{ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
    timeout::TimeoutLayer,
    limit::{RequestBodyLimitLayer},
};
use tracing_subscriber::{EnvFilter, fmt};
use ed25519_dalek::{SigningKey, VerifyingKey, SignatureError};
use rand_core::OsRng;
use bs58;
use once_cell::sync::OnceCell;
use anyhow::Result;

mod api;
mod admin;
mod bridge;
mod gossip;
mod state;
mod peers;
mod fork;

#[derive(Clone)]
struct AppState {
    signing: SigningKey,
    verifying: VerifyingKey,
    rid_b58: String,
    admin_key: String,
    bridge_key: String,
}

static APP_STATE: OnceCell<AppState> = OnceCell::new();

fn load_signing_key() -> Result<SigningKey> {
    use std::env;
    if let Ok(hex) = env::var("LRB_NODE_SK_HEX") {
        let bytes = hex::decode(hex.trim())?;
        let sk = SigningKey::from_bytes(bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad SK len"))?);
        return Ok(sk);
    }
    if let Ok(path) = env::var("LRB_NODE_SK_PATH") {
        let data = std::fs::read(path)?;
        let sk = SigningKey::from_bytes(data.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad SK len"))?);
        return Ok(sk);
    }
    anyhow::bail!("missing LRB_NODE_SK_HEX or LRB_NODE_SK_PATH");
}

fn rid_from_vk(vk: &VerifyingKey) -> String {
    bs58::encode(vk.as_bytes()).into_string()
}

fn read_env_required(n: &str) -> Result<String> {
    let v = std::env::var(n).map_err(|_| anyhow::anyhow!("missing env {}", n))?;
    Ok(v)
}

fn guard_secret(name: &str, v: &str) -> Result<()> {
    let bad = ["CHANGE_ADMIN_KEY","CHANGE_ME","", "changeme", "default"];
    if bad.iter().any(|b| v.eq_ignore_ascii_case(b)) {
        anyhow::bail!("{} is default/empty; refuse to start", name);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,axum=info"));
    fmt().with_env_filter(filter).init();

    // keys + env
    let sk = load_signing_key()?;
    let vk = VerifyingKey::from(&sk);
    let rid = rid_from_vk(&vk);

    let admin_key = read_env_required("LRB_ADMIN_KEY")?;
    let bridge_key = read_env_required("LRB_BRIDGE_KEY")?;
    guard_secret("LRB_ADMIN_KEY", &admin_key)?;
    guard_secret("LRB_BRIDGE_KEY", &bridge_key)?;

    let state = AppState {
        signing: sk,
        verifying: vk,
        rid_b58: rid.clone(),
        admin_key,
        bridge_key,
    };
    APP_STATE.set(state.clone()).unwrap();

    // CORS
    let cors = {
        let allowed_origin = std::env::var("LRB_WALLET_ORIGIN").unwrap_or_else(|_| String::from("https://wallet.example"));
        CorsLayer::new()
            .allow_origin(allowed_origin.parse::<axum::http::HeaderValue>().unwrap())
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
    };

    // limits/timeout
    let layers = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(RequestBodyLimitLayer::new(512 * 1024)) // 512 KiB
        .layer(cors)
        .into_inner();

    // маршруты
    let app = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/head", get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx", post(api::submit_tx))
        .route("/submit_tx_batch", post(api::submit_tx_batch))
        .route("/debug_canon", post(api::debug_canon))
        .route("/faucet", post(api::faucet)) // dev-only
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem", post(bridge::redeem))
        .route("/bridge/verify", post(bridge::verify))
        .route("/admin/snapshot", post(admin::snapshot))
        .route("/admin/restore", post(admin::restore))
        .route("/node/info", get(admin::node_info))
        .with_state(state)
        .layer(layers);

    let addr: SocketAddr = std::env::var("LRB_NODE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    tracing::info!("logos_node listening on {} (RID={})", addr, rid);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
