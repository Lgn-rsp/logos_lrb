use anyhow::Result;
use axum::{
    middleware::{from_fn_with_state},
    routing::{get, post},
    Router,
};
use bs58;
use ed25519_dalek::{SigningKey, VerifyingKey};
use once_cell::sync::OnceCell;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower_http::{
    cors::CorsLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer,
};
use tracing_subscriber::{fmt, EnvFilter};

use lrb_core::ledger::Ledger;
use lrb_core::rcp_engine::engine_with_channels;
use lrb_core::types::Rid;

mod admin;
mod api;
mod auth;
mod bridge;
mod fork;
mod guard;
mod metrics;
mod openapi;
mod peers;
mod state;
mod storage;
mod version;

use dashmap::DashMap;
use parking_lot::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
    pub rid_b58: String,
    pub admin_key: String,
    pub bridge_key: String,
    pub ledger: Ledger,
    pub store: Arc<storage::Storage>,
    pub locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
}

static APP_STATE: OnceCell<AppState> = OnceCell::new();

fn load_signing_key() -> Result<SigningKey> {
    use std::env;
    if let Ok(hex) = env::var("LRB_NODE_SK_HEX") {
        let bytes = hex::decode(hex.trim())?;
        let sk = SigningKey::from_bytes(
            bytes.as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad SK len"))?,
        );
        return Ok(sk);
    }
    if let Ok(path) = env::var("LRB_NODE_SK_PATH") {
        let data = std::fs::read(path)?;
        let sk = SigningKey::from_bytes(
            data.as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad SK len"))?,
        );
        return Ok(sk);
    }
    anyhow::bail!("missing LRB_NODE_SK_HEX or LRB_NODE_SK_PATH");
}
fn rid_from_vk(vk: &VerifyingKey) -> String {
    bs58::encode(vk.as_bytes()).into_string()
}
fn read_env_required(n: &str) -> Result<String> {
    Ok(std::env::var(n).map_err(|_| anyhow::anyhow!(format!("missing env {}", n)))?)
}
fn guard_secret(name: &str, v: &str) -> Result<()> {
    let bad = ["CHANGE_ADMIN_KEY", "CHANGE_ME", "", "changeme", "default"];
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

    // keys/ids
    let sk = load_signing_key()?;
    let vk = VerifyingKey::from(&sk);
    let rid_b58 = rid_from_vk(&vk);
    let admin_key = read_env_required("LRB_ADMIN_KEY")?;
    let bridge_key = read_env_required("LRB_BRIDGE_KEY")?;
    guard_secret("LRB_ADMIN_KEY", &admin_key)?;
    guard_secret("LRB_BRIDGE_KEY", &bridge_key)?;

    // state
    let data_dir = std::env::var("LRB_DATA_DIR").unwrap_or_else(|_| "/var/lib/logos".into());
    std::fs::create_dir_all(&data_dir).ok();
    let ledger = Ledger::open(&data_dir)?;
    let store = Arc::new(storage::Storage::open(format!("{}/node_state", data_dir))?);

    let app_state = AppState {
        signing: sk,
        verifying: vk,
        rid_b58: rid_b58.clone(),
        admin_key,
        bridge_key,
        ledger: ledger.clone(),
        store,
        locks: Arc::new(DashMap::new()),
    };
    APP_STATE.set(app_state.clone()).ok();

    // engine
    let rid = Rid(rid_b58.clone());
    let _engine = engine_with_channels(ledger, rid);

    // CORS
    let allowed_origin =
        std::env::var("LRB_WALLET_ORIGIN").unwrap_or_else(|_| "http://localhost".into());
    let cors = {
        let hv = allowed_origin
            .parse::<axum::http::HeaderValue>()
            .expect("bad LRB_WALLET_ORIGIN");
        CorsLayer::new()
            .allow_origin(hv)
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
            ])
    };

    // Rate-limit (env)
    let qps: u64 = std::env::var("LRB_RATE_QPS").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let burst: u64 = std::env::var("LRB_RATE_BURST").ok().and_then(|s| s.parse().ok()).unwrap_or(40);
    let rl_enabled = qps > 0 && burst > 0;
    let bypass_cidr = std::env::var("LRB_RATE_BYPASS_CIDR")
        .unwrap_or_else(|_| "127.0.0.1/32,::1/128".into());
    let bypass = Arc::new(guard::parse_ip_allowlist(&bypass_cidr));
    let rl = Arc::new(guard::RateLimiter::new(qps, burst, bypass.clone()));

    // Admin IP ACL
    let admin_allow =
        std::env::var("LRB_ADMIN_IP_ALLOW").unwrap_or_else(|_| "127.0.0.1/32,::1/128".into());
    let admin_nets = Arc::new(guard::parse_ip_allowlist(&admin_allow));

    // Public routes
    let public = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/livez", get(api::livez))
        .route("/readyz", get(api::readyz))
        .route("/version", get(version::version))
        .route("/openapi.json", get(openapi::spec))
        .route("/metrics", get(metrics::metrics_handler))
        .route("/head", get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/history/:rid", get(api::history))
        .route("/block/:height", get(api::block))
        .route("/block/:height/mix", get(api::block_mix))
        .route("/economy", get(api::economy))
        .route("/submit_tx", post(api::submit_tx))
        .route("/submit_tx_batch", post(api::submit_tx_batch))
        .route("/debug_canon", post(api::debug_canon))
        .route("/faucet", post(api::faucet));

    // Admin routes
    let admin_routes = Router::new()
        .route("/admin/snapshot", post(admin::snapshot))
        .route("/admin/restore", post(admin::restore))
        .route("/node/info", get(admin::node_info))
        .layer(from_fn_with_state(admin_nets.clone(), guard::admin_ip_gate));

    // Bridge routes
    let bridge_routes = Router::new()
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem", post(bridge::redeem))
        .route("/bridge/verify", post(bridge::verify));

    // Build app
    let mut app = public
        .merge(admin_routes)
        .merge(bridge_routes)
        .with_state(app_state)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(512 * 1024))
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(TraceLayer::new_for_http());

    if rl_enabled {
        app = app.layer(from_fn_with_state(rl.clone(), guard::rate_limit_ip_gate));
    }

    // Start Axum 0.7
    let addr: SocketAddr = std::env::var("LRB_NODE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("logos_node listening on {} (RID={})", addr, rid_b58);
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
