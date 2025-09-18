use axum::{routing::{get, post}, Router};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::sync::Arc;
use tracing::{info, warn};

mod api;
mod bridge;
mod bridge_journal;
mod admin;
mod gossip;
mod state;
mod peers;
mod guard;
mod metrics;
mod version;
mod storage;
mod archive;
mod openapi;
mod auth;
mod stake;
mod wallet;
mod producer;

fn router(app_state: Arc<state::AppState>) -> Router {
    Router::new()
        .route("/healthz", get(api::healthz))
        .route("/head",    get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx", post(api::submit_tx))
        .route("/submit_tx_batch", post(api::submit_tx_batch))
        .route("/economy", get(api::economy))
        .route("/history/:rid", get(api::history))
        // archive
        .route("/archive/blocks", get(api::archive_blocks))
        .route("/archive/txs",    get(api::archive_txs))
        .route("/archive/history/:rid", get(api::archive_history))
        .route("/archive/tx/:txid",     get(api::archive_tx))
        // staking wrappers
        .route("/stake/delegate",   post(api::stake_delegate))
        .route("/stake/undelegate", post(api::stake_undelegate))
        .route("/stake/claim",      post(api::stake_claim))
        .route("/stake/my/:rid",    get(api::stake_my))
        // bridge (durable)
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem",  post(bridge::redeem))
        .route("/health/bridge",  get(bridge::health))
        // version/metrics/openapi
        .route("/version",     get(version::get))
        .route("/metrics",     get(metrics::prometheus))
        .route("/openapi.json",get(openapi::serve))
        // admin
        .route("/admin/set_balance", post(admin::set_balance))
        .route("/admin/bump_nonce",  post(admin::bump_nonce))
        .route("/admin/set_nonce",   post(admin::set_nonce))
        .route("/admin/mint",        post(admin::mint))
        .route("/admin/burn",        post(admin::burn))
        // legacy routes
        .merge(wallet::routes())
        .merge(stake::routes())
        .with_state(app_state)
        .layer(ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(axum::middleware::from_fn(guard::rate_limit_mw))
            .layer(axum::middleware::from_fn(metrics::track)))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    auth::assert_secrets_on_start().expect("secrets missing");

    let app_state = Arc::new(state::AppState::new()?);

    if let Some(ar) = crate::archive::Archive::new_from_env().await {
        unsafe { let p = Arc::as_ptr(&app_state) as *mut state::AppState; (*p).archive = Some(ar); }
        info!("archive backend initialized");
    } else { warn!("archive disabled"); }

    info!("producer start");
    let _producer = producer::run(app_state.clone());

    // start bridge retry worker
    tokio::spawn(bridge::retry_worker(app_state.clone()));

    let addr = state::bind_addr();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("logos_node listening on {addr}");
    axum::serve(listener, router(app_state)).await?;
    Ok(())
}
