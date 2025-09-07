use axum::{routing::{get, post}, Router};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::sync::Arc;

mod api;
mod bridge;
mod admin;
mod gossip;
mod state;
mod peers;
mod guard;
mod metrics;
mod version;
mod storage;
mod auth;
mod archive;
mod openapi; // <—

fn router(app_state: Arc<state::AppState>) -> Router {
    Router::new()
        // public
        .route("/healthz", get(api::healthz))
        .route("/head", get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/submit_tx", post(api::submit_tx))
        .route("/economy", get(api::economy))
        .route("/history/:rid", get(api::history))
        .route("/archive/history/:rid", get(api::archive_history))
        .route("/archive/tx/:txid",     get(api::archive_tx))
        .route("/version", get(version::get))
        .route("/metrics", get(metrics::prometheus))
        .route("/openapi.json", get(openapi::serve)) // <— контракт
        // bridge/admin
        .route("/bridge/deposit", post(bridge::deposit))
        .route("/bridge/redeem",  post(bridge::redeem))
        .route("/bridge/verify",  post(bridge::verify))
        .route("/admin/set_balance", post(admin::set_balance))
        .route("/admin/bump_nonce",  post(admin::bump_nonce))
        .route("/admin/set_nonce",   post(admin::set_nonce))
        .route("/admin/mint",        post(admin::mint))
        .route("/admin/burn",        post(admin::burn))
        .with_state(app_state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(axum::middleware::from_fn(guard::rate_limit_mw))
                .layer(axum::middleware::from_fn(metrics::track))
        )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    auth::assert_secrets_on_start().expect("unsafe or missing secrets");

    let app_state = Arc::new(state::AppState::new()?);
    if let Some(ar) = crate::archive::Archive::new_from_env().await {
        unsafe { let p = Arc::as_ptr(&app_state) as *mut state::AppState; (*p).archive = Some(ar); }
        tracing::info!("archive backend initialized");
    } else {
        tracing::warn!("archive disabled (no LRB_ARCHIVE_URL / LRB_ARCHIVE_PATH)");
    }

    let addr = state::bind_addr();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("logos_node listening on {}", addr);
    axum::serve(listener, router(app_state)).await?;
    Ok(())
}
