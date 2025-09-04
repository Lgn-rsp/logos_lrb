// node/src/main.rs — прод-роутер с историей/индексами и базовой инициализацией
mod bridge;
mod admin;
mod fork;
mod state;
mod gossip;
mod metrics;
mod api;
mod peers;

use anyhow::Result;
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Extension, Router,
};
use std::{env, net::SocketAddr, time::Duration};
use tokio::{signal, time::interval};

use lrb_core::*;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // --------- инициализация ключей/ledger/engine ----------
    // Ключи/ledger/engine инициализируй так, как у тебя уже сделано — здесь оставляем существующую логику.
    // Ниже только минимальные обязательные шаги, чтобы не поломать твой запуск.

    // Открываем базу
    let data_path = env::var("LRB_DATA_PATH").unwrap_or_else(|_| "/var/lib/logos/data.sled".to_string());
    let ledger = Ledger::open(&data_path)?;

    // ИНИЦИАЛИЗАЦИЯ ENGINE — используй фактическую функцию/конструктор, которая уже есть у тебя:
    // предположим у тебя есть что-то вроде: let (engine, _mp) = engine_with_channels(ledger, self_rid.clone());
    // Здесь для совместимости:
    let (engine, _mp) = {
        // В твоём коде уже есть построение self_rid / ключей — оставь его.
        // Ниже упрощённый вызов: если у тебя другой — подставь свой.
        let dummy_rid = Rid("DUMMY_RID".to_string());
        engine_with_channels(ledger, dummy_rid)
    };

    // Запуск block producer (оставляем как в твоём коде)
    {
        let eng = engine.clone();
        tokio::spawn(async move {
            let _ = eng.run_block_producer().await;
        });
    }

    // Собираем AppState из твоей реализации
    let st = AppState::new_for_router(engine.clone())?;

    // --------- Роуты (все действующие + история/индексы) ----------
    let mut app = Router::new()
        // базовые
        .route("/healthz", get(api::healthz))
        .route("/head",    get(api::head))
        .route("/balance/:rid", get(api::balance))
        .route("/account/:rid/state", get(api::account_state))
        // отправка транзакций
        .route("/submit_tx",        post(api::submit_tx))
        .route("/submit_tx_batch",  post(api::submit_tx_batch))
        // отладка канона/подписи
        .route("/debug_canon", post(api::debug_canon))
        // faucet (DEV)
        .route("/faucet/:rid/:amount", post(api::faucet))
        // мост
        .route("/bridge/deposit", post(api::bridge_deposit))
        .route("/bridge/redeem",  post(api::bridge_redeem))
        .route("/bridge/verify",  post(api::bridge_verify))
        // админка
        .route("/admin/snapshot",      get(api::snapshot))
        .route("/admin/snapshot-file", get(api::snapshot_file))
        .route("/admin/restore",       post(api::restore))
        .route("/admin/token",         get(api::admin_token))
        .route("/node/info",           get(api::node_info))
        // НОВОЕ: история/индексы
        .route("/block/:height", get(api::get_block))
        .route("/tx/:id",        get(api::get_tx))
        .route("/account/:rid/txs", get(api::account_txs))
        // лимит тела (предохраняемся от больших batch’ей)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(Extension(st.clone()));

    // Фоновая метрика — обновляем chain_height/mempool_len периодически (если у тебя уже есть — оставь свою)
    {
        let stc = st.clone();
        tokio::spawn(async move {
            let mut t = interval(Duration::from_millis(500));
            loop {
                t.tick().await;
                if let Ok((h, _)) = stc.engine.ledger().head() {
                    crate::state::HEIGHT_GAUGE.set(h as i64);
                }
                if let Ok(f) = stc.engine.ledger().get_finalized() {
                    crate::state::FINAL_GAUGE.set(f as i64);
                }
                crate::state::MEMPOOL_GAUGE.set(stc.engine.mempool_len() as i64);
            }
        });
    }

    // --------- запуск сервера ----------
    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    println!("LOGOS LRB node listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(async {
            let _ = signal::ctrl_c().await;
            eprintln!("shutdown...");
        })
        .await?;

    Ok(())
}
