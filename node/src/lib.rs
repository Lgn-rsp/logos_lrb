//! LOGOS node library crate — корневые модули и реэкспорты

pub mod api;
pub mod admin;
pub mod archive;
pub mod auth;
pub mod bridge;
pub mod bridge_journal;      // ← добавили модуль журнала моста
pub mod gossip;
pub mod guard;
pub mod metrics;
pub mod openapi;
pub mod peers;
pub mod producer;
pub mod state;
pub mod stake;
pub mod storage;
pub mod version;
pub mod wallet;

// точечные реэкспорты (по мере надобности)
pub use metrics::prometheus as metrics_prometheus;
pub use version::get as version_get;
