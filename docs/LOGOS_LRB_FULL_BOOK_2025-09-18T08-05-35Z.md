# LOGOS LRB — FULL BOOK (prod snapshot)

Срез **рабочей прод-версии** LOGOS LRB:
- Axum 0.7 стек
- строгая проверка подписи Ed25519 в /submit_tx
- BLAKE3-хэш блока (prev|height|ts)
- Prometheus-метрики: HTTP, TX (accepted/rejected), blocks, chain (head/final)

Generated (UTC): 2025-09-18T08-05-35Z

## Workspace / Cargo

### Cargo.toml

~~~toml
[workspace]
members  = ["lrb_core", "node"]
resolver = "2"

[workspace.package]
edition      = "2021"
rust-version = "1.78"

[workspace.dependencies]
axum       = { version = "0.7.9", features = ["macros", "json"] }
tower      = "0.4.13"
tower-http = { version = "0.5.2", features = ["trace", "cors", "compression-gzip"] }
tokio      = { version = "1.40", features = ["full"] }
reqwest    = { version = "0.12", default-features = false, features = ["rustls-tls", "http2", "json"] }

serde               = { version = "1.0", features = ["derive"] }
serde_json          = "1.0"
anyhow              = "1.0"
thiserror           = "1.0"
once_cell           = "1.19"
dashmap             = "5.5"
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["env-filter", "fmt"] }
bytes               = "1.6"

hex              = "0.4"
base64           = "0.21"
bs58             = "0.4"
sha2             = "0.10"
blake3           = "1.5"
ed25519-dalek    = { version = "2.2", default-features = false, features = ["rand_core"] }
rand             = "0.8"
ring             = "0.17"
uuid             = { version = "1.8", features = ["v4"] }
bincode          = "1.3"
jsonwebtoken     = "9"

sled             = "0.34"
deadpool-postgres= "0.12"
tokio-postgres   = { version = "0.7", features = ["with-uuid-1"] }
rusqlite         = { version = "0.32", features = ["bundled"] }
r2d2_sqlite      = "0.25"

parking_lot = "0.12"
ipnet       = "2.9"
prometheus  = "0.13"

[profile.release]
opt-level       = 3
lto             = "fat"
codegen-units   = 1
panic           = "abort"
incremental     = false
strip           = "symbols"

~~~

## lrb_core (core)

### lrb_core/Cargo.toml

~~~toml
[package]
name = "lrb_core"
version = "0.1.0"
edition = "2021"
description = "LOGOS LRB core: ledger + engine + types"
license = "Apache-2.0"

[dependencies]
anyhow = "1"
thiserror = "1"

# крипта/хэш
ed25519-dalek = { version = "2.1.1", default-features = false, features = ["std"] }
blake3 = "1.5"
sha2 = "0.10"          # ← НУЖЕН ДЛЯ ledger.rs (txid = sha256)

# кодеки/утилиты
base64 = "0.22"
hex = "0.4"            # ← НУЖЕН ДЛЯ ledger.rs
bs58 = "0.4"
uuid  = { version = "1", features = ["v4"] }

# хранилище/сериализация
sled = "0.34"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
once_cell = "1"

# движок/асинхронщина/логгинг
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time"] }
tracing = "0.1"
parking_lot = "0.12"

~~~

