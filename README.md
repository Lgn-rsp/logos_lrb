# LOGOS Resonance Blockchain — Monorepo

Состав:
- `lrb_core/`  — ядро (Rust)
- `node/`      — узел (Axum REST + gossip)
- `modules/`   — модульные компоненты
- `tools/`     — e2e и нагрузочные тесты (Go)
- `www/wallet/` — Web Wallet (MVP)
- `wallet-proxy/` — FastAPI proxy + scanner
- `infra/systemd`, `infra/nginx` — юниты/конфиги (без секретов)
- `configs/*.example` — примеры окружения

## Быстрый старт
1) Rust/Go/Python3.12
2) `cargo build --release -p logos_node`
3) Настрой ENV по `configs/keys.env.example` (секреты не коммить)
4) Подними systemd-юниты из `infra/systemd` (редактируй пути/ENV)
5) Nginx-site из `infra/nginx/lrb_wallet.conf` (wallet + proxy)
