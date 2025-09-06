# LOGOS LRB — Книга системы

---

## Глава 1. Архитектура репозитория

### 1. Дерево `/root/logos_lrb`
/root/logos_lrb
├── Cargo.toml / README.md
├── lrb_core/                  # Rust-ядро L1
│   └── src/{ledger.rs, rcp_engine.rs, phase_integrity.rs,
│            dynamic_balance.rs, spam_guard.rs, resonance.rs,
│            phase_consensus.rs, phase_filters.rs, quorum.rs, types.rs,…}
├── node/                      # Узел (Axum REST + gossip + метрики)
│   ├── Cargo.toml
│   ├── openapi/openapi.json
│   └── src/{main.rs, api.rs, admin.rs, bridge.rs, guard.rs,
│            gossip.rs, state.rs, peers.rs, fork.rs, metrics.rs, …}
├── modules/                   # uplink_*, external_phase_*, parser/…
├── www/
│   ├── wallet/                # Web Wallet (IndexedDB+WebCrypto)
│   └── explorer/              # Explorer (inline-JS, самодостаточный)
├── tools/                     # bench v4, e2e/load, SDK (TS)
├── scripts/                   # bootstrap_node.sh, healthcheck.sh, …
├── core/                      # аналитика/симуляции (py)
├── wallet-proxy/              # вспомогательные утилиты (py)
└── configs/                   # env-шаблоны, genesis.yaml

### 2. Роли директорий
- **lrb_core/** — ядро L1: ledger (sled), mempool, spam_guard, dynamic_balance, фазовые фильтры, Σ(t), финализация quorum=1.
- **node/** — REST-узел: `/healthz`, `/head`, `/balance/:rid`, `/submit_tx`, `/submit_tx_batch`, `/bridge/*`, `/economy`, `/history/:rid`, `/openapi.json`.
- **modules/** — uplink, external_phase, ritual_engine, analytics.
- **www/wallet/** — кошелёк: RID+пароль, AES-GCM (PBKDF2), Ed25519 (WebCrypto), batch-tx.
- **www/explorer/** — explorer: поиск RID/блока/nonce, история, последние блоки, автообновление.
- **tools/** — bench v4 (~10k tx/s), SDK (TS), e2e/load.
- **scripts/** — утилиты запуска/снапшотов.
- **configs/** — env и genesis.

---

## Глава 2. Инфраструктура (вне репозитория)

### 2.1 Пути/данные
/opt/logos/www/                 # прод-статика (wallet, explorer)  
/var/lib/logos/data.sled        # база блокчейна (sled)  
/var/lib/logos/node_key         # ключ ноды (если используется)  

### 2.2 systemd
/etc/systemd/system/logos-node.service  
/etc/systemd/system/logos-node.service.d/  
  ├─ data.conf        # LRB_DATA_PATH=/var/lib/logos/data.sled  
  ├─ zz-keys.conf     # ключи / ENV  
  ├─ ratelimit.conf   # лимиты QPS/Burst, bypass localhost  
  ├─ runas.conf       # user/group logos  
  ├─ security.conf    # ProtectSystem, NoNewPrivileges  
  └─ override.conf    # расширения  

### 2.3 nginx + TLS
/etc/nginx/conf.d/  
  ├─ 00_redirect_80.conf   # redirect 80→443  
  └─ 10_lrb_https.conf     # HTTPS, CSP, /api, /wallet, /explorer  

TLS: /etc/letsencrypt/live/<домен>/{fullchain.pem, privkey.pem}  

**CSP**:  
`default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'self'`  

**/explorer/**:  
`Cache-Control: no-store, no-cache, must-revalidate, max-age=0`  
`Pragma: no-cache`  
`Expires: 0`  

### 2.4 Мониторинг
- Prometheus: /etc/prometheus/prometheus.yml  
- Rules: /etc/prometheus/rules/lrb_core.yml  
- Alertmanager: /etc/alertmanager/alertmanager.yml (+ secrets.env: TELEGRAM_BOT_TOKEN, CHAT_ID)  
- Grafana: /etc/grafana/provisioning/{datasources,dashboards}/  
- Dashboards: /var/lib/grafana/dashboards/lrb_core.json  
- NodeExporter: 9100, Prometheus:9094, Alertmanager:9093, Grafana:3000  

### 2.5 Порты
| Компонент    | Порт | Комментарий           |
|--------------|------|-----------------------|
| nginx HTTPS  | 443  | wallet, explorer, API |
| nginx HTTP   | 80   | redirect → 443        |
| logos_node   | 8080 | REST (за nginx)       |
| prometheus   | 9094 |                       |
| alertmanager | 9093 |                       |
| node_exporter| 9100 |                       |
| grafana      | 3000 |                       |

---

## Глава 3. Функционал

- **Ledger**: sled, mempool, spam_guard, dynamic_balance.  
- **Consensus**: Σ(t), slot producer, финализация (quorum=1).  
- **Filters**: фазовые, phase_integrity.  
- **Crypto**: XChaCha20-Poly1305 (AEAD).  
- **REST**: healthz, head, balance, submit_tx, bridge, economy, history, openapi.json.  
- **Bridge**: idempotency, tickets, verify.  
- **Gossip**: блоки, голоса, Σ-подписи.  
- **Wallet**: WebCrypto, IndexedDB, batch-tx.  
- **Explorer**: история, поиск RID/блока, автообновление.  
- **Monitoring**: Prometheus/Grafana, alerting → Telegram.  
- **Bench v4**: ~10.6k tx/s.  

---

## Глава 4. Что работает сейчас

✔ Ядро (ledger, mempool, spam_guard, dynamic_balance).  
✔ REST-узел Axum 0.7 (все базовые маршруты).  
✔ Gossip, Σ(t) подписи.  
✔ rToken-мост (боевой, idempotent).  
✔ Экономика: hard-cap 81M, supply= minted−burned.  
✔ Инфра: systemd sandbox, nginx+TLS, healthcheck.timer.  
✔ Web Wallet (MVP), Explorer (inline-JS).  
✔ Prometheus+Grafana+Alertmanager+Telegram.  
✔ Bench v4: 10.6k tx/s.  

---

## Глава 5. Доработки до продакшена

1. Кворум >1, распределённый fork-choice.  
2. История блоков/tx (архив, индексы, полный explorer).  
3. Unit/chaos-тесты ядра.  
4. Мобильный кошелёк (Flutter).  
5. Web Wallet → WebCrypto+IndexedDB полностью.  
6. OpenAPI/SDK автоген (Go/Rust).  
7. Grafana-дашборды и оповещения.  
8. REST-защита: ACL/DoS guard с логированием атак.  

---

⚡ **Цель**: LOGOS LRB — резонансный блокчейн продакшен-уровня, готовый к миллионам пользователей, с web/mobile кошельком, безопасный и масштабируемый.
