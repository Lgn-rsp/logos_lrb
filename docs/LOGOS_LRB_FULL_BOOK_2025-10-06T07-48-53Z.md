# LOGOS LRB — FULL BOOK (2025-10-06T07-48-53Z)

**Branch:** main  
**Commit:** caa79a7efdfc  
**Remote:** git@github.com:Lgn-rsp/logos_lrb.git

---

## Структура репозитория (чистая, без артефактов)

```text
.
configs
configs/env
core
core/__pycache__
data.sled.bak
data.sled.bak/blobs
docs
docs/LOGOS_LRB_BOOK
docs/snapshots
docs/snapshots/LOGOS_SNAPSHOT_2025-10-05_16-06-03
docs/snapshots/LOGOS_SNAPSHOT_2025-10-05_16-15-36
infra
infra/nginx
infra/systemd
lrb_core
lrb_core/src
modules
node
node/.backup
node/.backup/20250928-060714
node/.backup/20250928-060714/src
node/openapi
node/src
node/src/api
node/src/archive
node/src/openapi
scripts
src
src/bin
src/core
src/utils
tools
tools/bench
tools/bench/go
tools/go_test
tools/load
tools/sdk
tools/sdk/go
tools/sdk/ts
wallet-proxy
www
www/explorer
www/wallet
Документы
```

---

## Рабочие модули и пакеты (Cargo/Python/JS)

```text
.
configs
configs/env
docs
infra/nginx
infra/systemd
lrb_core
modules
node
scripts
tools
www
```

---

## Rust workspace (manifestы)


### `Cargo.toml`

```toml
[workspace]
members = ["lrb_core","node"]
resolver = "2"

[workspace.package]
edition = "2021"
rust-version = "1.78"

[workspace.dependencies]
# web/async
axum = { version = "0.7", features = ["macros"] }
tower = "0.5"
tower-http = { version = "0.5", features = ["cors", "trace"] }
tokio = { version = "1.40", features = ["full"] }

# core utils
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
anyhow = "1.0"
bytes = "1.6"
time = { version = "0.3", features = ["macros"] }

# logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# crypto / hash / codecs
ring = "0.17"
rand = "0.8"
ed25519-dalek = { version = "2.2", default-features = false, features = ["rand_core","std"] }
sha2 = "0.10"
blake3 = "1.5"
hex = "0.4"
base64 = "0.22"
bs58 = "0.5"
uuid = { version = "1.8", features = ["v4"] }
bincode = "1.3"
jsonwebtoken = "9"

# storage / http
sled = "0.34"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls","http2","json"] }
```

### `lrb_core/Cargo.toml`

```toml
[package]
name = "lrb_core"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
bytes = { workspace = true }

# крипто/кодеки/идентификаторы
ring = { workspace = true }
rand = { workspace = true }
ed25519-dalek = { workspace = true }
sha2 = { workspace = true }
blake3 = { workspace = true }
hex = { workspace = true }
base64 = { workspace = true }
bs58 = { workspace = true }
uuid = { workspace = true }
bincode = { workspace = true }

# хранилище/сеть/асинхрон
sled = { workspace = true }
reqwest = { workspace = true }
tokio = { workspace = true }
```

### `node/Cargo.toml`

```toml
[dependencies]
# базовые
axum = { version = "0.7", features = ["macros"] }
tokio = { version = "1.47", features = ["rt-multi-thread","macros","signal"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter","fmt"] }

# внешние, требуемые кодом узла
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
reqwest = { version = "0.12", features = ["json"] }
base64 = "0.22"
ring = "0.17"
constant_time_eq = "0.3"
sled = "0.34"
rand = "0.8"
blake3 = "1.8.2"
hex = "0.4.3"
prometheus = "0.13"
once_cell = "1"

# связь с ядром
lrb_core = { path = "../lrb_core" }
[package]
name    = "logos_node"
version = "0.1.0"
edition = "2021"
```

---

## Конфиги (genesis, logos_config, env-примеры)


### `configs/genesis.yaml`

```
```

### `configs/logos_config.yaml`

```
```

---

## Инфраструктура: systemd и Nginx


### `infra/systemd/exec.conf`

```ini
[Service]
WorkingDirectory=/opt/logos
ExecStart=
ExecStart=/opt/logos/bin/logos_node
```

### `infra/systemd/keys.conf`

```ini
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

# Реальные ключи
Environment=LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
Environment=LRB_BRIDGE_KEY=CHANGE_ME
```

### `infra/systemd/logos-healthcheck.service`

```ini
[Unit]
Description=LOGOS healthcheck (HTTP)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/default/logos-healthcheck
ExecStart=/usr/local/bin/logos_healthcheck.sh
```

### `infra/systemd/logos-node.service`

```ini
[Unit]
Description=LOGOS LRB Node (Axum REST on :8080)
After=network-online.target
Wants=network-online.target

[Service]
User=root
WorkingDirectory=/root/logos_lrb
ExecStart=/root/logos_lrb/target/release/logos_node
Restart=always
RestartSec=2
LimitNOFILE=65536
Environment=LRB_DEV=1

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### `infra/systemd/logos-node@.service`

```ini
[Unit]
Description=LOGOS LRB Node (%i)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
Group=logos
EnvironmentFile=/etc/logos/node-%i.env
WorkingDirectory=/opt/logos
ExecStart=/opt/logos/bin/logos_node
Restart=always
RestartSec=1s
StartLimitIntervalSec=0
LimitNOFILE=1048576

# sandbox
AmbientCapabilities=
CapabilityBoundingSet=
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/logos /etc/logos
ProtectSystem=strict

# лог (journalctl -u logos-node@<inst>)
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### `infra/systemd/logos-snapshot.service`

```ini
[Unit]
Description=LOGOS LRB periodic snapshot

[Service]
Type=oneshot
EnvironmentFile=-/etc/logos/keys.env
ExecStart=/usr/bin/curl -s -H "X-Admin-Key: ${LRB_ADMIN_KEY}" \
  http://127.0.0.1:8080/admin/snapshot-file?name=snap-$(date +%%Y%%m%%dT%%H%%M%%S).json >/dev/null
```

### `infra/systemd/lrb-proxy.service`

```ini
[Unit]
Description=LOGOS Wallet Proxy (FastAPI on :9090)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
WorkingDirectory=/opt/logos/wallet-proxy
EnvironmentFile=/etc/logos/proxy.env
ExecStart=/opt/logos/wallet-proxy/venv/bin/uvicorn app:app --host 0.0.0.0 --port 9090 --workers 2
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `infra/systemd/lrb-scanner.service`

```ini
[Unit]
Description=LOGOS Wallet Scanner (USDT->rLGN)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
WorkingDirectory=/opt/logos/wallet-proxy
EnvironmentFile=/etc/logos/proxy.env
ExecStart=/opt/logos/wallet-proxy/venv/bin/python /opt/logos/wallet-proxy/scanner.py
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### `infra/systemd/override.conf`

```ini
[Service]
# Базовые ENV (правь под себя при необходимости)
Environment=LRB_DEV=1
Environment=LRB_PEERS=
Environment=LRB_QUORUM_N=1
Environment=LRB_VALIDATORS=

# Прод-тюнинг продюсера (можно менять без ребилда)
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615

# rToken-мост (лимит и ключ для бриджа)
Environment=LRB_BRIDGE_MAX_PER_TX=10000000
# Админ для /admin/snapshot
```

### `infra/systemd/runas.conf`

```ini
[Service]
User=logos
Group=logos
# разрешаем запись в каталог данных под sandbox
ReadWritePaths=/var/lib/logos
```

### `infra/systemd/security.conf`

```ini
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true
MemoryDenyWriteExecute=false

# Разрешаем запись ровно туда, где нужно
ReadWritePaths=/var/lib/logos /opt/logos /etc/logos

WorkingDirectory=/opt/logos
ExecStart=
ExecStart=/opt/logos/bin/logos_node
```

### `infra/systemd/tuning.conf`

```ini
[Service]
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615
```

### `infra/systemd/zz-consensus.conf`

```ini
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200
```

### `infra/systemd/zz-keys.conf`

```ini
[Service]
# читаем файл с секретами (на будущее)
EnvironmentFile=-/etc/logos/keys.env

# и ПРЯМО зашиваем реальные значения, чтобы перебить любой override
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key
Environment=LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
Environment=LRB_BRIDGE_KEY=CHANGE_ME
```

### `infra/systemd/zz-logging.conf`

```ini
[Service]
Environment=RUST_LOG=info
```

### `infra/nginx/lrb_wallet.conf`

```nginx
# Глобальные зоны rate-limit (по IP)
limit_req_zone $binary_remote_addr zone=api_zone:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=proxy_zone:10m rate=10r/s;

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name _;

    # --- Безопасные заголовки ---
    add_header X-Frame-Options        SAMEORIGIN       always;
    add_header X-Content-Type-Options nosniff          always;
    add_header Referrer-Policy        strict-origin-when-cross-origin always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # CSP: только self, без inline/CDN. Разрешаем data: для иконок/картинок в UI.
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; connect-src 'self' http: https:; img-src 'self' data:; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none';" always;

    # --- Gzip для JSON/JS/CSS/HTML ---
    gzip on;
    gzip_types text/plain text/css application/json application/javascript application/xml;
    gzip_min_length 1024;

    # --- Редирект корня на кошелёк ---
    location = / {
        return 302 /wallet/;
    }

    # --- Кошелёк (статические файлы) ---
    location /wallet/ {
        root /opt/logos/www;
        index index.html;
        try_files $uri $uri/ /wallet/index.html;
        # кэш статики
        location ~* \.(?:js|css|png|jpg|jpeg|gif|svg|ico)$ {
            expires 30d;
            access_log off;
        }
    }

    # --- LRB node API (Axum на 8080) ---
    location /api/ {
        limit_req zone=api_zone burst=60 nodelay;

        proxy_read_timeout      30s;
        proxy_connect_timeout   5s;
        proxy_send_timeout      15s;

        proxy_set_header Host                $host;
        proxy_set_header X-Real-IP           $remote_addr;
        proxy_set_header X-Forwarded-For     $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto   $scheme;

        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_pass http://127.0.0.1:8080/;
    }

    # --- Wallet Proxy (FastAPI на 9090) ---
    location /proxy/ {
        limit_req zone=proxy_zone burst=20 nodelay;

        proxy_read_timeout      30s;
        proxy_connect_timeout   5s;
        proxy_send_timeout      15s;

        proxy_set_header Host                $host;
        proxy_set_header X-Real-IP           $remote_addr;
        proxy_set_header X-Forwarded-For     $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto   $scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade             $http_upgrade;
        proxy_set_header Connection          $connection_upgrade;

        proxy_pass http://127.0.0.1:9090/;
    }

    # --- Закрыть доступ к скрытому/служебному ---
    location ~ /\.(?!well-known) {
        deny all;
    }
}
```

---

## OpenAPI (узел /node)

**Файл:** node/src/openapi/openapi.json  
**SHA256:** fb4c667edd32c0e7fa917aba8d279912ef82f82cab76375f8a22b568f94d1734

```json
{
  "openapi": "3.0.3",
  "info": { "title": "LOGOS LRB API", "version": "0.1.0" },
  "paths": {
    "/healthz": {
      "get": { "summary": "health", "responses": { "200": { "description": "OK" } } }
    },
    "/livez": {
      "get": { "summary": "liveness", "responses": { "200": { "description": "alive" } } }
    },
    "/readyz": {
      "get": {
        "summary": "readiness",
        "responses": {
          "200": { "description": "ready" },
          "503": { "description": "not ready" }
        }
      }
    },
    "/version": { "get": { "summary": "build info", "responses": { "200": { "description": "OK" } } } },
    "/metrics": { "get": { "summary": "prometheus metrics", "responses": { "200": { "description": "OK" } } } },

    "/head": {
      "get": {
        "summary": "current head heights",
        "responses": {
          "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Head" } } } }
        }
      }
    },

    "/submit_tx": {
      "post": {
        "summary": "submit transaction (Ed25519 verified)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TxIn" } } } },
        "responses": {
          "200": { "description": "accepted", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitResult" } } } },
          "401": { "description": "bad signature" },
          "409": { "description": "nonce reuse" }
        }
      }
    },

    "/submit_tx_batch": {
      "post": {
        "summary": "submit batch of transactions (Ed25519 verified)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitBatchReq" } } } },
        "responses": {
          "200": { "description": "per-item results", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/SubmitBatchItem" } } } } }
        }
      }
    },

    "/archive/blocks": {
      "get": {
        "summary": "recent blocks",
        "parameters": [
          { "name": "limit", "in": "query", "schema": { "type": "integer" } },
          { "name": "before_height", "in": "query", "schema": { "type": "integer" } }
        ],
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/archive/txs": {
      "get": {
        "summary": "recent txs",
        "parameters": [
          { "name": "limit", "in": "query", "schema": { "type": "integer" } },
          { "name": "rid", "in": "query", "schema": { "type": "string" } },
          { "name": "before_ts", "in": "query", "schema": { "type": "integer" } }
        ],
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/archive/history/{rid}": {
      "get": {
        "summary": "history by rid",
        "parameters": [ { "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/archive/tx/{txid}": {
      "get": {
        "summary": "tx by id",
        "parameters": [ { "name": "txid", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "OK" }, "404": { "description": "not found" } }
      }
    },

    "/stake/delegate": {
      "post": {
        "summary": "delegate (compat wrapper)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/stake/undelegate": {
      "post": {
        "summary": "undelegate (compat wrapper)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/stake/claim": {
      "post": {
        "summary": "claim rewards (compat wrapper)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/stake/my/{rid}": {
      "get": {
        "summary": "my delegations + rewards (compat wrapper)",
        "parameters": [ { "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } } ],
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/stake/claim_settle": {
      "post": {
        "summary": "settle reward into ledger",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimSettle" } } } },
        "responses": { "200": { "description": "OK" } }
      }
    },

    "/bridge/deposit_json": {
      "post": {
        "summary": "bridge deposit (mTLS + HMAC)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeDeposit" } } } },
        "responses": { "200": { "description": "idempotent OK" }, "202": { "description": "queued/retry" }, "401": { "description": "unauthorized (key/HMAC/nonce)" } }
      }
    },
    "/bridge/redeem_json": {
      "post": {
        "summary": "bridge redeem (mTLS + HMAC)",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeRedeem" } } } },
        "responses": { "200": { "description": "ok" }, "202": { "description": "queued/retry" }, "401": { "description": "unauthorized (key/HMAC/nonce)" } }
      }
    }
  },

  "components": {
    "schemas": {
      "Head": {
        "type": "object",
        "required": ["height","finalized"],
        "properties": {
          "height":   { "type": "integer", "format": "uint64" },
          "finalized":{ "type": "integer", "format": "uint64" }
        }
      },
      "Balance": {
        "type": "object",
        "required": ["rid","balance","nonce"],
        "properties": {
          "rid":     { "type": "string" },
          "balance": { "type": "integer", "format": "uint128" },
          "nonce":   { "type": "integer", "format": "uint64" }
        }
      },
      "TxIn": {
        "type": "object",
        "required": ["from","to","amount","nonce","sig_hex"],
        "properties": {
          "from":    { "type": "string", "description": "base58(pubkey)" },
          "to":      { "type": "string" },
          "amount":  { "type": "integer", "format": "uint64" },
          "nonce":   { "type": "integer", "format": "uint64" },
          "sig_hex": { "type": "string" },
          "memo":    { "type": "string", "nullable": true }
        }
      },
      "SubmitResult": {
        "type": "object",
        "required": ["ok","info"],
        "properties": {
          "ok":   { "type": "boolean" },
          "txid": { "type": "string", "nullable": true },
          "info": { "type": "string" }
        }
      },
      "SubmitBatchReq": {
        "type": "object",
        "required": ["txs"],
        "properties": {
          "txs": { "type": "array", "items": { "$ref": "#/components/schemas/TxIn" } }
        }
      },
      "SubmitBatchItem": {
        "type": "object",
        "required": ["ok","info","index"],
        "properties": {
          "ok":    { "type": "boolean" },
          "txid":  { "type": "string", "nullable": true },
          "info":  { "type": "string" },
          "index": { "type": "integer" }
        }
      },
      "StakeAction": {
        "type": "object",
        "required": ["rid"],
        "properties": {
          "rid":       { "type": "string" },
          "validator": { "type": "string" },
          "amount":    { "type": "integer", "format": "uint64", "nullable": true }
        }
      },
      "ClaimSettle": {
        "type": "object",
        "required": ["rid","amount"],
        "properties": {
          "rid":    { "type": "string" },
          "amount": { "type": "integer", "format": "uint64" }
        }
      },
      "BridgeDeposit": {
        "type": "object",
        "required": ["rid","amount","ext_txid"],
        "properties": {
          "rid":      { "type": "string" },
          "amount":   { "type": "integer", "format": "uint64" },
          "ext_txid": { "type": "string" }
        }
      },
      "BridgeRedeem": {
        "type": "object",
        "required": ["rid","amount","ext_txid"],
        "properties": {
          "rid":      { "type": "string" },
          "amount":   { "type": "integer", "format": "uint64" },
          "ext_txid": { "type": "string" }
        }
      }
    }
  }
}
```

---

## Метрики и health-ручки (докстринги/описания)

    node/src/metrics.rs:19:    register_int_counter_vec!("logos_http_requests_total","HTTP reqs",&["method","path","status"]).unwrap()
    node/src/metrics.rs:22:    register_histogram_vec!("logos_http_duration_seconds","HTTP latency",&["method","path","status"],
    node/src/metrics.rs:27:static BLOCKS_TOTAL: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("logos_blocks_produced_total","Blocks total").unwrap());
    node/src/metrics.rs:28:static HEAD_HEIGHT: Lazy<IntGauge>    = Lazy::new(|| register_int_gauge!("logos_head_height","Head").unwrap());
    node/src/metrics.rs:29:static FINAL_HEIGHT: Lazy<IntGauge>   = Lazy::new(|| register_int_gauge!("logos_finalized_height","Finalized").unwrap());
    node/src/metrics.rs:32:static TX_ACCEPTED: Lazy<IntCounter> = Lazy::new(|| register_int_counter!("logos_tx_accepted_total","Accepted tx").unwrap());
    node/src/metrics.rs:34:    register_int_counter_vec!("logos_tx_rejected_total","Rejected tx",&["reason"]).unwrap()
    node/src/metrics.rs:39:    register_int_counter_vec!("logos_bridge_ops_total","Bridge ops",&["kind","status"]).unwrap()
    node/src/metrics.rs:43:static ARCHIVE_QUEUE: Lazy<IntGauge> = Lazy::new(|| register_int_gauge!("logos_archive_queue","Archive queue depth").unwrap());

---

## Скрипты деплоя (канон)


### `scripts/bootstrap_node.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
DOMAIN="${DOMAIN:-example.com}"
INSTANCE="${INSTANCE:-a}"

sudo apt-get update -y
sudo apt-get install -y git curl jq build-essential pkg-config libssl-dev nginx

/usr/bin/id logos >/dev/null 2>&1 || sudo useradd -r -m -d /var/lib/logos -s /usr/sbin/nologin logos
sudo mkdir -p /opt/logos /etc/logos /var/lib/logos /opt/logos/www/wallet

cd "$(dirname "$0")/.."
cargo build --release -p logos_node
sudo cp ./target/release/logos_node /opt/logos/logos_node
sudo chown logos:logos /opt/logos/logos_node
sudo chmod 755 /opt/logos/logos_node

sudo cp ./infra/systemd/logos-node@.service /etc/systemd/system/logos-node@.service
sudo systemctl daemon-reload

sudo cp ./infra/nginx/logos-api-lb.conf.example /etc/nginx/sites-available/logos-api-lb.conf
sudo sed -i "s/YOUR_DOMAIN/${DOMAIN}/" /etc/nginx/sites-available/logos-api-lb.conf
sudo ln -sf /etc/nginx/sites-available/logos-api-lb.conf /etc/nginx/sites-enabled/logos-api-lb.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

sudo cp -r ./www/wallet/* /opt/logos/www/wallet/
sudo chown -R logos:logos /opt/logos/www

if [ ! -f "/etc/logos/node-${INSTANCE}.env" ]; then
  sudo cp ./configs/env/node.env.example "/etc/logos/node-${INSTANCE}.env"
  echo ">>> EDIT /etc/logos/node-${INSTANCE}.env (LRB_NODE_SK_HEX/LRB_ADMIN_KEY/LRB_WALLET_ORIGIN)"
fi

sudo systemctl enable --now "logos-node@${INSTANCE}"
systemctl --no-pager status "logos-node@${INSTANCE}"

echo "API: http://127.0.0.1:8080   Wallet: http://${DOMAIN}/wallet/"
```

### `scripts/collect_and_push.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="/root/logos_lrb"
GIT_REMOTE="${GIT_REMOTE:-origin}"
GIT_BRANCH="${GIT_BRANCH:-main}"
INCLUDE_SNAPSHOT="${INCLUDE_SNAPSHOT:-0}"

echo "[i] collecting from live system → $REPO_ROOT"
cd "$REPO_ROOT"

# .gitignore (если нет)
[ -f .gitignore ] || cat > .gitignore <<'EOF'
target/
**/target/
node_modules/
dist/
.DS_Store
*.swp
*.swo
/etc/logos/*.env
*.pem
*.key
*.crt
*.p12
/var/lib/logos/
/var/run/logos_health.json
/usr/local/bin/lrb_bench*
/usr/local/bin/logos_healthcheck.sh
/etc/letsencrypt/
*.log
/var/log/nginx/*.log
www/wallet/*.map
tools/**/go/bin/
EOF

# каталоги в репо
mkdir -p configs/env infra/systemd infra/nginx scripts tools/bench/go www/wallet docs

# wallet → www/wallet
if [ -d /opt/logos/www/wallet ]; then
  rsync -a --delete /opt/logos/www/wallet/ www/wallet/
  echo "[i] wallet synced"
fi

# systemd → infra/systemd
[ -f /etc/systemd/system/logos-node@.service ]       && cp -f /etc/systemd/system/logos-node@.service        infra/systemd/
[ -f /etc/systemd/system/logos-healthcheck.service ] && cp -f /etc/systemd/system/logos-healthcheck.service   infra/systemd/
[ -f /etc/systemd/system/logos-healthcheck.timer ]   && cp -f /etc/systemd/system/logos-healthcheck.timer     infra/systemd/

# nginx → infra/nginx (example)
[ -f /etc/nginx/sites-available/logos-api-lb.conf ] && cp -f /etc/nginx/sites-available/logos-api-lb.conf infra/nginx/logos-api-lb.conf.example

# healthcheck → scripts (если установлен в /usr/local/bin)
if [ -f /usr/local/bin/logos_healthcheck.sh ]; then
  cp -f /usr/local/bin/logos_healthcheck.sh scripts/logos_healthcheck.sh
  chmod +x scripts/logos_healthcheck.sh
fi

# env → *.example (обезличиваем секреты)
mkdir -p configs/env
shopt -s nullglob
for f in /etc/logos/node-*.env; do
  bn="$(basename "$f")"
  sed -E \
    -e 's/^(LRB_NODE_SK_HEX)=.*/\1=CHANGE_ME_64_HEX/' \
    -e 's/^(LRB_ADMIN_KEY)=.*/\1=CHANGE_ADMIN_KEY/' \
    -e 's/^(LRB_BRIDGE_KEY)=.*/\1=CHANGE_ME/' \
    "$f" > "configs/env/${bn}.example"
  echo "[i] env example: configs/env/${bn}.example"
done
# общий пример, если ничего не найдено
if [ -z "$(ls -1 configs/env/*.example 2>/dev/null || true)" ]; then
cat > configs/env/node.env.example <<'EEX'
LRB_NODE_SK_HEX=CHANGE_ME_64_HEX
LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
LRB_BRIDGE_KEY=CHANGE_ME
LRB_DATA_DIR=/var/lib/logos
LRB_NODE_LISTEN=0.0.0.0:8080
LRB_WALLET_ORIGIN=http://localhost
LRB_RATE_QPS=20
LRB_RATE_BURST=40
LRB_RATE_BYPASS_CIDR=127.0.0.1/32,::1/128
LRB_ENABLE_FAUCET=0
LRB_ADMIN_IP_ALLOW=127.0.0.1/32,::1/128
EEX
fi

# snapshots (опционально)
if [ "${INCLUDE_SNAPSHOT}" = "1" ]; then
  mkdir -p snapshots
  cp -f /root/logos_snapshot/*.txt snapshots/ 2>/dev/null || true
fi

# git add/commit/push
git add -A
if ! git diff --cached --quiet; then
  git commit -m "sync(live): full system snapshot (code+infra+wallet+scripts), env → *.example"
else
  echo "[i] nothing to commit"
fi

# пуш
git push "${GIT_REMOTE}" "${GIT_BRANCH}"
echo "[✓] pushed to ${GIT_REMOTE}/${GIT_BRANCH}"
```

### `scripts/logos_healthcheck.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
STATE_FILE="/var/run/logos_health.json"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT

# Метрика: время ответа healthz
START=$(date +%s%3N)
if ! curl -sf "$BASE/healthz" -o "$TMP" >/dev/null; then
  MSG="LOGOS: /healthz FAIL at $(date -u +%FT%TZ)"
  logger -t logos_health "$MSG"
  [ -n "${TG_TOKEN:-}" ] && curl -s "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
     -d chat_id="${TG_CHAT_ID}" -d text="$MSG" >/dev/null || true
  exit 1
fi
RT=$(( $(date +%s%3N) - START ))

# Высота
HEAD_JSON=$(curl -sf "$BASE/head")
HEIGHT=$(echo "$HEAD_JSON" | jq -r '.height' 2>/dev/null || echo 0)

LAST_H=0
LAST_TS=0
if [ -f "$STATE_FILE" ]; then
  LAST_H=$(jq -r '.height // 0' "$STATE_FILE" 2>/dev/null || echo 0)
  LAST_TS=$(jq -r '.ts_ms // 0' "$STATE_FILE" 2>/dev/null || echo 0)
fi

TS_MS=$(date +%s%3N)
printf '{"ts_ms":%s,"height":%s,"rt_ms":%s}\n' "$TS_MS" "$HEIGHT" "$RT" > "$STATE_FILE"

# Правила алертов
ALERT=""
[ "$RT" -gt 1500 ] && ALERT="slow healthz: ${RT}ms"
if [ -n "$LAST_TS" ] && [ $((TS_MS - LAST_TS)) -gt 300000 ]; then
  # если 5 минут прошло и высота не менялась (и была >0)
  if [ "$HEIGHT" -eq "$LAST_H" ] && [ "$HEIGHT" -gt 0 ]; then
    ALERT="${ALERT} height stuck at ${HEIGHT}"
  fi
fi

if [ -n "$ALERT" ]; then
  MSG="LOGOS ALERT: ${ALERT} at $(date -u +%FT%TZ)"
  logger -t logos_health "$MSG"
  if [ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHAT_ID:-}" ]; then
    curl -s "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
       -d chat_id="${TG_CHAT_ID}" -d text="$MSG" >/dev/null || true
  fi
fi

exit 0
```

---

## Суммы и размеры ключевых артефактов

```text
node/src/openapi/openapi.json                   8704  fb4c667edd32c0e7fa917aba8d279912ef82f82cab76375f8a22b568f94d1734
configs/genesis.yaml                               0  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
configs/logos_config.yaml                          0  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
