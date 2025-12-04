# LOGOS Deploy + Infra Snapshot

_Автогенерация: `2025-12-01 14:16:33Z`_


## Deploy/Bootstrap Scripts (scripts/)

`/root/logos_lrb/scripts`


---

### `/root/logos_lrb/scripts/bootstrap_node.sh`

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

---

### `/root/logos_lrb/scripts/collect_and_push.sh`

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

---

### `/root/logos_lrb/scripts/logos_healthcheck.sh`

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

## Infra (infra/)

`/root/logos_lrb/infra`


---

### `/root/logos_lrb/infra/nginx/lrb_wallet.conf`

```ini
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

### `/root/logos_lrb/infra/systemd/exec.conf`

```ini
[Service]
WorkingDirectory=/opt/logos
ExecStart=
ExecStart=/opt/logos/bin/logos_node

```

---

### `/root/logos_lrb/infra/systemd/keys.conf`

```ini
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key

# Реальные ключи
Environment=LRB_ADMIN_KEY=CHANGE_ADMIN_KEY
Environment=LRB_BRIDGE_KEY=CHANGE_ME

```

---

### `/root/logos_lrb/infra/systemd/logos-healthcheck.service`

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

---

### `/root/logos_lrb/infra/systemd/logos-node.service`

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

---

### `/root/logos_lrb/infra/systemd/logos-node@.service`

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

---

### `/root/logos_lrb/infra/systemd/logos-snapshot.service`

```ini
[Unit]
Description=LOGOS LRB periodic snapshot

[Service]
Type=oneshot
EnvironmentFile=-/etc/logos/keys.env
ExecStart=/usr/bin/curl -s -H "X-Admin-Key: ${LRB_ADMIN_KEY}" \
  http://127.0.0.1:8080/admin/snapshot-file?name=snap-$(date +%%Y%%m%%dT%%H%%M%%S).json >/dev/null

```

---

### `/root/logos_lrb/infra/systemd/lrb-proxy.service`

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

---

### `/root/logos_lrb/infra/systemd/lrb-scanner.service`

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

---

### `/root/logos_lrb/infra/systemd/override.conf`

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

---

### `/root/logos_lrb/infra/systemd/runas.conf`

```ini
[Service]
User=logos
Group=logos
# разрешаем запись в каталог данных под sandbox
ReadWritePaths=/var/lib/logos

```

---

### `/root/logos_lrb/infra/systemd/security.conf`

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

---

### `/root/logos_lrb/infra/systemd/tuning.conf`

```ini
[Service]
Environment=LRB_SLOT_MS=500
Environment=LRB_MAX_BLOCK_TX=10000
Environment=LRB_MEMPOOL_CAP=100000
Environment=LRB_MAX_AMOUNT=18446744073709551615

```

---

### `/root/logos_lrb/infra/systemd/zz-consensus.conf`

```ini
[Service]
Environment=LRB_VALIDATORS=5Ropc1AQhzuB5uov9GJSumGWZGomE8CTvCyk8D1q1pHb
Environment=LRB_QUORUM_N=1
Environment=LRB_SLOT_MS=200

```

---

### `/root/logos_lrb/infra/systemd/zz-keys.conf`

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

---

### `/root/logos_lrb/infra/systemd/zz-logging.conf`

```ini
[Service]
Environment=RUST_LOG=info

```

## systemd: logos-node@.service

### `/etc/systemd/system/logos-node@.service`

```ini
[Unit]
Description=LOGOS LRB Node (%i)
After=network-online.target
Wants=network-online.target

[Service]
User=logos
EnvironmentFile=/etc/logos/node-%i.env
ExecStart=/opt/logos/bin/logos_node
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
SystemCallFilter=@system-service @network-io ~keyctl
ReadWritePaths=/var/lib/logos /var/log/logos
RuntimeDirectory=logos
UMask=0077
[Install]
WantedBy=multi-user.target

```

## systemd overrides: logos-node@.service.d

`/etc/systemd/system/logos-node@.service.d`


---

### `/etc/systemd/system/logos-node@.service.d/10-restart-policy.conf`

```ini
[Service]
Restart=on-failure
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=5

```

---

### `/etc/systemd/system/logos-node@.service.d/20-env.conf`

```ini
[Service]
EnvironmentFile=-/etc/logos/node-%i.env

```

---

### `/etc/systemd/system/logos-node@.service.d/30-hardening.conf`

```ini
[Service]
# Sandbox
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

# Разрешаем запись ТОЛЬКО где нужно
ReadWritePaths=/var/lib/logos
ReadWritePaths=/var/log/logos

# Ресурсные лимиты
LimitNOFILE=262144
LimitNPROC=8192

# Capabilities обрезаем в ноль
CapabilityBoundingSet=
AmbientCapabilities=

```

---

### `/etc/systemd/system/logos-node@.service.d/31-bridge-key.conf`

```ini
[Service]
Environment=LRB_BRIDGE_KEY=supersecret

```

---

### `/etc/systemd/system/logos-node@.service.d/40-log.conf`

```ini
[Service]
Environment=RUST_LOG=trace,logos=trace,consensus=trace,axum=info,h2=info,tokio=info

```

---

### `/etc/systemd/system/logos-node@.service.d/41-faucet.conf`

```ini
[Service]
# Типичные ключи, которые встречаются в таких сборках:
Environment=LOGOS_FAUCET_ENABLED=true
Environment=LRB_FAUCET_ENABLED=true
# (на некоторых билдах есть явный биндинг — пусть будет)
Environment=LOGOS_FAUCET_PATH=/faucet

```

---

### `/etc/systemd/system/logos-node@.service.d/42-http-port.conf`

```ini
[Service]
Environment=LOGOS_HTTP_ADDR=127.0.0.1:8081
Environment=LRB_HTTP_ADDR=127.0.0.1:8081

```

---

### `/etc/systemd/system/logos-node@.service.d/env.conf`

```ini
[Service]
# Per-instance env (например /etc/logos/node-main.env)
EnvironmentFile=/etc/logos/node-%i.env
# Общие секреты (тот самый "keys", чтобы один раз положил — и все инстансы видят)
EnvironmentFile=/etc/logos/keys.env

```

---

### `/etc/systemd/system/logos-node@.service.d/override.conf`

```ini
[Service]
Environment=LOGOS_GENESIS_PATH=/etc/logos/genesis.yaml
Environment=LOGOS_NODE_KEY_PATH=/var/lib/logos/node_key

```

## systemd: logos-airdrop-api.service

### `/etc/systemd/system/logos-airdrop-api.service`

```ini
[Unit]
Description=LOGOS Airdrop API (FastAPI on :8092, Postgres)
After=network.target postgresql.service
Requires=network.target postgresql.service

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos/airdrop-api

# Все секреты и DSN лежат здесь
EnvironmentFile=/etc/logos/airdrop-api.env
Environment=PYTHONUNBUFFERED=1

# Uvicorn внутри venv, 4 воркера
ExecStart=/opt/logos/airdrop-api/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8092 --workers 4 --proxy-headers

Restart=always
RestartSec=3
TimeoutStopSec=20
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target

```

## systemd: logos-x-guard.service

### `/etc/systemd/system/logos-x-guard.service`

```ini
[Unit]
Description=LOGOS X Guard (Twitter airdrop verifier)
After=network-online.target logos-node@main.service
Wants=network-online.target

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos
ExecStart=/opt/logos/bin/logos_x_guard
EnvironmentFile=/etc/logos/node-main.env
Restart=always
RestartSec=2
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target

```

## nginx: logos.conf

### `/etc/nginx/sites-available/logos.conf`

```ini
# === LOGOS LRB — продовый периметр (HTTPS+HTTP/2) ===
# upstream до Axum (локально)
upstream logos_node_backend {
    server 127.0.0.1:8080;
    keepalive 64;
}

# 80 -> 443
server {
    listen 80 default_server;
    server_name 45-159-248-232.sslip.io 45.159.248.232 _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name 45-159-248-232.sslip.io 45.159.248.232 _;

    # --- TLS ---
    ssl_certificate     /etc/nginx/ssl/logos.crt;
    ssl_certificate_key /etc/nginx/ssl/logos.key;
    ssl_session_cache   shared:LOGOS_SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # --- Общие заголовки/параметры ---
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer-when-downgrade always;
    client_max_body_size 1m;

    # --- Проксирование к ноде на /api/ ---
    location /api/ {
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 30s;
        proxy_send_timeout 30s;

        # РОУТИНГ: /api/xxx -> http://127.0.0.1:8080/xxx
        proxy_pass http://logos_node_backend/;

        # Периметр-лимиты (важно: без ":20m")
        limit_conn logos_conn_api 120;
        limit_req  zone=logos_tx_api burst=50 nodelay;
    }

    # Узкое горлышко на метрики (не душим основной API)
    location = /api/metrics {
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://logos_node_backend/metrics;

        limit_req  zone=logos_metrics burst=20 nodelay;
        access_log off;
    }

    # (Опционально) статика кошелька/эксплорера, если раздаёшь с этого же инстанса
    # location /wallet/   { root /var/www; }
    # location /explorer/ { root /var/www; }
}

```

## nginx: logos_front

### `/etc/nginx/sites-available/logos_front`

```
# Upstream'ы для бэкендов
upstream logos_node_api {
    server 127.0.0.1:8080;
    keepalive 32;
}

upstream logos_wallet_api {
    server 127.0.0.1:9090;
    keepalive 32;
}

upstream airdrop_api {
    server 127.0.0.1:8092;
    keepalive 16;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name mw-expedition.com www.mw-expedition.com;

    root /var/www/logos/landing;
    index index.html;
    charset utf-8;

    access_log /var/log/nginx/logos_front.access.log;
    error_log  /var/log/nginx/logos_front.error.log warn;

    # Безопасные заголовки
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;

    # Gzip
    gzip on;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_vary on;
    gzip_proxied any;
    gzip_types
        text/plain
        text/css
        text/javascript
        application/javascript
        application/json
        application/xml
        application/rss+xml
        font/woff2
        application/font-woff2
        image/svg+xml;

    # SPA фронт (landing / wallet / explorer)
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Статика с долгим кэшем
    location ~* \.(?:css|js|ico|png|jpg|jpeg|gif|svg|woff2?)$ {
        access_log off;
        expires 30d;
        add_header Cache-Control "public, max-age=2592000, immutable";
        try_files $uri =404;
    }

    # --- Wallet proxy: /api/v1/... -> 9090 ---
    location /api/v1/ {
        proxy_pass http://logos_wallet_api/v1/;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout   60s;
        proxy_connect_timeout 5s;
        proxy_send_timeout   60s;

        proxy_buffering on;
        proxy_buffers 32 32k;
        proxy_busy_buffers_size 256k;
    }

    # --- Airdrop API: /api/airdrop/... -> 8092 ---
    location /api/airdrop/ {
        proxy_pass http://airdrop_api;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout   60s;
        proxy_connect_timeout 5s;
        proxy_send_timeout   60s;

        proxy_buffering on;
        proxy_buffers 16 16k;
        proxy_busy_buffers_size 64k;
    }

    # --- Нода: /api/head, /api/economy, /api/block,... -> 8081 ---
    location /api/ {
        proxy_pass http://logos_node_api/;   # /api/foo -> /foo
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout   120s;
        proxy_connect_timeout 5s;
        proxy_send_timeout   120s;

        proxy_buffering on;
        proxy_buffers 32 32k;
        proxy_busy_buffers_size 256k;
    }

    # SSL от Let's Encrypt
    ssl_certificate     /etc/letsencrypt/live/mw-expedition.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mw-expedition.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;
}

# HTTP -> HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name mw-expedition.com www.mw-expedition.com;

    return 301 https://$host$request_uri;
}

```

## nginx: logos-node-8000.conf

### `/etc/nginx/sites-available/logos-node-8000.conf`

```ini
server {
    listen 8000;
    server_name _;
    # если будете раздавать фронт-кошелёк со статикой — пропишите root
    # root /var/www/wallet;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

```
