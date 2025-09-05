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
