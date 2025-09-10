#!/usr/bin/env bash
set -euo pipefail

ROOT="/root/logos_lrb"
BOOK="$ROOT/docs/LOGOS_LRB_FULL_BOOK.md"
DATE="$(date -Iseconds)"
BRANCH="book-$(date +%Y%m%d-%H%M%S)"

# определяем язык для подсветки в книге по расширению файла
lang_by_ext() {
  case "${1##*.}" in
    rs) echo rust;;
    toml) echo toml;;
    json) echo json;;
    yml|yaml) echo yaml;;
    sh|bash) echo bash;;
    service|timer) echo ini;;
    conf) echo nginx;;
    html) echo html;;
    js) echo javascript;;
    css) echo css;;
    sql) echo sql;;
    *) echo text;;
  esac
}

# редактируем ТОЛЬКО вывод (секреты → CHANGE_ME)
redact() {
  sed -E \
    -e 's/(LRB_JWT_SECRET[=: ]+)[^" \n]+/\1CHANGE_ME/g' \
    -e 's/(LRB_BRIDGE_KEY[=: ]+)[^" \n]+/\1CHANGE_ME/g' \
    -e 's/(X-Admin-Key: )[^\n"]+/\1CHANGE_ME/g' \
    -e 's/(X-Admin-JWT: )[^\n"]+/\1<ADMIN_JWT>/g' \
    -e 's#(/etc/letsencrypt/live/)[^/]+/#\1<YOUR_DOMAIN>/#g'
}

add()   { printf "%s" "$1" >> "$BOOK"; }
addh()  { printf "\n\n---\n\n# %s\n\n" "$1" >> "$BOOK"; }
add_file() {
  local path="$1" lang; lang="$(lang_by_ext "$path")"
  printf "\n\n=== %s ===\n\n" "$path" >> "$BOOK"
  printf '```%s\n' "$lang" >> "$BOOK"
  if [[ -r "$path" ]]; then
    cat "$path" | redact >> "$BOOK"
  else
    echo "# file not found: $path" >> "$BOOK"
  fi
  printf '\n```\n' >> "$BOOK"
}
add_cmd() {
  local title="$1"; shift
  printf "\n\n=== %s ===\n\n" "$title" >> "$BOOK"
  printf '```text\n' >> "$BOOK"
  ( "$@" || true ) | redact >> "$BOOK"
  printf '\n```\n' >> "$BOOK"
}

# ──────────────────────────────────────────────
# Заголовок книги
echo "# LOGOS LRB — Полная книга системы" > "$BOOK"
add "
**Сборка:** $DATE  
**Репозиторий:** /root/logos_lrb

Эта книга содержит *весь код и конфиги* системы LOGOS LRB, а также инструкции «по канону».
Секреты заменены на **CHANGE_ME**."

# ──────────────────────────────────────────────
# 1. Введение и канон
addh "1. Введение и канон"
add '
## Что это
LOGOS LRB — L1 с резонансным ядром: ledger/mempool/Σ(t), фазовые фильтры, slot-продюсер (quorum=1),
мост rToken, Explorer (Postgres), Web Wallet (IndexedDB/WebCrypto).

## Канон работы
```bash
cd /root/logos_lrb/<путь_к_модулю>
rm -f <file.rs|.html|.json|.conf|.service>
nano <file>
# → Вставляешь боевой код целиком (прод-уровень)
#   Ctrl+O → Enter → Ctrl+X

cd /root/logos_lrb
cargo build --release -p logos_node
sudo systemctl stop logos-node
install -m 0755 target/release/logos_node /opt/logos/bin/logos_node
sudo chown logos:logos /opt/logos/bin/logos_node
sudo systemctl daemon-reload
sudo systemctl restart logos-node
sleep 1
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo
```'

# ──────────────────────────────────────────────
# 2. Версии и окружение
addh "2. Версии и окружение"
add_cmd "rustc --version" bash -lc "rustc --version"
add_cmd "cargo --version" bash -lc "cargo --version"
add_cmd "nginx -v"       bash -lc "nginx -v 2>&1"
add_cmd "psql --version" bash -lc "psql --version 2>&1 || true"
add_cmd "systemd env"    bash -lc "systemctl show -p Environment logos-node | tr ' ' '\n'"

# ──────────────────────────────────────────────
# 3. Cargo workspace
addh "3. Cargo workspace"
add_file "$ROOT/Cargo.toml"

# ──────────────────────────────────────────────
# 4. lrb_core (исходники + Cargo)
addh "4. lrb_core (исходники + Cargo)"
while IFS= read -r f; do
  add_file "$f"
done < <(find "$ROOT/lrb_core" -type f \( -name '*.rs' -o -name 'Cargo.toml' \) | sort)

# ──────────────────────────────────────────────
# 5. node (исходники + Cargo)
addh "5. node (исходники + Cargo)"
while IFS= read -r f; do
  add_file "$f"
done < <(find "$ROOT/node" -type f \( -name '*.rs' -o -name 'Cargo.toml' \) | sort)

# ──────────────────────────────────────────────
# 6. Web Wallet (PWA)
addh "6. Web Wallet (PWA)"
add_file "$ROOT/www/wallet/index.html"
add_file "$ROOT/www/wallet/wallet.css"
add_file "$ROOT/www/wallet/wallet.js"
add_file "$ROOT/www/wallet/staking.js"
[[ -f "$ROOT/www/wallet/manifest.json" ]] && add_file "$ROOT/www/wallet/manifest.json"
[[ -f "$ROOT/www/wallet/sw.js"        ]] && add_file "$ROOT/www/wallet/sw.js"

# ──────────────────────────────────────────────
# 7. Explorer
addh "7. Explorer"
add_file "$ROOT/www/explorer/index.html"

# ──────────────────────────────────────────────
# 8. Nginx конфиг
addh "8. Nginx конфиг"
add_file "/etc/nginx/conf.d/logos.conf"

# ──────────────────────────────────────────────
# 9. Systemd (unit + drop-ins)
addh "9. Systemd (unit + drop-ins)"
add_cmd "systemctl cat logos-node" bash -lc "systemctl cat logos-node"
while IFS= read -r f; do
  add_file "$f"
done < <(find /etc/systemd/system/logos-node.service.d -maxdepth 1 -type f | sort)

# ──────────────────────────────────────────────
# 10. Бэкап sled
addh "10. Бэкап sled"
[[ -f "/usr/local/bin/logos-sled-backup.sh" ]]          && add_file "/usr/local/bin/logos-sled-backup.sh"
[[ -f "/etc/systemd/system/logos-sled-backup.service" ]]&& add_file "/etc/systemd/system/logos-sled-backup.service"
[[ -f "/etc/systemd/system/logos-sled-backup.timer"   ]]&& add_file "/etc/systemd/system/logos-sled-backup.timer"

# ──────────────────────────────────────────────
# 11. Prometheus/Grafana (alerts)
addh "11. Prometheus/Grafana (alerts)"
[[ -f "/etc/prometheus/rules/logos_alerts.yml" ]] && add_file "/etc/prometheus/rules/logos_alerts.yml"

# ──────────────────────────────────────────────
# 12. Конфиги
addh "12. Конфиги"
[[ -f "$ROOT/configs/genesis.yaml"      ]] && add_file "$ROOT/configs/genesis.yaml"
[[ -f "$ROOT/configs/logos_config.yaml" ]] && add_file "$ROOT/configs/logos_config.yaml"

# ──────────────────────────────────────────────
# 13. OpenAPI контракт
addh "13. OpenAPI контракт"
add_cmd "GET /openapi.json" bash -lc "curl -s http://127.0.0.1:8080/openapi.json || true"

# ──────────────────────────────────────────────
# 14. Bootstrap на новом сервере (шаги)
addh "14. Bootstrap на новом сервере (шаги)"
add '
### Ubuntu 22.04/24.04 (root)
```bash
apt update && apt install -y curl git jq build-essential pkg-config libssl-dev \
  nginx postgresql postgresql-contrib rsync

curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. $HOME/.cargo/env

git clone https://github.com/Lgn-rsp/logos_lrb.git /root/logos_lrb
cd /root/logos_lrb

# По канону вставляем файлы из этой книги (см. главы 3–13):
# cd → rm -f → nano → вставить контент блока === <path> === → сохранить

sudo mkdir -p /etc/systemd/system/logos-node.service.d
sudo tee /etc/systemd/system/logos-node.service.d/zz-secrets-inline.conf >/dev/null <<EOF
[Service]
Environment=LRB_JWT_SECRET=CHANGE_ME
Environment=LRB_BRIDGE_KEY=CHANGE_ME
EOF
sudo tee /etc/systemd/system/logos-node.service.d/paths.conf >/dev/null <<EOF
[Service]
Environment=LRB_DATA_PATH=/var/lib/logos/data.sled
Environment=LRB_NODE_KEY_PATH=/var/lib/logos/node_key
EOF
sudo systemctl daemon-reload

cargo build --release -p logos_node
install -m 0755 target/release/logos_node /opt/logos/bin/logos_node
sudo chown logos:logos /opt/logos/bin/logos_node
sudo systemctl restart logos-node
sleep 1
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo

nginx -t && systemctl reload nginx
```'

# ──────────────────────────────────────────────
# 15. Канон проверки
addh "15. Канон проверки"
add '
```bash
journalctl -u logos-node -n 120 --no-pager | egrep -i "listening|panic|error" || true
curl -s http://127.0.0.1:8080/healthz; echo
curl -s http://127.0.0.1:8080/head; echo
curl -s http://127.0.0.1:8080/economy | jq
curl -s "http://127.0.0.1:8080/archive/blocks?limit=3" | jq
curl -s "http://127.0.0.1:8080/archive/txs?limit=3"    | jq
```'

# финальный маркер
echo -e "\n\n---\n\n# Конец книги\n" >> "$BOOK"

# ──────────────────────────────────────────────
# автопуш книги в GitHub (ветка book-YYYYmmdd-HHMMSS, репо Lgn-rsp/logos_lrb)
cd "$ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "NOTE: git repo not found."
  echo "Run once:"
  echo "  git init"
  echo "  git remote add origin https://github.com/Lgn-rsp/logos_lrb.git"
  echo "  git fetch origin"
fi

git config user.name  >/dev/null 2>&1 || git config --global user.name "LOGOS Ops"
git config user.email >/dev/null 2>&1 || git config --global user.email "ops@logos.local"

git checkout -b "$BRANCH" 2>/dev/null || git checkout "$BRANCH"
git add docs/LOGOS_LRB_FULL_BOOK.md tools/make_book_and_push.sh || true
git commit -m "docs: full system book ($DATE)" || true

if git remote get-url origin >/dev/null 2>&1; then
  git push -u origin "$BRANCH" || true
else
  echo "NOTE: set remote and push manually:"
  echo "  git remote add origin https://github.com/Lgn-rsp/logos_lrb.git"
  echo "  git push -u origin $BRANCH"
fi
