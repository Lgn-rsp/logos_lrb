#!/usr/bin/env bash
set -euo pipefail

# Куда писать книгу
DATE_UTC=$(date -u +%Y-%m-%dT%H-%M-%SZ)
BOOK="docs/LOGOS_LRB_BOOK_${DATE_UTC}.txt"

# Корень репозитория (чтобы пути были относительные)
REPO_ROOT="/root/logos_lrb"
cd "$REPO_ROOT"

echo "[*] Building book: $BOOK"
mkdir -p docs

# --- списки включений/исключений ---
# Git-трекаемые файлы + критичные конфиги вне репы
INCLUDE_LIST="$(mktemp)"
EXTRA_LIST="$(mktemp)"

# 1) всё полезное из git (код/конфиги), без мусора
git ls-files \
  | grep -Ev '^(\.gitignore|README\.md|LICENSE|^docs/LOGOS_LRB_BOOK_|^docs/.*\.pdf$)' \
  | grep -Ev '(^target/|/target/|^node_modules/|/node_modules/|\.DS_Store|\.swp$|\.sqlite$|/data\.sled|/data\.sled/|\.pem$|\.key$)' \
  > "$INCLUDE_LIST"

# 2) системные файлы вне репы (если существуют)
add_extra() { [[ -f "$1" ]] && echo "$1" >> "$EXTRA_LIST"; }
add_extra "/etc/systemd/system/logos-node.service"
for f in /etc/systemd/system/logos-node.service.d/*.conf; do [[ -f "$f" ]] && echo "$f" >> "$EXTRA_LIST"; done
add_extra "/etc/nginx/conf.d/10_lrb_https.conf"
add_extra "/etc/prometheus/prometheus.yml"
for f in /etc/prometheus/rules/*.yml; do [[ -f "$f" ]] && echo "$f" >> "$EXTRA_LIST"; done
# Grafana provisioning/дашборды (если есть)
for f in /etc/grafana/provisioning/dashboards/*.yaml /var/lib/grafana/dashboards/*.json; do
  [[ -f "$f" ]] && echo "$f" >> "$EXTRA_LIST"
done
# OpenAPI (в репе уже есть), APK/лендинг укажем ссылкой — бинарники в книгу не кладём

# --- заголовок книги ---
{
  echo "LOGOS LRB — FULL LIVE BOOK (${DATE_UTC})"
  echo
  echo "Содержимое: весь код репозитория + ключевая инфраструктура (systemd/nginx/prometheus/grafana),"
  echo "формат: секции BEGIN/END FILE c sha256 и блочным EOF. Бинарники (APK, sled, pem) не включаются."
  echo
  echo "Репозиторий: $REPO_ROOT"
  echo
} > "$BOOK"

emit_file () {
  local src="$1" dst
  # внутри репо пишем относительные пути; вне — абсолютные
  if [[ "$src" == $REPO_ROOT/* ]]; then
    dst="/${src#$REPO_ROOT/}"
  else
    dst="$src"
  fi
  # пропуск «мусора»
  if [[ -d "$src" ]]; then return 0; fi
  if [[ ! -f "$src" ]]; then return 0; fi
  # вычисляем sha256
  local sum
  sum=$(sha256sum "$src" | awk '{print $1}')
  {
    echo "===== BEGIN FILE $dst ====="
    echo "# sha256: $sum"
    echo "<<'EOF'"
    cat "$src"
    echo "EOF"
    echo "===== END FILE $dst ====="
    echo
  } >> "$BOOK"
}

echo "[*] Emitting repo files..."
while IFS= read -r p; do emit_file "$REPO_ROOT/$p"; done < "$INCLUDE_LIST"

echo "[*] Emitting extra system files..."
if [[ -s "$EXTRA_LIST" ]]; then
  while IFS= read -r p; do emit_file "$p"; done < "$EXTRA_LIST"
fi

# --- прикладываем «паспорт» окружения ---
{
  echo "===== BEGIN FILE /docs/ENV_SNAPSHOT.txt ====="
  echo "# sha256: N/A"
  echo "<<'EOF'"
  echo "[systemd env]"
  systemctl show logos-node -p Environment | sed 's/^Environment=//'
  echo
  echo "[nginx -v]"
  nginx -v 2>&1 || true
  echo
  echo "[prometheus rules list]"
  ls -1 /etc/prometheus/rules 2>/dev/null || true
  echo
  echo "[grafana dashboards list]"
  ls -1 /var/lib/grafana/dashboards 2>/dev/null || true
  echo "EOF"
  echo "===== END FILE /docs/ENV_SNAPSHOT.txt ====="
  echo
} >> "$BOOK"

echo "[*] Book is ready: $BOOK"
