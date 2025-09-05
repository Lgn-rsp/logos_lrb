#!/usr/bin/env bash
set -euo pipefail

OUTDIR="${OUTDIR:-/root/logos_snapshot}"
STAMP=$(date +%Y%m%d_%H%M)
OUT="$OUTDIR/LRB_FULL_LIVE_${STAMP}.txt"
MAX=${MAX:-800000}  # макс размер включаемого файла (байт)

mkdir -p "$OUTDIR"

say(){ echo "$@" >&2; }
add_head(){
  echo -e "\n\n## FILE: $1  (size=${2}b)\n\`\`\`" >> "$OUT"
}
add_tail(){
  echo -e "\n\`\`\`" >> "$OUT"
}

# Источники (живые пути)
SRC_LIST=(
  "/root/logos_lrb"                   # весь код репо
  "/opt/logos/www/wallet"             # кошелёк
  "/etc/systemd/system/logos-node@.service"
  "/etc/systemd/system/logos-healthcheck.service"
  "/etc/systemd/system/logos-healthcheck.timer"
  "/etc/nginx/sites-available/logos-api-lb.conf"
  "/usr/local/bin/logos_healthcheck.sh"
)

# Заголовок
{
  echo "# FULL LIVE SNAPSHOT — $(date -u +%FT%TZ)"
  echo "# sources:"
  for s in "${SRC_LIST[@]}"; do echo "#  - $s"; done
  echo "# size limit per file: ${MAX} bytes"
  echo
} > "$OUT"

# Вспомогательные функции
is_text(){
  # бинарники/картинки отсекаем простым тестом: попытка вывести «без нулевых байтов»
  # или используем file(1) если есть
  if command -v file >/dev/null 2>&1; then
    file -b --mime "$1" | grep -qiE 'text|json|xml|yaml|toml|javascript|html|css' && return 0 || return 1
  else
    grep -Iq . "$1" && return 0 || return 1
  fi
}

emit_file(){
  local f="$1"
  [ -f "$f" ] || return 0
  # исключения
  case "$f" in
    *.pem|*.key|*.crt|*.p12|*.so|*.bin|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.woff|*.woff2|*.ttf) return 0;;
  esac
  local sz
  sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if [ "$sz" -gt "$MAX" ]; then
    echo -e "\n\n## FILE: $f  (SKIPPED, size=${sz}b > ${MAX})" >> "$OUT"
    return 0
  fi
  if ! is_text "$f"; then
    echo -e "\n\n## FILE: $f  (SKIPPED, binary/non-text size=${sz}b)" >> "$OUT"
    return 0
  fi
  add_head "$f" "$sz"
  sed -e 's/\r$//' "$f" >> "$OUT"
  add_tail
}

# 1) Репозиторий: только текстовые файлы, игнорим target/node_modules/dist
if [ -d /root/logos_lrb ]; then
  say "[*] collecting /root/logos_lrb"
  cd /root/logos_lrb
  # берём отслеживаемые git'ом; если git недоступен — найдём все текстовые расширения
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files | while read -r f; do
      case "$f" in target/*|**/target/*|node_modules/*|dist/*) continue;; esac
      emit_file "/root/logos_lrb/$f"
    done
  else
    find . -type f ! -path "./target/*" ! -path "./node_modules/*" ! -path "./dist/*" \
      -regextype posix-extended -regex '.*\.(rs|toml|md|sh|bash|zsh|service|timer|conf|nginx|yaml|yml|json|ts|tsx|js|mjs|jsx|html|htm|css|go|py|proto|ini|cfg|txt)$' \
      -print0 | xargs -0 -I{} bash -c 'emit_file "{}"'
  fi
  cd - >/dev/null
fi

# 2) Статика кошелька
if [ -d /opt/logos/www/wallet ]; then
  say "[*] collecting /opt/logos/www/wallet"
  find /opt/logos/www/wallet -type f -print0 | while IFS= read -r -d '' f; do emit_file "$f"; done
fi

# 3) systemd units
for u in /etc/systemd/system/logos-node@.service /etc/systemd/system/logos-healthcheck.service /etc/systemd/system/logos-healthcheck.timer; do
  [ -f "$u" ] && emit_file "$u"
done

# 4) nginx site
[ -f /etc/nginx/sites-available/logos-api-lb.conf ] && emit_file /etc/nginx/sites-available/logos-api-lb.conf

# 5) healthcheck script
[ -f /usr/local/bin/logos_healthcheck.sh ] && emit_file /usr/local/bin/logos_healthcheck.sh

# 6) Живые .env → в слепок как обезличенные *.example
sanitize_env(){
  sed -E \
    -e 's/^(LRB_NODE_SK_HEX)=.*/\1=CHANGE_ME_64_HEX/' \
    -e 's/^(LRB_ADMIN_KEY)=.*/\1=CHANGE_ADMIN_KEY/' \
    -e 's/^(LRB_BRIDGE_KEY)=.*/\1=CHANGE_ME/' \
    -e 's/^(HOT_WALLET_PRIVATE_KEY)=.*/\1=CHANGE_ME/' \
    -e 's/^(TG_TOKEN)=.*/\1=CHANGE_ME/' \
    -e 's/^(TG_CHAT_ID)=.*/\1=CHANGE_ME/' \
    "$1"
}
if ls /etc/logos/node-*.env >/dev/null 2>&1; then
  for f in /etc/logos/node-*.env; do
    tmp="$(mktemp)"; sanitize_env "$f" > "$tmp"
    sz=$(stat -c%s "$tmp" 2>/dev/null || echo 0)
    add_head "${f}.example" "$sz"
    cat "$tmp" >> "$OUT"
    add_tail
    rm -f "$tmp"
  done
fi

echo "[ok] wrote $OUT"
