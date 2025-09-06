#!/usr/bin/env sh
# LOGOS LRB — FULL LIVE book: repo + infra в один TXT (с маскировкой секретов)
set -eu

ROOT="$(cd "$(dirname "$0")/.."; pwd)"
OUT_DIR="docs"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT_FILE_TMP="${OUT_DIR}/LRB_FULL_LIVE_${STAMP}.txt.tmp"
OUT_FILE="${OUT_DIR}/LRB_FULL_LIVE_${STAMP}.txt"
SIZE_LIMIT="${SIZE_LIMIT:-2000000}"   # 2 MB per file
REPO_ROOT="/root/logos_lrb"

# --- ВКЛЮЧАЕМ ИЗ РЕПО ---
REPO_GLOBS='
Cargo.toml
README.md
src
lrb_core/src
node/src
modules
core
wallet-proxy
docs
www/wallet
www/explorer
infra/nginx
infra/systemd
scripts
tools
configs
'

# --- ВКЛЮЧАЕМ ИНФРУ С СЕРВЕРА ---
INFRA_FILES='
/etc/nginx/nginx.conf
/etc/nginx/conf.d/*.conf
/etc/nginx/sites-enabled/*
/etc/systemd/system/logos-node.service
/etc/systemd/system/*.service
/etc/systemd/system/*.timer
/etc/systemd/system/logos-node.service.d/*.conf
/etc/prometheus/prometheus.yml
/etc/prometheus/rules/*.yml
/etc/alertmanager/alertmanager.yml
/etc/alertmanager/secrets.env
/etc/grafana/grafana.ini
/etc/grafana/provisioning/datasources/*.yaml
/etc/grafana/provisioning/dashboards/*.yaml
/var/lib/grafana/dashboards/*.json
/opt/logos/www/wallet/*
/opt/logos/www/explorer/*
'

# --- ИСКЛЮЧЕНИЯ ДЛЯ РЕПО ---
EXCLUDES_REPO='
.git
target
node_modules
venv
__pycache__
*.pyc
data.sled
var
*.log
*.pem
*.der
*.crt
*.key
*.zip
*.tar
*.tar.gz
*.7z
LOGOS_LRB_FULL_BOOK.md
'

# язык для подсветки
lang_for() {
  case "${1##*.}" in
    rs) echo "rust" ;; toml) echo "toml" ;; json) echo "json" ;;
    yml|yaml) echo "yaml" ;; sh|bash) echo "bash" ;; py) echo "python" ;;
    js) echo "javascript" ;; ts) echo "typescript" ;; tsx|jsx) echo "tsx" ;;
    html|htm) echo "html" ;; css) echo "css" ;; md) echo "markdown" ;;
    conf|ini|service|timer|env) echo "" ;; *) echo "" ;;
  esac
}

# доверяем расширению, иначе grep -Iq
looks_text() {
  case "$1" in
    *.rs|*.toml|*.json|*.yml|*.yaml|*.sh|*.bash|*.py|*.js|*.ts|*.tsx|*.jsx|*.html|*.htm|*.css|*.md|*.conf|*.ini|*.service|*.timer|*.env) return 0;;
    *) LC_ALL=C grep -Iq . "$1";;
  esac
}

# фильтр исключений репо
should_exclude_repo() {
  f="$1"
  # с двоеточиями — мусор от редакторов
  echo "$f" | grep -q ":" && return 0
  echo "$EXCLUDES_REPO" | while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    [ "${pat#\#}" != "$pat" ] && continue
    case "$f" in */$pat/*|*/$pat|$pat) exit 0;; esac
  done; return 1
}

# маска секретов
mask_secrets() {
  sed -E \
    -e 's/(TELEGRAM_BOT_TOKEN=)[A-Za-z0-9:_-]+/\1***MASKED***/g' \
    -e 's/(TELEGRAM_CHAT_ID=)[0-9-]+/\1***MASKED***/g' \
    -e 's/(LRB_ADMIN_KEY=)[A-Fa-f0-9]+/\1***MASKED***/g' \
    -e 's/(LRB_BRIDGE_KEY=)[A-Fa-f0-9]+/\1***MASKED***/g' \
    -e 's/(LRB_ADMIN_JWT_SECRET=)[A-Za-z0-9._-]+/\1***MASKED***/g'
}

write_header() {
  {
    echo "# FULL LIVE SNAPSHOT — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# sources: $REPO_ROOT + infra (/etc, /opt)"
    echo "# size limit per file: ${SIZE_LIMIT} bytes"
    echo
  } >>"$OUT_FILE_TMP"
}

dump_file() {
  f="$1"
  [ -f "$f" ] || return 0
  echo "$f" | grep -q ":" && return 0     # отсекаем мусорные имена

  sz="$(wc -c <"$f" | tr -d ' ' || echo 0)"
  [ "$sz" -eq 0 ] && { printf "\n## FILE: %s  (SKIPPED, empty)\n" "$f" >>"$OUT_FILE_TMP"; return 0; }
  [ "$sz" -gt "$SIZE_LIMIT" ] && { printf "\n## FILE: %s  (SKIPPED, size=%sb > limit)\n" "$f" "$sz" >>"$OUT_FILE_TMP"; return 0; }

  printf "\n## FILE: %s  (size=%sb)\n" "$f" "$sz" >>"$OUT_FILE_TMP"
  if looks_text "$f"; then
    printf '```\n' >>"$OUT_FILE_TMP"
    case "$f" in
      */alertmanager/secrets.env|*/logos-node.service.d/*|*/nginx/*.conf|*/conf.d/*.conf|*/sites-enabled/*|*/prometheus*.yml|*/grafana/*.ini|*/provisioning/*|*/dashboards/*.json)
        mask_secrets < "$f" >>"$OUT_FILE_TMP" ;;
      *) cat "$f" >>"$OUT_FILE_TMP" ;;
    esac
    printf '\n```\n' >>"$OUT_FILE_TMP"
  else
    printf "\n(SKIPPED, binary/non-text)\n" >>"$OUT_FILE_TMP"
  fi
}

collect_repo() {
  echo "$REPO_GLOBS" | while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    [ "${rel#\#}" != "$rel" ] && continue
    p="$REPO_ROOT/$rel"
    if [ -d "$p" ]; then find "$p" -type f; elif [ -f "$p" ]; then echo "$p"; fi
  done
}

collect_infra() {
  echo "$INFRA_FILES" | while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    [ "${pat#\#}" != "$pat" ] && continue
    for f in $pat; do [ -f "$f" ] && echo "$f"; done
  done
}

main() {
  mkdir -p "$OUT_DIR"
  : >"$OUT_FILE_TMP"
  write_header

  collect_repo  | sort -u | while IFS= read -r p; do
    if should_exclude_repo "$p"; then continue; fi
    dump_file "$p"
  done

  collect_infra | sort -u | while IFS= read -r p; do
    dump_file "$p"
  done

  mv -f "$OUT_FILE_TMP" "$OUT_FILE"
  echo "✅ created: $OUT_FILE"
  cp -f "$OUT_FILE" "${ROOT}/LOGOS_LRB_FULL_BOOK.md" 2>/dev/null || true
}

main "$@"
