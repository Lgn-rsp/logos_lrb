#!/usr/bin/env sh
set -eu

ROOT="$(cd "$(dirname "$0")/.."; pwd)"
OUT_DIR="docs"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT_FILE_TMP="${OUT_DIR}/LRB_FULL_LIVE_${STAMP}.txt.tmp"
OUT_FILE="${OUT_DIR}/LRB_FULL_LIVE_${STAMP}.txt"
SIZE_LIMIT="${SIZE_LIMIT:-2000000}"   # 2 МБ на файл
REPO_ROOT="/root/logos_lrb"

# --- что берём из репозитория (каталоги/файлы) ---
REPO_GLOBS='
Cargo.toml
README.md
lrb_core/src
node/src
modules
www/wallet
www/explorer
infra/nginx
infra/systemd
scripts
tools
configs
'

# --- что берём из системы (infra) ---
INFRA_FILES='
/etc/nginx/nginx.conf
/etc/nginx/conf.d/*.conf
/etc/nginx/sites-enabled/*
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

# --- исключаем мусор/бинарь/секреты из репозитория ---
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
*:*        # мусорные файлы с двоеточиями в имени
'

# язык подсветки по расширению
lang_for() {
  case "${1##*.}" in
    rs) echo "rust" ;; toml) echo "toml" ;; json) echo "json" ;;
    yml|yaml) echo "yaml" ;; sh|bash) echo "bash" ;; py) echo "python" ;;
    js) echo "javascript" ;; ts) echo "typescript" ;; tsx|jsx) echo "tsx" ;;
    html|htm) echo "html" ;; css) echo "css" ;; md) echo "markdown" ;;
    conf|ini|service|timer|env) echo "" ;; *) echo "" ;;
  esac
}

# доверяем расширению; иначе grep -Iq
looks_text() {
  case "$1" in
    *.rs|*.toml|*.json|*.yml|*.yaml|*.sh|*.bash|*.py|*.js|*.ts|*.tsx|*.jsx|*.html|*.htm|*.css|*.md|*.conf|*.ini|*.service|*.timer|*.env)
      return 0 ;;
    *) LC_ALL=C grep -Iq . "$1" ;;
  esac
}

should_exclude() {
  f="$1"
  echo "$EXCLUDES_REPO" | while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    [ "${pat#\#}" != "$pat" ] && continue
    case "$pat" in
      *"*") [ "$(printf '%s' "$f" | awk -v p="$pat" 'BEGIN{ret=1} $0 ~ p{ret=0} END{print ret}')" -eq 0 ] && exit 0 ;;
      *) case "$f" in */$pat/*|*/$pat|$pat) exit 0 ;; esac ;;
    esac
  done; exit 1
}

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
  sz="$(wc -c <"$f" | tr -d ' ' || echo 0)"

  # 0-байт и слишком большие — не тянем
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

  # repo
  collect_repo | sort -u | while IFS= read -r p; do
    should_exclude "$p" && continue
    dump_file "$p"
  done

  # infra
  collect_infra | sort -u | while IFS= read -r p; do
    dump_file "$p"
  done

  mv -f "$OUT_FILE_TMP" "$OUT_FILE"
  echo "✅ Сформировано: $OUT_FILE"

  # alias в корень
  cp -f "$OUT_FILE" "${ROOT}/LOGOS_LRB_FULL_BOOK.md" 2>/dev/null || true
}

main "$@"
