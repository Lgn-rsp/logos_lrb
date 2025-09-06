#!/usr/bin/env sh
set -eu

# -------- settings --------
OUT_DIR="docs"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT_FILE_TMP="${OUT_DIR}/LRB_FULL_LIVE_${STAMP}.txt.tmp"
OUT_FILE="${OUT_DIR}/LRB_FULL_LIVE_${STAMP}.txt"
SIZE_LIMIT="${SIZE_LIMIT:-800000}"   # байт
REPO_ROOT="/root/logos_lrb"

# Источники внутри репозитория
REPO_GLOBS='
lrb_core/src
node/src
modules
www/wallet
www/explorer
infra/nginx
infra/systemd
scripts
tools/bench/go
configs
README.md
Cargo.toml
'

# Внешние источники (инфра с сервера)
HOST_SOURCES='
/etc/nginx/conf.d
/etc/nginx/sites-enabled
/etc/systemd/system/prometheus.service
/etc/systemd/system/alertmanager.service
/etc/systemd/system/grafana.service
/etc/alertmanager/alertmanager.yml
/etc/prometheus/prometheus.yml
/opt/logos/www/wallet
/opt/logos/www/explorer
'

# Расширения, которые считаем текстовыми (порядок важен для языка)
is_text_ext() {
  case "$1" in
    *.rs|*.toml) echo rs; return 0 ;;
    *.go) echo go; return 0 ;;
    *.sh) echo bash; return 0 ;;
    *.py) echo python; return 0 ;;
    *.ts|*.tsx|*.js) echo ts; return 0 ;;
    *.json) echo json; return 0 ;;
    *.yaml|*.yml) echo yaml; return 0 ;;
    *.md) echo markdown; return 0 ;;
    *.html) echo html; return 0 ;;
    *.css) echo css; return 0 ;;
    *.conf|*.service|*.timer|*.env|*.ini) echo conf; return 0 ;;
    *) return 1 ;;
  esac
}

# Быстрая проверка «текст/бинарь»
is_text_file() {
  # grep -Iq . <file> → 0 для текста
  LC_ALL=C grep -Iq . "$1"
}

# Список файлов по маскам
collect_paths() {
  # 1) репозиторий
  echo "$REPO_GLOBS" | while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    [ "${rel#\#}" != "$rel" ] && continue
    p="$REPO_ROOT/$rel"
    if [ -d "$p" ]; then
      find "$p" -type f
    elif [ -f "$p" ]; then
      echo "$p"
    fi
  done
  # 2) внешние
  echo "$HOST_SOURCES" | while IFS= read -r abs; do
    [ -z "$abs" ] && continue
    [ "${abs#\#}" != "$abs" ] && continue
    if [ -d "$abs" ]; then
      find "$abs" -type f
    elif [ -f "$abs" ]; then
      echo "$abs"
    fi
  done
}

# Заголовок книги
write_header() {
  {
    echo "# FULL LIVE SNAPSHOT — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# sources:"
    echo "#  - ${REPO_ROOT}"
    echo "#  - /opt/logos/www/wallet"
    echo "#  - /opt/logos/www/explorer"
    echo "#  - /etc/nginx/conf.d, /etc/nginx/sites-enabled"
    echo "#  - /etc/systemd/system/*{prometheus,alertmanager,grafana}.service"
    echo "#  - /etc/{prometheus,alertmanager}/*.yml"
    echo "# size limit per file: ${SIZE_LIMIT} bytes"
    echo
  } >>"$OUT_FILE_TMP"
}

# Печать одного файла в формате:
# ## FILE: <path>  (size=NNNb)
# ```<lang>
# <content>
# ```
dump_file() {
  f="$1"
  [ -f "$f" ] || return 0

  sz="$(wc -c <"$f" | tr -d ' ')"
  rel="$f"
  lang=""

  # Пропустить слишком большие
  if [ "$sz" -gt "$SIZE_LIMIT" ]; then
    printf "\n## FILE: %s  (SKIPPED, size=%sb > limit)\n\n" "$rel" "$sz" >>"$OUT_FILE_TMP"
    return 0
  fi

  # Определить, текст/бинарь и язык
  if is_text_file "$f"; then
    if lang=$(is_text_ext "$f"); then :; else lang="txt"; fi
    printf "\n## FILE: %s  (size=%sb)\n" "$rel" "$sz" >>"$OUT_FILE_TMP"
    printf '```\n' >>"$OUT_FILE_TMP"     # без указания языка — GitHub рендерит стабильно
    cat "$f" >>"$OUT_FILE_TMP"
    printf '\n```\n' >>"$OUT_FILE_TMP"
  else
    printf "\n## FILE: %s  (SKIPPED, binary/non-text size=%sb)\n\n" "$rel" "$sz" >>"$OUT_FILE_TMP"
  fi
}

main() {
  mkdir -p "$OUT_DIR"
  : >"$OUT_FILE_TMP"

  write_header

  # Сбор всех путей и сортировка
  collect_paths | sort -u | while IFS= read -r p; do
    # Исключения (логи, большие кеши и пр.)
    case "$p" in
      *.log|*.map|*.cache|*.db|*.sqlite|*.wasm) continue ;;
      */target/*|*/node_modules/*|*/.git/*)    continue ;;
    esac
    dump_file "$p"
  done

  mv -f "$OUT_FILE_TMP" "$OUT_FILE"
  echo "✅ Сформировано: $OUT_FILE"

  # Дополнительно отдаём «короткий алиас» для удобства
  cp -f "$OUT_FILE" "${REPO_ROOT}/LOGOS_LRB_FULL_BOOK.md" 2>/dev/null || true
}

main "$@"
