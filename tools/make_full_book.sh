#!/usr/bin/env bash
# LOGOS LRB — Полная книга: исходники из репозитория + ключевые прод-конфиги
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.."; pwd)"
OUT="${ROOT}/LOGOS_LRB_FULL_BOOK.md"
TS="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
GIT_SHA="$(git -C "$ROOT" rev-parse --short=7 HEAD 2>/dev/null || echo 'no-git')"

# ---------- Параметры ----------
# исключаем мусор/бинарь/секреты
EXCLUDES_REPO=(
  ".git" "target" "node_modules" "venv" "__pycache__" "data.sled" "var"
  "LOGOS_LRB_FULL_BOOK.md" "*.log" "*.pem" "*.der" "*.crt" "*.key" "*.zip" "*.tar" "*.tar.gz" "*.7z"
)
# включаем infra из whitelist-путей
INFRA_FILES=(
  "/etc/nginx/conf.d/*.conf"
  "/etc/systemd/system/logos-node.service"
  "/etc/systemd/system/logos-node.service.d/*.conf"
  "/etc/prometheus/prometheus.yml"
  "/etc/prometheus/rules/*.yml"
  "/etc/alertmanager/alertmanager.yml"
  "/etc/alertmanager/secrets.env"
  "/etc/grafana/provisioning/datasources/*.yaml"
  "/etc/grafana/provisioning/dashboards/*.yaml"
  "/var/lib/grafana/dashboards/*.json"
)
MAX_SIZE=$((2*1024*1024))  # 2 МБ на файл

lang_for() {
  case "${1##*.}" in
    rs) echo "rust" ;; toml) echo "toml" ;; json) echo "json" ;;
    yml|yaml) echo "yaml" ;; sh|bash) echo "bash" ;; py) echo "python" ;;
    js) echo "javascript" ;; ts) echo "typescript" ;; tsx|jsx) echo "tsx" ;;
    html|htm) echo "html" ;; css) echo "css" ;; md) echo "markdown" ;;
    conf|ini|service|timer) echo "" ;;  *) echo "" ;;
  esac
}

exclude_match() {
  local f="$1"
  for p in "${EXCLUDES_REPO[@]}"; do
    case "$p" in
      *"*") [[ "$f" == $p ]] && return 0 ;;
      *)    [[ "$f" == */$p/* || "$f" == */$p || "$f" == $p ]] && return 0 ;;
    esac
  done
  return 1
}

# маскировка секретов для infra (телеграм токены, и т.п.)
mask_infra() {
  # stdin -> stdout
  sed -E \
    -e 's/(TELEGRAM_BOT_TOKEN=)[A-Za-z0-9:_-]+/\1***MASKED*** /g' \
    -e 's/(TELEGRAM_CHAT_ID=)[0-9-]+/\1***MASKED*** /g'
}

# ---------- Заголовок ----------
{
  echo "# LOGOS LRB — Полная книга (исходники + прод-конфиги)"
  echo
  echo "_Generated: ${TS} • Commit: ${GIT_SHA}_"
  echo
  echo "> В книге: весь код из репозитория + основные конфиги из /etc. Исключены бинарные/ключевые файлы; секреты замаскированы."
  echo
  echo "## Оглавление"
} > "$OUT"

TMP_LIST="$(mktemp)"
( cd "$ROOT" && find . -type f -print0 ) >"$TMP_LIST"

# ---------- Оглавление: репозиторий ----------
while IFS= read -r -d '' f; do
  exclude_match "$f" && continue
  sz=$(stat -c%s "$ROOT/$f" 2>/dev/null || echo 0)
  (( sz > MAX_SIZE )) && continue
  anchor="$(echo "repo-$f" | sed 's/^\.\///' | tr '/.' '--' | tr -cd '[:alnum:]-_' | tr '[:upper:]' '[:lower:]')"
  echo "- [repo:$f](#$anchor)" >> "$OUT"
done < "$TMP_LIST"

# ---------- Оглавление: infra ----------
for pat in "${INFRA_FILES[@]}"; do
  for f in $pat; do
    [[ -f "$f" ]] || continue
    sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
    (( sz > MAX_SIZE )) && continue
    anchor="$(echo "infra-$f" | sed 's#/##g;s#:#-#g' | tr -cd '[:alnum:]-_' | tr '[:upper:]' '[:lower:]')"
    echo "- [infra:$f](#$anchor)" >> "$OUT"
  done
done

{
  echo
  echo "---"
  echo
  echo "## Раздел I. Исходники репозитория"
  echo
} >> "$OUT"

# ---------- Контент: репозиторий ----------
while IFS= read -r -d '' f; do
  exclude_match "$f" && continue
  sz=$(stat -c%s "$ROOT/$f" 2>/dev/null || echo 0)
  (( sz > MAX_SIZE )) && { echo "skip big: $f" >&2; continue; }
  rel="${f#./}"
  anchor="$(echo "repo-$f" | sed 's/^\.\///' | tr '/.' '--' | tr -cd '[:alnum:]-_' | tr '[:upper:]' '[:lower:]')"
  lang="$(lang_for "$rel")"
  {
    echo "### $rel"
    echo "<a id=\"$anchor\"></a>"
    echo
    echo '```'"$lang"
    cat "$ROOT/$f"
    echo
    echo '```'
    echo
  } >> "$OUT"
done < "$TMP_LIST"

rm -f "$TMP_LIST"

# ---------- Контент: infra ----------
{
  echo
  echo "## Раздел II. Инфраструктурные конфиги (прод)"
  echo
} >> "$OUT"

for pat in "${INFRA_FILES[@]}"; do
  for f in $pat; do
    [[ -f "$f" ]] || continue
    sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
    (( sz > MAX_SIZE )) && { echo "skip big: $f" >&2; continue; }
    anchor="$(echo "infra-$f" | sed 's#/##g;s#:#-#g' | tr -cd '[:alnum:]-_' | tr '[:upper:]' '[:lower:]')"
    lang="$(lang_for "$f")"
    {
      echo "### $f"
      echo "<a id=\"$anchor\"></a>"
      echo
      echo '```'"$lang"
      # маскируем секреты в alertmanager/secrets.env и похожем
      case "$f" in
        */alertmanager/secrets.env) mask_infra < "$f" ;;
        *) cat "$f" ;;
      esac
      echo
      echo '```'
      echo
    } >> "$OUT"
  done
done

echo "✅ Сформировано: $OUT"
