#!/usr/bin/env bash
# LOGOS LRB — сборка "книги исходников" в один файл Markdown
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.."; pwd)"
OUT="${ROOT}/LOGOS_LRB_FULL_BOOK.md"
TS="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
GIT_SHA="$(git -C "$ROOT" rev-parse --short=7 HEAD 2>/dev/null || echo 'no-git')"

# Исключения (каталоги/паттерны) и лимиты
EXCLUDES=( "LOGOS_LRB_FULL_BOOK.md" 
  ".git" "target" "node_modules" "venv" "__pycache__" "data.sled" "var"
  "*.log" "*.pem" "*.der" "*.crt" "*.key" "*.zip" "*.tar" "*.tar.gz" "*.7z"
)
MAX_SIZE=$((1024*1024))  # 1 МБ

lang_for() {
  case "${1##*.}" in
    rs) echo "rust" ;;
    toml) echo "toml" ;;
    json) echo "json" ;;
    yml|yaml) echo "yaml" ;;
    sh|bash) echo "bash" ;;
    py) echo "python" ;;
    js) echo "javascript" ;;
    ts) echo "typescript" ;;
    tsx|jsx) echo "tsx" ;;
    html|htm) echo "html" ;;
    css) echo "css" ;;
    md) echo "markdown" ;;
    conf|ini) echo "" ;;
    *) echo "" ;;
  esac
}

exclude_match() {
  local f="$1"
  for p in "${EXCLUDES[@]}"; do
    case "$p" in
      *"*") [[ "$f" == $p ]] && return 0 ;;
      *)
        [[ "$f" == */$p/* || "$f" == */$p || "$f" == $p ]] && return 0
      ;;
    esac
  done
  return 1
}

# Заголовок книги
{
  echo "# LOGOS LRB — Полная книга исходников"
  echo
  echo "_Generated: ${TS} • Commit: ${GIT_SHA}_"
  echo
  echo "> Содержит исходники проекта в одном файле. Исключены бинарные/секретные/кэш-файлы; каждый модуль оформлен разделом с путём и код-блоком."
  echo
  echo "## Оглавление"
} > "$OUT"

# Собираем оглавление (null-delimited безопасно)
TMP_LIST="$(mktemp)"
( cd "$ROOT" && find . -type f -print0 ) >"$TMP_LIST"

# Оглавление
while IFS= read -r -d '' f; do
  exclude_match "$f" && continue
  sz=$(stat -c%s "$ROOT/$f" 2>/dev/null || echo 0)
  (( sz > MAX_SIZE )) && continue
  anchor="$(echo "$f" | sed 's/^\.\///' | tr '/.' '--' | tr -cd '[:alnum:]-_' | tr '[:upper:]' '[:lower:]')"
  echo "- [$f](#$anchor)" >> "$OUT"
done < "$TMP_LIST"

{
  echo
  echo "---"
  echo
} >> "$OUT"

# Контент
while IFS= read -r -d '' f; do
  exclude_match "$f" && continue
  sz=$(stat -c%s "$ROOT/$f" 2>/dev/null || echo 0)
  (( sz > MAX_SIZE )) && { echo "skip (>${MAX_SIZE}): $f" >&2; continue; }

  rel="${f#./}"
  anchor="$(echo "$f" | sed 's/^\.\///' | tr '/.' '--' | tr -cd '[:alnum:]-_' | tr '[:upper:]' '[:lower:]')"
  lang="$(lang_for "$rel")"

  {
    echo "## $rel"
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
echo "✅ Сформировано: $OUT"
