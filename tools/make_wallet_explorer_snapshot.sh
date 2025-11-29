#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_WALLET_EXPLORER_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_WALLET_EXPLORER/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_WALLET_EXPLORER"

echo "# LOGOS Wallet + Explorer Snapshot" > "$OUT"
echo "" >> "$OUT"
echo "_Автогенерация: \`$(date -u "+%Y-%m-%d %H:%M:%SZ")\`_" >> "$OUT"
echo "" >> "$OUT"

dump_dir () {
  local DIR="$1"
  local TITLE="$2"

  if [ ! -d "$DIR" ]; then
    echo "- [WARN] directory not found: $DIR" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`$DIR\`" >> "$OUT"
  echo "" >> "$OUT"

  find "$DIR" \
    -type f \
    \( \
      -name "*.py"   -o \
      -name "*.html" -o -name "*.htm" -o \
      -name "*.js"   -o \
      -name "*.ts"   -o \
      -name "*.css"  -o \
      -name "*.md"   -o \
      -name "*.json" -o \
      -name "*.toml" -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.sh"   -o \
      -name "*.service" -o -name "*.socket" -o \
      -name "*.conf" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/.venv/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/logs/*" \
    ! -path "*/log/*" \
    ! -name "*.log" \
    ! -name "*.sqlite3" \
    ! -name "*.sqlite" \
    ! -name "*.db" \
    ! -name "*.env" \
  | sort | while read -r FILE; do
        local REL="$FILE"

        echo "" >> "$OUT"
        echo "---" >> "$OUT"
        echo "" >> "$OUT"
        echo "### \`$REL\`" >> "$OUT"
        echo "" >> "$OUT"

        local EXT="${FILE##*.}"
        local LANG=""
        case "$EXT" in
          py)          LANG="python" ;;
          html|htm)    LANG="html" ;;
          js)          LANG="javascript" ;;
          ts)          LANG="typescript" ;;
          css)         LANG="css" ;;
          md)          LANG="markdown" ;;
          json)        LANG="json" ;;
          toml)        LANG="toml" ;;
          yml|yaml)    LANG="yaml" ;;
          sh)          LANG="bash" ;;
          service|socket|conf) LANG="ini" ;;
          *)           LANG="" ;;
        esac

        if [ -n "$LANG" ]; then
          echo "\`\`\`$LANG" >> "$OUT"
        else
          echo "\`\`\`" >> "$OUT"
        fi

        cat "$FILE" >> "$OUT"
        echo "" >> "$OUT"
        echo "\`\`\`" >> "$OUT"
    done
}

dump_file () {
  local FILE="$1"
  local TITLE="$2"

  if [ ! -f "$FILE" ]; then
    echo "- [WARN] file not found: $FILE" >&2
    return 0
  fi

  echo "" >> "$OUT"
  echo "## $TITLE" >> "$OUT"
  echo "" >> "$OUT"
  echo "### \`$FILE\`" >> "$OUT"
  echo "" >> "$OUT"

  local EXT="${FILE##*.}"
  local LANG=""
  case "$EXT" in
    service|socket|conf) LANG="ini" ;;
    *)                   LANG="" ;;
  esac

  if [ -n "$LANG" ]; then
    echo "\`\`\`$LANG" >> "$OUT"
  else
    echo "\`\`\`" >> "$OUT"
  fi

  cat "$FILE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`\`\`" >> "$OUT"
}

# 1. Frontend: wallet + explorer (исходники)
dump_dir "/root/logos_lrb/www" "Wallet + Explorer Frontend (sources)"

# 2. Wallet-proxy backend (исходники)
dump_dir "/root/logos_lrb/wallet-proxy" "Wallet Proxy Backend (sources)"

# 3. Wallet-proxy backend (боевой деплой, без venv/logs/db/env)
dump_dir "/opt/logos/wallet-proxy" "Wallet Proxy Backend (deployed code)"

# 4. Nginx configs, связанные с кошельком/эксплорером
dump_file "/etc/nginx/sites-available/logos.conf"         "nginx: logos.conf"
dump_file "/etc/nginx/sites-available/logos_front"        "nginx: logos_front"
dump_file "/etc/nginx/sites-available/logos-node-8000.conf" "nginx: logos-node-8000.conf"

echo ""
echo "Snapshot written to: $OUT"
