#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."; pwd)"

SNAP_NAME="LOGOS_WEB_STACK_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_WEB_STACK/$SNAP_NAME"

echo "# LOGOS Web Stack Snapshot" > "$OUT"
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
          py)     LANG="python" ;;
          html|htm) LANG="html" ;;
          js)     LANG="javascript" ;;
          ts)     LANG="typescript" ;;
          css)    LANG="css" ;;
          md)     LANG="markdown" ;;
          json)   LANG="json" ;;
          toml)   LANG="toml" ;;
          yml|yaml) LANG="yaml" ;;
          sh)     LANG="bash" ;;
          service|socket|conf) LANG="ini" ;;
          *)      LANG="" ;;
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
    env) LANG="bash" ;;
    *) LANG="" ;;
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

# 1. Лендинг и фронтенд
dump_dir "/var/www/logos/landing" "Landing / Frontend"

# 2. Telegram guard bot
dump_dir "/var/www/logos/landing/logos_tg_bot/logos_guard_bot" "Telegram Guard Bot"

# 3. Airdrop API backend
dump_dir "/opt/logos/airdrop-api" "Airdrop API Backend"

# 4. systemd и env
dump_file "/etc/systemd/system/logos-airdrop-api.service" "systemd: logos-airdrop-api.service"
dump_file "/etc/systemd/system/logos-x-guard.service" "systemd: logos-x-guard.service"
dump_file "/etc/logos/airdrop-api.env" "Env: /etc/logos/airdrop-api.env"

echo ""
echo "Snapshot written to: $OUT"
