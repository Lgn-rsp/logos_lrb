#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAP_NAME="LOGOS_AIRDROP_BOTS_BOOK_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_AIRDROP_BOTS_BOOK/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_AIRDROP_BOTS_BOOK"

echo "# LOGOS Airdrop Bots Book (TG + X + API + Front + Infra)" > "$OUT"
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
      -name "*.rs"   -o \
      -name "*.toml" -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.sh"   -o \
      -name "*.md"   -o \
      -name "*.json" -o \
      -name "*.service" -o -name "*.socket" -o \
      -name "*.conf" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/target/*" \
    ! -path "*/.venv/*" \
    ! -path "*/venv/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/logs/*" \
    ! -path "*/log/*" \
    ! -name "*.log" \
    ! -name "*.sqlite3" \
    ! -name "*.sqlite" \
    ! -name "*.db" \
    ! -name "*.env" \
    ! -name "*.bak" \
    ! -name "*.bak.*" \
  | sort | while read -r FILE; do
        echo "" >> "$OUT"
        echo "---" >> "$OUT"
        echo "" >> "$OUT"
        echo "### \`$FILE\`" >> "$OUT"
        echo "" >> "$OUT"

        local EXT="${FILE##*.}"
        local LANG=""
        case "$EXT" in
          py) LANG="python" ;;
          rs) LANG="rust" ;;
          toml) LANG="toml" ;;
          yml|yaml) LANG="yaml" ;;
          sh) LANG="bash" ;;
          md) LANG="markdown" ;;
          json) LANG="json" ;;
          service|socket|conf) LANG="ini" ;;
          *) LANG="" ;;
        esac

        [ -n "$LANG" ] && echo "\`\`\`$LANG" >> "$OUT" || echo "\`\`\`" >> "$OUT"
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
  echo "\`\`\`ini" >> "$OUT"
  cat "$FILE" >> "$OUT"
  echo "" >> "$OUT"
  echo "\`\`\`" >> "$OUT"
}

# 1) TG bot (боевой сервисный путь)
dump_dir "/opt/logos/airdrop-tg-bot" "Telegram Airdrop Bot (deployed)"

# 2) Airdrop API backend (боевой)
dump_dir "/opt/logos/airdrop-api" "Airdrop API (deployed)"

# 3) X Guard исходники (в репозитории)
dump_dir "/root/logos_lrb/modules/x_guard" "X Guard Module Source (modules/x_guard)"

# 4) systemd units
dump_file "/etc/systemd/system/logos-airdrop-tg-bot.service" "systemd: logos-airdrop-tg-bot.service"
dump_file "/etc/systemd/system/logos-airdrop-api.service"    "systemd: logos-airdrop-api.service"
dump_file "/etc/systemd/system/logos-x-guard.service"        "systemd: logos-x-guard.service"

# 5) nginx (маршрутизация API/ботов/фронта)
dump_file "/etc/nginx/sites-available/logos.conf" "nginx: logos.conf"

# ==== AIRDROP FRONT (HTML) ====
dump_file "/var/www/logos/landing/airdrop.html" "front: /var/www/logos/landing/airdrop.html"
dump_file "/var/www/logos/landing/landing/airdrop.html" "front: /var/www/logos/landing/landing/airdrop.html"

# ==== AIRDROP SHARED (MASTER) ====
dump_file "/opt/logos/www/shared/airdrop.css" "shared: airdrop.css"
dump_file "/opt/logos/www/shared/airdrop.js" "shared: airdrop.js"
dump_file "/opt/logos/www/shared/airdrop-fix.js" "shared: airdrop-fix.js"
dump_file "/opt/logos/www/shared/airdrop-x.js" "shared: airdrop-x.js"
dump_file "/opt/logos/www/shared/i18n.js" "shared: i18n.js"
dump_file "/opt/logos/www/shared/tweetnacl.min.js" "shared: tweetnacl.min.js"

# ==== AIRDROP SHARED COPIES IN LANDING ====
dump_file "/var/www/logos/landing/shared/airdrop-fix.js" "landing shared copy: airdrop-fix.js"
dump_file "/var/www/logos/landing/landing/shared/airdrop-fix.js" "landing/landing shared copy: airdrop-fix.js"


echo ""
echo "Snapshot written to: $OUT"
