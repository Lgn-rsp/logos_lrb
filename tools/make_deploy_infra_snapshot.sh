#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_DEPLOY_INFRA_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_DEPLOY_INFRA/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_DEPLOY_INFRA"

echo "# LOGOS Deploy + Infra Snapshot" > "$OUT"
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
      -name "*.sh"   -o \
      -name "*.md"   -o \
      -name "*.yaml" -o -name "*.yml" -o \
      -name "*.toml" -o \
      -name "*.json" -o \
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
          sh)          LANG="bash" ;;
          md)          LANG="markdown" ;;
          yml|yaml)    LANG="yaml" ;;
          toml)        LANG="toml" ;;
          json)        LANG="json" ;;
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
    yml|yaml)            LANG="yaml" ;;
    toml)                LANG="toml" ;;
    sh)                  LANG="bash" ;;
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

# 1. Скрипты деплоя/запуска
dump_dir "/root/logos_lrb/scripts" "Deploy/Bootstrap Scripts (scripts/)"

# 2. Инфраструктура (шаблоны, инфра-файлы)
dump_dir "/root/logos_lrb/infra" "Infra (infra/)"

# 3. systemd-юниты LOGOS
dump_file "/etc/systemd/system/logos-node@.service"        "systemd: logos-node@.service"
dump_dir  "/etc/systemd/system/logos-node@.service.d"      "systemd overrides: logos-node@.service.d"
dump_file "/etc/systemd/system/logos-airdrop-api.service"  "systemd: logos-airdrop-api.service"
dump_file "/etc/systemd/system/logos-x-guard.service"      "systemd: logos-x-guard.service"

# 4. nginx-конфиги LOGOS
dump_file "/etc/nginx/sites-available/logos.conf"          "nginx: logos.conf"
dump_file "/etc/nginx/sites-available/logos_front"         "nginx: logos_front"
dump_file "/etc/nginx/sites-available/logos-node-8000.conf" "nginx: logos-node-8000.conf"

echo ""
echo "Snapshot written to: $OUT"
