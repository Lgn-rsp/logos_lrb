#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_BLOCK_PRODUCER_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_BLOCK_PRODUCER/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_BLOCK_PRODUCER"

echo "# LOGOS Block Producer Snapshot" > "$OUT"
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
    ! -path "*/__pycache__/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/data.sled/*" \
    ! -path "*/data.sled.*/*" \
    ! -path "*/bridge_journal.sled/*" \
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
          rs)          LANG="rust" ;;
          toml)        LANG="toml" ;;
          yml|yaml)    LANG="yaml" ;;
          sh)          LANG="bash" ;;
          md)          LANG="markdown" ;;
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
    toml)                LANG="toml" ;;
    yml|yaml)            LANG="yaml" ;;
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

# 1. Ядро блокчейна: всё, где живут ledger, mempool, engine, producer
dump_dir "/root/logos_lrb/lrb_core" "LRB Core (ledger, mempool, engine, block producer)"

# 2. Нода: main.rs, API, архив, метрики — всё, что завязано на продюсере
dump_dir "/root/logos_lrb/node" "Node (REST, producer loop, archive, metrics)"

# 3. Конфиги сети и генезиса
dump_dir "/root/logos_lrb/configs" "Configs (genesis, logos_config)"

# 4. Инфраструктура для ноды (если есть шаблоны)
dump_dir "/root/logos_lrb/infra" "Infra (node-related infra configs)"

# 5. Инструменты для тестирования продюсера (бенчи)
dump_dir "/root/logos_lrb/tools" "Tools (benchmarks, tx generators, helpers)"

# 6. systemd-юниты и overrides для ноды
dump_file "/etc/systemd/system/logos-node@.service" "systemd: logos-node@.service"
dump_dir  "/etc/systemd/system/logos-node@.service.d" "systemd overrides: logos-node@.service.d"

echo ""
echo "Snapshot written to: $OUT"
