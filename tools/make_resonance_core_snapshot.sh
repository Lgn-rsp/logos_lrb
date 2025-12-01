#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNAP_NAME="LOGOS_RESONANCE_CORE_SNAPSHOT_$(date -u +%Y-%m-%dT%H-%M-%SZ).md"
OUT="$ROOT_DIR/docs/LOGOS_RESONANCE_CORE/$SNAP_NAME"

mkdir -p "$ROOT_DIR/docs/LOGOS_RESONANCE_CORE"

echo "# LOGOS Resonance Core + Modules Snapshot" > "$OUT"
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
      -name "*.json" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/target/*" \
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
          rs)          LANG="rust" ;;
          toml)        LANG="toml" ;;
          yml|yaml)    LANG="yaml" ;;
          sh)          LANG="bash" ;;
          md)          LANG="markdown" ;;
          json)        LANG="json" ;;
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

# 1. Python core (резонанс, onboarding, rid, offline и т.п.)
dump_dir "/root/logos_lrb/core" "Python Resonance Core (core/)"

# 2. Все сервисные модули (включая x_guard, chaos_guard, env_impact и др.)
dump_dir "/root/logos_lrb/modules" "Service Modules (modules/)"

echo ""
echo "Snapshot written to: $OUT"
