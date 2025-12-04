#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/root/logos_lrb"
cd "$REPO_ROOT"

STAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
BOOK="docs/LOGOS_LRB_FULL_BOOK_${STAMP}.md"

# ---- helper: pretty header
h() { echo -e "\n---\n\n## $1\n"; }

# ---- repo meta
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'detached')"
GIT_SHA="$(git rev-parse --short=12 HEAD 2>/dev/null || echo 'unknown')"
GIT_REMOTE="$(git remote get-url origin 2>/dev/null || echo 'no-remote')"

# ---- clean lists (без мусора)
# исключаем build-артефакты: target, node_modules, venv, dist, .git и пр.
EXCLUDES='
  -path */target -prune -o
  -path */node_modules -prune -o
  -path */.git -prune -o
  -path */.venv -prune -o
  -path */venv -prune -o
  -path */dist -prune -o
  -path */build -prune -o
  -path */.idea -prune -o
  -path */.vscode -prune -o
'

# ---- список корней проектов
ROOTS_FILE="docs/snapshots/REPO_ROOTS_${STAMP}.txt"
mkdir -p docs/snapshots
{
  find . $EXCLUDES -type f -name Cargo.toml -printf '%h\n'
  find . $EXCLUDES -type f -name pyproject.toml -printf '%h\n'
  find . $EXCLUDES -type f -name package.json -printf '%h\n'
  printf '%s\n' \
    configs configs/env \
    infra/nginx infra/systemd \
    lrb_core node modules www tools scripts docs
} | sed 's#^\./##' | sort -u > "$ROOTS_FILE"

# ---- begin book
{
  echo "# LOGOS LRB — FULL BOOK (${STAMP})"
  echo
  echo "**Branch:** ${GIT_BRANCH}  "
  echo "**Commit:** ${GIT_SHA}  "
  echo "**Remote:** ${GIT_REMOTE}"
  h "Структура репозитория (чистая, без артефактов)"
  echo '```text'
  # печатаем дерево только до 4 уровней и без мусора
  find . $EXCLUDES -type d \( -name .git -o -name target -o -name node_modules -o -name dist -o -name build -o -name .venv -o -name venv \) -prune -false -o -type d -print \
    | sed 's#^\./##' \
    | awk -F/ 'NF<=4' \
    | sort
  echo '```'

  h "Рабочие модули и пакеты (Cargo/Python/JS)"
  echo '```text'
  cat "$ROOTS_FILE"
  echo '```'

  h "Rust workspace (manifestы)"
  find . $EXCLUDES -type f -name Cargo.toml -print \
    | sed 's#^\./##' | sort \
    | while read -r f; do
        echo -e "\n### \`$f\`\n"
        echo '```toml'
        sed -n '1,200p' "$f"
        echo '```'
      done

  h "Конфиги (genesis, logos_config, env-примеры)"
  for f in $(find configs -maxdepth 2 -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.env' -o -name '*.toml' \) | sort); do
    echo -e "\n### \`$f\`\n"
    echo '```'
    sed -n '1,300p' "$f"
    echo '```'
  done

  h "Инфраструктура: systemd и Nginx"
  for f in $(find infra/systemd -type f -name '*.service' -o -name '*.conf' 2>/dev/null | sort); do
    echo -e "\n### \`$f\`\n"
    echo '```ini'; sed -n '1,300p' "$f"; echo '```'
  done
  for f in $(find infra/nginx -type f \( -name '*.conf' -o -name '*.snippets' \) 2>/dev/null | sort); do
    echo -e "\n### \`$f\`\n"
    echo '```nginx'; sed -n '1,300p' "$f"; echo '```'
  done

  h "OpenAPI (узел /node)"
  if [ -f node/src/openapi/openapi.json ]; then
    echo "**Файл:** node/src/openapi/openapi.json  "
    echo -n "**SHA256:** "
    sha256sum node/src/openapi/openapi.json | awk '{print $1}'
    echo
    echo '```json'
    sed -n '1,400p' node/src/openapi/openapi.json
    echo '```'
  else
    echo "_openapi.json не найден_"
  fi

  h "Метрики и health-ручки (докстринги/описания)"
  grep -Rsn --include='*.rs' -E 'logos_(http|head|finalized|blocks|tx_|bridge|archive)' node 2>/dev/null | sed 's#^\./##' | head -n 400 | sed 's/^/    /'

  h "Скрипты деплоя (канон)"
  for f in $(ls -1 scripts/*.sh 2>/dev/null || true); do
    echo -e "\n### \`$f\`\n"
    echo '```bash'; sed -n '1,200p' "$f"; echo '```'
  done

  h "Суммы и размеры ключевых артефактов"
  echo '```text'
  for f in node/src/openapi/openapi.json configs/genesis.yaml configs/logos_config.yaml; do
    [ -f "$f" ] || continue
    printf "%-40s  %10s  %s\n" "$f" "$(stat -c%s "$f" 2>/dev/null)" "$(sha256sum "$f" | awk '{print $1}')"
  done
  echo '```'

} > "$BOOK"

# аккуратная подсветка завершения
wc -l "$BOOK" | awk '{printf "\nFULL_BOOK lines: %s\n", $1}'
ls -lh "$BOOK"

# ---- git add & push (openapi.json тоже как в каноне)
git add "$BOOK"
[ -f node/src/openapi/openapi.json ] && git add node/src/openapi/openapi.json || true

COMMIT_MSG="docs: FULL BOOK (prod snapshot; canon-aligned structure; clean tree; openapi)"
git commit -m "$COMMIT_MSG" || echo "Nothing to commit (already up to date)."
git push
