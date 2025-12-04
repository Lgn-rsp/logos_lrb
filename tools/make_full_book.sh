#!/usr/bin/env bash
set -euo pipefail

# Hardening locale and PATH
export LC_ALL=C LANG=C
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

REPO="/root/logos_lrb"
cd "$REPO"

STAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
BOOK="docs/LOGOS_LRB_FULL_BOOK_${STAMP}.md"
ROOTS_FILE="docs/snapshots/REPO_ROOTS_${STAMP}.txt"

# Clean file list (NO parentheses, NO eval)
FILES=$(
  find . -type f \
    -not -path "./.git/*" \
    -not -path "./.git" \
    -not -path "*/target/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/dist/*" \
    -not -path "*/build/*" \
    -not -path "*/.venv/*" \
    -not -path "*/venv/*" \
  | sed 's#^\./##' | sort
)

# Project roots (Cargo/Python/JS) + fixed directories
{
  find . -type f -name Cargo.toml \
    -not -path "./.git/*" -not -path "*/target/*" -not -path "*/node_modules/*" \
    -not -path "*/dist/*"  -not -path "*/build/*"  -not -path "*/.venv/*" -not -path "*/venv/*" \
    -printf '%h\n'
  find . -type f -name pyproject.toml \
    -not -path "./.git/*" -not -path "*/target/*" -not -path "*/node_modules/*" \
    -not -path "*/dist/*"  -not -path "*/build/*"  -not -path "*/.venv/*" -not -path "*/venv/*" \
    -printf '%h\n'
  find . -type f -name package.json \
    -not -path "./.git/*" -not -path "*/target/*" -not -path "*/node_modules/*" \
    -not -path "*/dist/*"  -not -path "*/build/*"  -not -path "*/.venv/*" -not -path "*/venv/*" \
    -printf '%h\n'
  printf '%s\n' configs configs/env infra/nginx infra/systemd lrb_core node modules www tools scripts docs
} | sed 's#^\./##' | sort -u > "$ROOTS_FILE"

# Header
{
  echo "# LOGOS LRB — FULL BOOK (${STAMP})"
  echo
  echo "**Branch:** $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)  "
  echo "**Commit:** $(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)  "
  echo "**Remote:** $(git remote get-url origin 2>/dev/null || echo none)"
  echo
  echo "---"
  echo
  echo "## Repository Structure (clean, no artifacts)"
  echo '```text'
  find . -type d \
    -not -path "./.git/*" -not -path "./.git" \
    -not -path "*/target/*" -not -path "*/node_modules/*" \
    -not -path "*/dist/*"  -not -path "*/build/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" \
  | sed 's#^\./##' | awk -F/ 'NF<=6' | sort
  echo '```'
  echo
  echo "## Project Roots (Cargo/Python/JS)"
  echo '```text'
  cat "$ROOTS_FILE"
  echo '```'
  echo
  echo "## Full File Contents"
} > "$BOOK"

# Embed every file (text: full, binary: only hash+size)
for f in $FILES; do
  # Skip previous books
  case "$f" in
    docs/LOGOS_LRB_FULL_BOOK_*) continue ;;
  esac

  SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
  SHA=$( (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f" 2>/dev/null) | awk '{print $1}' )

  if grep -Iq . "$f" 2>/dev/null; then
    {
      echo
      echo "### \`$f\`"
      echo
      [ -n "$SHA" ] && echo "**SHA256:** $SHA  |  **size:** ${SIZE} bytes**"
      echo
      echo '```'
      cat "$f"
      echo
      echo '```'
    } >> "$BOOK"
  else
    {
      echo
      echo "### \`$f\` (binary)"
      echo
      [ -n "$SHA" ] && echo "**SHA256:** $SHA  |  **size:** ${SIZE} bytes**"
    } >> "$BOOK"
  fi
done

# Footer
{
  echo
  echo "---"
  echo
  echo "## Summary"
  echo "- Total files: $(printf '%s\n' $FILES | wc -l)"
  echo "- Book SHA256: $( (sha256sum "$BOOK" 2>/dev/null || shasum -a 256 "$BOOK" 2>/dev/null) | awk '{print $1}')"
} >> "$BOOK"

# Git push
git add "$BOOK" || true
[ -f node/src/openapi/openapi.json ] && git add node/src/openapi/openapi.json || true
git commit -m "docs: FULL BOOK (complete snapshot; all text files included; binaries hashed)" || true
git push

# Output
wc -l "$BOOK" || true
ls -lh "$BOOK" || true
