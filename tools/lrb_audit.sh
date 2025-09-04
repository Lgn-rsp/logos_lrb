#!/usr/bin/env bash
set -euo pipefail
cd /root/logos_lrb

REPORT="AUDIT_REPORT.md"
echo "# LOGOS LRB — Аудит модулей" > "$REPORT"
echo "_$(date -u)_ UTC" >> "$REPORT"
echo >> "$REPORT"

sha() { sha256sum "$1" | awk '{print $1}'; }

audit_rust() {
  local f="$1"
  local lines; lines=$(wc -l <"$f")
  local s_unsafe s_unwrap s_expect s_panic s_todo s_dbg
  s_unsafe=$(grep -c '\<unsafe\>' "$f" || true)
  s_unwrap=$(grep -c 'unwrap(' "$f" || true)
  s_expect=$(grep -c 'expect(' "$f" || true)
  s_panic=$(grep -c 'panic!(' "$f" || true)
  s_dbg=$(grep -Ec 'dbg!|println!' "$f" || true)
  s_todo=$(grep -ni 'TODO\|FIXME\|todo!\|unimplemented!' "$f" | sed 's/^/    /' || true)
  {
    echo "### \`$f\` (Rust)"
    echo "- lines: $lines | sha256: \`$(sha "$f")\`"
    echo "- red-flags: unsafe=$s_unsafe, unwrap=$s_unwrap, expect=$s_expect, panic=$s_panic, dbg/println=$s_dbg"
    [ -n "$s_todo" ] && echo "- TODO/FIXME:"$'\n'"$s_todo"
    echo
  } >> "$REPORT"
}

audit_py() {
  local f="$1"
  local lines; lines=$(wc -l <"$f")
  local s_eval s_exec s_pickle s_subp s_todo
  s_eval=$(grep -c '\<eval\>' "$f" || true)
  s_exec=$(grep -c '\<exec\>' "$f" || true)
  s_pickle=$(grep -c 'pickle' "$f" || true)
  s_subp=$(grep -c 'subprocess' "$f" || true)
  s_todo=$(grep -ni 'TODO\|FIXME' "$f" | sed 's/^/    /' || true)
  {
    echo "### \`$f\` (Python)"
    echo "- lines: $lines | sha256: \`$(sha "$f")\`"
    echo "- red-flags: eval=$s_eval, exec=$s_exec, pickle=$s_pickle, subprocess=$s_subp"
    [ -n "$s_todo" ] && echo "- TODO/FIXME:"$'\n'"$s_todo"
    echo
  } >> "$REPORT"
}

audit_other() {
  local f="$1"
  local lines; lines=$(wc -l <"$f")
  {
    echo "### \`$f\`"
    echo "- lines: $lines | sha256: \`$(sha "$f")\`"
    grep -ni 'TODO\|FIXME' "$f" | sed 's/^/    - /' || true
    echo
  } >> "$REPORT"
}

echo "## Files in modules/" >> "$REPORT"
find modules -maxdepth 1 -type f | sort | while read -r f; do
  case "$f" in
    *.rs) audit_rust "$f" ;;
    *.py) audit_py "$f" ;;
    *.tsx|*.ts|*.yaml|*.yml|*.md) audit_other "$f" ;;
    *) audit_other "$f" ;;
  esac
done
echo >> "$REPORT"

echo "## Files in core/" >> "$REPORT"
find core -maxdepth 1 -type f | sort | while read -r f; do
  case "$f" in
    *.rs) audit_rust "$f" ;;
    *.py) audit_py "$f" ;;
    *.yaml|*.yml|*.md|*.toml) audit_other "$f" ;;
    *) audit_other "$f" ;;
  esac
done
echo >> "$REPORT"

echo "## Quick checks" >> "$REPORT"
{
  echo '```'
  cargo --version 2>/dev/null || true
  python3 --version 2>/dev/null || true
  echo '```'
  echo
} >> "$REPORT"

if [ -f Cargo.toml ]; then
  echo "### cargo check" >> "$REPORT"
  ( cargo check 2>&1 || true ) | sed 's/^/    /' >> "$REPORT"
  echo >> "$REPORT"
fi

# Python syntax check
: > py_err.log || true
find core modules -name '*.py' -print0 | xargs -0 -I{} sh -c 'python3 -m py_compile "{}" 2>>py_err.log' || true
if [ -s py_err.log ]; then
  echo "### python syntax errors" >> "$REPORT"
  sed 's/^/    /' py_err.log >> "$REPORT"
  echo >> "$REPORT"
fi

echo "Done -> $REPORT"
