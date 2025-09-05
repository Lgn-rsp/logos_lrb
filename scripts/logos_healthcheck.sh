#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
STATE_FILE="/var/run/logos_health.json"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT

# Метрика: время ответа healthz
START=$(date +%s%3N)
if ! curl -sf "$BASE/healthz" -o "$TMP" >/dev/null; then
  MSG="LOGOS: /healthz FAIL at $(date -u +%FT%TZ)"
  logger -t logos_health "$MSG"
  [ -n "${TG_TOKEN:-}" ] && curl -s "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
     -d chat_id="${TG_CHAT_ID}" -d text="$MSG" >/dev/null || true
  exit 1
fi
RT=$(( $(date +%s%3N) - START ))

# Высота
HEAD_JSON=$(curl -sf "$BASE/head")
HEIGHT=$(echo "$HEAD_JSON" | jq -r '.height' 2>/dev/null || echo 0)

LAST_H=0
LAST_TS=0
if [ -f "$STATE_FILE" ]; then
  LAST_H=$(jq -r '.height // 0' "$STATE_FILE" 2>/dev/null || echo 0)
  LAST_TS=$(jq -r '.ts_ms // 0' "$STATE_FILE" 2>/dev/null || echo 0)
fi

TS_MS=$(date +%s%3N)
printf '{"ts_ms":%s,"height":%s,"rt_ms":%s}\n' "$TS_MS" "$HEIGHT" "$RT" > "$STATE_FILE"

# Правила алертов
ALERT=""
[ "$RT" -gt 1500 ] && ALERT="slow healthz: ${RT}ms"
if [ -n "$LAST_TS" ] && [ $((TS_MS - LAST_TS)) -gt 300000 ]; then
  # если 5 минут прошло и высота не менялась (и была >0)
  if [ "$HEIGHT" -eq "$LAST_H" ] && [ "$HEIGHT" -gt 0 ]; then
    ALERT="${ALERT} height stuck at ${HEIGHT}"
  fi
fi

if [ -n "$ALERT" ]; then
  MSG="LOGOS ALERT: ${ALERT} at $(date -u +%FT%TZ)"
  logger -t logos_health "$MSG"
  if [ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHAT_ID:-}" ]; then
    curl -s "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
       -d chat_id="${TG_CHAT_ID}" -d text="$MSG" >/dev/null || true
  fi
fi

exit 0
