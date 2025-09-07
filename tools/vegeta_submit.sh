#!/usr/bin/env bash
set -euo pipefail

# --- дефолты ---
API="http://127.0.0.1:8080"
FROM="PAYER"
TO="RCV"
AMOUNT=1
RATE=500
DURATION="60s"
START_NONCE=1
COUNT=10000

# --- парсинг KEY=VALUE из аргументов ---
for kv in "$@"; do
  case "$kv" in
    API=*) API=${kv#API=} ;;
    FROM=*) FROM=${kv#FROM=} ;;
    TO=*) TO=${kv#TO=} ;;
    AMOUNT=*) AMOUNT=${kv#AMOUNT=} ;;
    RATE=*) RATE=${kv#RATE=} ;;
    DURATION=*) DURATION=${kv#DURATION=} ;;
    START_NONCE=*) START_NONCE=${kv#START_NONCE=} ;;
    COUNT=*) COUNT=${kv#COUNT=} ;;
    *) echo "[WARN] unknown arg: $kv" ;;
  esac
done

command -v vegeta >/dev/null 2>&1 || { echo "[ERR] vegeta not found in PATH"; exit 1; }

echo "[*] attack: rate=${RATE} for ${DURATION} | from=${FROM} to=${TO} amount=${AMOUNT} nonces=${START_NONCE}..$((START_NONCE+COUNT-1))"

gen_targets_json() {
  local n=${START_NONCE}
  local end=$((START_NONCE + COUNT - 1))
  while [[ $n -le $end ]]; do
    local body b64
    body=$(printf '{"from":"%s","to":"%s","amount":%d,"nonce":%d,"memo":"load","sig_hex":"00"}' \
      "$FROM" "$TO" "$AMOUNT" "$n")
    b64=$(printf '%s' "$body" | openssl base64 -A)
    printf '{"method":"POST","url":"%s/submit_tx","body":"%s","header":{"Content-Type":["application/json"]}}\n' \
      "$API" "$b64"
    n=$((n+1))
  done
}

# атака: live-репорт каждые 30s + финальные отчёты
gen_targets_json \
  | vegeta attack -format=json -rate="${RATE}" -duration="${DURATION}" \
  | tee results.bin \
  | vegeta report -every 30s

echo "[*] latency histogram:"
vegeta report -type='hist[0,500us,1ms,2ms,5ms,10ms,20ms,50ms,100ms]' results.bin

echo "[*] JSON metrics -> results.json"
vegeta report -type=json results.bin > results.json

# срез архива (если включён /archive)
if curl -sf "${API}/archive/history/${FROM}" >/dev/null 2>&1; then
  echo "[*] archive sample:"
  curl -sf "${API}/archive/history/${FROM}" | jq '.[0:5]' || true
fi
