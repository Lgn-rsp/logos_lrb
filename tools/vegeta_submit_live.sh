#!/usr/bin/env bash
set -euo pipefail

# === defaults ===
API="http://127.0.0.1:8080"
FROM="PAYER"
TO="RCV"
AMOUNT=1
RATE=500
DURATION="60s"
START_NONCE=1
COUNT=10000
REPORT_EVERY=30   # секунд

# === parse KEY=VALUE ===
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
    REPORT_EVERY=*) REPORT_EVERY=${kv#REPORT_EVERY=} ;;
    *) echo "[WARN] unknown arg: $kv" ;;
  esac
done

command -v vegeta >/dev/null 2>&1 || { echo "[ERR] vegeta not found"; exit 1; }

echo "[*] attack: rate=${RATE} for ${DURATION} | from=${FROM} to=${TO} amount=${AMOUNT} nonces=${START_NONCE}..$((START_NONCE+COUNT-1))"

# === generate JSONL targets ===
TARGETS="targets.jsonl"
RESULTS="results.bin"
rm -f "$TARGETS" "$RESULTS"

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

gen_targets_json > "$TARGETS"

# === start attack in background ===
( vegeta attack -format=json -rate="${RATE}" -duration="${DURATION}" -targets="$TARGETS" > "$RESULTS" ) &
VEG_PID=$!

# cleanup & final report on Ctrl+C / TERM
finish() {
  echo
  echo "[*] stopping attack (pid=$VEG_PID) and printing final report..."
  kill "$VEG_PID" 2>/dev/null || true
  wait "$VEG_PID" 2>/dev/null || true

  echo "[*] FINAL SUMMARY:"
  vegeta report "$RESULTS"

  echo "[*] FINAL HISTOGRAM:"
  vegeta report -type='hist[0,500us,1ms,2ms,5ms,10ms,20ms,50ms,100ms]' "$RESULTS"

  echo "[*] JSON metrics -> results.json"
  vegeta report -type=json "$RESULTS" > results.json

  # archive sample (если включён /archive)
  if curl -sf "${API}/archive/history/${FROM}" >/dev/null 2>&1; then
    echo "[*] archive sample:"
    curl -sf "${API}/archive/history/${FROM}" | jq '.[0:5]' || true
  fi
  exit 0
}
trap finish INT TERM

# === live progress loop ===
START_TS=$(date +%s)
while kill -0 "$VEG_PID" 2>/dev/null; do
  sleep "$REPORT_EVERY"
  NOW=$(date +%s); ELAPSED=$((NOW-START_TS))
  echo
  echo "[*] PROGRESS t=${ELAPSED}s:"
  vegeta report "$RESULTS" || true
done

# wait and final when finished naturally
finish
