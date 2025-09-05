#!/usr/bin/env bash
# load_healthz.sh — прогон healthz с прогрессом
# Usage: ./load_healthz.sh <TOTAL=50000> <CONC=200> <MODE=rr|lb>
set -euo pipefail
TOTAL="${1:-50000}"
CONC="${2:-200}"
MODE="${3:-rr}"

start_ts=$(date +%s%3N)
cnt=0
print_prog() { cnt=$((cnt+1)); if (( cnt % 1000 == 0 )); then echo -n "."; fi; }

if [ "$MODE" = "rr" ]; then
  seq 1 "$TOTAL" | xargs -n1 -P"$CONC" -I{} bash -c '
    i="{}"; r=$(( i % 3 ))
    if   [ $r -eq 0 ]; then p=8080
    elif [ $r -eq 1 ]; then p=8082
    else                   p=8084
    fi
    curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:${p}/healthz"
  ' && echo
else
  seq 1 "$TOTAL" | xargs -n1 -P"$CONC" -I{} bash -c '
    curl -sS --max-time 2 -o /dev/null "http://127.0.0.1/api/healthz"
  ' && echo
fi

end_ts=$(date +%s%3N)
dt_ms=$(( end_ts - start_ts ))
rps=$(( TOTAL * 1000 / (dt_ms>0?dt_ms:1) ))
echo "[OK] sent ${TOTAL} requests in ${dt_ms} ms  → ~${rps} req/s"
