#!/usr/bin/env bash
# tx_load.sh — надёжная нагрузка через LB/BE без конфликтов nonce.
# Отправка батчей строго по порядку внутри каждого RID (шарда).
# Параллельность — между шардами.
#
# Usage:
#   BACKEND=http://127.0.0.1:8080 ./tx_load.sh M K C [AMOUNT] [SHARDS]
#   (если хочешь через LB: BACKEND=http://127.0.0.1/api)
set -euo pipefail
BACKEND="${BACKEND:-http://127.0.0.1:8080}"   # куда шлём ВСЁ: faucet, canon, submit
M="${1:-1000}"     # всего tx
K="${2:-100}"      # размер батча
C="${3:-10}"       # параллельность шардов (RID)
AMOUNT="${4:-1}"
SHARDS="${5:-$C}"  # число независимых отправителей (RID)

need() { command -v "$1" >/dev/null || { echo "need $1"; exit 1; }; }
need curl; need jq; need openssl; need xxd; need seq; need awk; need sort; need xargs

work="$(mktemp -d -t lrb_load_XXXX)"
trap 'rm -rf "$work"' EXIT
echo "[*] work dir: $work"
per_shard=$(( (M + SHARDS - 1) / SHARDS ))
echo "[*] total=$M  shards=$SHARDS  per_shard≈$per_shard  batch=$K  parallel=$C  amount=$AMOUNT"
echo "[*] BACKEND=$BACKEND"

make_rid() {
  local out="$1"
  openssl genpkey -algorithm Ed25519 -out "$out/ed25519.sk.pem" >/dev/null 2>&1
  openssl pkey -in "$out/ed25519.sk.pem" -pubout -outform DER | tail -c 32 | xxd -p -c 32 > "$out/pk.hex"
  python3 - "$out/pk.hex" > "$out/RID.txt" <<'PY'
import sys
ALPH="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
pk=bytes.fromhex(open(sys.argv[1]).read().strip())
n=int.from_bytes(pk,'big'); s=""
while n>0: n,r=divmod(n,58); s=ALPH[r]+s
z=0
for b in pk:
    if b==0: z+=1
    else: break
print("1"*z + (s or "1"))
PY
}

# 1) Готовим шардовые каталоги: RID, faucet, nonce0
for s in $(seq 1 "$SHARDS"); do
  sd="$work/shard_$s"; mkdir -p "$sd/batches"
  make_rid "$sd"
  RID=$(cat "$sd/RID.txt")
  echo "[*] shard $s RID=$RID"
  curl -s -X POST "$BACKEND/faucet" -H 'Content-Type: application/json' \
    -d "{\"rid\":\"${RID}\",\"amount\":500000000}" >/dev/null
  NONCE0=$(curl -s "$BACKEND/balance/${RID}" | jq -r .nonce)
  echo "$NONCE0" > "$sd/nonce0"
done

# 2) Генерация подписанных tx для каждого шарда (последовательно → без гонок)
for s in $(seq 1 "$SHARDS"); do
  sd="$work/shard_$s"
  RID=$(cat "$sd/RID.txt")
  SK="$sd/ed25519.sk.pem"
  NONCE0=$(cat "$sd/nonce0")
  start=$(( (s-1)*per_shard + 1 ))
  end=$(( s*per_shard )); [ "$end" -gt "$M" ] && end="$M"
  count=$(( end - start + 1 )); [ "$count" -le 0 ] && continue
  echo "[*] shard $s: tx $start..$end (count=$count)"

  : > "$sd/cur_lines.jsonl"; idx=0; file_lines=0
  for i in $(seq 1 "$count"); do
    nonce=$(( NONCE0 + i ))
    echo "{\"tx\":{\"from\":\"$RID\",\"to\":\"$RID\",\"amount\":$AMOUNT,\"nonce\":$nonce}}" > "$sd/canon_payload.json"
    CANON_HEX=$(curl -s -X POST "$BACKEND/debug_canon" -H "Content-Type: application/json" \
      --data-binary @"$sd/canon_payload.json" | jq -r .canon_hex)
    echo -n "$CANON_HEX" | xxd -r -p > "$sd/canon.bin"
    openssl pkeyutl -sign -rawin -inkey "$SK" -in "$sd/canon.bin" -out "$sd/sig.bin" >/dev/null 2>&1
    SIG_HEX=$(xxd -p -c 256 "$sd/sig.bin")
    printf '{"from":"%s","to":"%s","amount":%s,"nonce":%s,"sig_hex":"%s"}\n' \
      "$RID" "$RID" "$AMOUNT" "$nonce" "$SIG_HEX" >> "$sd/cur_lines.jsonl"
    file_lines=$((file_lines+1))
    if [ "$file_lines" -ge "$K" ]; then
      idx=$((idx+1)); jq -s '{txs:.}' "$sd/cur_lines.jsonl" > "$sd/batches/batch_${s}_$(printf "%05d" $idx).json"
      : > "$sd/cur_lines.jsonl"; file_lines=0
    fi
  done
  if [ "$file_lines" -gt 0 ]; then
    idx=$((idx+1)); jq -s '{txs:.}' "$sd/cur_lines.jsonl" > "$sd/batches/batch_${s}_$(printf "%05d" $idx).json"
  fi
done

# 3) Отправляем батчи ПО ШАРДАМ: внутри каждого — строго по порядку; шарды — параллельно
start_ts=$(date +%s%3N)
ls -1d "$work"/shard_* | xargs -I{} -P"$C" bash -lc '
  sd="{}"
  for f in $(ls -1 "$sd"/batches/batch_*.json | sort -V); do
    curl -s -X POST "'"$BACKEND"'/submit_tx_batch" -H "Content-Type: application/json" \
      --data-binary @"$f" | jq -c "{accepted,rejected,new_height}"
  done
'
end_ts=$(date +%s%3N)
dt=$((end_ts - start_ts))
echo "=== DONE in ${dt} ms → ~ $(( M*1000/(dt>0?dt:1) )) tx/s (client-side est) ==="

# 4) HEAD / METRICS
echo "--- HEAD ---";    curl -s "$BACKEND/head" | jq .
echo "--- METRICS ---"
curl -s "$BACKEND/metrics" \
 | grep -E "lrb_tx_|submit_tx_batch|http_request_duration_seconds_bucket|http_inflight_requests" \
 | head -n 120 || true
