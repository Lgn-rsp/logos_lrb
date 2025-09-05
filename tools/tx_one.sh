#!/usr/bin/env bash
# tx_one.sh — e2e: генерирует ключ, делает RID, faucet, строит канон, подписывает Ed25519 (raw),
# отправляет /submit_tx_batch и печатает head/balance/метрики.
# Usage: PORT=8080 ./tx_one.sh [AMOUNT]
set -euo pipefail
PORT="${PORT:-8080}"
AMOUNT="${1:-1234}"

work="$(mktemp -d -t lrb_one_XXXX)"
trap 'rm -rf "$work"' EXIT

need() { command -v "$1" >/dev/null || { echo "need $1"; exit 1; }; }
need curl; need jq; need openssl; need xxd; need python3

# Key + RID
openssl genpkey -algorithm Ed25519 -out "$work/ed25519.sk.pem" >/dev/null 2>&1
openssl pkey -in "$work/ed25519.sk.pem" -pubout -outform DER | tail -c 32 | xxd -p -c 32 > "$work/pk.hex"
python3 - "$work/pk.hex" > "$work/RID.txt" <<'PY'
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
RID=$(cat "$work/RID.txt"); echo "RID=$RID"

# Faucet + state
curl -s -X POST "http://127.0.0.1:${PORT}/faucet" -H 'Content-Type: application/json' \
  -d "{\"rid\":\"${RID}\",\"amount\":1000000}" | jq .
STATE=$(curl -s "http://127.0.0.1:${PORT}/balance/${RID}")
NONCE_CUR=$(jq -r .nonce <<<"$STATE"); NONCE=$((NONCE_CUR+1))
echo "nonce: $NONCE_CUR -> $NONCE"

# Canon
jq -n --arg f "$RID" --arg t "$RID" --argjson a "$AMOUNT" --argjson n "$NONCE" \
  '{tx:{from:$f,to:$t,amount:$a,nonce:$n}}' > "$work/canon_payload.json"
CANON_HEX=$(curl -s -X POST "http://127.0.0.1:${PORT}/debug_canon" -H 'Content-Type: application/json' \
  --data-binary @"$work/canon_payload.json" | jq -r .canon_hex)
echo -n "$CANON_HEX" | xxd -r -p > "$work/canon.bin"

# Sign
openssl pkeyutl -sign -rawin -inkey "$work/ed25519.sk.pem" -in "$work/canon.bin" -out "$work/sig.bin" >/dev/null 2>&1
SIG_HEX=$(xxd -p -c 256 "$work/sig.bin")

# Batch
jq -n --arg f "$RID" --arg t "$RID" --argjson a "$AMOUNT" --argjson n "$NONCE" --arg s "$SIG_HEX" \
  '{txs:[{from:$f,to:$t,amount:$a,nonce:$n,sig_hex:$s}]}' > "$work/batch.json"
curl -s -X POST "http://127.0.0.1:${PORT}/submit_tx_batch" -H 'Content-Type: application/json' \
  --data-binary @"$work/batch.json" | jq .

# Head / post state / metrics
echo "--- HEAD ---";         curl -s "http://127.0.0.1:${PORT}/head" | jq .
echo "--- POST ---";         curl -s "http://127.0.0.1:${PORT}/balance/${RID}" | jq .
echo "--- METRICS ---";      curl -s "http://127.0.0.1:${PORT}/metrics" \
 | grep -E "lrb_tx_|submit_tx_batch|http_inflight_requests" | head -n 40 || true
