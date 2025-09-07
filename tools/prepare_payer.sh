#!/usr/bin/env bash
set -euo pipefail

API=${API:-http://127.0.0.1:8080}
FROM=${FROM:-PAYER}
AMOUNT=${AMOUNT:-1000000}
NONCE=${NONCE:-0}

JWT_SECRET="$(sed -n 's/^LRB_ADMIN_JWT_SECRET=//p' /etc/logos/keys.env | tr -d '[:space:]')"
if [[ -z "${JWT_SECRET}" ]]; then
  echo "[ERR] LRB_ADMIN_JWT_SECRET is empty"; exit 1
fi

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

H=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
P=$(printf '{"sub":"admin","iat":1690000000,"exp":2690000000}' | b64url)
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary | b64url)
JWT="$H.$P.$S"

echo "[*] set_balance $FROM = $AMOUNT"
curl -sf -X POST "$API/admin/set_balance" \
  -H "X-Admin-JWT: $JWT" -H 'Content-Type: application/json' \
  -d "{\"rid\":\"$FROM\",\"amount\":$AMOUNT}" || { echo; echo "[ERR] set_balance failed"; exit 1; }
echo

echo "[*] set_nonce $FROM = $NONCE"
curl -sf -X POST "$API/admin/set_nonce" \
  -H "X-Admin-JWT: $JWT" -H 'Content-Type: application/json' \
  -d "{\"rid\":\"$FROM\",\"value\":$NONCE}" || { echo; echo "[ERR] set_nonce failed"; exit 1; }
echo

echo "[*] balance:"
curl -sf "$API/balance/$FROM" || true
echo
