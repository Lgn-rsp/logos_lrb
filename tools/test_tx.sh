#!/usr/bin/env bash
set -euo pipefail

NODE="${NODE:-http://127.0.0.1:8080}"

echo "[*] Installing deps (jq, pip, pynacl, base58)..."
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y jq python3-pip >/dev/null 2>&1 || true
python3 -m pip install --quiet --no-input pynacl base58

echo "[*] Generating key, RID and signed tx..."
PYOUT="$(python3 - <<'PY'
import json, base64, base58
from nacl.signing import SigningKey

sk = SigningKey.generate()
vk = sk.verify_key
pk = bytes(vk)
rid = base58.b58encode(pk).decode()

amount = 12345
nonce  = 1

msg_obj = {
    "from": rid,
    "to": rid,
    "amount": amount,
    "nonce": nonce,
    "public_key": base64.b64encode(pk).decode()
}
msg = json.dumps(msg_obj, separators=(',',':')).encode()
sig = sk.sign(msg).signature

tx = {
    "from": rid,
    "to": rid,
    "amount": amount,
    "nonce": nonce,
    "public_key_b58": base58.b58encode(pk).decode(),
    "signature_b64": base64.b64encode(sig).decode()
}

print(json.dumps({"rid": rid, "tx": tx}))
PY
)"

RID="$(echo "$PYOUT" | jq -r .rid)"
TX="$(echo "$PYOUT" | jq -c .tx)"

echo "[*] Healthz:"
curl -s "$NODE/healthz" | jq .

echo "[*] Head before:"
curl -s "$NODE/head" | jq .

echo "[*] Submitting tx..."
RESP="$(curl -s -X POST "$NODE/submit_tx" -H 'content-type: application/json' -d "$TX")" || true
echo "$RESP" | jq . || true

# Если узел отклонил (например, nonce/balance), покажем причину и выйдем
if ! echo "$RESP" | jq -e '.accepted == true' >/dev/null 2>&1 ; then
  echo "[!] TX not accepted. Response above."
  exit 1
fi

TXID="$(echo "$RESP" | jq -r .tx_id)"
echo "[*] tx_id=$TXID"

echo "[*] Waiting 2s for block producer..."
sleep 2

echo "[*] Head after:"
curl -s "$NODE/head" | jq .

echo "[*] Balance for RID:"
curl -s "$NODE/balance/$RID" | jq .

echo "[*] Done."
