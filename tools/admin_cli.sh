#!/usr/bin/env bash
set -euo pipefail

NODE_URL="${NODE_URL:-http://127.0.0.1:8080}"

# --- helpers ---
get_env() {
  systemctl show -p Environment logos-node.service \
    | sed -n 's/^Environment=//p' \
    | tr ' ' '\n' \
    | sed 's/"//g'
}

ENV_CACHE="$(get_env || true)"
get_var() { echo "$ENV_CACHE" | sed -n "s/^$1=//p" | head -n1; }

AK="${AK:-$(get_var LRB_ADMIN_KEY || true)}"
BK="${BK:-$(get_var LRB_BRIDGE_KEY || true)}"

require_admin_key() {
  if [[ -z "${AK:-}" || "$AK" == "CHANGE_ADMIN_KEY" ]]; then
    echo "[!] LRB_ADMIN_KEY не задан или дефолтный. Укажи AK=... в окружении или в keys.conf" >&2
    exit 1
  fi
}
require_bridge_key() {
  if [[ -z "${BK:-}" || "$BK" == "CHANGE_ME" ]]; then
    echo "[!] LRB_BRIDGE_KEY не задан или дефолтный. Укажи BK=... в окружении или в keys.conf" >&2
    exit 1
  fi
}

jq_or_cat() {
  if command -v jq >/dev/null 2>&1; then jq .; else cat; fi
}

usage() {
cat <<'EOF'
admin_cli.sh — удобные команды для LOGOS LRB (prod)

ENV:
  NODE_URL=http://127.0.0.1:8080     # адрес ноды (по умолчанию)
  AK=<admin-key>                     # можно переопределить, иначе берется из systemd
  BK=<bridge-key>                    # можно переопределить, иначе берется из systemd

Команды:
  health                      — /healthz
  head                        — /head
  node-info                   — /node/info
  validators                  — /admin/validators
  metrics [grep]              — /metrics (опциональный grep)

  snapshot-json               — GET /admin/snapshot (требует AK)
  snapshot-file [name]        — GET /admin/snapshot/file?name=NAME (требует AK)
  restore <abs_path.json>     — POST /admin/restore (требует AK)

  deposit <rid> <amount> <ext_txid>         — POST /bridge/deposit (требует BK)
  redeem  <rid> <amount> <request_id>       — POST /bridge/redeem (требует BK)
  verify  <ticket> <vk_b58> <signature_b64> — POST /bridge/verify

  account-txs <rid> [limit]   — GET /account/:rid/txs?limit=N

Примеры:
  ./admin_cli.sh head
  ./admin_cli.sh validators
  AK=$(systemctl show -p Environment logos-node.service | sed -n 's/.*LRB_ADMIN_KEY=\([^ ]*\).*/\1/p') \
    ./admin_cli.sh snapshot-json
  BK=$(systemctl show -p Environment logos-node.service | sed -n 's/.*LRB_BRIDGE_KEY=\([^ ]*\).*/\1/p') \
    ./admin_cli.sh deposit RID_A 12345 ext-1
EOF
}

cmd="${1:-}"
case "$cmd" in
  ""|-h|--help|help) usage; exit 0 ;;
esac
shift || true

case "$cmd" in
  health)
    curl -s "$NODE_URL/healthz" | jq_or_cat
    ;;

  head)
    curl -s "$NODE_URL/head" | jq_or_cat
    ;;

  node-info)
    curl -s "$NODE_URL/node/info" | jq_or_cat
    ;;

  validators)
    curl -s "$NODE_URL/admin/validators" | jq_or_cat
    ;;

  metrics)
    body="$(curl -s "$NODE_URL/metrics")"
    if [[ $# -gt 0 ]]; then echo "$body" | grep -E "$*" || true; else echo "$body"; fi
    ;;

  snapshot-json)
    require_admin_key
    curl -s -H "X-Admin-Key: $AK" "$NODE_URL/admin/snapshot" | jq_or_cat
    ;;

  snapshot-file)
    require_admin_key
    name="${1:-snap-$(date +%s).json}"
    curl -s -H "X-Admin-Key: $AK" "$NODE_URL/admin/snapshot/file?name=$name" | jq_or_cat
    ;;

  restore)
    require_admin_key
    file="${1:-}"
    [[ -z "$file" ]] && { echo "[!] usage: restore /var/lib/logos/snapshots/<file>.json" >&2; exit 1; }
    curl -s -X POST -H "content-type: application/json" -H "X-Admin-Key: $AK" \
      "$NODE_URL/admin/restore" \
      -d "{\"file\":\"$file\"}" | jq_or_cat
    ;;

  deposit)
    require_bridge_key
    rid="${1:-}"; amt="${2:-}"; xtx="${3:-}"
    [[ -z "$rid" || -z "$amt" || -z "$xtx" ]] && { echo "[!] usage: deposit <rid> <amount> <ext_txid>" >&2; exit 1; }
    curl -s -X POST "$NODE_URL/bridge/deposit" \
      -H "content-type: application/json" -H "X-Bridge-Key: $BK" \
      -d "{\"rid\":\"$rid\",\"amount\":$amt,\"ext_txid\":\"$xtx\"}" | jq_or_cat
    ;;

  redeem)
    require_bridge_key
    rid="${1:-}"; amt="${2:-}"; reqid="${3:-}"
    [[ -z "$rid" || -z "$amt" || -z "$reqid" ]] && { echo "[!] usage: redeem <rid> <amount> <request_id>" >&2; exit 1; }
    curl -s -X POST "$NODE_URL/bridge/redeem" \
      -H "content-type: application/json" -H "X-Bridge-Key: $BK" \
      -d "{\"rid\":\"$rid\",\"amount\":$amt,\"request_id\":\"$reqid\"}" | jq_or_cat
    ;;

  verify)
    ticket="${1:-}"; vk_b58="${2:-}"; sig_b64="${3:-}"
    [[ -z "$ticket" || -z "$vk_b58" || -z "$sig_b64" ]] && { echo "[!] usage: verify <ticket> <vk_b58> <signature_b64>" >&2; exit 1; }
    curl -s -X POST "$NODE_URL/bridge/verify" \
      -H "content-type: application/json" \
      -d "{\"ticket\":\"$ticket\",\"vk_b58\":\"$vk_b58\",\"signature_b64\":\"$sig_b64\"}" | jq_or_cat
    ;;

  account-txs)
    rid="${1:-}"; limit="${2:-100}"
    [[ -z "$rid" ]] && { echo "[!] usage: account-txs <rid> [limit]" >&2; exit 1; }
    curl -s "$NODE_URL/account/$rid/txs?limit=$limit" | jq_or_cat
    ;;

  *)
    echo "[!] unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac
