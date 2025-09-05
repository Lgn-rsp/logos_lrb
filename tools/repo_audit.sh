#!/usr/bin/env bash
set -euo pipefail

fail=0
pass(){ printf "  [OK]  %s\n" "$1"; }
err(){  printf "  [FAIL] %s\n" "$1"; fail=1; }

echo "== GIT STATUS =="
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "not a git repo"; exit 1; }
git status --porcelain

echo "== CORE CODE =="
[ -d lrb_core/src ] && pass "lrb_core/src" || err "lrb_core/src missing"
[ -f lrb_core/src/ledger.rs ] && pass "lrb_core ledger.rs" || err "ledger.rs missing"
[ -f lrb_core/src/rcp_engine.rs ] && pass "lrb_core rcp_engine.rs" || err "rcp_engine.rs missing"
[ -f lrb_core/src/phase_filters.rs ] && pass "lrb_core phase_filters.rs" || err "phase_filters.rs missing"
[ -f lrb_core/src/crypto.rs ] && pass "lrb_core crypto.rs (AEAD)" || err "crypto.rs missing"

echo "== NODE =="
for f in node/src/main.rs node/src/api.rs node/src/metrics.rs node/src/guard.rs node/src/storage.rs node/src/version.rs; do
  [ -f "$f" ] && pass "$f" || err "$f missing"
done
[ -f node/src/openapi.json ] && pass "node/src/openapi.json" || err "openapi.json missing"
[ -f node/build.rs ] && pass "node/build.rs" || err "node/build.rs missing"
[ -f node/Cargo.toml ] && pass "node/Cargo.toml" || err "node/Cargo.toml missing"

echo "== MODULES DIR =="
[ -d modules ] && pass "modules/ present" || err "modules/ missing"

echo "== WALLET =="
for f in www/wallet/index.html www/wallet/wallet.css www/wallet/wallet.js; do
  [ -f "$f" ] && pass "$f" || err "$f missing"
done

echo "== INFRA =="
for f in infra/systemd/logos-node@.service infra/systemd/logos-healthcheck.service infra/systemd/logos-healthcheck.timer \
         infra/nginx/logos-api-lb.conf.example; do
  [ -f "$f" ] && pass "$f" || err "$f missing"
done

echo "== SCRIPTS =="
[ -f scripts/bootstrap_node.sh ] && pass "scripts/bootstrap_node.sh" || err "bootstrap_node.sh missing"
[ -f scripts/logos_healthcheck.sh ] && pass "scripts/logos_healthcheck.sh" || err "logos_healthcheck.sh missing"

echo "== TOOLS =="
[ -f tools/bench/go/bench.go ] && pass "bench v4: tools/bench/go/bench.go" || err "bench.go missing"
[ -f tools/sdk/ts/index.mjs ] && pass "TS SDK: tools/sdk/ts/index.mjs" || err "TS SDK missing"
[ -f tools/sdk/ts/sdk_test.mjs ] && pass "TS SDK test" || err "TS SDK test missing"
[ -f tools/sdk/go/logosapi.go ] && pass "Go SDK: tools/sdk/go/logosapi.go" || err "Go SDK missing"

echo "== CONFIGS / EXAMPLES =="
ls -1 configs/env/*.example >/dev/null 2>&1 && pass "env examples present" || err "env examples missing"
# убедимся что реальные .env не попали
if git ls-files | grep -E '^configs/env/.*\.env$' >/dev/null; then
  err "real .env found in repo"
else
  pass "no real .env tracked"
fi

echo "== SNAPSHOTS (optional) =="
[ -d snapshots ] && echo "  [info] snapshots/ exists (ok)"; true

echo "== SIZE / SUMMARY =="
echo "  tracked files: $(git ls-files | wc -l)"
echo "  repo disk size: $(du -sh . | cut -f1)"

echo "== SECRET LEAK SCAN (quick) =="
git grep -nE '(PRIVATE|SECRET|BEGIN (RSA|EC) PRIVATE KEY)' || true
git grep -nE 'LRB_NODE_SK_HEX=[0-9a-fA-F]{64}$' || true

echo
if [ $fail -eq 0 ]; then
  echo "[RESULT] REPO OK"
else
  echo "[RESULT] FAILS PRESENT"; exit 1
fi
