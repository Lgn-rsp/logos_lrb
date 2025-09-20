
# LOGOS LRB — FULL BOOK SNAPSHOT
**Дата (UTC):** 2025-09-20T14-14-42Z
**Репозиторий:** /root/logos_lrb
**Хост:** vm15330919.example.com | **Пользователь:** root
**Kernel:** Linux 6.8.0-79-generic x86_64 GNU/Linux
**OS:** Ubuntu 24.04.3 LTS

## Git
- **Remote(s):**
  origin	git@github.com:Lgn-rsp/logos_lrb.git (fetch)
  origin	git@github.com:Lgn-rsp/logos_lrb.git (push)
- **Текущая ветка:** main
- **HEAD коммит:** ba2c3f3689f1ecd5ea27bfe4ea95af9ce9453590
- **Статус:**
## main...origin/main
 M Cargo.lock
 M Cargo.toml
 M configs/genesis.yaml
 M configs/logos_config.yaml
 D infra/systemd/logos-node.service
 M lrb_core/Cargo.toml
 M lrb_core/src/anti_replay.rs
 M lrb_core/src/beacon.rs
 M lrb_core/src/crypto.rs
 M lrb_core/src/dynamic_balance.rs
 M lrb_core/src/heartbeat.rs
 M lrb_core/src/ledger.rs
 M lrb_core/src/lib.rs
 M lrb_core/src/phase_consensus.rs
 D lrb_core/src/phase_filters.rs
 M lrb_core/src/phase_integrity.rs
 M lrb_core/src/quorum.rs
 M lrb_core/src/rcp_engine.rs
 M lrb_core/src/resonance.rs
 M lrb_core/src/sigpool.rs
 M lrb_core/src/spam_guard.rs
 M lrb_core/src/types.rs
 M node/Cargo.toml
 M node/build.rs
 M node/openapi/openapi.json
 D node/src/api.rs
 M node/src/api/base.rs
 M node/src/api/mod.rs
 M node/src/api/tx.rs
 M node/src/bridge.rs
 M node/src/guard.rs
 M node/src/lib.rs
 M node/src/main.rs
 M node/src/metrics.rs
 M node/src/state.rs
 M tools/make_book_and_push.sh
 M tools/make_full_book.sh
 M www/explorer/index.html
 M www/wallet/app.js
 M www/wallet/index.html
?? configs/archive_ddl.sql
?? configs/archive_indexes.sql
?? configs/archive_view_and_indexes.sql
?? core/rid_log.json
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T03-52-10Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T06-54-12Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T06-55-06Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T06-56-55Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T07-01-04Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T07-02-36Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T07-03-42Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-20T14-14-42Z.md
?? docs/MODULES_INVENTORY_2025-09-18T08-17-49Z.csv
?? docs/MODULES_INVENTORY_2025-09-18T08-17-49Z.json
?? docs/MODULES_INVENTORY_2025-09-18T08-17-49Z.txt
?? docs/MODULES_INVENTORY_2025-09-18T08-20-54Z.csv
?? docs/MODULES_INVENTORY_2025-09-18T08-20-54Z.json
?? docs/MODULES_INVENTORY_2025-09-18T08-20-54Z.txt
?? docs/MODULES_INVENTORY_2025-09-18T08-25-35Z.csv
?? docs/MODULES_INVENTORY_2025-09-18T08-25-35Z.json
?? docs/MODULES_INVENTORY_2025-09-18T08-25-35Z.txt
?? docs/MODULES_INVENTORY_2025-09-18T08-26-33Z.csv
?? docs/MODULES_INVENTORY_2025-09-18T08-26-33Z.json
?? docs/MODULES_INVENTORY_2025-09-18T08-26-33Z.txt
?? ledger.rs
?? lrb_core/src/engine.rs
?? lrb_core/src/phase_filters/
?? node/Cargo.toml.bak.124637
?? node/Cargo.toml.bak.141054
?? node/Cargo.toml.bak.141744
?? node/src/archive_ingest.rs
?? node/src/bin/
?? node/src/history_sled.rs
?? node/src/main.rs.bak.093626
?? node/src/main.rs.bak.102422
?? node/src/main.rs.bak.102926
?? node/src/main.rs.bak.115338
?? node/src/main.rs.bak.115808
?? node/src/main.rs.bak.120849
?? node/src/main.rs.bak.121503
?? node/src/main.rs.bak.122015
?? node/src/main.rs.bak.122520
?? node/src/main.rs.bak.123043
?? node/src/main.rs.bak.124637
?? node/src/main.rs.bak.125221
?? node/src/main.rs.bak.125641
?? node/src/main.rs.bak.131403
?? node/src/main.rs.bak.132240
?? node/src/main.rs.bak.133009
?? node/src/main.rs.bak.134537
?? node/src/main.rs.bak.135012
?? node/src/main.rs.bak.135356
?? node/src/openapi/openapi.json.bak
?? node/src/producer.rs
?? node/src/stake.rs
?? node/src/stake_api.rs
?? node/src/staking.rs
?? node/src/types.rs
?? node/src/wallet.rs
?? tools/make_book_and_push.shy
?? tools/make_tx.rs
?? tools/scan_modules.sh
?? tools/seed_balance/
?? www/index.html
?? www/wallet.js
?? www/wallet/app.v2.js
?? www/wallet/app.v3.js
?? www/wallet/staking.js
?? www/wallet/wallet.js
?? www/wallet3/

## Инструменты
- **Rust:** rustc 1.89.0 (29483883e 2025-08-04)
- **Cargo:** cargo 1.89.0 (c24e10642 2025-06-23)
- **OpenSSL:** OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- **jq:** jq-1.7
- **tree:** tree v2.1.1 © 1996 - 2023 by Steve Baker, Thomas Moore, Francesc Rocher, Florian Sesser, Kyosuke Tokoro

# Структура проекта (/root/logos_lrb)
_Скрытые и тяжёлые директории исключены: .git, target, node_modules, dist, build._
.
├── AUDIT_REPORT.md
├── Cargo.lock
├── Cargo.toml
├── configs
│   ├── archive_ddl.sql
│   ├── archive_indexes.sql
│   ├── archive_view_and_indexes.sql
│   ├── env
│   │   ├── node-a.env.example
│   │   ├── node-b.env.example
│   │   ├── node-c.env.example
│   │   └── node.env.example
│   ├── genesis.yaml
│   ├── keys.env.example
│   ├── logos_config.yaml
│   └── proxy.env.example
├── core
│   ├── beta_rollout.yaml
│   ├── offline_resonance.py
│   ├── onboarding_sim.py
│   ├── onboarding_ui.py
│   ├── __pycache__
│   │   ├── offline_resonance.cpython-312.pyc
│   │   ├── onboarding_sim.cpython-312.pyc
│   │   ├── onboarding_ui.cpython-312.pyc
│   │   ├── resonance_analyzer.cpython-312.pyc
│   │   ├── rid_builder.cpython-312.pyc
│   │   ├── ritual_quest.cpython-312.pyc
│   │   └── rLGN_converter.cpython-312.pyc
│   ├── resonance_analyzer.py
│   ├── rid_builder.py
│   ├── rid_log.json
│   ├── ritual_quest.py
│   └── rLGN_converter.py
├── data.sled.bak
│   ├── blobs
│   ├── conf
│   ├── db
│   └── snap.0000000000001C67
├── docs
│   ├── architecture.md
│   ├── LOGOS_LRB_BOOK
│   │   └── LOGOS_LRB_BOOK.md
│   ├── LOGOS_LRB_BOOK_2025-09-07T14-13-01Z.txt
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T07-58-28Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T08-05-35Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T08-13-55Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T08-28-23Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T08-38-56Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T08-51-17Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T10-16-59Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T11-37-16Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T12-37-01Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T14-27-33Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-18T16-28-37Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T02-39-45Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T03-25-36Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T03-52-10Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T03-53-25Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T06-47-32Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T06-54-12Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T06-55-06Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T06-56-55Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T07-01-04Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T07-02-36Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T07-03-42Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-19T07-07-15Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-20T14-14-42Z.md
│   ├── LOGOS_LRB_FULL_BOOK.md
│   ├── LRB_FULL_LIVE_2025-09-07.txt
│   ├── LRB_SNAPSHOT_20250904_1426.txt
│   ├── MODULES_INVENTORY_2025-09-18T08-17-49Z.csv
│   ├── MODULES_INVENTORY_2025-09-18T08-17-49Z.json
│   ├── MODULES_INVENTORY_2025-09-18T08-17-49Z.txt
│   ├── MODULES_INVENTORY_2025-09-18T08-20-54Z.csv
│   ├── MODULES_INVENTORY_2025-09-18T08-20-54Z.json
│   ├── MODULES_INVENTORY_2025-09-18T08-20-54Z.txt
│   ├── MODULES_INVENTORY_2025-09-18T08-25-35Z.csv
│   ├── MODULES_INVENTORY_2025-09-18T08-25-35Z.json
│   ├── MODULES_INVENTORY_2025-09-18T08-25-35Z.txt
│   ├── MODULES_INVENTORY_2025-09-18T08-26-33Z.csv
│   ├── MODULES_INVENTORY_2025-09-18T08-26-33Z.json
│   ├── MODULES_INVENTORY_2025-09-18T08-26-33Z.txt
│   ├── snapshots
│   │   └── LRB_FULL_LIVE_20250905_1218.txt
│   └── WORKFLOW.md
├── .gitignore
├── infra
│   ├── nginx
│   │   ├── logos-api-lb.conf.example
│   │   ├── lrb_wallet.conf
│   │   └── lrb_wallet.conf.sample
│   └── systemd
│       ├── exec.conf
│       ├── keys.conf
│       ├── keys.env.example
│       ├── logos-healthcheck.service
│       ├── logos-healthcheck.timer
│       ├── logos-node@.service
│       ├── logos-node.service.sample
│       ├── logos-snapshot.service
│       ├── logos-snapshot.timer
│       ├── lrb-proxy.service
│       ├── lrb-proxy.service.sample
│       ├── lrb-scanner.service
│       ├── lrb-scanner.service.sample
│       ├── override.conf
│       ├── runas.conf
│       ├── security.conf
│       ├── tuning.conf
│       ├── zz-consensus.conf
│       ├── zz-keys.conf
│       └── zz-logging.conf
├── ledger.rs
├── LOGOS_LRB_FULL_BOOK.md
├── lrb_core
│   ├── Cargo.toml
│   └── src
│       ├── anti_replay.rs
│       ├── beacon.rs
│       ├── crypto.rs
│       ├── dynamic_balance.rs
│       ├── engine.rs
│       ├── heartbeat.rs
│       ├── ledger.rs
│       ├── ledger.rs:24:5
│       ├── ledger.rs:29:5
│       ├── lib.rs
│       ├── nano.114024.save
│       ├── phase_consensus.rs
│       ├── phase_filters
│       │   └── mod.rs
│       ├── phase_integrity.rs
│       ├── quorum.rs
│       ├── rcp_engine.rs
│       ├── resonance.rs
│       ├── sigpool.rs
│       ├── spam_guard.rs
│       └── types.rs
├── modules
│   ├── beacon_emitter.rs
│   ├── env_impact_tracker.py
│   ├── external_phase_broadcaster.rs
│   ├── external_phase_link.rs
│   ├── genesis_fragment_seeds.rs
│   ├── go_to_market.yaml
│   ├── heartbeat_monitor.rs
│   ├── legacy_migrator.rs
│   ├── maintenance_strategy.yaml
│   ├── resonance_analytics_frontend.tsx
│   ├── resonance_emergency_plan.yaml
│   ├── resonance_meshmap.yaml
│   ├── resonance_tutor.py
│   ├── ritual_engine.rs
│   ├── symbolic_parser.py
│   ├── uplink_controller.rs
│   └── uplink_router.rs
├── node
│   ├── build.rs
│   ├── Cargo.toml
│   ├── Cargo.toml.bak.124637
│   ├── Cargo.toml.bak.141054
│   ├── Cargo.toml.bak.141744
│   ├── openapi
│   │   └── openapi.json
│   └── src
│       ├── admin.rs
│       ├── api
│       │   ├── archive.rs
│       │   ├── base.rs
│       │   ├── mod.rs
│       │   ├── staking.rs
│       │   └── tx.rs
│       ├── api.rs:10:5
│       ├── api.rs:108:5
│       ├── api.rs:59:39
│       ├── archive
│       │   ├── mod.rs
│       │   ├── pg.rs
│       │   └── sqlite.rs
│       ├── archive_ingest.rs
│       ├── auth.rs
│       ├── auth.rs:37:5
│       ├── auth.rs:69:15
│       ├── bin
│       │   ├── bench_burst.rs
│       │   ├── make_tx.rs
│       │   ├── mint.rs
│       │   ├── rid_gen.rs
│       │   ├── sign_submit.rs
│       │   ├── tx_json.rs
│       │   ├── tx_submit.rs
│       │   └── tx_submit_try.rs
│       ├── bridge_journal.rs
│       ├── bridge.rs
│       ├── fork.rs
│       ├── gossip.rs
│       ├── guard.rs
│       ├── health.rs
│       ├── history_sled.rs
│       ├── JSON
│       ├── LE
│       ├── lib.rs
│       ├── main.rs
│       ├── main.rs:15:5
│       ├── main.rs:73:25
│       ├── main.rs.bak.093626
│       ├── main.rs.bak.102422
│       ├── main.rs.bak.102926
│       ├── main.rs.bak.115338
│       ├── main.rs.bak.115808
│       ├── main.rs.bak.120849
│       ├── main.rs.bak.121503
│       ├── main.rs.bak.122015
│       ├── main.rs.bak.122520
│       ├── main.rs.bak.123043
│       ├── main.rs.bak.124637
│       ├── main.rs.bak.125221
│       ├── main.rs.bak.125641
│       ├── main.rs.bak.131403
│       ├── main.rs.bak.132240
│       ├── main.rs.bak.133009
│       ├── main.rs.bak.134537
│       ├── main.rs.bak.135012
│       ├── main.rs.bak.135356
│       ├── metrics.rs
│       ├── openapi
│       │   ├── openapi.json
│       │   └── openapi.json.bak
│       ├── openapi.json
│       ├── openapi.rs
│       ├── payout_adapter.rs
│       ├── peers.rs
│       ├── producer.rs
│       ├── stake_api.rs
│       ├── stake_claim.rs
│       ├── stake.rs
│       ├── staking.rs
│       ├── state.rs
│       ├── storage.rs
│       ├── types.rs
│       ├── version.rs
│       └── wallet.rs
├── py_err.log
├── README.md
├── scripts
│   ├── bootstrap_node.sh
│   ├── collect_and_push.sh
│   └── logos_healthcheck.sh
├── src
│   ├── bin
│   │   ├── ai_signal_listener.rs
│   │   ├── orchestration_control.rs
│   │   ├── rcp_engine.rs
│   │   ├── resonance_mesh.rs
│   │   ├── resonance_sync.rs
│   │   ├── sigma_t.rs
│   │   └── Λ0.rs
│   ├── core
│   │   ├── biosphere_scanner.rs
│   │   ├── dao.rs
│   │   ├── logos_self.rs
│   │   ├── phase.rs
│   │   ├── resonance.rs
│   │   └── tx_spam_guard.rs
│   ├── lib.rs
│   └── utils
│       ├── filters.rs
│       ├── frequency.rs
│       ├── math.rs
│       └── types.rs
├── tools
│   ├── admin_cli.sh
│   ├── batch.json
│   ├── bench
│   │   └── go
│   │       └── bench.go
│   ├── book_make.sh
│   ├── book_restore.sh
│   ├── gen_full_codemap.py
│   ├── go_test
│   │   ├── go.mod
│   │   ├── go.sum
│   │   ├── main.go
│   │   └── two_rids.go
│   ├── k6_smoke.js
│   ├── load
│   │   ├── go.mod
│   │   ├── go.sum
│   │   └── load_submit_tx.go
│   ├── load_healthz.sh
│   ├── lrb_audit.sh
│   ├── make_book_and_push.sh
│   ├── make_book_and_push.shy
│   ├── make_codebook.sh
│   ├── make_full_book.sh
│   ├── make_full_snapshot_live.sh
│   ├── make_tx.rs
│   ├── prepare_payer.sh
│   ├── repo_audit.sh
│   ├── results.bin
│   ├── scan_modules.sh
│   ├── sdk
│   │   ├── go
│   │   │   ├── logosapi.go
│   │   │   └── main.go
│   │   └── ts
│   │       ├── index.mjs
│   │       └── sdk_test.mjs
│   ├── sdk_go
│   ├── sdk_rust
│   ├── seed_balance
│   │   ├── Cargo.toml
│   │   └── src
│   │       └── main.rs
│   ├── targets.jsonl
│   ├── test_tx.sh
│   ├── tx_load.sh
│   ├── tx_one.sh
│   ├── vegeta_submit_live.sh
│   └── vegeta_submit.sh
├── wallet-proxy
│   ├── app.py
│   ├── requirements.txt
│   └── scanner.py
└── www
    ├── explorer
    │   ├── explorer.css
    │   ├── explorer.js
    │   └── index.html
    ├── index.html
    ├── wallet
    │   ├── app.html
    │   ├── app.js
    │   ├── app.v2.js
    │   ├── app.v3.js
    │   ├── auth.js
    │   ├── index.html
    │   ├── login.html
    │   ├── staking.js
    │   ├── wallet.css
    │   └── wallet.js
    ├── wallet3
    │   ├── app.v3.js
    │   └── index.html
    └── wallet.js

46 directories, 301 files

# Ключевые файлы

### /root/logos_lrb/node/src/openapi/openapi.json
```json
     1	{
     2	  "openapi": "3.0.3",
     3	  "info": { "title": "LOGOS LRB API", "version": "0.1.0" },
     4	  "paths": {
     5	    "/healthz": {
     6	      "get": { "summary": "health", "responses": { "200": { "description": "OK" } } }
     7	    },
     8	    "/livez": {
     9	      "get": { "summary": "liveness", "responses": { "200": { "description": "alive" } } }
    10	    },
    11	    "/readyz": {
    12	      "get": {
    13	        "summary": "readiness",
    14	        "responses": {
    15	          "200": { "description": "ready" },
    16	          "503": { "description": "not ready" }
    17	        }
    18	      }
    19	    },
    20	    "/version": { "get": { "summary": "build info", "responses": { "200": { "description": "OK" } } } },
    21	    "/metrics": { "get": { "summary": "prometheus metrics", "responses": { "200": { "description": "OK" } } } },
    22	
    23	    "/head": {
    24	      "get": {
    25	        "summary": "current head heights",
    26	        "responses": {
    27	          "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Head" } } } }
    28	        }
    29	      }
    30	    },
    31	
    32	    "/submit_tx": {
    33	      "post": {
    34	        "summary": "submit transaction (Ed25519 verified)",
    35	        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TxIn" } } } },
    36	        "responses": {
    37	          "200": { "description": "accepted", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitResult" } } } },
    38	          "401": { "description": "bad signature" },
    39	          "409": { "description": "nonce reuse" }
    40	        }
    41	      }
    42	    },
    43	
    44	    "/submit_tx_batch": {
    45	      "post": {
    46	        "summary": "submit batch of transactions (Ed25519 verified)",
    47	        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitBatchReq" } } } },
    48	        "responses": {
    49	          "200": { "description": "per-item results", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/SubmitBatchItem" } } } } }
    50	        }
    51	      }
    52	    },
    53	
    54	    "/archive/blocks": {
    55	      "get": {
    56	        "summary": "recent blocks",
    57	        "parameters": [
    58	          { "name": "limit", "in": "query", "schema": { "type": "integer" } },
    59	          { "name": "before_height", "in": "query", "schema": { "type": "integer" } }
    60	        ],
    61	        "responses": { "200": { "description": "OK" } }
    62	      }
    63	    },
    64	    "/archive/txs": {
    65	      "get": {
    66	        "summary": "recent txs",
    67	        "parameters": [
    68	          { "name": "limit", "in": "query", "schema": { "type": "integer" } },
    69	          { "name": "rid", "in": "query", "schema": { "type": "string" } },
    70	          { "name": "before_ts", "in": "query", "schema": { "type": "integer" } }
    71	        ],
    72	        "responses": { "200": { "description": "OK" } }
    73	      }
    74	    },
    75	    "/archive/history/{rid}": {
    76	      "get": {
    77	        "summary": "history by rid",
    78	        "parameters": [ { "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } } ],
    79	        "responses": { "200": { "description": "OK" } }
    80	      }
    81	    },
    82	    "/archive/tx/{txid}": {
    83	      "get": {
    84	        "summary": "tx by id",
    85	        "parameters": [ { "name": "txid", "in": "path", "required": true, "schema": { "type": "string" } } ],
    86	        "responses": { "200": { "description": "OK" }, "404": { "description": "not found" } }
    87	      }
    88	    },
    89	
    90	    "/stake/delegate": {
    91	      "post": {
    92	        "summary": "delegate (compat wrapper)",
    93	        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
    94	        "responses": { "200": { "description": "OK" } }
    95	      }
    96	    },
    97	    "/stake/undelegate": {
    98	      "post": {
    99	        "summary": "undelegate (compat wrapper)",
   100	        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
   101	        "responses": { "200": { "description": "OK" } }
   102	      }
   103	    },
   104	    "/stake/claim": {
   105	      "post": {
   106	        "summary": "claim rewards (compat wrapper)",
   107	        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/StakeAction" } } } },
   108	        "responses": { "200": { "description": "OK" } }
   109	      }
   110	    },
   111	    "/stake/my/{rid}": {
   112	      "get": {
   113	        "summary": "my delegations + rewards (compat wrapper)",
   114	        "parameters": [ { "name": "rid", "in": "path", "required": true, "schema": { "type": "string" } } ],
   115	        "responses": { "200": { "description": "OK" } }
   116	      }
   117	    },
   118	    "/stake/claim_settle": {
   119	      "post": {
   120	        "summary": "settle reward into ledger",
   121	        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ClaimSettle" } } } },
   122	        "responses": { "200": { "description": "OK" } }
   123	      }
   124	    },
   125	
   126	    "/bridge/deposit_json": {
   127	      "post": {
   128	        "summary": "bridge deposit (mTLS + HMAC)",
   129	        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeDeposit" } } } },
   130	        "responses": { "200": { "description": "idempotent OK" }, "202": { "description": "queued/retry" }, "401": { "description": "unauthorized (key/HMAC/nonce)" } }
   131	      }
   132	    },
   133	    "/bridge/redeem_json": {
   134	      "post": {
   135	        "summary": "bridge redeem (mTLS + HMAC)",
   136	        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BridgeRedeem" } } } },
   137	        "responses": { "200": { "description": "ok" }, "202": { "description": "queued/retry" }, "401": { "description": "unauthorized (key/HMAC/nonce)" } }
   138	      }
   139	    }
   140	  },
   141	
   142	  "components": {
   143	    "schemas": {
   144	      "Head": {
   145	        "type": "object",
   146	        "required": ["height","finalized"],
   147	        "properties": {
   148	          "height":   { "type": "integer", "format": "uint64" },
   149	          "finalized":{ "type": "integer", "format": "uint64" }
   150	        }
   151	      },
   152	      "Balance": {
   153	        "type": "object",
   154	        "required": ["rid","balance","nonce"],
   155	        "properties": {
   156	          "rid":     { "type": "string" },
   157	          "balance": { "type": "integer", "format": "uint128" },
   158	          "nonce":   { "type": "integer", "format": "uint64" }
   159	        }
   160	      },
   161	      "TxIn": {
   162	        "type": "object",
   163	        "required": ["from","to","amount","nonce","sig_hex"],
   164	        "properties": {
   165	          "from":    { "type": "string", "description": "base58(pubkey)" },
   166	          "to":      { "type": "string" },
   167	          "amount":  { "type": "integer", "format": "uint64" },
   168	          "nonce":   { "type": "integer", "format": "uint64" },
   169	          "sig_hex": { "type": "string" },
   170	          "memo":    { "type": "string", "nullable": true }
   171	        }
   172	      },
   173	      "SubmitResult": {
   174	        "type": "object",
   175	        "required": ["ok","info"],
   176	        "properties": {
   177	          "ok":   { "type": "boolean" },
   178	          "txid": { "type": "string", "nullable": true },
   179	          "info": { "type": "string" }
   180	        }
   181	      },
   182	      "SubmitBatchReq": {
   183	        "type": "object",
   184	        "required": ["txs"],
   185	        "properties": {
   186	          "txs": { "type": "array", "items": { "$ref": "#/components/schemas/TxIn" } }
   187	        }
   188	      },
   189	      "SubmitBatchItem": {
   190	        "type": "object",
   191	        "required": ["ok","info","index"],
   192	        "properties": {
   193	          "ok":    { "type": "boolean" },
   194	          "txid":  { "type": "string", "nullable": true },
   195	          "info":  { "type": "string" },
   196	          "index": { "type": "integer" }
   197	        }
   198	      },
   199	      "StakeAction": {
   200	        "type": "object",
   201	        "required": ["rid"],
   202	        "properties": {
   203	          "rid":       { "type": "string" },
   204	          "validator": { "type": "string" },
   205	          "amount":    { "type": "integer", "format": "uint64", "nullable": true }
   206	        }
   207	      },
   208	      "ClaimSettle": {
   209	        "type": "object",
   210	        "required": ["rid","amount"],
   211	        "properties": {
   212	          "rid":    { "type": "string" },
   213	          "amount": { "type": "integer", "format": "uint64" }
   214	        }
   215	      },
   216	      "BridgeDeposit": {
   217	        "type": "object",
   218	        "required": ["rid","amount","ext_txid"],
   219	        "properties": {
   220	          "rid":      { "type": "string" },
   221	          "amount":   { "type": "integer", "format": "uint64" },
   222	          "ext_txid": { "type": "string" }
   223	        }
   224	      },
   225	      "BridgeRedeem": {
   226	        "type": "object",
   227	        "required": ["rid","amount","ext_txid"],
   228	        "properties": {
   229	          "rid":      { "type": "string" },
   230	          "amount":   { "type": "integer", "format": "uint64" },
   231	          "ext_txid": { "type": "string" }
   232	        }
   233	      }
   234	    }
   235	  }
   236	}
```

### /root/logos_lrb/node/src/main.rs
```rust json
     1	use axum::{
     2	    routing::{get, post},
     3	    Router,
     4	    Json,
     5	    extract::State,
     6	};
     7	use std::net::SocketAddr;
     8	use std::sync::Arc;
     9	
    10	use tower::ServiceBuilder;
    11	use tower_http::trace::TraceLayer;
    12	use tracing::{info, warn};
    13	use tracing_subscriber::{prelude::*, EnvFilter};
    14	
    15	mod api;
    16	mod bridge;
    17	mod bridge_journal;
    18	mod payout_adapter;
    19	mod admin;
    20	mod gossip;
    21	mod peers;
    22	mod state;
    23	mod guard;
    24	mod storage;
    25	mod metrics;
    26	mod openapi;
    27	mod archive;
    28	mod auth;
    29	mod stake_claim;
    30	mod health;
    31	mod wallet;
    32	mod stake;
    33	mod producer;
    34	
    35	/// /version (из Cargo.toml)
    36	async fn version() -> Json<serde_json::Value> {
    37	    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }))
    38	}
    39	
    40	/// Единый роутер (ВАЖНО: один with_state в начале; тип Router<Arc<AppState>>)
    41	fn router(app_state: Arc<state::AppState>) -> Router<Arc<state::AppState>> {
    42	    Router::new()
    43	        .with_state(app_state.clone())
    44	
    45	        // --- public ---
    46	        .route("/healthz", get(api::healthz))
    47	        .route("/livez",   get(health::livez))
    48	        .route("/readyz",  get(health::readyz))
    49	        .route("/head",    get(api::head))
    50	
    51	        .route("/submit_tx",       post(api::submit_tx))
    52	        .route("/submit_tx_batch", post(api::submit_tx_batch))
    53	
    54	        .route("/balance/:rid", get(api::balance))
    55	        .route("/economy",      get(api::economy))
    56	        .route("/history/:rid", get(api::history))
    57	
    58	        // --- archive (PG) ---
    59	        .route("/archive/blocks",        get(api::archive_blocks))
    60	        .route("/archive/txs",           get(api::archive_txs))
    61	        .route("/archive/history/:rid",  get(api::archive_history))
    62	        .route("/archive/tx/:txid",      get(api::archive_tx))
    63	
    64	        // --- staking wrappers ---
    65	        .route("/stake/delegate",   post(api::stake_delegate))
    66	        .route("/stake/undelegate", post(api::stake_undelegate))
    67	        .route("/stake/claim",      post(api::stake_claim))
    68	        .route("/stake/my/:rid",    get(api::stake_my))
    69	        .route("/stake/claim_settle", post(stake_claim::claim_settle))
    70	
    71	        // --- bridge JSON (лямбды — гарантированный Handler)
    72	        .route("/bridge/deposit_json", post(|st, hdrs, req| async move {
    73	            bridge::deposit_json(st, hdrs, req).await
    74	        }))
    75	        .route("/bridge/redeem_json",  post(|st, hdrs, req| async move {
    76	            bridge::redeem_json(st, hdrs, req).await
    77	        }))
    78	
    79	        // --- bridge обычные
    80	        .route("/bridge/deposit", post(|st: State<Arc<state::AppState>>, Json(body): Json<bridge::DepositReq>| async move {
    81	            bridge::deposit(st, Json(body)).await
    82	        }))
    83	        .route("/bridge/redeem",  post(|st: State<Arc<state::AppState>>, Json(body): Json<bridge::RedeemReq>| async move {
    84	            bridge::redeem(st, Json(body)).await
    85	        }))
    86	        .route("/health/bridge", get(bridge::health))
    87	
    88	        // --- misc ---
    89	        .route("/version",      get(version))
    90	        .route("/metrics",      get(metrics::prometheus))
    91	        .route("/openapi.json", get(openapi::serve))
    92	
    93	        // --- admin ---
    94	        .route("/admin/set_balance", post(admin::set_balance))
    95	        .route("/admin/bump_nonce",  post(admin::bump_nonce))
    96	        .route("/admin/set_nonce",   post(admin::set_nonce))
    97	        .route("/admin/mint",        post(admin::mint))
    98	        .route("/admin/burn",        post(admin::burn))
    99	
   100	        // --- legacy (если нужно) ---
   101	        .merge(wallet::routes())
   102	        .merge(stake::routes())
   103	
   104	        // --- layers ---
   105	        .layer(
   106	            ServiceBuilder::new()
   107	                .layer(TraceLayer::new_for_http())
   108	                .layer(axum::middleware::from_fn(guard::rate_limit_mw))
   109	                .layer(axum::middleware::from_fn(metrics::track))
   110	        )
   111	}
   112	
   113	#[tokio::main]
   114	async fn main() -> anyhow::Result<()> {
   115	    // logging
   116	    tracing_subscriber::registry()
   117	        .with(tracing_subscriber::fmt::layer())
   118	        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
   119	        .init();
   120	
   121	    // secrets
   122	    auth::assert_secrets_on_start().expect("secrets missing");
   123	
   124	    // state
   125	    let app_state = Arc::new(state::AppState::new()?);
   126	
   127	    // optional archive init
   128	    if let Some(ar) = archive::Archive::new_from_env().await {
   129	        unsafe {
   130	            let p = Arc::as_ptr(&app_state) as *mut state::AppState;
   131	            (*p).archive = Some(ar);
   132	        }
   133	        info!("archive backend initialized");
   134	    } else {
   135	        warn!("archive disabled");
   136	    }
   137	
   138	    // producer + retry worker
   139	    info!("producer start");
   140	    let _producer = producer::run(app_state.clone());
   141	    tokio::spawn(bridge::retry_worker(app_state.clone()));
   142	
   143	    // bind & serve — КАНОН Axum 0.6
   144	    let addr: SocketAddr = state::bind_addr();
   145	    info!("logos_node listening on {}", addr);
   146	
   147	    let app = router(app_state);
   148	    let app_stateless = axum::Router::new().merge(app);
   149	    axum::Server::bind(&addr)
   150	        .serve(app_stateless.into_make_service())
   151	        .await?;
   152	
   153	    Ok(())
   154	}
```

### /root/logos_lrb/lrb_core/src/lib.rs
```rust json
     1	pub mod types;
     2	pub mod ledger;
     3	pub mod phase_consensus;
     4	pub mod engine;
     5	pub mod phase_filters;
     6	
     7	// Полный ре-экспорт, чтобы узел видел все публичные методы/типы без рассинхрона
     8	pub use types::*;
     9	pub use ledger::*;
    10	pub use engine::*;
    11	pub use phase_consensus::*;
```

### /root/logos_lrb/lrb_core/src/ledger.rs
```rust json
     1	use sled::{Db, Tree};
     2	use anyhow::Result;
     3	use serde::{Serialize, Deserialize};
     4	use hex::{FromHex, ToHex};
     5	use blake3::Hasher;
     6	use std::time::{SystemTime, UNIX_EPOCH};
     7	use std::convert::TryInto;
     8	
     9	use crate::types::BlockHash;
    10	
    11	// ===== helpers / keys =====
    12	pub fn now_ms() -> u64 {
    13	    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
    14	}
    15	fn be64(v: u64) -> [u8;8] { v.to_be_bytes() }
    16	fn from_be64(v: &[u8]) -> u64 { u64::from_be_bytes(v.try_into().unwrap()) }
    17	
    18	const H_H:  &str = "h";   // head height (u64 be)
    19	const H_HH: &str = "hh";  // head hash (hex)
    20	const H_FIN:&str = "fin"; // finalized height (u64 be)
    21	const H_M:  &str = "mint";
    22	const H_B:  &str = "burn";
    23	
    24	fn k_block_by_height(h: u64) -> String { format!("b|{}", h) } // -> StoredBlock(JSON)
    25	fn k_bh(hex: &str) -> String          { format!("bh|{}", hex) } // -> be64(height)
    26	fn k_tx(txid: &str) -> String         { format!("t|{}", txid) } // -> StoredTx(JSON)
    27	
    28	fn k_bal(rid: &str)   -> String { format!("bal|{}", rid) }    // u64
    29	fn k_nonce(rid: &str) -> String { format!("nonce|{}", rid) }  // u64
    30	
    31	fn k_acct(rid: &str, h: u64, idx: u32) -> String { format!("a|{}|{}|{}", rid, h, idx) }
    32	fn acct_prefix(rid: &str) -> String { format!("a|{}|", rid) }
    33	
    34	#[derive(Serialize, Deserialize, Clone)]
    35	pub struct StoredBlock {
    36	    pub height: u64,
    37	    pub hash:   String,   // hex
    38	    pub ts_ms:  u128,
    39	    pub tx_ids: Vec<String>,
    40	}
    41	
    42	#[derive(Serialize, Deserialize, Clone)]
    43	pub struct StoredTx {
    44	    pub txid:   String,
    45	    pub from:   String,
    46	    pub to:     String,
    47	    pub amount: u64,
    48	    pub nonce:  u64,
    49	    pub height: u64,
    50	    pub index:  u32,
    51	    /// время в мс — именно `ts`, как ждёт node (он делает stx.ts/1000)
    52	    pub ts:     u64,
    53	    /// мемо опционально; node может передать
    54	    pub memo:   Option<String>,
    55	}
    56	
    57	#[derive(Serialize, Deserialize, Clone)]
    58	pub struct BlockHeaderView { pub block_hash: String }
    59	
    60	// ===== Ledger =====
    61	#[derive(Clone)]
    62	pub struct Ledger {
    63	    db: Db,
    64	    head:   Tree,   // meta
    65	    blocks: Tree,   // b|<h>     -> StoredBlock(JSON)
    66	    bh:     Tree,   // bh|<hex>  -> be64(height)
    67	    txs:    Tree,   // t|<txid>  -> StoredTx(JSON)
    68	    acct:   Tree,   // a|rid|h|idx -> txid
    69	    bal:    Tree,   // bal|rid   -> be64(balance)
    70	    nonces: Tree,   // nonce|rid -> be64(nonce)
    71	}
    72	
    73	impl Ledger {
    74	    pub fn open(path: &str) -> Result<Self> {
    75	        let db = sled::open(path)?;
    76	        Ok(Self {
    77	            head:   db.open_tree("head")?,
    78	            blocks: db.open_tree("blocks")?,
    79	            bh:     db.open_tree("bh_index")?,
    80	            txs:    db.open_tree("txs")?,
    81	            acct:   db.open_tree("acct_txs")?,
    82	            bal:    db.open_tree("balances")?,
    83	            nonces: db.open_tree("nonces")?,
    84	            db,
    85	        })
    86	    }
    87	
    88	    // ===== Совместимость с node: head/height API =====
    89	    pub fn load_head(&self) -> BlockHash {
    90	        let hh_hex = self.head.get(H_HH).ok().flatten()
    91	            .and_then(|v| String::from_utf8(v.to_vec()).ok()).unwrap_or_default();
    92	        <[u8;32]>::from_hex(hh_hex).map(BlockHash).unwrap_or(BlockHash([0u8;32]))
    93	    }
    94	    pub fn load_head_height(&self) -> u64 {
    95	        self.head.get(H_H).ok().flatten().map(|v| from_be64(&v)).unwrap_or(0)
    96	    }
    97	    pub fn height(&self) -> Result<u64> { Ok(self.load_head_height()) }
    98	    pub fn head_height(&self) -> Result<u64> { self.height() }
    99	    pub fn height_u64(&self) -> u64 { self.load_head_height() }
   100	
   101	    pub fn set_head(&self, h: u64, hash_hex: &str) -> Result<()> {
   102	        self.head.insert(H_H,  &be64(h))?;
   103	        self.head.insert(H_HH, hash_hex.as_bytes())?;
   104	        Ok(())
   105	    }
   106	    pub fn set_finalized(&self, h: u64) -> Result<()> {
   107	        self.head.insert(H_FIN, &be64(h))?;
   108	        Ok(())
   109	    }
   110	
   111	    pub fn get_block_by_height(&self, h: u64) -> Result<BlockHeaderView> {
   112	        let key = k_block_by_height(h);
   113	        if let Some(v) = self.blocks.get(key)? {
   114	            let sb: StoredBlock = serde_json::from_slice(&v)?;
   115	            Ok(BlockHeaderView { block_hash: sb.hash })
   116	        } else {
   117	            let hh = self.head.get(H_HH)?
   118	                .map(|v| String::from_utf8(v.to_vec()).unwrap())
   119	                .unwrap_or_default();
   120	            Ok(BlockHeaderView { block_hash: hh })
   121	        }
   122	    }
   123	
   124	    /// Быстрый поиск высоты по hash (для Engine/BFT)
   125	    pub fn lookup_height(&self, b: &BlockHash) -> Option<u64> {
   126	        let hex = b.0.encode_hex::<String>();
   127	        self.bh.get(k_bh(&hex)).ok().flatten().map(|iv| from_be64(&iv))
   128	    }
   129	
   130	    /// Коммит блока (без применения tx)
   131	    pub fn commit_block(&self, b: &BlockHash, h: u64) {
   132	        let hex = b.0.encode_hex::<String>();
   133	        let sb = StoredBlock { height: h, hash: hex.clone(), ts_ms: now_ms() as u128, tx_ids: vec![] };
   134	        self.blocks.insert(k_block_by_height(h), serde_json::to_vec(&sb).unwrap()).unwrap();
   135	        self.bh.insert(k_bh(&hex), &be64(h)).unwrap();
   136	        self.head.insert(H_H, &be64(h)).unwrap();
   137	        self.head.insert(H_HH, hex.as_bytes()).unwrap();
   138	    }
   139	
   140	    pub fn db(&self) -> &Db { &self.db }
   141	
   142	    // ===== Балансы / нонсы / supply =====
   143	    pub fn get_balance(&self, rid: &str) -> Result<u64> {
   144	        Ok(self.bal.get(k_bal(rid))?.map(|v| from_be64(&v)).unwrap_or(0))
   145	    }
   146	    pub fn set_balance(&self, rid: &str, v: u128) -> Result<()> {
   147	        let clipped = if v > u128::from(u64::MAX) { u64::MAX } else { v as u64 };
   148	        self.bal.insert(k_bal(rid), &be64(clipped))?;
   149	        Ok(())
   150	    }
   151	    pub fn get_nonce(&self, rid: &str) -> Result<u64> {
   152	        Ok(self.nonces.get(k_nonce(rid))?.map(|v| from_be64(&v)).unwrap_or(0))
   153	    }
   154	    pub fn set_nonce(&self, rid: &str, value: u64) -> Result<()> {
   155	        self.nonces.insert(k_nonce(rid), &be64(value))?;
   156	        Ok(())
   157	    }
   158	    pub fn bump_nonce(&self, rid: &str) -> Result<u64> {
   159	        let n = self.get_nonce(rid)? + 1;
   160	        self.set_nonce(rid, n)?;
   161	        Ok(n)
   162	    }
   163	
   164	    pub fn add_minted(&self, amount: u64) -> Result<u64> {
   165	        let cur = self.head.get(H_M)?.map(|v| from_be64(&v)).unwrap_or(0);
   166	        let new = cur.saturating_add(amount);
   167	        self.head.insert(H_M, &be64(new))?;
   168	        Ok(new.saturating_sub(self.head.get(H_B)?.map(|v| from_be64(&v)).unwrap_or(0)))
   169	    }
   170	    pub fn add_burned(&self, amount: u64) -> Result<u64> {
   171	        let cur = self.head.get(H_B)?.map(|v| from_be64(&v)).unwrap_or(0);
   172	        let new = cur.saturating_add(amount);
   173	        self.head.insert(H_B, &be64(new))?;
   174	        Ok(self.head.get(H_M)?.map(|v| from_be64(&v)).unwrap_or(0).saturating_sub(new))
   175	    }
   176	    pub fn supply(&self) -> Result<(u64,u64)> {
   177	        Ok((
   178	            self.head.get(H_M)?.map(|v| from_be64(&v)).unwrap_or(0),
   179	            self.head.get(H_B)?.map(|v| from_be64(&v)).unwrap_or(0),
   180	        ))
   181	    }
   182	
   183	    // ===== Транзакции / история аккаунта =====
   184	    pub fn get_tx(&self, txid: &str) -> Result<Option<StoredTx>> {
   185	        Ok(self.txs.get(k_tx(txid))?.map(|v| serde_json::from_slice::<StoredTx>(&v)).transpose()?)
   186	    }
   187	
   188	    pub fn account_txs_page(&self, rid: &str, _cursor: u64, limit: u64) -> Result<Vec<StoredTx>> {
   189	        let mut out = Vec::new();
   190	        let prefix = acct_prefix(rid).into_bytes();
   191	        for kv in self.acct.scan_prefix(prefix).take(limit as usize) {
   192	            let (_k, v) = kv?;
   193	            let txid = String::from_utf8(v.to_vec()).unwrap();
   194	            if let Some(stx) = self.get_tx(&txid)? {
   195	                out.push(stx);
   196	            }
   197	        }
   198	        Ok(out)
   199	    }
   200	
... (truncated)
```

### /root/logos_lrb/lrb_core/src/dynamic_balance.rs
```rust json
     1	// Простейшая адаптация LGN_cost: основана на длине мемпула.
     2	#[derive(Clone, Debug)]
     3	pub struct DynamicBalance {
     4	    base_cost_microunits: u64, // 1e-6 LGN
     5	    slope_per_tx: u64,         // увеличение за каждую tx в мемпуле
     6	}
     7	
     8	impl DynamicBalance {
     9	    pub fn new(base: u64, slope: u64) -> Self {
    10	        Self {
    11	            base_cost_microunits: base,
    12	            slope_per_tx: slope,
    13	        }
    14	    }
    15	    pub fn lgn_cost(&self, mempool_len: usize) -> u64 {
    16	        self.base_cost_microunits + (self.slope_per_tx * mempool_len as u64)
    17	    }
    18	}
```

### /root/logos_lrb/lrb_core/src/spam_guard.rs
```rust json
     1	use anyhow::{anyhow, Result};
     2	
     3	#[derive(Clone, Debug)]
     4	pub struct SpamGuard {
     5	    max_mempool: usize,
     6	    max_tx_per_block: usize,
     7	    max_amount: u64,
     8	}
     9	
    10	impl SpamGuard {
    11	    pub fn new(max_mempool: usize, max_tx_per_block: usize, max_amount: u64) -> Self {
    12	        Self {
    13	            max_mempool,
    14	            max_tx_per_block,
    15	            max_amount,
    16	        }
    17	    }
    18	    pub fn check_mempool(&self, cur_len: usize) -> Result<()> {
    19	        if cur_len > self.max_mempool {
    20	            return Err(anyhow!("mempool overflow"));
    21	        }
    22	        Ok(())
    23	    }
    24	    pub fn check_amount(&self, amount: u64) -> Result<()> {
    25	        if amount == 0 || amount > self.max_amount {
    26	            return Err(anyhow!("amount out of bounds"));
    27	        }
    28	        Ok(())
    29	    }
    30	    pub fn max_block_txs(&self) -> usize {
    31	        self.max_tx_per_block
    32	    }
    33	}
```

### /root/logos_lrb/configs/genesis.yaml
```
     1	# LOGOS LRB — GENESIS (full-mainnet ready)
     2	l0_symbol: "Λ0"
     3	
     4	sigma:
     5	  f1: 7.83
     6	  f2: 1.618
     7	  harmonics: [432, 864, 3456]
     8	
     9	emission:
    10	  total_lgn: 81000000
    11	  cap_micro: 81000000000000
    12	  allocations:
    13	    - { rid: "Λ0@7.83Hzφ0.0000", micro: 1000000000 } # 1000 LGN для технологических нужд
    14	
    15	consensus:
    16	  producer_slot_ms: 1000
    17	  bft:
    18	    enabled: true
    19	    # список валидаторов (RID или валидатор-ID, как у тебя заведено)
    20	    validators:
    21	      - "val1_rid_base58"
    22	      - "val2_rid_base58"
    23	      - "val3_rid_base58"
    24	    # 2/3 финализация: автоматически вычисляется из числа валидаторов
    25	    view_timeout_ms: 3000       # таймаут смены раунда (view)
    26	    max_round_skew: 3           # макс. допуск «скоса» раунда при лаге
    27	    equivocation_slash: true    # на будущее: реакция на двойное голосование
    28	  fork_choice: "LMD-GHOST"      # стратегия выбора ветки
    29	
    30	bridge:
    31	  max_per_tx_micro: 10000000
    32	
    33	guard:
    34	  rate_limit_qps: 500
    35	  rate_limit_burst: 1000
    36	
    37	limits:
    38	  mempool_cap: 200000
    39	  max_block_tx: 20000
    40	
    41	phase:
    42	  enabled: true
    43	  freqs_hz: [7.83, 1.618, 432]
    44	  min_score: -0.2
    45	
    46	explorer:
    47	  page_size: 50
```

### /root/logos_lrb/configs/logos_config.yaml
```
     1	# LOGOS LRB — Node Config (prod)
     2	
     3	node:
     4	  listen: "0.0.0.0:8080"
     5	  data_path: "/var/lib/logos/data.sled"
     6	  node_key_path: "/var/lib/logos/node_key"
     7	
     8	limits:
     9	  mempool_cap: 200000
    10	  max_block_tx: 20000
    11	  slot_ms: 1000
    12	
    13	guard:
    14	  rate_limit_qps: 500
    15	  rate_limit_burst: 1000
    16	  cidr_bypass: ["127.0.0.1/32","::1/128"]
    17	
    18	phase:
    19	  enabled: true
    20	  freqs_hz: [7.83, 1.618, 432]
    21	  min_score: -0.2
    22	
    23	bridge:
    24	  max_per_tx: 10000000
    25	
    26	explorer:
    27	  page_size: 50
```

### /root/logos_lrb/README.md
```
     1	# LOGOS Resonance Blockchain — Monorepo
     2	
     3	Состав:
     4	- `lrb_core/`  — ядро (Rust)
     5	- `node/`      — узел (Axum REST + gossip)
     6	- `modules/`   — модульные компоненты
     7	- `tools/`     — e2e и нагрузочные тесты (Go)
     8	- `www/wallet/` — Web Wallet (MVP)
     9	- `wallet-proxy/` — FastAPI proxy + scanner
    10	- `infra/systemd`, `infra/nginx` — юниты/конфиги (без секретов)
    11	- `configs/*.example` — примеры окружения
    12	
    13	## Быстрый старт
    14	1) Rust/Go/Python3.12
    15	2) `cargo build --release -p logos_node`
    16	3) Настрой ENV по `configs/keys.env.example` (секреты не коммить)
    17	4) Подними systemd-юниты из `infra/systemd` (редактируй пути/ENV)
    18	5) Nginx-site из `infra/nginx/lrb_wallet.conf` (wallet + proxy)
```

# Sanity (локальный узел)
_Если узел запущен: curl к локальным ручкам._


### GET /livez
```
ok
```


### GET /readyz
```
{"db":true,"archive":true,"payout_cfg":true}
```


### GET /healthz
```
{"status":"ok"}
```


### GET /health/bridge
```
{"pending":0,"confirmed":6,"redeemed":0}
```


### GET /version
```
{"version":"0.1.0","git_hash":"84913577cf8b","git_branch":"main","built_at":"2025-09-18T16:53:15.203252988+00:00"}
```


### GET /head
```
{"height":1276189,"finalized":1276188}
```

## Метрики Prometheus (срез)
```
```

# Сборка (cargo check --release)
```
```

# Итог
- Книга собрана: /root/logos_lrb/docs/LOGOS_LRB_FULL_BOOK_2025-09-20T14-14-42Z.md
- Размер репозитория:
19G	.
- Кол-во строк кода (примерно):
cloc не установлен, считаю через wc
49016506
