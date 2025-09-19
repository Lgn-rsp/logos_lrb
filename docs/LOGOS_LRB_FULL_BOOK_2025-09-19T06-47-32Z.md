
# LOGOS LRB — FULL BOOK SNAPSHOT
**Дата (UTC):** 2025-09-19T06-47-32Z
**Репозиторий:** /root/logos_lrb
**Хост:** vm15330919.example.com | **Пользователь:** root
**Kernel:** Linux 6.8.0-79-generic x86_64 GNU/Linux
**OS:** Ubuntu 24.04.3 LTS

## Git
- **Remote(s):**
  origin	git@github.com:Lgn-rsp/logos_lrb.git (fetch)
  origin	git@github.com:Lgn-rsp/logos_lrb.git (push)
- **Текущая ветка:** main
- **HEAD коммит:** dc073cab61b3d575a5adc759ad7e0f6134f99353
- **Статус:**
## main...origin/main
 M Cargo.lock
 M Cargo.toml
 M configs/genesis.yaml
 M configs/logos_config.yaml
 D infra/systemd/logos-node.service
 M lrb_core/Cargo.toml
 M lrb_core/src/ledger.rs
 M lrb_core/src/lib.rs
 D lrb_core/src/phase_filters.rs
 M lrb_core/src/phase_integrity.rs
 M lrb_core/src/quorum.rs
 M lrb_core/src/rcp_engine.rs
 M lrb_core/src/types.rs
 M node/build.rs
 M node/openapi/openapi.json
 D node/src/api.rs
 M node/src/api/tx.rs
 M node/src/bridge.rs
 M node/src/lib.rs
 M node/src/state.rs
 M tools/make_book_and_push.sh
 M www/explorer/index.html
 M www/wallet/app.js
 M www/wallet/index.html
?? configs/archive_ddl.sql
?? configs/archive_indexes.sql
?? configs/archive_view_and_indexes.sql
?? core/rid_log.json
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T03-52-10Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-19T06-47-32Z.md
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
?? lrb_core/src/engine.rs
?? lrb_core/src/phase_filters/
?? node/src/api_extra.rs
?? node/src/archive_ingest.rs
?? node/src/bin/
?? node/src/history_sled.rs
?? node/src/openapi/openapi.json.bak
?? node/src/producer.rs
?? node/src/stake.rs
?? node/src/stake_api.rs
?? node/src/staking.rs
?? node/src/types.rs
?? node/src/wallet.rs
?? tools/make_book_and_push.shy
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
│       ├── api_extra.rs
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
│       │   └── mint.rs
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

46 directories, 265 files

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
     1	use axum::{routing::{get, post}, Router};
     2	use tower::ServiceBuilder;
     3	use tower_http::trace::TraceLayer;
     4	use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
     5	use std::sync::Arc;
     6	use tracing::{info, warn};
     7	
     8	mod api;
     9	mod bridge;
    10	mod bridge_journal;
    11	mod payout_adapter;   // адаптер выплат (используется в bridge)
    12	mod admin;
    13	mod gossip;
    14	mod state;
    15	mod peers;
    16	mod guard;
    17	mod metrics;
    18	mod version;
    19	mod storage;
    20	mod archive;
    21	mod openapi;
    22	mod auth;
    23	mod stake;
    24	mod stake_claim;      // реальный claim_settle (зачисление в ledger)
    25	mod health;           // /livez + /readyz
    26	mod wallet;
    27	mod producer;
    28	
    29	fn router(app_state: Arc<state::AppState>) -> Router {
    30	    Router::new()
    31	        // --- public ---
    32	        .route("/healthz", get(api::healthz))
    33	        .route("/livez",  get(health::livez))       // liveness
    34	        .route("/readyz", get(health::readyz))      // readiness
    35	        .route("/head",    get(api::head))
    36	        .route("/balance/:rid", get(api::balance))
    37	        .route("/submit_tx",       post(api::submit_tx))
    38	        .route("/submit_tx_batch", post(api::submit_tx_batch))
    39	        .route("/economy",         get(api::economy))
    40	        .route("/history/:rid",    get(api::history))
    41	
    42	        // --- archive API (PG) ---
    43	        .route("/archive/blocks",      get(api::archive_blocks))
    44	        .route("/archive/txs",         get(api::archive_txs))
    45	        .route("/archive/history/:rid",get(api::archive_history))
    46	        .route("/archive/tx/:txid",    get(api::archive_tx))
    47	
    48	        // --- staking wrappers (совместимость с фронтом) ---
    49	        .route("/stake/delegate",   post(api::stake_delegate))
    50	        .route("/stake/undelegate", post(api::stake_undelegate))
    51	        .route("/stake/claim",      post(api::stake_claim))
    52	        .route("/stake/my/:rid",    get(api::stake_my))
    53	        // реальный settle награды в ledger
    54	        .route("/stake/claim_settle", post(stake_claim::claim_settle))
    55	
    56	        // --- bridge (durable + payout, Send-safe) ---
    57	        // JSON endpoints для mTLS+HMAC периметра (Nginx rewrites → сюда)
    58	        .route("/bridge/deposit_json", post(bridge::deposit_json))
    59	        .route("/bridge/redeem_json",  post(bridge::redeem_json))
    60	        // Оставляем и «обычные» (внутренние) эндпоинты через безопасные замыкания
    61	        .route(
    62	            "/bridge/deposit",
    63	            post(|st: axum::extract::State<Arc<state::AppState>>,
    64	                  body: axum::Json<bridge::DepositReq>| async move {
    65	                bridge::deposit(st, body).await
    66	            })
    67	        )
    68	        .route(
    69	            "/bridge/redeem",
    70	            post(|st: axum::extract::State<Arc<state::AppState>>,
    71	                  body: axum::Json<bridge::RedeemReq>| async move {
    72	                bridge::redeem(st, body).await
    73	            })
    74	        )
    75	        .route("/health/bridge",  get(bridge::health))
    76	
    77	        // --- version / metrics / openapi ---
    78	        .route("/version",     get(version::get))
    79	        .route("/metrics",     get(metrics::prometheus))
    80	        .route("/openapi.json",get(openapi::serve))
    81	
    82	        // --- admin ---
    83	        .route("/admin/set_balance", post(admin::set_balance))
    84	        .route("/admin/bump_nonce",  post(admin::bump_nonce))
    85	        .route("/admin/set_nonce",   post(admin::set_nonce))
    86	        .route("/admin/mint",        post(admin::mint))
    87	        .route("/admin/burn",        post(admin::burn))
    88	
    89	        // --- legacy (если используются) ---
    90	        .merge(wallet::routes())
    91	        .merge(stake::routes())
    92	
    93	        // --- layers/state ---
    94	        .with_state(app_state)
    95	        .layer(
    96	            ServiceBuilder::new()
    97	                .layer(TraceLayer::new_for_http())
    98	                .layer(axum::middleware::from_fn(guard::rate_limit_mw))
    99	                .layer(axum::middleware::from_fn(metrics::track))
   100	        )
   101	}
   102	
   103	#[tokio::main]
   104	async fn main() -> anyhow::Result<()> {
   105	    // logging
   106	    tracing_subscriber::registry()
   107	        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,hyper=warn")))
   108	        .with(tracing_subscriber::fmt::layer())
   109	        .init();
   110	
   111	    // secrets/keys
   112	    auth::assert_secrets_on_start().expect("secrets missing");
   113	
   114	    // state
   115	    let app_state = Arc::new(state::AppState::new()?);
   116	
   117	    // optional archive
   118	    if let Some(ar) = crate::archive::Archive::new_from_env().await {
   119	        unsafe {
   120	            let p = Arc::as_ptr(&app_state) as *mut state::AppState;
   121	            (*p).archive = Some(ar);
   122	        }
   123	        info!("archive backend initialized");
   124	    } else {
   125	        warn!("archive disabled");
   126	    }
   127	
   128	    // producer
   129	    info!("producer start");
   130	    let _producer = producer::run(app_state.clone());
   131	
   132	    // bridge retry worker
   133	    tokio::spawn(bridge::retry_worker(app_state.clone()));
   134	
   135	    // bind & serve
   136	    let addr = state::bind_addr();
   137	    let listener = tokio::net::TcpListener::bind(addr).await?;
   138	    info!("logos_node listening on {addr}");
   139	    axum::serve(listener, router(app_state)).await?;
   140	    Ok(())
   141	}
```

### /root/logos_lrb/lrb_core/src/lib.rs
```rust json
     1	// lrb_core/src/lib.rs — единая точка экспорта ядра
     2	
     3	pub mod types;
     4	pub mod ledger;
     5	pub mod engine;
     6	pub mod phase_filters;
     7	
     8	// точечные реэкспорты (без лишних *), чтобы не плодить ambiguous glob re-exports
     9	pub use types::{Rid, Nonce, Amount, Transaction, Block};
    10	pub use ledger::{Ledger, StoredTx, StoredBlock, BlockHeaderView, now_ms};
    11	pub use engine::{Engine, EngineHandle, EngineEvent};
    12	pub use phase_filters::block_passes_phase;
```

### /root/logos_lrb/lrb_core/src/ledger.rs
```rust json
     1	// lrb_core/src/ledger.rs — sled-хранилище, head/supply, account history, tx-simple, index_block.
     2	
     3	use std::{convert::TryInto, path::Path, time::{SystemTime, UNIX_EPOCH}};
     4	use sled::{Db, Tree};
     5	use serde::{Serialize, Deserialize};
     6	use sha2::{Sha256, Digest};
     7	use anyhow::Result;
     8	
     9	#[allow(unused_imports)]
    10	use crate::types::*;
    11	
    12	// helpers
    13	#[inline] fn be64(v: u64) -> [u8; 8] { v.to_be_bytes() }
    14	#[inline] fn be32(v: u32) -> [u8; 4] { v.to_be_bytes() }
    15	#[inline] fn k_bal(r:&str)->Vec<u8>{ format!("bal:{r}").into_bytes() }
    16	#[inline] fn k_nonce(r:&str)->Vec<u8>{ format!("nonce:{r}").into_bytes() }
    17	
    18	const K_HEAD:      &[u8] = b"h";    // u64
    19	const K_HEAD_HASH: &[u8] = b"hh";   // utf8
    20	const K_FINAL:     &[u8] = b"fin";  // u64
    21	const K_MINTED:    &[u8] = b"mint"; // u64
    22	const K_BURNED:    &[u8] = b"burn"; // u64
    23	
    24	#[derive(Clone)]
    25	pub struct Ledger {
    26	    db: Db,
    27	    // trees
    28	    #[allow(dead_code)]
    29	    lgn:   Tree,   // balances
    30	    head:  Tree,   // head/final/supply
    31	    blocks:Tree,   // b|h -> StoredBlock
    32	    txs:   Tree,   // t|id -> StoredTx
    33	    acct:  Tree,   // a|rid|h|idx -> txid
    34	}
    35	
    36	#[derive(Serialize, Deserialize, Clone)]
    37	pub struct StoredBlock { pub height:u64, pub hash:String, pub ts:u128, pub tx_ids:Vec<String> }
    38	
    39	#[derive(Serialize, Deserialize, Clone)]
    40	pub struct StoredTx {
    41	    pub txid:String, pub from:String, pub to:String,
    42	    pub amount:u64, pub nonce:u64, pub height:u64, pub index:u32, pub ts:u128,
    43	}
    44	
    45	// ====== открытие / базовые геттеры ======
    46	impl Ledger {
    47	    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
    48	        let db = sled::open(path)?;
    49	        Ok(Self{
    50	            lgn:    db.open_tree("lgn")?,
    51	            head:   db.open_tree("head")?,
    52	            blocks: db.open_tree("blocks")?,
    53	            txs:    db.open_tree("txs")?,
    54	            acct:   db.open_tree("acct_txs")?,
    55	            db,
    56	        })
    57	    }
    58	    #[inline] pub fn db(&self) -> &sled::Db { &self.db }
    59	}
    60	
    61	// ====== время (для tx/block) ======
    62	pub fn now_ms() -> i64 {
    63	    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64
    64	}
    65	
    66	// ====== HEAD / FINAL / HASH ======
    67	impl Ledger {
    68	    pub fn height(&self) -> Result<u64> {
    69	        Ok(self.head.get(K_HEAD)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0))
    70	    }
    71	    pub fn head_height(&self) -> Result<u64> { self.height() }
    72	
    73	    pub fn set_head(&self, h:u64, hash:&str) -> Result<()> {
    74	        self.head.insert(K_HEAD, &be64(h))?;
    75	        self.head.insert(K_HEAD_HASH, hash.as_bytes())?;
    76	        Ok(())
    77	    }
    78	    pub fn set_finalized(&self, h:u64) -> Result<()> {
    79	        self.head.insert(K_FINAL, &be64(h))?;
    80	        Ok(())
    81	    }
    82	
    83	    pub fn get_block_by_height(&self, h:u64) -> Result<BlockHeaderView> {
    84	        let mut k=Vec::with_capacity(9); k.extend_from_slice(b"b"); k.extend_from_slice(&be64(h));
    85	        if let Some(v) = self.blocks.get(k)? {
    86	            let b: StoredBlock = serde_json::from_slice(&v)?;
    87	            Ok(BlockHeaderView{ block_hash: b.hash })
    88	        } else {
    89	            let hh = self.head.get(K_HEAD_HASH)?
    90	                .map(|v| String::from_utf8(v.to_vec()).unwrap())
    91	                .unwrap_or_default();
    92	            Ok(BlockHeaderView{ block_hash: hh })
    93	        }
    94	    }
    95	}
    96	
    97	#[derive(Serialize, Deserialize)]
    98	pub struct BlockHeaderView { pub block_hash:String }
    99	
   100	// ====== supply ======
   101	impl Ledger {
   102	    pub fn supply(&self) -> Result<(u64,u64)> {
   103	        let minted = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
   104	        let burned = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
   105	        Ok((minted, burned))
   106	    }
   107	    pub fn add_minted(&self, amount:u64) -> Result<u64> {
   108	        let cur = self.head.get(K_MINTED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
   109	        let newv = cur.saturating_add(amount);
   110	        self.head.insert(K_MINTED, &be64(newv))?; Ok(newv)
   111	    }
   112	    pub fn add_burned(&self, amount:u64) -> Result<u64> {
   113	        let cur = self.head.get(K_BURNED)?.map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap())).unwrap_or(0);
   114	        let newv = cur.saturating_add(amount);
   115	        self.head.insert(K_BURNED, &be64(newv))?; Ok(newv)
   116	    }
   117	}
   118	
   119	// ====== балансы / nonce ======
   120	impl Ledger {
   121	    pub fn get_balance(&self, rid:&str) -> Result<u64> {
   122	        Ok(self.db.get(k_bal(rid))?
   123	            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
   124	            .unwrap_or(0))
   125	    }
   126	    pub fn set_balance(&self, rid:&str, amount_u128:u128) -> Result<()> {
   127	        let amount: u64 = amount_u128.try_into().map_err(|_| anyhow::anyhow!("amount too large"))?;
   128	        self.db.insert(k_bal(rid), &be64(amount))?;
   129	        Ok(())
   130	    }
   131	    pub fn get_nonce(&self, rid:&str) -> Result<u64> {
   132	        Ok(self.db.get(k_nonce(rid))?
   133	            .map(|v| u64::from_be_bytes(v.as_ref().try_into().unwrap_or([0u8;8])))
   134	            .unwrap_or(0))
   135	    }
   136	    pub fn set_nonce(&self, rid:&str, value:u64) -> Result<()> {
   137	        self.db.insert(k_nonce(rid), &be64(value))?; Ok(())
   138	    }
   139	    pub fn bump_nonce(&self, rid:&str) -> Result<u64> {
   140	        let cur = self.get_nonce(rid)?; let next = cur.saturating_add(1);
   141	        self.set_nonce(rid, next)?; Ok(next)
   142	    }
   143	}
   144	
   145	// ====== простая транзакция для REST (/submit_tx) ======
   146	impl Ledger {
   147	    /// Сохраняем tx-заготовку (height=0,index=0), возвращаем StoredTx с txid/ts
   148	    pub fn submit_tx_simple(&self, from:&str, to:&str, amount:u64, nonce:u64, _memo:Option<String>) -> Result<StoredTx> {
   149	        // txid = sha256(from|to|amount|nonce)
   150	        let mut h=Sha256::new();
   151	        h.update(from.as_bytes()); h.update(b"|");
   152	        h.update(to.as_bytes());   h.update(b"|");
   153	        h.update(&amount.to_be_bytes()); h.update(b"|");
   154	        h.update(&nonce.to_be_bytes());
   155	        let txid = hex::encode(h.finalize());
   156	
   157	        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
   158	        let stx = StoredTx{ txid:txid.clone(), from:from.into(), to:to.into(), amount, nonce, height:0, index:0, ts };
   159	
   160	        // t|id -> StoredTx
   161	        let mut k_tx=Vec::with_capacity(1+txid.len()); k_tx.extend_from_slice(b"t"); k_tx.extend_from_slice(txid.as_bytes());
   162	        self.txs.insert(k_tx, serde_json::to_vec(&stx)?)?;
   163	
   164	        // a|from|0|0 -> txid; a|to|0|0 -> txid
   165	        let mut k_af=Vec::new(); k_af.extend_from_slice(b"a"); k_af.extend_from_slice(from.as_bytes()); k_af.push(b'|'); k_af.extend_from_slice(&be64(0)); k_af.extend_from_slice(&be32(0));
   166	        self.acct.insert(k_af, txid.as_bytes())?;
   167	        let mut k_at=Vec::new(); k_at.extend_from_slice(b"a"); k_at.extend_from_slice(to.as_bytes());   k_at.push(b'|'); k_at.extend_from_slice(&be64(0)); k_at.extend_from_slice(&be32(0));
   168	        self.acct.insert(k_at, txid.as_bytes())?;
   169	
   170	        Ok(stx)
   171	    }
   172	
   173	    /// История аккаунта — постранично (упрощённо: первая страница)
   174	    pub fn account_txs_page(&self, rid:&str, _cursor_usize:usize, limit:usize) -> Result<Vec<StoredTx>> {
   175	        let lim = limit.min(100).max(1);
   176	        let prefix = { let mut k=Vec::new(); k.extend_from_slice(b"a"); k.extend_from_slice(rid.as_bytes()); k.push(b'|'); k };
   177	        let mut out=Vec::new();
   178	        for kv in self.acct.scan_prefix(prefix).take(lim) {
   179	            let (_k, v) = kv?;
   180	            let txid = String::from_utf8(v.to_vec()).unwrap_or_default();
   181	            if let Some(stx) = self.get_tx(&txid)? { out.push(stx); }
   182	        }
   183	        Ok(out)
   184	    }
   185	    pub fn get_tx(&self, txid:&str)-> Result<Option<StoredTx>> {
   186	        let mut k=Vec::with_capacity(1+txid.len()); k.extend_from_slice(b"t"); k.extend_from_slice(txid.as_bytes());
   187	        Ok(self.txs.get(k)?.map(|v| serde_json::from_slice::<StoredTx>(&v)).transpose()?)
   188	    }
   189	}
   190	
   191	// ====== индексирование блока (для продюсера/engine) ======
   192	#[derive(Serialize, Deserialize)]
   193	pub struct TransactionView { pub from:String, pub to:String, pub amount:u64, pub nonce:u64 }
   194	
   195	impl Ledger {
   196	    /// Индексация блока: запишем заголовок и перелинкуем его tx в обеих индексах
   197	    pub fn index_block(&self, height: u64, hash: &str, ts: u128, txs: &[TransactionView]) -> Result<()> {
   198	        let mut ids = Vec::with_capacity(txs.len());
   199	        for (i, tx) in txs.iter().enumerate() {
   200	            let mut h=Sha256::new();
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
     1	# LOGOS LRB — GENESIS (prod)
     2	l0_symbol: "Λ0"
     3	
     4	sigma:
     5	  f1: 7.83
     6	  f2: 1.618
     7	  harmonics: [432, 864, 3456]
     8	
     9	emission:
    10	  total_lgn: 81000000            # 81M LGN (человеческая деноминация)
    11	  cap_micro: 81000000000000      # 81_000_000 * 1_000_000 (микро-LGN)
    12	  allocations:
    13	    # пример стартовых аллокаций (замени RID и суммы по необходимости)
    14	    - { rid: "Λ0@7.83Hzφ0.3877", micro: 1000000000 } # 1000.000000 LGN
    15	
    16	fees:
    17	  base_lgn_cost_microunits: 100  # 0.000100 LGN
    18	  burn_percent: 10
    19	
    20	consensus:
    21	  producer_slot_ms: 1000         # интервал блока (ms)
    22	  quorum: 1
    23	  fork_choice: "deterministic"   # для single-node
    24	
    25	bridge:
    26	  max_per_tx_micro: 10000000
    27	
    28	guard:
    29	  rate_limit_qps: 500
    30	  rate_limit_burst: 1000
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
{"height":715645,"finalized":715644}
```

## Метрики Prometheus (срез)
```
```

# Сборка (cargo check --release)
```
```

# Итог
- Книга собрана: /root/logos_lrb/docs/LOGOS_LRB_FULL_BOOK_2025-09-19T06-47-32Z.md
- Размер репозитория:
708M	.
- Кол-во строк кода (примерно):
cloc не установлен, считаю через wc
315426
