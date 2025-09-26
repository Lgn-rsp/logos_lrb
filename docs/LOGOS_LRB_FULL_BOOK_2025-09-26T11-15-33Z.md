
# LOGOS LRB — FULL BOOK SNAPSHOT
**Дата (UTC):** 2025-09-26T11-15-33Z
**Репозиторий:** /root/logos_lrb
**Хост:** vm15330919.example.com | **Пользователь:** root
**Kernel:** Linux 6.8.0-79-generic x86_64 GNU/Linux
**OS:** Ubuntu 24.04.3 LTS

## Git
- **Remote(s):**
  origin	git@github.com:Lgn-rsp/logos_lrb.git (fetch)
  origin	git@github.com:Lgn-rsp/logos_lrb.git (push)
- **Текущая ветка:** main
- **HEAD коммит:** af5a67fea44de76cf341ce7dbcddfa7a392bd00f
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
 M node/src/admin.rs
 D node/src/api.rs
 M node/src/api/archive.rs
 M node/src/api/base.rs
 M node/src/api/mod.rs
 M node/src/api/tx.rs
 M node/src/archive/mod.rs
 M node/src/bridge.rs
 M node/src/guard.rs
 M node/src/lib.rs
 M node/src/main.rs
 M node/src/metrics.rs
 M node/src/stake_claim.rs
 M node/src/state.rs
 M node/src/version.rs
 M tools/make_book_and_push.sh
 M tools/make_full_book.sh
 M www/explorer/index.html
 M www/wallet/app.js
 M www/wallet/index.html
?? 10-env.conf
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
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-20T14-24-56Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-24T12-48-01Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-24T14-36-35Z.md
?? docs/LOGOS_LRB_FULL_BOOK_2025-09-26T11-15-33Z.md
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
?? lrb_core/src/mempool.rs
?? lrb_core/src/phase_filters/
?? lrb_core/src/rcp_bft.rs
?? lrb_core/tests/
?? node/Cargo.toml.bak.124637
?? node/Cargo.toml.bak.141054
?? node/Cargo.toml.bak.141744
?? node/Cargo.toml.bak.20250921T133102Z
?? node/Cargo.toml.bak.20250921T135301Z
?? node/Cargo.toml.bak.20250921T152031Z
?? node/Cargo.toml.bak.20250921T152838Z
?? node/Cargo.toml.bak.20250921T165322Z
?? node/Cargo.toml.bak.20250922T021131Z
?? node/Cargo.toml.bak.20250922T042246Z
?? node/build.rs.bak.20250921T152855Z
?? node/src/api/admin.rs
?? node/src/api/archive.rs.bak.20250925T062016Z
?? node/src/api/archive.rs.bak.20250925T063016Z
?? node/src/api/archive.rs.bak.20250925T082833Z
?? node/src/api/archive.rs.bak.20250925T084948Z
?? node/src/api/archive.rs.bak.20250925T090242Z
?? node/src/api/archive.rs.bak.20250925T091303Z
?? node/src/api/archive.rs.bak.20250925T102026Z
?? node/src/api/archive.rs.bak.20250925T103043Z
?? node/src/api/archive.rs.bak.20250925T112740Z
?? node/src/api/base.rs.bak.20250922T084527Z
?? node/src/api/base.rs.bak.20250922T085303Z
?? node/src/api/base.rs.bak.20250922T093326Z
?? node/src/api/bridge.rs
?? node/src/api/mod.rs.bak.20250922T075006Z
?? node/src/api/mod.rs.bak.20250922T080344Z
?? node/src/api/mod.rs.bak.20250922T081341Z
?? node/src/api/mod.rs.bak.20250922T082714Z
?? node/src/api/mod.rs.bak.20250922T083621Z
?? node/src/api/mod.rs.bak.20250924T084318Z
?? node/src/api/mod.rs.bak.20250924T085240Z
?? node/src/api/tx.rs.bak.20250922T072341Z
?? node/src/api/tx.rs.bak.20250922T073044Z
?? node/src/api/tx.rs.bak.20250922T142220Z
?? node/src/api/tx.rs.bak.20250924T074445Z
?? node/src/api/tx.rs.bak.20250924T075441Z
?? node/src/api/tx.rs.bak.20250924T084246Z
?? node/src/api/tx.rs.bak.20250924T090505Z
?? node/src/api/tx.rs.bak.20250924T091810Z
?? node/src/api/tx.rs.bak.20250924T094320Z
?? node/src/api/tx.rs.bak.20250924T095516Z
?? node/src/api/tx.rs.bak.20250924T100553Z
?? node/src/api/tx.rs.bak.20250925T065040Z
?? node/src/api/tx.rs.bak.20250925T065932Z
?? node/src/api/tx.rs.bak.20250925T070847Z
?? node/src/api/tx.rs.bak.20250925T074324Z
?? node/src/archive/mod.rs.bak.20250925T082754Z
?? node/src/archive/mod.rs.bak.20250925T084856Z
?? node/src/archive/mod.rs.bak.20250925T090219Z
?? node/src/archive/mod.rs.bak.20250925T091222Z
?? node/src/archive/mod.rs.bak.20250925T112654Z
?? node/src/archive/mod.rs.bak.20250925T114106Z
?? node/src/archive_ingest.rs
?? node/src/bin/
?? node/src/bridge/
?? node/src/guard.rs.bak.20250925T055846Z
?? node/src/history_sled.rs
?? node/src/lib.rs.bak.20250925T055037Z
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
?? node/src/main.rs.bak.20250922T042341Z
?? node/src/main.rs.bak.20250922T044532Z
?? node/src/main.rs.bak.20250925T050028Z
?? node/src/main.rs.bak.20250925T051226Z
?? node/src/main.rs.bak.20250925T053132Z
?? node/src/main.rs.bak.20250925T053845Z
?? node/src/main.rs.bak.20250925T092647Z
?? node/src/main.rs.bak.20250925T095259Z
?? node/src/metrics_plus.rs
?? node/src/middleware.rs
?? node/src/net/
?? node/src/openapi/openapi.json.bak
?? node/src/producer.rs
?? node/src/stake.rs
?? node/src/stake_api.rs
?? node/src/staking.rs
?? node/src/state.rs.bak.20250925T093717Z
?? node/src/types.rs
?? node/src/wallet.rs
?? tools/full_audit.sh
?? tools/make_book_and_push.shy
?? tools/make_book_and_push_v2.sh
?? tools/make_full_book_v2.sh
?? tools/make_prod_book_and_push.sh
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
├── 10-env.conf
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
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-20T14-24-56Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-20T14-35-44Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-24T12-48-01Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-24T14-36-35Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-25T02-22-18Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-25T03-04-37Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-25T12-31-13Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-26T09-45-52Z.md
│   ├── LOGOS_LRB_FULL_BOOK_2025-09-26T11-15-33Z.md
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
│   ├── src
│   │   ├── anti_replay.rs
│   │   ├── beacon.rs
│   │   ├── crypto.rs
│   │   ├── dynamic_balance.rs
│   │   ├── engine.rs
│   │   ├── heartbeat.rs
│   │   ├── ledger.rs
│   │   ├── ledger.rs:24:5
│   │   ├── ledger.rs:29:5
│   │   ├── lib.rs
│   │   ├── mempool.rs
│   │   ├── nano.114024.save
│   │   ├── phase_consensus.rs
│   │   ├── phase_filters
│   │   │   └── mod.rs
│   │   ├── phase_integrity.rs
│   │   ├── quorum.rs
│   │   ├── rcp_bft.rs
│   │   ├── rcp_engine.rs
│   │   ├── resonance.rs
│   │   ├── sigpool.rs
│   │   ├── spam_guard.rs
│   │   └── types.rs
│   └── tests
│       ├── mempool_tests.rs
│       └── rcp_bft_tests.rs
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
│   ├── build.rs.bak.20250921T152855Z
│   ├── Cargo.toml
│   ├── Cargo.toml.bak.124637
│   ├── Cargo.toml.bak.141054
│   ├── Cargo.toml.bak.141744
│   ├── Cargo.toml.bak.20250921T133102Z
│   ├── Cargo.toml.bak.20250921T135301Z
│   ├── Cargo.toml.bak.20250921T152031Z
│   ├── Cargo.toml.bak.20250921T152838Z
│   ├── Cargo.toml.bak.20250921T165322Z
│   ├── Cargo.toml.bak.20250922T021131Z
│   ├── Cargo.toml.bak.20250922T042246Z
│   ├── openapi
│   │   └── openapi.json
│   └── src
│       ├── admin.rs
│       ├── api
│       │   ├── admin.rs
│       │   ├── archive.rs
│       │   ├── archive.rs.bak.20250925T062016Z
│       │   ├── archive.rs.bak.20250925T063016Z
│       │   ├── archive.rs.bak.20250925T082833Z
│       │   ├── archive.rs.bak.20250925T084948Z
│       │   ├── archive.rs.bak.20250925T090242Z
│       │   ├── archive.rs.bak.20250925T091303Z
│       │   ├── archive.rs.bak.20250925T102026Z
│       │   ├── archive.rs.bak.20250925T103043Z
│       │   ├── archive.rs.bak.20250925T112740Z
│       │   ├── base.rs
│       │   ├── base.rs.bak.20250922T084527Z
│       │   ├── base.rs.bak.20250922T085303Z
│       │   ├── base.rs.bak.20250922T093326Z
│       │   ├── bridge.rs
│       │   ├── mod.rs
│       │   ├── mod.rs.bak.20250922T075006Z
│       │   ├── mod.rs.bak.20250922T080344Z
│       │   ├── mod.rs.bak.20250922T081341Z
│       │   ├── mod.rs.bak.20250922T082714Z
│       │   ├── mod.rs.bak.20250922T083621Z
│       │   ├── mod.rs.bak.20250924T084318Z
│       │   ├── mod.rs.bak.20250924T085240Z
│       │   ├── staking.rs
│       │   ├── tx.rs
│       │   ├── tx.rs.bak.20250922T072341Z
│       │   ├── tx.rs.bak.20250922T073044Z
│       │   ├── tx.rs.bak.20250922T142220Z
│       │   ├── tx.rs.bak.20250924T074445Z
│       │   ├── tx.rs.bak.20250924T075441Z
│       │   ├── tx.rs.bak.20250924T084246Z
│       │   ├── tx.rs.bak.20250924T090505Z
│       │   ├── tx.rs.bak.20250924T091810Z
│       │   ├── tx.rs.bak.20250924T094320Z
│       │   ├── tx.rs.bak.20250924T095516Z
│       │   ├── tx.rs.bak.20250924T100553Z
│       │   ├── tx.rs.bak.20250925T065040Z
│       │   ├── tx.rs.bak.20250925T065932Z
│       │   ├── tx.rs.bak.20250925T070847Z
│       │   └── tx.rs.bak.20250925T074324Z
│       ├── api.rs:10:5
│       ├── api.rs:108:5
│       ├── api.rs:59:39
│       ├── archive
│       │   ├── mod.rs
│       │   ├── mod.rs.bak.20250925T082754Z
│       │   ├── mod.rs.bak.20250925T084856Z
│       │   ├── mod.rs.bak.20250925T090219Z
│       │   ├── mod.rs.bak.20250925T091222Z
│       │   ├── mod.rs.bak.20250925T112654Z
│       │   ├── mod.rs.bak.20250925T114106Z
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
│       │   ├── nonce_of_rid.rs
│       │   ├── rid_gen.rs
│       │   ├── rid_of_key.rs
│       │   ├── sign_raw_hex.rs
│       │   ├── sign_submit.rs
│       │   ├── tx_json.rs
│       │   ├── tx_offline_sign.rs
│       │   ├── tx_offline_sign.rs.bak.20250922T045932Z
│       │   ├── tx_offline_sign.rs.bak.20250922T050907Z
│       │   ├── tx_offline_sign.rs.bak.20250922T065707Z
│       │   ├── tx_offline_sign.rs.bak.20250922T070552Z
│       │   ├── tx_offline_sign.rs.bak.20250922T075039Z
│       │   ├── tx_submit.rs
│       │   └── tx_submit_try.rs
│       ├── bridge
│       │   └── state_machine.rs
│       ├── bridge_journal.rs
│       ├── bridge.rs
│       ├── fork.rs
│       ├── gossip.rs
│       ├── guard.rs
│       ├── guard.rs.bak.20250925T055846Z
│       ├── health.rs
│       ├── history_sled.rs
│       ├── JSON
│       ├── LE
│       ├── lib.rs
│       ├── lib.rs.bak.20250925T055037Z
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
│       ├── main.rs.bak.20250922T042341Z
│       ├── main.rs.bak.20250922T044532Z
│       ├── main.rs.bak.20250925T050028Z
│       ├── main.rs.bak.20250925T051226Z
│       ├── main.rs.bak.20250925T053132Z
│       ├── main.rs.bak.20250925T053845Z
│       ├── main.rs.bak.20250925T092647Z
│       ├── main.rs.bak.20250925T095259Z
│       ├── metrics_plus.rs
│       ├── metrics.rs
│       ├── middleware.rs
│       ├── net
│       │   ├── mod.rs
│       │   └── resonance_network.rs
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
│       ├── state.rs.bak.20250925T093717Z
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
│   ├── full_audit.sh
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
│   ├── make_book_and_push_v2.sh
│   ├── make_codebook.sh
│   ├── make_full_book.sh
│   ├── make_full_book_v2.sh
│   ├── make_full_snapshot_live.sh
│   ├── make_prod_book_and_push.sh
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
├── www
│   ├── explorer
│   │   ├── explorer.css
│   │   ├── explorer.js
│   │   └── index.html
│   ├── index.html
│   ├── wallet
│   │   ├── app.html
│   │   ├── app.js
│   │   ├── app.v2.js
│   │   ├── app.v3.js
│   │   ├── auth.js
│   │   ├── index.html
│   │   ├── login.html
│   │   ├── staking.js
│   │   ├── wallet.css
│   │   └── wallet.js
│   ├── wallet3
│   │   ├── app.v3.js
│   │   └── index.html
│   └── wallet.js
└── Документы
    ├── LOGOS_LRB_AUDIT_2025-09-25T02-57-15Z.md
    ├── LOGOS_LRB_AUDIT_2025-09-25T03-23-17Z.md
    └── LOGOS_LRB_FULL_BOOK_2025-09-24T14-37-48Z.md

50 directories, 397 files

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
     1	use std::{net::SocketAddr, sync::Arc};
     2	use tracing::{info, Level};
     3	use logos_node::{AppState, build_app};
     4	
     5	#[tokio::main]
     6	async fn main() {
     7	    tracing_subscriber::fmt()
     8	        .with_max_level(Level::INFO)
     9	        .with_target(false)
    10	        .init();
    11	
    12	    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    13	    let addr: SocketAddr = bind.parse().expect("BIND_ADDR parse");
    14	
    15	    let state = Arc::new(AppState::new().expect("init AppState"));
    16	    // ВАЖНО: build_app теперь возвращает Router (Router<()>)
    17	    let app = build_app(state);
    18	
    19	    info!("LOGOS node listening on {}", addr);
    20	
    21	    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    22	    // Для Axum 0.7 так и нужно: Router подаём напрямую в serve()
    23	    axum::serve(listener, app).await.unwrap();
    24	}
```

### /root/logos_lrb/lrb_core/src/lib.rs
```rust json
     1	#![deny(unused_must_use)]
     2	#![forbid(unsafe_code)]
     3	
     4	// компилируемые модули ядра
     5	pub mod types;     // вспомогательные типы/хэлперы (fixed from_be64/128)
     6	pub mod ledger;    // ваш ledger на sled с JSON-сериализацией
     7	pub mod mempool;   // anti-spam: LRU/TTL/per-RID
     8	pub mod rcp_bft;   // HotStuff-подобное голосование (без serde на Signature)
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

### /root/logos_lrb/lrb_core/src/mempool.rs
```rust json
     1	use std::{
     2	    cmp::Reverse,
     3	    collections::{BTreeMap, BinaryHeap},
     4	    num::NonZeroUsize,
     5	    time::{Duration, Instant},
     6	};
     7	use anyhow::{Result, bail};
     8	use dashmap::DashMap;
     9	use lru::LruCache;
    10	use parking_lot::Mutex;
    11	use serde::{Deserialize, Serialize};
    12	use blake3;
    13	
    14	pub type Rid = [u8; 32];
    15	pub type TxId = [u8; 32];
    16	
    17	#[derive(Clone, Debug, Serialize, Deserialize)]
    18	pub struct Tx {
    19	    pub id: TxId,
    20	    pub from: Rid,
    21	    pub to: Rid,
    22	    pub amount: u128,
    23	    pub nonce: u64,
    24	    pub sig: Vec<u8>,
    25	    pub created_ms: u128,
    26	}
    27	
    28	impl Tx {
    29	    pub fn compute_id(&self) -> TxId {
    30	        let mut h = blake3::Hasher::new();
    31	        h.update(&self.from);
    32	        h.update(&self.to);
    33	        h.update(&self.amount.to_le_bytes());
    34	        h.update(&self.nonce.to_le_bytes());
    35	        *h.finalize().as_bytes()
    36	    }
    37	}
    38	
    39	#[derive(Clone, Copy)]
    40	struct Expiring { at: Instant, txid: TxId }
    41	impl PartialEq for Expiring { fn eq(&self, o:&Self)->bool{ self.at.eq(&o.at) } }
    42	impl Eq for Expiring {}
    43	impl PartialOrd for Expiring { fn partial_cmp(&self,o:&Self)->Option<std::cmp::Ordering>{Some(self.at.cmp(&o.at))} }
    44	impl Ord for Expiring { fn cmp(&self,o:&Self)->std::cmp::Ordering{ self.at.cmp(&o.at) } }
    45	
    46	pub struct Mempool {
    47	    per_rid: DashMap<Rid, BTreeMap<u64, Tx>>,
    48	    dup_lru: Mutex<LruCache<TxId, Instant>>,
    49	    ttl_heap: Mutex<BinaryHeap<Reverse<Expiring>>>,
    50	    ttl: Duration,
    51	    per_rid_cap: usize,
    52	    global_cap: usize,
    53	    total_len: Mutex<usize>,
    54	}
    55	
    56	impl Mempool {
    57	    pub fn new(ttl: Duration, per_rid_cap: usize, global_cap: usize, dup_capacity: usize) -> Self {
    58	        let cap = NonZeroUsize::new(dup_capacity).unwrap_or_else(|| NonZeroUsize::new(10_000).unwrap());
    59	        Self {
    60	            per_rid: DashMap::new(),
    61	            dup_lru: Mutex::new(LruCache::new(cap)),
    62	            ttl_heap: Mutex::new(BinaryHeap::new()),
    63	            ttl,
    64	            per_rid_cap,
    65	            global_cap,
    66	            total_len: Mutex::new(0),
    67	        }
    68	    }
    69	
    70	    #[inline] pub fn len(&self) -> usize { *self.total_len.lock() }
    71	    #[inline] fn incr_total(&self, by: isize) {
    72	        let mut g = self.total_len.lock();
    73	        let v = (*g as isize + by).max(0) as usize;
    74	        *g = v;
    75	    }
    76	
    77	    pub fn enqueue(&self, tx: Tx) -> Result<()> {
    78	        let id = if tx.id == [0u8;32] { tx.compute_id() } else { tx.id };
    79	
    80	        // 1) дубликаты
    81	        {
    82	            let mut lru = self.dup_lru.lock();
    83	            if lru.contains(&id) { bail!("duplicate-tx"); }
    84	            lru.put(id, Instant::now());
    85	        }
    86	
    87	        // 2) TTL индекс
    88	        {
    89	            let mut heap = self.ttl_heap.lock();
    90	            heap.push(Reverse(Expiring { at: Instant::now() + self.ttl, txid: id }));
    91	        }
    92	
    93	        // 3) очередь per-RID
    94	        let mut q = self.per_rid.entry(tx.from).or_insert_with(BTreeMap::new);
    95	        if q.len() >= self.per_rid_cap { bail!("per-rid-cap-exceeded"); }
    96	        if let Some((&min_nonce, _)) = q.first_key_value() {
    97	            if tx.nonce < min_nonce.saturating_sub(1) { bail!("low-nonce"); }
    98	        }
    99	        q.insert(tx.nonce, tx);
   100	        self.incr_total(1);
   101	
   102	        // 4) глобальный cap
   103	        if self.len() > self.global_cap { self.evict_one()?; }
   104	        Ok(())
   105	    }
   106	
   107	    fn evict_one(&self) -> Result<()> {
   108	        let mut heap = self.ttl_heap.lock();
   109	        if let Some(Reverse(exp)) = heap.pop() {
   110	            self.dup_lru.lock().pop(&exp.txid);
   111	            for mut entry in self.per_rid.iter_mut() {
   112	                if let Some((nonce, _)) = entry.value().iter()
   113	                    .find(|(_, t)| t.id == exp.txid)
   114	                    .map(|(n, t)| (*n, t.clone())) {
   115	                    entry.value_mut().remove(&nonce);
   116	                    self.incr_total(-1);
   117	                    break;
   118	                }
   119	            }
   120	        }
   121	        Ok(())
   122	    }
   123	
   124	    pub fn evict_ttl(&self) {
   125	        let now = Instant::now();
   126	        let mut removed = 0usize;
   127	        {
   128	            let mut heap = self.ttl_heap.lock();
   129	            while let Some(Reverse(exp)) = heap.peek().cloned() {
   130	                if exp.at > now { break; }
   131	                let _ = heap.pop();
   132	                self.dup_lru.lock().pop(&exp.txid);
   133	                for mut entry in self.per_rid.iter_mut() {
   134	                    if let Some((nonce, _)) = entry.value().iter()
   135	                        .find(|(_, t)| t.id == exp.txid)
   136	                        .map(|(n, t)| (*n, t.clone())) {
   137	                        entry.value_mut().remove(&nonce);
   138	                        removed += 1;
   139	                        break;
   140	                    }
   141	                }
   142	            }
   143	        }
   144	        if removed > 0 { self.incr_total(-(removed as isize)); }
   145	    }
   146	
   147	    /// Сбор батча: по одному tx с каждой RID-очереди (fair), до max
   148	    pub fn drain_fair_batch(&self, max: usize) -> Vec<Tx> {
   149	        let mut batch = Vec::with_capacity(max);
   150	        for _ in 0..max {
   151	            let mut pick: Option<(Rid, u64, Tx)> = None;
   152	            for entry in self.per_rid.iter() {
   153	                if let Some((&nonce, tx)) = entry.value().first_key_value() {
   154	                    pick = Some((*entry.key(), nonce, tx.clone()));
   155	                    break;
   156	                }
   157	            }
   158	            if let Some((rid, nonce, tx)) = pick {
   159	                if let Some(mut q) = self.per_rid.get_mut(&rid) {
   160	                    q.remove(&nonce);
   161	                    self.incr_total(-1);
   162	                    batch.push(tx);
   163	                }
   164	            } else { break; }
   165	        }
   166	        batch
   167	    }
   168	}
```

### /root/logos_lrb/lrb_core/src/dynamic_balance.rs
```rust json
     1	use metrics::gauge;
     2	use anyhow::Result;
     3	use crate::ledger::Ledger;
     4	
     5	#[derive(Clone, Copy, Debug)]
     6	pub struct FeeParams {
     7	    pub base_microunits: u64,
     8	    pub slope_per_ktps: u64,
     9	    pub max_microunits: u64,
    10	}
    11	
    12	pub struct DynamicFees { pub params: FeeParams }
    13	
    14	impl DynamicFees {
    15	    pub fn new(params: FeeParams) -> Self { Self { params } }
    16	
    17	    pub fn current_fee(&self, load_tps: f64) -> u64 {
    18	        let k = (load_tps / 1000.0).floor() as u64;
    19	        let fee = self.params.base_microunits
    20	            .saturating_add(k * self.params.slope_per_ktps)
    21	            .min(self.params.max_microunits);
    22	        gauge!("logos_fee_current_microunits", fee as f64);
    23	        fee
    24	    }
    25	
    26	    pub fn burn_on_commit(&self, ledger: &Ledger, fee_micros_total: u128) -> Result<()> {
    27	        ledger.burn_supply(fee_micros_total)?;
    28	        Ok(())
    29	    }
    30	}
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
ok
```


### GET /healthz
_недоступно_


### GET /health/bridge
_недоступно_


### GET /version
_недоступно_


### GET /head
_недоступно_

## Метрики Prometheus (срез)
```
logos_bridge_ops_total{kind="deposit",status="accepted"} 1
logos_bridge_ops_total{kind="deposit",status="duplicate"} 1
logos_bridge_ops_total{kind="redeem",status="enqueued"} 1
```

# Сборка (cargo check --release)
```
```

# Итог
- Книга собрана: /root/logos_lrb/docs/LOGOS_LRB_FULL_BOOK_2025-09-26T11-15-33Z.md
- Размер репозитория:
43G	.
- Кол-во строк кода (примерно):
github.com/AlDanial/cloc v 1.98  T=40.93 s (45.2 files/s, 44044.2 lines/s)
--------------------------------------------------------------------------------
Language                      files          blank        comment           code
--------------------------------------------------------------------------------
Markdown                         38         206170            548        1445279
Text                             22          13293              0          84260
Rust                            109           4147            361          23220
D                               781           1957              0          12661
JSON                            818             23              0           2843
Bourne Shell                     24            298            171           1824
Python                           13            193            141           1308
JavaScript                       12            112             81            986
Go                                6            117             59            753
YAML                              7             56              4            491
HTML                              6             22              6            454
CSV                               2              0              0            229
TOML                              4             19              8            114
TypeScript                        1             11              5            114
Bourne Again Shell                1             10             12             81
CSS                               2              1              1             81
SQL                               3              9             13             46
C                                 1              0              0              1
--------------------------------------------------------------------------------
SUM:                           1850         226438           1410        1574745
--------------------------------------------------------------------------------
