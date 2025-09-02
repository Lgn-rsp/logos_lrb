# LOGOS LRB — Аудит модулей
_Tue Sep  2 03:51:50 PM UTC 2025_ UTC

## Files in modules/
### `modules/beacon_emitter.rs` (Rust)
- lines: 194 | sha256: `03cd9a74af6e7b586104afe804a1e0224f5c1387ce6234c2bf95306a0aa6b89a`
- red-flags: unsafe=0, unwrap=5, expect=0, panic=0, dbg/println=1

### `modules/env_impact_tracker.py` (Python)
- lines: 132 | sha256: `b53ddccbec9d9d44389a89586503c46e0086276a5a2c5688c69f851ae70ee5fb`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0

### `modules/external_phase_broadcaster.rs` (Rust)
- lines: 203 | sha256: `223e4b0a408be9ace9cf8e1f68b0e2a576c9cfa46a9115f660cc70f31346e2bd`
- red-flags: unsafe=0, unwrap=5, expect=0, panic=0, dbg/println=1

### `modules/external_phase_link.rs` (Rust)
- lines: 179 | sha256: `12a75800714e3d6d6c590614bde1f5c975b1f87c9ac0b2e85642f56a5cf1aa04`
- red-flags: unsafe=1, unwrap=5, expect=0, panic=0, dbg/println=0

### `modules/genesis_fragment_seeds.rs` (Rust)
- lines: 184 | sha256: `5e419ca4d8b184e474d36bddd218ed0dbd9ac158e82d7c9532fd8d50e961145e`
- red-flags: unsafe=0, unwrap=5, expect=1, panic=0, dbg/println=0

### `modules/go_to_market.yaml`
- lines: 118 | sha256: `e80378d944c12f2a6a3541d909558c73d425fc4d9324005ba1184c7b75c9859f`

### `modules/heartbeat_monitor.rs` (Rust)
- lines: 208 | sha256: `a216c54e63bddf080ffbaf6f766b31aabbdd73ef933bfdcf573c9b43460d4f34`
- red-flags: unsafe=0, unwrap=7, expect=1, panic=0, dbg/println=0
- TODO/FIXME:
    143:        true // TODO: Реализовать

### `modules/legacy_migrator.rs` (Rust)
- lines: 191 | sha256: `41a10672b9a9712134cafb319bfac083563746b3b3da78d4f94a9d02e9e0a7c0`
- red-flags: unsafe=0, unwrap=3, expect=0, panic=0, dbg/println=0

### `modules/maintenance_strategy.yaml`
- lines: 85 | sha256: `a7e0e7363849c31cd503d927ce99ef2483f4c51cf6130979f6d1b33b343398b9`

### `modules/resonance_analytics_frontend.tsx`
- lines: 130 | sha256: `f82ff2dbb08cb3c0aa72176cc7aa5b867ff8e747eec8c71aa0be400371772937`

### `modules/resonance_emergency_plan.yaml`
- lines: 91 | sha256: `ee09fef020db662eed88a8a64ac3da99e7e6442c9080292643d0ee161a6e8ccd`

### `modules/resonance_meshmap.yaml`
- lines: 89 | sha256: `8a54cb1d9b389d88717b0a37a19a05b25a73d7e3cd6985614f4dddc3386643c6`

### `modules/resonance_tutor.py` (Python)
- lines: 135 | sha256: `42e2d397e8728edfbc3c3d297f8f0078accbf1f0a2f6d97fd3ce095a65bd128f`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0

### `modules/ritual_engine.rs` (Rust)
- lines: 211 | sha256: `2342009f23dc74f16b5eda9c52bd9c2836a4ca881b32fe4a83e3ac2f10175f2c`
- red-flags: unsafe=0, unwrap=3, expect=0, panic=0, dbg/println=0

### `modules/symbolic_parser.py` (Python)
- lines: 110 | sha256: `99655b49fe33f7affe4d6f5c8707d0b84cc30f4ee34fccee058e3e49e899bfd8`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0

### `modules/uplink_controller.rs` (Rust)
- lines: 208 | sha256: `03cb0431dc4237567534d6efb6728a23c7e0dc225d197435d37a897a2625a47b`
- red-flags: unsafe=1, unwrap=3, expect=0, panic=0, dbg/println=0

### `modules/uplink_router.rs` (Rust)
- lines: 186 | sha256: `ec121080b9c3c05f6af17114e8630ccc14a2c313d5321244130f97cdf08cabe0`
- red-flags: unsafe=0, unwrap=5, expect=0, panic=0, dbg/println=0


## Files in core/
### `core/beta_rollout.yaml`
- lines: 94 | sha256: `b6ac3c0b19a730e9bcd41ccf24fce349dbf62013a1f45bc9d42bf74b13f5d76b`

### `core/offline_resonance.py` (Python)
- lines: 131 | sha256: `c4ba94d1e96a70963929aaf5a965f4ac03eaa091a3c3d7426e0f43036f1f9808`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0

### `core/onboarding_sim.py` (Python)
- lines: 125 | sha256: `6aa4c1aef4f763d4a3f042a8ffae36ea9b59f3104067a56e0c47944986a4f178`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0
- TODO/FIXME:
    90:        # TODO: Интеграция с rcp_engine.rs

### `core/onboarding_ui.py` (Python)
- lines: 137 | sha256: `8c17317ed7aa9339b495e725f58a8f88cd7e6cb792f0b6cd820ce5ad143e8149`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0
- TODO/FIXME:
    114:        # TODO: Интеграция с rcp_engine.rs для проверки резонанса

### `core/resonance_analyzer.py` (Python)
- lines: 83 | sha256: `6c2245061e9b99bd9f0fe865fcb4815e20a4c237c7e16d0a8267756cfacea094`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0

### `core/rid_builder.py` (Python)
- lines: 133 | sha256: `9fac8b299c40f69320f21ce6fc156f913241a284f137ed4fcb2b0f1a96556de0`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0
- TODO/FIXME:
    98:        # TODO: Интеграция с rcp_engine.rs

### `core/ritual_quest.py` (Python)
- lines: 186 | sha256: `0fcba7423a2920b0f14b333f7641110b6c1412c572529ec3b263a629a21e4d7a`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0
- TODO/FIXME:
    150:        # TODO: Интеграция с rcp_engine.rs

### `core/rLGN_converter.py` (Python)
- lines: 136 | sha256: `7a0dba1500ffac08f51a5f16de2ba226da3efd8a063f71fd4bb380f16aba0d24`
- red-flags: eval=0, exec=0, pickle=0, subprocess=0


## Quick checks
```
Python 3.12.3
```

