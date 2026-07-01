# WatchdogVPN QA Audit - Layer 3 Rotation, Recovery and Resilience

> Date: 2026-07-02  
> Protocol: `/home/gabodev/Escritorio/temporales/WatchdogVPN_QA_AUDIT_PROTOCOL.md`  
> Scope: detection and documentation only. No fixes were made during this audit.
> Follow-up: all findings were fixed in the Layer 3 hardening closure before
> Phase 10 work started.

## Audited Surface

- `rotation/pool_builder.py`
- `rotation/rotation_engine.py`
- `rotation/recovery.py`
- `core/watchdog.py`
- `config/app_config.py`
- Evidence from:
  - `tests/test_pool_builder.py`
  - `tests/test_rotation_engine.py`
  - `tests/test_recovery.py`
  - `tests/test_core_watchdog.py`

## Findings

### AUD-L3-001

| Field | Value |
|---|---|
| ID | AUD-L3-001 |
| Layer | Layer 3 - Rotation, recovery and resilience |
| Severity | HIGH |
| Description | The global `rotation.enabled` configuration default is not enforced before automatic rotation. |
| Scenario | `config/app_config.py` defaults `rotation.enabled` to `False`, but after reconnect attempts are exhausted, `WatchdogRuntime._recover_from_failure()` calls `_attempt_rotation()` without checking that flag. |
| Impact | A user or default configuration can indicate rotation is disabled while WatchdogVPN still rotates to another profile if profiles are marked `in_rotation_pool`. This can silently change endpoint/location and violates the user's expected recovery policy. |
| Status | RESOLVED 2026-07-02 |

Evidence:
- `config/app_config.py` defines `rotation.enabled = False`.
- `core/watchdog.py` calls `_attempt_rotation()` after reconnect attempts are exhausted without checking `config["rotation"]["enabled"]`.
- `rotation/pool_builder.py` filters per-profile and per-provider rotation state, but does not enforce the global rotation switch.
- Existing watchdog tests exercise rotation with `rotation: {}` and do not cover `rotation.enabled = False`.

Resolution:
- `WatchdogRuntime._attempt_rotation()` now refuses automatic rotation when `rotation.enabled` is false.
- Manual forced rotation can still bypass that gate through `rotate_now(force=True)`.
- Added tests proving automatic recovery does not build or rotate a pool while rotation is disabled.

### AUD-L3-002

| Field | Value |
|---|---|
| ID | AUD-L3-002 |
| Layer | Layer 3 - Rotation, recovery and resilience |
| Severity | MEDIUM |
| Description | An unavailable or empty rotation pool is collapsed into the same runtime path as "all candidates failed". |
| Scenario | `pool_builder.build_pool()` returns an empty pool because all profiles are excluded by cooldown, source policy, compatibility, or current-profile exclusion. `RotationEngine.rotate()` correctly returns category `unavailable` with zero attempts, but `WatchdogRuntime._attempt_rotation()` still calls `_apply_all_failed_kill_switch()` and `Recovery.handle_all_failed()`. |
| Impact | The runtime increments all-failed recovery state and may enable the kill switch even though no rotation candidate was actually tried. Logs and user-facing status cannot distinguish "no eligible rotation candidates" from "eligible candidates were tried and failed". |
| Status | RESOLVED 2026-07-02 |

Evidence:
- `RotationEngine.rotate([])` returns `RotationResult(success=False, attempts=0, category="unavailable")`.
- `WatchdogRuntime._attempt_rotation()` does not branch on `result.category` or `result.attempts`; every unsuccessful result enters the all-failed path.
- Existing tests assert that an empty mocked pool returns `normal_network_temp` or `kill_switch_active`, which confirms the current behavior.

Resolution:
- Added `rotation_unavailable` as an explicit connection status.
- `WatchdogRuntime._attempt_rotation()` now routes unavailable or zero-attempt rotation results to a dedicated unavailable path.
- `Recovery.handle_rotation_unavailable()` now logs and schedules backoff separately from all-candidates-failed.
- Added tests for empty pool, disabled rotation, and real candidates failing.

### AUD-L3-003

| Field | Value |
|---|---|
| ID | AUD-L3-003 |
| Layer | Layer 3 - Rotation, recovery and resilience |
| Severity | MEDIUM |
| Description | Recovery backoff configuration is declared but not applied to the runtime `Recovery` instance. |
| Scenario | A user or config file sets `rotation.max_backoff_interval_seconds`, including a value lower than the base interval. `WatchdogRuntime` still uses the default `Recovery(max_interval_seconds=300.0)` unless a test manually injects a configured instance. |
| Impact | Operators cannot rely on configured recovery backoff limits. A low cap meant to make retries faster, or a high cap meant to reduce repeated recovery attempts, is silently ignored. |
| Status | RESOLVED 2026-07-02 |

Evidence:
- `config/app_config.py` declares `rotation.max_backoff_interval_seconds`.
- `Recovery.backoff_interval()` itself handles a lower max cap gracefully by returning `min(interval, max_interval_seconds)`.
- No runtime code maps `config["rotation"]["max_backoff_interval_seconds"]` into `Recovery.max_interval_seconds`.
- Existing recovery tests instantiate `Recovery` directly and do not verify app-config wiring.

Resolution:
- `WatchdogRuntime._configure_recovery()` now maps `watchdog.reconnect_backoff_seconds` and `rotation.max_backoff_interval_seconds` into the runtime `Recovery` instance.
- `_recover_from_failure()` applies recovery configuration before checking the retry window.
- Added tests proving configured base and max backoff values affect runtime recovery behavior.

## Checked Scenarios Without Findings

### Pool with all profiles recently down

`pool_builder.build_pool()` excludes profiles with `health_status = "down"` when `last_health_check` is within `rotation.health_status_cooldown_seconds`. `RotationEngine.rotate([])` returns `category="unavailable"` and does not attempt an empty rotation loop.

Finding AUD-L3-002 covers the runtime-level semantic collapse after that correct engine result.

### Single-node pool with the last known good profile

For a single-node pool, `RotationEngine.rotate()` uses `_single_node_check()` and does not enter the rollback path. It may retest the same profile, but it does not roll back to the same failing node through rollback logic.

### Watchdog check interval shorter than rotation warmup

Inside the Python rotation engine, `_try_profile()` blocks synchronously during `warmup_seconds` before the injected health check runs. A same-process health check cannot fire before warmup completes. External timer overlap was not treated as a Layer 3 Python-runtime finding in this audit.

### Same monotonic timestamp for consecutive recovery failures

`Recovery.record_failure()` sets `_next_retry_at` to `clock() + interval`; `can_retry_now()` remains false until the clock reaches that value. If two failures are recorded at the same clock value, the second failure extends the retry target by the second attempt's interval from that same timestamp. This is coherent and does not create an immediate retry loop.

### Rotated active profile survives reboot startup path

`WatchdogRuntime._attempt_rotation()` updates `active_profile_id` after successful rotation. `WatchdogRuntime.startup()` later reads `active_profile_id` and attempts to connect that profile. Existing tests cover successful rotation updating state and startup reconnecting by persisted active profile.

## Original Recommended Priority Order

### HIGH

1. AUD-L3-001 - Enforce `rotation.enabled` before automatic rotation and add tests for disabled rotation.

### MEDIUM

2. AUD-L3-002 - Split "rotation unavailable" from "all candidates failed" in runtime recovery/status handling.
3. AUD-L3-003 — Wire recovery backoff configuration into the runtime `Recovery` instance or remove/rename the unused config key.

## Hardening Closure - 2026-07-02

All Layer 3 findings listed above were fixed before Phase 10 work started.

Implemented closure:
- Enforced `rotation.enabled` for automatic recovery rotation.
- Split `rotation_unavailable` from `all_failed` runtime status.
- Added dedicated recovery logging/backoff handling for unavailable rotation.
- Wired recovery backoff configuration into `WatchdogRuntime`.
- Added focused regression coverage for disabled rotation, unavailable pools,
  failed candidates, runtime backoff config, and the new status.

Validation:
- `python3 -m unittest tests.test_models tests.test_recovery tests.test_core_watchdog tests.test_pool_builder tests.test_rotation_engine` passed: 92 tests.
- `python3 -m unittest discover tests` passed: 351 tests.
- `bash tests/syntax.sh` passed.
- `bash tests/unit.sh` passed.
- `python3 -m pytest tests` could not run because `pytest` is not installed in this environment.

## Notes For Future Work

- No code changes were made during the audit commit itself.
- The follow-up hardening closure resolved every recorded Layer 3 finding before
  Phase 10 DNS work started.
