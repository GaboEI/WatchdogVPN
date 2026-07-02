# WatchdogVPN QA Audit - Layer 1 Core Logic and State

> Date: 2026-07-03  
> Protocol: `/home/gabodev/Escritorio/temporales/WatchdogVPN_QA_AUDIT_PROTOCOL.md`  
> Scope: detection and documentation only. No fixes were made during this audit.
> Follow-up: HIGH and MEDIUM findings must be fixed in the Layer 1 hardening
> closure before Phase 11 starts.

## Audited Surface

- `config/state_manager.py`
- `config/profile_store.py`
- `config/provider_store.py`
- `config/dns_policy_store.py`
- `config/app_config.py`
- `models/profile.py`
- `models/provider.py`
- `dns/models.py`
- `core/watchdog.py`
- `rotation/pool_builder.py`
- Evidence from:
  - `tests/test_config_storage.py`
  - `tests/test_core_watchdog.py`
  - `tests/test_dns_models.py`
  - `tests/test_dns_state_manager.py`

## Findings

### AUD-L1-001

| Field | Value |
|---|---|
| ID | AUD-L1-001 |
| Layer | Layer 1 - Core logic and state |
| Severity | HIGH |
| Description | Persistent state and store writes are direct, unlocked, and non-atomic, so concurrent WatchdogVPN processes or a crash during write can corrupt user state. |
| Scenario | Two processes update `state.toml`, `profiles.json`, `providers.json`, or `dns-policy.json` at the same time, or the process/host crashes while `write_text()` or `open("wb")` is truncating and rewriting the file. |
| Impact | The next startup, CLI command, or watchdog iteration can read a truncated TOML/JSON file and crash, lose a profile/provider/DNS setting, or overwrite another process's update. This is exactly the class of persistence failure Phase 11 would amplify by adding more state. |
| Status | OPEN |

Evidence:
- `StateManager.save()` writes directly to `state.toml`.
- `AppConfig.save()` writes directly to `config.toml`.
- `ProfileStore._save_raw()` writes directly to `profiles.json`.
- `ProviderStore._save_raw()` writes directly to `providers.json`.
- `DNSPolicyStore.save()` writes directly to `dns-policy.json`.
- No config/store module uses `flock`, a lock file, temp-file + `os.replace`,
  or any equivalent atomic write helper.

### AUD-L1-002

| Field | Value |
|---|---|
| ID | AUD-L1-002 |
| Layer | Layer 1 - Core logic and state |
| Severity | HIGH |
| Description | Invalid `vpn_desired_state` values are treated as automatic-actions-enabled instead of fail-closed standby. |
| Scenario | `state.toml` contains `vpn_desired_state = "maybe"`, an empty string, or any value other than `"off"` after manual edit, partial migration, or corrupted state recovery. |
| Impact | `WatchdogRuntime.automatic_actions_enabled()` only blocks exactly `"off"`, so any other invalid value permits health checks, reconnect, recovery, and rotation. A corrupted user-decision field can therefore turn automation on silently. |
| Status | OPEN |

Evidence:
- `core/watchdog.py::automatic_actions_enabled()` returns `False` only for
  `desired_state == "off"` and returns `True` for everything else.
- `core/watchdog.py::startup()` only treats `"off"` as standby, so invalid
  state values can pass into the autoconnect path.
- `StateManager.load()` merges TOML values into defaults without validating
  enum-like fields.

### AUD-L1-003

| Field | Value |
|---|---|
| ID | AUD-L1-003 |
| Layer | Layer 1 - Core logic and state |
| Severity | HIGH |
| Description | Corrupted persistent files raise raw parser/schema exceptions instead of surfacing a controlled fallback or repair path. |
| Scenario | `state.toml` is truncated, `profiles.json` contains partial JSON, `providers.json` contains a JSON object instead of a list, or `dns-policy.json` is invalid JSON. |
| Impact | First run is safe when files are absent, but once a file exists and becomes malformed, callers crash through `tomllib.load()`, `json.loads()`, `Profile.from_dict()`, `Provider.from_dict()`, or `DNSPolicy.from_dict()`. The user gets a traceback rather than a clear "state file is corrupt; backup/repair/reset" status. |
| Status | OPEN |

Evidence:
- `StateManager.load()` does not catch `TOMLDecodeError` or validate the loaded
  object type.
- `ProfileStore._load_raw()` and `ProviderStore._load_raw()` do not catch
  `JSONDecodeError` or require the top-level data to be a list before callers
  iterate over it.
- `DNSPolicyStore.load()` catches neither `JSONDecodeError` nor schema
  `ValueError`; it validates only that the top-level value is a JSON object.

### AUD-L1-004

| Field | Value |
|---|---|
| ID | AUD-L1-004 |
| Layer | Layer 1 - Core logic and state |
| Severity | HIGH |
| Description | Wrong-type values in state, config, profiles, providers, and DNS policy can be coerced into dangerous truthy values instead of rejected. |
| Scenario | A future version, manual edit, or broken tool writes strings like `"false"` or `"0"` into boolean fields such as `enabled`, `in_rotation_pool`, `rotation_enabled`, `kill_switch.enabled`, `tun_hijack`, or `ecs_direct_enabled`. |
| Impact | Python `bool("false")` is `True`, so a field that visually says false can enable a profile, include it in rotation, enable provider rotation, activate kill-switch behavior, or enable DNS behavior. This is silent state corruption and can cause the live runtime to do the opposite of what the stored config appears to request. |
| Status | OPEN |

Evidence:
- `Profile.from_dict()` uses `bool(data.get("in_rotation_pool", False))` and
  `bool(data.get("enabled", True))`.
- `Provider.from_dict()` uses `bool(data.get("rotation_enabled", False))` and
  `bool(data.get("auto_update", True))`.
- `DNSPolicy.from_dict()` uses `bool(...)` for multiple feature flags.
- `WatchdogRuntime._configure_kill_switch()` uses `bool(...)` for config fields
  loaded from `config.toml`.

### AUD-L1-005

| Field | Value |
|---|---|
| ID | AUD-L1-005 |
| Layer | Layer 1 - Core logic and state |
| Severity | MEDIUM |
| Description | Forward-version or manually added unknown fields are silently discarded on load-save round trips for profiles, providers, DNS policy, and app config. |
| Scenario | A future WatchdogVPN version adds a field to `dns-policy.json` or `profiles.json`, or a user stores local metadata in a supported JSON file, then the current CLI/TUI loads and saves the same object. |
| Impact | Unknown fields are not preserved and may be lost without warning. This is recoverable from backups, but it creates migration risk as Phase 11 adds routing rules and more persistent state. |
| Status | OPEN |

Evidence:
- `Profile.from_dict()` and `Provider.from_dict()` reconstruct only known
  dataclass fields and `to_dict()` emits only those fields.
- `DNSPolicy.from_dict()` ignores unknown keys and `to_dict()` emits only the
  current schema.
- `AppConfig.save()` merges only dict sections and known defaults; scalar or
  unknown future shapes have no explicit preservation/diagnostic behavior.

### AUD-L1-006

| Field | Value |
|---|---|
| ID | AUD-L1-006 |
| Layer | Layer 1 - Core logic and state |
| Severity | MEDIUM |
| Description | Profile health cooldown uses wall-clock timestamps without clamping future `last_health_check` values. |
| Scenario | The system clock jumps backward after NTP resync, or `profiles.json` contains a future `last_health_check` timestamp for a `health_status = "down"` profile. |
| Impact | `pool_builder.build_pool()` can exclude a profile for much longer than the configured cooldown because `now - last_health_check` becomes negative and remains below the cooldown threshold. Rotation can appear unavailable even after the intended cooldown should have expired. |
| Status | OPEN |

Evidence:
- `rotation/pool_builder.py::_recently_failed()` compares
  `datetime.now(timezone.utc) - last_health_check` directly against the
  cooldown.
- There is no guard for `last_health_check > now`.
- Rotation/recovery timing already uses injected monotonic clocks elsewhere,
  but persisted health timestamps remain wall-clock based.

## Checked Scenarios Without Findings

### Missing state file on first run

`StateManager.load()` returns a copy of `DEFAULT_STATE` when `state.toml` does
not exist. This satisfies the first-run behavior required by Phase 1 and Phase
7.

### Missing active profile ID on startup

`WatchdogRuntime.startup()` handles an empty `active_profile_id` by logging and
returning standby without calling `driver.connect()`.

### Deleted active profile ID on startup and recovery

`WatchdogRuntime.startup()` checks `profile_store.get(active_profile_id)` and
returns standby if the profile is missing. `WatchdogRuntime._active_profile()`
also returns `None` when the stored ID no longer exists, so recovery skips the
same-profile reconnect path and proceeds to rotation/unavailable handling
instead of crashing.

### Rotated active profile survives reboot startup path

The Phase 8 integration path persists `active_profile_id` after successful
rotation. Existing tests cover rotation updating state and startup reconnecting
from the persisted active profile.

### Missing DNS policy file

`DNSPolicyStore.load()` returns `DNSPolicy()` when `dns-policy.json` does not
exist. The missing-file path is safe; the corrupted-file path is tracked as
AUD-L1-003.

## User Data Flow Trace

This audit used the Phase 10 lesson as an explicit check: for every mutable
user-facing state file, trace whether data reaches the live runtime intact.

- `state.toml -> StateManager -> WatchdogRuntime`: values do reach runtime, but
  enum-like state is not validated. Invalid `vpn_desired_state` reaches the
  automatic-action gate and is interpreted as enabled (AUD-L1-002).
- `config.toml -> AppConfig -> WatchdogRuntime`: values reach kill switch,
  recovery, and rotation config, but boolean-like wrong types are coerced with
  `bool(...)` (AUD-L1-004).
- `profiles.json -> ProfileStore -> WatchdogRuntime/rotation`: values reach
  driver selection and rotation pool, but wrong-type booleans can flip behavior
  and malformed schemas crash callers (AUD-L1-003, AUD-L1-004).
- `providers.json -> ProviderStore -> pool_builder/subscription provider`:
  provider rotation and metadata reach pool selection, but wrong-type booleans
  can enable provider rotation unexpectedly (AUD-L1-004).
- `dns-policy.json -> DNSPolicyStore -> WatchdogRuntime -> SingBoxDriver`:
  Phase 10G fixed the policy reaching the live process. Layer 1 remaining risk
  is corrupted or wrong-type policy data before the policy is loaded
  (AUD-L1-003, AUD-L1-004).

## Recommended Priority Order

### HIGH

1. AUD-L1-001 - Add a shared locked, atomic write/read-update-write helper for
   state and JSON/TOML stores.
2. AUD-L1-002 - Validate `vpn_desired_state` and fail closed to standby for
   invalid values.
3. AUD-L1-004 - Replace truthiness coercion with strict boolean/type parsing
   for persisted state/config/model fields.
4. AUD-L1-003 - Add controlled persistent-state load errors and user-actionable
   messages for corrupt TOML/JSON/schema files.

### MEDIUM

5. AUD-L1-006 - Clamp or expire future health-check timestamps so clock jumps
   do not create indefinite cooldowns.
6. AUD-L1-005 - Decide and implement an unknown-field policy before Phase 11
   adds more persisted state.

## Notes For Hardening Closure

- The closure should avoid Phase 11 rule-store work.
- Regression tests must cover invalid state values, corrupt files, strict
  boolean parsing, atomic write behavior, and future health timestamps.
- The closure should update this audit report with resolution notes after fixes
  land.
