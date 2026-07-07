# Phase 19 Task 19.3 - Runtime Mapping Implementation

Date: 2026-07-07
Status: closed

## Scope

Task 19.3 implements the minimum compatibility runtime mapping from the Task
19.2 design. It introduces a versioned routing/capture state shape while
preserving existing `active_mode` behavior for current users, backups, CLI
automation, and driver calls.

This task does not finalize the Full CLI vocabulary and does not implement
system proxy activation, LAN sharing/gateway mode, remote rule-set lifecycle,
or proxy-chain syntax.

## Implemented State Shape

`config/state_manager.py` now persists and validates these version 1 fields:

- `routing_state_version = "1"`;
- `routing_policy = "rule" | "global"`;
- `capture_modes = "local_proxy" | "local_proxy,tun" | "local_proxy,system_proxy"`;
- `default_route_action = "current" | "direct" | "block"`;
- `active_mode` remains as a compatibility mirror.

Legacy state files containing only `active_mode` are migrated in memory on
load/save. `StateManager.set("active_mode", value)` updates both the legacy
mirror and the new routing shape.

Unsupported future routing-state versions fail validation instead of being
guessed.

## Legacy Mapping

The implementation maps all existing `active_mode` values:

| Legacy `active_mode` | Routing policy | Capture modes | Default route action |
| --- | --- | --- | --- |
| `rules` | `rule` | `local_proxy` | `current` |
| `global` | `global` | `local_proxy` | `current` |
| `direct` | `global` | `local_proxy` | `direct` |
| `tun` | `global` | `local_proxy,tun` | `current` |
| `proxy` | `global` | `local_proxy` | `current` |

`proxy` remains accepted as a legacy alias. Because it maps to the same version
1 shape as `global`, the compatibility mirror preserves a user-requested
`proxy` write when that is the source of the update.

## Runtime Adapter

`WatchdogRuntime._connect_options()` now reads the versioned routing shape and
builds driver compatibility options from it:

- `routing_policy=rule` maps to driver mode `rules`, loads rule groups, and
  loads app policy.
- `global + local_proxy + current` maps to driver mode `global`.
- `global + local_proxy + direct` maps to driver mode `direct`.
- `global + local_proxy,tun + current` maps to driver mode `tun`.
- `global + local_proxy + block` maps through driver mode `rules` with no rule
  groups/app policy and `final_policy=block`, preserving the new fail-closed
  default route action without treating it as rule policy.

This is an internal compatibility adapter. It does not expose the old
one-dimensional mode model as the final product contract.

The rotation driver router now merges runtime-derived connect options once,
avoiding duplicate keyword arguments when forwarding `final_policy`.

## CLI Compatibility

`watchdog config set mode` remains available for compatibility. It still
accepts:

- `rules`;
- `global`;
- `direct`;
- `tun`;
- `proxy`.

Text output now reports the compatibility alias and the derived routing shape.
JSON output preserves `active_mode` and adds:

- `routing_state_version`;
- `routing_policy`;
- `capture_modes` as an array;
- `default_route_action`.

Automation that only reads `active_mode` remains compatible.

### Compatibility Mirror Guardrail

`rollback_active_mode_for_routing_state()` remains strict: it raises
`PersistentValidationError` for version 1 routing shapes that have no exact
legacy `active_mode` equivalent, such as `default_route_action=block`.

`compatibility_active_mode_for_routing_state()` intentionally keeps
`active_mode` writable/readable as an approximate compatibility mirror when a
legacy equivalent does not exist. That fallback is safe only because runtime
routing decisions do not consume `active_mode`; `WatchdogRuntime._connect_options()`
reads `routing_policy`, `capture_modes`, and `default_route_action` directly.

If a future change reintroduces `active_mode` as a runtime decision source, this
fallback becomes unsafe and must be replaced with strict refusal or an explicit
version-aware runtime mapping. The existing regression
`test_connect_maps_global_block_routing_shape_without_rule_policy` pins the
current behavior: a non-legacy-equivalent `default_route_action=block` shape is
kept fail-closed even when the compatibility mirror says `global`.

## Backup/Restore Compatibility

Selection-state backup validation now accepts legacy-only state documents and
migrates them through the same state validator.

Selection-state backup validation rejects invalid version 1 routing shapes
before mutation. This preserves the existing backup manager contract: invalid
restore input must fail before applying local state changes.

## Bugs Found and Fixed During Task 19.3

Two real implementation bugs were found by the focused tests and fixed before
closure:

1. `StateManager` initially merged `DEFAULT_STATE` before validation, which
   made a legacy-only state file look like it already contained version 1
   routing fields. Legacy `active_mode` values such as `global` and `tun` would
   have migrated incorrectly. Fixed by validating the raw loaded document and
   letting `_validate_state()` apply defaults after legacy detection.
2. `_RuntimeDriverRouter.connect()` initially forwarded runtime-derived
   `final_policy` and the method's own `final_policy` keyword at the same time,
   causing duplicate keyword argument failures during rotation paths. Fixed by
   building one options dictionary and forwarding it once.

## Validation

Validation passed on 2026-07-07:

- `python3 -m unittest tests.test_config_storage tests.test_cli_config_commands tests.test_core_watchdog tests.test_backup_manager`
- `bash tests/unit.sh`
- `bash tests/syntax.sh`
- `git diff --check`
- `python3 -m unittest discover -s tests -p 'test_*.py'`
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`

Full Python unittest result: 1037 tests passed, 1 skipped.

Additional installed-VM validation was performed after updating the VM runtime
to this checkout:

- `./update.sh` completed successfully and installed runtime commit
  `870ff799c63804fba7519e7889b2c90b74c444c4`;
- `./doctor.sh` reported the installed runtime matched the source checkout,
  daemon IPC was reachable, and `FAIL=0`;
- installed `/usr/local/bin/watchdog config set mode <mode> --json` was smoke
  tested with temporary state files for `rules`, `global`, `direct`, `tun`, and
  `proxy`;
- installed legacy-only state loading was smoke tested with
  `PYTHONPATH=/usr/local/lib/watchdogvpn` and temporary state files containing
  only `active_mode` for all five legacy modes.

No live WatchdogVPN tunnel/capture test was run because Task 19.3 changes
state mapping and local runtime option construction only; it does not add new
capture mechanisms or live routing behavior beyond existing compatibility
paths. A separate third-party VPN was manually disconnected before the installed
smokes to avoid contaminating routing state.
