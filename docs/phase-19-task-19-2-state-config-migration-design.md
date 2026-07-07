# Phase 19 Task 19.2 - State and Config Migration Design

Date: 2026-07-07
Status: closed

## Scope

Task 19.2 defines the persisted routing/capture shape that Task 19.3 will
implement. It does not change runtime behavior.

The design separates the current one-dimensional `active_mode` state into the
three axes accepted by ADR 0005:

- routing policy: whether rules are honored;
- capture or entry mechanisms: how traffic reaches WatchdogVPN;
- default route action: where unmatched or globally-routed captured traffic is
  sent.

## Current Compatibility Surface

Existing installations persist `active_mode` in `state.toml` with one of:

- `rules`;
- `global`;
- `direct`;
- `tun`;
- `proxy`.

The current CLI exposes the same field through:

```sh
watchdog config set mode <rules|global|direct|tun|proxy>
```

Backups include the validated selection state document, including
`active_mode`. Automation may also parse the JSON result from
`watchdog config set mode --json`, currently:

```json
{"active_mode":"global"}
```

The migration must therefore be additive first. A fresh Task 19.3 runtime must
understand old state files, old backups, and old CLI automation before any
later deprecation removes compatibility aliases.

## Persisted Shape

Task 19.3 should introduce a versioned routing state block in `state.toml`
while keeping `active_mode` as a compatibility mirror during the v2 migration.

Recommended fields:

```toml
routing_state_version = "1"
routing_policy = "rule"
capture_modes = "local_proxy"
default_route_action = "current"
active_mode = "rules"
```

### Field Contract

`routing_state_version`

- String version for the persisted routing/capture shape.
- Initial value: `"1"`.
- Missing value means legacy state and must be migrated in memory before save.
- Unsupported future values must fail closed with a validation error rather
  than guessing.

`routing_policy`

- Allowed values for version 1: `rule`, `global`.
- `rule` means configured routing rules, app policy, split-tunnel exceptions,
  rule sets, node-group actions, and blocks are honored.
- `global` means all captured traffic uses the default route action and ignores
  split-tunnel exceptions.

`capture_modes`

- Version 1 should use a comma-separated string to stay compatible with the
  current simple TOML writer fallback in `config/state_manager.py`.
- Allowed version 1 tokens: `local_proxy`, `tun`, `system_proxy`.
- Empty string means no explicit capture mode is selected. Task 19.3 should
  reject an effective connect attempt with no usable capture path unless a
  future driver path has its own non-sing-box capture semantics.
- `local_proxy,tun` is valid: local proxy and TUN may coexist.
- `system_proxy` is design-only until Task 19.6 defines cleanup and platform
  boundaries. If persisted before that task, it must be accepted as stored
  state but not silently enabled at runtime.
- LAN proxy sharing and LAN gateway/router are excluded from version 1 because
  Phase 20 owns their branch-only, VM-only validation.

`default_route_action`

- Allowed values for version 1: `current`, `direct`, `block`.
- `current` means the selected protected profile/path.
- `direct` remains a first-class route action.
- `block` is allowed in the persisted shape so the model can represent a
  fail-closed default without overloading routing policy.
- `group:<name>` and `auto` remain route actions in rule/app-policy data, but
  they should not be accepted as the global default in version 1 until Task
  19.9 decides route-chain/proxy-chain behavior and Task 19.5 finalizes live
  rule-set lifecycle failure modes.

`active_mode`

- Kept as a compatibility mirror in version 1.
- Legacy reads must still work.
- Legacy writes through `watchdog config set mode` must update the new fields
  by deterministic mapping.
- New writes in later CLI work should update the new fields and then refresh
  the mirror.

## Legacy Mapping

Task 19.3 must map every legacy `active_mode` deterministically:

| Legacy `active_mode` | `routing_policy` | `capture_modes` | `default_route_action` | Compatibility note |
| --- | --- | --- | --- | --- |
| `rules` | `rule` | `local_proxy` | `current` | TUN remains auto-added at runtime when app policy or DNS capture requires it, preserving current behavior without pretending it was explicitly selected. |
| `global` | `global` | `local_proxy` | `current` | Preserves local-proxy protected routing for captured traffic. |
| `direct` | `global` | `local_proxy` | `direct` | Treats direct as a route action, not a routing policy. |
| `tun` | `global` | `local_proxy,tun` | `current` | Keeps local proxy available for health checks and explicit proxy users while adding explicit TUN capture. |
| `proxy` | `global` | `local_proxy` | `current` | Treats proxy as capture, not routing policy. |

The `tun` mapping intentionally includes `local_proxy`. Existing sing-box
connections always build local SOCKS/HTTP inbounds, and health checks depend on
the local proxy path. Version 1 should not make local proxy conditional without
rewiring health checks first.

## Effective Runtime Rules for Task 19.3

Task 19.3 should derive a runtime request object from the persisted shape before
calling drivers. The old driver `mode` string may remain as an internal
compatibility adapter while downstream code is converted.

Minimum effective mapping for sing-box:

| Routing shape | Driver compatibility mode | Groups/app policy loaded | TUN expected | Final policy |
| --- | --- | --- | --- | --- |
| `rule` + `local_proxy` + `current` | `rules` | yes | only if app policy/DNS capture requires it | `current_profile` |
| `global` + `local_proxy` + `current` | `global` | no | no | `current_profile` |
| `global` + `local_proxy` + `direct` | `direct` | no | no | `direct` |
| `global` + `local_proxy,tun` + `current` | `tun` | no | yes | `current_profile` |

Task 19.3 should not expose this adapter as the final product model. It is a
compatibility bridge so runtime behavior remains stable while internals move to
the three-axis contract.

## Migration and Save Behavior

On load:

1. Validate known legacy fields first.
2. If `routing_state_version` is missing, derive the new fields from
   `active_mode`.
3. If version 1 fields are present, validate them and derive an effective
   compatibility `active_mode` when needed.
4. If both legacy and version 1 fields are present but disagree, version 1
   fields win only when they validate. The compatibility `active_mode` mirror
   should be refreshed on the next save.
5. Unknown routing fields or unsupported version values must raise
   `PersistentValidationError`.

On save:

1. Validate the full state.
2. Ensure version 1 routing fields are present.
3. Refresh `active_mode` from the version 1 fields when the state was changed
   through the new API.
4. Preserve unrelated state fields exactly as the current `StateManager` does.
5. Write atomically through the existing persistence helpers.

## Rollback Behavior

Rollback must not depend on reconstructing old semantics from partial writes.

Task 19.3 should provide a helper that converts a validated version 1 routing
shape back to the closest legacy `active_mode`:

| Version 1 shape | Rollback `active_mode` |
| --- | --- |
| `routing_policy=rule`, `default_route_action=current`, no explicit `tun` | `rules` |
| `routing_policy=global`, `capture_modes=local_proxy`, `default_route_action=current` | `global` |
| `routing_policy=global`, `capture_modes=local_proxy`, `default_route_action=direct` | `direct` |
| `routing_policy=global`, `capture_modes` contains `tun`, `default_route_action=current` | `tun` |

If no exact legacy equivalent exists, rollback should refuse with a clear error
instead of silently weakening policy. Examples: global default `block`, stored
`system_proxy`, or future multi-capture combinations involving LAN.

Before a future migration removes `active_mode`, backup/restore and rollback
must have a separate schema-versioned downgrade/export path. That is outside
Task 19.3.

## CLI and JSON Compatibility

`watchdog config set mode` must remain as a compatibility command through
Task 19.3.

Text output should warn that `mode` is a compatibility alias once the new
fields exist. JSON output should keep the old key and add the new routing shape
without removing anything:

```json
{
  "active_mode": "tun",
  "routing_state_version": "1",
  "routing_policy": "global",
  "capture_modes": ["local_proxy", "tun"],
  "default_route_action": "current"
}
```

The persisted `capture_modes` string may be rendered as a JSON array for API
ergonomics. Automation that only reads `active_mode` remains compatible.

Future CLI work may add explicit commands such as routing-policy/capture/action
setters, but Task 19.3 should keep that minimal and avoid freezing the final
Full CLI vocabulary before Tasks 19.6 through 19.9 close.

## Backup and Restore Compatibility

Selection-state backups that only contain legacy `active_mode` must restore and
migrate successfully.

Selection-state backups that include version 1 fields must validate all routing
fields before mutation. If validation fails, restore must fail before applying
any local state changes, matching the existing backup manager contract.

Encrypted and plaintext backups must behave identically after decryption: the
routing-state validation belongs to the selection-state document, not to the
backup container format.

## Test Requirements for Task 19.3

Task 19.3 implementation must include focused tests for:

- loading each legacy `active_mode` value maps to the expected version 1 shape;
- saving a migrated legacy state writes version 1 fields and preserves unrelated
  fields;
- invalid routing version fails validation;
- invalid routing policy, capture token, or default action fails validation;
- disagreement between valid version 1 fields and legacy `active_mode` resolves
  predictably and refreshes the mirror on save;
- `watchdog config set mode` updates both legacy and version 1 fields;
- `watchdog config set mode --json` preserves `active_mode` and includes the
  new shape;
- selection-state restore accepts legacy-only backups;
- selection-state restore rejects invalid version 1 routing shape before
  mutation;
- rollback conversion covers every exact legacy-equivalent shape and refuses
  non-equivalent shapes.

Runtime tests in Task 19.3 must also pin the effective sing-box mapping for
`rule`, `global`, `direct`, and `tun` compatibility paths without changing
Phase 20 LAN behavior.

## Deferred by Design

This task does not implement:

- runtime mapping changes;
- final Full CLI vocabulary;
- system proxy activation or cleanup;
- LAN proxy sharing or LAN gateway/router state;
- live remote rule-set lifecycle;
- proxy-chain or route-chain syntax.

Those are owned by later Phase 19 tasks and Phase 20. The version 1 shape keeps
space for them without claiming they are active.

## Validation

Task 19.2 validation performed on 2026-07-07:

- reviewed `config/state_manager.py`, `cli/main.py`,
  `config/backup_manager.py`, `tests/test_cli_config_commands.py`,
  `tests/test_backup_manager.py`, ADR 0005, and Task 19.1 audit notes;
- confirmed the design preserves every legacy `active_mode` value:
  `rules`, `global`, `direct`, `tun`, and `proxy`;
- confirmed the design keeps Direct as a route action, not a routing policy;
- confirmed local proxy/TUN/system proxy/LAN are modeled as capture or entry,
  not as routing policies;
- confirmed old `watchdog config set mode --json` automation can continue
  reading `active_mode`;
- ran `git diff --check`;
- checked the new document does not name external reference apps.

No runtime behavior was changed.

The design satisfies the Task 19.2 validation criteria:

- the document preserves every legacy `active_mode` value;
- Direct remains a route action;
- local proxy, TUN, and future system/LAN capture are not treated as routing
  policies;
- the proposed CLI compatibility keeps old JSON automation working;
- the rollback table refuses policy-weakening guesses.
