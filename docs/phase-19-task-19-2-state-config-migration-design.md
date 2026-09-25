# State and config migration

The routing/capture state separates the legacy one-dimensional `active_mode`
into three axes:

- **routing policy** — whether rules are honored;
- **capture (entry) mechanisms** — how traffic reaches WatchdogVPN;
- **default route action** — where unmatched or globally-routed captured traffic
  is sent.

This document defines the persisted shape, its field contract, the legacy
mapping, the effective runtime semantics, and the migration and rollback
behavior. It describes the design; it does not by itself change runtime
behavior.

## Legacy compatibility surface

Existing installations persist `active_mode` in `state.toml` as one of `rules`,
`global`, `direct`, `tun`, or `proxy`.

The CLI exposes the same field:

```sh
watchdog config set mode <rules|global|direct|tun|proxy>
```

Backups include the validated selection-state document, including `active_mode`.
Automation may parse the JSON result from `watchdog config set mode --json`:

```json
{"active_mode":"global"}
```

The migration is therefore additive first. New runtime code must understand old
state files, old backups, and old CLI automation before any later deprecation
removes compatibility aliases.

## Persisted shape

The routing state block in `state.toml` is versioned. `active_mode` is kept as a
compatibility mirror during the v2 migration.

```toml
routing_state_version = "1"
routing_policy = "rule"
capture_modes = "local_proxy"
default_route_action = "current"
active_mode = "rules"
```

### Field contract

`routing_state_version`

- String version of the persisted routing/capture shape; initial value `"1"`.
- Missing value means legacy state and must be migrated in memory before save.
- Unsupported future values fail closed with a validation error rather than
  guessing.

`routing_policy`

- Allowed values for version 1: `rule`, `global`.
- `rule` honors configured routing rules, app policy, split-tunnel exceptions,
  rule sets, node-group actions, and blocks.
- `global` sends all captured traffic to the default route action and ignores
  split-tunnel exceptions.

`capture_modes`

- Version 1 uses a comma-separated string to stay compatible with the simple
  TOML writer fallback in `config/state_manager.py`.
- Allowed version 1 tokens: `local_proxy`, `tun`, `system_proxy`.
- An empty string means no explicit capture mode is selected; an effective
  connect attempt with no usable capture path is rejected, unless a future
  driver path has its own non-sing-box capture semantics.
- `local_proxy,tun` is valid: local proxy and TUN may coexist.
- `system_proxy` is represented in state, but runtime activation is fail-closed
  until apply, cleanup, crash recovery and platform boundaries are implemented.
  It must not be silently enabled.
- LAN proxy sharing and LAN gateway/router are excluded from version 1; their
  validation belongs to the LAN sharing work.

`default_route_action`

- Allowed values for version 1: `current`, `direct`, `block`.
- `current` means the selected protected profile/path.
- `direct` remains a first-class route action.
- `block` is allowed so the model can represent a fail-closed default without
  overloading routing policy.
- `group:<name>` and `auto` remain route actions in rule/app-policy data, but
  are not accepted as the global default in version 1 until route-chain and
  proxy-chain behavior and live rule-set lifecycle failure modes are decided.

`active_mode`

- Kept as a compatibility mirror in version 1.
- Legacy reads must still work.
- Legacy writes through `watchdog config set mode` update the new fields by
  deterministic mapping.
- New writes update the new fields and then refresh the mirror.

## Legacy mapping

Every legacy `active_mode` maps deterministically:

| Legacy `active_mode` | `routing_policy` | `capture_modes` | `default_route_action` | Compatibility note |
| --- | --- | --- | --- | --- |
| `rules` | `rule` | `local_proxy` | `current` | TUN remains auto-added at runtime when app policy or DNS capture requires it, preserving current behavior without pretending it was explicitly selected. |
| `global` | `global` | `local_proxy` | `current` | Preserves local-proxy protected routing for captured traffic. |
| `direct` | `global` | `local_proxy` | `direct` | Treats direct as a route action, not a routing policy. |
| `tun` | `global` | `local_proxy,tun` | `current` | Keeps local proxy available for health checks and explicit proxy users while adding explicit TUN capture. |
| `proxy` | `global` | `local_proxy` | `current` | Treats proxy as capture, not routing policy. |

The `tun` mapping intentionally includes `local_proxy`. Existing sing-box
connections always build local SOCKS/HTTP inbounds, and health checks depend on
the local proxy path, so version 1 does not make local proxy conditional.

## Effective runtime semantics

Runtime derives a request object from the persisted shape before calling drivers.
The old driver `mode` string may remain as an internal compatibility adapter
while downstream code is converted.

Minimum effective mapping for sing-box:

| Routing shape | Driver compatibility mode | Groups/app policy loaded | TUN expected | Final policy |
| --- | --- | --- | --- | --- |
| `rule` + `local_proxy` + `current` | `rules` | yes | only if app policy/DNS capture requires it | `current_profile` |
| `global` + `local_proxy` + `current` | `global` | no | no | `current_profile` |
| `global` + `local_proxy` + `direct` | `direct` | no | no | `direct` |
| `global` + `local_proxy,tun` + `current` | `tun` | no | yes | `current_profile` |

This adapter is a compatibility bridge, not the final product model; runtime
behavior stays stable while internals move to the three-axis contract.

## Migration and save behavior

On load:

1. Validate known legacy fields first.
2. If `routing_state_version` is missing, derive the new fields from
   `active_mode`.
3. If version 1 fields are present, validate them and derive an effective
   compatibility `active_mode` when needed.
4. If both legacy and version 1 fields are present but disagree, version 1
   fields win when they validate; the compatibility `active_mode` mirror is
   refreshed on the next save.
5. Unknown routing fields or unsupported version values raise
   `PersistentValidationError`.

On save:

1. Validate the full state.
2. Ensure version 1 routing fields are present.
3. Refresh `active_mode` from the version 1 fields when the state was changed
   through the new API.
4. Preserve unrelated state fields exactly as `StateManager` does.
5. Write atomically through the existing persistence helpers.

## Rollback behavior

Rollback must not depend on reconstructing old semantics from partial writes. A
helper converts a validated version 1 routing shape back to the closest legacy
`active_mode`:

| Version 1 shape | Rollback `active_mode` |
| --- | --- |
| `routing_policy=rule`, `default_route_action=current`, no explicit `tun` | `rules` |
| `routing_policy=global`, `capture_modes=local_proxy`, `default_route_action=current` | `global` |
| `routing_policy=global`, `capture_modes=local_proxy`, `default_route_action=direct` | `direct` |
| `routing_policy=global`, `capture_modes` contains `tun`, `default_route_action=current` | `tun` |

If no exact legacy equivalent exists, rollback refuses with a clear error instead
of silently weakening policy. Examples: global default `block`, stored
`system_proxy`, or future multi-capture combinations involving LAN.

Before a future migration removes `active_mode`, backup/restore and rollback
need a separate schema-versioned downgrade/export path.

## CLI and JSON compatibility

`watchdog config set mode` remains a compatibility command.

Text output warns that `mode` is a compatibility alias once the new fields
exist. JSON output keeps the old key and adds the new routing shape without
removing anything:

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

Future CLI work may add explicit routing-policy/capture/action setters, but this
is kept minimal until the capture, coexistence and chain contracts are settled.

## Backup and restore compatibility

Selection-state backups that only contain legacy `active_mode` must restore and
migrate successfully.

Selection-state backups that include version 1 fields must validate all routing
fields before mutation. If validation fails, restore fails before applying any
local state changes, matching the existing backup manager contract.

Encrypted and plaintext backups behave identically after decryption:
routing-state validation belongs to the selection-state document, not to the
backup container format.

## Deferred by design

The version 1 shape does not implement:

- runtime mapping changes;
- the final Full CLI vocabulary;
- system proxy activation or cleanup;
- LAN proxy sharing or LAN gateway/router state;
- live remote rule-set lifecycle;
- proxy-chain or route-chain syntax.

The version 1 shape keeps space for them without claiming they are active.
