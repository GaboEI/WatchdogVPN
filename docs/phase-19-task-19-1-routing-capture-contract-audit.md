# Phase 19 Task 19.1 - Routing/Capture Contract Audit

Date: 2026-07-07
Status: closed

## Scope

Task 19.1 audits the current one-dimensional routing/capture model before any
runtime migration. Per ADR 0005, the target product contract has three axes:

- routing policy: `rule` or `global`;
- capture or entry mechanism: local proxy, system proxy, TUN, LAN proxy, LAN
  gateway/router;
- route action: `direct`, `current`/`current_profile`, `block`, `group:<name>`
  / `auto`, and possible future chains.

No runtime or persistence code changes were made in this task.

## Current Mixed Surfaces

### Persisted State

`config/state_manager.py` persists `active_mode` as one string with allowed
values `rules`, `global`, `direct`, `tun`, and `proxy`.

This mixes:

- `rules`: routing policy;
- `global`: routing policy;
- `direct`: route action;
- `tun`: capture mechanism;
- `proxy`: capture mechanism.

Default state is `active_mode = "rules"`, so the current default is also tied
to the old vocabulary.

### CLI

`watchdog config set mode <value>` writes `active_mode` directly through
`cli/main.py::_config_set_mode_value()`. This exposes the mixed internal model
as user-facing configuration.

`watchdog status` prints `Mode` from `ConnectionState.mode`, plus separate TUN
and proxy booleans. The current displayed `Mode` is not the routing policy:
`SingBoxDriver.status()` reports `mode="sing-box"` while the actual requested
mode is kept internally as `_active_mode`.

### Runtime

`core/watchdog.py::_active_mode()` reads `active_mode` and forwards it as
`mode` to drivers. `_connect_options()` only loads rule groups and app policy
when `mode == "rules"`, so the current mode string controls both policy loading
and capture behavior.

`drivers/singbox_driver.py` interprets the same `mode` string in several ways:

- `_mode_requires_tun()` treats `mode == "tun"` as TUN capture and also enables
  TUN when `mode == "rules"` with enabled app policy;
- `generate_singbox_config()` only applies persisted rule groups and app policy
  when `mode == "rules"`;
- every mode except `rules` routes without rule groups;
- `direct` mode is implemented by setting the final route action to `direct`;
- `tun` mode is implemented as capture, not as routing policy;
- proxy inbounds are always generated, but `status()` reports
  `proxy_active=False` when `_active_mode == "tun"`.

Task 19.10 closure note: the stale `proxy_active=False` status report for TUN
capture was fixed after the Phase 19 model made `tun` map to
`local_proxy,tun`. `SingBoxDriver.status()` now reports local proxy active for
running sing-box sessions because SOCKS/HTTP inbounds remain present alongside
TUN capture.

This is the core one-dimensional shortcut Phase 19 must replace.

### Route Generation

`rules/singbox.py::build_singbox_route_rules()` already models route actions
more cleanly than `active_mode`:

- `direct` maps to the `direct` outbound;
- `current_profile` / `current` maps to the active profile outbound;
- `block` maps to a native reject rule;
- `auto_select` and `group:<name>` currently collapse to the active outbound in
  the sing-box route rule generator, while node-group selection affects the
  connection candidate pool in `core/watchdog.py`.

This means route actions exist, but their runtime meaning is split across route
rule generation and candidate-pool selection.

### App Policy

`app_policy.models` has its own vocabulary:

- mode: `whitelist` / `blacklist`;
- action: `current`, `direct`, `block`, and `group:<name>`.

This is not the same as `active_mode`. It should remain an app-policy model,
then feed into route actions under routing policy `rule`.

### DNS Diagnostics

`watchdog dns diagnose` already combines rule groups, app policy and DNS policy
as configured-policy diagnostics. It does not consume `active_mode`, routing
policy, or capture state. Phase 19.7 should extend diagnostics so it can
distinguish:

- configured route action prediction;
- selected routing policy;
- selected capture mechanism;
- live runtime proof, when available.

### Documentation

ADR 0005, `README.md`, and `docs/product-roadmap.md` already describe the target
three-axis contract. `docs/cli.md` still documents runtime update/configuration
commands but does not yet provide a final routing/capture CLI vocabulary. That
is appropriate until 19.2/19.3 define and implement the compatibility layer.

## Compatibility Constraints

Existing persisted `active_mode` values must not break on upgrade. The
migration design in Task 19.2 should define a compatibility mapping. Initial
audit recommendation:

| Legacy `active_mode` | Routing policy | Capture / entry | Default route action | Notes |
| --- | --- | --- | --- | --- |
| `rules` | `rule` | local proxy plus TUN when required by app policy/DNS capture | `current` | Preserve current behavior first; later allow explicit capture selection. |
| `global` | `global` | local proxy | `current` | All traffic entering the local proxy uses current profile. |
| `direct` | `global` | local proxy | `direct` | Treat as a compatibility alias for a direct default action, not a routing policy. |
| `tun` | `global` | TUN | `current` | Treat as a compatibility alias for TUN capture with global protected routing. |
| `proxy` | `global` | local proxy | `current` | Treat as a compatibility alias for local proxy capture. |

Task 19.2 should decide whether the new persisted shape stores this directly,
for example as `routing_policy`, `capture`, and `default_route_action`, or
whether it keeps `active_mode` as a compatibility field while adding a new
versioned state/config document.

## Migration Path

Task 19.2 should design the persisted shape before implementation. The design
must include:

- a versioned state/config schema for routing policy and capture mechanisms;
- a deterministic import path from existing `active_mode`;
- a rollback path that can restore the old `active_mode` if migration fails;
- CLI wording that avoids exposing `tun`/`proxy` as routing policies;
- JSON output compatibility for automation;
- a deprecation plan for `watchdog config set mode`;
- explicit treatment of app policy and DNS capture requirements;
- tests for every legacy `active_mode` value.

Task 19.3 should then implement only the minimum runtime mapping needed to keep
existing behavior while aligning the internal model with ADR 0005.

## Findings

No immediate runtime bug was fixed in this audit. The current behavior is a
known architecture mismatch captured by ADR 0005 and Phase 19. The audit found
no evidence that Phase 19 should remove Direct, proxy, TUN, app policy, rule
groups, or node-group route actions. The migration must preserve them and split
their meanings across the correct axes.

## Validation

Audit-only validation:

- reviewed ADR 0005 and Phase 19 master-plan contract;
- reviewed `config/state_manager.py`, `core/watchdog.py`,
  `drivers/singbox_driver.py`, `rules/singbox.py`, `rules/models.py`,
  `app_policy/models.py`, `cli/main.py`, status output, README/product roadmap,
  and tests covering active-mode forwarding and sing-box route generation;
- no code changes were made.
