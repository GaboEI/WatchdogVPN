# Routing and capture contract

WatchdogVPN's routing and capture configuration is three independent axes:

- **Routing policy** — whether configured route rules are honored: `rule` or
  `global`.
- **Capture (entry) mechanism** — how traffic reaches WatchdogVPN: local proxy,
  system proxy, TUN, LAN proxy, LAN gateway/router.
- **Route action** — where captured traffic is sent: `direct`,
  `current`/`current_profile`, `block`, `group:<name>`/`auto`, and possible
  future chains.

Older builds collapsed these into a single persisted `active_mode` string. This
document describes that mixed legacy surface, the compatibility constraints it
imposes, and the migration path toward the three-axis model. The target model is
recorded in
[`docs/decisions/0005-routing-mode-and-capture-contract.md`](decisions/0005-routing-mode-and-capture-contract.md).

## Legacy mixed surface

### Persisted state

`config/state_manager.py` persists `active_mode` as one string with allowed
values `rules`, `global`, `direct`, `tun`, and `proxy`, mixing:

- `rules`, `global`: routing policy;
- `direct`: route action;
- `tun`, `proxy`: capture mechanism.

The default is `active_mode = "rules"`, so the default is also expressed in the
old vocabulary.

### CLI

`watchdog config set mode <value>` writes `active_mode` directly through
`cli/main.py::_config_set_mode_value()`, exposing the mixed internal model as
user-facing configuration.

`watchdog status` prints `Mode` from `ConnectionState.mode`, plus separate TUN
and proxy booleans. The displayed `Mode` is not the routing policy:
`SingBoxDriver.status()` reports `mode="sing-box"` while the requested mode is
kept internally as `_active_mode`.

### Runtime

`core/watchdog.py::_active_mode()` reads `active_mode` and forwards it as `mode`
to drivers. `_connect_options()` only loads rule groups and app policy when
`mode == "rules"`, so the same string controls both policy loading and capture
behavior.

`drivers/singbox_driver.py` interprets that `mode` string in several ways:

- `_mode_requires_tun()` treats `mode == "tun"` as TUN capture and also enables
  TUN when `mode == "rules"` with enabled app policy;
- `generate_singbox_config()` applies persisted rule groups and app policy only
  when `mode == "rules"`;
- every mode except `rules` routes without rule groups;
- `direct` mode sets the final route action to `direct`;
- `tun` mode is implemented as capture, not as routing policy;
- proxy inbounds are always generated; `status()` reports local proxy active for
  running sing-box sessions because SOCKS/HTTP inbounds remain present alongside
  TUN capture.

This one-dimensional shortcut is what the three-axis model replaces.

### Route generation

`rules/singbox.py::build_singbox_route_rules()` already models route actions more
cleanly than `active_mode`:

- `direct` maps to the `direct` outbound;
- `current_profile` / `current` maps to the active profile outbound;
- `block` maps to a native reject rule;
- `auto_select` and `group:<name>` collapse to the active outbound in the
  sing-box route rule generator, while node-group selection affects the
  connection candidate pool in `core/watchdog.py`.

Route actions therefore exist, but their runtime meaning is split across
route-rule generation and candidate-pool selection.

### App policy

`app_policy/models.py` has its own vocabulary:

- mode: `whitelist` / `blacklist`;
- action: `current`, `direct`, `block`, and `group:<name>`.

This is not `active_mode`. It remains an app-policy model and feeds into route
actions under routing policy `rule`.

### DNS diagnostics

`watchdog dns diagnose` combines rule groups, app policy and DNS policy as
configured-policy diagnostics. It does not consume `active_mode`, routing policy,
or capture state. Route diagnostics should distinguish:

- configured route-action prediction;
- selected routing policy;
- selected capture mechanism;
- live runtime proof, when available.

## Compatibility constraints

Existing persisted `active_mode` values must not break on upgrade. The migration
defines a deterministic compatibility mapping:

| Legacy `active_mode` | Routing policy | Capture / entry | Default route action | Notes |
| --- | --- | --- | --- | --- |
| `rules` | `rule` | local proxy, plus TUN when required by app policy or DNS capture | `current` | Preserves current behavior first; explicit capture selection comes later. |
| `global` | `global` | local proxy | `current` | All traffic entering the local proxy uses the current profile. |
| `direct` | `global` | local proxy | `direct` | Compatibility alias for a direct default action, not a routing policy. |
| `tun` | `global` | TUN | `current` | Compatibility alias for TUN capture with global protected routing. |
| `proxy` | `global` | local proxy | `current` | Compatibility alias for local proxy capture. |

## Migration path

The persisted shape is designed before implementation and must include:

- a versioned state/config schema for routing policy and capture mechanisms;
- a deterministic import path from existing `active_mode`;
- a rollback path that can restore the old `active_mode` if migration fails;
- CLI wording that does not expose `tun`/`proxy` as routing policies;
- JSON output compatibility for automation;
- deprecation of `watchdog config set mode`;
- explicit treatment of app policy and DNS capture requirements.

The runtime migration applies only the minimum mapping needed to keep existing
behavior while aligning the internal model with the three-axis contract. Direct,
proxy, TUN, app policy, rule groups and node-group route actions are all
preserved; their meanings are split across the correct axes.
