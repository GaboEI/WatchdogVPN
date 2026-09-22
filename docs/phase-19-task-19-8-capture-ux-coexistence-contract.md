# Capture modes and coexistence

This document defines the user-facing routing/capture vocabulary and which
capture combinations are valid, invalid, connectable, or representable but
runtime fail-closed.

System proxy apply/restore, LAN proxy sharing and LAN gateway/router mode are
not implemented here. The legacy `mode` compatibility setter is retained.

## Vocabulary

### Routing policy

Routing policy answers whether route rules are honored:

- `rule`: evaluate route rules, app policy and rule-set references, then fall
  back to `default_route_action` when no route rule matches;
- `global`: ignore route rules and send all captured traffic to
  `default_route_action`.

### Capture modes

Capture modes answer how traffic reaches WatchdogVPN:

- `local_proxy`: loopback-only SOCKS/HTTP listeners;
- `tun`: system-level capture through the sing-box TUN inbound;
- `system_proxy`: desktop/session proxy settings that point applications at the
  local proxy listener, representable but runtime fail-closed until the
  dedicated apply/restore implementation exists.

`direct` is not a capture mode. It remains a route action.

LAN proxy sharing and LAN gateway/router mode are not accepted in the routing
state shape.

### Route actions

`default_route_action` is one of:

- `current`: use the current selected protected path;
- `direct`: use the normal network path;
- `block`: reject traffic.

## Capture coexistence matrix

State validation accepts only these capture combinations:

| Capture modes | State status | Runtime status | Notes |
| --- | --- | --- | --- |
| `local_proxy` | valid | connectable | Local proxy only. Apps must explicitly use the loopback proxy. |
| `local_proxy,tun` | valid | connectable | TUN and local proxy coexist. TUN is the stronger capture path. |
| `local_proxy,system_proxy` | valid intent | fail-closed | System proxy requires local proxy but is not implemented yet. |
| `local_proxy,tun,system_proxy` | valid intent | fail-closed | TUN plus future system proxy intent; system proxy still blocks runtime connect. |

Invalid capture states:

| Capture modes | Reason |
| --- | --- |
| empty / none | at least one capture mode is required |
| `system_proxy` | system proxy requires `local_proxy` |
| `tun,system_proxy` | system proxy requires `local_proxy` |
| `tun` | not exposed as a standalone v1 capture shape; the sing-box runtime keeps local proxy inbounds for health checks and operator use |
| LAN modes | not accepted in this state shape |

Capture mode input is order-insensitive. State persistence and JSON output use
the canonical order `local_proxy,tun,system_proxy`, so equivalent input such as
`tun,local_proxy` is accepted and saved as `local_proxy,tun`.

## CLI contract

`watchdog config set mode <legacy>` remains a compatibility command.

New explicit state setters are available:

```sh
watchdog config set routing-policy rule
watchdog config set routing-policy global
watchdog config set capture-modes local_proxy
watchdog config set capture-modes local_proxy,tun
watchdog config set default-route-action current
watchdog config set default-route-action direct
watchdog config set default-route-action block
```

`watchdog config routing-contract` is read-only and reports:

- current routing state;
- connectable and representable capture combinations;
- invalid capture examples and reasons;
- notes that `direct` is a route action, not capture;
- LAN proxy/gateway deferral.

JSON emitted by routing/capture config commands includes
`active_mode_role = "compatibility-display-only"` because `active_mode` is not
the decision source for routing/capture state. States that do not have an exact
legacy `active_mode` equivalent may keep an approximate compatibility mirror for
older readers; new code must use `routing_policy`, `capture_modes` and
`default_route_action`.

## Runtime guardrails

`StateManager` rejects an empty `capture_modes` string and unsupported capture
combinations before they can reach runtime mapping.

Runtime refuses any state containing `system_proxy` with:

```text
system_proxy capture is not implemented yet; use local_proxy or tun
```

This prevents WatchdogVPN from claiming system proxy capture is active before
the apply/restore lifecycle exists.
