# Phase 19 Task 19.8 - Capture UX and Coexistence Contract

> Date: 2026-07-08
> Status: CLOSED - capture vocabulary and coexistence contract implemented.

## Scope

Task 19.8 defines the user-facing routing/capture vocabulary and pins which
capture combinations are valid, invalid, connectable or representable but
runtime fail-closed.

This task does not implement system proxy apply/restore, LAN proxy sharing or
LAN gateway/router mode. It also does not remove the legacy `mode` compatibility
setter.

## Vocabulary

### Routing Policy

Routing policy answers whether route rules are honored:

- `rule`: evaluate route rules, app policy and rule-set references, then fall
  back to `default_route_action` when no route rule matches;
- `global`: ignore route rules and send all captured traffic to
  `default_route_action`.

### Capture Modes

Capture modes answer how traffic reaches WatchdogVPN:

- `local_proxy`: loopback-only SOCKS/HTTP listeners;
- `tun`: system-level capture through the sing-box TUN inbound;
- `system_proxy`: desktop/session proxy settings that point applications at
  the local proxy listener, representable but runtime fail-closed until the
  dedicated apply/restore implementation exists.

`direct` is not a capture mode. It remains a route action.

LAN proxy sharing and LAN gateway/router mode remain Phase 20 work and are not
accepted in the Phase 19 state shape.

### Route Actions

`default_route_action` is one of:

- `current`: use the current selected protected path;
- `direct`: use the normal network path;
- `block`: reject traffic.

## Capture Coexistence Matrix

Current Phase 19 state validation accepts only these capture combinations:

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
| `tun` | not exposed as a standalone v1 capture shape; current sing-box runtime keeps local proxy inbounds for health checks and operator use |
| LAN modes | scheduled for Phase 20 branch-only VM validation |

## CLI Contract

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
- LAN proxy/gateway deferral to Phase 20.

## Runtime Guardrails

`StateManager` now rejects an empty `capture_modes` string and unsupported
capture combinations before they can reach runtime mapping.

Runtime still refuses any state containing `system_proxy` with:

```text
system_proxy capture is not implemented yet; use local_proxy or tun
```

This prevents WatchdogVPN from claiming system proxy capture is active before
the apply/restore lifecycle exists.

## Validation Notes

Focused local validation covers:

- Rule + local proxy;
- Rule + TUN;
- Global + local proxy;
- Global + TUN;
- local proxy with direct default action;
- local proxy with block default action;
- TUN + system proxy fail-closed;
- local-proxy-only as connectable;
- no-capture rejection;
- system-proxy-without-local-proxy rejection;
- `watchdog config routing-contract --json`;
- explicit setters for routing policy, capture modes and default route action.

This task changes local state validation and CLI contract only. It does not
start sing-box, apply TUN, mutate system proxy, change DNS, or alter live
routes. Installed VM validation should therefore use temporary state files and
read-only/config-only smokes unless a later task changes live capture behavior.
