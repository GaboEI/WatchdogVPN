# 0005 - Routing mode and capture contract

## Status

Accepted

## Context

WatchdogVPN can describe its runtime with modes such as `rules`, `global`,
`direct`, `tun`, and `proxy`. Those names are useful implementation states, but
they mix three different product concepts:

- routing policy: whether routing rules are honored;
- capture or entry mechanism: how traffic reaches WatchdogVPN;
- route action: where matched traffic is sent.

Mixing those concepts risks freezing the CLI and TUI around an internal
implementation shortcut, capping the product before LAN sharing, gateway mode,
rule import compatibility, and richer route diagnostics are complete.

## Decision

WatchdogVPN's product model separates routing policy, capture mechanism, and
route action.

### Routing policy

Routing policy answers whether routing rules are used:

- `rule`: respect user rules, default rules, rule sets, split-tunnel
  exceptions, block rules, node-group selections, and route chains.
- `global`: ignore split-tunnel exceptions and route all captured traffic
  through the selected protected profile/path.

The user-facing meaning of `global` is "protected full routing for captured
traffic," not "disable TUN" and not "local proxy only."

### Capture and entry

Capture or entry answers how traffic reaches WatchdogVPN:

- local proxy: applications explicitly configured to use WatchdogVPN's local
  proxy;
- system proxy: operating-system proxy configuration where supported and safe;
- TUN: system-level capture through a virtual network interface;
- LAN proxy sharing: LAN clients explicitly configured to use the WatchdogVPN
  host as proxy;
- LAN gateway/router mode: LAN clients use the WatchdogVPN host as their
  protected route.

TUN and proxy are not replacements for `rule` or `global`; they are entry
mechanisms. TUN may coexist with local/system proxy. LAN proxy and gateway
work builds on the same separation.

### Route actions

Route actions answer where matched traffic goes:

- `direct`: leave through the normal direct network path;
- `current` / `current_profile`: use the selected protected profile/path;
- `block`: reject the traffic;
- `group:<name>` / `auto`: use a validated node-group or auto-selection policy
  when the runtime supports it;
- `chain:<id>`: route through an explicit proxy chain when the runtime supports
  it.

`direct` is a first-class route action. It must not be removed or hidden merely
because the product also supports global protected routing.

### Contract requirements

- Rule/Global is a routing-policy concept, not a proxy/TUN toggle.
- Proxy/TUN/LAN are explicit capture/entry concepts.
- Direct/current/block/group route actions are preserved.
- Existing `active_mode` behavior may remain internally during migration, but it
  must not define the final product contract.
- Rule import compatibility and live rule-set lifecycle must not tie
  WatchdogVPN to one external JSON layout.
- System-proxy and local-proxy cleanup, warning and coexistence behavior must be
  defined.
- Rule detection diagnostics must answer "which rule would match this
  domain/IP/process, and which route action would apply?".
- The localhost-only LAN posture is kept until broader exposure is validated.

## Consequences

- The CLI and TUI must not expose a confusing one-dimensional "mode" model.
- WatchdogVPN can support both simple users and network operators without
  dropping advanced routing/capture capabilities.
- New routing, capture or chain work must extend this contract instead of
  retroactively rewriting it.
