# ADR 0005: Routing Mode and Capture Contract

Date: 2026-07-06

## Status

Accepted.

## Context

WatchdogVPN has historically used internal runtime modes such as `rules`,
`global`, `direct`, `tun`, and `proxy`. Those names are useful implementation
states, but they mix three different product concepts:

- routing policy: whether routing rules are honored;
- capture or entry mechanism: how traffic reaches WatchdogVPN;
- route action: where matched traffic is sent.

Mixing those concepts risks freezing the final CLI/TUI around an internal
implementation shortcut. That would cap the product before LAN sharing,
gateway mode, rule import compatibility, and richer route diagnostics are
complete.

## Decision

WatchdogVPN's product model separates routing policy, capture mechanism, and
route action.

### Routing Policy

Routing policy answers whether routing rules are used:

- `rule`: respect user rules, default rules, rule sets, split-tunnel
  exceptions, block rules, node-group selections, and future route chains.
- `global`: ignore split-tunnel exceptions and route all captured traffic
  through the selected protected profile/path.

The user-facing meaning of `global` is "protected full routing for captured
traffic," not "disable TUN" and not "local proxy only."

### Capture and Entry

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
mechanisms. TUN may coexist with local/system proxy. Future LAN proxy/gateway
work builds on the same separation.

### Route Actions

Route actions answer where matched traffic goes:

- `direct`: leave through the normal direct network path;
- `current` / `current_profile`: use the selected protected profile/path;
- `block`: reject the traffic;
- `group:<name>` / `auto`: use a validated node-group or auto-selection
  policy when the runtime supports it;
- future chain actions: route through explicit proxy chains if accepted by a
  later design task.

`direct` is a first-class route action. It must not be removed or hidden merely
because the product also supports global protected routing.

## Required Follow-Up

Before the final Full CLI phase, the dedicated Phase 19 track must align the
runtime configuration, CLI vocabulary, TUI vocabulary, docs, importers,
diagnostics, and tests with this contract.

That phase must:

- audit existing `active_mode` behavior and decide any migration or
  compatibility layer;
- make Rule/Global a routing-policy concept, not a proxy/TUN toggle;
- make Proxy/TUN/LAN explicit capture/entry concepts;
- preserve direct/current/block/group route actions;
- define rule import compatibility without tying WatchdogVPN to one external
  JSON layout;
- ensure rule detection diagnostics can answer "which rule would match this
  domain/IP/process, and which route action would apply?";
- keep the current localhost-only LAN posture until the dedicated LAN phase
  validates broader exposure.

## Consequences

- The final CLI/TUI must not expose a confusing one-dimensional "mode" model.
- Existing implementation states may remain internally during migration, but
  they must not define the final product contract.
- WatchdogVPN can support both simple users and network operators without
  dropping advanced routing/capture capabilities.
- Future phases must add new phases or tasks for this work instead of editing
  closed phase history retroactively.
