# Phase 21.5 Task 21.5.3 - Chain Runtime Mapping

Date: 2026-07-09
Status: closed

## Scope

Task 21.5.3 maps persisted route chains to structured runtime plans and
sing-box route configuration without starting installed-VM validation.

This task does not mutate firewall, LAN/gateway, forwarding or system proxy
state. It does not claim installed VM validation. It adds only the minimal
runtime status objects needed to prove fail-closed chain mapping before the
diagnostics task.

## Runtime Plan

`route_chains.runtime` adds:

- `ChainRuntimeResolver`;
- `ChainRuntimePlan`;
- `ChainRuntimeHopPlan`;
- `ChainRuntimeStatus`;
- `ChainHopRuntimeStatus`;
- `ChainDNSPathStatus`.

The resolver accepts a `chain:<id>` route action only when it resolves to an
enabled persisted chain. Non-chain actions return no chain plan.

Resolved plans include:

- route action;
- chain ID;
- whole-chain status;
- DNS path status;
- failure and health policy;
- final route outbound tag;
- ordered hop plans;
- per-hop target type, target, resolved profile ID, status and outbound tag.

Blocked plans are still explicit plans. They carry `status = blocked` and a
failure reason instead of falling back to another route action.

## Route Action Behavior

Rules, app-policy rules and `default_route_action` now accept syntactically
valid `chain:<id>` values. Runtime mapping decides whether the action can be
used:

- valid resolved chain: route to the chain final outbound tag;
- missing chain: reject/fail closed;
- disabled chain: reject/fail closed;
- missing profile target: reject/fail closed;
- missing group target: reject/fail closed;
- empty group resolution: reject/fail closed;
- unsupported profile protocol for sing-box chain outbounds: reject/fail
  closed;
- DNS ownership unavailable: reject/fail closed.

There is no silent fallback to `current`, `direct`, `group:<name>` or a shorter
chain.

## Hop Mapping

Supported v2.0 hop types remain:

- `profile`;
- `group`.

Profile hops resolve directly to a profile if the profile exists, is eligible
under the same health eligibility pass used by pool/node-group resolution and
uses a sing-box-supported protocol.

Group hops resolve through the existing node-group membership, health filter
and deterministic selection behavior. Manual groups respect the manual profile
pin. Auto groups use the existing deterministic scoring path.

Nested chain, direct, current/current-profile, provider wildcard, inline URL and
raw runtime-tag hop shapes remain rejected by the model.

## Outbound Tags

Chain hop outbound tags are stable and do not include profile IDs:

```text
watchdogvpn-chain-<chain_id>-hop-<index>
```

Operator hop order remains `hop 1 -> hop 2 -> final hop`. The sing-box detour
mapping uses the backend-required inverse dependency:

- hop 1 has no chain detour;
- hop 2 detours through hop 1;
- hop N detours through hop N-1;
- route rules target hop N.

This preserves the operator-visible path while giving sing-box a deterministic
outbound graph.

## DNS Behavior

Chain DNS ownership is required before a chain resolves:

- DNS policy must be present and not off;
- the proxy DNS channel must have at least one enabled resolver;
- there is no direct or system resolver fallback for chain ownership;
- unknown or unavailable DNS ownership blocks the chain.

For global chain routing, the generated sing-box DNS proxy resolver detours
through the chain final outbound tag. Rule-specific mixed-chain DNS explanation
is intentionally left to Task 21.5.4 diagnostics and Task 21.5.5 installed-VM
validation; this task does not claim VM-level DNS proof.

## Runtime Integration

`WatchdogRuntime._connect_options()` collects chain actions from:

- `default_route_action`;
- route rules;
- app-policy rules;
- app-policy default action.

It resolves those actions into `chain_runtime_plans` and passes them to the
driver. The sing-box driver adds resolved chain hop outbounds and maps route
rules/final policy to the resolved final chain tag. Missing or blocked chain
plans become native reject rules.

Non-sing-box drivers accept and ignore `chain_runtime_plans` to preserve the
shared driver interface.

## Validation

Tests cover:

- valid profile-hop chain;
- valid group-hop chain;
- missing chain;
- disabled chain;
- missing profile target;
- missing group target;
- empty group resolution;
- DNS path unavailable;
- outbound tag stability;
- rejected nested/direct/current/runtime-tag-style hop shapes through model
  validation;
- chain route actions never silently collapsing to current, direct or group;
- sing-box chain outbound tag and detour generation;
- global-chain DNS proxy detour through the chain final hop;
- runtime passing resolved chain plans from core to the driver.

Installed-VM validation remains Task 21.5.5.
