# ADR 0007: Proxy and Route Chain Decision

Date: 2026-07-08

## Status

Accepted.

## Context

Phase 19 separates routing policy, capture modes, and route actions. That
separation intentionally leaves room for richer route actions, including a
future action that sends matched traffic through an explicit ordered chain.

A chain is not just another spelling for `group:<name>`. A chain would need to
define ordered proxy/profile hops, DNS ownership for each hop, loop prevention,
health checks, failure behavior, diagnostics, import/export semantics, and
operator-facing wording. Accepting chain syntax before those behaviors exist
would make the product appear safer and more deterministic than the runtime can
prove.

## Decision

Explicit proxy-chain and route-chain actions are deferred out of v2.0.0 and
into a later v2.x phase.

v2.0.0 keeps the route-action model open, but it does not accept or silently
coerce chain actions. Current accepted route actions remain:

- `direct`;
- `current` / `current_profile`;
- `block`;
- `group:<name>` and `auto_select` where the existing rule/app-policy runtime
  supports them.

`chain:<name>` and similar future chain actions must fail validation until a
dedicated phase defines and validates the complete contract.

## Future Chain Contract

Before chain actions can be accepted, the later phase must define:

- persistent chain syntax and migration rules;
- allowed hop types and whether chains can reference profiles, node groups, or
  other chains;
- loop prevention for direct self-reference, indirect cycles, nested groups and
  imported policy data;
- DNS behavior for route diagnostics and runtime, including which resolver is
  used before, between and after chain hops;
- health checks, scoring and failover for every hop;
- fail-open/fail-closed behavior for missing, unhealthy, stale or partially
  resolved chains;
- rule-set and importer behavior for chain targets;
- metrics and diagnostics that explain the selected chain and unavailable hops
  without creating sensitive traffic logs;
- installed-VM validation that proves route, DNS, teardown and failure behavior
  with external VPN down/up where safe.

## Consequences

- v2.0.0 avoids a half-built chain feature that could misroute traffic or hide
  DNS behavior.
- Existing route actions remain stable and inspectable.
- Future chain work can add a new route-action namespace without rewriting the
  Phase 19 routing/capture contract.
- Validators must continue to reject `chain:<name>` until the dedicated v2.x
  phase lands.
