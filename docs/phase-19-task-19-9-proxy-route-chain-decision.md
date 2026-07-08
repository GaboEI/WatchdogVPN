# Phase 19 Task 19.9: Proxy-Chain and Route-Chain Decision

Date: 2026-07-08

## Decision

Explicit proxy-chain and route-chain actions are split out of Phase 19 and
scheduled for a dedicated v2 phase before the final Full CLI and v2.0.0
release.

The product model stays open to chain actions, but current Phase 19 validators
must not accept `chain:<name>` or silently map it to the current profile, a
node group, or direct routing before the dedicated chain phase implements the
full runtime contract.

The architectural decision is recorded in
[`docs/decisions/0007-proxy-route-chain-decision.md`](decisions/0007-proxy-route-chain-decision.md).

## Current v2.0.0 Route Actions

Current accepted route actions remain:

- `direct`;
- `current` / `current_profile`;
- `block`;
- `group:<name>` and `auto_select` where the current rule/app-policy runtime
  supports them.

`default_route_action` remains intentionally narrower:

- `current`;
- `direct`;
- `block`.

This keeps global and no-match behavior deterministic while richer targets stay
inside explicit rule/app-policy data.

## Rationale

A chain feature needs more than syntax. Before implementation, WatchdogVPN must
define:

- ordered hop syntax and persistence;
- whether chains may reference profiles, node groups or other chains;
- loop and cycle prevention;
- DNS ownership before, through and after the chain;
- health checks, scoring and failure behavior per hop;
- diagnostics and metrics that explain the chain without recording sensitive
  browsing history;
- rule-set/importer behavior for chain targets;
- installed-VM validation for route, DNS, teardown and failure paths.

Accepting chain actions before those contracts exist would make configuration
look supported while runtime behavior is under-specified.

## Validation Contract

Task 19.9 pins the current boundary with tests:

- route rules reject `chain:<name>`;
- app-policy rules/defaults reject `chain:<name>`;
- persistent `default_route_action` rejects `chain:<name>`.

No runtime route, capture, DNS or TUN behavior is changed by this task.
