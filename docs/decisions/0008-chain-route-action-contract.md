# ADR 0008: Chain Route Action Contract

Date: 2026-07-08

## Status

Accepted.

## Context

ADR 0007 split proxy-chain and route-chain runtime out of Phase 19 because a
chain requires more than syntax. Phase 21.5 must now define the product
contract before validators can accept `chain:<id>`.

Chains affect routing, DNS, health, failover and diagnostics across multiple
hops. A partial implementation that silently collapses to the current profile,
direct routing or a node group would be worse than no chain support because it
would make the operator believe traffic is following a path the runtime cannot
prove.

## Decision

WatchdogVPN will add `chain:<chain_id>` as a first-class route action in Phase
21.5 after model validation and runtime mapping land.

Accepted v2.0 chain hop types:

- `profile`: one explicit profile ID;
- `group`: one node group name resolved to a concrete profile at runtime.

Rejected v2.0 chain hop types:

- nested chains;
- direct/current/current-profile hops;
- provider-wide wildcard hops;
- inline URL/subscription/runtime-outbound definitions.

The default failure posture is fail-closed:

- missing chain, missing hop, disabled target, empty group, stale health,
  unsupported runtime mapping or DNS uncertainty must block/reject the chain
  route action rather than silently shortening the chain or falling back to
  current/direct/group behavior.

The default DNS posture is chain-owned:

- DNS for domain traffic matched to a chain must remain inside the protected
  chain path or be reported as unavailable/blocked. Direct DNS fallback is not
  accepted by default.

## Consequences

- `chain:<id>` remains rejected until the Phase 21.5 model and runtime mapping
  are implemented and validated.
- Nested chains are intentionally deferred beyond v2.0.
- Route/app-policy/default-action integration must use one canonical chain
  parser and must never silently coerce a chain action.
- Diagnostics must explain hop order, DNS strategy, health/failure status and
  unavailable hop reasons.
- Support export must redact local topology and endpoint identifiers while
  preserving status and counts.
- Installed-VM validation is required before Phase 21.5 may merge back to
  `main`.
