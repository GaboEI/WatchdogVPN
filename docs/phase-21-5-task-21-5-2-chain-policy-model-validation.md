# Phase 21.5 Task 21.5.2 - Chain Policy Model Validation

Date: 2026-07-09
Status: closed

## Scope

Task 21.5.2 implements the persistent route-chain policy model and validation
contract defined by Task 21.5.1.

This task does not enable `chain:<id>` route actions in runtime, rule
validators or app-policy validators. It does not start or stop connections,
generate chain runtime configuration, mutate DNS, routes, firewall, forwarding,
LAN sharing, gateway mode or system proxy state.

## Persistent Store

Route chains are stored in a separate JSON document:

```text
chains.json
```

The store is exposed through `route_chains.store.RouteChainStore`.

Document schema:

```json
{
  "schema_version": 1,
  "chains": []
}
```

Chain schema:

```json
{
  "id": "work-safe",
  "enabled": false,
  "description": "Local operator label",
  "hops": [
    {
      "type": "profile",
      "target": "profile-id",
      "required": true
    },
    {
      "type": "group",
      "target": "resilient-exit",
      "selection_policy": "group_policy",
      "required": true
    }
  ],
  "dns_strategy": "chain",
  "failure_policy": "fail_closed",
  "health_policy": "all_required"
}
```

Defaults remain manual and disabled:

- an absent `chains.json` loads as an empty document;
- new persisted chains default to `enabled = false`;
- route/app-policy/default route actions still reject `chain:<id>`.

## Validation

The model rejects:

- unsupported document schema versions;
- unknown document, chain or hop fields;
- duplicate chain IDs;
- invalid chain IDs;
- empty hop lists;
- unsupported hop types;
- nested `chain` hops;
- `direct`, `current`, `current_profile`, provider wildcard, inline URL and
  raw runtime outbound hop shapes;
- optional hops, because explicit alternate-hop failover is not modeled yet;
- non-chain DNS strategy;
- non-fail-closed failure policy;
- non-all-required health policy;
- group-hop `selection_policy` values other than `group_policy`;
- `selection_policy` on profile hops.

`route_chains.models.chain_target()` is the canonical parser for `chain:<id>`.
It validates the syntax only. It does not authorize use of chain route actions.

`route_chains.validation` provides structured validators for later integration:

- `validate_chain_references()` reports missing profile and group hop targets;
- `validate_chain_action_reference()` reports route actions that point at
  missing or disabled chains;
- `validate_chain_runtime_dependencies()` reports self-cycle shapes where a
  chain hop selects a profile, or a group-selected profile, whose route action
  requires the same chain.

Direct chain-to-chain cycles are unrepresentable in v2.0 because nested
`chain` hops are rejected by the model.

## Backup And Restore

Normal backups now include a `route-chains` section backed by
`route-chains.json`. Restore validates the full route-chain document before
writing. Merge restore preserves local chains and imports colliding chain IDs
with the same timestamped `imported-<id>-<timestamp>` pattern used by other
mergeable sections.

The backup sensitivity warning includes route chains because chain definitions
can reveal local topology and routing intent.

## Privacy Boundary

Route-chain support export redaction is modeled separately from full backups.
`redact_chain_document()` preserves:

- schema version;
- chain count;
- enabled status;
- hop count;
- hop type sequence;
- DNS, failure and health policies;
- timestamp presence.

It does not include:

- hop targets;
- local chain descriptions;
- profile IDs;
- group names;
- provider URLs, tokens, endpoint details or raw profile config.

## Runtime Boundary

Task 21.5.2 is data-model only. The following remain unchanged:

- rule actions still reject `chain:<id>`;
- app-policy actions still reject `chain:<id>`;
- `default_route_action` still rejects `chain:<id>`;
- no daemon connection lifecycle is changed;
- no DNS, route, firewall, forwarding, LAN sharing, gateway or system proxy
  state is mutated.

Task 21.5.3 must add runtime mapping with fail-closed behavior before any chain
route action can be accepted by route/app-policy/default-action validators.
