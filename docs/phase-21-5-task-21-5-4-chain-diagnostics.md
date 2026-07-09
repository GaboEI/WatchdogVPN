# Phase 21.5 Task 21.5.4 - Chain Diagnostics

Date: 2026-07-09
Status: closed

## Scope

Task 21.5.4 adds read-only human and JSON diagnostics for `chain:<id>` route
actions. It explains configured chain state, runtime plan state, unsupported
live-observation state and installed-VM validation state without changing chain
execution semantics.

This task does not claim installed-VM validation. It does not mutate firewall,
LAN/gateway, forwarding, DNS state, routes, system proxy or daemon runtime
connections.

## Diagnostic Model

`diagnostics.chain_routes` adds:

- `ChainDiagnosticStatus`;
- `ChainRouteDiagnostic`;
- `diagnose_chain_route_action()`;
- `diagnose_configured_chains()`.

Each chain diagnostic reports:

- matched route action and chain ID;
- route-action status;
- configured state: `missing`, `enabled` or `disabled`;
- runtime plan state from the Task 21.5.3 resolver;
- live observed state, currently `not-observed`;
- validation state, currently `unsupported-not-vm-validated`;
- whole-chain status: `resolved`, `partial`, `unavailable` or `unknown`;
- confidence: `predicted` for resolved configured plans until live validation
  exists, otherwise the fail-closed status;
- DNS path status;
- final outbound target status;
- redacted hop order with hop type and per-hop availability;
- unavailable/missing/disabled hop reasons.

The `predicted` confidence does not mean traffic has been observed. It means the
configured chain resolved to a deterministic runtime plan, but this task still
does not run installed-VM validation.

## Human Output

`rules explain` and `dns diagnose` now print a `Chain diagnostic` section when
the selected route action is `chain:<id>`.

The human section is safe by default:

- it shows chain ID and route-action status;
- it shows confidence, DNS path and final outbound availability;
- it states `live observation: not-observed`;
- it states `vm validation: not-claimed`;
- it lists hop order by index and hop type;
- it reports unavailable reasons without printing raw profile IDs, group names,
  provider URLs, endpoint tokens, private keys or raw profile configs.

## JSON Output

`RouteDiagnostic.to_dict()` and `RouteDNSDiagnostic.to_dict()` include a stable
`chain` object when a chain diagnostic is supplied. Unified diagnostics adds
`routing.chain_diagnostics`, which summarizes configured chain actions across:

- route rules;
- app-policy rules;
- app-policy default action;
- global default route action.

The unified summary includes aggregate status, matched chain ID when known,
stable item objects and human-safe lines suitable for CLI/TUI/support export
reuse.

## DNS Reporting

Chain diagnostics keep DNS ownership explicit:

- resolved chain DNS is reported as `chain-owned`;
- unavailable DNS ownership reports `unavailable`;
- unknown DNS ownership reports `unknown`;
- route/DNS diagnostics describe chain actions as requiring the chain-owned
  proxy DNS path;
- no direct or system resolver fallback is reported or introduced.

## Fail-Closed Reporting

Missing, disabled, invalid or partially resolved chain actions report
fail-closed route-action statuses:

- `fail-closed-unknown`;
- `fail-closed-unavailable`;
- `fail-closed-partial`.

The diagnostic keeps partial plans visible so operators can see the hop that
failed while preserving redaction boundaries.

## Support Export Redaction

Support export redaction treats chain hop targets and outbound tags as sensitive
by key. The exported payload keeps safe chain facts such as chain ID, status,
confidence, hop index, hop type, DNS path status and unavailable reasons, while
redacting or avoiding:

- provider URLs;
- endpoint tokens;
- private keys;
- raw profile configs;
- raw profile IDs and group names in hop targets;
- sensitive local topology;
- browsing or destination history.

`support_export_ready = true` still means only that the redacted export path is
available. Export still requires explicit user review.

## Validation

Tests cover:

- valid profile-hop chain diagnostics;
- valid group-hop chain diagnostics;
- missing chain;
- disabled chain;
- missing profile hop;
- missing group hop;
- empty group resolution;
- DNS unavailable;
- fail-closed route-action status;
- stable JSON shape;
- human output that does not claim VM validation;
- `rules explain --json` chain output redaction;
- support export redaction with fake canary secrets.

Installed-VM validation remains Task 21.5.5.
