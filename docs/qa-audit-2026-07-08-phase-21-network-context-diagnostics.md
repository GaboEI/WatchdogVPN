# QA Audit - Phase 21 Network Context Diagnostics

Date: 2026-07-08
Branch: `phase-21-network-context-diagnostics`
Status: closed

## Scope

This audit closes Phase 21 network-context automation and diagnostics before
work can proceed toward merge preparation.

Audited areas:

- network-context automation defaults, consent and non-execution semantics;
- privacy boundaries for stored, transient and forbidden facts;
- unified diagnostics redaction and accuracy;
- redacted support export behavior;
- provider metadata and health summaries;
- route, DNS, proxy, TUN, LAN and system-proxy diagnostics;
- unsupported monitor fallback behavior.

No merge to `main` was performed.

## Method

The audit reviewed:

- `network_context/models.py`;
- `network_context/monitor.py`;
- `diagnostics/unified.py`;
- `diagnostics/support_export.py`;
- Phase 21 tests and documentation;
- master-plan Phase 21 acceptance criteria.

The audit also used targeted searches for:

- remote upload or transmission paths in support export;
- forbidden network/location history fields;
- raw SSID/BSSID/interface/gateway persistence;
- runtime autoconnect/autodisconnect execution;
- support-export review bypasses.

## Findings

| ID | Severity | Status | Area | Finding | Resolution |
| --- | --- | --- | --- | --- | --- |
| AUD-P21-001 | LOW | RESOLVED | Documentation / support export semantics | Task 21.4 and Task 21.5 docs still described support export as unavailable after Task 21.6 changed `UnifiedDiagnostics.support_export_ready` to `true`. This could imply either stale behavior or silent export permission. | Updated Task 21.4, Task 21.5 and Task 21.6 docs to state that `support_export_ready = true` means only that a redacted export path exists and is available. Added a focused test proving the flag does not bypass `user_reviewed=True`. |
| AUD-P21-002 | INFO | CLOSED | Network-context automation | Network-context connect/disconnect intents are modeled only. `runtime_action_executed` is always false, unsupported monitors degrade to manual mode, and automatic intents require explicit enabled actions with explanation, disable hint and reversible semantics. | No code change required. Existing tests cover disabled policy, unsupported fallback, modeled intent and non-execution. |
| AUD-P21-003 | INFO | CLOSED | Privacy boundaries | Raw SSID/BSSID/interface/gateway facts are transient observation data. Persisted policy rejects forbidden history fields by default, and raw match persistence requires explicit consent and a consent note. | No code change required. Existing tests cover forbidden fields, consent requirements and redacted policy export. |
| AUD-P21-004 | INFO | CLOSED | Redaction | Unified diagnostics redacts route interfaces/gateways, resolver nameservers/search domains, LAN bind/gateway interface values and network-context observation values. Support export adds a second recursive redaction pass with canary-secret tests. | No code change required beyond the new support-export semantics test. |
| AUD-P21-005 | INFO | CLOSED | Diagnostics accuracy | Unified diagnostics distinguishes configured, observed, unsupported, error, unknown and representable-fail-closed states across routing, capture, routes, DNS, proxy, TUN, LAN, provider metadata and system proxy. | No code change required. Existing tests cover unsupported route-table fallback, missing runtime unknowns, provider metadata unknowns and system-proxy representability. |

## Severity Summary

- HIGH: 0
- MEDIUM: 0
- LOW: 1 resolved
- INFO: 4 closed observations

No unresolved HIGH or MEDIUM findings remain.

## Network-Context Automation

Phase 21 remains safe by default:

- persisted policy defaults to disabled/manual behavior;
- automatic actions are opt-in modeled intents, not runtime execution;
- connect/disconnect intents must be explainable, disableable and reversible;
- unsupported monitor environments degrade to manual mode;
- `runtime_action_executed` remains false in the decision model and unified
  diagnostics.

No daemon connection, autoconnect or autodisconnect behavior was added.

## Privacy Boundaries

Phase 21 keeps network facts classified:

- persisted facts: policy shape, hashed/typed matches, explicit consent marker,
  trigger intent and redaction preferences;
- transient facts: observed SSID/BSSID/interface/gateway/default-route data used
  for immediate policy evaluation;
- forbidden-by-default facts: network transition history, captive-portal
  history, public exit IP history, per-network automation history, DNS query
  history and destination history.

Raw SSID/BSSID/interface/gateway match values require explicit consent and a
consent note before persistence. Normal observation output remains redacted.

## Redaction Audit

Unified diagnostics:

- excludes provider URLs;
- summarizes provider metadata without refreshing providers;
- redacts route-table devices/gateways;
- redacts DNS nameservers/search domains while keeping counts;
- redacts LAN bind and gateway interface values;
- redacts TUN interface values;
- redacts network-context observations;
- reports recent failure categories without raw event payloads.

Support export:

- requires explicit `user_reviewed=True`;
- does not upload or transmit data;
- does not provide a raw full-export mode;
- applies strict recursive redaction over the unified payload;
- includes guard metadata with `user_review_required = true`;
- tests seed false secrets across provider metadata, profile config, LAN, DNS,
  routes, network-context text and recent failures, then assert serialized
  output does not contain those canaries.

## Support Export Semantics

`support_export_ready = true` means:

- the redacted support export path exists;
- the path is available to a caller that performs review.

`support_export_ready = true` does not mean:

- export is safe without user review;
- upload or remote transmission is allowed;
- raw unredacted export is available.

The enforceable gate is `build_redacted_support_export(..., user_reviewed=True)`.
Without that explicit flag, the builder raises `SupportExportReviewRequired`.

## Runtime And Network Behavior

This audit introduced no runtime or network behavior changes. Phase 21 still
does not:

- wire NetworkManager/system events into automation;
- start or stop daemon connections from network context;
- execute autoconnect/autodisconnect;
- mutate DNS, routes, firewall, forwarding, LAN sharing, gateway mode or system
  proxy state;
- upload support exports.

## Closure

Phase 21 has no unresolved HIGH or MEDIUM audit findings. The branch is ready
for merge preparation after standard validation, subject to the project rule
that `main` is not touched until explicitly authorized.
