# Phase 21 Task 21.4 - Unified Diagnostics Engine

Date: 2026-07-08
Status: closed

## Scope

Task 21.4 adds a structured, read-only unified diagnostics engine.

This task does not implement support export. The support-export flow, including
user review and export-specific redaction controls, remains Task 21.6.

Task 21.4 also does not start or stop daemon connections, run autoconnect or
autodisconnect, mutate DNS, routes, firewall, forwarding, LAN sharing, gateway
mode or system proxy state.

## Engine

`diagnostics.unified.collect_unified_diagnostics()` returns
`UnifiedDiagnostics`, a JSON-ready dataclass with these sections:

- `routing`: configured routing policy, capture modes, default route action
  and compatibility-only `active_mode`;
- `capture`: configured and observed local proxy, TUN and system proxy capture
  state;
- `route_tables`: read-only route-table summary from `ip -j route show table
  main` when available;
- `dns`: DNS policy and resolver-manager inventory;
- `exit_ip`: public exit IP probe status;
- `proxy`: local proxy, system proxy and LAN proxy summaries;
- `tun`: configured/observed TUN and kill-switch state;
- `lan`: LAN proxy/gateway configuration and runtime status;
- `network_context`: Task 21.3 observation and policy decision;
- `providers`: provider update summary without provider URLs or metadata
  values;
- `recent_failures`: non-sensitive failure categories;
- `diagnostics`: collection errors or partial-state notes.

At Task 21.4 close time the engine set `support_export_ready = false` to make
the Task 21.6 boundary explicit. Task 21.6 later changed this field to `true`.
After Task 21.6, `support_export_ready = true` means only that a redacted
support export path exists and is available. It does not mean export may happen
without explicit user review.

## Privacy And Honesty

Unified diagnostics are structured facts, not a support bundle.

Privacy rules:

- provider URLs are not included;
- provider metadata values are not included in Task 21.4;
- local network identifiers use the Task 21.3 redacted/not-observed markers;
- route-table interface and gateway values are redacted;
- resolver nameservers and search domains are counted and redacted;
- LAN bind and gateway interface values are redacted;
- public exit IP probing is not run by default and no public IP history is
  stored.

Honesty rules:

- unsupported route-table observation reports `unsupported`;
- missing runtime state reports `unknown`, not healthy;
- system proxy remains `representable-fail-closed` when configured;
- LAN gateway DNS reports `manual-client-dns-only`;
- recent failures report categories only, not raw events;
- enabled network-context connect/disconnect intents are still reported with
  `runtime_action_executed = false`.
- `support_export_ready` reports redacted export path availability only; the
  support export builder still requires explicit `user_reviewed = true`.

## Read-Only Inputs

Task 21.4 may read:

- app config;
- routing state;
- DNS policy and resolver inventory;
- provider metadata summary;
- optional runtime state supplied by a caller;
- Task 21.3 network-context policy/observation/decision;
- `ip -j route show table main` for route-table summary.

The command runner is injectable for tests. Default command execution uses
list-form subprocess calls with captured output and a short timeout.

## Task 21.4 Acceptance

Task 21.4 closes when:

- one structured diagnostics layer can summarize routing, capture, route-table,
  DNS, exit IP status, proxy, TUN, LAN, provider update and recent failure
  facts;
- support export remains explicitly out of scope;
- sensitive local network values are redacted while unavailable values remain
  distinguishable;
- unsupported observations degrade honestly;
- tests and standard validation pass;
- no runtime or network mutation is introduced.

## Implementation Finding

During validation, `tests/unit.sh` found that the installed Python runtime
package list did not include `network_context`, which was introduced in Tasks
21.2 and 21.3 and is imported by unified diagnostics. `lib/runtime.sh` now
ships `network_context` so install/update paths do not produce
`ModuleNotFoundError`.
