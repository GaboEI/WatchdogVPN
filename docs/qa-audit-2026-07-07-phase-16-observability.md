# QA Audit - Phase 16 Privacy-Preserving Observability

> Date: 2026-07-07
> Scope: Phase 16 Tasks 16.1 through 16.6
> Result: CLOSED - no unresolved HIGH or MEDIUM findings.

## Scope

This audit closes Phase 16 observability work:

- local data sensitivity;
- metrics store schema and retention;
- purge behavior;
- runtime counter recording;
- stats CLI behavior;
- diagnostic report redaction;
- backup/sync boundary for Phase 17.

Phase 16 does not implement packet inspection, byte accounting, DNS query
history, destination history, process history, per-request timestamps, remote
telemetry, remote sync or private full export.

## Surfaces Reviewed

- `metrics.models`
- `metrics.store`
- `metrics.recorder`
- `daemon.runtime_worker`
- `cli.main` `watchdog stats ...`
- `bin/watchdogvpn` diagnostic report summary
- `docs/phase-16-task-16-1-observability-threat-model.md`
- `docs/phase-16-task-16-2-metrics-store.md`
- `docs/phase-16-task-16-3-traffic-rule-counters.md`
- `docs/phase-16-task-16-4-diagnostic-export-rules.md`
- `docs/phase-16-task-16-5-observability-commands.md`
- `docs/reporting.md`
- `docs/security.md`
- Phase 17 backup/sync plan in the external master plan

## Findings

| ID | Severity | Status | Summary |
| --- | --- | --- | --- |
| AUD-P16-001 | MEDIUM | RESOLVED in Task 16.1 | IPv6 literals were not redacted by the shared report/log sanitization path even though the config exposed `reporting.sanitize_ipv6`. |
| AUD-P16-002 | LOW | ACCEPTED | `watchdog stats summary` may display local aggregate profile, rule-group, route-action and node-group counter keys. This is acceptable because it is an explicit local stats command, not a support export or diagnostic report. |
| AUD-P16-003 | LOW | ACCEPTED | Phase 17 backup format includes `metrics-policy.json`. Backup implementation must preserve the Phase 16 boundary by exporting metrics policy only unless a future task explicitly designs and warns about metrics history export. |

No HIGH findings remain open.

No MEDIUM findings remain open.

## Local Data Sensitivity

The metrics store schema is strict and versioned. It contains:

- `enabled`;
- `retention_days`;
- `redaction_mode`;
- `max_bytes`;
- hourly aggregate buckets;
- aggregate counters;
- `updated_at`.

The schema does not contain fields for raw destinations, DNS query names,
process names, process paths, provider URLs, tokens, private keys, LAN
credentials or packet payloads.

Runtime counters are aggregate-only. Profile, rule-group, route-action and
named node-group counters can contain local configuration identifiers, so they
are treated as local user data. They are allowed in the explicit local
`watchdog stats summary` command and excluded from normal diagnostic reports.

## Retention And Size Boundaries

The metrics store enforces:

- minimum and maximum retention days;
- maximum metrics document size;
- strict bucket and document validation;
- no negative counter values;
- atomic persistence through existing persistence helpers.

Increment and prune behavior are covered by unit tests.

## Purge Correctness

`MetricsStore.purge()` removes the metrics file. `watchdog stats purge --yes`
uses this emergency purge path and refuses to run without explicit `--yes`.

The lock file may remain or be recreated as a synchronization artifact, but it
does not contain metrics data.

## Diagnostic Redaction

`watchdogvpn report` includes only a redacted observability summary:

- metrics availability;
- enabled state;
- redaction mode;
- retention days;
- bucket count;
- total aggregate event count;
- allowlisted runtime counters.

Normal reports exclude:

- raw `metrics.json`;
- metrics file paths;
- profile-scoped counters;
- rule-group counters;
- named node-group counters;
- route-action group labels;
- DNS-query-like counter keys;
- destination history;
- process paths;
- provider secrets.

Existing tests cover report redaction with deliberately sensitive-looking
counter keys.

## Stats CLI Boundary

`watchdog stats status` is read-only and does not create a missing metrics file.

`watchdog stats summary` displays known aggregate counter families and withholds
unknown/future counter keys. This prevents corrupted or future metrics content
from silently exposing DNS-query-like or destination-like keys through the
default summary output.

`watchdog stats privacy-mode detailed` stores the policy mode value but does
not enable detailed request history. Phase 16 still reports
`detailed_history_supported=false`.

## Backup And Sync Boundary

Phase 17 may export `metrics-policy.json` as policy metadata. It must not treat
the metrics history/counter store as safe for normal backup, diagnostics or
remote sync by default.

Any future export of metrics history requires:

- an explicit task;
- a sensitive-data warning;
- a clear user action;
- retention and purge handling;
- exclusion from normal diagnostic reports;
- a remote-sync threat-model decision before network sync.

## Acceptance Review

- Observability is default-off or aggregate-only by default: PASS.
- Sensitive request history is never silently enabled: PASS.
- Retention and purge are implemented and tested: PASS.
- Diagnostic exports do not leak sensitive history by default: PASS.
- Phase-specific QA audit has no unresolved HIGH or MEDIUM findings: PASS.

## Validation

Closure validation:

- `python3 -m unittest tests.test_cli_stats_commands tests.test_metrics_store tests.test_daemon_runtime_worker`
- `bash tests/unit/test_watchdogvpn_cli.sh`
- `python3 -m unittest discover -s tests -p 'test_*.py'`
- `bash tests/unit.sh`
- `bash tests/syntax.sh`
- `git diff --check`
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`
