# Phase 16 Task 16.5 - Observability Commands

> Date: 2026-07-07
> Status: CLOSED - local stats commands implemented.

## Scope

Task 16.5 adds local CLI commands for inspecting and controlling the Phase 16
metrics store:

```sh
watchdog stats status [--json]
watchdog stats summary [--json]
watchdog stats purge --yes
watchdog stats privacy-mode <off|aggregate|detailed>
```

These commands are local-only. They do not upload metrics, contact providers,
mutate VPN runtime state, inspect packets, read DNS query history or create a
detailed request log.

## Commands

### `watchdog stats status`

Reports metrics store state without creating a missing metrics file.

Reported fields include:

- metrics availability;
- enabled state;
- privacy/redaction mode;
- retention days;
- maximum store size;
- aggregate bucket count;
- aggregate event count;
- last update timestamp;
- whether detailed request history is supported.

`detailed_history_supported` is always `false` in Phase 16.

### `watchdog stats summary`

Reports aggregate counters from the metrics store.

The summary includes only known aggregate counter families:

- command counters;
- rotation counters;
- health-check status counters;
- recovery status counters;
- node-group aggregate counters;
- coarse error counters;
- profile aggregate counters;
- route-action aggregate counters;
- rule-group aggregate counters.

Unknown or future counter keys are withheld from the printed/JSON counter
summary and counted through `withheld_counter_keys`. This prevents a corrupted
or future metrics file from silently exposing DNS-query-like or destination-like
keys through the default summary command.

### `watchdog stats purge --yes`

Removes the local metrics file through the `MetricsStore.purge()` emergency
purge path. The command refuses to run without `--yes`.

### `watchdog stats privacy-mode`

Sets the local metrics mode:

- `off`: disables metrics recording and stores redaction mode `off`;
- `aggregate`: enables aggregate metrics recording;
- `detailed`: enables the policy mode value but does not enable detailed
  request history because no detailed history implementation exists in Phase
  16.

When `detailed` is selected, the CLI prints an explicit note that detailed
request history is not implemented and aggregate counters remain the only
recorded data.

## Privacy Boundary

Task 16.5 does not add:

- raw destination domains;
- destination IP history;
- DNS query history;
- process names or paths;
- per-request timestamps;
- packet payloads;
- provider secrets;
- private full export.

Normal diagnostic export behavior remains governed by Task 16.4 and stays
redacted by default.

## Validation

Tests cover:

- missing metrics status does not create `metrics.json`;
- status JSON reports default privacy posture;
- summary JSON includes known aggregate counters;
- summary JSON withholds unknown/DNS-query-like counter keys;
- purge refuses to run without `--yes`;
- purge removes the metrics file;
- `privacy-mode detailed` does not report detailed history support;
- `privacy-mode off` disables metrics.
