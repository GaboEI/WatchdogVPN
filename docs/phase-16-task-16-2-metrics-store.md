# Phase 16 Task 16.2 - Metrics Store

> Date: 2026-07-06
> Status: CLOSED - strict metrics store implemented, no runtime counters yet.

## Scope

Task 16.2 implements the local persistence layer for future observability
metrics. It does not record traffic, route decisions, DNS queries or process
activity. Runtime counters belong to Task 16.3.

## Store

The metrics store lives at:

```text
metrics.json
```

Default path resolution follows the shared WatchdogVPN config/state directory.
Tests and operators may override it with:

```sh
WATCHDOGVPN_METRICS_FILE=/path/to/metrics.json
```

## Schema

`metrics.models.MetricsDocument` is strict schema version `1`:

```json
{
  "schema_version": 1,
  "enabled": false,
  "retention_days": 7,
  "redaction_mode": "aggregate",
  "max_bytes": 1048576,
  "buckets": [],
  "updated_at": null
}
```

Fields:

- `enabled`: whether metrics recording is allowed once runtime counters exist.
- `retention_days`: bounded retention window, 1 to 30 days.
- `redaction_mode`: `off`, `aggregate` or `detailed`.
- `max_bytes`: bounded store size, 1 KiB to 10 MiB.
- `buckets`: aggregate buckets for later Task 16.3 counters.
- `updated_at`: ISO timestamp set by the store on save.

The default document is disabled but aggregate-ready. This satisfies the Phase
16 default privacy posture: no metrics are recorded until later runtime work
writes aggregate counters, and raw request history is not part of this schema.

## Safety Properties

- Unknown top-level or bucket fields are rejected.
- Invalid booleans, integers, retention windows, redaction modes and ISO
  timestamps are rejected.
- Bucket counter values must be non-negative integers.
- Writes use the repository's atomic JSON persistence helper.
- The store validates serialized size before writing.
- `prune()` removes buckets older than `retention_days`.
- `purge()` removes the metrics file as the emergency purge path.

## Privacy Boundary

This store is for aggregate data. The schema does not include raw destination
domains, destination IPs, DNS query history, process paths, raw provider URLs,
tokens, private keys, LAN credentials or packet payloads.

`redaction_mode = detailed` is accepted as a policy value for future CLI/state
compatibility, but Task 16.2 does not implement detailed history collection.
Any future detailed mode remains gated by the Task 16.1 threat model.

## Validation

Implemented tests in `tests/test_metrics_store.py` cover:

- default disabled aggregate document;
- strict schema rejection for unknown fields and invalid values;
- non-negative counter validation;
- save/load round trip;
- size-limit rejection before write;
- retention pruning;
- emergency purge;
- environment path override;
- corrupt/non-object load rejection;
- atomic write temp-file cleanup.
