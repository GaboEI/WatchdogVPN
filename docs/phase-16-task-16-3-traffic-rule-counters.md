# Phase 16 Task 16.3 - Traffic And Rule Counters

> Date: 2026-07-06
> Status: CLOSED - aggregate counter recording implemented, no destination
> history.

## Scope

Task 16.3 adds the aggregate counter write path for runtime observability. It
does not add packet inspection, byte accounting from network interfaces, DNS
query logging, process tracking or destination history.

The implementation records only local aggregate counters when metrics are
explicitly enabled in `metrics.json`.

## Counter Storage

`MetricsStore.increment()` writes counters into hourly aggregate buckets:

```text
bucket_start = YYYY-MM-DDTHH:00:00+00:00
bucket_end   = bucket_start + 1 hour
```

If metrics are disabled or the metrics file is missing, increment is a no-op and
does not create a metrics file or lock file. This preserves the Phase 16 privacy
default.

Every increment:

- validates counters through the strict schema;
- merges into the current hourly bucket;
- prunes expired buckets according to `retention_days`;
- validates the configured `max_bytes` limit before writing;
- uses atomic persistence.

## Runtime Recorder

`metrics.recorder.MetricsRecorder` converts runtime lifecycle events into safe
aggregate counter keys. Runtime recording is best-effort: metrics failures are
logged as warnings and must not break connect, disconnect, rotation, health
checks or node-group auto-test.

Recorded categories:

- connect attempts/success/failure;
- disconnect attempts/success/failure;
- manual rotation attempts and resulting status;
- scheduled rotation attempts and resulting status;
- health-check status;
- recovery status categories such as `reconnecting`, `recovered`,
  `all_failed`, `kill_switch_active` and `rotation_unavailable`;
- node-group auto-test attempts and result categories;
- runtime worker exception categories;
- profile-scoped aggregate events by local profile id.

The recorder also exposes aggregate helpers for future route/rule sources:

- `record_route_action(action)`;
- `record_rule_group(group_name)`;
- `record_profile_event(profile_id, event)`.

Those helpers intentionally record only local identifiers and aggregate counts.
They do not store destinations, process paths or per-request traces.

## Runtime Integration

`daemon.runtime_worker.RuntimeWorker` now records aggregate metrics for the
serialized daemon operations it already owns:

- `connect`;
- `disconnect`;
- manual `rotate`;
- scheduled rotation;
- autonomous health-check tick;
- node-group auto-test;
- tick/scheduled-rotation exception categories.

`status` remains read-only and does not increment counters.

## Privacy Boundary

Task 16.3 does not store:

- destination domains;
- destination IPs;
- DNS query names;
- process names or paths;
- request timestamps;
- packet payloads;
- provider URLs or secrets.

Profile, node-group and rule-group ids are local configuration identifiers and
are recorded only as aggregate counter keys when metrics are enabled.

Byte counters are not fabricated in this task. They require a trustworthy
runtime source in a later task before they can be recorded honestly.

## Validation

Tests cover:

- missing metrics file remains a no-op without creating local state;
- enabled metrics merge counters into hourly buckets;
- increment pruning removes expired buckets;
- recorder emits aggregate runtime counters;
- recorder route-action and rule-group helpers write aggregate counters;
- `RuntimeWorker` records connect, rotate, node-group auto-test and disconnect
  counters when metrics are enabled;
- existing worker behavior remains unchanged when metrics are absent.
