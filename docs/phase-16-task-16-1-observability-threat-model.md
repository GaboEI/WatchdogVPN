# Phase 16 Task 16.1 - Observability Threat Model

> Date: 2026-07-06
> Status: CLOSED - privacy contract defined before metrics storage.

## Decision

WatchdogVPN observability must default to aggregate, local-only, bounded data.
It must not silently become a destination history, process activity log, or
support bundle of secrets.

The default Phase 16 posture is:

- aggregate counters may be stored locally by default once a metrics store
  exists;
- full request/destination history is not implemented in Phase 16 by default;
- detailed history, if ever accepted, must be explicitly enabled, clearly
  labeled sensitive, retention-bounded, purgeable, and excluded from normal
  diagnostics exports;
- all metrics storage must have a single emergency purge path;
- diagnostic exports must redact or omit observability data unless the user
  explicitly requests a private full export.

## Data Classification

### Allowed By Default: Aggregate And Low-Sensitivity

These fields may be stored by default in aggregate form:

- total bytes in/out;
- counters by route action (`direct`, `current`, `block`, group/auto);
- counters by rule group id/name;
- counters by profile id or node group id;
- counts of reconnects, rotations, recovery outcomes, health-check outcomes
  and failure categories;
- coarse last-updated timestamps for aggregate buckets;
- metrics policy fields such as enabled state, retention days and redaction
  mode.

Constraints:

- no raw destination domain/IP is stored in default aggregate mode;
- no raw process path is stored in default aggregate mode;
- no raw provider URL, token, private key or subscription secret is stored;
- profile and group identifiers are local identifiers and still must be treated
  as user configuration, not anonymous telemetry.

### Allowed Only With Explicit Sensitive Mode

These fields are sensitive and may be stored only if a future task implements a
clearly labeled opt-in mode:

- raw destination domains;
- raw destination IP addresses;
- per-flow or per-request timestamps;
- process names;
- process executable paths;
- full rule-match traces for individual requests;
- provider/profile ids attached to individual destinations;
- DNS query history;
- public exit IP history.

Required controls before this can exist:

- default-off;
- explicit CLI warning before enabling;
- retention days with a low maximum;
- bounded file/database size;
- emergency purge;
- excluded from normal `watchdogvpn report` and support exports;
- private full export requires explicit user action and warning.

### Forbidden In Metrics Storage

These fields must not be stored in Phase 16 metrics:

- private keys;
- passwords;
- provider tokens;
- subscription URLs with credentials;
- raw provider import payloads;
- LAN proxy credentials;
- raw packet payloads;
- browser URLs beyond the host/domain classification explicitly accepted by a
  future sensitive mode;
- unredacted diagnostic report contents.

## Retention And Purge

The Phase 16 metrics store must support:

- disabled/off state;
- aggregate mode;
- future detailed mode only if explicitly accepted;
- retention days;
- atomic writes;
- bounded on-disk size;
- emergency purge that removes all metrics data, including future detailed
  history;
- no backup/export inclusion by default before Phase 17 defines backup
  handling for metrics.

Recommended defaults for the implementation phase:

- mode: `aggregate`;
- detailed history: disabled / unsupported unless explicitly enabled later;
- retention: short and bounded;
- export: exclude metrics from normal diagnostics unless summarized and
  redacted.

## Diagnostics And Support Export Rules

Normal diagnostics may report:

- metrics enabled state;
- retention days;
- redaction mode;
- aggregate totals;
- top-level failure categories.

Normal diagnostics must not include:

- raw destination history;
- per-request timestamps;
- process paths;
- provider URLs/tokens;
- private keys;
- LAN credentials;
- raw metric store files.

If a future private full export is implemented, it must require a separate
explicit flag and display a sensitive-data warning before writing the bundle.

## Existing Surfaces Reviewed

- `watchdogvpn report` writes a local report only and applies basic
  sanitization.
- `watchdogvpn logs` reads local logs only and sanitizes obvious sensitive
  values.
- Daemon event payloads currently expose runtime state such as status,
  active profile id, mode, TUN/proxy flags and kill-switch state; they do not
  include destination history.
- Driver runtime logs are per-run local files under private runtime
  directories and are cleaned with runtime cleanup; sing-box log level remains
  `warning` by default.

## Bug Fixed During This Task

AUD-P16-001 found that the CLI exposed and documented
`reporting.sanitize_ipv6`, but the shared report/log sanitization pipeline did
not redact IPv6 literals. This could leak IPv6 addresses in `watchdogvpn
report` or `watchdogvpn logs` output.

Resolution:

- `bin/watchdogvpn::sanitize_stream()` now redacts common compressed and
  uncompressed IPv6 literals.
- `tests/unit/test_watchdogvpn_cli.sh` now includes IPv6 sample data and fails
  if the raw IPv6 prefix remains in report or logs output.

## Deferred Work

The following work belongs to later Phase 16 tasks:

- strict metrics store schema;
- retention enforcement;
- bounded file/database size;
- emergency purge implementation;
- aggregate traffic/rule counters;
- stats CLI commands;
- diagnostics export integration.

No metrics store or runtime counters were implemented in Task 16.1.

## Acceptance

Task 16.1 closes when:

- the observability data classification is documented;
- default privacy posture is explicit;
- sensitive request history is rejected by default or requires explicit opt-in;
- later Phase 16 implementation tasks have clear storage, purge, retention and
  export constraints;
- any privacy bug found in the reviewed existing surfaces is fixed.
