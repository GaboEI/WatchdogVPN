# Phase 16 Task 16.4 - Diagnostic Export Rules

> Date: 2026-07-06
> Status: CLOSED - redacted observability summary added to diagnostics.

## Scope

Task 16.4 defines and implements the default diagnostic export behavior for
Phase 16 observability data.

`watchdogvpn report` may include a small observability summary, but it must not
export the raw metrics store or local identifiers that could reveal user
configuration, routing policy names, node-group names, profile ids, destination
history or DNS query history.

## Default Report Fields

The normal diagnostic report may include:

- metrics availability state;
- metrics enabled state;
- configured redaction mode;
- configured retention days;
- aggregate bucket count;
- aggregate total event count;
- allowlisted aggregate counters for runtime command, rotation, health-check,
  recovery, node-group auto-test and coarse error categories.

The report intentionally does not print the metrics file path.

## Excluded By Default

Normal diagnostic reports must not include:

- raw `metrics.json` contents;
- profile-scoped counter keys;
- rule-group counter keys;
- named node-group counter keys;
- route-action group labels;
- DNS query names;
- raw destination domains or IP addresses;
- process names or paths;
- provider URLs, credentials, tokens or private keys;
- per-request timestamps or detailed traces.

Those exclusions apply even when metrics are locally enabled.

## Private Full Export

Task 16.4 does not implement a private full export.

If a future task adds one, it must use a separate explicit command or flag,
display a sensitive-data warning, and keep normal `watchdogvpn report` behavior
redacted by default.

## Validation

Tests cover:

- `watchdogvpn report` includes the observability metrics section;
- allowlisted aggregate counters are included;
- profile, rule-group, named node-group, route-action group and DNS-query-like
  counter keys are excluded;
- the raw metrics file name is not printed;
- existing report and log sanitization for email, IPv4, IPv6 and home-path-like
  data remains active.
