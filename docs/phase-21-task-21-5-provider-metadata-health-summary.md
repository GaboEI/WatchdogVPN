# Phase 21 Task 21.5 - Provider Metadata And Health Summary

Date: 2026-07-08
Status: closed

## Scope

Task 21.5 adds provider metadata and health summary semantics to the structured
unified diagnostics engine.

This task does not refresh providers, contact subscription URLs, mutate provider
state, start or stop daemon connections, rotate profiles, or change DNS,
routes, firewall, forwarding, LAN sharing, gateway mode or system proxy state.

This task also does not implement support export. User-reviewed support export
remains Task 21.6. After Task 21.6, `support_export_ready = true` means only
that the redacted export path is available; export still requires explicit
user review.

## Provider Summary

`diagnostics.unified` now summarizes each provider with:

- provider ID and local provider name;
- last update timestamp and `last_updated_status`;
- provider profile count;
- rotation and auto-update policy flags;
- update interval;
- metadata keys present;
- quota summary;
- expiry summary;
- profile health summary.

Provider URLs are still excluded from unified diagnostics.

## Quota Summary

Quota metadata is optional. The engine recognizes common provider metadata
keys:

- used: `traffic_used`, `used`, `quota_used`;
- limit: `traffic_limit`, `traffic_total`, `total`, `quota_total`,
  `quota_limit`;
- remaining: `traffic_remaining`, `remaining`, `quota_remaining`.

If any quota field is present, `quota.status = "reported"`. Missing quota
metadata reports `quota.status = "unknown"` and `unlimited_assumed = false`.

The engine never treats missing quota as unlimited.

## Expiry Summary

Expiry metadata is optional. The engine recognizes:

- `expires_at`;
- `expire`;
- `expires`;
- `expiry`;
- `valid_until`.

ISO-8601 timestamps, ISO dates and Unix timestamps are normalized to UTC when
parseable. Parseable values report:

- `expiry.status = "known"`;
- normalized `expires_at`;
- boolean `expired`.

Missing expiry reports:

- `expiry.status = "unknown"`;
- `expires_at = null`;
- `expired = "unknown"`.

Unparseable expiry reports `expiry.status = "reported-unparsed"` and
`expired = "unknown"` instead of assuming the provider is healthy.

## Health Summary

Provider health is derived from local profile state only. The engine does not
run live health checks in Task 21.5.

The summary includes:

- referenced provider profile count;
- observed local profile count;
- enabled profile count;
- rotation profile count;
- health `status_counts`;
- latest local `last_health_check`;
- aggregate status.

Aggregate health rules:

- no referenced profiles: `unknown`;
- any `down` or `degraded` profile: `degraded`;
- all referenced profiles observed as `ok`: `ok`;
- missing or mixed unknown status: `unknown`.

Missing profile health is never treated as healthy.

## Validation

Task 21.5 adds/updates tests for:

- quota metadata when present;
- missing quota as unknown and not unlimited;
- expiry metadata when present;
- missing expiry as unknown;
- unparseable expiry as reported but unknown health;
- provider profile health aggregation;
- provider URLs remaining excluded;
- unified diagnostics still preserving the Task 21.6 support-export boundary.

## Task 21.5 Acceptance

Task 21.5 closes when:

- provider quota/expiry/update metadata is summarized when present;
- missing quota/expiry/health is reported as unknown, not unlimited or healthy;
- provider URLs remain excluded;
- no provider refresh or runtime mutation is introduced;
- tests and standard validation pass.
