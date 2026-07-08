# Phase 21 Task 21.6 - Redacted Support Export

Date: 2026-07-08
Status: closed

## Scope

Task 21.6 adds a user-reviewed, redacted support export path for the structured
unified diagnostics engine.

The task does not upload support bundles, add CLI/TUI wiring, refresh
providers, contact subscription URLs, start or stop daemon connections, rotate
profiles, or change DNS, routes, firewall, forwarding, LAN sharing, gateway
mode or system proxy state.

## Export Path

`diagnostics.support_export.build_redacted_support_export()` accepts a
`UnifiedDiagnostics` object and returns a JSON-ready `RedactedSupportExport`.

`UnifiedDiagnostics.support_export_ready = true` means only that the redacted
support export path exists and is available. It does not grant permission to
export without review.

The function requires explicit `user_reviewed=True`. Calling it without that
flag raises `SupportExportReviewRequired`, so callers cannot silently create a
support export without a user-review step.

The export wrapper includes:

- support export schema version;
- generator name;
- generation timestamp;
- `user_reviewed = true`;
- `redaction_mode = "strict"`;
- redacted diagnostics payload;
- explicit redaction guard metadata.

## Redaction Boundaries

The support export applies a second recursive redaction pass over the unified
diagnostics payload. This is intentional: the unified diagnostics engine already
redacts known sensitive fields, but support export must also defend against
future nested shapes, untrusted provider metadata strings and sensitive values
embedded in free-text diagnostics.

The support export redacts:

- provider URLs and endpoint URLs;
- endpoint tokens and authorization values;
- private keys and key-like secret fields;
- LAN credentials and password fields;
- raw SSID/BSSID/interface/gateway identifiers;
- public and local IP literals;
- CIDR values;
- DNS nameserver and search-domain values;
- provider IDs and provider local names;
- sensitive free-text values that mention network-context markers.

The export keeps structured counts, statuses and safety booleans where they do
not expose sensitive values.

## Canary Validation

Task 21.6 tests seed false secrets into provider URLs, provider metadata,
profile config, LAN settings, DNS resolver inventory, route tables, network
context observations, user-facing policy text and recent failure categories.

The tests serialize the support export and assert that none of the seeded
canary values survive in the output. This verifies that the export is not only
visually clean, but also fails closed when future payloads contain nested or
unexpected secret shapes.

## Task 21.6 Acceptance

Task 21.6 closes when:

- support export requires explicit user review;
- support export returns JSON-ready structured data;
- provider URLs, tokens, private keys, LAN credentials and local network
  identifiers are redacted by default;
- false secrets seeded in tests do not appear in serialized output;
- unified diagnostics marks support export as available;
- no runtime or network behavior changes are introduced;
- tests and standard validation pass.
