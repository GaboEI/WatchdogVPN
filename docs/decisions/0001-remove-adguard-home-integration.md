# 0001 — Remove AdGuard Home integration

## Status

Accepted — 2026-07-01

## Context

v1 included guided AdGuard Home installation and DNS management as an optional
advanced mode. After real daily use on Ubuntu 24.04 with `systemd-resolved`,
the integration introduced more operational friction than product value:

- It created a second DNS source of truth outside WatchdogVPN's v2 DNS layer.
- It increased installer, updater, doctor and TUI surface area for an optional
  component.
- It made DNS behavior harder to reason about across reboots and
  NetworkManager changes.
- It tied WatchdogVPN DNS UX to an external product instead of a
  backend-agnostic DNS manager.

The v2 DNS system will provide user-configurable DNS without requiring an
external component.

## Decision

Remove all WatchdogVPN-guided AdGuard Home integration in v2.0.0. This is a
hard cut with no migration period. Users who want AdGuard's DNS resolvers can
configure them as custom DNS servers in the v2 DNS system. A standalone
AdGuard Home installation is unaffected and continues to work independently;
this decision only removes WatchdogVPN's guided setup and integration layer.

## Consequences

### Positive

- Single source of truth for DNS in v2.
- Smaller support, installer, doctor and TUI surface.
- Cleaner install flow for non-technical users.

### Negative

- Users who relied on the guided AdGuard Home setup must install and configure
  AdGuard Home independently if they still want it.
- One-time cleanup is required before Phase 10.

### Neutral

- v1 to v2 migration does not preserve AdGuard Home configuration as a
  WatchdogVPN-managed concern. Any standalone AdGuard Home installation remains
  outside WatchdogVPN scope.
