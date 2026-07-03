# 0001 - Remove guided third-party DNS integration

## Status

Accepted - 2026-07-01

## Context

v1 included guided installation and DNS management for an optional external DNS
component. After real daily use on Ubuntu 24.04 with `systemd-resolved`, the
integration introduced more operational friction than product value:

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

Remove all WatchdogVPN-guided third-party DNS integration in v2.0.0. This is a
hard cut with no migration period. Users who want custom DNS resolvers can
configure them explicitly in the v2 DNS system. Standalone DNS services remain
outside WatchdogVPN scope.

## Consequences

### Positive

- Single source of truth for DNS in v2.
- Smaller support, installer, doctor and TUI surface.
- Cleaner install flow for non-technical users.

### Negative

- Users who relied on the guided external DNS setup must install and configure
  their DNS stack independently if they still want it.
- One-time cleanup is required before Phase 10.

### Neutral

- v1 to v2 migration does not preserve external DNS configuration as a
  WatchdogVPN-managed concern. Standalone DNS services remain outside
  WatchdogVPN scope.
