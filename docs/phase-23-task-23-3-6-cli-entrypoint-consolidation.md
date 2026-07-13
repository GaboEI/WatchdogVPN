# Phase 23 Task 23.3.6 CLI Entrypoint Consolidation

Date: 2026-07-13

## Decision

`watchdog` is the single canonical WatchdogVPN CLI. It owns:

- the only root help and parser;
- the product version contract;
- daemon-backed connect, disconnect, status and rotate semantics;
- profiles, providers, DNS, routing, app policy and node groups;
- backup, setup, doctor, panic and uninstall flows;
- the `maintenance` namespace for the remaining local Bash support functions.

`watchdogvpn` is retained only as a deprecated compatibility alias. It does not
parse product commands or query runtime state independently. Every invocation
is routed to `watchdog`, with a migration warning written to stderr. stdout is
not prefixed, which preserves JSON and machine-readable output during migration.

## Command Migration

| Deprecated invocation | Canonical invocation |
|---|---|
| `watchdogvpn --help` or `watchdogvpn help` | `watchdog --help` |
| `watchdogvpn version` or `watchdogvpn --version` | `watchdog version` |
| `watchdogvpn status` | `watchdog status` |
| `watchdogvpn doctor` | `watchdog doctor` |
| `watchdogvpn backend ...` | `watchdog maintenance backend ...` |
| `watchdogvpn config ...` | `watchdog maintenance config ...` |
| `watchdogvpn logs ...` | `watchdog maintenance logs ...` |
| `watchdogvpn report` | `watchdog maintenance report` |
| `watchdogvpn runtime-update ...` | `watchdog maintenance runtime-update ...` |
| `watchdogvpn tui` | `watchdog maintenance tui` |
| `watchdogvpn update-check` | `watchdog maintenance update-check` |
| `watchdogvpn update-plan` | `watchdog maintenance update-plan` |
| Any other `watchdogvpn <args>` | `watchdog <args>` |

The compatibility alias no longer preserves the old `vpnctl`-backed status
contract. Both command names now reach the same daemon IPC status implementation,
JSON envelope and exit code. This is an intentional safety correction: the same
host must not expose two conflicting answers under the same product brand.

## Version And Removal Policy

The release marker remains shared by the compatibility script and canonical
`watchdog version` implementation. The alias cannot produce a separate version.

`watchdogvpn` remains installed for the complete v2 major release line. Its
earliest possible removal is v3.0, with advance notice in release notes. New
documentation, scripts, tests and TUI command builders must use `watchdog`.
Automation that cannot migrate immediately may temporarily set
`WATCHDOGVPN_SUPPRESS_DEPRECATION_WARNING=1`; this changes only the stderr
warning and never restores the old dispatcher.

## Maintenance Boundary

The Bash implementation remains responsible for its existing local-only support
operations: sanitized logs and reports, custom-VPS backend inspection, legacy
language/TUI/reporting preferences, source-checkout update inspection and the
current TUI launcher. The Python CLI invokes it through an argv-list subprocess
with an internal execution marker, preserving signal normalization and avoiding
shell interpolation. The marked backend rejects every command outside the
maintenance allowlist, so manually setting the marker cannot restore the old
Bash runtime-status contract.

Top-level runtime truth never crosses this boundary. `status`, `doctor`, version
and every unknown/non-maintenance alias command go directly to the canonical
Python parser.
