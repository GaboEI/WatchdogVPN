# WatchdogVPN v2.0.0 Roadmap

## Summary

WatchdogVPN v2.0.0 is the stable Linux CLI + TUI line. Its purpose is to turn
the project into a reusable resilience layer for VPN/proxy connections on
Linux, centered on the v2 daemon, profile/provider stores, sing-box,
AmneziaWG, OpenVPN+Cloak, DNS v2 and rules.

The v3.0.0 line is future-facing and reserved for a GUI expansion across additional platforms after v2 is stable.

## v2.0.0 Direction

- Preserve the watchdog core and the real-state verification model.
- Add the new profile, provider, parser and driver structure in small validated steps.
- Keep CLI and TUI the primary user surfaces.
- Treat kill switch, DNS, rules, rotation and recovery as first-class product areas.
- Keep docs, tests and runtime behavior aligned before expanding scope.

## v2.0.0 Scope Boundaries

- Linux only.
- CLI + TUI only.
- No mobile or desktop GUI rewrite in this version line.
- No silent behavior changes that can surprise existing users.

## v3.0.0 Direction

- Future GUI product on top of the v2 core.
- Multiplatform target: Linux, Windows, macOS, iOS and Android.
- Built after v2.0.0 is stable and operationally proven.
- Opens the door to broader collaboration after the Linux stable line is complete.

## Working Rules

- Finish one phase before starting the next.
- Keep each phase small enough to validate independently.
- Do not let roadmap work imply runtime features that are not yet implemented.
- Preserve compatibility where possible, but prefer the v2 architecture direction.

## Recent v2 Phase Status

The root roadmap tracks current public direction. Detailed task sequencing lives
in the local v2 master plan, but these completed phase markers keep the public
repo narrative aligned with the current codebase:

- Phase 5.5 - Manual-off runtime state: completed.
- Phase 7 - Rotation/recovery state handling: completed.
- Phase 8 - Driver and process hardening: completed.
- Phase 9 - Profile/provider/parser foundation: completed.
- Phase 9.5 - guided third-party DNS integration removal: completed.
- Phase 10 - DNS v2 system: completed and wired into live sing-box connect paths.
- Pre-Phase 11 QA audits for Layers 1, 4 and 5: completed with no open HIGH or
  MEDIUM debt.

## Reference Docs

- [Architecture](docs/architecture.md)
- [CLI](docs/cli.md)
- [Configuration](docs/configuration.md)
- [Product Roadmap](docs/product-roadmap.md)
- [Post-Alpha Roadmap](docs/roadmap-post-alpha.md)
