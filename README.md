<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/branding/logo-horizontal-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/branding/logo-horizontal-light.png">
    <img alt="WatchdogVPN" src="docs/assets/branding/logo-horizontal-light.png" width="480">
  </picture>
</p>

[![CI](https://github.com/GaboEI/WatchdogVPN/actions/workflows/ci.yml/badge.svg)](https://github.com/GaboEI/WatchdogVPN/actions/workflows/ci.yml)

- **Status:** v2.0.0 in active development (product line target; not a released
  tag). The installed CLI reports its own version via `watchdog version`
  (currently `v0.3.1`).
- **Platform:** Linux — certified on 14 distributions (see [Supported Platforms](#supported-platforms))
- **Interface:** CLI first, TUI second
- **License:** GPL-3.0-or-later. See [LICENSE](LICENSE).

WatchdogVPN is a local network control plane for resilient VPN/proxy routing on
Linux. It does not try to be a generic "connect button"; it manages privileged
network behavior such as routing policy, DNS policy, kill-switch state,
split-tunnel decisions, profile recovery and operator diagnostics from a
CLI-first architecture.

The project is built for networks where ordinary assumptions are not enough:
routes change, DNS fails, providers misreport state, endpoints degrade, DPI can
interfere with protocols, and a silent tunnel failure can put the user at risk.

![WatchdogVPN dashboard](docs/assets/tui-dashboard.png)

## Why It Exists

Most VPN tools focus on starting a tunnel. WatchdogVPN focuses on the harder
operational question: **what is the machine really doing with traffic, DNS and
routes, and what should happen when protection degrades?**

WatchdogVPN is designed for users who need observable, recoverable connectivity
under unstable or censored network conditions: journalists, researchers,
developers, students, remote workers and people operating in restrictive
networks. It does not promise anonymity or magic bypass. It gives the operator
clear state, safer recovery paths and auditable decisions.

## Current v2 Foundation

The v2 line is being rebuilt in stages. The current repository already contains
the core foundation:

| Area | Current State |
| --- | --- |
| Daemon/runtime | daemon-backed runtime path with IPC and systemd integration |
| Profiles/providers | manual imports, subscription-backed providers and persistent stores |
| Protocol drivers | sing-box, AmneziaWG, OpenVPN and OpenVPN+Cloak driver paths |
| Rotation/recovery | controlled rotation, cooldowns, known-good handling and failure categories |
| Kill switch | nftables/iptables fail-closed model with DNS leak ordering |
| DNS v2 | DNS policy model, resolver control, TUN hijack, FakeIP, ECS, static IP mappings and rollback |
| Routing rules | persistent rule groups, rule engine and sing-box route generation |
| Split tunnel / app policy | `watchdog split-tunnel` CLI surface shipped; `watchdog app-policy` remains the compatibility alias |
| Installer/update | non-destructive install/update contracts with backup and safety checks |
| Hardening | strict input handling and fail-closed defaults across the runtime |

## Active Roadmap Before v2.0.0

These rows are remaining work before a frozen v2.0.0 operator surface. Several
areas already have a CLI; the roadmap below is about hardening, product freeze
and TUI—not claiming those commands are absent.

| Track | Goal |
| --- | --- |
| Split-tunnel / app-policy hardening | refine matchers, enforcement guarantees and operator UX beyond the shipped CLI |
| Policy diagnostics hardening | deepen `watchdog rules explain` / DNS diagnose confidence and runtime-backed cases |
| Node groups / auto-selection hardening | improve health-aware selection on top of the existing `watchdog node-group` CLI |
| DNS/network hardening | refine DNS diagnostics, time checks and LAN-service decisions |
| Privacy-preserving observability | aggregate stats without silently logging sensitive browsing history |
| Backup/restore/sync hardening | strengthen versioned backups, restore rollback and remote-sync threat review beyond the shipped ZIP CLI |
| Routing/capture architecture | align Rule/Global, Proxy/TUN/LAN and route actions before final CLI freeze |
| LAN sharing / gateway mode | branch-gated LAN proxy and gateway capability for network operators |
| Network context automation and diagnostics | network-aware activation plus unified diagnostics before final CLI freeze |
| CLI freeze | freeze the operator surface after remaining capabilities settle |
| CLI hardening | complete the operator surface before final TUI work |
| TUI premium experience | final v2 TUI over proven behavior |

Detailed sequencing lives in the local master plan used by the maintainer. The
public roadmap summary is in [ROADMAP.md](ROADMAP.md).

## Development Reproducibility

The canonical interpreter for regenerating committed CLI inventory snapshots is
Python 3.14.6, recorded in [`.python-version`](.python-version). The inventory
derives public cardinality and mutually exclusive-group semantics itself, so
supported Python releases do not depend on `argparse`'s private formatting or
requiredness internals.

Automatic remote backup sync remains deferred. The supported portable workflow
is explicit ZIP export/import, preferably encrypted before moving the archive
off the local machine.

Before the CLI is frozen, WatchdogVPN will align its routing model so
Rule/Global are routing policies, Proxy/TUN/LAN are capture or entry
mechanisms, and Direct/Current/Block/Group are route actions. After that,
WatchdogVPN includes a carefully gated LAN sharing track for network operators:
authenticated LAN proxy sharing and full gateway/router mode for devices that
intentionally use the WatchdogVPN host as their protected path. This remains
disabled by default and requires explicit bind/firewall controls, kill-switch
coverage, DNS honesty and clean teardown.

Before the CLI is frozen, WatchdogVPN will also add network-context
automation and unified diagnostics. That track is expected to cover
trusted/untrusted network policy, interface/default-route changes, safe
autoconnect behavior, provider update metadata and redacted support exports.
Automatic behavior must be explainable and reversible, and diagnostics must not
silently become browsing history or a secret dump.

## Protocol Support

WatchdogVPN separates **resilient profile families** from **standard
compatibility profiles**. This distinction matters: supporting a protocol does
not automatically mean it is appropriate for hostile DPI environments.

| Category | Protocol Families |
| --- | --- |
| Resilient / anti-DPI oriented | VLESS+Reality, Trojan TLS/uTLS, Hysteria2, AmneziaWG, OpenVPN+Cloak/OverCloud |
| Compatibility | plain WireGuard, VMess, standard Shadowsocks, SOCKS, HTTP, normal OpenVPN |
| Conditional | TUIC and Shadowsocks may be treated as resilient only when configured appropriately for restrictive networks |

Compatibility profiles are useful, but WatchdogVPN should not describe them as
censorship-resistant unless the concrete configuration is appropriate for them.

## Core Concepts

### Real-State Truth

Provider status text is not treated as truth. WatchdogVPN checks observable
state such as tunnel interface, route, DNS behavior and public IP where
appropriate.

### Recovery With User Intent

The runtime distinguishes automatic recovery from a user-requested manual stop.
If the user deliberately turns the VPN off, automation must not immediately
fight that decision.

### DNS Safety

DNS v2 is part of the product, not an afterthought. WatchdogVPN can model DNS
channels, apply local resolver state with rollback, hijack application DNS into
the tunnel path and avoid LAN resolver leaks when the kill switch is active.

### Explicit Traffic Policy

Routing rules make traffic decisions inspectable. The current CLI exposes rule
explanations, Linux app/process policy and node-group routing; the remaining v2
work hardens those flows before the operator surface is frozen.

### Non-Destructive Operations

Install, update, uninstall and restore flows must preserve user configuration
unless the user explicitly approves destructive behavior.

## Supported Platforms

WatchdogVPN runs on Linux. The table below lists the currently supported
releases, each with its release model, support state and protocol coverage.

<!-- BEGIN GENERATED: compat-support-table -->
| Distribution | Release | Model | Support | Certification | Freshness | Protocols |
| --- | --- | --- | --- | --- | --- | --- |
| AlmaLinux | AlmaLinux 9 | stable | certified | 2026-09-02 | — | All 12 in-scope protocols |
| Arch Linux | Arch Linux | rolling | certified | 2026-08-15 | current (365 days) | All 12 in-scope protocols |
| CachyOS | CachyOS | rolling | certified | 2026-08-16 | current (365 days) | All 12 in-scope protocols |
| CentOS Stream | CentOS Stream | rolling | certified | 2026-09-20 | current (365 days) | All 12 in-scope protocols |
| Debian | Debian 13.6 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Fedora | Fedora 44 | stable | certified | 2026-08-19 | — | All 12 in-scope protocols |
| Kali GNU/Linux | Kali GNU/Linux | rolling | certified | 2026-09-14 | current (365 days) | All 12 in-scope protocols |
| Linux Mint | Linux Mint 22.3 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Manjaro | Manjaro | rolling | certified | 2026-09-18 | current (365 days) | All 12 in-scope protocols |
| Pop!_OS | Pop!_OS 24.04 | stable | certified | 2026-09-16 | — | All 12 in-scope protocols |
| Red Hat Enterprise Linux | Red Hat Enterprise Linux 9 | stable | family_inferred | — | — | — |
| Rocky Linux | Rocky Linux 9 | stable | certified | 2026-08-20 | — | All 12 in-scope protocols |
| Ubuntu | Ubuntu 24.04.4 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Ubuntu | Ubuntu 26.04 | stable | experimental | — | — | — |
| openSUSE Leap | openSUSE Leap 15.6 | stable | certified | 2026-09-08 | — | All 12 in-scope protocols |
| openSUSE Tumbleweed | openSUSE Tumbleweed | rolling | certified | 2026-09-10 | current (365 days) | All 12 in-scope protocols |

<!-- END GENERATED: compat-support-table -->

`certified` means the exact release is fully supported across installation, the
in-scope protocols and the full lifecycle. `family_inferred` and
`experimental` releases share a packaging family with a certified release but
are **not certified on their own**: they are compatible but are not claimed as
certified and may need preparation on a specific machine. A release
is never certified through another distribution.

<!-- BEGIN GENERATED: compat-protocol-list -->
The following protocol families are in scope for certified releases:

- AmneziaWG
- HTTP proxy
- Hysteria2
- OpenVPN
- OpenVPN + Cloak/OverCloud
- Shadowsocks
- SOCKS
- Trojan
- TUIC
- VLESS
- VMess
- WireGuard

This list applies to certified releases only. A `family_inferred` or
`experimental` release does not imply full protocol coverage, and every
certified release is supported exactly as its own row states.

<!-- END GENERATED: compat-protocol-list -->

**Red Hat Enterprise Linux is not certified.** RHEL has its own release model
and is never certified through CentOS Stream. Other Debian/Ubuntu derivatives
beyond Linux Mint and Pop!_OS are likewise not individually certified.

## Installation

WatchdogVPN is currently Linux-focused. Run it from a checkout:

```sh
git clone https://github.com/GaboEI/WatchdogVPN.git
cd WatchdogVPN
./doctor.sh
./install.sh
```

Launch the current TUI:

```sh
VPN
```

Run the product CLI:

```sh
watchdog --help
```

Common starting points:

```sh
watchdog status
watchdog profile list
watchdog provider list
watchdog dns status
watchdog split-tunnel status
watchdog panic status
watchdog maintenance --help
```

Full operator docs: [CLI](docs/cli.md). Exhaustive public routes:
[command inventory](docs/generated/cli-command-inventory.md).

`watchdog` is the canonical CLI. The installed `watchdogvpn` command is a
deprecated compatibility alias that forwards to the same parser and writes a
migration warning to stderr. Local report, log, update and current-TUI helpers
are available under `watchdog maintenance --help`.

`doctor.sh` is read-only. It checks whether the machine has the expected
dependencies, runtime state and time/NTP health. It reports clock skew as a
connectivity risk; it does not change system time.

## Updating

```sh
cd WatchdogVPN
git pull
./update.sh
```

The updater checks the checkout, backs up managed files and preserves user
configuration, logs, shared runtime state and DNS configuration. If the daemon
was already active, the updater restarts it after replacing the runtime and
requires the new process generation to be serving before it completes.

## Uninstalling

```sh
cd WatchdogVPN
./uninstall.sh
```

Guided uninstall choices are available through the Python CLI:

```sh
cd WatchdogVPN
watchdog uninstall --keep-data --yes
watchdog uninstall --backup-first --backup-output ~/watchdogvpn-backup.zip --yes
watchdog uninstall --delete-all-data --confirm-delete DELETE --backup-output ~/watchdogvpn-pre-delete.zip --yes
```

Full product purge:

```sh
cd WatchdogVPN
./uninstall.sh --purge-config --purge-logs --purge-state --confirm-delete DELETE
```

Uninstall does not remove user-owned VPN/proxy provider software, private keys,
profiles or account state unless an explicit future contract says otherwise.
A full purge also removes the internal `watchdogvpn` system account/group and
the installing user's membership in it, plus WatchdogVPN's internal recovery
backups under `/var/backups/watchdogvpn`; it does not create new internal
copies while deleting data. A plain uninstall preserves all of them. The CLI
`--delete-all-data` flow first exports the user's explicit backup outside
product-owned paths, so an encrypted export is not undermined by a second
silent unencrypted copy. The full purge also removes the invoking
user's preserved legacy migration source at `~/.config/watchdogvpn` and the
fixed historical root copy; it never scans or deletes unrelated users' homes.
Every uninstall removes the product's ephemeral
`/run/watchdogvpn` directory even if an interrupted install already rolled the
systemd unit back; the shared `/run/amneziawg` path is removed only when empty.

## For Providers

WatchdogVPN is provider-agnostic. It can accept compatible subscription/profile
formats without depending on or endorsing any specific provider.

Local subscription and node management uses `watchdog provider --help`. See
[CLI — Profiles And Providers](docs/cli.md#profiles-and-providers) for the
operator commands. Provider collaboration is welcome when it improves
interoperability. See [Provider Collaboration](docs/providers.md) for accepted
formats, expectations and submission guidance.

## For Contributors

Useful contributions include:

- protocol/profile parser fixtures;
- distro compatibility reports;
- documentation corrections;
- installer, DNS, routing, daemon and recovery improvements;
- carefully scoped bug reports with sanitized logs.

Before opening an issue, read [Reporting Issues](docs/reporting.md) and
[Security Policy](SECURITY.md), especially if logs may reveal network or account
details.

## Repository Layout

```text
bin/        User-facing helper commands
cli/        Python CLI surface for v2 functionality
config/     Persistent stores and application config
core/       Runtime orchestration
daemon/     daemon IPC and worker entrypoints
dns/        DNS v2 policy and apply/restore logic
drivers/    Protocol/runtime drivers
models/     Shared data models
providers/  Manual and subscription provider imports
rotation/   Health checks, rotation and recovery
rules/      Routing rule models, parser and sing-box generation
systemd/    Services and timers
tui/        Terminal UI
docs/       Architecture, security and release docs
tests/      Automated behavior and syntax checks
```

## Health Check

The product health check is read-only and reports the current system state
without modifying it:

```sh
./doctor.sh
```

## Documentation

- [Architecture](docs/architecture.md)
- [CLI](docs/cli.md)
- [Configuration](docs/configuration.md)
- [DNS CLI](docs/dns-cli.md)
- [Security](docs/security.md)
- [Threat Model](docs/threat-model.md)
- [Validation](docs/validation.md)
- [Demo](docs/demo.md)
- [Provider Collaboration](docs/providers.md)
- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)

## Safety Rule

WatchdogVPN must preserve existing user configuration unless the user
explicitly approves a change. Features that touch DNS, routing, daemon state,
privileged files or installed runtime paths must be reversible and must never
silently change user-owned state.

## License

WatchdogVPN is licensed under GPL-3.0-or-later. You may use, study, modify and
redistribute it under the terms of the GNU General Public License version 3 or
any later version.
