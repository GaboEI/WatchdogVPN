# WatchdogVPN

[![CI](https://github.com/GaboEI/WatchdogVPN/actions/workflows/ci.yml/badge.svg)](https://github.com/GaboEI/WatchdogVPN/actions/workflows/ci.yml)

- **Status:** `v0.3.1`
- **License:** GPL-3.0-or-later. See [LICENSE](LICENSE).
- **Primary backend:** AdGuard VPN CLI
- **Supported today:** Ubuntu 24.04, Debian and Arch Linux validation paths

WatchdogVPN is a terminal-first resilience layer for AdGuard VPN CLI on Linux. It turns a fragile command-line VPN setup into an observable control center with real-state checks, automatic recovery, location rotation, domain exclusions, DNS tooling, log housekeeping and traceable events.

It is built for the real case where a VPN connection is not perfect: endpoints degrade, routes change, DNS can fail and the provider CLI may say one thing while the real network state says another. WatchdogVPN assumes the connection will eventually fail, then focuses on detecting that failure and recovering without forcing the user to live inside a terminal.

![WatchdogVPN dashboard](docs/assets/tui-dashboard.png)

## Quick Links

| Need | Start Here |
| --- | --- |
| See the interface | [Demo and screenshots](docs/demo.md) |
| Install it | [Install](#install) |
| Understand the design | [Architecture](docs/architecture.md) |
| See how it evolved | [Project History](docs/project-history.md) |
| Review security tradeoffs | [Security](docs/security.md) and [Threat Model](docs/threat-model.md) |
| Report an issue safely | [Reporting Issues](docs/reporting.md) and [Security Policy](SECURITY.md) |
| Validate a machine | [Validation](docs/validation.md) |
| Use the CLI | [CLI](docs/cli.md) |
| Follow CLI planning | [CLI Plan v0.3.0](docs/cli-plan-v0.3.0.md) |
| Understand configuration | [Configuration](docs/configuration.md) |
| Prepare Custom VPS | [Custom VPS Backend](docs/custom-vps-backend.md) |
| Review release status | [v0.3.1 notes](docs/release-notes-v0.3.1.md) |
| Prepare a release | [Release Checklist](docs/release-checklist.md) |
| Configure GitHub About | [GitHub About](docs/github-about.md) |
| Check planned work | [Product Roadmap](docs/product-roadmap.md), [Roadmap](docs/roadmap.md) and [Post-Alpha Roadmap](docs/roadmap-post-alpha.md) |

## Core Capabilities

| Capability | What It Solves |
| --- | --- |
| Truth check | Verifies tunnel, route and public IP instead of trusting only CLI text |
| Watchdog | Detects real VPN failures and triggers recovery when needed |
| Rotation | Changes VPN location on a controlled schedule with validation |
| Locations | Lets the user select country/city candidates from the TUI |
| Exclusions | Routes selected domains outside the VPN tunnel when required |
| DNS safety | Applies optional AdGuard Home profiles with backup and rollback |
| Notifications | Emits user-facing and traceable events through `vpn_notify` |
| Housekeeping | Keeps operational logs bounded with logrotate/systemd timers |

## TUI Overview

WatchdogVPN includes a terminal control center designed for repeated operational
use rather than one-off script execution.

| View | Purpose |
| --- | --- |
| Dashboard | Real VPN state, session, tunnel, route, IP, DNS and timers |
| Locations | Select VPN country/city from measured candidates |
| Actions | Restart, disconnect, rotate now and run immediate health checks |
| DNS | Apply validated DNS profiles with rollback protection |
| Exclusions | Manage domains routed outside the VPN tunnel |
| Timers | Adjust watchdog and rotation intervals without editing units by hand |
| Logs | Read recent operational logs and traceable events |
| Settings | Read and update safe persistent language and TUI preferences |
| Update | Product update status, remote check and safe runtime update guidance |

More screenshots and command examples are available in [Demo](docs/demo.md).

## Status

WatchdogVPN is an installable Linux alpha release. It is useful for controlled
testing and portfolio review, but it is not a stable public 1.0 release yet.

Current support status:

| Distribution | Status |
| --- | --- |
| Ubuntu 24.04 | Tested on a real workstation |
| Arch Linux | Tested on a real workstation |
| Debian | Tested with a real install flow, including DNS tooling |
| CachyOS | Tested with a real install flow; initial VPN settle may require reboot |
| Fedora | Future target |

The project is designed as one multi-distro codebase rather than separate repositories per distro.

## Philosophy

WatchdogVPN is not designed around the fantasy that a VPN is always fast, stable or honest about its own state. It is designed around a harsher assumption: in unstable networks, censored environments or hostile information conditions, the connection will eventually break.

The goal is resilience for people who cannot afford to stop working because the tunnel silently died: journalists, researchers, developers, students, remote workers and users living under network censorship or unreliable routing. The product does not promise the fastest possible VPN. It tries to keep the connection observable, recoverable and boring in the best sense: when something fails, the system should detect it, repair it when possible and keep the user informed only when attention is needed.

The stable backend is currently AdGuard VPN CLI. The architecture also includes
an experimental Custom VPS backend that can control a user-configured local
systemd service, while reusing the same operating model: truth check, watchdog,
rotation/recovery policy where supported, DNS safety, logs and a clear TUI.

## What It Does

- Shows a professional terminal dashboard for VPN state, session, tunnel, route, IP, DNS, timers and exclusions.
- Uses `vpn_truth_check` as the source of truth instead of trusting only CLI text output.
- Detects tunnel, route, public IP and country state.
- Rotates VPN locations safely with validation and anti-loop behavior.
- Runs a watchdog that can recover from real VPN failures.
- Detects expired or invalid AdGuard VPN sessions.
- Supports domain exclusion rules for selected domains that should not use the VPN route.
- Provides optional DNS management through AdGuard Home.
- Keeps logs under rotation with a dedicated logrotate policy.
- Emits traceable events through `vpn_notify`.
- Offers optional Conky and desktop launcher integrations.

## What It Does Not Do

- It does not replace AdGuard VPN.
- It does not provide VPN credentials or bypass licensing.
- It does not hide illegal activity or encourage misuse.
- It does not install AdGuard Home unless the user explicitly chooses advanced DNS mode.
- It does not erase existing user configuration without confirmation.

## System Requirements

Required base components are checked by `doctor.sh` and the guided installer:

- `systemd`
- `NetworkManager`
- `bash`
- `python3`
- `curl`
- `iproute2`
- `sudo`
- `logrotate`
- AdGuard VPN CLI installed and logged in, or a system where the installer can guide the official CLI setup

## Install

```sh
git clone https://github.com/GaboEI/WatchdogVPN.git
cd WatchdogVPN
./doctor.sh
./install.sh
VPN
```

For an SSH checkout, use:

```sh
git clone git@github.com:GaboEI/WatchdogVPN.git
```

`doctor.sh` is read-only. It checks whether the machine is ready.

`install.sh` is guided but conservative. It asks only product-level choices:

- Enable advanced DNS with AdGuard Home?
- Install desktop launcher?
- Install Conky integration?

It does not ask internal technical defaults such as watchdog interval, rotation interval, log housekeeping or internal installation paths. Those defaults are part of the product and can be adjusted later from the TUI.

## Update

```sh
cd WatchdogVPN
git pull
./update.sh
```

The updater validates the repository, backs up managed files and preserves user configuration, logs, rotation state, DNS configuration and Conky files.

## Uninstall

Basic removal:

```sh
cd WatchdogVPN
./uninstall.sh
```

Full product purge, preserving the official AdGuard VPN CLI and account/license state:

```sh
cd WatchdogVPN
./uninstall.sh --purge-config --purge-logs --purge-state --purge-conky
```

This does not remove the official AdGuard VPN CLI or the user's AdGuard account/license state.

## Repository Layout

```text
bin/                User-facing helper commands
sbin/               Privileged runtime scripts
tui/                Terminal UI and support modules
systemd/            Services and timers
networkmanager/     NetworkManager dispatcher hooks
etc/                Product configuration templates
examples/           Safe example configs
lib/                Installer shared functions
distros/            Ubuntu/Debian/Arch adapters
conky/              Optional Conky integration
desktop/            Optional desktop launcher
adguard-home/       Optional DNS advanced integration
docs/               Architecture, validation and operating notes
tests/              Syntax, unit behavior and runtime validation helpers
```

## Key Design Decisions

- **Real-state validation:** the project checks tunnel, route and public IP state instead of relying only on `adguardvpn-cli status`.
- **Fail-safe recovery:** the watchdog distinguishes normal failures, unknown IP states and expired authentication.
- **One runtime, distro adapters:** Ubuntu, Debian and Arch use the same runtime. Only installation and package checks differ.
- **Optional advanced DNS:** AdGuard Home is useful but not mandatory and is protected by preflight, backup and rollback.
- **No duplicate repos by distro:** multi-distro support stays in one repository to avoid divergent behavior.
- **Traceable logs:** operational events are written in a parseable format for future diagnostics.
- **User-owned exclusions:** new installations start without personal bypass domains. Each user chooses which domains should leave through the normal network route.

## Known Limitations

- `v0.3.1` is not a stable 1.0 release.
- CachyOS is Arch-derived and uses the Arch adapter through `ID_LIKE=arch`
  detection. Real installation and DNS validation passed, with one observation:
  the initial VPN tunnel may need extra settle time or one reboot after install.
- The current TUI is functional and the gradual module split has started, but most rendering/action flow still lives in `tui/VPN`.
- Some Python TUI command helpers still use `shell=True`; this is tracked as security hardening work.
- The installer can guide installation of the official AdGuard VPN CLI, but external installer verification is not fully cryptographically pinned yet.
- The stable backend is AdGuard VPN CLI. Custom VPS/private tunnel support is
  experimental and requires user-provided local service configuration.

## Validation

Current validation commands:

```sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
bash tests/syntax.sh
bash tests/unit.sh
systemd-analyze verify systemd/*.service systemd/*.timer
./doctor.sh
```

Generate a local support report without uploading anything:

```sh
watchdogvpn report
```

GitHub Actions runs syntax checks and systemd unit verification automatically. `shellcheck` and `shfmt` are currently advisory checks while the shell code is being hardened.

Some local system validations require root or an installed system target, for example:

```sh
sudo logrotate -d etc/logrotate.d/myvpn
```

## Documentation

- [Architecture](docs/architecture.md)
- [Problem Context](docs/problem-context.md)
- [Project History](docs/project-history.md)
- [Security](docs/security.md)
- [Threat Model](docs/threat-model.md)
- [Reporting Issues](docs/reporting.md)
- [CLI](docs/cli.md)
- [Configuration](docs/configuration.md)
- [Runtime Update Contract](docs/runtime-update-contract.md)
- [Demo](docs/demo.md)
- [Validation](docs/validation.md)
- [v0.3.1 Release Notes](docs/release-notes-v0.3.1.md)
- [v0.3.0 Release Notes](docs/release-notes-v0.3.0.md)
- [v0.2.0 Release Notes](docs/release-notes-v0.2.0.md)
- [v0.1.1 Release Notes](docs/release-notes-v0.1.1.md)
- [v0.1.0-alpha Release Notes](docs/release-notes-v0.1.0-alpha.md)
- [Release Checklist](docs/release-checklist.md)
- [GitHub About](docs/github-about.md)
- [GitHub Planning](docs/github-planning.md)
- [Product Roadmap](docs/product-roadmap.md)
- [Roadmap](docs/roadmap.md)
- [Post-Alpha Roadmap](docs/roadmap-post-alpha.md)
- [Roadmap v1.1.0](docs/roadmap-v1.1.0.md)
- [Install Contracts](docs/install-contracts.md)

## Security

WatchdogVPN is system tooling that can modify VPN services, DNS configuration,
NetworkManager hooks and systemd units. Review [Security](docs/security.md) and
[Threat Model](docs/threat-model.md) before running it on a sensitive machine.

## Roadmap

- Polish the event history view in the TUI.
- Add a first-class `watchdogvpn`/brand command while keeping `VPN` as a compatibility launcher.
- Continue clean-install testing across Ubuntu, Debian and Arch Linux.
- Validate Arch-derived distributions such as CachyOS after adapter detection.
- Evaluate Fedora support after the 1.0 baseline is stable.
- Harden experimental backend support beyond AdGuard VPN CLI.

## License

WatchdogVPN is licensed under GPL-3.0-or-later. You may use, study, modify and
redistribute it under the terms of the GNU General Public License version 3 or
any later version. See [LICENSE](LICENSE).

## Safety Rule

The installer must preserve existing user configuration unless the user explicitly approves a change.

This project is intended as a practical resilience and operations tool for legitimate access, study, development and day-to-day connectivity.
