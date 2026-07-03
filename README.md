<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/branding/logo-horizontal-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/branding/logo-horizontal-light.png">
    <img alt="WatchdogVPN" src="docs/assets/branding/logo-horizontal-light.png" width="480">
  </picture>
</p>

[![CI](https://github.com/GaboEI/WatchdogVPN/actions/workflows/ci.yml/badge.svg)](https://github.com/GaboEI/WatchdogVPN/actions/workflows/ci.yml)

- **Status:** `v2.0.0` planning line
- **License:** GPL-3.0-or-later. See [LICENSE](LICENSE).
- **Primary direction:** Linux VPN/proxy resilience layer

WatchdogVPN is a terminal-first resilience layer for VPN and proxy connections on Linux. It focuses on real-state verification, automatic recovery, safe rotation, optional kill switch handling, DNS control, routing rules, profile management and traceable diagnostics.

The product assumes network connections fail in the real world: endpoints degrade, routes change, DNS breaks, providers misreport state and users sometimes need to stop automation on purpose. WatchdogVPN is built to observe that state, respect user decisions and recover when recovery is safe.

![WatchdogVPN dashboard](docs/assets/tui-dashboard.png)

## Quick Links

| Need | Start Here |
| --- | --- |
| See the interface | [Demo and screenshots](docs/demo.md) |
| Understand the design | [Architecture](docs/architecture.md) |
| Review the current roadmap | [Roadmap](ROADMAP.md) |
| See project history | [Project History](docs/project-history.md) |
| Review security tradeoffs | [Security](docs/security.md) and [Threat Model](docs/threat-model.md) |
| Report an issue safely | [Reporting Issues](docs/reporting.md) and [Security Policy](SECURITY.md) |
| Validate a machine | [Validation](docs/validation.md) |
| Use the CLI | [CLI](docs/cli.md) |
| Understand configuration | [Configuration](docs/configuration.md) |
| Review release status | [Current release notes](docs/release-notes-v0.3.1.md) |
| Prepare a release | [Release Checklist](docs/release-checklist.md) |

## Core Capabilities

| Capability | What It Solves |
| --- | --- |
| Truth check | Verifies tunnel, route and public IP instead of trusting CLI text alone |
| Watchdog | Detects real VPN failures and triggers recovery when needed |
| Rotation | Changes connection targets on a controlled schedule with validation |
| Profiles | Supports manual imports and subscription-backed profile sources |
| Providers | Keeps profile sources manageable and capped where required |
| Exclusions | Routes selected domains outside the tunnel when required |
| DNS safety | Applies validated DNS profiles with backup and rollback behavior |
| Routing rules | Keeps traffic policy explicit and inspectable |
| Notifications | Emits user-facing and traceable events through `vpn_notify` |
| Housekeeping | Keeps operational logs bounded with logrotate and systemd timers |

## TUI Overview

WatchdogVPN includes a terminal control center designed for repeated operational use rather than one-off script execution.

| View | Purpose |
| --- | --- |
| Dashboard | Real connection state, session, tunnel, route, IP, DNS and timers |
| Locations | Select connection targets from measured candidates |
| Actions | Restart, disconnect, rotate now and run immediate health checks |
| DNS | Apply validated DNS profiles with rollback protection |
| Exclusions | Manage domains routed outside the VPN or proxy path |
| Timers | Adjust watchdog and rotation intervals without editing units by hand |
| Logs | Read recent operational logs and traceable events |
| Settings | Read and update safe persistent language and UI preferences |
| Update | Product update status, remote check and safe runtime update guidance |

More screenshots and command examples are available in [Demo](docs/demo.md).

## Status

WatchdogVPN is currently in the transition toward a stable `v2.0.0` line. The v2 direction is a Linux CLI + TUI product centered on resilience, profiles, routing and safe recovery.

Current support status:

| Distribution | Status |
| --- | --- |
| Ubuntu 24.04 | Tested on a real workstation |
| Arch Linux | Tested on a real workstation |
| Debian | Tested with a real install flow, including DNS tooling |
| CachyOS | Tested with a real install flow; initial settle may require reboot |
| Fedora | Future target |

The project is designed as one multi-distro codebase rather than separate repositories per distro.

## Philosophy

WatchdogVPN is not designed around the fantasy that a VPN or proxy is always fast, stable or honest about its own state. It is designed around a harsher assumption: in unstable networks, censored environments or hostile information conditions, the connection will eventually break.

The goal is resilience for people who cannot afford to stop working because the tunnel silently died: journalists, researchers, developers, students, remote workers and users living under network censorship or unreliable routing. The product does not promise the fastest possible connection. It tries to keep the connection observable, recoverable and boring in the best sense: when something fails, the system should detect it, repair it when possible and keep the user informed only when attention is needed.

The v2 product direction is not tied to any single vendor. It is centered on reusable connection handling, profile management and safe recovery across protocols and providers.

## What It Does

- Shows a terminal dashboard for connection state, tunnel, route, IP, DNS,
  backend and exclusions.
- Uses `vpn_truth_check` as the source of truth instead of trusting only provider text output.
- Detects tunnel, route, public IP and country state.
- Rotates connection targets safely with validation and anti-loop behavior.
- Runs a watchdog that can recover from real connection failures.
- Supports domain exclusion rules for selected domains that should not use the tunnel.
- Provides optional DNS management with backup and rollback behavior.
- Keeps logs under rotation with a dedicated logrotate policy.
- Emits traceable events through `vpn_notify`.
- Offers an optional desktop launcher.

## What It Does Not Do

- It does not replace the underlying VPN or proxy provider.
- It does not provide credentials or bypass licensing.
- It does not hide illegal activity or encourage misuse.
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
- A supported backend installed and available for the selected mode

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

- Install desktop launcher?

It does not ask internal technical defaults such as daemon internals, log
housekeeping or internal installation paths.

## Update

```sh
cd WatchdogVPN
git pull
./update.sh
```

The updater validates the repository, backs up managed files and preserves user
configuration, logs, shared runtime state and DNS configuration.

## Uninstall

Basic removal:

```sh
cd WatchdogVPN
./uninstall.sh
```

Full product purge:

```sh
cd WatchdogVPN
./uninstall.sh --purge-config --purge-logs --purge-state
```

This does not remove the user's underlying VPN/proxy provider state unless the selected backend contract explicitly says otherwise.

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
desktop/            Optional desktop launcher
docs/               Architecture, validation and operating notes
tests/              Syntax, unit behavior and runtime validation helpers
```

## Key Design Decisions

- **Real-state validation:** the project checks tunnel, route and public IP state instead of relying only on provider status text.
- **Fail-safe recovery:** the watchdog distinguishes normal failures, unknown IP states and authentication problems.
- **One runtime, distro adapters:** Ubuntu, Debian and Arch use the same runtime. Only installation and package checks differ.
- **DNS v2 ownership:** DNS management is handled by the WatchdogVPN v2 DNS
  system; the removed guided third-party DNS integration is not part of the
  current product.
- **No duplicate repos by distro:** multi-distro support stays in one repository to avoid divergent behavior.
- **Traceable logs:** operational events are written in a parseable format for future diagnostics.
- **User-owned exclusions:** new installations start without personal bypass domains. Each user chooses which domains should leave through the normal network route.

## Known Limitations

- `v0.3.1` is the last documented alpha-line release.
- The current TUI is functional and the gradual module split has started, but most rendering/action flow still lives in `tui/VPN`.
- Python TUI command helpers avoid subprocess shell mode; legacy shell pipelines run through explicit Bash argv wrappers.

## Validation

Development test dependencies are installed in a local virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Current validation commands:

```sh
pytest tests
python -m pytest tests
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
- [Roadmap](ROADMAP.md)
- [Product Roadmap](docs/product-roadmap.md)
- [Post-Alpha Roadmap](docs/roadmap-post-alpha.md)
- [Roadmap v1.1.0](docs/roadmap-v1.1.0.md)
- [Install Contracts](docs/install-contracts.md)

## Security

WatchdogVPN is system tooling that can modify VPN services, DNS configuration, NetworkManager hooks and systemd units. Review [Security](docs/security.md) and [Threat Model](docs/threat-model.md) before running it on a sensitive machine.

## Roadmap

- Complete the v2.0.0 CLI and TUI stable line.
- Expand profile, provider, parser and driver coverage in controlled phases.
- Harden the runtime and tests before any v3 GUI work.
- Treat multiplatform GUI work as a future v3.0.0 direction, not the next immediate step.

## License

WatchdogVPN is licensed under GPL-3.0-or-later. You may use, study, modify and redistribute it under the terms of the GNU General Public License version 3 or any later version. See [LICENSE](LICENSE).

## Safety Rule

The installer must preserve existing user configuration unless the user explicitly approves a change.

This project is intended as a practical resilience and operations tool for legitimate access, study, development and day-to-day connectivity.
