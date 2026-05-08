# WatchdogVPN

WatchdogVPN is a terminal-first resilience layer for AdGuard VPN CLI on Linux. It provides a TUI, real-state checks, automatic recovery, location rotation, domain exclusions, DNS tooling, log housekeeping and traceable events around an AdGuard VPN installation.

It is built for the real case where a VPN connection is not perfect: endpoints degrade, routes change, DNS can fail and the provider CLI may say one thing while the real network state says another. WatchdogVPN assumes the connection will eventually fail, then focuses on detecting that failure and recovering without forcing the user to live inside a terminal.

## Status

WatchdogVPN is an installable private Linux product candidate. Current supported targets:

- Ubuntu
- Debian
- Arch Linux

Fedora and other distributions are future targets, but the project is designed as one multi-distro codebase rather than separate repositories per distro.

The repository should remain private until the 1.0 release decision is made.

## Philosophy

WatchdogVPN is not designed around the fantasy that a VPN is always fast, stable or honest about its own state. It is designed around a harsher assumption: in unstable networks, censored environments or hostile information conditions, the connection will eventually break.

The goal is resilience for people who cannot afford to stop working because the tunnel silently died: journalists, researchers, developers, students, remote workers and users living under network censorship or unreliable routing. The product does not promise the fastest possible VPN. It tries to keep the connection observable, recoverable and boring in the best sense: when something fails, the system should detect it, repair it when possible and keep the user informed only when attention is needed.

The first backend is AdGuard VPN CLI. The architecture is intentionally shaped so future backends, including WireGuard-based private tunnels, can reuse the same operating model: truth check, watchdog, rotation/recovery policy, DNS safety, logs and a clear TUI.

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

## Supported Systems

Initial support:

| Distribution | Status |
| --- | --- |
| Ubuntu | Target |
| Debian | Target |
| Arch Linux | Target |
| Fedora | Future |

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
git clone git@github.com:GaboEI/WatchdogVPN.git
cd WatchdogVPN
./doctor.sh
./install.sh
VPN
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

## Repository Layout

```text
bin/                User-facing helper commands
sbin/               Privileged runtime scripts
tui/                Terminal UI
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
tests/              Syntax and runtime validation helpers
```

## Key Design Decisions

- **Real-state validation:** the project checks tunnel, route and public IP state instead of relying only on `adguardvpn-cli status`.
- **Fail-safe recovery:** the watchdog distinguishes normal failures, unknown IP states and expired authentication.
- **One runtime, distro adapters:** Ubuntu, Debian and Arch use the same runtime. Only installation and package checks differ.
- **Optional advanced DNS:** AdGuard Home is useful but not mandatory and is protected by preflight, backup and rollback.
- **No duplicate repos by distro:** multi-distro support stays in one repository to avoid divergent behavior.
- **Traceable logs:** operational events are written in a parseable format for future diagnostics.
- **User-owned exclusions:** new installations start without personal bypass domains. Each user chooses which domains should leave through the normal network route.

## Validation

Current validation commands:

```sh
python3 -m py_compile tui/VPN
bash tests/syntax.sh
./doctor.sh
```

Some system validations require root or an installed system target, for example:

```sh
sudo logrotate -d etc/logrotate.d/myvpn
systemd-analyze verify systemd/*.service systemd/*.timer
```

## Documentation

- [Architecture](docs/architecture.md)
- [Problem Context](docs/problem-context.md)
- [Validation](docs/validation.md)
- [Roadmap](docs/roadmap.md)
- [Install Contracts](docs/install-contracts.md)

## Roadmap

- Polish the event history view in the TUI.
- Add a first-class `watchdogvpn`/brand command while keeping `VPN` as a compatibility launcher.
- Continue clean-install testing across Ubuntu, Debian and Arch Linux.
- Evaluate Fedora support after the 1.0 baseline is stable.
- Prepare future backend support beyond AdGuard VPN CLI.

## License

No license has been selected yet. While the repository remains private, all rights are reserved by default. A public license will be chosen before any public release.

## Safety Rule

The installer must preserve existing user configuration unless the user explicitly approves a change.

This project is intended as a practical resilience and operations tool for legitimate access, study, development and day-to-day connectivity.
