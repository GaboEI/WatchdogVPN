# WatchdogVPN

WatchdogVPN is a terminal-first operations layer for AdGuard VPN CLI on Linux. It provides a TUI, real-state checks, automatic recovery, location rotation, domain bypass, DNS tooling, log housekeeping and traceable events around an existing AdGuard VPN installation.

The project was built from a real operational need: keeping a VPN connection observable and recoverable in unstable network conditions where endpoints may degrade, routes may change and the CLI status alone is not enough to know whether traffic is really protected.

## Status

This repository is in the product-packaging phase.

The runtime already exists and is being migrated into a clean, reproducible repository structure. The current public target is an installable Linux tool for:

- Ubuntu
- Debian
- Arch Linux

Fedora support is planned for a future release.

The repository should remain private until the 1.0 milestone is complete: installer, updater, uninstaller and clean-install testing.

## What It Does

- Shows a professional terminal dashboard for VPN state, session, tunnel, route, IP, DNS, timers and bypass.
- Uses `vpn_truth_check` as the source of truth instead of trusting only CLI text output.
- Detects tunnel, route, public IP and country state.
- Rotates VPN locations safely with validation and anti-loop behavior.
- Runs a watchdog that can recover from real VPN failures.
- Detects expired or invalid AdGuard VPN sessions.
- Supports domain bypass rules for selected domains that should not use the VPN route.
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

Required base components:

- `systemd`
- `NetworkManager`
- `bash`
- `python3`
- `curl`
- `iproute2`
- `sudo`
- `logrotate`
- AdGuard VPN CLI installed and logged in

## Planned Install Flow

```sh
git clone <repo-url>
cd WatchdogVPN
./doctor.sh
./install.sh
VPN
```

`doctor.sh` is read-only. It checks whether the machine is ready.

`install.sh` is intentionally guided but conservative. It asks only product-level choices:

- Enable advanced DNS with AdGuard Home?
- Install desktop launcher?
- Install Conky integration?

It does not ask internal technical defaults such as watchdog interval, rotation interval, log housekeeping or internal installation paths. Those defaults are part of the product and can be adjusted later from the TUI.

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
docs/               Architecture, validation and roadmap
tests/              Syntax and runtime validation helpers
```

## Key Design Decisions

- **Real-state validation:** the project checks tunnel, route and public IP state instead of relying only on `adguardvpn-cli status`.
- **Fail-safe recovery:** the watchdog distinguishes normal failures, unknown IP states and expired authentication.
- **One runtime, distro adapters:** Ubuntu, Debian and Arch use the same runtime. Only installation and package checks differ.
- **Optional advanced DNS:** AdGuard Home is useful but not mandatory.
- **No duplicate repos by distro:** multi-distro support stays in one repository to avoid divergent behavior.
- **Traceable logs:** operational events are written in a parseable format for future diagnostics.

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

## Current Roadmap

1. Complete professional repository packaging.
2. Finish `doctor.sh` as a read-only preflight.
3. Implement `install.sh` for Ubuntu, Debian and Arch Linux.
4. Implement safe `update.sh`.
5. Implement careful `uninstall.sh`.
6. Test installation on a clean Ubuntu/Debian system.
7. Test installation on Arch Linux.
8. Polish event history view in the TUI.

## License

No license has been selected yet. While the repository remains private, all rights are reserved by default. A public license will be chosen before any public release.

## Safety Rule

The installer must preserve existing user configuration unless the user explicitly approves a change.

This project is intended as a practical resilience and operations tool for legitimate access, study, development and day-to-day connectivity.
