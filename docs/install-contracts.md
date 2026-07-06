# Installation Contracts

This document defines how the product scripts should behave.

## Principles

- One repository supports Ubuntu, Debian and Arch Linux.
- Fedora is future scope.
- Runtime behavior should be shared across distros.
- Distro differences belong in `distros/` and installer helpers.
- The installer should not ask internal technical questions.
- Existing user configuration must not be overwritten without backup.
- The installer configures WatchdogVPN's own runtime and does not depend on a
  third-party commercial VPN CLI.

## User-Facing Questions

`install.sh` may ask:

- Install desktop launcher?
- Configure the Custom VPS backend metadata when needed.

`install.sh` should not ask:

- initial rotation interval
- initial watchdog interval
- whether log housekeeping is enabled
- whether base domain bypass support is prepared
- internal install paths
- Custom VPS passwords, private keys, tokens or certificate pins

Those are product defaults and can be adjusted later from the TUI.

## doctor.sh

Role: read-only preflight and diagnostics.

It must not install, remove or modify files.
It must not change system time or NTP settings; wrong time is reported as a
protocol-connectivity risk with actionable guidance.

It should check:

- Linux with systemd
- supported distro
- NetworkManager
- sudo
- bash
- python3
- curl
- iproute2
- awk/sed/coreutils
- logrotate
- WatchdogVPN daemon user, unit, IPC socket and installed runtime
- system time/NTP sync state and severe clock skew risk
- basic DNS
- previous installation state
- optional desktop launcher

Result levels:

- `OK`: does not block
- `WARN`: installation can continue, but the user should know
- `FAIL`: installation should stop

## install.sh

Role: install a new system or complete a partial installation.

Expected flow:

1. Run preflight checks.
2. Explain that the product installs the WatchdogVPN runtime and can configure
   the custom-vps service-control path.
3. Detect distro and load its adapter.
4. Validate dependencies.
5. Ask product-level options.
6. Show an installation plan with target paths, options and backup location.
7. Back up files that would be replaced.
8. Validate scripts and TUI.
9. Install runtime files.
10. Validate systemd and logrotate.
11. Enable services and timers.
12. Run final checks.
13. Tell the user to open `VPN`.

## update.sh

Role: update an existing installation without reinstalling from zero.

It must preserve:

- `/etc/vpn-domain-bypass.conf`
- `/var/lib/watchdogvpn/`
- logs

It should replace only product-managed runtime files after validation and backup.
It should show a preservation contract and update plan before replacing files.

## uninstall.sh

Role: remove WatchdogVPN without deleting user-owned VPN/proxy software or
account state.

It should remove:

- product scripts
- TUI
- product systemd units
- product NetworkManager dispatcher
- product logrotate config
- optional desktop launcher installed by the product

It must ask before deleting:

- `/etc/vpn-domain-bypass.conf`
- `/var/log/myvpn/`
- `/var/lib/watchdogvpn/`

It must not remove:

- user-owned provider software, profiles, private keys or account state
- unrelated user files

It should show a removal plan before disabling units or removing files.
