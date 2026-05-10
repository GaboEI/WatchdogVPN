# Installation Contracts

This document defines how the product scripts should behave.

## Principles

- One repository supports Ubuntu, Debian and Arch Linux.
- Fedora is future scope.
- Runtime behavior should be shared across distros.
- Distro differences belong in `distros/` and installer helpers.
- The installer should not ask internal technical questions.
- Existing user configuration must not be overwritten without backup.
- AdGuard VPN CLI is required and is not replaced by this project.

## User-Facing Questions

`install.sh` may ask:

- Enable advanced DNS with AdGuard Home?
- Install desktop launcher?
- Install Conky integration?

`install.sh` should not ask:

- initial rotation interval
- initial watchdog interval
- whether log housekeeping is enabled
- whether base domain bypass support is prepared
- internal install paths

Those are product defaults and can be adjusted later from the TUI.

## doctor.sh

Role: read-only preflight and diagnostics.

It must not install, remove or modify files.

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
- AdGuard VPN CLI
- AdGuard VPN session/auth state
- basic DNS
- previous installation state
- optional AdGuard Home
- optional Conky
- optional desktop launcher

Result levels:

- `OK`: does not block
- `WARN`: installation can continue, but the user should know
- `FAIL`: installation should stop

## install.sh

Role: install a new system or complete a partial installation.

Expected flow:

1. Run preflight checks.
2. Explain that the product controls AdGuard VPN but does not replace it.
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

- `/etc/adguardvpn.env`
- `/etc/vpn-domain-bypass.conf`
- `/var/lib/vpn-rotate/`
- logs
- user AdGuard Home configuration
- user Conky configuration

It should replace only product-managed runtime files after validation and backup.
It should show a preservation contract and update plan before replacing files.

## uninstall.sh

Role: remove the product without breaking the official AdGuard VPN installation.

It should remove:

- product scripts
- TUI
- product systemd units
- product NetworkManager dispatcher
- product logrotate config
- optional desktop launcher installed by the product

It must ask before deleting:

- `/etc/adguardvpn.env`
- `/etc/vpn-domain-bypass.conf`
- `/var/log/myvpn/`
- `/var/lib/vpn-rotate/`
- AdGuard Home configuration
- Conky configuration

It must not remove:

- official AdGuard VPN CLI
- AdGuard account/license state
- unrelated user files

It should show a removal plan before disabling units or removing files.
