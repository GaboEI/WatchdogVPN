# Roadmap

This roadmap describes the path from the current packaged runtime to a reproducible multi-distro product.

## Current Phase

Repository packaging.

The working runtime has been imported into a clean structure. The next work is focused on making installation, update and removal reproducible on Ubuntu, Debian and Arch Linux.

The repository is being prepared for the first public alpha release.

## Milestone 1: Repository Baseline

- Clean repository layout.
- Runtime files imported without legacy helpers.
- Professional README.
- Architecture and validation docs.
- Syntax validation script.
- Read-only `doctor.sh` scaffold.

Acceptance criteria:

- No personal paths or credentials in runtime files.
- `python3 -m compileall -q tui tests/unit/test_tui_modules.py` passes.
- `bash tests/syntax.sh` passes.
- `./doctor.sh` runs without modifying the system.

## Milestone 2: Doctor

Complete `doctor.sh` as a read-only preflight tool.

It should validate:

- supported distro
- systemd
- NetworkManager
- required commands
- AdGuard VPN CLI presence
- AdGuard VPN auth/session state
- basic DNS
- previous installation state
- optional integrations

Acceptance criteria:

- reports `OK`, `WARN` and `FAIL` clearly
- does not install or modify anything
- works on Ubuntu, Debian and Arch Linux

## Milestone 3: Installer

Implement `install.sh`.

The installer should ask only product-level choices:

- advanced DNS with AdGuard Home
- desktop launcher
- Conky integration

It should configure safe defaults for:

- TUI
- rotation
- watchdog
- domain bypass
- log housekeeping
- traceable notifications
- systemd services and timers

Acceptance criteria:

- preserves existing user configuration
- backs up files before replacing them
- validates scripts, units and logrotate before activation
- finishes with `VPN` usable from the terminal

## Milestone 4: Update Path

Implement `update.sh`.

It should update the product without deleting:

- `/etc/adguardvpn.env`
- `/etc/vpn-domain-bypass.conf`
- `/var/lib/vpn-rotate/`
- logs
- user AdGuard Home configuration
- user Conky configuration

Acceptance criteria:

- validates before installing
- backs up replaced files
- reloads systemd only when needed
- restarts only affected services

## Milestone 5: Uninstall

Implement `uninstall.sh`.

It should remove product-managed files without removing the official AdGuard VPN CLI or user data by default.

Acceptance criteria:

- disables product timers
- removes product units/scripts/TUI
- asks before deleting configs, logs or state
- leaves systemd clean

## Milestone 6: Clean Install Testing

Test on:

- Ubuntu or Debian clean environment
- Arch Linux clean environment

Acceptance criteria:

- `./doctor.sh`
- `./install.sh`
- `VPN`
- `vpn_truth_check`
- `vpn_auth_check`
- watchdog timer active
- rotation timer active
- logrotate validates

## Future Work

- Fedora support.
- More complete automated tests.
- TUI event history polish.
- More advanced diagnostic summary.
- Optional packaging format after the shell installer is stable.
