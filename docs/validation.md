# Validation

This repository separates lightweight validation from system-level validation.

## Local Syntax Checks

These checks do not modify the system:

```sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
bash tests/syntax.sh
bash tests/unit.sh
./doctor.sh
```

## Public Clone Smoke Test

Last recorded public clone smoke test: 2026-05-15.

Commands:

```sh
git clone https://github.com/GaboEI/WatchdogVPN.git /tmp/watchdogvpn-public-test
cd /tmp/watchdogvpn-public-test
python3 -m compileall -q tui tests/unit/test_tui_modules.py
bash tests/syntax.sh
bash tests/unit.sh
./install.sh --dry-run --yes --skip-doctor
./doctor.sh
```

Recorded result:

- HTTPS clone succeeded from the public repository.
- Python compile check passed.
- Syntax checks passed.
- Unit behavior checks passed.
- Installer dry-run passed without modifying the system.
- `doctor.sh` executed, but returned expected environment failures in a
  non-systemd/non-NetworkManager test context. A full doctor pass still requires
  a real supported Linux host.

## Real Distribution Validation

Current manually reported validation status:

| Distribution | Status | Notes |
| --- | --- | --- |
| Ubuntu 24.04 | Passed | Real workstation validation. |
| Arch Linux | Passed | Real non-virtualized machine validation. |
| Debian | Passed | Real install flow including DNS tooling. |
| CachyOS | Passed with observation | Real install flow including DNS tooling; VPN recovered after reboot. |

The CachyOS result confirms that the Arch adapter works for a real install flow
with advanced DNS. During the first post-install validation, `adguardvpn.service`
was still `activating` and `vpn_truth_check` reported `DEGRADED`; after reboot,
the system came up healthy without manual repair. The installer now performs an
extra post-install VPN settle check and gives reboot guidance if the tunnel
remains degraded.

On tiling/minimal environments such as Hyprland setups where `xdg-user-dir
DESKTOP` resolves to `$HOME` or no real Desktop folder exists, the installer
should install only the application-menu launcher and skip the desktop-file copy
with a warning.

## Persistent Configuration Update Validation

Last recorded persistent configuration update validation: 2026-05-16.

Host type:

- Arch Linux real workstation.
- Existing WatchdogVPN runtime already installed.
- Existing VPN services active.

Commands:

```sh
cd ~/WatchdogVPN
git status --short --branch
sudo -v
./update.sh --skip-doctor
hash -r
command -v watchdogvpn
watchdogvpn version
watchdogvpn config get language.current
watchdogvpn config get tui.theme
watchdogvpn config get reporting.sanitize_ipv4
./doctor.sh
vpnctl status
vpnctl connect US
```

Recorded result:

- Repository was clean and synchronized with `origin/main`.
- `update.sh --skip-doctor` completed successfully.
- Installed CLI resolved to `/usr/local/bin/watchdogvpn`.
- Installed CLI reported `WatchdogVPN v0.1.1`.
- Persistent config reads returned:
  - `language.current`: `en`
  - `tui.theme`: `default`
  - `reporting.sanitize_ipv4`: `true`
- `doctor.sh` reported `OK=68 WARN=0 FAIL=0`.
- `vpnctl status` reported real VPN state `UP`.
- `vpnctl connect US` completed and kept real VPN state `UP`.
- AdGuard VPN CLI text still reported disconnected, but WatchdogVPN correctly
  treated that provider CLI text as non-authoritative because tunnel, route and
  public IP truth checks were healthy.

## Unit Behavior Checks

`tests/unit.sh` runs behavior checks with mocked system commands and temporary
state. These tests do not require a real VPN tunnel, do not write to `/etc`,
`/run`, `/var` or systemd, and do not restart services.

Current coverage:

- `vpn_truth_check` state contract:
  - `UP` when `tun0`, route and public IP are healthy
  - `DEGRADED` when the tunnel exists but route or public IP is unhealthy
  - `DOWN` when the tunnel is absent
  - `--shell`, `--quiet` and `--json` output behavior
- `vpn_watchdog.sh` decision behavior:
  - healthy VPN state does not trigger rotation
  - hard `DOWN` state triggers remediation
  - unknown public IP is treated as a soft failure until the configured
    threshold is reached
- TUI module behavior:
  - extracted action command builders, command helpers, state collectors,
    render helpers, constants, formatters, parsers and validators keep stable
    behavior
  - installed layout with `VPN` plus `watchdogvpn/` remains importable
  - non-interactive launcher execution exits cleanly before terminal setup

## System-Level Checks

These checks require a Linux system with systemd and, in some cases, sudo:

```sh
systemd-analyze verify systemd/*.service systemd/*.timer
sudo logrotate -d etc/logrotate.d/myvpn
```

## Runtime Checks After Installation

```sh
vpn_truth_check
vpn_auth_check
watchdogvpn report
systemctl status vpn-watchdog.timer
systemctl status vpn-rotate.timer
VPN
```

## Acceptance Criteria

A clean install is considered valid when:

- `doctor.sh` reports no blocking failures.
- The TUI opens with `VPN`.
- Dashboard shows VPN, session, tunnel, location and DNS state.
- `vpn_truth_check` returns parseable state.
- `vpn_auth_check` returns `AUTH=OK` or a clear non-OK state.
- watchdog and rotation timers are enabled and active.
- logrotate config validates.
- uninstall can remove product files without deleting AdGuard VPN itself.
