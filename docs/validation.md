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
