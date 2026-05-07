# Validation

This repository separates lightweight validation from system-level validation.

## Local Syntax Checks

These checks do not modify the system:

```sh
python3 -m py_compile tui/VPN
bash tests/syntax.sh
./doctor.sh
```

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
