# Architecture

WatchdogVPN is a terminal-first control layer for AdGuard VPN CLI.

The current backend is AdGuard VPN CLI. The runtime is intentionally separated
into truth checking, recovery, rotation, DNS safety and TUI layers so future VPN
backends can reuse the same product shape without rewriting the user experience.

The runtime is shared across supported distributions. Distro differences belong
only in installation and dependency detection.

## Core Runtime

- `tui/VPN`: compatibility entrypoint and main terminal UI loop
- `tui/watchdogvpn/`: extracted command runners, state collectors, constants,
  parsers, formatters and validators
- `bin/vpnctl`: user command surface
- `bin/vpn_truth_check`: source of truth for tunnel/routing/IP state
- `bin/vpn_auth_check`: AdGuard VPN session check
- `bin/vpn_notify`: desktop notification and traceable event helper
- `sbin/vpn_set`: privileged location setter
- `sbin/vpn_rotate.sh`: safe location rotation
- `sbin/vpn_watchdog.sh`: recovery watchdog
- `sbin/vpn_domain_bypass_apply.sh`: domain exclusion/bypass rules

## Install Layer

- `doctor.sh`: read-only preflight
- `install.sh`: guided installer
- `update.sh`: safe update path
- `uninstall.sh`: careful removal
- `lib/`: shared installer functions
- `distros/`: Ubuntu, Debian and Arch adapters

## Optional Integrations

- AdGuard Home for advanced DNS profiles
- Conky desktop status
- `.desktop` launcher
