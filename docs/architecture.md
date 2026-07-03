# Architecture

WatchdogVPN is a terminal-first VPN resilience control layer.

The product direction for v2 is broader than any single vendor. The runtime is
split into truth checking, daemon-owned connection lifecycle, profile/provider
stores, recovery, rotation, DNS safety and TUI layers so supported providers can
reuse the same product shape without rewriting the user experience.

The runtime is shared across supported distributions. Distro differences belong
only in installation and dependency detection.

## Core Runtime

- `tui/VPN`: compatibility entrypoint and main terminal UI loop
- `tui/watchdogvpn/`: extracted action command builders, command runners, state
  collectors, render helpers, constants, parsers, formatters and validators
- `bin/watchdogvpn`: product CLI for status, TUI launch and local diagnostic
  reports
- `bin/vpn_backend`: backend contract helper for the custom-vps legacy bash
  compatibility path
- `bin/vpnctl`: user command surface
- `bin/vpn_truth_check`: source of truth for tunnel/routing/IP state
- `bin/vpn_manual_state`: runtime state helper for user-requested manual-off
- `bin/vpn_notify`: desktop notification and traceable event helper
- `sbin/vpn_domain_bypass_apply.sh`: domain exclusion/bypass rules
- `daemon/`: systemd daemon, IPC server, runtime worker and event bus
- `rules/`: routing-rule store, parser, engine and sing-box translation

## Install Layer

- `doctor.sh`: read-only preflight
- `install.sh`: guided installer
- `update.sh`: safe update path
- `uninstall.sh`: careful removal
- `lib/`: shared installer functions
- `distros/`: Ubuntu, Debian and Arch adapters

## Optional Integrations

- `.desktop` launcher
