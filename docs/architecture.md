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
- `bin/watchdog`: canonical Python CLI wrapper for runtime, policy, recovery and
  maintenance commands
- `bin/watchdogvpn`: deprecated compatibility alias that routes into
  `bin/watchdog`; its internal Bash path implements the canonical maintenance
  namespace only
- `bin/vpn_backend`: backend contract helper for the custom-vps legacy bash
  compatibility path
- `bin/vpnctl`: user command surface
- `bin/vpn_truth_check`: mode-aware runtime truth check. It prefers the
  reachable v2 daemon lifecycle plus independently observed interface and
  egress evidence, and falls back to the custom-vps compatibility backend only
  when the daemon cannot provide an authoritative lifecycle.
- `bin/vpn_manual_state`: runtime state helper for user-requested manual-off
- `bin/vpn_notify`: desktop notification and traceable event helper
- `sbin/vpn_domain_bypass_apply.sh`: domain exclusion/bypass rules
- `daemon/`: systemd daemon, IPC server, runtime worker and event bus
- `core/kill_switch.py`: fail-closed nftables/iptables policy. On sing-box TUN
  sessions, the nftables output path accepts the capture mark only with a
  companion postrouting guard that drops it unless the final interface is the
  managed TUN; the physical outbound mark remains restricted to the daemon
  UID. DNS leak rejects run before capture traffic is admitted.
- `rules/`: routing-rule store, parser, engine and sing-box translation

## Install Layer

- `doctor.sh`: read-only preflight
- `install.sh`: guided installer
- `update.sh`: safe update path
- `uninstall.sh`: careful removal
- `lib/`: shared installer functions
- `distros/`: Ubuntu, Debian, Arch, Fedora/Red Hat-family and openSUSE adapters
