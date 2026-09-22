# CLI design

`watchdogvpn` is the primary product command for daily operations. The goal is
not to hide the existing low-level commands: users and maintainers get one
stable command surface while `VPN`, `vpnctl`, `vpn_truth_check` and other
lower-level tools remain available for automation and troubleshooting.

## Current CLI surface

```sh
watchdogvpn status
watchdogvpn doctor
watchdogvpn tui
watchdogvpn report
watchdogvpn config get [section.key]
watchdogvpn config set section.key value
watchdogvpn config reset [language|tui|reporting|all] --yes
watchdogvpn version
watchdogvpn help
```

## Target command surface

```sh
watchdogvpn status
watchdogvpn doctor
watchdogvpn tui
watchdogvpn report
watchdogvpn logs
watchdogvpn update-check
watchdogvpn update-plan
watchdogvpn config get [section.key]
watchdogvpn config set section.key value
watchdogvpn config reset [language|tui|reporting|all] --yes
watchdogvpn version
watchdogvpn help
```

Possible later commands, not part of the current surface:

```sh
watchdogvpn connect <location>
watchdogvpn disconnect
watchdogvpn rotate
watchdogvpn runtime-update
```

Those later commands change VPN or system state and need stronger confirmation,
privilege and rollback design before becoming product CLI commands.

## Safety classes

Read-only commands:

- `watchdogvpn status`
- `watchdogvpn doctor`
- `watchdogvpn report`
- `watchdogvpn logs`
- `watchdogvpn update-check`
- `watchdogvpn update-plan`
- `watchdogvpn config get`
- `watchdogvpn version`
- `watchdogvpn help`

Config-write commands:

- `watchdogvpn config set`
- `watchdogvpn config reset`

Interactive commands:

- `watchdogvpn tui`

Deferred state-changing commands:

- `watchdogvpn connect`
- `watchdogvpn disconnect`
- `watchdogvpn rotate`
- `watchdogvpn runtime-update`

## Non-goals

- Automatic runtime updates.
- Full VPN connect/disconnect/rotate product CLI.
- Replacing `VPN` as an interactive shortcut.
- Removing lower-level automation commands.
- Full internationalized CLI output.
