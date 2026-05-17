# CLI Plan v0.3.0

`v0.3.0` turns `watchdogvpn` into the primary product command for daily
operations.

The goal is not to hide the existing low-level commands. The goal is to give
users and maintainers one stable command surface while keeping `VPN`, `vpnctl`,
`vpn_truth_check`, `vpn_dnsctl` and other lower-level tools available for
automation and troubleshooting.

## Current CLI Surface

Already available:

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

## Target Command Shape

Target for `v0.3.0`:

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

Possible later commands, not required for `v0.3.0`:

```sh
watchdogvpn connect <location>
watchdogvpn disconnect
watchdogvpn rotate
watchdogvpn runtime-update
```

Those later commands change VPN or system state and need stronger confirmation,
privilege and rollback design before becoming product CLI commands.

## Safety Classes

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

## Implementation Order

1. Improve `watchdogvpn help`
   - Show command groups.
   - Clearly mark read-only vs write commands.
   - Point users to `watchdogvpn help <command>` if supported.

2. Add `watchdogvpn logs`
   - Read recent WatchdogVPN logs without requiring users to remember file
     paths.
   - Keep it read-only.
   - Sanitize obvious sensitive data where practical.

3. Add `watchdogvpn update-check`
   - Mirror the TUI Update Center read-only status.
   - Report local version, source checkout state, sync state and runtime update
     readiness.
   - Do not run `pull`, `push`, `update.sh` or privileged commands.

4. Add `watchdogvpn update-plan`
   - Print the same contextual guidance as the TUI Update Center.
   - Keep it read-only.

5. Update documentation and tests
   - Expand `docs/cli.md`.
   - Add unit coverage for new commands.
   - Keep installer/update validation unchanged unless command paths change.

## Acceptance Criteria

- `watchdogvpn --help` and `watchdogvpn help` are clear.
- New commands are covered by unit tests.
- Read-only commands do not require sudo.
- State-changing behavior is not added accidentally.
- `docs/cli.md` documents every supported command.
- `VPN` remains a direct TUI launcher.
- Existing low-level commands remain available for scripts and debugging.

## Non-Goals

- Automatic runtime updates.
- Full VPN connect/disconnect/rotate product CLI.
- Replacing `VPN` as an interactive shortcut.
- Removing lower-level automation commands.
- Full internationalized CLI output.
