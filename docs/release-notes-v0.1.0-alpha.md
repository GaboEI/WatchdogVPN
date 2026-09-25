# WatchdogVPN v0.1.0-alpha Release Notes

Status: alpha release.

This is the first product-shaped WatchdogVPN alpha release. It packages the
working local VPN resilience stack into a reproducible repository with an
installer, updater, uninstaller, TUI, systemd units, DNS tooling, documentation
and CI.

## Highlights

- Terminal control center for VPN state, locations, actions, DNS, exclusions,
  timers and logs.
- Initial TUI module split for action command builders, command helpers, state
  collectors, render helpers, constants, parsers, formatting helpers and
  validators.
- Installer/update support for deploying the extracted TUI support package next
  to the `VPN` launcher.
- Real-state validation through `vpn_truth_check` instead of trusting only a
  provider CLI status.
- Watchdog service for automatic recovery when the tunnel, route or public IP
  state is unhealthy.
- Controlled VPN location rotation with validation and anti-loop behavior.
- Optional legacy DNS profile management with backup, preflight and rollback.
- Domain exclusions that start empty by default for new users.
- Guided install/update/uninstall flows with backups and preservation contracts.
- Read-only `doctor.sh` preflight diagnostics.
- GitHub Actions CI for syntax and systemd validation.
- Unit behavior tests with mocks for truth-check and watchdog decisions.
- Security, threat model, project history, demo and validation documentation.
- Hardening notes and warnings for external vendor installers.
- Defensive TUI action validation for user-facing DNS, timer and bypass inputs.

## Supported and Targeted Platforms

| Distribution | Status |
| --- | --- |
| Ubuntu 24.04 | Supported (stable) |
| Arch Linux | Supported (rolling) |
| Debian 13.6 | Supported (stable) |
| CachyOS | Supported (rolling) |
| Fedora | Future target |

## Known Limitations

- This is not a stable 1.0 release.
- The project is licensed under GPL-3.0-or-later.
- On CachyOS, the initial post-install VPN state may need extra settle time or
  one reboot.
- The TUI still contains most rendering flow in `tui/VPN`, but action command
  builders, render primitives and state/command helpers are already split into
  importable modules.
- TUI command helpers use explicit argv wrappers instead of subprocess shell mode.
- External installer verification for the initial provider CLI and optional DNS
  component is not yet cryptographically pinned.
- The first backend is provider-CLI based. WireGuard/private backend support is
  not implemented yet.

## Release Checklist

- [x] Product README and support matrix.
- [x] GPL-3.0-or-later license.
- [x] CI workflow.
- [x] Security and threat-model documentation.
- [x] Demo screenshots and examples.
- [x] Project history documentation.
- [ ] Release checklist approved.
- [ ] GitHub release tag and release entry.
- [ ] GitHub About description and topics.

## Upgrade Notes

Existing testers can update with:

```sh
cd WatchdogVPN
git pull
./update.sh
```

The updater preserves user configuration, logs, rotation state and legacy DNS
configuration.

## Fresh Install

```sh
git clone https://github.com/GaboEI/WatchdogVPN.git
cd WatchdogVPN
./doctor.sh
./install.sh
VPN
```

For SSH access, use:

```sh
git clone git@github.com:GaboEI/WatchdogVPN.git
```
