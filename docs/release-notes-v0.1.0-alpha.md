# WatchdogVPN v0.1.0-alpha Candidate Release Notes

Status: alpha candidate, private portfolio review build.

This is the first product-shaped WatchdogVPN release candidate. It packages the
working local VPN resilience stack into a reproducible repository with
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
- Real-state validation through `vpn_truth_check` instead of trusting only
  `adguardvpn-cli status`.
- Watchdog service for automatic recovery when the tunnel, route or public IP
  state is unhealthy.
- Controlled VPN location rotation with validation and anti-loop behavior.
- Optional AdGuard Home DNS profile management with backup, preflight and
  rollback.
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
| Ubuntu 24.04 | Tested on a real workstation |
| Arch Linux | Tested in a clean VM flow |
| Debian | Adapter exists; clean validation still required |
| Fedora | Future target |

## Known Limitations

- This is not a stable 1.0 release.
- The repository is still private and under portfolio-review licensing.
- Debian has not completed a clean-system validation pass.
- The TUI still contains most rendering flow in `tui/VPN`, but action command
  builders, render primitives and state/command helpers are already split into
  importable modules.
- Some TUI command helpers still use `shell=True`; this is tracked as hardening
  work, although simple helper paths have started moving to argument-list
  subprocess calls.
- External installer verification for the official AdGuard VPN CLI and AdGuard
  Home is not yet cryptographically pinned.
- The first backend is AdGuard VPN CLI. WireGuard/private backend support is not
  implemented yet.

## Release Candidate Checklist

- [x] Product README and support matrix.
- [x] Portfolio-review license notice.
- [x] CI workflow.
- [x] Unit behavior tests for core decision logic.
- [x] Security and threat-model documentation.
- [x] Demo screenshots and validation examples.
- [x] Project history documentation.
- [x] Ubuntu real-machine validation.
- [x] Arch clean-VM validation.
- [ ] Debian clean-system validation.
- [ ] Final license decision before public release.
- [ ] Release checklist approved.
- [ ] GitHub release tag and release entry.
- [ ] GitHub About description and topics.

The full publication checklist is tracked in
[Release Checklist](release-checklist.md).

## Upgrade Notes

Existing private testers can update with:

```sh
cd WatchdogVPN
git pull
./update.sh
```

The updater preserves user configuration, logs, rotation state, AdGuard Home
configuration and Conky files.

## Fresh Install

```sh
git clone https://github.com/GaboEI/WatchdogVPN.git
cd WatchdogVPN
./doctor.sh
./install.sh
VPN
```

For private repository access, use the SSH clone URL:

```sh
git clone git@github.com:GaboEI/WatchdogVPN.git
```
