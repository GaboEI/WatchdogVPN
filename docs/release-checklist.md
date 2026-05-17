# WatchdogVPN Release Checklist

This checklist defines what must be true before a WatchdogVPN build is tagged
and presented as a public release.

## Current Target

- Target version: `v0.2.0`
- Current status: persistent configuration foundation complete
- Intended audience: portfolio reviewers, Linux automation reviewers and
  controlled Linux testers
- Public license: GPL-3.0-or-later

## Required Before Tagging `v0.1.0-alpha`

- [x] README explains the product purpose, status, install flow and limitations.
- [x] GPL-3.0-or-later license exists.
- [x] CI runs on push and pull request.
- [x] CI validates Python compilation, Bash syntax and systemd units.
- [x] CI runs unit behavior tests with mocks for truth checks and watchdog
  decisions.
- [x] CI validates the installed TUI layout after the module split.
- [x] Security and threat-model documentation exist.
- [x] External installer risks and manual-first alternatives are documented.
- [x] Install/uninstall security contracts are covered by unit checks.
- [x] Demo screenshots and real command examples exist.
- [x] Release notes exist for the alpha release.
- [x] Changelog is grouped by release.
- [x] Post-alpha and v1.1.0 roadmap documents exist.
- [x] Ubuntu 24.04 real-machine validation passed.
- [x] Arch Linux real-machine validation passed.
- [x] Debian clean-system validation passed, including DNS tooling.
- [x] Final public-license decision is made.
- [x] GitHub About description, topics and website/demo link are documented.
- [x] GitHub About description, topics and website/demo link are configured.
- [x] Final release tag is created.
- [x] GitHub release entry is published with release notes.

## Required Before Tagging `v0.1.1`

- [x] `SECURITY.md` exists.
- [x] Bug report and feature request issue templates exist.
- [x] Reporting guidance exists in `docs/reporting.md`.
- [x] Public clone smoke test recorded.
- [x] Local diagnostic report command exists.
- [x] Initial GitHub milestones, labels and issue drafts are documented.
- [x] GitHub milestones and labels are created.
- [x] Debian clean-system validation passed.
- [x] CachyOS/Arch-derived distro detection issue fixed.
- [x] CachyOS real-machine validation passed with post-reboot VPN recovery observation.
- [x] Installed `watchdogvpn` CLI is not shadowed by the TUI support package.
- [x] `v0.1.1` release notes exist.

## Required Before Tagging `v0.2.0`

- [x] Configuration contract exists in `docs/configuration.md`.
- [x] Default config example exists in `examples/watchdogvpn-config.toml.example`.
- [x] Default config schema is covered by a unit contract test.
- [x] Minimal config helper functions exist in `lib/config.sh`.
- [x] `/etc/watchdogvpn/config.toml` is created on fresh install.
- [x] `uninstall.sh` preserves config by default.
- [x] `uninstall.sh --purge-config` removes WatchdogVPN config explicitly.
- [x] `update.sh` preserves existing user configuration.
- [x] Missing config keys are added safely during migration.
- [x] Config migration creates a backup before modifying the active file.
- [x] `watchdogvpn config get` exists.
- [x] `watchdogvpn config set` validates supported keys and values.
- [x] `watchdogvpn config reset` requires confirmation.
- [x] Config create, preserve, migration and reset behavior is covered by tests.
- [x] `docs/cli.md` documents the current product CLI.
- [x] TUI shows a read-only Settings view backed by persistent config.
- [x] TUI Settings can update safe language and TUI preferences.
- [x] TUI Settings reset requires confirmation and does not touch DNS/timers.
- [x] TUI Update Center shows local version, repository state and update
  commands without executing privileged changes.
- [x] TUI Update Center reports local sync state without running `fetch`,
  `pull` or privileged commands.
- [x] TUI Update Center can refresh remote metadata with confirmed
  `git fetch origin --tags` only.
- [x] TUI Update Center shows a contextual runtime update plan without
  executing update commands.
- [x] TUI Update Center presents product-facing status separately from
  maintainer technical details.
- [x] TUI Update Center installed-runtime validation is recorded.

## Manual GitHub Repository Setup

GitHub metadata is not stored entirely in the repository. Before making the
repository public, configure these fields manually in GitHub.

Suggested description:

```text
Terminal-first resilience layer for AdGuard VPN CLI on Linux: truth checks, watchdog recovery, rotation, DNS safety and TUI control center.
```

Suggested topics:

```text
linux vpn tui systemd networkmanager bash python devops dns adguard-vpn automation resilience
```

Suggested website/demo link:

```text
https://github.com/GaboEI/WatchdogVPN/blob/main/docs/demo.md
```

## Validation Commands

Run from the repository root:

```sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
bash tests/syntax.sh
systemd-analyze verify systemd/*.service systemd/*.timer
./doctor.sh
watchdogvpn report
vpnctl status
vpn_dnsctl local-test
systemctl list-timers --all vpn-watchdog.timer vpn-rotate.timer vpn-domain-bypass.timer myvpn-logrotate.timer --no-pager
```

## Tagging Command

Do not run this until the checklist is approved:

```sh
git tag -a v0.1.1 -m "WatchdogVPN v0.1.1"
git push origin v0.1.1
```

## Release Boundaries

`v0.1.1` should not claim:

- stable 1.0 readiness
- broad Arch-derived distribution validation beyond Arch Linux and CachyOS
- Fedora support
- WireGuard/private backend support
- complete TUI modularity
- complete removal of all `shell=True` call sites
- cryptographically pinned verification for every external installer path

Those items belong to future hardening releases.
