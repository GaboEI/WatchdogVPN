# WatchdogVPN Release Checklist

This checklist defines what must be true before a WatchdogVPN build is tagged
and presented as a public release.

## Current Target

- Target version: `v0.1.0-alpha`
- Current status: alpha candidate
- Intended audience: portfolio reviewers and controlled Linux testers
- Public license: not selected yet

## Required Before Tagging `v0.1.0-alpha`

- [x] README explains the product purpose, status, install flow and limitations.
- [x] Portfolio-review license notice exists while no public license is selected.
- [x] CI runs on push and pull request.
- [x] CI validates Python compilation, Bash syntax and systemd units.
- [x] CI runs unit behavior tests with mocks for truth checks and watchdog
  decisions.
- [x] CI validates the installed TUI layout after the module split.
- [x] Security and threat-model documentation exist.
- [x] Demo screenshots and real command examples exist.
- [x] Release notes exist for the alpha candidate.
- [x] Changelog is grouped by release.
- [x] Ubuntu 24.04 real-machine validation passed.
- [x] Arch Linux clean-VM validation passed.
- [ ] Debian clean-system validation passed.
- [ ] Final public-license decision is made.
- [ ] GitHub About description, topics and website/demo link are configured.
- [ ] Final release tag is created.
- [ ] GitHub release entry is published with release notes.

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

## Validation Commands

Run from the repository root:

```sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
bash tests/syntax.sh
systemd-analyze verify systemd/*.service systemd/*.timer
./doctor.sh
vpnctl status
vpn_dnsctl local-test
systemctl list-timers --all vpn-watchdog.timer vpn-rotate.timer vpn-domain-bypass.timer myvpn-logrotate.timer --no-pager
```

## Tagging Command

Do not run this until the checklist is approved:

```sh
git tag -a v0.1.0-alpha -m "WatchdogVPN v0.1.0-alpha"
git push origin v0.1.0-alpha
```

## Release Boundaries

`v0.1.0-alpha` should not claim:

- stable 1.0 readiness
- full Debian validation
- Fedora support
- WireGuard/private backend support
- complete TUI modularity
- complete removal of all `shell=True` call sites
- cryptographically pinned verification for every external installer path

Those items belong to future hardening releases.
