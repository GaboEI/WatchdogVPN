# WatchdogVPN v0.1.1 Release Notes

Status: alpha maintenance release.

`v0.1.1` is the first maintenance release after the public `v0.1.0-alpha`
tag. It focuses on support readiness, real-system validation and a safer
installed command layout.

## Highlights

- Add public security reporting guidance in `SECURITY.md`.
- Add GitHub issue templates for bug reports and feature requests.
- Add `docs/reporting.md` with safe diagnostic sharing guidance.
- Add the initial `watchdogvpn` product CLI.
- Add `watchdogvpn report` for local sanitized diagnostic reports.
- Document GitHub milestones, labels and issue drafts for post-alpha planning.
- Record a public clone smoke test.
- Record successful Debian real install validation, including DNS tooling.
- Add Arch-derived distro detection so CachyOS can use the Arch adapter.
- Record successful CachyOS real install validation with advanced DNS.
- Improve post-install VPN settle handling with one recovery restart and clear
  reboot guidance when the tunnel remains degraded.
- Move the installed TUI support package out of `~/.local/bin` so it no longer
  shadows the `watchdogvpn` CLI command.
- Skip desktop-file placement cleanly when tiling/minimal desktop environments
  do not expose a real Desktop folder.

## Supported and Targeted Platforms

| Distribution | Status |
| --- | --- |
| Ubuntu 24.04 | Tested on a real workstation |
| Arch Linux | Tested on a real workstation |
| Debian | Tested with a real install flow, including DNS tooling |
| CachyOS | Tested with a real install flow, advanced DNS and post-reboot VPN recovery |
| Fedora | Future target |

## Upgrade Notes

Existing users can update with:

```sh
cd WatchdogVPN
git pull
sudo -v
./update.sh --skip-doctor
hash -r
./doctor.sh
watchdogvpn report
VPN
```

The updater preserves user configuration, logs, rotation state and legacy DNS
configuration.

## Important Fix

Older installs placed the TUI support package at:

```text
~/.local/bin/watchdogvpn
```

That directory could shadow the new `/usr/local/bin/watchdogvpn` CLI when
`~/.local/bin` appeared earlier in `PATH`, causing shells to report permission
errors. `v0.1.1` moves the support package to:

```text
~/.local/share/watchdogvpn/watchdogvpn
```

After updating, `command -v watchdogvpn` should return:

```text
/usr/local/bin/watchdogvpn
```

## Known Limitations

- This is still an alpha release, not a stable 1.0 release.
- TUI command helpers use explicit argv wrappers instead of subprocess shell mode.
- External installer verification for the initial provider CLI and optional DNS
  component is not yet cryptographically pinned.
- The first backend is provider-CLI based. WireGuard/private backend support is
  not implemented yet.
- Fedora support remains a future target.

## Validation

Validated locally before release:

```sh
bash tests/unit.sh
bash tests/syntax.sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
git diff --check
HOME=/tmp ./bin/watchdogvpn report
```

Real-machine validation recorded:

- Arch Linux workstation.
- Debian install flow with DNS tooling.
- CachyOS install flow with advanced DNS and post-reboot VPN recovery.
