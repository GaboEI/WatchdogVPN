# WatchdogVPN v0.3.0 Release Notes

Status: alpha feature release.

`v0.3.0` turns the `watchdogvpn` command into a more professional product CLI.
The release focuses on read-only diagnostics, safer update visibility and
clearer command help.

This is still not a stable 1.0 release.

## Highlights

- Add a grouped `watchdogvpn help` surface.
- Make `watchdogvpn --help` behave like `watchdogvpn help`.
- Add topic help such as `watchdogvpn help logs`,
  `watchdogvpn help update-check`, `watchdogvpn help update-plan` and
  `watchdogvpn help config`.
- Add `watchdogvpn logs` for recent sanitized local WatchdogVPN logs.
- Add `watchdogvpn update-check` for local source checkout update state.
- Add `watchdogvpn update-plan` for safe manual update guidance.
- Keep update and log commands read-only.
- Expand `docs/cli.md` with the current command reference.
- Add unit coverage for the new CLI commands.

## Product CLI

The `watchdogvpn` command now has a clearer command surface:

```sh
watchdogvpn status
watchdogvpn doctor
watchdogvpn report
watchdogvpn logs
watchdogvpn update-check
watchdogvpn update-plan
watchdogvpn config get language.current
watchdogvpn config set tui.theme high_contrast
watchdogvpn config reset tui --yes
watchdogvpn tui
watchdogvpn version
watchdogvpn help
```

The help output is grouped by safety class:

- read-only commands
- configuration-write commands
- interactive commands

State-changing runtime commands such as automatic update execution, connect,
disconnect and rotate remain intentionally deferred.

## Local Logs

`watchdogvpn logs` reads recent local WatchdogVPN logs without using `sudo`.

Examples:

```sh
watchdogvpn logs
watchdogvpn logs events 80
watchdogvpn logs watchdog 120
watchdogvpn logs rotate 120
watchdogvpn logs dispatcher 80
```

Supported targets:

```text
events      /var/log/myvpn/vpn-events.log
watchdog    /var/log/myvpn/vpn-watchdog.log
rotate      /var/log/myvpn/vpn-rotate.log
dispatcher  /var/log/myvpn/vpn-dispatcher.log
```

The command sanitizes obvious home paths, email addresses and IPv4 addresses.
It does not modify logs, services, configuration or VPN state.

## Update Visibility

`watchdogvpn update-check` shows local source checkout state without contacting
the network:

```sh
watchdogvpn update-check
```

It reports version, repository, branch, commit, upstream, origin, local sync
state, working tree state, ahead/behind counts and latest local tag.

It does not run:

- `git fetch`
- `git pull`
- `git push`
- `update.sh`
- `sudo`

`watchdogvpn update-plan` prints safe manual update guidance for the current
checkout state:

```sh
watchdogvpn update-plan
```

If the working tree is dirty, diverged, missing upstream metadata or ambiguous,
the command stops at source-checkout guidance and does not recommend runtime
update steps.

When the checkout is clean and safe to proceed, it prints the installed-runtime
routine:

```sh
sudo -v
./update.sh --skip-doctor
hash -r
./doctor.sh
```

## Upgrade Notes

Existing users can update with:

```sh
cd ~/WatchdogVPN
git fetch origin --tags
git pull --ff-only origin main
bash tests/unit.sh
bash tests/syntax.sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
git diff --check
sudo -v
./update.sh --skip-doctor
hash -r
watchdogvpn version
watchdogvpn help
watchdogvpn update-check
watchdogvpn update-plan
./doctor.sh
```

## Supported and Targeted Platforms

| Distribution | Status |
| --- | --- |
| Ubuntu 24.04 | Tested on a real workstation |
| Arch Linux | Tested on a real workstation |
| Debian | Tested with a real install flow, including DNS tooling |
| CachyOS | Tested with a real install flow, advanced DNS and post-reboot VPN recovery |
| Fedora | Future target |

## Known Limitations

- This is still an alpha release, not a stable 1.0 release.
- `watchdogvpn update-check` uses local Git metadata only. Run
  `git fetch origin --tags` manually first if you want fresh remote metadata.
- `watchdogvpn update-plan` prints commands only. It does not execute updates.
- Automatic runtime update execution remains deferred.
- Full VPN connect/disconnect/rotate product CLI commands remain deferred.
- Timer and DNS preferences are still not fully writable runtime settings.
- Full TUI internationalization is not implemented yet.
- Fedora support remains a future target.

## Validation

Validated locally before release:

```sh
bash tests/unit.sh
bash tests/syntax.sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
git diff --check
./bin/watchdogvpn help
./bin/watchdogvpn logs --help
./bin/watchdogvpn update-check
./bin/watchdogvpn update-plan
```

Real-machine validation already recorded for the project:

- Arch Linux persistent configuration update validation.
- Arch Linux TUI Settings runtime validation.
- Arch Linux TUI Update Center runtime validation.
- Debian real install validation, including DNS tooling.
- CachyOS real install validation with advanced DNS and post-reboot VPN
  recovery.

## Non-Goals For This Release

- Stable 1.0 support promise.
- Automatic update execution.
- Full VPN connect/disconnect/rotate product CLI.
- Full TUI internationalization.
- WireGuard/private backend support.
- Fedora support.
