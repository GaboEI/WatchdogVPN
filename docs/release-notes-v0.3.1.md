# WatchdogVPN v0.3.1 Release Notes

Status: alpha feature release.

`v0.3.1` adds the safe runtime update engine behind
`watchdogvpn runtime-update`. The release turns the update work introduced in
`v0.3.0` from read-only visibility into a confirmed command flow that can update
the source checkout and installed runtime while preserving strict safety checks.

This is still not a stable 1.0 release.

## Highlights

- Add `watchdogvpn runtime-update --preflight` safety validation.
- Add confirmed `watchdogvpn runtime-update` execution.
- Require exact `yes` confirmation before any state-changing update step.
- Refuse unsafe source checkout states before execution.
- Run `git fetch origin --tags` before updating source metadata.
- Recompute safety state after fetch.
- Run `git pull --ff-only origin main`.
- Run `./update.sh --skip-doctor`.
- Run `hash -r`.
- Run `./doctor.sh`.
- Stop at the first failed step.
- Report the failed step and last successful step.
- Cover the runtime update command order and failure paths with mocks.

## Runtime Update Flow

The new state-changing command is:

```sh
watchdogvpn runtime-update
```

Before changing anything, it prints the current checkout state, the exact
execution plan and a warning that `./update.sh --skip-doctor` may prompt for
`sudo`.

The user must type:

```text
yes
```

Any other input cancels the update before `fetch`, `pull`, `update.sh` or
`doctor.sh` run.

When confirmed, the command runs:

```sh
git fetch origin --tags
git pull --ff-only origin main
./update.sh --skip-doctor
hash -r
./doctor.sh
```

## Preflight

The read-only preflight remains available:

```sh
watchdogvpn runtime-update --preflight
```

It validates the same source checkout safety rules without running `fetch`,
`pull`, `update.sh`, `doctor.sh` or `sudo`.

The command refuses to continue when:

- the command is not running from a Git checkout;
- the current branch is not `main`;
- no upstream is configured;
- the working tree is dirty;
- the local branch is ahead of upstream;
- the local branch has diverged from upstream;
- upstream state is unknown;
- `update.sh` is missing or not executable;
- `doctor.sh` is missing or not executable.

## Failure Reporting

On failure, the command reports:

```text
Runtime update failed.
Failed step: <step>
Last successful step: <step-or-none>
```

The covered failure points are:

- `git fetch origin --tags`
- post-fetch preflight
- `git pull --ff-only origin main`
- `./update.sh --skip-doctor`
- `./doctor.sh`

## Upgrade Notes

Existing users can update from a clean checkout with the manual routine:

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
watchdogvpn runtime-update --preflight
./doctor.sh
```

After this release is installed, future updates can use:

```sh
watchdogvpn runtime-update
```

## Validation

Validated locally before release candidate documentation:

```sh
bash tests/unit.sh
bash tests/syntax.sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
git diff --check
./bin/watchdogvpn runtime-update --preflight
```

Unit coverage uses temporary repositories and mock scripts. The tests do not run
`sudo` or execute a real product update.

## Known Limitations

- This is still an alpha release, not a stable 1.0 release.
- Real installed-workstation validation is still required before tagging.
- The final TUI Update Center UX is not part of this release.
- The TUI does not auto-relaunch after update yet.
- Background or silent automatic updates are not implemented.
- Rollback remains limited to what `update.sh` already backs up.
- Full VPN connect/disconnect/rotate product CLI commands remain deferred.
- Fedora support remains a future target.

## Non-Goals For This Release

- Stable 1.0 support promise.
- Final graphical/TUI update workflow.
- Automatic TUI relaunch.
- Background scheduled updates.
- Silent updates.
- Rollback beyond existing `update.sh` backups.
- Full VPN connect/disconnect/rotate product CLI.
