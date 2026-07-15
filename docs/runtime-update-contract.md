# Runtime Update Contract

This document defines the contract for the `watchdog maintenance runtime-update`
command.

The command is implemented for the `v0.3.1` release line.

## Goal

Provide a real product update action that can update the local source checkout
and installed WatchdogVPN runtime without hiding risk from the user.

The command must be safer than asking users to improvise:

```sh
git pull
sudo ./update.sh
```

## Command Shape

Command:

```sh
watchdog maintenance runtime-update
```

Help:

```sh
watchdog maintenance runtime-update --help
```

## Safety Class

`runtime-update` is a state-changing command.

It may:

- fetch remote Git metadata;
- update the local source checkout;
- run the WatchdogVPN updater;
- refresh installed runtime commands;
- trigger `sudo` through `./update.sh`;
- run post-update validation.

Because of that, it must never run silently.

## Required Preflight

The command must refuse to continue unless all of these are true:

- The command is running inside a Git checkout.
- The checkout is the WatchdogVPN source checkout.
- The current branch is `main`.
- An upstream branch is configured.
- The working tree is clean.
- The branch is not ahead of upstream.
- The branch is not diverged from upstream.
- `git` is available.
- `./update.sh` exists and is executable.
- `./doctor.sh` exists and is executable.

Before deciding whether source updates are available, it may run:

```sh
git fetch origin --tags
```

After fetch, it must recompute the local/remote state.

## Refusal Cases

The command must stop before making runtime changes when:

- the working tree is dirty;
- the branch is ahead;
- the branch is diverged;
- upstream is missing;
- branch is not `main`;
- `git fetch origin --tags` fails;
- `git pull --ff-only origin main` is not possible;
- required scripts are missing;
- the user does not confirm.

Each refusal should explain the reason and point to the safest next step.

## Planned Execution Steps

When preflight passes and the user confirms, the command may run:

```sh
git fetch origin --tags
git pull --ff-only origin main
./update.sh --skip-doctor
hash -r
./doctor.sh
```

Important:

- `git pull` must use `--ff-only`.
- `./update.sh` must remain responsible for product-managed backups.
- The command must stop on the first failure.
- The command must report the failed step.
- The command must report the last successful step.

## Confirmation

Before executing state-changing steps, the command must print:

- current version;
- branch;
- current commit;
- upstream;
- sync state after fetch;
- exact commands that will run;
- warning that `sudo` may prompt during `./update.sh`.

The user must confirm explicitly.

Initial accepted confirmation:

```text
yes
```

Uppercase confirmation words should not be required for the final product UX.

## Output Contract

Successful run should end with:

```text
Runtime update completed.
```

Failed run should include:

```text
Runtime update failed.
Failed step: <step>
Last successful step: <step-or-none>
```

## TUI Integration Contract

The TUI Update Center must not implement its own update logic.

It should eventually call the same runtime-update engine used by the CLI.

For `v0.4.0`, the TUI can provide a product-facing flow:

- current version;
- update status;
- simple check/update button;
- progress indicator;
- success message;
- failure message;
- technical details screen.

The main TUI update screen should not expose Git commands to normal users.

## Non-Goals For v0.3.1

- Closing and relaunching the TUI automatically.
- Progress bars in the CLI.
- VPN connect/disconnect/rotate commands.
- Rollback beyond what `update.sh` already backs up.
- Background updates.
- Automatic scheduled updates.

## Test Requirements

Unit tests should cover:

- dirty tree refusal;
- no upstream refusal;
- ahead refusal;
- diverged refusal;
- wrong branch refusal;
- missing `update.sh` refusal;
- missing `doctor.sh` refusal;
- confirmation required;
- successful planned command order using mocks;
- failure stops later steps;
- failed step and last successful step are reported.

Manual validation should cover:

- installed Arch workstation;
- installed Ubuntu workstation;
- at least one clean update from a previous release checkout;
- failed update path if feasible without risking the system.
