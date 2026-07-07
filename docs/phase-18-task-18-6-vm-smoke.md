# Phase 18 Task 18.6 - VM Smoke Procedure

Date: 2026-07-07
Scope: non-destructive install/update smoke validation on a disposable VM or
snapshot.

## Objective

Task 18.6 must prove, with real install/update execution, that:

- existing backend config and runtime state are preserved;
- profiles, providers, routing rules, DNS policy, app policy and node groups
  survive update unchanged;
- the daemon restarts cleanly;
- product-managed files are backed up before replacement, giving a rollback
  path if replacement fails;
- installed CLI wrappers, product CLI, daemon unit and doctor agree with the
  installed source commit;
- `PATH` resolves to the newly installed product entrypoints;
- stale legacy entrypoints are removed or explicitly reported;
- legacy-contaminated VM update succeeds or fails closed with recovery steps;
- the clean-machine/fresh shared-state proof deferred from Tasks 18.3 and 18.4
  is exercised on a real VM.

## VM Coordination Model

The development session stays on the workstation. The VM owns real
system-mutating validation. Sync the repository in the VM, run the commands
below, then paste the full output back into the development chat for review.

## VM Commands

Run from the repository checkout inside the VM:

```sh
cd ~/WatchdogVPN
git fetch origin
git checkout main
git pull --ff-only origin main
git status --short --branch
```

Run a baseline real install on a disposable VM/snapshot:

```sh
WATCHDOGVPN_VM_SMOKE=1 tests/vm/phase18_6_vm_smoke.sh install-baseline
```

Then run the non-destructive update preservation smoke:

```sh
WATCHDOGVPN_VM_SMOKE=1 tests/vm/phase18_6_vm_smoke.sh update-preserve
```

Both modes intentionally mutate system install paths and must not be run on the
maintainer workstation.

## What The Helper Does

`install-baseline`:

- writes a supported non-secret Custom VPS config;
- runs real `install.sh --yes --skip-doctor`;
- verifies `/var/lib/watchdogvpn/.migrated`;
- verifies the service user's Python config resolution reaches
  `/var/lib/watchdogvpn`;
- verifies the installed/source version marker;
- verifies `PATH` entrypoint resolution;
- runs `doctor.sh` and records its result without making it a hard failure
  unless the install itself failed.

`update-preserve`:

- writes a supported non-secret Custom VPS config;
- seeds valid shared runtime state through the product's Python stores:
  `profiles.json`, `providers.json`, `rules/phase18-smoke.json`,
  `dns-policy.json`, `app-policy.json`, `node_groups.json`, and `state.toml`;
- plants known-dead legacy product artifacts;
- records a content hash manifest before update;
- runs `update.sh --dry-run --yes --skip-doctor`;
- runs real `update.sh --yes --skip-doctor`;
- records a content hash manifest after update and requires it to match;
- verifies config hash preservation;
- verifies daemon active/enabled state and IPC status;
- verifies installed/source version marker;
- verifies installed wrappers and daemon unit entrypoint;
- verifies `PATH` resolves to `/usr/local/bin` entrypoints;
- verifies planted legacy artifacts were removed;
- verifies product-managed backups exist under `/var/backups/watchdogvpn`;
- runs `doctor.sh` and records its result.

## Expected Output

Each successful mode ends with:

```text
== Phase 18.6 VM smoke result ==
mode=<mode>
result=PASS
```

If a mode fails, keep the full output. The failure point is part of the Task
18.6 evidence and should be reviewed before changing the script or rerunning.

## Validation Result

Task 18.6 was validated on a real VM on 2026-07-07 from branch
`phase-18-6-vm-smoke`.

- `install-baseline` passed on commit `fa58216`, proving a fresh install
  creates shared state, marks `/var/lib/watchdogvpn/.migrated`, converges the
  daemon service user and CLI on `/var/lib/watchdogvpn`, installs the expected
  entrypoints, records the installed/source version marker, and produces a
  doctor result with no `FAIL` findings.
- `update-preserve` initially passed on commit `fa58216`, but exposed a real
  updater bug: optional dependency installers called `prompt_yes_no` from
  `update.sh` even though the updater did not define the helper. Commit
  `a32baf3` restored the updater prompt helper and added regression coverage.
- `update-preserve` passed again on commit `a32baf3` with no
  `prompt_yes_no: command not found` errors. The smoke confirmed state and
  config hashes were preserved, the daemon was active/enabled, IPC status
  returned standby, the installed/source version marker matched `a32baf3`,
  `PATH` resolved to `/usr/local/bin/watchdog`,
  `/usr/local/bin/watchdogvpn`, and `/usr/local/bin/watchdogvpn-daemon`,
  planted legacy wrappers/units were removed, backups existed under
  `/var/backups/watchdogvpn`, and doctor reported `OK=77 WARN=3 FAIL=0`.

Known VM warnings were non-blocking for this task: NTP was unsynchronized, the
truth state was `DOWN` because no live VPN profile was connected, and
AmneziaWG tooling was not installed because the VM smoke did not exercise
AmneziaWG profiles.
