# Phase 18 Task 18.2 - Installer Entrypoint Audit

Date: 2026-07-07
Scope: audit `install.sh`, `update.sh`, `lib/*.sh`, systemd units and installed
binaries for v1-only entrypoints; fix the one real regression the Task 18.1
inventory found and left deliberately unfixed (INV-18.1-001).

## Objective

Confirm no v1-only entrypoint remains in the primary install/update/uninstall
path, and that installed `watchdog`, `watchdogvpn`, the daemon unit and
`doctor.sh` resolve to the same v2 runtime/source.

## Entrypoint Audit Result

WatchdogVPN ships two current, intentional CLI entrypoints, not a legacy/v2
split:

- `watchdog` (`/usr/local/bin/watchdog`, generated wrapper around
  `python3 -m cli.main`): the v2 Python CLI. Owns `uninstall`, `stats`,
  `backup`, rules/node-groups/app-policy management and other structured
  subsystems added since Phase 8.
- `watchdogvpn` (`/usr/local/bin/watchdogvpn`, the shell script installed
  verbatim from `bin/watchdogvpn`): the documented primary product command
  for diagnostics, configuration and common operations (`docs/cli.md`:
  "documentation should prefer `watchdogvpn`").

Both are current v2 product surface by design; this is not contamination.
The daemon unit (`watchdogvpn.service`) executes
`/usr/local/bin/watchdogvpn-daemon`, a generated wrapper around
`python3 -m daemon.main` - also current v2 code, confirmed in Task 18.1.

No v1-only entrypoint remains reachable through `install.sh`, `update.sh`, or
the shipped `systemd/*.service`/`*.timer` files. The only v1-only entrypoints
still capable of existing on a real machine were the seven AdGuard-era
systemd units and four AdGuard-era scripts identified in Task 18.1
(`docs/phase-18-task-18-1-legacy-contamination-inventory.md`), which are not
part of the shipped set but could survive on a machine that installed before
Phase 2.6, because nothing removed them anymore. That gap is INV-18.1-001,
fixed below.

The claim "installed `watchdog`/`watchdogvpn`/daemon unit/doctor resolve to
the same v2 runtime/source" was **not fully provable** at this task's initial
closure: Task 18.1 found live evidence that an installed runtime can silently
drift behind the source checkout with no detectable version marker. See the
"Addendum" section below - the maintainer rejected leaving this as "did
nothing" and it was implemented the same day, ahead of Task 18.7.

## Fix: INV-18.1-001 - restored legacy AdGuard-era cleanup

Commit `c19394f` added `remove_legacy_adguard_units()` to `uninstall.sh` to
clean up a machine that installed before the AdGuard removal. Commit
`59f4260` deleted that function, its call site, its regression test
assertions, and the related `/etc/adguardvpn.env` / `/var/lib/vpn-rotate/` /
`~/.conky/WatchdogVPN/` cleanup, with no replacement. This task restores
equivalent coverage, generalized this time so a future refactor can't repeat
the same silent regression.

### `lib/systemd.sh`

- Added `SYSTEMD_LEGACY_UNITS`, a fixed array of the seven historical unit
  names, kept explicitly separate from `SYSTEMD_UNITS` (the current shipped
  set) with a comment pointing at INV-18.1-001.
- Added `remove_legacy_systemd_units()`: disables (best-effort, matching the
  original function's tolerance for absent units) and removes each legacy
  unit file, then reloads systemd.

### `uninstall.sh`

- Added `remove_legacy_runtime_files()`: removes the four historical binaries
  (`vpn_auth_check`, `vpn_rotate.sh`, `vpn_set`, `vpn_watchdog.sh`) and the
  orphaned NetworkManager dispatcher (`99-vpn-rotate`). Kept separate from
  `remove_runtime_files()` (current product files), unlike the original
  design where the binaries were mixed directly into the current-files
  function - that mixing is what made them easy to delete unnoticed
  alongside real AdGuard code in `59f4260`.
- Extended `remove_optional_user_data()` to also purge
  `/etc/adguardvpn.env` and `~/.conky/WatchdogVPN/` under the existing
  `--purge-config` flag, and `/var/lib/vpn-rotate/` under the existing
  `--purge-state` flag, each printing a `[KEEP] legacy ...` line when not
  purged. This reuses the existing purge flags rather than reintroducing the
  original standalone `--purge-conky` flag, which was narrower than
  necessary; Conky is fully removed from the product, so folding its
  leftover files under `--purge-config` (the same class of user-local
  product customization as the config directory) is a reasonable
  simplification rather than a behavior gap.
- Wired both new functions into the main uninstall sequence, immediately
  after their current-product equivalents (`remove_systemd_units` ->
  `remove_legacy_systemd_units`; `remove_runtime_files` ->
  `remove_legacy_runtime_files`).
- Updated `print_contract()` so the printed removal/preservation plan
  mentions the legacy cleanup instead of silently doing it.

### Deliberately not changed

- No new CLI flag was added. The legacy paths reuse the existing
  `--purge-config`/`--purge-state` gates instead.
- Full mixed-install classification (fresh / clean update / legacy migration
  / mixed-inconsistent, with an explicit refusal/migration plan) is still
  Task 18.5's job. What changed in the addendum below is narrower and safer
  than that: unconditionally sweeping away *known-dead* legacy units/files
  that are never part of any supported configuration, not classifying or
  refusing anything.

## Addendum (2026-07-07, same day): update.sh was left too weak, version skew was left undone

The initial closure above shipped two decisions the maintainer explicitly
rejected on review:

1. "`update.sh` does not run legacy cleanup... assigned to Task 18.5" - in
   practice this meant a machine that never gets fully uninstalled (the
   overwhelming majority of real usage) would carry AdGuard-era systemd units
   and binaries forever, since most users update, they don't reinstall from
   scratch. Deferring this to a future task's *classification* work was
   conflating two different things: refusing/classifying mixed installs
   (genuinely Task 18.5) vs. sweeping away files that are unconditionally
   dead in every supported configuration (safe to do now, no classification
   needed).
2. "the version-skew claim is honestly assessed as not-yet-provable... Task
   18.7's job" - correctly honest, but the maintainer's point was that
   *some* concrete step should have been taken now (e.g. recording a marker)
   instead of zero, leaving the rest for Task 18.7's fuller doctor
   integration (PATH conflicts, capabilities, etc.).

Both were fixed the same day, alongside the Task 18.3 AmneziaWG UX addendum:

### Legacy cleanup moved to `lib/runtime.sh`, now runs on every install/update

`remove_legacy_runtime_files()` moved from `uninstall.sh` into
`lib/runtime.sh`, next to `remove_legacy_systemd_units` calls, both now
invoked unconditionally inside `install_runtime_files()` - the function
already shared by `install.sh` and `update.sh`. This means every install and
every update now sweeps the seven AdGuard-era systemd units and four legacy
binaries/dispatcher, not only a full `uninstall.sh` run. `uninstall.sh` now
sources `lib/runtime.sh` and still calls the same two functions explicitly
in its own removal sequence (unchanged behavior there, just a shared
definition instead of a duplicated one).

### Installed/source version marker implemented now

New `lib/version_marker.sh`:

- `record_installed_version()`: writes `commit=<git rev-parse HEAD>` and
  `installed_at=<UTC timestamp>` to
  `${WATCHDOGVPN_CONFIG_DIR:-/etc/watchdogvpn}/installed-version`. Called
  automatically at the end of `install_python_package_tree()` (in
  `lib/runtime.sh`), so both `install.sh` and `update.sh` record it without
  extra wiring. Skips writing under `--dry-run` (prints
  `[DRY-RUN] record installed version marker ...` instead), verified not to
  create a file in that mode.
- `installed_version_commit()` / `installed_version_timestamp()`: read the
  marker.
- `source_checkout_commit()`: `git -C "$ROOT_DIR" rev-parse HEAD`, i.e. the
  commit of whatever checkout is currently running `doctor.sh`.

`doctor.sh` gained an "Installed/Source Version Skew" section: `OK` if the
marker's commit matches the current checkout's `HEAD`; `WARN` with both
hashes and a `run ./update.sh` hint if they differ; `info` (not a failure)
if no marker exists yet (older install, pre-dating this feature) or
`doctor.sh` is not being run from inside a git checkout.

This does not close the full Task 18.7 scope (PATH conflicts, capability
reporting, systemd unit status, legacy-wrapper detection all remain there),
but "is the installed runtime the same commit as this checkout" - the core
of what Task 18.1/18.2 originally flagged as unprovable - is now answered
directly instead of deferred to zero.

## Tests

- Restored (and generalized) the regression coverage silently deleted in
  `59f4260`, in `tests/unit/test_install_security_contracts.sh`:
  assertions that `SYSTEMD_LEGACY_UNITS`/`remove_legacy_systemd_units()`
  exist and target the AdGuard-era unit names, that `uninstall.sh` calls
  `remove_legacy_systemd_units` and calls `remove_legacy_runtime_files`
  (definition now in `lib/runtime.sh`, shared) with the four historical
  binary/dispatcher paths, that purge-config/state also remove the legacy
  config/state paths, that legacy systemd cleanup runs in the correct order
  relative to current-unit cleanup, and that `install_runtime_files()` calls
  both legacy cleanup functions (so install/update get them too).
- New `tests/unit/test_version_marker.sh`: static wiring (install.sh/
  update.sh/doctor.sh all source `lib/version_marker.sh`; doctor reports the
  new section) plus real behavioral coverage - `record_installed_version`
  skips writing under `--dry-run` (asserted no file gets created), a marker
  written with this exact checkout's `HEAD` is read back as matching, and a
  stale/fake commit in the marker is correctly detected as a mismatch.

## Validation

- `bash -n uninstall.sh lib/systemd.sh lib/runtime.sh lib/version_marker.sh
  update.sh install.sh doctor.sh tests/unit/test_install_security_contracts.sh
  tests/unit/test_version_marker.sh` passed.
- `bash tests/unit/test_install_security_contracts.sh` passed.
- `bash tests/unit/test_version_marker.sh` passed.
- `bash tests/unit.sh` passed (18 shell test files, including both new/
  updated ones).
- `bash tests/syntax.sh` passed.
- `python3 -m unittest discover -s tests -p 'test_*.py'` passed: 1026 tests
  (unaffected - this task only touched shell scripts and docs).
- `git diff --check` passed.
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`
  passed.
- Manually ran a real `update.sh --dry-run --yes --skip-doctor` end to end on
  this development machine and confirmed, in order: the version marker
  dry-run line right after the Python package tree install line, then all
  seven legacy systemd units and four legacy files reported `[KEEP] absent`
  (this machine was never AdGuard-era contaminated, so nothing to remove -
  but the code path runs and targets the right names), then the normal
  current-product file replacement continuing unchanged.
- No VM was used; this closure is local-only, same as Task 18.1. Task 18.6
  still owes a real VM smoke test that provisions the seven legacy units and
  four legacy files on both a fresh-uninstall path and an update path, then
  proves both actually remove them on a real system.

## Deferred To Later Tasks

- **Task 18.3**: dependency installation, including sing-box checksum/
  signature pinning (already flagged in Task 18.1).
- **Task 18.4**: shared-state permission re-audit.
- **Task 18.5**: full mixed-install classification (fresh / clean update /
  legacy migration / mixed-inconsistent) and migration plan. The addendum
  above already makes `update.sh` sweep known-dead legacy artifacts
  unconditionally; 18.5 is the broader classify-and-explain-a-plan work,
  not "does update.sh clean anything up at all."
- **Task 18.6**: VM smoke test proving the cleanup functions actually work
  against a real legacy-contaminated install, on both the update and
  uninstall paths.
- **Task 18.7**: the remaining, broader doctor-integration scope - PATH
  conflicts, capability reporting, systemd unit status, legacy-wrapper
  detection, and the `doctor.sh` "Legacy Systemd Units" section naming fix.
  Version-skew detection itself (installed-vs-source marker) is no longer
  deferred - it shipped in this task's addendum.
- **Task 18.8**: installer audit closure.

## Acceptance

Task 18.2 closes when:

- [x] `install.sh`/`update.sh`/shipped systemd units are confirmed to use only
  current v2 entrypoints;
- [x] the one concrete v1-only-entrypoint gap found in Task 18.1
  (INV-18.1-001) is fixed with regression coverage, and runs on every
  install/update, not only a full uninstall;
- [x] the installed-vs-source version marker is implemented and reported by
  `doctor.sh`, not left as "not yet provable, deferred";
- [x] full local validation (shell + Python test suites, syntax, compileall,
  whitespace) passes;
- [x] real VM validation remains explicitly owed to Task 18.6, not claimed as
  done here.
