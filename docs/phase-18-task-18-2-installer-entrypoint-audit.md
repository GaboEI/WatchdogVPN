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
the same v2 runtime/source" is **not fully provable today**: Task 18.1 found
live evidence that an installed runtime can silently drift behind the source
checkout with no detectable version marker. That gap is real but is Task
18.7's job (doctor integration / version-skew detection), not this task's -
implementing it here would require inventing the install-time marker
mechanism without the doctor-side reporting work it depends on, which is out
of scope for an entrypoint audit.

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

- `update.sh` does not run legacy cleanup. It only replaces currently-shipped
  product files; teaching it to detect and clean arbitrary historical state
  is the mixed-install classification and migration-plan work explicitly
  assigned to Task 18.5, not this task.
- No new CLI flag was added. The legacy paths reuse the existing
  `--purge-config`/`--purge-state` gates instead.

## Tests

- Restored (and generalized) the regression coverage silently deleted in
  `59f4260`, in `tests/unit/test_install_security_contracts.sh`:
  assertions that `SYSTEMD_LEGACY_UNITS`/`remove_legacy_systemd_units()`
  exist and target the AdGuard-era unit names, that `uninstall.sh` calls
  `remove_legacy_systemd_units` and defines `remove_legacy_runtime_files()`
  with the four historical binary/dispatcher paths, that purge-config/state
  also remove the legacy config/state paths, and that legacy systemd cleanup
  runs in the correct order relative to current-unit cleanup.

## Validation

- `bash -n uninstall.sh lib/systemd.sh tests/unit/test_install_security_contracts.sh`
  passed.
- `bash tests/unit/test_install_security_contracts.sh` passed.
- `bash tests/unit.sh` passed (16 shell test files, including the updated
  one).
- `bash tests/syntax.sh` passed.
- `python3 -m unittest discover -s tests -p 'test_*.py'` passed: 1026 tests
  (unaffected - this task only touched shell scripts and docs).
- `git diff --check` passed.
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`
  passed.
- No VM was used; this closure is local-only, same as Task 18.1. Task 18.6
  still owes a real VM smoke test that provisions the seven legacy units and
  four legacy files, then proves `uninstall.sh` actually removes them on a
  real system (dry-run and static assertions only prove the code path exists
  and targets the right names).

## Deferred To Later Tasks

- **Task 18.3**: dependency installation, including sing-box checksum/
  signature pinning (already flagged in Task 18.1).
- **Task 18.4**: shared-state permission re-audit.
- **Task 18.5**: mixed-install classification and migration plan; should also
  decide whether `update.sh` (not just `uninstall.sh`) should surface legacy
  contamination during a non-destructive update, rather than only cleaning it
  up on full uninstall.
- **Task 18.6**: VM smoke test proving this task's cleanup functions actually
  work against a real legacy-contaminated install.
- **Task 18.7**: version-skew detection (installed-vs-source marker) and the
  `doctor.sh` "Legacy Systemd Units" section naming fix, both noted in Task
  18.1 and left open here.
- **Task 18.8**: installer audit closure.

## Acceptance

Task 18.2 closes when:

- [x] `install.sh`/`update.sh`/shipped systemd units are confirmed to use only
  current v2 entrypoints;
- [x] the one concrete v1-only-entrypoint gap found in Task 18.1
  (INV-18.1-001) is fixed with regression coverage;
- [x] the version-skew claim is honestly assessed as not-yet-provable and
  explicitly deferred to Task 18.7, rather than asserted without evidence;
- [x] full local validation (shell + Python test suites, syntax, compileall,
  whitespace) passes;
- [x] real VM validation remains explicitly owed to Task 18.6, not claimed as
  done here.
