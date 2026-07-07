# QA Audit - Phase 18 Installer v2 Migration & Runtime Dependencies

Date: 2026-07-07
Status: closed

## Scope

This audit closes Phase 18 after Tasks 18.1 through 18.8. It reviewed:

- `install.sh`, `update.sh`, `uninstall.sh`, `doctor.sh`;
- `lib/common.sh`, `lib/install_files.sh`, `lib/install_preflight.sh`,
  `lib/runtime.sh`, `lib/systemd.sh`, `lib/version_marker.sh`;
- installer/unit/runtime tests under `tests/unit/`;
- VM evidence from `tests/vm/phase18_6_vm_smoke.sh`;
- Phase 18 task documentation and memory handoff notes.

The audit focused on installation, update, uninstall, permissions, systemd,
runtime binary handling, legacy contamination detection, mixed-install refusal,
doctor integration, and VM smoke evidence.

## Findings

### AUD-P18-001 - Unexpected installer/update failure lacked recovery guidance

Severity: MEDIUM
Status: RESOLVED

Scenario: `install.sh` and `update.sh` use `set -euo pipefail`. If an unexpected
command failed after backups had started, the script could exit without a clear
recovery block explaining preserved data, backup location, and next diagnostic
steps.

Impact: User configuration/state/logs were still designed to be preserved, and
product files were backed up before replacement/removal where possible, but a
failed update could leave the operator without explicit recovery instructions at
the highest-stress moment.

Fix: Added `print_installer_failure_recovery()` and `install_failure_trap()` in
`lib/common.sh`, then installed an `ERR` trap in `install.sh` and `update.sh`.
The recovery block states preserved config/state/log paths, the backup root, and
the next steps: inspect the error, run `./doctor.sh`, then rerun
`./update.sh` or `./install.sh` after fixing the reported issue.

Coverage: `tests/unit/test_install_security_contracts.sh` now asserts the shared
recovery function and both script traps. A focused subshell smoke verified the
trap prints the expected recovery block on failure.

## Audit Result

No unresolved HIGH or MEDIUM findings remain.

## Evidence Summary

- Mixed-install preflight classifies fresh install, clean update, legacy
  migration, mixed-inconsistent, and unsupported states before mutation.
- Mixed/inconsistent and unsupported states fail closed unless a safe documented
  repair path exists.
- Known-dead legacy product units/wrappers are swept on install/update/uninstall;
  legacy user data is preserved by default.
- Shared state migration creates `/var/lib/watchdogvpn/.migrated` even on fresh
  installs with no legacy user data, so CLI and daemon converge on shared state.
- Shared state permissions are repaired to daemon/user group-writable setgid
  form.
- `install.sh` and `update.sh` install/check runtime dependencies, including
  python cryptography, sing-box, optional Cloak, and guided AmneziaWG setup.
- The installed version marker records the source commit and doctor reports
  installed/source skew.
- Doctor reports dependency state, service state, permissions/capabilities,
  systemd unit state, PATH conflicts, legacy artifacts, incomplete installs,
  and recovery hints while remaining read-only.
- Uninstall preserves config/logs/state by default, requires explicit
  confirmation for data purge, runs kill-switch cleanup, runs domain-bypass
  routing rescue, and runs DNS rescue before removing runtime files.
- The Phase 18.6 VM smoke validated fresh install and non-destructive update on
  a real VM. The final VM update preserved state/config hashes, kept daemon IPC
  healthy, matched installed/source version, resolved PATH entrypoints, removed
  planted legacy artifacts, confirmed backups, and doctor reported no `FAIL`.
- A full codebase search found no executable `shell=True` usage; only historical
  documentation mentions remained.

## Validation

Passed:

- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `python3 -m unittest discover -s tests -p 'test_*.py'`;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`;
- `git diff --check`;
- focused installer failure-trap smoke via a temporary failing subshell;
- `rg -n "shell=True" . --glob '!.git/**'` returned only historical
  documentation references, not executable code.

## Not Revalidated

No additional real install/update/uninstall was run on the maintainer
workstation during Task 18.8. Task 18.6 already supplied VM evidence for real
fresh install and real non-destructive update; live workstation mutation would
touch installed runtime files, systemd services, and potentially active network
state.
