# Phase 18 Task 18.7 - Installer Doctor Integration

Date: 2026-07-07
Status: closed

## Scope

Task 18.7 completes the installer-facing doctor integration for runtime
dependencies, service state, permissions, capabilities, installed/source
version skew, PATH conflicts, legacy wrappers, systemd unit state, and recovery
hints.

## Implementation

`doctor.sh` remains read-only and non-privileged. It now:

- sources the shared systemd/runtime installer metadata so current and legacy
  unit lists stay aligned with install/update/uninstall behavior;
- reports an explicit `PATH Entrypoints` section for `watchdog`, `watchdogvpn`,
  `watchdogvpn-daemon`, `vpnctl`, and `vpn_truth_check`;
- warns when an earlier PATH hit shadows the expected `/usr/local/bin`
  entrypoint and prints a recovery hint;
- reports an incomplete existing installation, rather than only listing files
  that happen to exist;
- renames the previous misleading `Legacy Systemd Units` section into
  `Current Product Systemd Units`;
- adds a separate `Legacy Product Artifacts` section for the actual
  known-dead systemd units, runtime wrappers, dispatcher script, and legacy
  user wrapper directory;
- preserves the existing installed/source version marker check and upgrades
  its remediation wording into a recovery hint;
- adds recovery hints for missing service user, inactive/missing daemon unit,
  missing systemd capability configuration, effective capability mismatch,
  socket reachability/permission problems, missing current units, and legacy
  artifacts.

## Local Doctor Evidence

A read-only local `./doctor.sh` run completed with `FAIL=0` and `Result: WARN`.
The warnings were useful diagnostics:

- installed/source version skew: installed runtime marker was
  `3996f53f96ac553208514e6ae95e9f289ae97345`, while the checkout was
  `4e4f8dbbfe14d6eecd9a62fce7d8bda2648dfd37`;
- the local installed runtime was incomplete for current product files
  `/usr/local/bin/vpn_domain_bypass_rescue` and
  `/usr/local/bin/watchdog_panic`;
- the local daemon was inactive/disabled and its socket was absent;
- truth state was `DOWN`, expected without a live WatchdogVPN tunnel.

No real `install.sh` or `update.sh` was run on the maintainer workstation for
this task. A real update would mutate installed runtime files and systemd state;
that kind of validation remains reserved for explicit VM or maintainer-approved
live-machine runs.

## Validation

Passed:

- `./doctor.sh` (read-only, `FAIL=0`, `Result: WARN` due local installed-state
  findings above);
- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `python3 -m unittest discover -s tests -p 'test_*.py'`;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`;
- `git diff --check`.

Regression coverage was added to `tests/unit/test_doctor_daemon_contract.sh` so
the doctor keeps reporting PATH diagnostics, current systemd units, real legacy
artifacts, incomplete installs, capability/service/socket recovery hints, and
remains read-only.

## Follow-Up

No unresolved Task 18.7 debt remains. Task 18.8 should consume the richer
doctor output during the final installer audit closure, including the local
version-skew/incomplete-install evidence and the successful Task 18.6 VM smoke
results.
