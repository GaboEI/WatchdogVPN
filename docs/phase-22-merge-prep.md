# Phase 22 Merge Preparation

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: merge-ready, pending explicit maintainer merge approval

## Scope

This document records merge preparation for Phase 22 Full CLI Interface. It
does not merge `phase-22-full-cli-interface` into `main`.

The Phase 22 branch gate remains in force:

- merge back to `main` requires explicit maintainer approval;
- merge must use a merge commit;
- Phase 22 history must not be squashed.

## Branch State

Prepared branch:

```text
phase-22-full-cli-interface
```

Expected merge base target:

```text
origin/main = 9869a7105067d4a625c9e5a3249a5bb9ae57a419
```

Phase 22 final implementation head at merge-prep start:

```text
51fbea9cab3a5aed30da676543f9bbbbf5c179da
```

## Completed Work

Phase 22 completed:

- branch gate;
- CLI architecture audit;
- connection lifecycle CLI;
- profile/provider CLI;
- policy CLI;
- DNS/stats/backup/uninstall CLI;
- setup/doctor CLI;
- CLI audit closure.

Final audit report:

```text
docs/qa-audit-2026-07-09-phase-22-full-cli-interface.md
```

Task closure:

```text
docs/phase-22-task-22-7-cli-audit-closure.md
```

## Gate Checklist

- [x] Dedicated Phase 22 branch used for all Phase 22 work.
- [x] `main` was not modified during Phase 22 branch work.
- [x] All Phase 22 task groups are complete.
- [x] All command groups in scope are implemented.
- [x] JSON output contracts are documented and validated.
- [x] Human output was reviewed for operator safety and recovery hints.
- [x] Mutations validate input and create backups where the product contract
  requires backups.
- [x] Setup wizard exists and supports dry-run/confirmed operation.
- [x] Doctor exists in the Python CLI as a thin wrapper over `doctor.sh`.
- [x] `watchdog version` exists in the Python CLI.
- [x] `watchdog panic sleep|wake|status` exists as a thin passthrough to
  `bin/watchdog_panic`.
- [x] No `shell=True` exists in the CLI layer.
- [x] No unresolved HIGH, MEDIUM, LOW or INFO findings remain for Phase 22.
- [x] No known Phase 22 bugs or technical debt remain.
- [x] Docs, external master plan and external memory are updated.
- [x] Runtime/network/system-state behavior was not changed by merge-prep.
- [x] VM/lab validation was not required for merge-prep because it changed
  documentation only.

## Runtime Boundary

Merge-prep changes documentation and memory only. It does not change daemon
runtime behavior, connect/disconnect behavior, DNS runtime behavior, routes,
firewall behavior, forwarding, system proxy behavior, provider refresh,
installed package state or external network behavior.

## Validation

Final merge-prep validation:

```text
python3 -m unittest tests.test_cli_version_panic_commands tests.test_cli_profile_commands tests.test_cli_provider_commands tests.test_cli_rules_commands tests.test_cli_app_policy_commands tests.test_cli_node_group_commands tests.test_cli_dns_commands tests.test_cli_stats_commands tests.test_cli_backup_commands tests.test_cli_uninstall_commands tests.test_cli_setup_doctor_commands
OK - 113 tests

bash tests/unit.sh
OK

bash tests/syntax.sh
OK

python3 -m unittest discover -s tests -p 'test_*.py'
OK - 1212 tests, 1 skipped

git diff --check
OK

PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
OK

rg -n "shell=True|subprocess\." cli/main.py
OK - no shell=True; subprocess calls remain argv-list form
```

## Merge Instruction

Do not merge this branch until the maintainer explicitly approves the merge
step. When approved, merge `phase-22-full-cli-interface` into `main` with a
merge commit, not a squash commit.
