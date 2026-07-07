# Phase 17 Task 17.10 - Backup/Sync Audit Closure

> Date: 2026-07-07
> Status: CLOSED - Phase 17 audit complete.

## Scope

Task 17.10 closes Phase 17 by auditing backup creation, restore rollback,
secret handling, path traversal, corrupted ZIP handling, restore behavior and
the remote-sync threat model.

The detailed audit is recorded in
[QA Audit - Phase 17 Backup, Restore And Safe Sync](qa-audit-2026-07-07-phase-17-backup-sync.md).

## Result

Phase 17 has no unresolved HIGH or MEDIUM findings.

One MEDIUM finding was found and fixed during closure:

- `AUD-P17-001`: failed restore could leave newly-created `rules/*.json` files
  behind after a later apply failure. Fixed by recording and restoring the
  pre-restore rule file set.

## Closure Notes

- Backup ZIP entry validation rejects path traversal, absolute paths, duplicate
  entries, nested paths and unsupported entries.
- Restore validates backup contents before mutation.
- Replace restore requires strong confirmation.
- Merge restore is intentionally limited to routing rules, app policy and node
  groups.
- Metrics history/counters are excluded from normal backups.
- Diagnostics are explicit-only.
- Encrypted backups authenticate payloads and reject wrong passwords,
  corruption and unsupported formats before mutation.
- Uninstall delete-all-data requires `DELETE` and writes backups outside
  WatchdogVPN-owned paths.
- Automatic remote sync is deferred by ADR 0006.
- No LAN listener or upload/download command is introduced in Phase 17.

## Validation

Focused validation:

- `python3 -m unittest tests.test_backup_manager` -> 27 tests OK;
- `python3 -m py_compile config/backup_manager.py tests/test_backup_manager.py` -> passed;
- backup/sync reference audit with `rg` -> reviewed expected references.

Full validation is recorded in the master plan for Task 17.10.

Final validation:

- `python3 -m unittest tests.test_backup_manager tests.test_cli_uninstall_commands tests.test_config_storage tests.test_metrics_store` -> 78 tests OK;
- `python3 -m unittest discover -s tests -p 'test_*.py'` -> 1026 tests OK;
- `bash tests/unit.sh` -> passed;
- `bash tests/syntax.sh` -> passed;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .` -> passed.
