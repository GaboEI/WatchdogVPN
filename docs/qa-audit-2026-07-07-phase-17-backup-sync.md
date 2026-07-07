# QA Audit - Phase 17 Backup, Restore And Safe Sync

> Date: 2026-07-07
> Scope: Phase 17 Tasks 17.1 through 17.10
> Status: CLOSED - no unresolved HIGH or MEDIUM findings.

## Scope

This audit covers the Phase 17 backup/sync surface:

- versioned backup creation and manifest contract;
- section-scoped export/import;
- replace and merge restore behavior;
- selection-state and provider-state restore behavior;
- auto-backup reasons and bounded retention;
- sensitive-data warnings and encrypted backup format;
- uninstall backup flow;
- remote-sync threat-model decision.

## Audit Matrix

| Area | Result | Notes |
| --- | --- | --- |
| Versioned backup manifest | PASS | Backups carry schema/product/section metadata and sensitive warning. |
| ZIP entry safety | PASS | Duplicate entries, path traversal, absolute paths, nested paths and unsupported entries are rejected. |
| Corrupted ZIP handling | PASS | Invalid ZIP and invalid JSON are rejected with `BackupValidationError`. |
| Section validation | PASS | Sections are validated through local model/store validators before mutation. |
| Replace restore confirmation | PASS | Replace restore requires `RESTORE-WATCHDOGVPN-BACKUP`. |
| Restore rollback | PASS after AUD-P17-001 | File snapshots are restored on apply failure, including removal of rule files created during a failed restore. |
| Merge restore scope | PASS | Merge is limited to routing rules, app policy and node groups. Unsupported merge sections are rejected. |
| Provider-state restore | PASS | Provider state updates existing providers only and does not create/remove providers or change provider definitions. |
| Selection-state restore | PASS | Active profile references must exist after selected restore sections are applied. |
| Metrics boundary | PASS | Normal backups include metrics policy only, not buckets/history/counters. |
| Diagnostics boundary | PASS | Diagnostics are omitted by default and included only when explicitly requested. |
| Auto-backup retention | PASS | Auto-backup reasons are bounded and pruning leaves manual backups untouched. |
| Sensitive warning | PASS | Backup manifests identify backups as sensitive. |
| Encrypted backup format | PASS | AES-256-GCM plus scrypt encrypted container implemented; wrong password/corruption/unsupported format fail before mutation. |
| Encrypted restore pre-backup | PASS | Encrypted restore creates an encrypted pre-restore backup with the same passphrase. |
| Uninstall flow | PASS | `watchdog uninstall` supports keep-data, backup-first and delete-all-data modes; delete-all-data requires `DELETE`. |
| Uninstall backup output | PASS | Uninstall backup outputs inside WatchdogVPN-owned paths are rejected. |
| Remote sync | PASS | Automatic WebDAV/LAN/remote sync is explicitly deferred by ADR 0006; no upload/download command or credential storage is added. |
| LAN exposure | PASS | No LAN listener, peer discovery, LAN proxy or gateway behavior is added in Phase 17. |

## Findings

### AUD-P17-001 - MEDIUM - Fixed

**Area:** Restore rollback.

**Issue:** A failed restore could leave newly-created rule group JSON files in
`rules/` if restore wrote routing rules and then failed later while applying a
different section. The snapshot restored existing rule files but did not remove
rule files that did not exist before the restore attempt.

**Impact:** Local routing policy could retain an imported rule group after a
failed restore. This violates the restore rollback guarantee.

**Fix:** `BackupManager._snapshot_targets()` now records the pre-restore rule
file set, and `_restore_snapshot()` removes any current `rules/*.json` file not
present in that set before restoring snapshot contents.

**Validation:** Added
`test_restore_rolls_back_new_rule_files_when_later_apply_fails`.

## Residual Risk

Automatic remote sync is not implemented. ZIP export/import remains the
supported portable workflow. Future remote sync must update or supersede ADR
0006 and define encrypted-only upload, credential storage, conflict handling,
partial-transfer recovery and stale archive detection.

LAN sync and LAN gateway behavior remain outside Phase 17. Any LAN exposure is
gated by ADR 0004 and Phase 20.

## Validation

Focused validation:

- `python3 -m unittest tests.test_backup_manager` -> 27 tests OK.
- `python3 -m py_compile config/backup_manager.py tests/test_backup_manager.py` -> passed.
- `rg -n "WebDAV|webdav|remote sync|upload|download|LAN sync|peer discovery|payload.bin|confirm-delete|pre-uninstall-delete|RESTORE-WATCHDOGVPN-BACKUP|path traversal|duplicate entries" config cli tests docs README.md ROADMAP.md uninstall.sh -g "*.*"` -> reviewed expected references.

Full validation is recorded in the Phase 17 Task 17.10 master-plan closure.

Final validation:

- `python3 -m unittest tests.test_backup_manager tests.test_cli_uninstall_commands tests.test_config_storage tests.test_metrics_store` -> 78 tests OK.
- `python3 -m unittest discover -s tests -p 'test_*.py'` -> 1026 tests OK.
- `bash tests/unit.sh` -> passed.
- `bash tests/syntax.sh` -> passed.
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .` -> passed.
