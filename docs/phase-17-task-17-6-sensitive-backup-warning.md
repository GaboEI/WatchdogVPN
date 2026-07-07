# Phase 17 Task 17.6 - Sensitive Backup Warning And Encryption Decision

> Date: 2026-07-07
> Status: CLOSED - sensitive warning implemented; encryption deferred to Task 17.7.

## Scope

Task 17.6 defines the sensitive-data posture for backup exports.

Backups remained plaintext ZIP files in this task. Encryption was intentionally
deferred to the dedicated Phase 17 Task 17.7 reviewed encrypted backup format
work, because Task 17.6 did not yet have a reviewed cryptographic dependency,
key-derivation contract, recovery UX or documented encrypted backup format.

## Sensitive Warning

Every new backup manifest records:

- `sensitive=true`;
- `sensitive_warning`;
- `encryption.enabled=false`;
- `encryption.supported=false` at Task 17.6 close;
- `encryption.format=null`.

The warning states that backups may contain:

- private keys;
- passwords;
- provider tokens;
- subscription URLs;
- routing policy;
- app policy;
- local selection state.

Future user-facing backup commands must display this warning before writing or
sharing an export.

## Encryption Decision

At Task 17.6 close, `BackupManager.create_backup(..., encrypt=True)` was
rejected with a clear validation error. `inspect_backup()` also rejected backups
whose plaintext manifest claimed `encryption.enabled=true`.

This prevents callers from assuming that encrypted backups are supported by the
current format.

## Restore Safety

Plaintext backups remain restoreable. Task 17.7 later defined and implemented
the encrypted container format.

## Deferred Work

The following remain later Phase 17 work:

- user-facing CLI wiring;
- CLI warning/confirmation UX;
- WebDAV/LAN sync;
- uninstall flow UX.

## Validation

Tests cover:

- backup manifests include the sensitive warning;
- Task 17.6 backup manifests declared encryption unsupported and disabled;
- Task 17.6 `create_backup(encrypt=True)` was rejected;
- Task 17.6 plaintext manifests declaring encrypted backups were rejected.

Commands run:

- `python3 -m unittest tests.test_backup_manager`;
- `python3 -m unittest tests.test_backup_manager tests.test_config_storage tests.test_metrics_store`;
- `python3 -m unittest discover -s tests -p 'test_*.py'`;
- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `git diff --check`;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`.
