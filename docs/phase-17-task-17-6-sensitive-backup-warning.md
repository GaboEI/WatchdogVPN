# Phase 17 Task 17.6 - Sensitive Backup Warning And Encryption Decision

> Date: 2026-07-07
> Status: CLOSED - sensitive warning implemented; encryption explicitly not implemented.

## Scope

Task 17.6 defines the sensitive-data posture for backup exports.

Backups remain plaintext ZIP files in this task. Encryption is intentionally
deferred to the dedicated Phase 17 Task 17.7 reviewed encrypted backup format
work, because the project does not yet have a reviewed cryptographic library
dependency, key-derivation contract, recovery UX or documented encrypted backup
format.

## Sensitive Warning

Every new backup manifest records:

- `sensitive=true`;
- `sensitive_warning`;
- `encryption.enabled=false`;
- `encryption.supported=false`;
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

`BackupManager.create_backup(..., encrypt=True)` is rejected with a clear
validation error. `inspect_backup()` also rejects backups whose manifest claims
`encryption.enabled=true`.

This prevents callers from assuming that encrypted backups are supported by the
current format.

## Restore Safety

Plaintext backups remain restoreable. Encrypted backups are not accepted until
Task 17.7 defines and implements the encrypted format.

## Deferred Work

The following remain later Phase 17 work:

- user-facing CLI wiring;
- CLI warning/confirmation UX;
- Phase 17 Task 17.7 reviewed encrypted backup format;
- WebDAV/LAN sync;
- uninstall flow UX.

## Validation

Tests cover:

- backup manifests include the sensitive warning;
- backup manifests declare encryption unsupported and disabled;
- `create_backup(encrypt=True)` is rejected;
- manifests declaring encrypted backups are rejected.

Commands run:

- `python3 -m unittest tests.test_backup_manager`;
- `python3 -m unittest tests.test_backup_manager tests.test_config_storage tests.test_metrics_store`;
- `python3 -m unittest discover -s tests -p 'test_*.py'`;
- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `git diff --check`;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`.
