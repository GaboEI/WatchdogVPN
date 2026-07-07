# Phase 17 Task 17.7 - Reviewed Encrypted Backup Format

> Date: 2026-07-07
> Status: CLOSED - encrypted backup format implemented.

## Scope

Task 17.7 defines and implements the first reviewed encrypted WatchdogVPN
backup format. Plaintext backups remain supported for local manual workflows,
but callers can now request encrypted archives with an explicit passphrase.

## Format

Encrypted backups are ZIP files with exactly two top-level entries:

- `manifest.json`: public metadata needed to identify and validate the
  encrypted archive;
- `payload.bin`: authenticated ciphertext.

`payload.bin` contains a complete normal WatchdogVPN plaintext backup ZIP after
encryption. Restore decrypts the payload first, then runs the existing plaintext
backup validation and restore path. This avoids a parallel restore parser and
keeps section validation, path traversal checks, schema checks and rollback
behavior shared with plaintext backups.

## Cryptography

The encrypted format uses the reviewed `cryptography` Python package:

- algorithm: AES-256-GCM;
- KDF: scrypt;
- scrypt parameters: `n=16384`, `r=8`, `p=1`, `length=32`;
- salt length: 16 bytes;
- AES-GCM nonce length: 12 bytes;
- authenticated additional data: `WatchdogVPN encrypted backup v1`;
- format identifier: `watchdogvpn-backup-aesgcm-scrypt-v1`.

The passphrase is supplied by the caller at backup creation or restore time. It
is not written to disk, not stored in the manifest and not recoverable.

## Manifest Contract

The public encrypted manifest records:

- backup schema version, product, creation time and reason;
- selected section names and section file mapping;
- the sensitive-data warning;
- encryption format, algorithm, KDF parameters, salt, nonce and AAD.

The public manifest intentionally exposes section names. It does not expose
section contents, profiles, providers, keys, tokens, policy details or selection
state values.

## Restore Behavior

Encrypted backup inspection and restore require the password. Missing password,
wrong password, payload authentication failure, malformed ciphertext,
unsupported format metadata or unsupported KDF parameters fail with
`BackupValidationError` before any local configuration mutation.

Successful restore decrypts the inner ZIP and then uses the same validation,
replace confirmation, merge restrictions and rollback behavior as plaintext
backups. When the source backup is encrypted, the pre-restore auto-backup is
also encrypted with the same passphrase so the restore flow does not create an
unexpected plaintext copy of existing local sensitive data.

## Bug Fixed During Implementation

Encrypted restore initially reused the default plaintext auto-backup path for
the pre-restore snapshot. That would have created an unexpected plaintext copy
of existing local sensitive data during an encrypted restore. The restore path
now marks parsed encrypted backups and creates the pre-restore auto-backup with
the same encryption password.

## Limitations

There is no password recovery. If the passphrase is lost, the encrypted backup
cannot be restored.

Encrypted backup support lives in `BackupManager` and is used by backup/uninstall
flows. Automatic remote sync is deferred by Phase 17 Task 17.9 / ADR 0006.

Remote or LAN sync must not upload plaintext backups silently. Remote sync must
use encrypted backups or document a stronger reviewed security contract before
shipping.

## Validation

Tests cover:

- encrypted backup creation;
- encrypted outer ZIP shape and hidden section files;
- decryption and inspection with the correct password;
- restore with the correct password;
- encrypted pre-restore auto-backup creation during encrypted restore;
- missing password rejection;
- wrong password/authentication failure;
- corrupt payload rejection;
- unsupported encrypted format rejection.

Commands run:

- `python3 -m unittest tests.test_backup_manager` -> 26 tests OK;
- `python3 -m unittest tests.test_backup_manager tests.test_config_storage tests.test_metrics_store` -> 69 tests OK;
- `python3 -m unittest discover -s tests -p 'test_*.py'` -> 1017 tests OK;
- `bash tests/unit.sh` -> passed;
- `bash tests/syntax.sh` -> passed;
- `git diff --check` -> passed;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .` -> passed.

Additional local-machine validation:

- ran an isolated temporary-config validation on the development machine;
- created an encrypted backup containing a profile secret and provider token;
- verified the outer ZIP exposes only `manifest.json` and `payload.bin`;
- verified plaintext secret/token bytes are not present in `payload.bin`;
- verified inspect without password fails;
- verified inspect with wrong password fails;
- verified inspect with the correct password succeeds;
- removed the profile and restored from the encrypted backup;
- verified restore recreated the profile;
- verified the restore-created pre-restore backup also requires the password.
