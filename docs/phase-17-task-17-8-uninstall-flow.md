# Phase 17 Task 17.8 - Uninstall Flow

> Date: 2026-07-07
> Status: CLOSED - CLI uninstall flow implemented.

## Scope

Task 17.8 adds a user-facing `watchdog uninstall` flow on top of the existing
conservative `uninstall.sh` script.

The command locates `uninstall.sh` from `--uninstall-script`, the
`WATCHDOGVPN_UNINSTALL_SCRIPT` override, `WATCHDOGVPN_REPO_DIR`, the current
working directory or the source/package root. Installed users should run it from
the WatchdogVPN checkout or set `WATCHDOGVPN_REPO_DIR` when the checkout is not
the current directory.

The flow offers three explicit modes:

- keep local data;
- export a backup first, then uninstall product files;
- export a pre-delete backup, then uninstall and delete WatchdogVPN data.

## Safety Contract

`watchdog uninstall --keep-data --yes` preserves WatchdogVPN config, logs and
shared runtime state and invokes `uninstall.sh` without purge flags.

`watchdog uninstall --backup-first --backup-output PATH --yes` creates a
WatchdogVPN backup at `PATH`, then invokes `uninstall.sh` without purge flags.

`watchdog uninstall --delete-all-data --confirm-delete DELETE --backup-output
PATH --yes` creates a `pre-uninstall-delete` backup at `PATH`, then invokes
`uninstall.sh` with `--purge-config --purge-logs --purge-state`.

Backup output paths inside WatchdogVPN-owned paths are rejected. This prevents a
pre-delete backup from being removed by the same delete-all-data operation.

Encrypted backups are supported through:

```sh
watchdog uninstall --backup-first \
  --backup-output ~/watchdogvpn-backup.zip \
  --encrypt-backup \
  --backup-password-env WATCHDOGVPN_BACKUP_PASSWORD \
  --yes
```

The password is read from the named environment variable and is not stored.

## Script Hardening

`uninstall.sh` now accepts `--confirm-delete DELETE`. If any purge flag is used
without the literal confirmation, the script prompts interactively or fails in
non-interactive mode.

The script still removes only WatchdogVPN product files by default and preserves
config, logs and shared runtime state unless purge flags are present.

## Validation

Tests cover:

- `watchdog uninstall` rejects non-interactive calls without an explicit mode;
- keep-data mode calls `uninstall.sh` without purge flags;
- backup-first mode creates a backup before uninstall;
- delete-all-data requires `--confirm-delete DELETE`;
- delete-all-data creates a `pre-uninstall-delete` backup and passes purge
  flags plus confirmation to `uninstall.sh`;
- backup output paths inside WatchdogVPN data paths are rejected;
- encrypted uninstall backups require a password and restore through
  `BackupManager`;
- `uninstall.sh` contains the DELETE confirmation guard.

Commands run:

- `python3 -m unittest tests.test_cli_uninstall_commands` -> 8 tests OK;
- `python3 -m unittest tests.test_cli_uninstall_commands tests.test_backup_manager tests.test_cli_config_commands tests.test_cli_stats_commands` -> 49 tests OK;
- `python3 -m unittest discover -s tests -p 'test_*.py'` -> 1025 tests OK;
- `bash tests/unit/test_install_security_contracts.sh` -> passed;
- `bash tests/unit.sh` -> passed;
- `bash tests/syntax.sh` -> passed;
- `bash -n uninstall.sh && python3 -m py_compile cli/main.py tests/test_cli_uninstall_commands.py` -> passed;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .` -> passed.
