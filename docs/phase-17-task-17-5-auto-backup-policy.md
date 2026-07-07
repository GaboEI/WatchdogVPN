# Phase 17 Task 17.5 - Auto-Backup Policy

> Date: 2026-07-07
> Status: CLOSED - manager-level auto-backup policy and retention implemented.

## Scope

Task 17.5 defines the low-level auto-backup policy in
`config.backup_manager.BackupManager`.

It does not add user-facing CLI commands or uninstall flow integration yet.
Instead, it provides explicit manager APIs for future CLI/install/uninstall code
to call before risky mutations. Plaintext sensitive-warning behavior was added
later in Task 17.6. Encrypted backup format support was added later in Task
17.7.

## Auto-Backup Reasons

The manager supports these auto-backup reasons:

- `pre-restore`;
- `pre-replace-import`;
- `pre-destructive-remove`;
- `pre-uninstall-delete`.

Unknown reasons are rejected. This keeps auto-backups discoverable by filename
and prevents arbitrary callers from creating unmanaged backup classes.

## Restore Integration

`restore_backup()` now creates auto-backups through `create_auto_backup()`:

- replace restore uses `pre-replace-import`;
- merge restore uses `pre-restore`.

Both paths still validate the backup before creating the pre-mutation backup,
snapshot current target files, and roll back on apply failure.

## Retention

Auto-backup retention defaults to 10 backups. The manager exposes:

- `create_auto_backup(reason=..., max_backups=...)`;
- `list_auto_backups()`;
- `prune_auto_backups(max_backups=...)`.

Retention applies only to recognized auto-backup files. Manual backups are not
deleted by auto-backup pruning.

`max_backups` must be an integer from 1 to 100. The exported
`backup-policy.json` records the default retention policy.

## Filename Safety

Default backup paths are unique even when multiple backups are created in the
same second. The manager adds numeric suffixes instead of overwriting an
existing backup.

## Deferred Work

The following remain later Phase 17 work:

- user-facing CLI wiring;
- CLI copy and confirmation UX;
- connecting destructive profile/provider/rule/node-group commands to
  `create_auto_backup(reason="pre-destructive-remove")`;
- connecting uninstall deletion to
  `create_auto_backup(reason="pre-uninstall-delete")`;
- WebDAV/LAN sync;
- uninstall flow UX.

## Validation

Tests cover:

- restore creates a `pre-replace-import` backup for replace mode;
- default backup paths remain unique within the same second;
- auto-backup retention prunes old auto-backups;
- manual backups are not removed by auto-backup retention;
- auto-backup reason validation rejects unknown reasons;
- retention validation rejects invalid `max_backups`;
- backup-policy validation rejects invalid retention.

Commands run:

- `python3 -m unittest tests.test_backup_manager`;
- `python3 -m unittest tests.test_backup_manager tests.test_config_storage tests.test_cli_provider_commands tests.test_cli_profile_commands tests.test_cli_rules_commands tests.test_rule_store tests.test_node_groups_store`;
- `python3 -m unittest discover -s tests -p 'test_*.py'`;
- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `git diff --check`;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`.
