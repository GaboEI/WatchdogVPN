# Phase 17 Task 17.2 - Partial Export And Import

> Date: 2026-07-07
> Status: CLOSED - section-scoped backup create/restore implemented.

## Scope

Task 17.2 adds section-scoped backup creation and restore to
`config.backup_manager.BackupManager`.

It does not add the user-facing CLI yet. It also does not implement merge-mode
conflict semantics, replace confirmations, remote sync, encryption or uninstall
flow integration.

## Section Selection

`create_backup()` accepts a `sections` argument. When omitted, the manager
creates the normal full local backup. When provided, only the requested section
files are included and `manifest.json` records exactly those sections.

The manager loads only the selected section stores. A diagnostics-only export,
for example, does not read or lock settings, profiles, providers or metrics
files.

Supported section names:

- `settings`;
- `profiles`;
- `providers`;
- `provider-state`;
- `routing-rules`;
- `app-policy`;
- `node-groups`;
- `selection-state`;
- `dns-policy`;
- `metrics-policy`;
- `backup-policy`;
- `metadata`;
- `diagnostics`.

Unknown, duplicate or empty section selections are rejected.

## Partial Restore

`restore_backup()` accepts a `sections` argument. When omitted, it restores all
sections present in the backup. When provided, it applies only the requested
sections.

The restore path still:

- validates the whole backup before mutation;
- creates a pre-restore backup;
- snapshots current target files;
- rolls back if an apply step fails.

Partial restore refuses to run when the requested section is not present in the
backup.

## Diagnostics

Diagnostics are not included in normal backups. The `diagnostics` section is
included only when explicitly requested.

The manager accepts a caller-provided diagnostics payload and stores it in
`diagnostics.json` with `included_by_explicit_request=true`. This keeps support
exports separate from normal backup behavior.

## Metrics

Metrics remain policy-only. `metrics-policy` never includes metrics buckets,
history or counters.

## Deferred Work

The following remain later Phase 17 work:

- CLI wiring;
- merge-mode conflict behavior;
- replace-mode confirmation;
- bounded auto-backup retention;
- backup encryption;
- WebDAV/LAN sync;
- uninstall flow integration.

## Validation

Tests cover:

- partial backup includes only requested sections;
- manifest section list matches selected sections;
- default backups exclude diagnostics;
- diagnostics are included only by explicit request;
- diagnostics-only export does not touch unrequested stores;
- partial restore applies only requested sections;
- partial restore rejects missing requested sections;
- unknown and duplicate section selections are rejected.

Commands run:

- `python3 -m unittest tests.test_backup_manager`;
- `python3 -m unittest tests.test_backup_manager tests.test_config_storage tests.test_metrics_store`;
- `python3 -m unittest discover -s tests -p 'test_*.py'`;
- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `git diff --check`;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`.
