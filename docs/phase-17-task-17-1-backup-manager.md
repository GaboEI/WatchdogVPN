# Phase 17 Task 17.1 - Backup Manager

> Date: 2026-07-07
> Status: CLOSED - versioned ZIP backup manager implemented.

## Scope

Task 17.1 introduces the low-level backup/restore manager. It does not add a
user-facing CLI yet, and it does not implement merge-mode imports, remote sync,
encryption or uninstall UX.

The implemented manager is `config.backup_manager.BackupManager`.

## Backup Format

Backups are ZIP files with one manifest and versioned JSON section files:

```text
watchdogvpn-backup.zip
|-- manifest.json
|-- settings.json
|-- profiles.json
|-- providers.json
|-- provider-state.json
|-- routing-rules.json
|-- app-policy.json
|-- node-groups.json
|-- selection-state.json
|-- dns-policy.json
|-- metrics-policy.json
|-- backup-policy.json
`-- metadata.json
```

`manifest.json` records:

- backup schema version;
- product name;
- creation timestamp;
- reason;
- section schema version;
- section names and file names;
- sensitivity marker;
- notes warning that backups can contain secrets.

Every section includes `schema_version`.

## Section Behavior

Task 17.1 wrote all supported default sections. Section-scoped export/import was
added later in Task 17.2.

Definitions are separated from selection/use state:

- profiles/providers live in `profiles.json` and `providers.json`;
- provider update metadata is represented through `provider-state.json`;
- runtime/user selection state lives in `selection-state.json`;
- metrics backup is policy-only through `metrics-policy.json`.

`metrics-policy.json` intentionally excludes metrics buckets, history and
counters.

## Restore Safety

`restore_backup()`:

1. validates the entire backup before mutation;
2. creates a pre-restore auto-backup;
3. snapshots current target files;
4. applies all sections;
5. restores the snapshot if any apply step fails.

The restore path does not reconnect, restart services, mutate live network
state or upload anything.

## Validation Rules

The manager rejects:

- invalid ZIP files;
- missing `manifest.json`;
- duplicate ZIP entries;
- absolute paths;
- path traversal;
- nested paths;
- unsupported entries;
- unsupported backup schema versions;
- unsupported section schema versions;
- manifest/entry mismatches;
- invalid section payloads.

Section payloads are validated through the existing model/store validators where
available.

## Deferred Work

The following are intentionally left for later Phase 17 tasks:

- user-facing CLI commands;
- merge vs replace behavior;
- stronger replace confirmations;
- bounded auto-backup retention;
- backup encryption;
- WebDAV/LAN sync;
- uninstall flow integration;
- private metrics history export.

## Validation

Tests cover:

- backup ZIP contains the full manifest and supported section set;
- `metrics-policy.json` excludes metrics history/counters;
- selection state is backed up separately;
- path traversal is rejected;
- duplicate entries are rejected;
- unsupported schema versions are rejected;
- restore validates and creates pre-restore backup;
- restore rolls back target files when apply fails.
