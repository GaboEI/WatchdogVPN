# Phase 22 Task 22.5 - DNS, Stats, Backup And Uninstall CLI

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: closed

## Scope

Task 22.5 audits and completes CLI contracts for:

- DNS policy/state commands;
- observability stats privacy commands;
- backup create/export/inspect/restore/import commands;
- uninstall wrapper behavior.

The existing argparse architecture is kept. This task does not start Task 22.6,
does not add TUI work and does not change connect/disconnect runtime behavior.

## DNS Command Contract

Audited DNS commands:

- `watchdog dns status [--json]`;
- `watchdog dns test [--json]`;
- `watchdog dns diagnose ... [--json]`;
- `watchdog dns apply --dry-run [--json]`;
- `watchdog dns apply --yes [--json]`;
- `watchdog dns reset --yes [--json]`.

`status`, `test` and `diagnose` remain read-only. `apply --dry-run` returns the
apply plan without creating a DNS snapshot or mutating resolver state. Real
apply requires `--yes`, refuses non-standard system resolver ports, saves or
reuses rollback snapshot metadata and returns `rollback_snapshot` plus
`snapshot_saved` in JSON. `reset` requires `--yes`, restores from the saved
snapshot, removes the snapshot file after successful restore and returns
`rollback_snapshot.restored=true` in JSON.

Tests use mocked DNS managers or isolated temporary resolver files only. Task
22.5 does not touch the workstation's real NetworkManager, systemd-resolved,
`/etc/resolv.conf` or DNS runtime state.

## Stats Command Contract

Audited stats commands:

- `watchdog stats status [--json]`;
- `watchdog stats summary [--json]`;
- `watchdog stats purge --yes [--json]`;
- `watchdog stats privacy-mode <off|aggregate|detailed> [--json]`.

Phase 16 privacy boundaries are preserved:

- no DNS query history;
- no destination history;
- no process history;
- no packet payloads;
- no provider secrets;
- no private full export.

Summary JSON continues to expose allowlisted aggregate counters only and counts
unknown or future-sensitive counter keys as `withheld_counter_keys`.

`stats purge` still refuses without `--yes`; JSON purge output reports whether
a metrics file was removed and keeps `history_included=false`.

`stats privacy-mode detailed` still stores only the policy value. JSON output
keeps `detailed_history_supported=false` and `history_included=false`.

## Backup And Restore Command Contract

Task 22.5 adds the top-level backup group over the existing `BackupManager`:

- `watchdog backup create [--output PATH] [--section SECTION] [--json]`;
- `watchdog backup export [--output PATH] [--section SECTION] [--json]`;
- `watchdog backup inspect PATH [--json]`;
- `watchdog backup restore PATH [--dry-run] [--section SECTION] [--mode replace|merge] [--json]`;
- `watchdog backup import PATH [--dry-run] [--section SECTION] [--mode replace|merge] [--json]`.

`create` and `export` are equivalent. Section selection is validated against
the backup manager's supported section names. Diagnostics are not included by
default. Encrypted backup passwords are read only from `--password-env`; pasted
password arguments are not accepted.

`inspect` validates the archive manifest and section schema without printing
raw section payloads.

`restore` and `import` are equivalent. Dry-run restore validates the archive,
selected sections and merge-section compatibility without writing local state
or creating a pre-restore backup. Real replace restore requires the literal
confirmation `RESTORE-WATCHDOGVPN-BACKUP`. Real restore creates a pre-restore
backup and returns `pre_restore_backup` in JSON.

Backup JSON distinguishes normal backups from support exports:

- `normal_backup=true`;
- `support_export=false`;
- `redacted_export=false`.

Normal backups are sensitive archives. They may contain private keys, provider
tokens, subscription URLs, routing policy, app policy, route chains and local
selection state.

## Uninstall Command Contract

Audited uninstall command:

- `watchdog uninstall --keep-data --dry-run [--json]`;
- `watchdog uninstall --keep-data --yes [--json]`;
- `watchdog uninstall --backup-first --backup-output PATH --yes [--json]`;
- `watchdog uninstall --delete-all-data --confirm-delete DELETE --backup-output PATH --yes [--json]`.

Real uninstall execution now requires `--yes`; `--dry-run` is plan-only in the
Python CLI wrapper and does not invoke `uninstall.sh`, create backups or remove
files. Delete-all-data still requires literal `DELETE` for real execution.

Uninstall JSON reports:

- selected mode;
- dry-run state;
- backup path;
- encryption state;
- argv-form command;
- product-managed files;
- preserved user state;
- log behavior;
- backup behavior;
- systemd units in scope.

Backup output paths inside WatchdogVPN-owned paths remain rejected so a
pre-delete backup is not removed by the same uninstall operation.

## Redaction And Privacy

Normal backup creation is intentionally not a redacted export. `backup inspect`
and backup command JSON do not print raw backup section payloads, profile
configs, provider metadata, provider subscription URLs, endpoint tokens or
private keys.

Stats output remains aggregate-only and withholds unknown counter keys.

DNS status output reports configured policy and resolver inventory; tests avoid
real system resolver mutation.

## Tests

Task 22.5 adds or hardens tests for:

- DNS rollback snapshot JSON metadata;
- stats purge/privacy-mode JSON privacy contract;
- backup create/export/inspect/restore/import CLI behavior;
- restore dry-run no-write behavior;
- replace restore confirmation behavior;
- uninstall dry-run plan-only behavior;
- uninstall real execution requiring `--yes`;
- uninstall JSON contract metadata.

## Validation

Task validation:

```text
python3 -m unittest tests.test_cli_dns_commands tests.test_cli_stats_commands tests.test_backup_manager tests.test_cli_backup_commands tests.test_cli_uninstall_commands
OK - 67 tests
```

Full validation was run before task closure and recorded in the task summary.

## Runtime Boundary

This task changes CLI parsing, JSON/human output, backup/restore CLI wiring,
validation, tests and docs. It does not change daemon/runtime behavior,
connect/disconnect behavior, DNS runtime behavior, routes, firewall,
forwarding, system proxy, installed package behavior or external network
behavior.

Installed VM/lab validation was not required because no real runtime/network or
system resolver behavior changed.
