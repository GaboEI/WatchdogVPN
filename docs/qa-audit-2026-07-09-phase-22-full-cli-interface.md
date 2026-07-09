# QA Audit - Phase 22 Full CLI Interface

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: closed

## Scope

This audit closes Phase 22 Full CLI Interface. It covers:

- command inventory versus Phase 22 scope;
- JSON contracts for automation-oriented commands;
- human output safety and recovery hints;
- mutation confirmation and backup behavior;
- redaction and privacy boundaries;
- subprocess execution in the CLI layer;
- runtime/network/system-state boundaries.

The audit does not start TUI work and does not merge the branch to `main`.

## Command Inventory

Audited Python CLI command groups:

- `connect`, `disconnect`, `status`, `rotate`;
- `version`;
- `panic sleep|wake|status`;
- `doctor`;
- `setup`;
- `profile`;
- `provider`;
- `rules`;
- `ruleset`;
- `app-policy`;
- `node-group`;
- `dns`;
- `stats`;
- `backup`;
- `uninstall`;
- `config`.

Task 22.7 resolved the remaining Task 22.1 command inventory gaps by adding:

- `watchdog version [--json]`;
- `watchdog panic sleep|wake|status` as a thin passthrough to
  `bin/watchdog_panic`.

Task 22.7 also resolved the accepted Task 22.1 nested-help usability finding by
requiring subcommands for nested command groups. A group invocation such as
`watchdog profile` now fails with the group-specific argparse error instead of
falling through to root help.

## JSON Contract Audit

Phase 22 JSON contracts are documented in `docs/cli.md` and the task-specific
closure docs:

- lifecycle daemon response envelope with `payload.lifecycle`;
- redacted profile and provider summaries;
- policy mutation rollback metadata;
- DNS rollback snapshot metadata;
- aggregate-only stats output;
- backup manifest/restore metadata;
- uninstall plan metadata;
- setup plan and backup metadata;
- doctor stdout/stderr/exit capture;
- version product/version metadata.

Audit result: PASS. JSON output paths are parseable and tests cover the command
groups added or hardened during Phase 22.

## Human Output Audit

Human output was reviewed for operator safety:

- lifecycle output reports daemon reachability, desired state, runtime state,
  active profile and cleanup expectations;
- profile/provider output avoids raw config, subscription URLs, endpoint
  tokens, private keys and raw metadata;
- policy output prints backups and rollback guidance for mutations;
- DNS output distinguishes status/test/diagnose/apply/reset semantics;
- stats output does not imply detailed traffic history support;
- backup and uninstall output warns about sensitive backups and explicit
  destructive choices;
- setup output clearly reports dry-run, applied state, runtime/network action
  flags and backup path;
- panic remains owned by the standalone script and retains its existing
  operator wording.

Audit result: PASS.

## Mutation And Backup Audit

Mutation commands validate inputs before writes. Commands that can make
destructive or broad local changes require explicit confirmation or dry-run:

- DNS apply/reset require `--yes` or dry-run as appropriate;
- stats purge requires `--yes`;
- backup restore replace requires the literal restore confirmation;
- uninstall requires mode-specific confirmation and `--yes`;
- setup writes require `--yes` and `--acknowledge-backup-warning`;
- policy mutations create section or group backups where the current product
  contract requires them.

Profile/provider direct store mutations keep the Task 22.3 contract: destructive
remove output returns redacted rollback points, but does not create
secret-bearing backup archives because those stores do not define automatic
backup-file creation for those direct mutations.

Audit result: PASS.

## Privacy And Redaction Audit

Phase 22 preserves the privacy boundaries from prior phases:

- no DNS query history;
- no destination history;
- no process history;
- no packet payloads;
- no provider secrets;
- no raw profile configs in normal output;
- no provider subscription URLs in normal output;
- no raw backup payload dump in inspect output.

Audit result: PASS.

## Subprocess Audit

`cli/main.py` contains no `shell=True`. CLI subprocess calls are argv-list form:

- `watchdog panic` delegates to `[watchdog_panic, mode]`;
- `watchdog doctor` delegates to `[doctor.sh]`;
- `watchdog uninstall` delegates to the selected uninstall script argv;
- `profile add --text` opens the configured editor as `[editor, temp_file]`.

Audit result: PASS.

## Runtime Boundary

Phase 22 changed CLI parsing, output, validation, local store mutation, backup
wiring, tests and documentation. It did not change daemon/runtime connection
logic, DNS runtime behavior, routes, firewall behavior, forwarding, system
proxy behavior, installed package behavior or provider refresh behavior.

VM/lab validation was not required for Task 22.7 because it did not introduce
new runtime/network/system mutation behavior beyond existing passthrough
commands.

## Findings

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| AUD-P22-001 | INFO | Closed | Argparse remains fit for Phase 22; no framework migration required. |
| AUD-P22-002 | INFO | Closed | Python CLI `watchdog panic sleep|wake|status` was missing; Task 22.7 added a thin passthrough to `bin/watchdog_panic`. |
| AUD-P22-003 | INFO | Closed | Python CLI `watchdog version` was missing; Task 22.7 added human and JSON output using the existing release marker. |
| AUD-P22-004 | LOW | Closed | Nested command groups without subcommands fell through to root help; Task 22.7 now requires nested subcommands. |
| AUD-P22-005 | LOW | Closed | JSON and backup behavior were inconsistent at Phase 22 start; Tasks 22.2-22.6 hardened contracts per command group. |

No unresolved HIGH, MEDIUM, LOW or INFO findings remain for Phase 22.

## Validation

Final validation was run before Phase 22 audit closure and is recorded in
`docs/phase-22-task-22-7-cli-audit-closure.md`.
