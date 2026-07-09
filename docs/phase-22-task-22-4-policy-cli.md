# Phase 22 Task 22.4 - Policy CLI

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: closed

## Scope

Task 22.4 audits and completes the policy CLI command group while keeping the
existing argparse CLI architecture:

- `watchdog rules list [--json]`;
- `watchdog rules explain ... [--json]`;
- `watchdog rules enable <group> [--json]`;
- `watchdog rules disable <group> [--json]`;
- `watchdog rules add-rule <group> <rule_id> --action ACTION --condition KEY=VALUE [--json]`;
- `watchdog rules remove-rule <group> <rule_id> [--json]`;
- `watchdog rules import <file> [--replace] [--dry-run] [--json]`;
- `watchdog rules export <group> (--output PATH|--json)`;
- `watchdog app-policy status [--json]`;
- `watchdog app-policy enable|disable [--json]`;
- `watchdog app-policy mode <blacklist|whitelist> [--json]`;
- `watchdog app-policy default-action <current|direct|block> [--json]`;
- `watchdog app-policy add --process-name NAME --action ACTION [--id ID] [--json]`;
- `watchdog app-policy add --process-path PATH --action ACTION [--id ID] [--json]`;
- `watchdog app-policy remove <id> [--json]`;
- `watchdog node-group list [--json]`;
- `watchdog node-group create <name> [--json]`;
- `watchdog node-group add-profile <group> <profile> [--json]`;
- `watchdog node-group select <group> <profile|auto> [--json]`;
- `watchdog node-group auto-test <group> [--json]`.

This task does not start Task 22.5, does not add TUI work and does not change
daemon/runtime, DNS, route, firewall, forwarding or system proxy behavior.

## Rules Command Contract

Rules list JSON returns rule-group summaries with:

- `name`;
- `enabled`;
- `priority`;
- `rule_count`;
- `rules`.

Rules mutation JSON returns the changed group and rollback metadata:

- `backup_path` for a group-level backup where applicable;
- `rollback_point.kind = "existing-group-backup"` for existing group changes;
- `rollback_point.section = "routing-rules"`;
- `section_backup_path` for real `rules import` operations.

`rules import --dry-run` remains read-only and returns
`rollback_point.kind = "preview-only"`. Real imports create a routing-rules
section backup before writing. Replacing an existing group also writes the
existing group backup before replacement.

Rules mutations validate target groups, duplicate rule IDs and missing rule IDs
before writing. Missing groups point operators to `watchdog rules list`.
Duplicate or missing rule IDs point operators to `watchdog rules export
<group> --json`.

## App Policy Command Contract

App-policy status JSON returns:

- `valid`;
- `error`;
- `policy`;
- `rule_count`;
- `enabled_rule_count`;
- `rules`.

Rule entries include `match_confidence`. Mutation JSON also includes:

- `backup_path`;
- `rollback_point.kind = "section-backup"`;
- `rollback_point.section = "app-policy"`.

Every app-policy mutation validates the resulting policy before writing and
creates a restorable app-policy section backup first. Duplicate and missing rule
ID failures now return controlled CLI errors with recovery hints instead of
falling through as generic `ValueError` output.

## Node Group Command Contract

Node-group list JSON returns the stored group document.

Node-group mutation commands now support `--json` and return:

- `group`;
- `backup_path`;
- `rollback_point.kind = "section-backup"`;
- `rollback_point.section = "node-groups"`.

`node-group add-profile` also returns `added_profile_id`. Manual
`node-group select` returns `selected_profile_id`; auto selection returns
`selection = "auto"`.

Every node-group mutation validates the target group and profile references
before writing and creates a restorable node-groups section backup first.
Missing profiles point operators to `watchdog profile list`; duplicate or
missing groups point operators to `watchdog node-group list`.

`node-group auto-test` remains a daemon IPC command. It evaluates the group
through the daemon and does not mutate local policy by itself.

## Human Output Contract

Human output remains operator-safe and does not print raw profile configs,
provider subscription URLs, provider metadata, endpoint tokens or private keys.

Policy mutation output prints the changed object and backup path. Import output
prints accepted/rejected counts, group backup where present, section backup
where present and rollback guidance for newly imported groups.

## Backup And Validation Behavior

Task 22.4 strengthens policy mutation safety:

- `rules enable|disable|add-rule|remove-rule` validate the existing group and
  write a group backup before mutation;
- `rules import` validates the import plan before writing and creates a
  routing-rules section backup for real imports;
- `app-policy` mutations validate the resulting policy before writing and
  create an app-policy section backup;
- `node-group` mutations validate target objects before writing and create a
  node-groups section backup.

Backups are local files only. No backup is uploaded or synced.

## Tests

Task 22.4 adds or hardens tests for:

- rules group mutation backups and rollback metadata;
- rules import section backups;
- rules missing-target recovery hints;
- app-policy mutation backups and rollback metadata;
- app-policy duplicate rule recovery hints without traceback output;
- node-group mutation JSON output;
- node-group mutation backups and rollback metadata;
- node-group duplicate recovery hints.

## Validation

Task validation:

```text
python3 -m unittest tests.test_cli_rules_commands tests.test_cli_app_policy_commands tests.test_cli_node_group_commands
OK - 49 tests
```

Full validation was run before task closure and recorded in the task summary.

## Runtime Boundary

This task changes CLI output, validation, backup behavior, tests and docs only.
It does not change daemon/runtime behavior, connect/disconnect behavior, DNS,
routes, firewall, forwarding, system proxy, installed package behavior or
external network behavior.

Installed VM/lab validation was not required because runtime/network behavior
did not change.
