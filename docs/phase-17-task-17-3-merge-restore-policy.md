# Phase 17 Task 17.3 - Merge Restore Policy

> Date: 2026-07-07
> Status: CLOSED - manager-level merge and replace contracts implemented.

## Scope

Task 17.3 defines the low-level restore policy for importing rule/policy/group
sections without overwriting existing local data.

It does not add user-facing CLI commands. It also does not add merge behavior
for settings, profiles, providers, DNS policy, selection state, provider state,
metrics policy, backup policy or diagnostics. Bounded auto-backup retention was
added later in Task 17.5. Plaintext sensitive-warning behavior was added later
in Task 17.6. Encrypted backup format support was added later in Task 17.7.

## Restore Modes

`BackupManager.restore_backup()` accepts a `mode` argument:

- `replace`: destructive restore mode;
- `merge`: non-destructive import mode for supported policy sections.

Replace mode requires the explicit `RESTORE-WATCHDOGVPN-BACKUP` confirmation
token through `replace_confirmation`. This guard lives in the manager, not only
in future CLI code.

## Merge Sections

Merge mode currently supports only:

- `routing-rules`;
- `app-policy`;
- `node-groups`.

Any other section requested in merge mode is rejected. This prevents accidental
partial semantics for stateful or sensitive sections that do not have a merge
contract yet.

## Routing Rules

Imported rule groups are always written under timestamped imported names:

```text
imported-<source-group-name>-<YYYYMMDDHHMMSS>
```

If the generated name already exists, the manager adds a numeric suffix. Local
rule groups are never removed or overwritten in merge mode.

## App Policy

App policy merge preserves local top-level policy settings:

- `enabled`;
- `mode`;
- `default_action`;
- schema version.

Imported app-policy rules are appended with timestamped imported IDs:

```text
imported-<source-rule-id>-<YYYYMMDDHHMMSS>
```

This avoids clobbering local rule IDs and avoids silently changing whether app
policy is enabled or how unmatched apps are handled.

## Node Groups

Imported node groups are always written under timestamped imported names:

```text
imported-<source-group-name>-<YYYYMMDDHHMMSS>
```

Local node groups are never removed or overwritten in merge mode. Imported
group membership, exclusions, resilience policy and selection mode are
preserved inside the renamed group.

## Restore Safety

Both replace and merge modes still:

- validate the whole backup before mutation;
- create a pre-restore backup;
- snapshot current target files;
- roll back if an apply step fails.

## Deferred Work

The following remain later Phase 17 work:

- user-facing CLI wiring;
- CLI copy and confirmation UX;
- merge behavior for profiles/providers if deliberately designed;
- WebDAV/LAN sync, later explicitly deferred by Task 17.9 / ADR 0006;
- uninstall flow integration.

## Validation

Tests cover:

- replace restore requires strong confirmation;
- merge restore preserves local app-policy settings;
- merge restore appends imported app-policy rules with timestamped IDs;
- merge restore imports rule groups with timestamped names;
- merge restore imports node groups with timestamped names;
- merge restore rejects unsupported sections.

Commands run:

- `python3 -m unittest tests.test_backup_manager`;
- `python3 -m unittest tests.test_backup_manager tests.test_config_storage tests.test_metrics_store tests.test_cli_rules_commands tests.test_rule_store tests.test_node_groups_models`;
- `python3 -m unittest discover -s tests -p 'test_*.py'`;
- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `git diff --check`;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`.
