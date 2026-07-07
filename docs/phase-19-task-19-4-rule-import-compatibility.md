# Phase 19 Task 19.4 - Rule Import Compatibility

Date: 2026-07-07
Status: closed

## Scope

Task 19.4 defines and implements WatchdogVPN's rule import compatibility layer
without tying WatchdogVPN to one external JSON layout.

The import path now builds an explicit import plan before writing anything. The
plan records:

- detected source format;
- imported rule group preview;
- accepted rule count;
- rejected constructs and reasons;
- rollback point;
- whether the run is a preview-only dry run.

## Supported Formats

### Native WatchdogVPN Rule Group

The existing native rule-group JSON remains supported:

```json
{
  "name": "custom",
  "enabled": true,
  "priority": 100,
  "rules": [
    {
      "id": "example",
      "action": "direct",
      "conditions": {"domain": ["example.com"]},
      "enabled": true
    }
  ]
}
```

Unknown fields, duplicate rule IDs, invalid actions, and unsupported condition
types are rejected before mutation.

### Simple Domain/IP Lists

Plain text files and JSON string arrays are supported as simple lists when
entries are domains, domain suffixes, or IP CIDRs:

```text
example.com
.ads.example
10.0.0.0/24
```

Simple list rules use `--default-action` and default to `block`.

### Safe Clash Rule Subset

JSON string arrays using a Clash-style `TYPE,value,ACTION` subset are supported
for:

- `DOMAIN`;
- `DOMAIN-SUFFIX`;
- `DOMAIN-KEYWORD`;
- `IP-CIDR`;
- `IP-CIDR6`;
- `PROCESS-NAME`.

Supported actions map to WatchdogVPN actions:

- `DIRECT` -> `direct`;
- `REJECT`, `REJECT-DROP`, `BLOCK` -> `block`;
- `PROXY`, `GLOBAL` -> `current_profile`.

Unsupported rule types or actions are reported as rejected constructs.

### Safe sing-box Route Rule Subset

JSON objects containing `route.rules` or a top-level `rules` list are supported
when each rule is a simple, non-logical match using WatchdogVPN-compatible
fields such as:

- `domain`;
- `domain_suffix`;
- `domain_keyword`;
- `domain_regex`;
- `ip_cidr`;
- `process_name`;
- `process_path`;
- `port`;
- `port_range`;
- `protocol`;
- `network`.

Simple `outbound`/`action` values are mapped when safe:

- `direct` -> `direct`;
- `block`/`reject` -> `block`;
- `current`/`current_profile`/`proxy` -> `current_profile`.

Logical rules, rule-set references, source matching, Wi-Fi matching, Clash mode
matching, and other unsupported constructs are rejected with reasons instead of
being silently weakened.

## CLI Behavior

`watchdog rules import` now supports:

```sh
watchdog rules import FILE [--name NAME] [--default-action ACTION] [--dry-run]
watchdog rules import FILE --replace
watchdog rules import FILE --allow-partial
watchdog rules import FILE --json
```

`--dry-run` previews without writing files and reports
`rollback_point.kind = "preview-only"`.

`--replace` preserves the existing behavior: replacement writes a backup before
overwriting the group and reports it as `rollback_point.kind =
"existing-group-backup"`.

New groups report `rollback_point.kind = "new-group-delete"` because the
rollback action is removing the newly imported group. Validation happens before
write, and the final write remains atomic through `RuleStore.replace_group()`.

Partial imports are rejected by default if any construct is unsupported. Users
must pass `--allow-partial` to import supported rules while receiving a rejected
construct report.

## Bugs Found and Fixed During Task 19.4

Two real bugs were found during implementation:

1. Native rule groups with unknown fields initially surfaced as internal errors
   instead of user input errors after moving parsing into `rules.importer`.
   Fixed by mapping persistent validation errors to `RuleImportError`, which
   the CLI reports as parse/input failure.
2. JSON arrays of Clash-style strings were initially autodetected as simple
   domain/IP lists. Fixed by detecting supported Clash line prefixes before
   falling back to simple-list parsing.

## Validation

Validation passed on 2026-07-07:

- `python3 -m unittest tests.test_cli_rules_commands tests.test_rule_store`
- `bash tests/unit.sh`
- `bash tests/syntax.sh`
- `git diff --check`
- `python3 -m unittest discover -s tests -p 'test_*.py'`
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`

Full Python unittest result: 1043 tests passed, 1 skipped.

The focused rule import tests cover:

- native WatchdogVPN rule-group import compatibility;
- replace import backup behavior;
- invalid schema and duplicate rule rejection without mutation;
- simple domain/IP list dry-run and write behavior;
- default rejection of partial imports without mutation;
- explicit `--allow-partial` import with rejected construct reporting;
- safe Clash subset import;
- safe sing-box subset import and unsupported construct rejection.

No VM/live-network validation was run because Task 19.4 only changes local rule
import parsing and rule-store writes. It does not apply routes or connect a
tunnel.
