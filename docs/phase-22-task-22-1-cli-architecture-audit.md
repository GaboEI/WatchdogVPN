# Phase 22 Task 22.1 - CLI Architecture Audit

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: closed

## Scope

Task 22.1 audits the current Python CLI architecture before Phase 22 adds or
completes command groups. It covers:

- `bin/watchdog` entrypoint behavior;
- `cli/main.py` parser structure;
- current command inventory versus Phase 22 scope;
- JSON and human-output architecture;
- mutation safety and backup boundaries;
- subprocess usage in the CLI layer;
- whether a framework migration is justified.

This task does not implement new command groups.

## Decision

Keep the existing argparse-based CLI architecture for Phase 22.

No concrete defect was found that requires a framework migration. The current
CLI already has:

- a small installed wrapper, `bin/watchdog`, that executes
  `python3 -m cli.main "$@"`;
- one explicit parser builder in `cli/main.py`;
- direct handler functions per command;
- list-form subprocess calls where CLI subprocess execution is needed;
- test coverage for major existing command groups;
- JSON output paths for several automation-oriented commands.

The Phase 22 gaps are command completeness, consistency, validation depth and
contract documentation. Those are better solved by extending the current CLI
conservatively than by rewriting the framework.

## Current Entrypoint

`bin/watchdog` is intentionally thin:

```text
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m cli.main "$@"
```

This keeps the installed command aligned with repository execution and avoids a
second command-dispatch implementation.

## Current Command Inventory

Implemented top-level commands:

- `connect`
- `disconnect`
- `status`
- `rotate`
- `uninstall`
- `profile`
- `provider`
- `node-group`
- `dns`
- `config`
- `stats`
- `rules`
- `ruleset`
- `app-policy`

Implemented nested command coverage includes:

- profile add/list/remove/enable/disable/rotation;
- provider add/list/stats/update/remove/edit/rotation/node;
- node-group list/create/add-profile/auto-test/select;
- dns status/test/diagnose/apply/reset;
- config set/routing-contract/lan-sharing-credentials;
- stats status/summary/purge/privacy-mode;
- rules list/explain/enable/disable/add-rule/remove-rule/import/export;
- ruleset status/refresh;
- app-policy status/enable/disable/mode/default-action/add/remove.

## Phase 22 Gaps

Known gaps against the Phase 22 plan:

- `watchdog backup ...` is not yet a top-level CLI group.
- `watchdog setup` is not yet implemented.
- `watchdog doctor` is not yet implemented in the Python CLI surface.
- `watchdog version` is not yet implemented in the Python CLI surface.
- `watchdog panic sleep|wake|status` is not yet implemented as a thin
  passthrough to `bin/watchdog_panic`.
- Some existing mutation commands do not yet expose JSON output.
- Some existing mutation commands do not yet create backups where the Phase 22
  contract will require backups.
- JSON output schemas are implemented command-by-command but not yet documented
  as stable contracts.
- Nested command invocations without a subcommand fall back to the root parser
  help behavior instead of command-specific help. This is a usability gap, not
  a framework blocker.

## Subprocess Audit

No `shell=True` usage was found in the CLI layer.

CLI subprocess use is list-form:

- `watchdog uninstall` runs the selected `uninstall.sh` script as an argv list;
- `profile add --text` opens `$EDITOR` as `[editor, temp_file]`.

Phase 22 must keep this invariant. New CLI subprocess calls must use argv lists,
bounded behavior where appropriate and no shell interpolation.

## JSON And Human Output

The current architecture supports JSON output by handler. This is sufficient for
Phase 22, but command contracts need hardening:

- automation-oriented commands need stable JSON schemas;
- human output should include critical warnings and recovery hints;
- mutation commands should avoid leaking secrets in text output;
- provider URLs and credential-like values must stay redacted by default.

## Mutation Safety

Existing safety patterns are mixed:

- DNS apply/reset require `--yes` or dry-run and use snapshot/restore paths.
- Rules import writes a rollback point and backs up replaced groups.
- Uninstall requires explicit mode and delete confirmation.
- Stats purge requires `--yes`.

Phase 22 must make mutation safety consistent across all command groups:

- validate before writing;
- create backups where the product contract requires them;
- provide rollback/recovery hints;
- keep JSON output parseable even for dry-runs and failed plans where feasible.

## Findings

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| AUD-P22-001 | INFO | Accepted | Argparse remains fit for Phase 22. The known problems are command completeness and contract consistency, not framework capability. |
| AUD-P22-002 | INFO | Accepted | `watchdog panic sleep|wake|status` is missing from the Python CLI and must be added later as a thin passthrough to `bin/watchdog_panic`, without reimplementing panic logic in Python. |
| AUD-P22-003 | INFO | Accepted | Top-level `backup`, `setup`, `doctor` and `version` commands are still missing from the Python CLI surface. These are Phase 22 implementation tasks, not Task 22.1 blockers. |
| AUD-P22-004 | LOW | Accepted | Nested command groups without a subcommand show root-level help instead of group-specific help. This is a usability issue to fix while completing command groups, but it does not block the architecture decision. |
| AUD-P22-005 | LOW | Accepted | JSON coverage and backup behavior are not yet uniform across mutation commands. Phase 22 should address this per command group and pin stable schemas with tests. |

No HIGH or MEDIUM findings were identified.

## Implementation Guidance For Next Tasks

- Keep `argparse`.
- Keep `bin/watchdog` as the thin Python CLI wrapper.
- Add commands incrementally by task group.
- Prefer shared output helpers only where they remove real duplication.
- Add command-specific tests with isolated temporary config paths.
- Preserve existing command behavior unless a documented bug requires a fix.
- Do not start TUI work in Phase 22.
- For runtime/network-affecting commands, prepare operator-run VM/lab
  validation instead of running disruptive checks directly.

## Phase 22 Closure Note

Task 22.7 resolved the remaining Python CLI inventory gaps identified in this
audit:

- `watchdog backup ...` was added in Task 22.5;
- `watchdog setup` and `watchdog doctor` were added in Task 22.6;
- `watchdog version` and `watchdog panic sleep|wake|status` were added in
  Task 22.7;
- nested command groups now require a subcommand and no longer fall through to
  root help.

## Validation

Task 22.1 validation:

```text
bash tests/syntax.sh
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```

This task changed documentation only and did not require installed VM
validation.

## Runtime Boundary

No runtime, daemon, DNS, route, firewall, forwarding, system proxy, installed
package or network behavior changed.
