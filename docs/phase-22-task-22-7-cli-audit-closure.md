# Phase 22 Task 22.7 - CLI Audit Closure

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: closed

## Scope

Task 22.7 closes the Phase 22 CLI audit. It covers:

- command inventory;
- JSON output contracts;
- human output contracts;
- mutation confirmation and backup behavior;
- redaction and privacy boundaries;
- subprocess execution;
- runtime/network/system-state boundaries.

The audit report is:

- `docs/qa-audit-2026-07-09-phase-22-full-cli-interface.md`.

## Implementation Closure

Task 22.7 fixed the remaining Python CLI command inventory gaps from Task 22.1:

- added `watchdog version [--json]`;
- added `watchdog panic sleep|wake|status`.

`watchdog version` reads the existing release marker from `bin/watchdogvpn`.
Human output is:

```text
WatchdogVPN v0.3.1
```

JSON output includes:

- `product`;
- `version`;
- `python_cli=true`.

`watchdog panic` is a thin argv-list subprocess passthrough to the standalone
`bin/watchdog_panic` script. The Python CLI does not reimplement panic logic.

Task 22.7 also fixed the Task 22.1 nested-help LOW finding. Nested command
groups now require a subcommand, so incomplete invocations fail with a
group-specific argparse error instead of falling through to root help.

## Audit Result

Phase 22 closes with no unresolved HIGH, MEDIUM, LOW or INFO findings.

The existing branch gate still applies: merge back to `main` requires explicit
maintainer merge-preparation approval and must use a merge commit rather than
squash.

## Runtime Boundary

Task 22.7 changes CLI parsing, thin command passthrough, output, tests and
docs. It does not change daemon/runtime connection logic, DNS runtime behavior,
routes, firewall behavior, forwarding, system proxy behavior, provider refresh
behavior or installed package behavior.

VM/lab validation was not required because Task 22.7 did not introduce new
runtime/network/system mutation behavior.

## Validation

Task validation:

```text
python3 -m unittest tests.test_cli_version_panic_commands
OK - 4 tests

python3 -m unittest tests.test_cli_profile_commands tests.test_cli_provider_commands tests.test_cli_rules_commands tests.test_cli_app_policy_commands tests.test_cli_node_group_commands tests.test_cli_dns_commands tests.test_cli_stats_commands tests.test_cli_backup_commands tests.test_cli_uninstall_commands tests.test_cli_setup_doctor_commands
OK - 113 tests

bash tests/unit.sh
OK

bash tests/syntax.sh
OK

python3 -m unittest discover -s tests -p 'test_*.py'
OK - 1212 tests, 1 skipped

git diff --check
OK

PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
OK

rg -n "shell=True|subprocess\." cli/main.py
OK - no shell=True; subprocess calls remain argv-list form
```
