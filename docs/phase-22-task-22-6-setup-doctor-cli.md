# Phase 22 Task 22.6 - Setup And Doctor CLI

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: closed

## Scope

Task 22.6 adds the missing Python CLI surface for:

- `watchdog setup`;
- `watchdog doctor`.

The existing argparse architecture is kept. This task does not start TUI work,
does not change connect/disconnect runtime behavior and does not modify
`rotation/rotation_engine.py`.

## Setup Command Contract

`watchdog setup` configures local first-run preferences and policy defaults:

- selected language;
- app autostart intent;
- VPN autoconnect intent;
- first local profile URI;
- first provider definition;
- kill-switch policy;
- DNS policy mode;
- app-policy enabled state;
- app-policy mode;
- app-policy default action;
- backup warning acknowledgement.

Supported shape:

```text
watchdog setup [--dry-run] [--yes] [--json]
  [--language LANG]
  [--autostart enable|disable]
  [--autoconnect enable|disable]
  [--profile-uri URI]
  [--provider-url URL] [--provider-name NAME]
  [--kill-switch enable|disable]
  [--dns-mode auto|off|custom|advanced]
  [--app-policy enable|disable]
  [--app-policy-mode blacklist|whitelist]
  [--app-policy-default-action current|direct|block]
  [--acknowledge-backup-warning]
```

Dry-run validates and prints the setup plan without writing local state. Real
setup writes require both `--yes` and `--acknowledge-backup-warning`.

Provider URLs are stored as local provider definitions without fetching nodes.
Provider refresh remains owned by `watchdog provider update`.

## Setup JSON Contract

Setup JSON includes:

- `has_changes`;
- `operations`;
- `sections`;
- `backup_warning`;
- `network_fetch_performed=false`;
- `runtime_action_executed=false`;
- `dry_run`;
- `applied`;
- `backup_path`;
- `backup_warning_acknowledged`.

Profile operations use redacted profile summaries with
`config_included=false`. Provider operations use redacted provider summaries
with `metadata_included=false`.

## Doctor Command Contract

`watchdog doctor` is a thin Python CLI wrapper around the existing repository
`doctor.sh`:

```text
watchdog doctor [--json]
```

The Python wrapper does not reimplement doctor checks. Human mode runs the
script as an argv-list subprocess. JSON mode captures stdout, stderr and exit
code in one JSON document:

- `command`;
- `doctor_exit_code`;
- `doctor_stdout`;
- `doctor_stderr`;
- `read_only=true`;
- `mutates_runtime=false`.

The wrapper does not call `sudo` and does not mutate runtime state.

## Backup And Mutation Behavior

Real setup writes create a pre-setup backup over the affected sections before
local state is written. Setup may write:

- `settings`;
- `selection-state`;
- `profiles`;
- `providers`;
- `dns-policy`;
- `app-policy`.

Dry-run setup creates no backup and writes no stores.

## Runtime Boundary

Task 22.6 changes CLI parsing, local setup store mutation, doctor wrapping,
tests and docs only. It does not connect, disconnect, rotate, refresh
providers, apply DNS, mutate resolver state, change routes, edit firewall
rules, mutate system proxy settings, start services or contact external
network resources.

Installed VM/lab validation was not required because runtime/network behavior
did not change.

## Tests

Task 22.6 adds tests for:

- setup dry-run not writing profile/provider stores;
- setup apply writing local state, config, DNS policy, app policy, profile and
  provider definition with a backup;
- setup requiring `--yes` and backup warning acknowledgement for writes;
- doctor JSON wrapping a script without shell execution.

## Validation

Task validation:

```text
python3 -m unittest tests.test_cli_setup_doctor_commands
OK - 4 tests
python3 -m unittest tests.test_cli_setup_doctor_commands tests.test_cli_config_commands tests.test_cli_dns_commands tests.test_cli_app_policy_commands tests.test_cli_profile_commands tests.test_cli_provider_commands
OK - 77 tests
bash tests/unit.sh
OK
bash tests/syntax.sh
OK
python3 -m unittest discover -s tests -p 'test_*.py'
OK - 1208 tests, 1 skipped
git diff --check
OK
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
OK
rg -n "shell=True|subprocess\." cli/main.py
OK - no shell=True; subprocess calls remain argv-list form
```
