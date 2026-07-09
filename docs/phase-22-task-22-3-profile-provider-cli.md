# Phase 22 Task 22.3 - Profile And Provider CLI

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: closed

## Scope

Task 22.3 audits and completes the profile/provider CLI command group while
keeping the existing argparse CLI architecture:

- `watchdog profile add --clipboard|--uri|--file|--text`;
- `watchdog profile list [--json] [--pool]`;
- `watchdog profile remove <id>`;
- `watchdog profile enable <id>`;
- `watchdog profile disable <id>`;
- `watchdog profile rotation <id> --enable|--disable|--on|--off`;
- `watchdog provider add <url> [--name NAME]`;
- `watchdog provider list [--json]`;
- `watchdog provider stats <id> [--json]`;
- `watchdog provider update <id>|--all`;
- `watchdog provider remove <id>`;
- `watchdog provider edit <id> [--name NAME] [--url URL]`;
- `watchdog provider rotation <id> --enable|--disable`;
- `watchdog provider node <provider_id> <node_id> --rotation --enable|--disable`.

This task does not start Task 22.4, does not add TUI work and does not change
connect/disconnect/runtime behavior.

## Profile Command Contract

Profile imports now support JSON output for all import sources. Human output
prints each imported profile with ID, protocol, resilience category, display
name and rotation state.

Profile list output includes:

- profile ID;
- protocol;
- resilience category;
- source;
- enabled state;
- rotation-pool state;
- health state;
- local profile name.

The resilience category is one of:

- `resilient`;
- `compatibility`.

The category is a local classification. It is not a guarantee of censorship
resistance, successful connection, uptime or egress behavior.

Profile mutation commands validate the target profile before writing. Missing
profiles fail with a recovery hint that points operators to
`watchdog profile list`.

`watchdog profile rotation` keeps the existing `--enable`/`--disable` flags
and adds compatibility aliases `--on`/`--off`.

## Provider Command Contract

Provider mutations now support JSON output for add, update, remove, edit,
rotation and provider-node rotation.

Provider commands validate target objects before writing:

- provider stats/remove/edit/rotation require an existing provider;
- provider-node rotation requires the provider and profile to exist;
- provider-node rotation refuses nodes owned by a different provider.

Missing providers fail with a recovery hint that points operators to
`watchdog provider list`.

Provider update tests use mocked/local fixtures. Task 22.3 does not contact a
real provider URL or validate external egress behavior.

## JSON Output Contract

Profile JSON emits redacted profile summary objects with:

- `id`;
- `name`;
- `protocol`;
- `resilience_category`;
- `source`;
- `provider_id`;
- `enabled`;
- `in_rotation_pool`;
- `health_status`;
- `latency_ms`;
- `last_health_check`;
- `last_latency_check`;
- `config_included=false`.

Provider JSON emits redacted provider summary objects with:

- `id`;
- `name`;
- redacted `url`;
- `rotation_enabled`;
- `node_count`;
- `last_updated`;
- `traffic`;
- `expires_at`;
- `metadata_included=false`.

Mutation JSON returns the changed redacted object. Destructive remove JSON also
returns a redacted `rollback_point`.

## Human Output Contract

Human output is operator-safe:

- profile output shows protocol and resilience category without raw config;
- provider output shows local labels and aggregate counts;
- provider stats show redacted URL only;
- remove commands print rollback guidance.

Normal human output does not print subscription URLs, endpoint tokens, private
keys, raw profile configs or provider metadata values.

## Redaction And Privacy

Task 22.3 fixes a real privacy bug: `watchdog profile list --json` previously
serialized `Profile.to_dict()`, which could expose raw `config` values. It now
uses the same safe profile summary as other profile commands.

The command group now redacts by default:

- provider subscription URLs;
- endpoint tokens;
- private keys;
- raw profile config;
- raw provider metadata values.

Tests include false canary secrets and assert that normal human and JSON output
does not emit them.

## Backup And Rollback Behavior

The current `ProfileStore` and `ProviderStore` direct mutation contracts do not
define automatic backup-file creation for profile/provider enable, disable,
rotation, edit or remove operations.

Task 22.3 therefore does not create new secret-bearing backup files. Instead,
destructive remove commands validate before writing and return redacted rollback
points:

- profile remove: summary only, `raw_profile_config_included=false`;
- provider remove: summary only, `subscription_url_included=false`.

Full recovery requires the original URI, file or provider subscription URL.
Those secret-bearing inputs are intentionally not printed or embedded in JSON
rollback output.

## Tests

Task 22.3 adds/hardens tests for:

- profile import/list JSON redaction;
- profile list pool category output;
- profile text import redaction;
- profile enable/disable/rotation/remove JSON;
- `--on`/`--off` profile rotation aliases;
- profile missing-id recovery hint;
- provider list/stats redaction;
- provider add/update/edit/rotation/node/remove JSON;
- provider missing-id recovery hint;
- mocked provider update paths without real provider URLs.

## Validation

Task validation:

```text
python3 -m unittest tests.test_cli_profile_commands tests.test_cli_provider_commands
OK - 20 tests

bash tests/unit.sh
OK

bash tests/syntax.sh
OK

python3 -m unittest discover -s tests -p 'test_*.py'
OK - 1193 tests, 1 skipped

git diff --check
OK

PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
OK
```

## Runtime Boundary

This task changes CLI profile/provider output, validation and tests only. It
does not change daemon/runtime behavior, connect/disconnect behavior, DNS,
routes, firewall, forwarding, system proxy or installed package behavior.

Installed VM/lab validation was not required because runtime/network behavior
did not change.
