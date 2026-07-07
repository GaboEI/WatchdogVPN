# Phase 17 Task 17.4 - Selection And Provider-State Restore

> Date: 2026-07-07
> Status: CLOSED - selection-state and provider-state restore contracts implemented.

## Scope

Task 17.4 defines how local selection/use state and provider update metadata are
restored by `config.backup_manager.BackupManager`.

It does not add user-facing CLI commands. It also does not reconnect, restart
services, mutate live network state or perform provider refreshes after restore.
Bounded auto-backup retention was added later in Task 17.5. Plaintext
sensitive-warning behavior was added later in Task 17.6. Encrypted backup
format support was added later in Task 17.7.

## Selection State

`selection-state.json` restores persisted state from `state.toml`, including:

- active profile id;
- active mode;
- autostart/autoconnect flags;
- desired VPN state;
- language state.

Before writing selection state, the manager validates the document with the
normal `StateManager` validator. If `active_profile_id` is non-empty, the
profile must exist in the current restored/local profile store.

This means:

- full replace restore can restore profiles first, then restore matching
  selection state;
- selection-only restore refuses to point at a missing profile;
- restore never connects merely because an active profile id was imported.

Any runtime action after restore still requires an explicit user command.

## Node-Group Selection

Node-group selection is part of `node-groups.json`, not `selection-state.json`.
Replace restore writes the node-group document. Merge restore renames imported
node groups per Task 17.3 and does not alter existing local node groups.

## Provider State

`provider-state.json` restores update metadata for existing providers only:

- `last_updated`;
- `metadata`.

Provider-state restore does not:

- create missing providers;
- remove providers;
- change provider name;
- change provider URL;
- change provider profile membership;
- change rotation or auto-update settings.

This keeps provider definitions under the `providers` section while allowing
safe refresh metadata restoration.

## Runtime Safety

Selection-state and provider-state restore are file-level mutations only. The
backup manager does not reconnect, restart daemons, refresh providers, rotate
profiles, upload backups or mutate live network routes.

## Deferred Work

The following remain later Phase 17 work:

- user-facing CLI wiring;
- CLI copy and confirmation UX;
- profiles/providers merge behavior if deliberately designed;
- WebDAV/LAN sync;
- uninstall flow integration.

## Validation

Tests cover:

- selection-state restore rejects a missing active profile id;
- rejected selection-state restore leaves existing state unchanged;
- provider-state restore updates existing provider `last_updated`;
- provider-state restore updates existing provider metadata;
- provider-state restore does not create missing providers;
- provider-state restore preserves provider definitions;
- provider-state validation rejects invalid `last_updated` values.

Commands run:

- `python3 -m unittest tests.test_backup_manager`;
- `python3 -m unittest tests.test_backup_manager tests.test_config_storage tests.test_cli_provider_commands tests.test_subscription_provider tests.test_core_watchdog tests.test_core_watchdog_node_groups tests.test_node_groups_models`;
- `python3 -m unittest discover -s tests -p 'test_*.py'`;
- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `git diff --check`;
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`.
