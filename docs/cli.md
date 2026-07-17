# WatchdogVPN CLI

`watchdog` is the single canonical product CLI. It owns the root help, version,
daemon-backed runtime state, profiles, providers, policy, backup/recovery and
local maintenance namespaces.

`watchdogvpn` is a deprecated compatibility alias. It forwards every invocation
to `watchdog`, writes one migration warning to stderr and never owns an
independent status, version or help contract. Alias stdout is left unchanged so
JSON consumers can migrate without parsing a second payload. The alias remains
available throughout the v2 major release line; its earliest possible removal
is v3.0 with advance release-note notice. Set
`WATCHDOGVPN_SUPPRESS_DEPRECATION_WARNING=1` only as a temporary automation aid
while replacing the command name.

The routing and removal policy is recorded in
[Phase 23 CLI Entrypoint Consolidation](phase-23-task-23-3-6-cli-entrypoint-consolidation.md).

The existing Bash-only support functions are preserved under
`watchdog maintenance`. The `VPN` command remains a direct TUI launcher until
the planned TUI replacement.

## Generated Inventory And Parity Gate

The complete public route and argument inventory is generated directly from
the canonical argparse tree:

- [human-readable command inventory](generated/cli-command-inventory.md);
- [machine-readable JSON inventory](generated/cli-command-inventory.json).

The generated inventory includes the canonical root, every nested argparse
route and each documented maintenance passthrough choice. Suppressed internal
test/recovery path overrides are intentionally excluded from public docs.

Regenerate snapshots after an intentional parser change:

```sh
python3 scripts/generate_cli_inventory.py
```

Verify parity without modifying files:

```sh
python3 scripts/generate_cli_inventory.py --check
```

The parity check is part of the test gate. A route, summary, usage or public
argument change fails until both generated snapshots are reviewed and updated.
This prevents the hand-maintained examples below from becoming the only command
inventory.

## Curated Command Summary

The examples below highlight common workflows and reviewed safety contracts.
They are not a second exhaustive inventory; use the generated references above
for every current route and public parser argument.

Canonical root and runtime commands:

```sh
watchdog --help
watchdog version [--json]
watchdog status [--json]
watchdog doctor [--json]
watchdog config routing-contract [--json]
```

Local maintenance and compatibility commands:

```sh
watchdog maintenance backend status
watchdog maintenance report
watchdog maintenance logs [events|dispatcher] [lines]
watchdog maintenance update-check
watchdog maintenance update-plan
watchdog maintenance runtime-update --preflight
watchdog maintenance config get [section.key]
watchdog maintenance config set section.key value
watchdog maintenance config reset [language|tui|reporting|all] --yes
watchdog maintenance tui
```

Deprecated forms route to the same parser and implementation:

```sh
watchdogvpn status                  # watchdog status
watchdogvpn backend status         # watchdog maintenance backend status
watchdogvpn report                 # watchdog maintenance report
watchdogvpn profile list --json    # watchdog profile list --json
```

Python configuration commands:

```sh
watchdog config set routing-policy <rule|global>
watchdog config set capture-modes <local_proxy|local_proxy,tun|local_proxy,system_proxy|local_proxy,tun,system_proxy>
watchdog config set default-route-action <current|direct|block>
watchdog config set lan_sharing.enabled <true|false>
watchdog config set lan_sharing.mode <disabled|proxy|gateway>
watchdog config set lan_sharing.bind_address <ip-address>
watchdog config set lan_sharing.socks_port <port>
watchdog config set lan_sharing.http_port <port>
watchdog config set lan_sharing.authentication_required <true|false>
watchdog config set lan_sharing.firewall_managed <true|false>
watchdog config lan-sharing-credentials [--show-secret] [--json]
```

Preflight-only state-changing commands:

```sh
watchdog maintenance runtime-update --preflight
```

State-changing runtime commands:

```sh
watchdog maintenance runtime-update
```

`runtime-update` validates whether a runtime update is safe, prints the exact
execution plan and requires explicit `yes` confirmation before it changes the
source checkout or installed runtime. Its full safety contract is documented in
[Runtime Update Contract](runtime-update-contract.md).

Interactive commands:

```sh
watchdog maintenance tui
```

Additional canonical commands:

```sh
watchdog connect <profile_id> [--json]
watchdog disconnect [--json]
watchdog status [--json]
watchdog rotate [--force] [--json]
watchdog command outcome <command-uuid> [--json]
watchdog command cancel <command-uuid> [--json]
watchdog version [--json]
watchdog panic sleep|wake|status
watchdog doctor [--json]
watchdog setup [--dry-run] [--yes] [--json]
watchdog uninstall --keep-data --yes
watchdog uninstall --keep-data --dry-run [--json]
watchdog uninstall --backup-first --backup-output ~/watchdogvpn-backup.zip --yes
watchdog uninstall --delete-all-data --confirm-delete DELETE --backup-output ~/watchdogvpn-pre-delete.zip --yes
watchdog stats status [--json]
watchdog stats summary [--json]
watchdog stats purge --yes [--json]
watchdog stats privacy-mode <off|aggregate|detailed> [--json]
watchdog backup create [--output PATH] [--section SECTION] [--json]
watchdog backup export [--output PATH] [--section SECTION] [--json]
watchdog backup inspect PATH [--json]
watchdog backup restore PATH [--dry-run] [--section SECTION] [--mode replace|merge] [--json]
watchdog backup import PATH [--dry-run] [--section SECTION] [--mode replace|merge] [--json]
watchdog rules list [--json]
watchdog rules explain [--domain DOMAIN] [--ip IP] [--process-name NAME] [--json]
watchdog rules enable <group> [--json]
watchdog rules disable <group> [--json]
watchdog rules add-rule <group> <rule_id> --action ACTION --condition KEY=VALUE [--json]
watchdog rules remove-rule <group> <rule_id> [--json]
watchdog rules import <file> [--replace] [--dry-run] [--json]
watchdog rules export <group> (--output PATH|--json)
watchdog ruleset status [--json]
watchdog ruleset refresh [RULE_SET_ID ...] [--referenced-only] [--force] [--json]
watchdog app-policy status [--json]
watchdog app-policy enable|disable [--json]
watchdog app-policy mode <blacklist|whitelist> [--json]
watchdog app-policy default-action <current|direct|block> [--json]
watchdog app-policy add --process-name NAME --action ACTION [--id ID] [--json]
watchdog app-policy add --process-path PATH --action ACTION [--id ID] [--json]
watchdog app-policy remove <id> [--json]
watchdog node-group list [--json]
watchdog node-group create <name> [--json]
watchdog node-group add-profile <group> <profile> [--json]
watchdog node-group select <group> <profile|auto> [--json]
watchdog node-group auto-test <group> [--json]
```

## Connection Lifecycle

The Python lifecycle commands use the daemon IPC path:

```text
watchdog CLI -> daemon IPC socket -> RuntimeWorker -> WatchdogRuntime/driver
```

They do not directly mutate DNS, routes, firewall, interfaces or driver
processes from the CLI process.

Every daemon-backed request has a command UUID. If a mutation reaches its
server deadline before it finishes, the daemon never reports an ambiguous
success or a generic timeout: it either acknowledges cancellation before the
mutation starts, or returns `command_in_progress` with that UUID. Inspect the
authoritative final result with `watchdog command outcome <command-uuid>`.
`watchdog command cancel <command-uuid>` only acknowledges cancellation while
the command is still queued; it never claims to interrupt a running network
operation.

The IPC protocol also has an exact payload schema per command. Unsupported
payload keys are rejected at the daemon boundary with a structured
`unsupported_payload_fields` response; they are never silently ignored.

### `watchdog connect`

Requests a daemon-managed connection to a saved profile.

```sh
watchdog connect <profile_id>
watchdog connect <profile_id> --json
```

Human output reports daemon reachability, desired state, actual runtime state,
active profile, proxy/TUN state, LAN gateway state, kill switch state and
failure/degraded status.

### `watchdog disconnect`

Requests daemon-managed disconnect and cleanup.

```sh
watchdog disconnect
watchdog disconnect --json
```

Disconnect cleanup is owned by the daemon/runtime layer:

- child process cleanup is handled by driver disconnect;
- TUN/interface/route cleanup applies where owned runtime state was created;
- DNS/system state restore uses the saved runtime snapshot when present;
- owned local proxy listeners are removed by driver disconnect where
  applicable.

The CLI prints these cleanup expectations but does not claim installed runtime
cleanup proof unless a VM/lab validation task recorded it.

### `watchdog status`

Shows daemon-reported runtime state and local desired state.

```sh
watchdog status
watchdog status --json
```

The command distinguishes daemon reachability, desired state, actual runtime
state, active runtime state, clean disconnect state and failure/degraded state.

Status is reconciled against read-only operating-system evidence rather than
trusting driver memory alone. The daemon attributes processes by durable
runtime records, private runtime paths, or the exact `watchdogvpn.service`
cgroup; maps those processes to their TCP listeners through `/proc`; and
checks exact WatchdogVPN interfaces, routing artifacts, and managed firewall
state. An unrelated process with the same executable name is not sufficient
ownership evidence.

`runtime_mismatch` is a critical status. It means owned effective state and
the expected lifecycle disagree, including missing `127.0.0.1:2080` or
`:2081` sing-box listeners, orphaned listeners/interfaces/routes, unexpected
TUN routing in proxy-only mode, or a partial/inconsistent kill-switch ruleset.
Human output lists the effective evidence. JSON exposes
`runtime_mismatch_severity`, `runtime_artifacts`, `kill_switch_status`,
`kill_switch_method`, and `kill_switch_consistent`. A complete kill switch
without a live tunnel is reported as `kill_switch_active`, never `standby`.
`watchdog status` remains read-only; explicit disconnect owns reconciliation
and cleanup.

### `watchdog rotate`

Requests a daemon-managed manual rotation.

```sh
watchdog rotate
watchdog rotate --force
watchdog rotate --json
```

Manual rotation still goes through `RuntimeWorker` and
`WatchdogRuntime.rotate_now()`. It does not bypass lifecycle safety in the CLI.

### Lifecycle JSON

Lifecycle JSON remains a daemon response envelope with an added
`payload.lifecycle` object:

```json
{
  "version": 1,
  "type": "response",
  "ok": true,
  "payload": {
    "state": {},
    "lifecycle": {
      "daemon_reachable": true,
      "desired_state": "off",
      "actual_runtime_state": "standby",
      "runtime_active": false,
      "runtime_artifacts": [],
      "kill_switch_status": "inactive",
      "kill_switch_consistent": true,
      "disconnected_cleanly": true,
      "failure_or_degraded": false
    }
  },
  "error": null
}
```

Daemon-unreachable JSON uses the same envelope with `ok=false`,
`daemon_reachable=false`, `actual_runtime_state=unknown` and recovery hints.

## Profiles And Providers

The Python profile and provider commands are local state commands. They do not
connect, disconnect, rotate live runtime state, mutate DNS, routes, firewall or
system proxy settings.

### `watchdog profile`

Imports, lists and updates saved profiles.

```sh
watchdog profile add --clipboard [--json]
watchdog profile add --uri URI [--json]
watchdog profile add --file PATH [--json]
watchdog profile add --text [--json]
watchdog profile list [--json] [--pool] [--wide]
watchdog profile list [--source manual|provider] [--protocol PROTOCOL]
                      [--health ok|unknown|down|degraded]
                      [--provider PROVIDER_ID]
                      [--enabled-only|--disabled-only]
watchdog profile remove <id> [--json]
watchdog profile enable <id> [--json]
watchdog profile disable <id> [--json]
watchdog profile rotation <id> --enable [--json]
watchdog profile rotation <id> --disable [--json]
watchdog profile rotation <id> --on [--json]
watchdog profile rotation <id> --off [--json]
```

Human output shows profile ID, protocol, source, enabled state, rotation state,
health state, name and resilience category where applicable. The category is a
local classification only:

```text
resilient
compatibility
```

It must not be read as a guarantee of censorship resistance, availability or
successful connection through any specific network.

Normal human list output follows the detected terminal width. At narrow widths
it uses a stacked profile view; medium widths use a compact table; wider
terminals retain separate enabled and rotation columns. Names, IDs, provider
labels, summaries and warnings are constrained so normal output has no visible
overflow at 40, 80 or 120 columns. Untrusted control characters in stored
display values are neutralized before terminal output.

Use the filters above to reduce large provider inventories. Filters compose and
also apply to `--json`, whose profile values remain complete. `--wide` is the
explicit opt-in to an untruncated human table and may exceed the terminal
width. Use `--json` when automation needs complete structured values without a
human table.

Profile JSON uses redacted summary objects. It includes stable fields such as
`id`, `name`, `protocol`, `resilience_category`, `source`, `provider_id`,
`enabled`, `in_rotation_pool`, `health_status`, latency timestamps and
`config_included=false`. It does not include raw profile config, private keys,
endpoint tokens or imported URI payloads.

Profile mutation commands validate that the target profile exists before
writing. Remove output includes a redacted rollback point and recovery wording,
but it does not include the raw profile config. To restore a removed profile,
re-import it from the original URI, file or provider source.

### `watchdog provider`

Imports, lists and updates external provider definitions and provider-owned
nodes.

```sh
watchdog provider add <url> [--name NAME] [--json]
watchdog provider list [--json]
watchdog provider stats <id> [--json]
watchdog provider update <id> [--json]
watchdog provider update --all [--json]
watchdog provider remove <id> [--json]
watchdog provider edit <id> [--name NAME] [--url URL] [--json]
watchdog provider rotation <id> --enable [--json]
watchdog provider rotation <id> --disable [--json]
watchdog provider node <provider_id> <node_id> --rotation --enable [--json]
watchdog provider node <provider_id> <node_id> --rotation --disable [--json]
```

Human output never prints raw subscription URLs. Provider stats print a redacted
URL and aggregate counts only. Provider list output shows provider ID, local
name, rotation state, node count, update time and trusted summary metadata such
as traffic and expiry when present.

Provider JSON uses redacted summary objects. It includes provider ID, local
name, redacted URL, rotation state, node count, last update, traffic/expiry
summary and `metadata_included=false`. It does not include raw provider
metadata, subscription URLs, endpoint tokens, private keys or raw profile
configs.

Provider mutation commands validate that the provider exists before target
writes. Provider node mutation also validates that the node belongs to the
selected provider. Remove output includes a redacted rollback point and
recovery wording, but it does not include the subscription URL. To restore a
removed provider, add it again from the original subscription URL.

The profile and provider stores do not currently define an automatic
store-level backup contract for these direct mutations. Task 22.3 therefore
adds redacted rollback guidance and JSON rollback points for destructive
removes without writing secret-bearing backup documents.

## Version And Panic

### `watchdog version`

Prints the canonical CLI version. The deprecated `watchdogvpn version` alias
delegates here and therefore cannot report a different version.

```sh
watchdog version
watchdog version --json
```

Human output:

```text
WatchdogVPN v0.3.1
```

JSON output includes `product`, `version` and `python_cli=true`.

### `watchdog panic`

Delegates to the standalone panic button script as an argv-list subprocess.
The Python CLI does not reimplement panic behavior.

```sh
watchdog panic status
watchdog panic sleep
watchdog panic wake
```

`status` reports the current panic/sleep state. `sleep` and `wake` preserve
the existing `watchdog_panic` behavior, including daemon, firewall,
domain-bypass and autostart effects documented in `docs/security.md`.

## Setup And Doctor

### `watchdog setup`

Configures local first-run preferences and policy defaults without starting
runtime services or contacting provider URLs.

```sh
watchdog setup --dry-run --json --language es --dns-mode auto
watchdog setup --yes --acknowledge-backup-warning --language es --autoconnect enable
watchdog setup --yes --acknowledge-backup-warning --profile-uri URI
watchdog setup --yes --acknowledge-backup-warning --provider-url URL --provider-name NAME
```

Supported setup fields:

- `--language LANG`: sets manual selected language in selection state;
- `--autostart enable|disable`: stores app autostart intent;
- `--autoconnect enable|disable`: stores VPN autoconnect intent;
- `--profile-uri URI`: imports one local profile URI without printing raw config;
- `--provider-url URL`: stores one HTTPS provider definition without fetching nodes;
- `--kill-switch enable|disable`: sets local kill-switch policy;
- `--dns-mode auto|off|custom|advanced`: sets DNS policy mode;
- `--app-policy enable|disable`: sets app-policy enabled state;
- `--app-policy-mode blacklist|whitelist`: sets app-policy mode;
- `--app-policy-default-action current|direct|block`: sets app-policy default.

`setup --dry-run` validates the plan and does not write local state. Setup first
compares every requested value and imported definition with effective local
state. An exact repeat returns `has_changes=false`, `outcome=no_changes`, an
empty `operations`/`sections` diff and `backup_path=null`; it does not require
write confirmation, create a backup or rewrite any store. Partial repeats back
up and write only sections with effective changes. Existing matching profiles
are recognized by their secret-safe semantic fingerprint, while matching
provider definitions preserve refreshed profiles, metadata and rotation state.

Real setup writes require both `--yes` and
`--acknowledge-backup-warning`. A pre-setup backup is created before effective
writes. Setup does not connect, disconnect, rotate, apply DNS, change routes,
edit firewall rules, mutate system proxy settings, start services or refresh
providers.

JSON output includes `has_changes`, `outcome` (`applied`, `dry_run` or
`no_changes`), `operations`, `sections`, `backup_path`,
`network_fetch_performed=false` and `runtime_action_executed=false`.

### `watchdog doctor`

Runs the installed or checkout `doctor.sh` through argv-list subprocess
execution.

```sh
watchdog doctor
watchdog doctor --json
```

The Python wrapper does not reimplement doctor logic. It resolves explicit
`--doctor-script` / `WATCHDOGVPN_DOCTOR_SCRIPT` first, then
`WATCHDOGVPN_REPO_DIR`, then the installed runtime support tree. JSON mode
captures doctor stdout/stderr and exit code in one JSON document. The command
is read-only and does not use `sudo`.

## Uninstall Flow

### `watchdog uninstall`

Runs the safe uninstall flow by wrapping `uninstall.sh` with explicit user-data
choices.

Installed systems resolve `uninstall.sh` from the installed runtime support
tree, independent of the current working directory. Source checkouts can still
set `WATCHDOGVPN_REPO_DIR` or use the hidden test/lab `--uninstall-script`
override.

```sh
watchdog uninstall --keep-data --yes
watchdog uninstall --keep-data --dry-run --json
watchdog uninstall --backup-first --backup-output ~/watchdogvpn-backup.zip --yes
watchdog uninstall --delete-all-data --confirm-delete DELETE --backup-output ~/watchdogvpn-pre-delete.zip --yes
```

Modes:

- `--keep-data`: uninstall product files while preserving WatchdogVPN config,
  logs and shared runtime state;
- `--backup-first`: export a backup outside WatchdogVPN-owned paths, then
  uninstall product files while preserving data;
- `--delete-all-data`: export a pre-delete backup outside WatchdogVPN-owned
  paths, then pass `--purge-config --purge-logs --purge-state` to
  `uninstall.sh`.

`--delete-all-data` requires `--confirm-delete DELETE`. Backups can be encrypted
with `--encrypt-backup --backup-password-env ENV_NAME`; the password is read
from the named environment variable and is not written to the backup manifest.

Backup output paths inside WatchdogVPN-owned paths are rejected so a pre-delete
backup is not deleted by the same uninstall operation.

`--dry-run` is plan-only in the Python CLI wrapper: it does not invoke
`uninstall.sh`, create backups or remove files. Real uninstall execution
requires `--yes`. JSON output includes the selected mode, dry-run state,
backup path, encryption state, argv-form command, product-managed files,
preserved user state, logs, backups and systemd unit contract.

## Backup Archives

### `watchdog backup create` / `watchdog backup export`

Creates a normal WatchdogVPN backup archive through `BackupManager`.

```sh
watchdog backup create --output ~/watchdogvpn-backup.zip
watchdog backup create --section profiles --section providers --json
watchdog backup export --output ~/watchdogvpn-backup.zip --encrypt --password-env WATCHDOGVPN_BACKUP_PASSWORD
```

Section names are validated by the backup manager. By default, diagnostics are
not included. Normal backups are sensitive archives and may contain private
keys, provider tokens, subscription URLs, routing policy, app policy, route
chains and local selection state. Backup JSON reports `normal_backup=true`,
`support_export=false` and `redacted_export=false` so automation does not
confuse full backups with redacted support exports.

Encrypted backups read the password from `--password-env`; passwords are not
accepted in command arguments or written to the manifest.

### `watchdog backup inspect`

Validates a backup archive manifest and section schema without printing section
payloads.

```sh
watchdog backup inspect ~/watchdogvpn-backup.zip --json
```

JSON output includes path, schema version, format, creation time, reason,
section names, encryption state and sensitive-data warning. It does not print
profile configs, provider metadata, subscription URLs, endpoint tokens, private
keys or raw backup section payloads.

### `watchdog backup restore` / `watchdog backup import`

Validates and restores a backup archive through `BackupManager`.

```sh
watchdog backup restore ~/watchdogvpn-backup.zip --dry-run --json
watchdog backup restore ~/watchdogvpn-backup.zip --confirm RESTORE-WATCHDOGVPN-BACKUP
watchdog backup import ~/watchdogvpn-backup.zip --mode merge --section routing-rules
```

Dry-run restore validates the archive, selected sections and merge-section
compatibility without writing local state or creating a pre-restore backup.
Real replace restore requires the literal confirmation
`RESTORE-WATCHDOGVPN-BACKUP`; real restore creates a pre-restore backup and
returns `pre_restore_backup` in JSON.

## Runtime Commands

### `watchdog status`

Shows daemon-backed WatchdogVPN runtime status through the canonical IPC
contract.

```sh
watchdog status
```

Use this for a quick operational view after install, update, reboot or recovery.

### `watchdog maintenance backend status`

Shows the active backend contract without changing runtime state.

```sh
watchdog maintenance backend status
```

The legacy bash backend contract is custom-vps-only. It controls a local
systemd service configured by the user and fails closed if required
configuration, such as `custom_vps.service_name`, is missing.

### `watchdog doctor`

Runs the installed or checkout doctor script when available.

```sh
watchdog doctor
```

Installed systems do not need to run this from the repository root; the
installed runtime support tree is used when present.

### `watchdog maintenance tui`

Opens the WatchdogVPN terminal UI.

```sh
watchdog maintenance tui
```

This is equivalent to launching:

```sh
VPN
```

`VPN` is kept because it is short and already familiar for interactive use.

## Observability Stats

## DNS Policy And State

The Python DNS commands expose DNS policy status, resolver testing,
configured-policy diagnostics and bounded apply/reset operations.

```sh
watchdog dns status [--json]
watchdog dns test [--json]
watchdog dns diagnose [--domain DOMAIN] [--ip IP] [--process-name NAME] [--json]
watchdog dns apply --dry-run [--json]
watchdog dns apply --yes [--json]
watchdog dns reset --yes [--json]
```

DNS policy CRUD is available without touching the active system resolver:

```sh
watchdog dns channel add <channel> [--json]
watchdog dns channel remove <channel> [--json]
watchdog dns resolver add <channel> <uri> [--label LABEL] [--disabled] [--json]
watchdog dns resolver remove <channel> <uri> [--json]
watchdog dns resolver enable <channel> <uri> [--json]
watchdog dns resolver disable <channel> <uri> [--json]
watchdog dns rule add <id> --pattern TYPE:VALUE --action use_channel --channel <channel> [--priority N] [--disabled] [--json]
watchdog dns rule add <id> --pattern TYPE:VALUE --action reject [--priority N] [--disabled] [--json]
watchdog dns rule remove <id> [--json]
watchdog dns rule enable <id> [--json]
watchdog dns rule disable <id> [--json]
watchdog dns static-ip add <domain> <ip> [--disabled] [--json]
watchdog dns static-ip remove <domain> [--ip IP] [--json]
```

These commands mutate only the stored DNS policy. They validate and
round-trip the complete policy before writing, create a restorable backup,
and return `backup_path` plus `rollback_point` in JSON. These
commands do not activate the policy; activation remains the separately
confirmed `watchdog dns apply --yes` operation.

Resolver URIs are validated when added, channels accept at most four
resolvers, and duplicate resolver URIs are rejected. Removing a channel is
refused while a DNS rule references it. A `use_channel` rule requires an
existing channel, while a `reject` rule refuses `--channel`. Static mappings
require a valid domain and IP address. The per-entry `--disabled` flags are
independent from the top-level `dns.rules_enabled` and
`dns.static_ip_enabled` policy switches.

`dns status`, `dns test` and `dns diagnose` are read-only. `dns apply --dry-run`
returns the apply plan without creating a DNS snapshot or mutating resolver
state. Real apply requires `--yes`, refuses non-standard system resolver ports,
saves or reuses rollback snapshot metadata and returns `rollback_snapshot` plus
`snapshot_saved` in JSON. `dns reset` requires `--yes`, restores from the saved
snapshot, removes the snapshot file after successful restore and returns
`rollback_snapshot.restored=true` in JSON.

Normal tests and local CLI validation must use mocked managers or isolated
temporary resolver files. Do not run DNS apply/reset against the workstation's
real resolver paths unless an explicit VM/lab validation task calls for it.

### `watchdog stats status`

Shows local observability metrics state.

```sh
watchdog stats status
watchdog stats status --json
```

The command is read-only and does not create `metrics.json` when metrics are
absent. It reports enabled state, privacy mode, retention, bucket count, total
aggregate event count and whether detailed request history is supported.

Detailed request history is not supported in Phase 16.

### `watchdog stats summary`

Shows aggregate local metrics counters.

```sh
watchdog stats summary
watchdog stats summary --json
```

The summary exposes known aggregate counter families only. Unknown or
DNS-query-like counter keys are withheld from the summary and counted as
`withheld_counter_keys`.

### `watchdog stats purge`

Purges the local metrics store.

```sh
watchdog stats purge --yes
watchdog stats purge --yes --json
```

The command refuses to run without `--yes`.

JSON output reports whether a file was purged, does not include metric buckets
or raw counters, and keeps `history_included=false`.

### `watchdog stats privacy-mode`

Sets the local metrics privacy mode.

```sh
watchdog stats privacy-mode off
watchdog stats privacy-mode aggregate
watchdog stats privacy-mode detailed
watchdog stats privacy-mode detailed --json
```

`off` disables metrics recording. `aggregate` enables aggregate counters.
`detailed` stores the policy mode value but does not enable request history,
because detailed history is not implemented in Phase 16.

JSON output keeps `detailed_history_supported=false` and
`history_included=false` even when the selected mode is `detailed`.

## Rule Diagnostics

## Routing Policy Commands

The Python policy commands mutate local policy stores only. They do not connect,
disconnect, refresh providers, apply DNS, edit firewall rules, change routes or
start capture.

### `watchdog rules`

Manages local routing rule groups.

```sh
watchdog rules list [--json]
watchdog rules enable <group> [--json]
watchdog rules disable <group> [--json]
watchdog rules add-rule <group> <rule_id> --action ACTION --condition KEY=VALUE [--json]
watchdog rules remove-rule <group> <rule_id> [--json]
watchdog rules set-priority <group> <priority> [--json]
watchdog rules enable-rule <group> <rule_id> [--json]
watchdog rules disable-rule <group> <rule_id> [--json]
watchdog rules import <file> [--replace] [--dry-run] [--json]
watchdog rules export <group> (--output PATH|--json)
```

Rule list JSON returns rule-group summaries with `name`, `enabled`,
`priority`, `rule_count` and `rules`. Mutation JSON returns the changed group,
`backup_path` when a group-level backup is created and a `rollback_point`.
`rules import` also returns `section_backup_path` for the pre-import routing
rules backup. Dry-run imports do not write policy or backups and return
`rollback_point.kind = "preview-only"`.

Every real `rules` mutation validates the target group/rule before writing.
Group enable/disable, per-rule enable/disable, priority changes, add-rule,
remove-rule and replace import create a backup before the active group changes.
New imports create a section backup and report that rollback is deleting the
imported group.

### `watchdog app-policy`

Manages local Linux app/process routing policy.

```sh
watchdog app-policy status [--json]
watchdog app-policy enable [--json]
watchdog app-policy disable [--json]
watchdog app-policy mode <blacklist|whitelist> [--json]
watchdog app-policy default-action <current|direct|block> [--json]
watchdog app-policy add --process-name NAME --action ACTION [--id ID] [--json]
watchdog app-policy add --process-path PATH --action ACTION [--id ID] [--json]
watchdog app-policy add --process-path-regex REGEX --action ACTION [--id ID] [--json]
watchdog app-policy add --user NAME --action ACTION [--id ID] [--json]
watchdog app-policy add --user-id UID --action ACTION [--id ID] [--json]
watchdog app-policy enable-rule <id> [--json]
watchdog app-policy disable-rule <id> [--json]
watchdog app-policy remove <id> [--json]
```

Status JSON returns `valid`, `error`, `policy`, `rule_count`,
`enabled_rule_count` and `rules`. Rule entries include `match_confidence`.
Mutation JSON adds `backup_path` and a `rollback_point` with
`kind = "section-backup"` and `section = "app-policy"`.

Every app-policy mutation validates the resulting policy before writing and
creates a restorable app-policy backup first. Missing or duplicate rule IDs
include recovery wording pointing operators back to
`watchdog app-policy status`. Exactly one matcher is accepted per `add` call.
Path regular expressions are compiled and rejected if invalid; user IDs must
be non-negative integers. Process paths and numeric user IDs have high match
confidence, path regular expressions and user names have medium confidence,
and process names have low confidence. Inspect `match_confidence` before
depending on a broad matcher for a censorship-sensitive routing decision.

### `watchdog node-group`

Manages local node groups and manual/auto selection intent.

```sh
watchdog node-group list [--json]
watchdog node-group create <name> [--json]
watchdog node-group add-profile <group> <profile> [--json]
watchdog node-group select <group> <profile|auto> [--json]
watchdog node-group add-provider <group> <provider> [--json]
watchdog node-group remove-provider <group> <provider> [--json]
watchdog node-group exclude <group> <profile> [--json]
watchdog node-group unexclude <group> <profile> [--json]
watchdog node-group resilience <group> <resilient_only|preferred|compatibility_allowed> [--json]
watchdog node-group enable <group> [--json]
watchdog node-group disable <group> [--json]
watchdog node-group auto-test <group> [--json]
```

Node-group list JSON returns the stored group document. Mutation JSON returns
the changed `group`, `backup_path` and a `rollback_point` with
`kind = "section-backup"` and `section = "node-groups"`. `add-profile` also
returns `added_profile_id`; manual `select` returns `selected_profile_id`.

Every node-group mutation validates the target group and profile references
before writing and creates a restorable node-groups backup first. Missing
profiles point operators to `watchdog profile list`; provider membership
validates against `watchdog provider list`; duplicate or missing groups point
operators to `watchdog node-group list`. Explicit exclusions take precedence
over profiles discovered through provider membership.

`resilient_only` fails closed when no resilient candidate is healthy and
never silently falls back to a compatibility profile. `preferred` allows a
compatibility fallback after resilient candidates; `compatibility_allowed`
opts out of resilience-category preference. Manual selection is a hard pin:
if the selected profile becomes unavailable, it does not silently change to
automatic selection.

`watchdog node-group auto-test` is a daemon IPC command. It asks the daemon to
evaluate the configured group and does not mutate local policy by itself.

### `watchdog chain`

Manages ordered, persistent multi-hop route chains.

```sh
watchdog chain list [--json]
watchdog chain show <id> [--json]
watchdog chain create <id> --hop profile:<profile> --hop group:<group> [--description TEXT] [--json]
watchdog chain add-hop <id> --type <profile|group> --target <id> [--selection-policy group_policy] [--json]
watchdog chain remove-hop <id> --index <one-based-index> [--json]
watchdog chain enable <id> [--json]
watchdog chain disable <id> [--json]
watchdog chain remove <id> [--json]
```

Chain creation and hop insertion validate every referenced profile or node
group before writing. New chains start disabled. Enabling revalidates every
hop, so a stale or missing reference cannot become active. Removing the last
hop is refused; remove the chain explicitly instead. Every mutation creates a
restorable `route-chains` section backup and returns its rollback metadata in
JSON. These commands change only the local route-chain store and do not
connect, disconnect or alter live network state.

### `watchdog rules explain`

Explains the configured routing decision for hypothetical traffic without
observing live packets or changing connectivity.

```sh
watchdog rules explain --domain example.com
watchdog rules explain --ip 203.0.113.42 --json
watchdog rules explain --domain example.com --process-name curl
```

The command reports the Phase 19 routing shape:

- `routing_policy`: `rule` evaluates route rules; `global` ignores route rules
  and uses the default route action for captured traffic;
- `capture_modes`: reported for context only; the diagnostic does not start or
  modify capture;
- `default_route_action`: used when no rule matches under `rule`, and always
  used under `global`;
- `active_mode`: displayed only as a compatibility mirror and never used as the
  diagnostic decision source.

JSON output is a superset of the older rule-explanation model. Existing fields
such as `matched`, `priority_path`, `skipped_conditions`,
`unevaluated_rule_sets` and `confidence` remain present, with additional route
diagnostic fields including `route_action`, `route_action_status`,
`route_source`, `routing`, `rule_evaluation`, `no_rule_match`,
`diagnostic_scope` and `runtime_observation`.

Confidence remains intentionally conservative:

- `definitive`: static configuration is enough to state the route action;
- `partial`: more input is needed, or app-policy matchers exist that cannot be
  evaluated from the supplied fields;
- `runtime-required`: remote or built-in rule-set contents can affect the
  result and require the runtime;
- `unknown`: the input is insufficient to diagnose a rule-policy decision.

Rule-set references are not expanded by the Python diagnostic. They are
reported as unevaluated with trust/cache status loaded from
`ruleset-trust.json`, including missing policy, `stale`, `failed`,
`fail-closed` and `warn-and-skip` states when available.

## Routing And Capture Contract

### `watchdog config routing-contract`

Shows the Phase 19 routing/capture contract without changing runtime state.

```sh
watchdog config routing-contract
watchdog config routing-contract --json
```

The command reports the current routing state, connectable capture-mode sets,
representable fail-closed system-proxy intent, invalid capture examples, and
notes that `direct` is a route action rather than a capture mode.

Explicit routing-shape setters are available for operator validation and future
CLI wiring:

```sh
watchdog config set routing-policy rule
watchdog config set routing-policy global
watchdog config set capture-modes local_proxy
watchdog config set capture-modes local_proxy,tun
watchdog config set default-route-action current
watchdog config set default-route-action direct
watchdog config set default-route-action block
```

`system_proxy` may be represented only with `local_proxy`, but runtime connect
remains fail-closed until the dedicated system-proxy apply/restore task is
implemented and installed-VM validated.

## Phase 20 LAN Sharing

WatchdogVPN stores LAN sharing intent under `lan_sharing`. Authenticated
SOCKS/HTTP LAN proxy listeners are exposed only when
`lan_sharing.enabled = true` and `lan_sharing.mode = proxy`. Disabled-by-default
IPv4 LAN gateway mode is selected with `lan_sharing.mode = gateway`.

Gateway mode passed the Phase 20 VM/lab matrix, but remains explicit,
disabled by default and bounded to the documented IPv4/manual-DNS contract.

Supported scaffold keys:

```sh
watchdog config set lan_sharing.enabled <true|false>
watchdog config set lan_sharing.mode <disabled|proxy|gateway>
watchdog config set lan_sharing.bind_address <ip-address>
watchdog config set lan_sharing.socks_port <port>
watchdog config set lan_sharing.http_port <port>
watchdog config set lan_sharing.authentication_required <true|false>
watchdog config set lan_sharing.firewall_managed <true|false>
watchdog config set lan_sharing.gateway_interface <interface>
watchdog config set lan_sharing.gateway_client_cidr <ipv4-cidr>
watchdog config set lan_sharing.gateway_dns_mode manual
```

Gateway mode requires TUN capture, a concrete non-loopback interface,
`firewall_managed = true`, manual LAN-client DNS and an IPv4 client CIDR. It
uses WatchdogVPN-owned nftables rules and temporary IPv4 forwarding with
rollback on disconnect or failed apply.

Validation rules:

- LAN sharing is disabled by default.
- `mode` must be `disabled`, `proxy` or `gateway`.
- `bind_address` must be an IP address when set.
- wildcard binds such as `0.0.0.0` and `::` are rejected outside explicit test
  fixtures.
- enabled LAN sharing requires `mode = proxy`, an explicit non-loopback
  `bind_address`, and `authentication_required = true`.
- SOCKS and HTTP ports must be in `1..65535` and must differ.
- the runtime refuses to apply LAN sharing if `bind_address` is not assigned to
  a local interface.

When enabled and connected through the sing-box runtime, WatchdogVPN keeps the
existing loopback inbounds and adds:

- `watchdogvpn-lan-socks-in` on `bind_address:socks_port`;
- `watchdogvpn-lan-http-in` on `bind_address:http_port`.

Both LAN inbounds require generated username/password authentication. The
credentials are stored in `lan-sharing-credentials.json` with private file
permissions. Normal config JSON output does not print the password.

Credential status:

```sh
watchdog config lan-sharing-credentials
watchdog config lan-sharing-credentials --json
watchdog config lan-sharing-credentials --show-secret
```

`--show-secret` is the explicit secret-output flag. Use it only in a trusted
terminal.

Firewall state is not managed in Task 20.3. Opening or restricting LAN access is
the operator's responsibility until a later Phase 20 task implements managed
firewall apply/teardown.

## Rule-Set Runtime Lifecycle

### `watchdog ruleset status`

Shows trusted remote and built-in rule-set policies plus their cache status.

```sh
watchdog ruleset status
watchdog ruleset status --json
```

The command reads `ruleset-trust.json`. Remote rule-set policies must be
explicitly pinned with SHA-256 before runtime can use them.

### `watchdog ruleset refresh`

Refreshes WatchdogVPN-owned rule-set cache files.

```sh
watchdog ruleset refresh
watchdog ruleset refresh remote-ads --force
watchdog ruleset refresh --referenced-only --json
```

Remote downloads require HTTPS and a matching `expected_sha256` pin. Built-in
rule sets load from explicit local source paths. Runtime uses verified local
cache files in sing-box rather than sing-box remote rule-set downloads.

### `watchdog ruleset add` / `watchdog ruleset remove`

Mutates the local rule-set trust registry without downloading or activating a
rule set.

```sh
watchdog ruleset add <id> --kind remote --source https://example.invalid/rules.srs --sha256 <64-hex-digest> [--critical|--no-critical] [--failure-behavior fail-closed|warn-and-skip] [--json]
watchdog ruleset add <id> --kind built-in --source <local-path> [--json]
watchdog ruleset remove <id> [--json]
```

Remote policies are rejected unless the source uses HTTPS and an exact SHA-256
pin is supplied. Update and maximum-stale intervals must be positive, and the
maximum-stale interval cannot be shorter than the update interval. Policies
are critical by default: their default failure behavior is `fail-closed`;
non-critical policies default to `warn-and-skip`. An existing trust registry
is backed up before add or remove. Use `watchdog ruleset refresh` separately to
fetch and verify a remote policy after reviewing the stored trust contract.

### Canonical version and compatibility alias

`watchdog version` prints the installed CLI version. `watchdogvpn version` and
`watchdogvpn --version` are compatibility forms that delegate to the same
canonical command and add only the deprecation warning on stderr.

```sh
watchdog version
```

Expected output for the current release:

```text
WatchdogVPN v0.3.1
```

### Canonical root help

`watchdog --help` is the only root help. Compatibility help delegates to it and
therefore has identical stdout.

```sh
watchdog --help
watchdog maintenance --help
watchdog maintenance logs --help
watchdog maintenance update-check --help
watchdog maintenance update-plan --help
watchdog maintenance runtime-update --help
watchdog maintenance config --help
watchdog maintenance backend --help
```

The root help owns all daemon-backed lifecycle, configuration and policy
commands and links the maintenance namespace. The deprecated alias does not
maintain a second command inventory. Root help and generated argparse route
help wrap dynamically to the detected terminal width. Root and profile-list
help are regression-tested at 40, 80 and 120 columns; every argparse-owned help
route is additionally checked at 40 columns.

## Diagnostic Reports

### `watchdog maintenance report`

Generates a local diagnostic report.

```sh
watchdog maintenance report
```

Rules:

- Nothing is uploaded automatically.
- The report is written to a local text file.
- The user must review the file before sharing it.
- Sensitive sample data is sanitized where possible.
- Observability metrics are summarized only through the Phase 16 redacted
  export contract.
- Raw metrics stores, profile ids, rule-group names, named node groups,
  route-action group labels and DNS-query-like counter keys are excluded from
  normal reports.

The report may include runtime status, doctor-adjacent checks, VPN truth state,
daemon state, DNS test output, a redacted observability summary and recent
troubleshooting context. See [Reporting Issues](reporting.md) for safe sharing
guidance.

## Local Logs

### `watchdog maintenance logs`

Reads recent local WatchdogVPN logs without using `sudo`.

```sh
watchdog maintenance logs
watchdog maintenance logs events 80
watchdog maintenance logs dispatcher 80
```

Supported targets:

```text
events      /var/log/myvpn/vpn-events.log
dispatcher  /var/log/myvpn/vpn-dispatcher.log
```

Rules:

- Defaults to `events` and 80 lines.
- Accepts 1 to 500 lines.
- Sanitizes obvious home paths, email addresses and IPv4 addresses.
- Sanitizes common IPv6 literals.
- Does not call `sudo`.
- Does not modify logs, services, configuration or VPN state.

## Update State

### `watchdog maintenance update-check`

Shows local source checkout status without contacting the network.

```sh
watchdog maintenance update-check
```

Reported fields include:

- WatchdogVPN CLI version.
- Repository root.
- Current branch.
- Current commit.
- Configured upstream.
- Origin URL, sanitized for obvious sensitive values.
- Local upstream sync state: `up to date`, `behind`, `ahead`, `diverged`,
  `no upstream` or `unknown`.
- Local working tree state: `clean` or `dirty`.
- Latest local tag.

Rules:

- Does not run `git fetch`.
- Does not run `git pull`.
- Does not run `git push`.
- Does not run `update.sh`.
- Does not use `sudo`.
- Uses only local Git metadata already present in the checkout.

### `watchdog maintenance update-plan`

Prints a safe manual update plan for the current checkout state.

```sh
watchdog maintenance update-plan
```

The command uses the same local Git metadata as
`watchdog maintenance update-check`.
It prints commands and guidance only.

Rules:

- Does not run `git fetch`.
- Does not run `git pull`.
- Does not run `git push`.
- Does not run `update.sh`.
- Does not use `sudo`.
- Does not recommend runtime update steps while the working tree is dirty,
  diverged, missing an upstream or otherwise ambiguous.

When the source checkout is clean and safe to proceed, it prints the installed
runtime update routine:

```sh
sudo -v
./update.sh --skip-doctor
hash -r
./doctor.sh
```

### `watchdog maintenance runtime-update`

Runs the confirmed runtime update flow.

```sh
watchdog maintenance runtime-update
watchdog maintenance runtime-update --preflight
watchdog maintenance runtime-update --help
```

Current `v0.3.1` behavior:

- Runs preflight before executing state-changing steps.
- Prints the exact command order before executing it.
- Requires explicit confirmation: `yes`.
- Runs `git fetch origin --tags`.
- Recomputes repository safety state after fetch.
- Runs `git pull --ff-only origin main`.
- Runs `./update.sh --skip-doctor`.
- Runs `hash -r`.
- Runs `./doctor.sh`.
- Stops at the first failure.
- Reports the failed step and last successful step.

The command refuses to continue when:

- the command is not running from a Git checkout;
- the current branch is not `main`;
- no upstream is configured;
- the working tree is dirty;
- the local branch is ahead of upstream;
- the local branch has diverged from upstream;
- upstream state is unknown;
- `update.sh` is missing or not executable;
- `doctor.sh` is missing or not executable.

When all checks pass and the user confirms, it runs:

```sh
git fetch origin --tags
git pull --ff-only origin main
./update.sh --skip-doctor
hash -r
./doctor.sh
```

Use `watchdog maintenance runtime-update --preflight` to run only the safety checks. In
preflight mode, the command does not fetch, pull, run `update.sh`, run
`doctor.sh` or use `sudo`.

## Configuration Commands

Persistent configuration lives at:

```text
/etc/watchdogvpn/config.toml
```

The default schema is installed from:

```text
/etc/watchdogvpn/config.toml.example
```

See [Configuration](configuration.md) for the full contract.

### `watchdog maintenance config get`

Prints the sanitized configuration.

```sh
watchdog maintenance config get
```

Print one key:

```sh
watchdog maintenance config get language.current
```

### `watchdog maintenance config set`

Updates a supported safe key after validation.

```sh
sudo watchdogvpn config set language.current es
sudo watchdogvpn config set tui.theme high_contrast
sudo watchdogvpn config set tui.color false
sudo watchdogvpn config set reporting.sanitize_ipv4 true
```

Each successful write creates a backup before modifying the active config.

Currently writable keys:

```text
language.current
language.auto_detect
tui.theme
tui.color
tui.unicode
reporting.sanitize_ipv4
reporting.sanitize_ipv6
reporting.sanitize_email
reporting.sanitize_home
```

Current accepted values:

```text
language.current: en, es, ru, fa, zh_CN, ar, fr
language.auto_detect: true, false
tui.theme: default, high_contrast, no_color
tui.color: true, false
tui.unicode: true, false
reporting.sanitize_ipv4: true, false
reporting.sanitize_ipv6: true, false
reporting.sanitize_email: true, false
reporting.sanitize_home: true, false
```

Timer and DNS keys are intentionally read-only until they are wired to runtime
application logic.

### `watchdog maintenance config reset`

Resets safe sections to default values from `config.toml.example`.

```sh
watchdog maintenance config reset language --yes
watchdog maintenance config reset tui --yes
watchdog maintenance config reset reporting --yes
watchdog maintenance config reset all --yes
```

Rules:

- `--yes` is required.
- A backup is created before changes are made.
- Only safe user-interface and reporting sections are reset.
- `timers` and `dns` are not resettable yet.

## Exit Behavior

The CLI uses non-zero exit codes for invalid commands, invalid config keys,
invalid values and unavailable files. Scripts should check command exit status
instead of parsing user-facing text.

Common root and nested command typos provide one bounded suggestion, for
example `statu` -> `watchdog status`, `profile lst` ->
`watchdog profile list`, and `dns statsu` -> `watchdog dns status`. Suggestions
are informational only: the invalid command is never executed and the process
still exits with argparse code `2`. Distant or ambiguous input receives no
guess and points to the relevant `--help`. JSON parse errors keep the standard
stdout envelope and include the same suggestion in `error`.

Signal and pipeline handling is centralized for every Python CLI command:

- Ctrl+C exits with `130` (`128 + SIGINT`). Human mode writes one brief
  `error: operation cancelled` diagnostic to stderr. JSON mode writes one error
  envelope to stdout. Neither mode emits a traceback.
- A broken output pipe exits with `141` (`128 + SIGPIPE`) without a diagnostic
  or traceback because the downstream consumer has already closed the stream.
  With `set -o pipefail`, an intentionally truncated pipeline such as
  `watchdog doctor | head -n 5` can therefore return `141`; without `pipefail`,
  the pipeline normally reports the downstream command's status.
- Support subprocesses terminated by a signal use the same shell-compatible
  `128 + signal` convention. JSON wrapper fields such as
  `doctor_exit_code` and `uninstall_exit_code` contain that normalized code,
  never Python's negative `subprocess` representation.

## Safety Notes

- Do not share diagnostic reports before reviewing them.
- Do not edit `/etc/watchdogvpn/config.toml` while another update or config
  command is running.
- Prefer `sudo watchdogvpn config set` over manual edits for the legacy
  language/TUI/reporting preference keys it supports.
- Use `./update.sh --skip-doctor` from a clean, current checkout when updating
  installed runtime files.
- If you need to put WatchdogVPN completely to sleep (daemon, kill switch,
  domain-bypass routing) without uninstalling it, run `watchdog panic sleep`;
  `watchdog panic wake` resumes it. The standalone `watchdog_panic` script
  remains available for emergency use. See `docs/security.md`
  "WatchdogVPN Panic Button".
