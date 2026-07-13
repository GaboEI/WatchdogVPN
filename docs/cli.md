# WatchdogVPN CLI

`watchdogvpn` is the product command for diagnostics, configuration and common
runtime entry points.

The legacy `VPN` command remains the direct TUI launcher. New automation and
documentation should prefer `watchdogvpn`.

## Command Summary

Read-only commands:

```sh
watchdogvpn status
watchdogvpn backend status
watchdogvpn doctor
watchdogvpn report
watchdogvpn logs [events|dispatcher] [lines]
watchdogvpn update-check
watchdogvpn update-plan
watchdogvpn runtime-update --preflight
watchdogvpn config get [section.key]
watchdog config routing-contract [--json]
watchdogvpn version
watchdogvpn help
watchdogvpn --help
```

Configuration commands:

```sh
watchdogvpn config set section.key value
watchdogvpn config reset [language|tui|reporting|all] --yes
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
watchdogvpn runtime-update --preflight
```

State-changing runtime commands:

```sh
watchdogvpn runtime-update
```

`runtime-update` validates whether a runtime update is safe, prints the exact
execution plan and requires explicit `yes` confirmation before it changes the
source checkout or installed runtime. Its full safety contract is documented in
[Runtime Update Contract](runtime-update-contract.md).

Interactive commands:

```sh
watchdogvpn tui
```

Python runtime commands:

```sh
watchdog connect <profile_id> [--json]
watchdog disconnect [--json]
watchdog status [--json]
watchdog rotate [--force] [--json]
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
watchdog profile list [--json] [--pool]
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

Prints the Python CLI version using the same release marker as
`watchdogvpn version`.

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

### `watchdogvpn status`

Shows VPN runtime status through `vpnctl`.

```sh
watchdogvpn status
```

Use this for a quick operational view after install, update, reboot or recovery.

### `watchdogvpn backend status`

Shows the active backend contract without changing runtime state.

```sh
watchdogvpn backend status
```

The legacy bash backend contract is custom-vps-only. It controls a local
systemd service configured by the user and fails closed if required
configuration, such as `custom_vps.service_name`, is missing.

### `watchdogvpn doctor`

Runs the installed or checkout doctor script when available.

```sh
watchdogvpn doctor
```

Installed systems do not need to run this from the repository root; the
installed runtime support tree is used when present.

### `watchdogvpn tui`

Opens the WatchdogVPN terminal UI.

```sh
watchdogvpn tui
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
Group enable/disable, add-rule, remove-rule and replace import create a backup
before the active group changes. New imports create a section backup and report
that rollback is deleting the imported group.

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
watchdog app-policy remove <id> [--json]
```

Status JSON returns `valid`, `error`, `policy`, `rule_count`,
`enabled_rule_count` and `rules`. Rule entries include `match_confidence`.
Mutation JSON adds `backup_path` and a `rollback_point` with
`kind = "section-backup"` and `section = "app-policy"`.

Every app-policy mutation validates the resulting policy before writing and
creates a restorable app-policy backup first. Missing or duplicate rule IDs
include recovery wording pointing operators back to
`watchdog app-policy status`.

### `watchdog node-group`

Manages local node groups and manual/auto selection intent.

```sh
watchdog node-group list [--json]
watchdog node-group create <name> [--json]
watchdog node-group add-profile <group> <profile> [--json]
watchdog node-group select <group> <profile|auto> [--json]
watchdog node-group auto-test <group> [--json]
```

Node-group list JSON returns the stored group document. Mutation JSON returns
the changed `group`, `backup_path` and a `rollback_point` with
`kind = "section-backup"` and `section = "node-groups"`. `add-profile` also
returns `added_profile_id`; manual `select` returns `selected_profile_id`.

Every node-group mutation validates the target group and profile references
before writing and creates a restorable node-groups backup first. Missing
profiles point operators to `watchdog profile list`; duplicate or missing
groups point operators to `watchdog node-group list`.

`watchdog node-group auto-test` is a daemon IPC command. It asks the daemon to
evaluate the configured group and does not mutate local policy by itself.

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

### `watchdogvpn version`

Prints the installed CLI version.

```sh
watchdogvpn version
```

Expected output for the current release:

```text
WatchdogVPN v0.3.1
```

### `watchdogvpn help`

Prints grouped command help.

```sh
watchdogvpn help
watchdogvpn --help
watchdogvpn help logs
watchdogvpn help update-check
watchdogvpn help update-plan
watchdogvpn help runtime-update
watchdogvpn help config
watchdogvpn help backend
```

The help output separates read-only commands, configuration-write commands and
interactive commands. The Python `watchdog` CLI owns daemon-backed connect,
disconnect, status and rotate commands for the v2 runtime.

## Diagnostic Reports

### `watchdogvpn report`

Generates a local diagnostic report.

```sh
watchdogvpn report
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

### `watchdogvpn logs`

Reads recent local WatchdogVPN logs without using `sudo`.

```sh
watchdogvpn logs
watchdogvpn logs events 80
watchdogvpn logs dispatcher 80
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

### `watchdogvpn update-check`

Shows local source checkout status without contacting the network.

```sh
watchdogvpn update-check
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

### `watchdogvpn update-plan`

Prints a safe manual update plan for the current checkout state.

```sh
watchdogvpn update-plan
```

The command uses the same local Git metadata as `watchdogvpn update-check`.
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

### `watchdogvpn runtime-update`

Runs the confirmed runtime update flow.

```sh
watchdogvpn runtime-update
watchdogvpn runtime-update --preflight
watchdogvpn runtime-update --help
watchdogvpn help runtime-update
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

Use `watchdogvpn runtime-update --preflight` to run only the safety checks. In
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

### `watchdogvpn config get`

Prints the sanitized configuration.

```sh
watchdogvpn config get
```

Print one key:

```sh
watchdogvpn config get language.current
```

### `watchdogvpn config set`

Updates a supported safe key after validation.

```sh
watchdogvpn config set language.current es
watchdogvpn config set tui.theme high_contrast
watchdogvpn config set tui.color false
watchdogvpn config set reporting.sanitize_ipv4 true
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

### `watchdogvpn config reset`

Resets safe sections to default values from `config.toml.example`.

```sh
watchdogvpn config reset language --yes
watchdogvpn config reset tui --yes
watchdogvpn config reset reporting --yes
watchdogvpn config reset all --yes
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
- Prefer `watchdogvpn config set` over manual edits for supported keys.
- Use `./update.sh --skip-doctor` from a clean, current checkout when updating
  installed runtime files.
- If you need to put WatchdogVPN completely to sleep (daemon, kill switch,
  domain-bypass routing) without uninstalling it, run `watchdog panic sleep`;
  `watchdog panic wake` resumes it. The standalone `watchdog_panic` script
  remains available for emergency use. See `docs/security.md`
  "WatchdogVPN Panic Button".
