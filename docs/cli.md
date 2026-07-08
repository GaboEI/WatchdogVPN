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
watchdog config set lan_sharing.mode <disabled|proxy>
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
watchdog uninstall --keep-data --yes
watchdog uninstall --backup-first --backup-output ~/watchdogvpn-backup.zip --yes
watchdog uninstall --delete-all-data --confirm-delete DELETE --backup-output ~/watchdogvpn-pre-delete.zip --yes
watchdog stats status [--json]
watchdog stats summary [--json]
watchdog stats purge --yes
watchdog stats privacy-mode <off|aggregate|detailed>
watchdog rules explain [--domain DOMAIN] [--ip IP] [--process-name NAME] [--json]
watchdog ruleset status [--json]
watchdog ruleset refresh [RULE_SET_ID ...] [--referenced-only] [--force] [--json]
```

## Uninstall Flow

### `watchdog uninstall`

Runs the safe uninstall flow by wrapping `uninstall.sh` with explicit user-data
choices.

Run it from the WatchdogVPN checkout, or set `WATCHDOGVPN_REPO_DIR` to the
checkout path if launching from another directory.

```sh
watchdog uninstall --keep-data --yes
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

Runs the repository doctor when the command can find it from the current
checkout.

```sh
watchdogvpn doctor
```

For installed systems, `./doctor.sh` from the repository root remains the most
complete validation path.

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
```

The command refuses to run without `--yes`.

### `watchdog stats privacy-mode`

Sets the local metrics privacy mode.

```sh
watchdog stats privacy-mode off
watchdog stats privacy-mode aggregate
watchdog stats privacy-mode detailed
```

`off` disables metrics recording. `aggregate` enables aggregate counters.
`detailed` stores the policy mode value but does not enable request history,
because detailed history is not implemented in Phase 16.

## Rule Diagnostics

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

Phase 20 stores LAN sharing intent under `lan_sharing`. On the dedicated Phase
20 branch, Task 20.3 can expose authenticated SOCKS/HTTP LAN proxy listeners
when `lan_sharing.enabled = true`.

This remains branch-only until Phase 20 closes. It does not implement gateway
routing, NAT, IP forwarding, DNS listener exposure or firewall rule management.

Supported scaffold keys:

```sh
watchdog config set lan_sharing.enabled <true|false>
watchdog config set lan_sharing.mode <disabled|proxy>
watchdog config set lan_sharing.bind_address <ip-address>
watchdog config set lan_sharing.socks_port <port>
watchdog config set lan_sharing.http_port <port>
watchdog config set lan_sharing.authentication_required <true|false>
watchdog config set lan_sharing.firewall_managed <true|false>
```

Validation rules:

- LAN sharing is disabled by default.
- `mode` must be `disabled` or `proxy`.
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

## Safety Notes

- Do not share diagnostic reports before reviewing them.
- Do not edit `/etc/watchdogvpn/config.toml` while another update or config
  command is running.
- Prefer `watchdogvpn config set` over manual edits for supported keys.
- Use `./update.sh --skip-doctor` from a clean, current checkout when updating
  installed runtime files.
- If you need to put WatchdogVPN completely to sleep (daemon, kill switch,
  domain-bypass routing) without uninstalling it, run `watchdog_panic sleep`;
  `watchdog_panic wake` resumes it. See `docs/security.md`
  "WatchdogVPN Panic Button".
