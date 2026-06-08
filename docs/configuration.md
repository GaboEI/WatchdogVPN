# Configuration

This document defines the planned persistent configuration contract for
WatchdogVPN `v0.2.0`.

The goal is to separate product defaults from user preferences so installs,
updates and future CLI/TUI features can evolve without overwriting local choices.

## Status

Persistent configuration is being introduced for `v0.2.0`.

`v0.1.1` preserves existing product-managed configuration files such as
`/etc/adguardvpn.env`, `/etc/vpn-domain-bypass.conf`, AdGuard Home user
configuration, Conky configuration, logs and rotation state. It does not yet
provide a central WatchdogVPN configuration file.

The `v0.2.0` development path now creates `/etc/watchdogvpn/config.toml` from
the packaged defaults when the file is missing. When the file already exists,
missing default sections and keys are added without overwriting existing values.

## Planned Paths

Primary configuration directory:

```text
/etc/watchdogvpn/
```

Primary user-editable configuration:

```text
/etc/watchdogvpn/config.toml
```

Packaged defaults and reference example:

```text
/etc/watchdogvpn/config.toml.example
```

Repository source for that example:

```text
examples/watchdogvpn-config.toml.example
```

Backups created during migration or update should use the existing WatchdogVPN
backup root:

```text
/var/backups/watchdogvpn/
```

## Initial Schema

The initial configuration should stay small and stable.

```toml
[backend]
mode = "adguard"
active = "adguard"

[custom_vps]
enabled = false
name = ""
host = ""
ssh_user = ""
ssh_port = 22
protocol = ""
profile_path = ""
service_name = ""

[language]
current = "en"
auto_detect = true

[timers]
watchdog_interval = "5min"
rotation_interval = "12h"

[dns]
advanced_mode = false
profile = "quad9-doh"

[tui]
theme = "default"
color = true
unicode = true

[reporting]
sanitize_ipv4 = true
sanitize_ipv6 = true
sanitize_email = true
sanitize_home = true
```

## Field Meaning

`backend.active`

Active VPN backend name. The implemented value in this phase is `adguard`.
`custom-vps` is reserved for a future user-owned server backend and currently
fails closed before runtime commands touch services, routes or vendor CLIs.

`backend.mode`

Configured backend mode. Supported values are `adguard`, `custom-vps` and
`both`. `both` keeps AdGuard as the active implemented backend today while
preparing local Custom VPS configuration for a future implementation.

`custom_vps.*`

Local placeholders for a future user-owned VPS backend. These fields must not
store passwords, private keys, API tokens or other secrets. Until the backend is
implemented, they are informational configuration only.

`language.current`

Selected interface language. English is the default. Internationalization is
planned later, so early releases may preserve this value before using it
throughout the TUI.

`language.auto_detect`

Whether WatchdogVPN may use the system locale as a suggestion. Auto-detection
must never override an explicit user choice.

`timers.watchdog_interval`

Preferred watchdog timer interval. The value must be validated before writing
systemd timer overrides.

`timers.rotation_interval`

Preferred VPN rotation interval. The value must be validated before writing
systemd timer overrides.

`dns.advanced_mode`

Whether the user opted into advanced DNS management with AdGuard Home.

`dns.profile`

Preferred DNS profile name. The value must match a known profile before it is
applied.

`tui.theme`

Terminal UI theme. Initial values should be `default`, `high_contrast` and
`no_color`.

`tui.color`

Whether the TUI may use ANSI color.

`tui.unicode`

Whether the TUI may use Unicode box drawing and symbols. ASCII fallback should
remain possible for limited terminals.

`reporting.sanitize_*`

Controls for local report sanitization. Reports must remain local only and must
not be uploaded automatically.

## Install Contract

Fresh install:

- Create `/etc/watchdogvpn/` if it does not exist.
- Install `config.toml.example`.
- Create `config.toml` from defaults only when it does not already exist.
- Do not store credentials, tokens, account data or private keys in
  `config.toml`.
- Validate the generated file before continuing.

Existing install:

- Do not overwrite `config.toml`.
- Preserve existing values.
- Add missing default keys only through the migration flow.

## Update Contract

Update must be conservative.

- Back up `config.toml` before any migration.
- Preserve all existing user values.
- Add new default keys when missing.
- Keep unknown keys unless they are known to be unsafe.
- Validate the migrated file before replacing the active file.
- If migration fails, keep the old file and print a clear warning.

The updater must never reset timer, DNS, language, theme or reporting
preferences silently.

## Uninstall Contract

Default uninstall:

- Preserve `/etc/watchdogvpn/config.toml`.
- Preserve logs and state unless the user explicitly requests purge options.

Full purge:

- Remove `/etc/watchdogvpn/` only when `--purge-config` is provided.
- Keep the official AdGuard VPN CLI and account/license state untouched.

## Reset Contract

Reset must be explicit.

Planned command forms:

```sh
watchdogvpn config reset
watchdogvpn config reset timers
watchdogvpn config reset dns
watchdogvpn config reset tui
watchdogvpn config reset reporting
```

Rules:

- Interactive reset must ask for confirmation.
- Non-interactive reset must require an explicit confirmation flag.
- Reset must create a backup before changing the file.
- Reset must only affect the requested section unless the whole config is
  requested.

## CLI Contract

For the complete command reference, see [WatchdogVPN CLI](cli.md).

Planned command forms:

```sh
watchdogvpn config get
watchdogvpn config get language.current
watchdogvpn config set language.current es
watchdogvpn config set tui.theme high_contrast
watchdogvpn config set tui.color false
watchdogvpn config reset language --yes
watchdogvpn config reset tui --yes
watchdogvpn config reset reporting --yes
```

Behavior:

- `get` with no key prints the sanitized configuration. Implemented.
- `get section.key` prints only one value. Implemented.
- `set section.key value` validates key and value before writing. Implemented
  for safe user-interface and reporting keys.
- `reset [section|all] --yes` restores safe sections to defaults. Implemented
  for `language`, `tui`, `reporting` and `all`.
- Unknown keys must fail with a clear error.
- Values that can affect systemd or DNS must be validated before being applied.

`config set` currently supports only:

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

Timer and DNS keys are intentionally read-only until their changes are wired to
systemd and DNS apply flows.

The TUI Settings view can update the safe user-interface keys through the same
`watchdogvpn config set` contract:

```text
language.current
tui.theme
tui.color
tui.unicode
```

It can also reset the safe language and TUI sections through explicit
confirmation. This does not reset DNS, timers or reporting preferences.

## Validation Rules

Required validation:

- Timer intervals must use supported systemd-compatible durations.
- DNS profile must be a known profile.
- Language must be a supported language code or a preserved future value.
- TUI theme must be a known theme.
- Boolean values must be parsed strictly.
- Reporting sanitization options must default to safe values.

## Tests Required For v0.2.0

Planned test files:

```text
tests/unit/test_config_create_default.sh
tests/unit/test_config_preserve_existing.sh
tests/unit/test_config_add_missing_keys.sh
tests/unit/test_config_reset_requires_confirmation.sh
tests/unit/test_update_preserves_config.sh
tests/unit/test_watchdogvpn_config_cli.sh
```

Acceptance criteria:

- Fresh install creates default config.
- Update does not overwrite user preferences.
- Migration adds missing keys.
- Reset requires confirmation.
- Uninstall preserves config by default.
- `--purge-config` removes config explicitly.
- CLI get/set/reset commands validate inputs.

## Non-Goals For v0.2.0

- Full TUI internationalization.
- Full visual theme system.
- Remote telemetry.
- Automatic upload of reports or logs.
- Storing VPN credentials or tokens.

Those belong to later stabilization or `v1.1.0` work.
