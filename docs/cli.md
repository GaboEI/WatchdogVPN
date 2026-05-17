# WatchdogVPN CLI

`watchdogvpn` is the product command for diagnostics, configuration and common
runtime entry points.

The legacy `VPN` command remains the direct TUI launcher. New automation and
documentation should prefer `watchdogvpn`.

## Command Summary

Read-only commands:

```sh
watchdogvpn status
watchdogvpn doctor
watchdogvpn report
watchdogvpn config get [section.key]
watchdogvpn version
watchdogvpn help
watchdogvpn --help
```

Configuration commands:

```sh
watchdogvpn config set section.key value
watchdogvpn config reset [language|tui|reporting|all] --yes
```

Interactive commands:

```sh
watchdogvpn tui
```

## Runtime Commands

### `watchdogvpn status`

Shows VPN runtime status through `vpnctl`.

```sh
watchdogvpn status
```

Use this for a quick operational view after install, update, reboot or recovery.

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

### `watchdogvpn version`

Prints the installed CLI version.

```sh
watchdogvpn version
```

Expected output for the current release:

```text
WatchdogVPN v0.2.0
```

### `watchdogvpn help`

Prints grouped command help.

```sh
watchdogvpn help
watchdogvpn --help
```

The help output separates read-only commands, configuration-write commands and
interactive commands. State-changing runtime commands such as update, connect,
disconnect and rotate are intentionally not part of the product CLI yet.

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

The report may include runtime status, doctor-adjacent checks, VPN truth state,
auth state, DNS test output and recent troubleshooting context. See
[Reporting Issues](reporting.md) for safe sharing guidance.

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
