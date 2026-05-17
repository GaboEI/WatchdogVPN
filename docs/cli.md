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
watchdogvpn logs [events|watchdog|rotate|dispatcher] [lines]
watchdogvpn update-check
watchdogvpn update-plan
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

## Local Logs

### `watchdogvpn logs`

Reads recent local WatchdogVPN logs without using `sudo`.

```sh
watchdogvpn logs
watchdogvpn logs events 80
watchdogvpn logs watchdog 120
watchdogvpn logs rotate 120
watchdogvpn logs dispatcher 80
```

Supported targets:

```text
events      /var/log/myvpn/vpn-events.log
watchdog    /var/log/myvpn/vpn-watchdog.log
rotate      /var/log/myvpn/vpn-rotate.log
dispatcher  /var/log/myvpn/vpn-dispatcher.log
```

Rules:

- Defaults to `events` and 80 lines.
- Accepts 1 to 500 lines.
- Sanitizes obvious home paths, email addresses and IPv4 addresses.
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
