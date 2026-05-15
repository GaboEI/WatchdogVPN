# Reporting Issues

WatchdogVPN is a VPN resilience and system-management tool, so reports can
include sensitive local networking details if they are copied without review.
Always sanitize diagnostics before sharing them publicly.

## Before Opening an Issue

Run the lightweight checks from the repository root when possible:

```sh
./doctor.sh
vpn_truth_check
vpn_auth_check
systemctl list-timers --all vpn-watchdog.timer vpn-rotate.timer vpn-domain-bypass.timer myvpn-logrotate.timer --no-pager
```

For installer or update issues, also include whether the command was run with:

```sh
./install.sh --dry-run
./update.sh --dry-run
./uninstall.sh --dry-run
```

## What To Remove From Logs

Before posting output, remove or replace:

- VPN account information.
- Tokens, passwords, private keys and license details.
- Private domains and internal hostnames.
- Public IP history if it is not needed for the bug.
- Personal paths outside normal repository paths.

Use placeholders such as:

```text
<redacted-ip>
<redacted-domain>
<redacted-user>
```

## Useful Bug Report Content

Good reports include:

- WatchdogVPN version or commit.
- Distribution and version.
- Install method: fresh install, update or manual copy.
- Whether advanced DNS is enabled.
- Whether Conky or desktop launcher integration is enabled.
- Exact command or TUI action that failed.
- Expected behavior.
- Actual behavior.
- Sanitized output.

## Security Reports

Do not open a public issue with exploit details, credentials or sensitive local
network information. Follow [SECURITY.md](../SECURITY.md) for vulnerability
reports.

## Local Report Direction

A future `watchdogvpn report` command is planned. It should generate a local
diagnostic bundle only after explicit user consent and should never upload data
automatically.
