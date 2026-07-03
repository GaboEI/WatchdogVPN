# Security Policy

WatchdogVPN is Linux system tooling. It manages VPN services, DNS configuration,
NetworkManager hooks, systemd units, privileged scripts and local logs. Treat
security reports as high signal, especially when they involve command execution,
privilege boundaries, DNS recovery or preservation of user configuration.

## Supported Versions

| Version | Supported |
| --- | --- |
| `main` / v2.0.0 development line | Security reports accepted |
| `v0.3.1` | Security reports accepted |
| `v0.3.0` | Security reports accepted |
| `v0.1.1` | Security reports accepted |
| `v0.1.0-alpha` | Security reports accepted |

The project is not yet a stable `v2.0.0` release. Reports are still useful and
shape the stabilization roadmap, especially when they affect daemon/runtime
behavior, DNS, routing, install/update/uninstall safety or local data handling.

## Reporting a Vulnerability

If the report includes a working exploit, private host details, credentials,
tokens, account information, private domains, logs with sensitive network data
or anything that should not be public, do not open a public issue with those
details.

Use one of these paths:

- Open a GitHub security advisory if available for the repository.
- Contact the maintainer directly through the profile/contact information
  associated with the repository.
- If the issue is low-risk and does not expose sensitive data, open a GitHub
  issue and clearly mark it as security-related.

## What To Include

Useful reports include:

- WatchdogVPN version or commit.
- Distribution and version.
- Whether the issue affects install, update, uninstall, TUI, DNS, timers or
  privileged helpers.
- Exact command or user action that triggers the issue.
- Expected behavior.
- Actual behavior.
- Sanitized logs or terminal output.

Do not include:

- VPN account details.
- API tokens, passwords or private keys.
- Private domains or internal hostnames unless strictly necessary.
- Full public IP history.
- Raw logs that have not been reviewed.

## Security Scope

In scope:

- Command injection or unsafe shell execution.
- Privilege escalation paths.
- Unsafe file permissions.
- Unsafe install, update or uninstall behavior.
- DNS breakage or failure to recover DNS after uninstall.
- Loss or overwrite of preserved user configuration.
- Dangerous behavior in daemon, rotation, DNS, routing, app-policy, provider,
  backup or bypass paths.
- Sensitive data leakage through logs, diagnostics, backups or statistics.

Out of scope:

- Requests to bypass VPN licensing or provider restrictions.
- General anonymity guarantees.
- Unsupported distributions not claimed as validated.

## Project Security Notes

The detailed security model is documented in:

- [Security](docs/security.md)
- [Threat Model](docs/threat-model.md)

Known development limitations include:

- External installer verification is not fully cryptographically pinned.
- CI is stronger than syntax-only validation, but not yet a full integration
  simulation.
- The final CLI/TUI surfaces are still being completed and audited for v2.0.0.
