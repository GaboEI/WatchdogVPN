# Security

WatchdogVPN is system software. It manages VPN services, DNS configuration,
systemd units, NetworkManager hooks, logs and privileged helper scripts. Treat it
as trusted local administration tooling, not as an unprivileged desktop app.

## Security Goals

- Detect when the real network state disagrees with the VPN client status.
- Recover from common tunnel, route and DNS failures without hiding them.
- Preserve user configuration during install, update and uninstall.
- Avoid destructive changes unless the user explicitly approves them.
- Keep operational events traceable in logs and notifications.
- Provide a read-only preflight path before making system changes.

## Non-Goals

- WatchdogVPN does not replace the underlying VPN or proxy provider.
- WatchdogVPN does not provide VPN credentials or bypass licensing.
- WatchdogVPN does not guarantee anonymity.
- WatchdogVPN does not protect a host that is already compromised.
- WatchdogVPN does not hide malicious or illegal traffic.
- WatchdogVPN does not attempt to defeat endpoint monitoring on the local
  machine.

## Privilege Model

Most user-facing commands live under `bin/` and are installed into
`/usr/local/bin`. Privileged runtime scripts live under `sbin/` and are installed
into `/usr/local/sbin` with root ownership and restrictive permissions.

The privileged layer is required because WatchdogVPN controls:

- `systemd` services and timers.
- VPN service restarts.
- Network route and domain exclusion rules.
- DNS profile application through AdGuard Home.
- logrotate policy installation.
- files under `/etc`, `/var/lib` and `/var/log`.

The TUI asks for sudo only when an action changes system state. Read-only views
should continue to work without privileged access where possible.

## Files and Paths Managed by the Product

Product-managed runtime files include:

- `/usr/local/bin/vpnctl`
- `/usr/local/bin/vpn_backend`
- `/usr/local/bin/vpn_truth_check`
- `/usr/local/bin/vpn_auth_check`
- `/usr/local/bin/vpn_dnsctl`
- `/usr/local/bin/vpn_dns_rescue`
- `/usr/local/bin/vpn_manual_state`
- `/usr/local/bin/vpn_notify`
- `/usr/local/bin/no_vpn`
- `/usr/local/bin/watchdogvpn`
- `/usr/local/sbin/vpn_set`
- `/usr/local/sbin/vpn_rotate.sh`
- `/usr/local/sbin/vpn_watchdog.sh`
- `/usr/local/sbin/vpn_domain_bypass_apply.sh`
- product units under `/etc/systemd/system/`
- product dispatcher hook under `/etc/NetworkManager/dispatcher.d/`
- product logrotate policy under `/etc/logrotate.d/myvpn`
- TUI launcher under `~/.local/bin/VPN`
- optional desktop launcher under the user's application/desktop paths
- optional Conky files under `~/.conky/WatchdogVPN`

User configuration and state that must be preserved by default:

- `/etc/adguardvpn.env`
- `/etc/vpn-domain-bypass.conf`
- `/var/lib/vpn-rotate/`
- `/var/lib/watchdogvpn/`
- `/var/log/myvpn/`
- AdGuard Home user configuration
- Conky user configuration
- provider installation and account/license state

## Install, Update and Uninstall Safety

`doctor.sh` is read-only and must not install, remove or modify files.

`install.sh` and `update.sh` validate repository files before installing them,
back up replaced files and preserve existing user configuration.

`uninstall.sh` removes product-managed files but does not remove the underlying
provider installation or account/license state. Config, logs, rotation state
and Conky files are removed only when the user explicitly asks for purge options.

## DNS Safety

Advanced DNS mode is optional. When enabled, WatchdogVPN uses AdGuard Home and
`vpn_dnsctl` to apply DNS profiles with preflight checks, backups and rollback.

Known DNS safety behavior:

- DNS profiles are tested before application.
- The current AdGuard Home config is backed up before replacement.
- Local DNS health is validated after application.
- Rollback is attempted if validation fails.
- `vpn_dns_rescue` exists to recover name resolution when local DNS services are
  removed or broken during uninstall/recovery work.

## External Installer Risk

WatchdogVPN can guide installation of the selected provider path when the
required CLI is missing. This currently depends on downloading the
vendor-provided installer from a remote endpoint.

Current risk:

- The installer path is practical but not yet fully pinned by checksum or
  cryptographic signature inside this repository.
- If the remote endpoint changes or is unavailable, automated installation may
  fail.
- Advanced DNS can also install AdGuard Home through the vendor installer. That
  path has the same remote-script trust model.

Current mitigation:

- The installer is explicit about what it is doing.
- The project does not bundle credentials or licensing bypasses.
- Users may install the selected provider manually before running WatchdogVPN.
- Users may answer "no" to advanced DNS and install AdGuard Home manually later.

Manual-first path:

1. Install the selected provider from the vendor documentation.
2. Confirm the provider CLI works.
3. Run `./install.sh` and let WatchdogVPN configure its service user and runtime.
4. For DNS, either skip advanced DNS during install or install AdGuard Home
   manually first, then use `vpn_dnsctl` for profile application.

Planned hardening:

- Document manual verified installation as the safest path.
- Add checksum/signature validation if the upstream distribution provides stable
  verification material.
- Keep automatic download behavior visible and auditable.

## Python TUI Command Execution

The TUI centralizes shell execution in `tui/watchdogvpn/commands.py`. Some helper
functions still use `subprocess.run(..., shell=True)` because the current TUI
executes existing shell pipelines around systemd, sudo, awk and sed. This remains
a hardening area because the product can trigger privileged actions.

Current rules:

- Simple subprocess calls should use argument-list helpers such as `run_args`
  and `run_process_args`.
- User-provided domains and locations should be shell-quoted before command
  execution.
- User-provided domains, timer intervals and DNS profiles are validated before
  command construction in the TUI action layer where practical.
- Privileged operations are routed through narrow helper scripts where possible.
- The TUI is treated as trusted local tooling, not as a sandbox boundary.
- New action command builders should be covered by unit tests when they accept
  dynamic input.

Planned hardening:

- Convert simple commands to argument-list subprocess calls.
- Keep shell execution only for pipelines or scripts that genuinely require it.
- Add tests for command construction and parser behavior.

## Uninstall and DNS Recovery

`uninstall.sh` runs DNS rescue before removing product runtime files by default.
The goal is to avoid leaving the host pointed at a local resolver that no longer
exists. Users can disable this with `--skip-dns-rescue`, but the default path is
conservative.

The uninstall contract is:

- never remove the underlying provider installation without consent;
- never remove provider account/license state without consent;
- preserve config, logs, rotation state and Conky unless purge flags are used;
- attempt DNS recovery before removing WatchdogVPN commands.

## Local Diagnostic Reports

`watchdogvpn report` generates a local text report for support and debugging. It
does not upload anything automatically. The report applies basic sanitization for
common sensitive values such as IPv4 addresses, email addresses, device-code URLs
and the user's home directory path, but users should still review the file before
sharing it.

## Reporting Security Issues

For the alpha release, report security concerns through GitHub issues or direct
maintainer contact. A dedicated security policy should be added before a stable
1.0 release.
