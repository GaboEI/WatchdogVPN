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
- DNS safety and rescue tooling.
- logrotate policy installation.
- files under `/etc`, `/var/lib` and `/var/log`.

The TUI asks for sudo only when an action changes system state. Read-only views
should continue to work without privileged access where possible.

## Files and Paths Managed by the Product

Product-managed runtime files include:

- `/usr/local/bin/vpnctl`
- `/usr/local/bin/vpn_backend`
- `/usr/local/bin/vpn_truth_check`
- `/usr/local/bin/vpn_dns_rescue`
- `/usr/local/bin/vpn_manual_state`
- `/usr/local/bin/vpn_notify`
- `/usr/local/bin/no_vpn`
- `/usr/local/bin/watchdogvpn`
- `/usr/local/sbin/vpn_domain_bypass_apply.sh`
- product units under `/etc/systemd/system/`
- product dispatcher hook under `/etc/NetworkManager/dispatcher.d/`
- product logrotate policy under `/etc/logrotate.d/myvpn`
- product kernel tunable defaults under `/etc/sysctl.d/99-watchdogvpn.conf`
  (`net.ipv4.conf.all.src_valid_mark` and
  `net.ipv4.conf.default.src_valid_mark`, required for AmneziaWG/WireGuard
  fwmark default-route policy routing; the daemon itself cannot set kernel
  tunables under `ProtectKernelTunables=true`, so this is applied once at
  install/update time and reapplied by `systemd-sysctl.service` on boot)
- TUI launcher under `~/.local/bin/VPN`

User configuration and state that must be preserved by default:

- `/etc/vpn-domain-bypass.conf`
- `/var/lib/watchdogvpn/`
- `/var/log/myvpn/`
- provider installation and account/license state

## Install, Update and Uninstall Safety

`doctor.sh` is read-only and must not install, remove or modify files.

`install.sh` and `update.sh` validate repository files before installing them,
back up replaced files and preserve existing user configuration.

`uninstall.sh` removes product-managed files but does not remove user-owned
provider software, profiles, private keys or account state. Config, logs, shared
runtime state are removed only when the user explicitly asks for
purge options.

## DNS Safety

The old guided third-party DNS integration was removed before Phase 10. DNS v2
will own resolver selection and custom DNS behavior without depending on an
external DNS service. `vpn_dns_rescue` remains as a fallback helper to recover
name resolution when local DNS services are removed or broken during
uninstall/recovery work.

## Kill Switch Scope

The kill switch is a system-wide fail-closed firewall guard for WatchdogVPN's
own protected route. When it is genuinely active after a WatchdogVPN connection
failure, outbound traffic that is not allowed through the active WatchdogVPN TUN
path is blocked.

This includes other VPN or proxy clients that were already connected before the
WatchdogVPN failure. Phase 23 field validation proved this behavior with a real
external VPN active: after a controlled WatchdogVPN runtime failure triggered
the kill switch, that external VPN's egress was also blocked. This is expected
by design, not a separate external-client allowlist failure. Users who run
another VPN client alongside WatchdogVPN should treat an active WatchdogVPN kill
switch as taking precedence over the host's normal outbound networking until
WatchdogVPN recovers, disconnects cleanly or the panic button removes the
firewall rules.

## WatchdogVPN Panic Button

`watchdog_panic` (installed to `/usr/local/bin/`) is a deliberately separate
concept from both `watchdog disconnect` (only tears down the active tunnel)
and disabling autostart (only affects the next boot). `watchdog_panic sleep`
puts WatchdogVPN completely to sleep - the daemon, the kill switch and any
live domain-bypass routing state - without uninstalling anything, and it
stays asleep across reboots and across running `install.sh`/`update.sh`
again, until the user explicitly runs `watchdog_panic wake`.

Always invoke it with the full installed path, not the bare command name:

```
sudo /usr/local/bin/watchdog_panic sleep
sudo /usr/local/bin/watchdog_panic wake
sudo /usr/local/bin/watchdog_panic status
```

This matters because it needs root. `sudo`'s own `secure_path` setting -
separate from, and evaluated before, the invoked command's own `PATH` - is
compiled to exclude `/usr/local/bin` on several distros (confirmed on Rocky
Linux 9), so `sudo watchdog_panic sleep` (bare name) fails there with
`sudo: watchdog_panic: command not found`, even though the same command
resolves fine without `sudo`. A full path never needs that lookup at all,
so it works everywhere regardless of a given distro's `secure_path`, with no
system-wide sudoers change required. (Command-scoped `Defaults!cmnd
secure_path=...` rules cannot help here either - `sudo` has to resolve which
command is being run, from its bare name, before it can even test whether a
command-scoped rule applies; confirmed empirically, not just by reading the
sudoers manual.)

Implemented as a dependency-light bash script, not a Python CLI command,
on purpose: a panic button must still work if the daemon or the Python
runtime it depends on is the thing behaving badly. It intentionally
duplicates a small amount of cleanup logic already present elsewhere
(`core/kill_switch.py`'s nftables/iptables table/chain names,
`vpn_domain_bypass_rescue`'s ip rule cleanup) rather than depending on
either, for the same reason.

`watchdog_panic sleep`:

1. Attempts a graceful disconnect through the daemon, best effort.
2. Removes kill switch firewall rules directly (nftables table `watchdogvpn`
   / iptables chain `WATCHDOGVPN-OUTPUT`), independent of whether the daemon
   itself is able to do so.
3. Stops and disables `watchdogvpn.service`.
4. Runs `vpn_domain_bypass_rescue auto` to clean up any domain-bypass
   routing state.
5. Writes `/etc/watchdogvpn/.hibernating`.

`watchdog_panic wake` removes the marker and re-enables/starts the daemon.
It deliberately does not also re-enable domain-bypass automation - that
keeps its own independent on/off state (see below).

Contract: while `/etc/watchdogvpn/.hibernating` exists, `install.sh`/
`update.sh` will not re-enable `watchdogvpn.service` on their own
(`enable_watchdogvpn_service_unless_hibernating()` in `lib/systemd.sh`) -
the same "don't silently undo an explicit user safety decision" principle
already used for domain bypass. `uninstall.sh` disables the daemon
regardless of the marker (uninstalling always wins), and now also
explicitly removes kill switch firewall rules before removing files - a
gap found while building this feature: nothing previously cleaned up an
active kill switch on uninstall, which could have left a user's traffic
firewalled with no WatchdogVPN left to undo it.

## Domain Bypass Network Safety

`vpn-domain-bypass.timer`/`vpn-domain-bypass.service` apply live kernel
routing state: `ip rule` entries for each configured bypass domain's
resolved IPs, plus a catch-all fallback `ip rule` (default priority
`32000`) pointing traffic at a dedicated routing table (default `880`).
This is real, persistent, system-wide routing policy - it is not scoped to
a single application or user session, and it can conflict with any other
VPN or proxy client on the same machine that also manages its own routes
(observed in practice: a real incident on 2026-07-07 where this collided
with another VPN client's own profile on the same machine, producing
errors like `set routes: add route 0: File exists`).

Contract:

- `install.sh`/`update.sh` only enable `vpn-domain-bypass.timer`
  automatically when `/etc/vpn-domain-bypass.conf` actually has configured
  domains. A fresh install with the default empty config never enables it.
- If the timer is already active, `install.sh`/`update.sh` never restart it.
  `systemctl enable --now` on an already-active timer resets its
  `OnActiveSec` schedule and forces an unplanned re-application of routing
  rules - a routine software update must not have that side effect.
- `uninstall.sh` disabling the timer does not, by itself, remove ip rules
  it already applied (stopping a timer does not undo already-applied kernel
  state). `uninstall.sh` therefore always runs `vpn_domain_bypass_rescue`
  before removing product files, regardless of purge flags.
- `vpn_domain_bypass_rescue` (installed to `/usr/local/bin/`) is the
  official recovery command: it stops/disables the domain-bypass
  automation, removes the ip rules it created, flushes the custom routing
  table and the route cache, and never touches any other VPN/proxy
  software's configuration. Run it manually
  (`vpn_domain_bypass_rescue auto`) any time another VPN/proxy client
  cannot set its own routes on a machine that also runs WatchdogVPN.
- `vpn_domain_bypass_rescue` also records that the user disabled the timer
  on purpose (`/etc/watchdogvpn/.domain-bypass-disabled`). systemd's own
  enabled/disabled state cannot distinguish "never enabled" from
  "explicitly disabled after a conflict" - both look identical. Because of
  this marker, `install.sh`/`update.sh` will not silently re-enable the
  timer on a later run just because domains are still configured; the user
  has to explicitly run `systemctl enable --now vpn-domain-bypass.timer`
  themselves to opt back in, which also clears the marker.
- Users who intentionally run another VPN/proxy client on the same machine
  as WatchdogVPN should not enable domain bypass at all, or should expect to
  run `vpn_domain_bypass_rescue` before switching between them.

## OpenVPN and OpenVPN+Cloak Profile Safety

WatchdogVPN imports OpenVPN and OpenVPN+Cloak profiles from user-provided files,
subscriptions and third-party tools. Because these files can contain arbitrary
directives, the parser applies a fail-closed whitelist before any profile is
stored or used.

What the parser enforces:

- **Directive whitelist**: only known, safe OpenVPN directives are accepted.
  Dangerous executable-control directives such as `script-security`, `up`,
  `down`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`,
  `client-connect`, `client-disconnect`, `learn-address`, `plugin`,
  `management`, `config`, `providers`, `pkcs11-providers`, `engine` and
  `iproute` are rejected.
- **No external file references**: `ca`, `cert`, `key`, `tls-auth`,
  `tls-crypt`, `tls-crypt-v2`, `pkcs12`, `secret`, `extra-certs` and
  `crl-verify` must be provided inline (`[inline]`); paths to external files
  are rejected.
- **No bypass quoting**: quoted forms (`"up" "/bin/sh"`) and double-dash
  forms (`--plugin`) are rejected.
- **Strict inline blocks**: inline tags must open and close correctly, must
  not be nested and must contain data.
- **Network endpoint restrictions**: profiles must declare exactly one
  `remote`, the endpoint must be a global IPv4 address (no hostname, no
  loopback, no IPv6, no multiple remotes).
- **Process isolation**: the OpenVPN process is launched through `setpriv`
  with only `net_admin` and `net_raw` capabilities, even when the daemon
  holds broader privileges.

These checks run at profile import time and are repeated by the drivers
before writing any runtime config file. Malformed or unsafe profiles are
rejected with a managed error and are not stored.

Limitations: inline certificate/key material is passed to the underlying
OpenSSL/OpenVPN stack as supplied by the profile. WatchdogVPN validates the
shape of the config, not the cryptographic trustworthiness of the PEM
payload. Users should still obtain profiles from trusted sources.

## External Installer Risk

WatchdogVPN can guide installation of required open runtime dependencies when
they are missing. Any future provider-specific download path must be explicit,
auditable and separately validated.

Current risk:

- Some distribution packages or upstream runtime binaries may not be pinned by
  repository-managed checksum in early development paths.
- If an upstream package endpoint changes or is unavailable, automated
  installation may fail.
Current mitigation:

- The installer is explicit about what it is doing.
- The project does not bundle credentials or licensing bypasses.
- Users may install the selected provider manually before running WatchdogVPN.

Manual-first path:

1. Install any user-owned provider software from trusted documentation.
2. Confirm the service/profile works independently.
3. Run `./install.sh` and let WatchdogVPN configure its daemon and runtime.
4. Configure DNS through the WatchdogVPN v2 DNS system.

Planned hardening:

- Document manual verified installation as the safest path.
- Add checksum/signature validation if the upstream distribution provides stable
  verification material.
- Keep automatic download behavior visible and auditable.

## Rule-Set Downloads And Runtime Cache

Remote rule sets are security-sensitive routing policy inputs. WatchdogVPN owns
their download and cache lifecycle before runtime uses them.

Security rules:

- Remote rule-set sources must use HTTPS.
- Remote rule-set trust policies require `expected_sha256`.
- Built-in rule sets load from explicit local source paths.
- New payloads replace cache files only after integrity and source-format
  validation pass.
- Critical rule-set failures fail closed before runtime starts.
- Runtime emits local sing-box rule-set declarations from verified cache files;
  it does not delegate remote rule-set downloads to sing-box.

## Python TUI Command Execution

The TUI centralizes command execution in `tui/watchdogvpn/commands.py`. Existing
shell pipelines around systemd, sudo, awk and sed run through explicit Bash argv
wrappers with `shell=False`.

Current rules:

- Simple subprocess calls should use argument-list helpers such as `run_args`
  and `run_process_args`.
- User-provided domains and locations should be shell-quoted before command
  execution.
- User-provided domains, TUI settings and DNS profiles are validated before
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

- never remove user-owned provider software without consent;
- never remove provider account/license state, private keys or profiles without consent;
- preserve config, logs and shared runtime state unless purge flags are used;
- require the literal `DELETE` confirmation before purging WatchdogVPN data;
- write uninstall pre-delete backups outside WatchdogVPN-owned paths;
- attempt DNS recovery before removing WatchdogVPN commands.

## Local Diagnostic Reports

`watchdog maintenance report` generates a local text report for support and debugging. It
does not upload anything automatically. The report applies basic sanitization for
common sensitive values such as IPv4/IPv6 addresses, email addresses,
device-code URLs and the user's home directory path, but users should still
review the file before sharing it.

Phase 16 observability must default to local aggregate counters only. Full
destination or request history, if ever implemented, must be explicit opt-in,
clearly labeled sensitive, retention-bounded, purgeable and excluded from normal
diagnostic exports by default.

Local metrics can be inspected with `watchdog stats status` and
`watchdog stats summary`. Metrics can be purged with
`watchdog stats purge --yes`. Normal diagnostics may include only a redacted
aggregate metrics summary; they must not include raw `metrics.json` contents.
Future backups may include metrics policy metadata, but metrics history/counters
must not be included in normal backup or remote sync flows without a separate
sensitive-data decision.

## Backup Sensitivity

WatchdogVPN backups are sensitive archives. Backup manifests are marked
sensitive and warn that exports may contain private keys, passwords, provider
tokens, subscription URLs, routing policy, app policy and local selection state.

Plaintext local ZIP backups remain supported. Encrypted backups use an outer ZIP
with public `manifest.json` metadata and encrypted `payload.bin`. The payload is
a complete normal WatchdogVPN backup ZIP encrypted with AES-256-GCM using a key
derived from the caller-supplied passphrase with scrypt
(`n=16384`, `r=8`, `p=1`, 32-byte key). Passwords are not stored and cannot be
recovered.

Encrypted restores require the password. Missing password, wrong password,
payload authentication failure, unsupported encrypted format metadata or
unsupported KDF parameters fail before local configuration is mutated. When
restoring from an encrypted backup, the pre-restore auto-backup is encrypted
with the same passphrase instead of writing an unexpected plaintext copy.

Backups are local files. WatchdogVPN must not silently upload backup archives.
Automatic WebDAV, LAN and other remote backup sync are deferred by ADR 0006.
Future remote or LAN sync must first define acceptable client-side encryption,
conflict handling and credential storage. It must not silently upload plaintext
backup archives.

## Reporting Security Issues

For the alpha release, report security concerns through GitHub issues or direct
maintainer contact. A dedicated security policy should be added before a stable
1.0 release.
