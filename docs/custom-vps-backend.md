# Custom VPS Backend

Custom VPS is the user-owned backend path for people who want to operate
WatchdogVPN with their own server instead of depending only on a commercial VPN
provider.

## Current Status

Custom VPS is available as an experimental backend controlled through a local
systemd service configured by the user. WatchdogVPN does not install protocols,
does not provision servers and does not store secrets.

That means:

- the installer can prepare `backend.mode = "custom-vps"` or `backend.mode = "both"`;
- `watchdogvpn backend status` reports the selected mode and active backend;
- the TUI has a Backend view for status and configuration review;
- `vpnctl connect`, `vpnctl disconnect`, `vpnctl restart` and `vpnctl status`
  can control the configured service;
- rotation is disabled for Custom VPS unless a future backend explicitly
  supports multiple nodes;
- runtime commands fail closed if required Custom VPS fields are missing.

## Installer Flow

Run:

```sh
./install.sh
```

The installer asks:

```text
Select VPN backend:
  1. AdGuard VPN
  2. Custom VPS
  3. Both
```

`AdGuard VPN` keeps the current working backend.

`Custom VPS` prepares WatchdogVPN for a user-owned server and skips AdGuard CLI
installation and login.

`Both` keeps AdGuard active and stores Custom VPS metadata for experimental
service-control use.

## Non-Secret Fields

The installer may store these local fields in `/etc/watchdogvpn/config.toml`:

```toml
[custom_vps]
enabled = true
name = "My VPS"
host = "203.0.113.10"
ssh_user = "ubuntu"
ssh_port = 22
protocol = "awg"
profile_path = "/etc/watchdogvpn/custom-vps.conf"
service_name = "custom-vps.service"
interface = "wg0"
```

Do not store passwords, private keys, API tokens, certificate pins or
obfuscation secrets in this file or in the repository.

`service_name` must be a local systemd service unit, for example
`custom-vps.service` or `wg-quick@wg0.service`.

`interface` is optional but recommended. Without it WatchdogVPN can control the
service, but `vpn_truth_check` cannot prove that the default route uses the
VPN tunnel.

## Diagnostics

Use:

```sh
watchdogvpn backend status
watchdogvpn config get backend.mode
watchdogvpn config get backend.active
watchdogvpn config get custom_vps.enabled
vpnctl status
```

In the TUI, open:

```text
VPN -> Backend
```

## Future Implementation

Future implementation work should add:

- protocol-specific setup helpers;
- health check and cleanup behavior per protocol;
- optional rotation over one or more user-owned nodes;
- tests that prove unsupported or incomplete configuration fails closed.
