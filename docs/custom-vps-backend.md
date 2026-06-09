# Custom VPS Backend

Custom VPS is the future backend path for users who want to operate WatchdogVPN
with their own server instead of depending only on a commercial VPN provider.

## Current Status

Custom VPS configuration is available as non-secret local metadata. Runtime
control is not implemented yet.

That means:

- the installer can prepare `backend.mode = "custom-vps"` or `backend.mode = "both"`;
- `watchdogvpn backend status` reports the selected mode and active backend;
- the TUI has a Backend view for status and configuration review;
- runtime commands fail closed if `backend.active = "custom-vps"` until a real
  backend implementation exists.

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

`Both` keeps AdGuard active today and stores Custom VPS metadata for a future
backend implementation.

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
```

Do not store passwords, private keys, API tokens, certificate pins or
obfuscation secrets in this file or in the repository.

## Diagnostics

Use:

```sh
watchdogvpn backend status
watchdogvpn config get backend.mode
watchdogvpn config get backend.active
watchdogvpn config get custom_vps.enabled
```

In the TUI, open:

```text
VPN -> Backend
```

## Future Implementation

The future backend implementation should add:

- real connect/disconnect/status operations for Custom VPS;
- truth check support for its tunnel interface;
- health check and cleanup behavior;
- optional rotation over one or more user-owned nodes;
- tests that prove unsupported or incomplete configuration fails closed.
