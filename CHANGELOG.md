# Changelog

## Unreleased

- Create WatchdogVPN product repository structure.
- Import current runtime files from the working local deployment.
- Add multi-distro direction for Ubuntu, Debian and Arch Linux.
- Add read-only `doctor.sh` entrypoint scaffold.
- Add the first real `install.sh` flow with dry-run support, distro adapters, backups, runtime installation, systemd enablement and optional desktop/Conky hooks.
- Add the first real `update.sh` flow for backed-up runtime refreshes that preserve user configuration, state and logs.
- Add the first real `uninstall.sh` flow that removes product-managed files while preserving configuration, logs and state unless explicitly purged.
- Implement advanced DNS installation with AdGuard Home provisioning, local starter config, DNS profile application and `vpn_dnsctl` path detection.
- Rename the desktop launcher source file to `watchdogvpn.desktop`.
- Keep `/var/lib/adguardvpn` owned by the `adgvpn` service user during install/update.
- Guide first-time `adgvpn` service-user login during installation and add `~/.local/bin` to the user's shell PATH when needed.
- Add final installer validation for doctor checks, DNS local health and service settlement.
- Add a DNS rescue helper and run it during uninstall so removing local DNS services does not leave the host without name resolution.
- Let DNS profile apply continue with rollback protection when the current system resolver is broken before AdGuard Home is configured.
- Add guided installation of the official AdGuard VPN CLI when a clean system does not have `adguardvpn-cli`.
- Add timeout and visible progress around the official AdGuard VPN CLI installer download.
- Add GitHub raw IPv4 fallbacks for networks that resolve `raw.githubusercontent.com` poorly.
- Make service-user authentication checks tolerate fresh CLI logins by falling back to `adguardvpn-cli status`.
- Treat `adguardvpn-cli license` output that includes `Logged in as` as authenticated even if the CLI does not exit before timeout.
