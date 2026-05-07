# Changelog

## Unreleased

- Create WatchdogVPN product repository structure.
- Import current runtime files from the working local deployment.
- Add multi-distro direction for Ubuntu, Debian and Arch Linux.
- Add read-only `doctor.sh` entrypoint scaffold.
- Add the first real `install.sh` flow with dry-run support, distro adapters, backups, runtime installation, systemd enablement and optional desktop/Conky hooks.
- Add the first real `update.sh` flow for backed-up runtime refreshes that preserve user configuration, state and logs.
