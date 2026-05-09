# Changelog

All notable product-facing changes are documented here.

WatchdogVPN is currently an alpha candidate. The repository is still private and
published for portfolio review only until the public release checklist is
complete.

## Unreleased

- No unreleased changes yet.

## v0.1.0-alpha candidate - 2026-05-09

### Productization

- Create the WatchdogVPN product repository structure.
- Rename the product to WatchdogVPN and align README/product messaging.
- Import the current runtime from the working local deployment.
- Add multi-distro direction for Ubuntu, Debian and Arch Linux.
- Add project history documentation that summarizes the local prototype timeline
  without publishing machine-specific state.

### Install, Update and Uninstall

- Add the first real `install.sh` flow with dry-run support, distro adapters,
  backups, runtime installation, systemd enablement and optional desktop/Conky
  hooks.
- Add the first real `update.sh` flow for backed-up runtime refreshes that
  preserve user configuration, state and logs.
- Add the first real `uninstall.sh` flow that removes product-managed files
  while preserving configuration, logs and state unless explicitly purged.
- Add final installer validation for doctor checks, DNS local health and service
  settlement.
- Keep `/var/lib/adguardvpn` owned by the `adgvpn` service user during
  install/update.
- Guide first-time `adgvpn` service-user login during installation and add
  `~/.local/bin` to the user's shell PATH when needed.
- Install the optional launcher both in the application menu and on the user's
  desktop directory.
- Rename the desktop launcher source file to `watchdogvpn.desktop`.

### AdGuard VPN and Recovery

- Add read-only `doctor.sh` preflight checks.
- Add guided installation of the official AdGuard VPN CLI when a clean system
  does not have `adguardvpn-cli`.
- Add timeout and visible progress around the official AdGuard VPN CLI installer
  download.
- Add GitHub raw IPv4 fallbacks for networks that resolve
  `raw.githubusercontent.com` poorly.
- Make service-user authentication checks tolerate fresh CLI logins by falling
  back to `adguardvpn-cli status`.
- Treat `adguardvpn-cli license` output that includes `Logged in as` as
  authenticated even if the CLI does not exit before timeout.
- Try AdGuard VPN CLI `status` before reporting a license timeout as unknown
  authentication.

### DNS and Exclusions

- Implement advanced DNS installation with AdGuard Home provisioning, local
  starter config, DNS profile application and `vpn_dnsctl` path detection.
- Add a DNS rescue helper and run it during uninstall so removing local DNS
  services does not leave the host without name resolution.
- Let DNS profile apply continue with rollback protection when the current
  system resolver is broken before AdGuard Home is configured.
- Block advanced DNS installation early when required download domains cannot be
  resolved.
- Strengthen DNS rescue on systems without `systemd-resolved` by writing
  temporary public fallback DNS when automatic restore does not recover
  resolution.
- Keep new bypass configurations empty by default so users do not inherit
  machine-specific domains.

### Timers and Automation

- Schedule recurring watchdog, rotation and domain-bypass timers from service
  inactivity so they keep a next trigger after one-shot runs.
- Teach the TUI timer display to read `OnUnitInactiveSec` intervals after the
  timer scheduling fix.
- Update TUI timer interval changes to write `OnUnitInactiveSec`, including
  custom rotation/watchdog intervals.
- Remove the 5-minute activation trigger from `vpn-rotate.timer` so automatic
  location rotation only runs after boot, on the stable interval, or through
  real remediation paths.

### TUI and Notifications

- Start a gradual TUI module split by extracting side-effect-free constants,
  parsers, formatting helpers and validators into `tui/watchdogvpn/`.
- Install, update, uninstall and doctor now track the extracted TUI support
  package next to the `VPN` launcher.
- Make VPN location notifications user-facing by hiding public IPs and using
  readable location names.
- Keep manual notification tests quiet when the current user cannot write the
  root-owned event log.
- Refresh the TUI installation screen to describe the current product installer,
  update and uninstall flow.
- Refresh README and problem-context documentation around the product
  philosophy, install/update/uninstall commands and current support status.
- Add real TUI screenshots and a demo document with representative doctor,
  status, DNS and timer output.

### Documentation, CI and Security

- Add portfolio-review license notice and README alpha status, support matrix
  and known limitations.
- Add alpha candidate release notes and a release checklist for the first public
  tag.
- Add GitHub Actions CI for Python/Bash syntax, systemd unit verification and
  advisory shell style checks.
- Add unit behavior tests with mocks for `vpn_truth_check` and watchdog
  remediation decisions.
- Add security and threat-model documentation covering privileges, DNS safety,
  external installer risk and current hardening gaps.
- Add an operational audit for excessive VPN rotations and identify
  timer/restart-triggered rotations as the main suspect after real connectivity
  failures are excluded.
