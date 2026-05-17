# Changelog

All notable product-facing changes are documented here.

WatchdogVPN is a public alpha. The current `v0.2.0` target adds persistent
configuration, safer product CLI configuration commands, TUI Settings and a
product-facing Update Center.

## Unreleased

- Group `watchdogvpn help` by read-only, configuration and interactive command
  classes, and make `watchdogvpn --help` match `watchdogvpn help`.
- Add read-only `watchdogvpn logs` for recent sanitized local WatchdogVPN log
  output without running `sudo`.
- Add read-only `watchdogvpn update-check` for local repository update status
  without running `fetch`, `pull`, `push`, `update.sh` or `sudo`.
- Add read-only `watchdogvpn update-plan` for safe manual update guidance based
  on the current local checkout state.
- Polish `watchdogvpn help <topic>`, config help and update command argument
  validation for the v0.3.0 CLI surface.
- Add `v0.3.0` release notes.
- Start `v0.3.0` professional CLI planning.
- Add the planned WatchdogVPN persistent configuration default example and unit
  contract checks for the v0.2.0 configuration schema.
- Add minimal persistent configuration helper functions and unit coverage.
- Create the persistent WatchdogVPN config defaults during runtime install and
  preserve `/etc/watchdogvpn/` during uninstall unless `--purge-config` is used.
- Add safe config migration for missing keys without overwriting existing user
  preferences.
- Add read-only `watchdogvpn config get` support.
- Add validated `watchdogvpn config set` support for safe language, TUI and
  reporting keys.
- Add confirmed `watchdogvpn config reset` support for safe config sections.
- Add `docs/cli.md` with the current `watchdogvpn` command reference.
- Record real Arch update validation for the persistent configuration
  foundation.
- Add a read-only TUI Settings view for persistent configuration preferences.
- Add TUI Settings actions for safe language, theme, color and unicode
  preferences.
- Apply persisted TUI color and theme preferences when the interface starts and
  after Settings changes.
- Add confirmed TUI Settings reset for language and visual preferences without
  touching DNS or timers.
- Record real Arch runtime validation for TUI Settings update and reset.
- Add a read-only TUI Update Center for local version, repository state and
  recommended update routines.
- Add read-only Update Center sync status for `up to date`, `behind`, `ahead`,
  `diverged` and dirty working tree states.
- Add a confirmed TUI Update Center action to run `git fetch origin --tags`
  without running `pull`, `push`, `update.sh` or privileged commands.
- Add a contextual TUI runtime update plan that recommends safe manual steps
  based on dirty, behind, ahead, diverged or clean repository states.
- Polish the TUI Update Center into a product-facing status view and move
  maintainer commands into a separate technical details screen.
- Record real installed-runtime validation for the TUI Update Center.
- Add `v0.2.0` release notes.

## v0.1.1 - 2026-05-16

- Add `SECURITY.md` for public vulnerability reporting guidance.
- Add GitHub issue templates for bug reports and feature requests.
- Add `docs/reporting.md` with safe diagnostic sharing guidance.
- Record a public clone smoke test for the alpha repository.
- Record successful Debian real install validation, including DNS tooling.
- Add Arch-derived distro detection so CachyOS can use the Arch adapter.
- Skip desktop-file placement cleanly when tiling/minimal desktop environments
  do not expose a real Desktop folder.
- Record CachyOS real install validation with advanced DNS and post-reboot VPN
  recovery observation.
- Add a post-install VPN settle check with one recovery restart and clear reboot
  guidance when the tunnel remains degraded.
- Add initial `watchdogvpn` product CLI with local sanitized diagnostic report
  generation.
- Document initial GitHub milestones, labels and issue drafts for post-alpha
  planning.
- Move the installed TUI support package out of `~/.local/bin` so it no longer
  shadows the `watchdogvpn` CLI command.

## v0.1.0-alpha - 2026-05-09

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

- Continue the gradual TUI module split by extracting action command builders,
  command helpers, state collectors, render helpers, side-effect-free
  constants, parsers, formatting helpers and validators into
  `tui/watchdogvpn/`.
- Install, update, uninstall and doctor now track the extracted TUI support
  package next to the `VPN` launcher.
- Validate each installed TUI support module in `doctor.sh` and make the
  launcher safe to execute in non-interactive checks.
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

- Add README alpha status, support matrix, license state and known limitations.
- Add alpha release notes and a release checklist for the first public tag.
- Add GitHub Actions CI for Python/Bash syntax, systemd unit verification and
  advisory shell style checks.
- Add unit behavior tests with mocks for `vpn_truth_check` and watchdog
  remediation decisions.
- Add security and threat-model documentation covering privileges, DNS safety,
  external installer risk and current hardening gaps.
- Add explicit runtime warnings for remote vendor installers used by AdGuard VPN
  CLI and AdGuard Home, including the manual-install-first security path.
- Harden TUI action command builders with defensive validation for DNS profiles,
  timer units, timer intervals and bypass domains.
- Add install/security contract tests for privileged file modes, TUI package
  installation and DNS rescue ordering during uninstall.
- Start reducing `shell=True` usage by adding argument-list subprocess helpers
  for simple TUI command execution.
- Add an operational audit for excessive VPN rotations and identify
  timer/restart-triggered rotations as the main suspect after real connectivity
  failures are excluded.
