# Changelog

All notable product-facing changes are documented here.

WatchdogVPN is moving toward a stable `v2.0.0` Linux CLI + TUI line. The
current documentation and implementation work are reorienting the product from
a provider-specific tool into a broader VPN/proxy resilience layer.

## Unreleased

### Added

- Add the DNS v2 system (Phase 10): resolver schema and presets, a resolver
  tester with auto-setup recommendations, a system DNS state manager
  (`systemd-resolved`, NetworkManager, classic `resolv.conf`) with snapshot
  restore, sing-box DNS policy generation, TUN DNS hijack, FakeIP, ECS for
  direct traffic, static IP mapping and DNS diversion rules.
- Add `watchdog dns status|test|apply|reset` CLI commands and matching TUI DNS
  controls, all backed by real behavior with no placeholders.
- Harden the kill switch to reject DNS/DoT traffic before `established,related`
  flows, closing a DNS leak window for already-established conntrack entries.
- Wire the DNS v2 policy into the live sing-box connect path (direct connect,
  startup autoconnect, reconnect, and rotation) so `custom`/`advanced` mode,
  FakeIP, ECS, static IP mapping and DNS diversion rules actually take effect
  on a running connection, and automatically restore system DNS state on VPN
  disconnect when a `watchdog dns apply` snapshot exists.
- Migrate `dns/singbox.py` away from the deprecated sing-box 1.12.0 `outbound`
  DNS rule matcher (`dns.rules[].outbound`) to the current `domain_resolver`
  field on outbound objects, fixing a FATAL exit on sing-box 1.13.14 whenever
  any DNS channel was configured.

### Removed

- Guided third-party DNS installation and DNS management mode. Users who want
  custom DNS resolvers can configure them explicitly in the v2 DNS system.
  Standalone DNS services remain outside WatchdogVPN scope.

### Changed

- Harden persistent state and config storage before Phase 11 with locked atomic
  writes, controlled corrupt-file errors, strict boolean/type validation,
  fail-closed invalid `vpn_desired_state` handling, and rotation cooldown
  protection for future health-check timestamps.
- Harden profile and provider input validation before Phase 11 with controlled
  URI port errors, explicit loopback endpoint rejection, HTML subscription
  detection, clearer zero-node subscription errors, explicit empty sing-box/Clash
  parser failures, and WireGuard runtime-validation metadata.
- Harden CLI persistent validation error handling before Phase 11 so malformed
  persisted stores report stable `error: ...` output instead of Python
  tracebacks, including JSON command paths.
- Respect the global rotation enable flag during automatic recovery, report
  unavailable rotation separately from failed candidates, and apply configured
  recovery backoff limits at runtime.
- Harden driver process management with private per-run runtime config paths,
  version-checked availability, readiness-gated connect success, stale
  AmneziaWG interface reconciliation, and guarded forced process cleanup.
- Start the `v2.0.0` documentation reorientation with the new Linux
  resilience-layer identity.
- Refresh Pre-Phase 11 repo documentation coherence for DNS v2 shipped state,
  guided DNS removal wording and recent v2 phase status.
- Mark provider-specific compatibility as legacy support in the public product
  narrative while preserving existing compatibility paths.
- Add installer backend selection for the legacy provider backend,
  experimental `custom-vps` and `both` mode, with the legacy backend kept as
  the default for compatibility.
- Add guided non-secret Custom VPS metadata prompts to the installer and a TUI
  Backend view for status/configuration review.
- Add `docs/custom-vps-backend.md` as the public product guide for the
  user-owned VPS backend.
- Add experimental Custom VPS service-control backend for user-owned tunnels via
  a configured local systemd service.
- Add non-secret `custom_vps` configuration placeholders and fail-closed
  validation while required Custom VPS fields are missing.
- Add a backend contract helper with stable legacy-provider support, experimental
  `custom-vps` support and fail-closed validation for unsupported backend names.
- Add backend visibility to `watchdogvpn backend status`, reports, truth-check
  output and the TUI dashboard without integrating new providers yet.
- Add a manual-off runtime state for user-requested VPN shutdowns.
- Make `vpnctl disconnect` pause watchdog and rotation automation before
  stopping the active VPN, so recovery paths do not immediately reconnect
  against the user's intent.
- Teach watchdog, rotation and NetworkManager dispatcher paths to skip
  remediation while manual-off is active.
- Route the TUI disconnect action through `vpnctl disconnect`.

## v0.3.1 - 2026-05-18

- Add the `watchdogvpn runtime-update` safety contract for the `v0.3.1` update
  engine.
- Add `watchdogvpn runtime-update --preflight` to validate safe runtime-update
  conditions without fetching, pulling, running `update.sh` or using `sudo`.
- Add confirmed `watchdogvpn runtime-update` execution with exact `yes`
  confirmation.
- Run runtime update steps in the safe order: `git fetch origin --tags`,
  post-fetch preflight, `git pull --ff-only origin main`,
  `./update.sh --skip-doctor`, `hash -r` and `./doctor.sh`.
- Stop runtime update execution at the first failed step and report the failed
  step plus the last successful step.
- Cover runtime update execution order and step failures with temporary
  repositories and mock scripts.
- Add `v0.3.1` release notes.

## v0.3.0 - 2026-05-17

- Start `v0.3.0` professional CLI planning.
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

## v0.2.0 - 2026-05-17

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
  backups, runtime installation, systemd enablement and optional desktop hooks.
- Add the first real `update.sh` flow for backed-up runtime refreshes that
  preserve user configuration, state and logs.
- Add the first real `uninstall.sh` flow that removes product-managed files
  while preserving configuration, logs and state unless explicitly purged.
- Add final installer validation for doctor checks, DNS local health and service
  settlement.
- Keep legacy provider state owned by the dedicated service user during
  install/update.
- Guide first-time service-user login during installation and add `~/.local/bin`
  to the user's shell PATH when needed.
- Install the optional launcher both in the application menu and on the user's
  desktop directory.
- Rename the desktop launcher source file to `watchdogvpn.desktop`.

### VPN and Recovery

- Add read-only `doctor.sh` preflight checks.
- Add guided installation of the initial provider CLI when a clean system does
  not have it.
- Add timeout and visible progress around the initial provider CLI installer
  download.
- Add GitHub raw IPv4 fallbacks for networks that resolve
  `raw.githubusercontent.com` poorly.
- Make service-user authentication checks tolerate fresh CLI logins by falling
  back to provider CLI status.
- Treat provider CLI license output that includes a logged-in account as
  authenticated even if the CLI does not exit before timeout.
- Try provider CLI status before reporting a license timeout as unknown
  authentication.

### DNS and Exclusions

- Implement legacy advanced DNS installation with third-party DNS provisioning,
  local starter config and DNS profile application.
- Add a DNS rescue helper and run it during uninstall so removing local DNS
  services does not leave the host without name resolution.
- Let legacy DNS profile apply continue with rollback protection when the
  current system resolver is broken before the local resolver is configured.
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
- Remove the 5-minute activation trigger from the legacy rotation timer so
  automatic location rotation only runs after boot, on the stable interval, or
  through real remediation paths.

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
- Add explicit runtime warnings for remote vendor installers, including the
  manual-install-first security path.
- Harden TUI action command builders with defensive validation for DNS profiles,
  timer units, timer intervals and bypass domains.
- Add install/security contract tests for privileged file modes, TUI package
  installation and DNS rescue ordering during uninstall.
- Start reducing subprocess shell-mode usage by adding argument-list subprocess helpers
  for simple TUI command execution.
- Add an operational audit for excessive VPN rotations and identify
  timer/restart-triggered rotations as the main suspect after real connectivity
  failures are excluded.
