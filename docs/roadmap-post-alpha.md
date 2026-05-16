# Post-Alpha Roadmap

This roadmap starts after `v0.1.0-alpha`.

The goal is to move WatchdogVPN from a public alpha into a reliable, testable
and maintainable Linux system tool without rushing into large international
features too early.

## Release Strategy

```text
v0.1.0-alpha  -> public technical alpha
v0.1.1        -> post-release hygiene and support readiness
v0.2.0        -> persistent configuration and migration
v0.3.0        -> professional CLI
v1.0.0        -> first stable baseline
v1.1.0        -> internationalization and advanced UX
```

## v0.1.1: Post-Release Hygiene

Status: ready for release tagging.

Purpose: make the public alpha easier to support, report and review.

Planned work:

- Add `SECURITY.md`. Done.
- Add GitHub issue templates for bugs and feature requests. Done.
- Add `docs/reporting.md`. Done.
- Add a local diagnostic report command or first report generator. Done.
- Perform a public clone smoke test. Done.
- Validate Debian clean install if a clean system is available. Done.
- Fix CachyOS/Arch-derived distro detection. Done.
- Validate CachyOS on a real machine. Done, with post-reboot VPN recovery observation.
- Create initial GitHub milestones and labels. Done.
- Fix installed `watchdogvpn` CLI path shadowing. Done.

Acceptance criteria:

- Users know how to report security issues.
- Users can open structured bug reports.
- Users can generate a local diagnostic report without telemetry.
- A public clone can run `doctor.sh` and installer dry-run.
- Debian validation is recorded after a real install flow.
- CachyOS validation is recorded after a real install flow with advanced DNS.
- Known post-alpha risks are tracked through GitHub planning and issues.
- `watchdogvpn report` works after update from an older installed layout.

## v0.2.0: Persistent Configuration

Status: foundation complete.

Purpose: separate product defaults from user preferences.

Planned work:

- Add central configuration under `/etc/watchdogvpn/`.
- Prefer `config.toml` if the standard toolchain remains simple enough.
- Add default config example and schema contract tests. Done.
- Add minimal configuration helper functions. Done.
- Create default config during install/update and preserve it during uninstall.
  Done.
- Preserve timer, DNS, language and TUI preferences during update.
  Foundation done; timer and DNS runtime application remains read-only for now.
- Add missing config keys during migration without overwriting user values.
  Done.
- Add read-only `watchdogvpn config get`. Done.
- Add validated `watchdogvpn config set` for safe keys. Done.
- Add explicit reset commands for selected configuration groups.
  Done for safe sections.
- Add migration and preservation tests. Done.
- Document configuration in [Configuration](configuration.md). Done.
- Document the current product CLI in [CLI](cli.md). Done.
- Validate installed config update on a real Arch workstation. Done.
- Add a read-only TUI Settings view backed by persistent config. Done.
- Add TUI Settings actions for safe language and TUI preferences. Done.
- Add confirmed TUI Settings reset for language and TUI preferences. Done.
- Add a read-only TUI Update Center for version, repository state and update
  routines. Done.
- Add read-only Update Center sync status for local/remote divergence and dirty
  working trees. Done.

Acceptance criteria:

- Updates do not reset user timer preferences.
- Missing new config keys are added safely.
- Existing config is backed up before migration.
- Reset behavior requires explicit confirmation.
- `docs/configuration.md` defines the install, update, uninstall, reset and CLI
  contracts before runtime implementation begins.

## v0.3.0: Professional CLI

Purpose: expose WatchdogVPN as a product command, not only as `VPN`.

Planned command shape:

```sh
watchdogvpn status
watchdogvpn tui
watchdogvpn doctor
watchdogvpn config get
watchdogvpn config set
watchdogvpn report
watchdogvpn logs
watchdogvpn version
```

Compatibility:

- Keep `VPN` as a TUI launcher.
- Let `watchdogvpn tui` open the same TUI.
- Keep existing low-level commands available for automation.

Acceptance criteria:

- `watchdogvpn --help` is clear.
- Common operations have stable subcommands.
- Documentation exists in [CLI](cli.md).

## v1.0.0: Stable Baseline

Purpose: declare a stable first release only after the system-management parts
are mature enough.

Required before `v1.0.0`:

- Install/update/uninstall tested on Ubuntu and Arch.
- Debian validation completed or clearly maintained.
- Persistent config implemented and tested.
- Security reporting exists.
- Known `shell=True` hardening work is reduced or documented.
- CI is stronger than syntax-only validation.
- Release notes are written for non-author users.

Non-goals for `v1.0.0`:

- Full internationalization.
- Visual theme system.
- WireGuard backend.
- Fedora support.

## v1.1.0: International Product Expansion

Purpose: expand from a stable Linux tool into an international, configurable
and community-ready product.

The detailed vision is tracked in [Roadmap v1.1.0](roadmap-v1.1.0.md).
