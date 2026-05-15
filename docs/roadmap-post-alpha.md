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

Purpose: make the public alpha easier to support, report and review.

Planned work:

- Add `SECURITY.md`. Done.
- Add GitHub issue templates for bugs and feature requests. Done.
- Add `docs/reporting.md`. Done.
- Add a local diagnostic report command or first report generator.
- Perform a public clone smoke test.
- Validate Debian clean install if a clean system is available.
- Create initial GitHub milestones and labels.

Acceptance criteria:

- Users know how to report security issues.
- Users can open structured bug reports.
- A public clone can run `doctor.sh` and installer dry-run.
- Known post-alpha risks are tracked as GitHub issues.

## v0.2.0: Persistent Configuration

Purpose: separate product defaults from user preferences.

Planned work:

- Add central configuration under `/etc/watchdogvpn/`.
- Prefer `config.toml` if the standard toolchain remains simple enough.
- Preserve timer, DNS, language and TUI preferences during update.
- Add explicit reset commands for selected configuration groups.
- Add migration and preservation tests.
- Document configuration in `docs/configuration.md`.

Acceptance criteria:

- Updates do not reset user timer preferences.
- Missing new config keys are added safely.
- Existing config is backed up before migration.
- Reset behavior requires explicit confirmation.

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
- Documentation exists in `docs/cli.md`.

## v1.0.0: Stable Baseline

Purpose: declare a stable first release only after the system-management parts
are mature enough.

Required before `v1.0.0`:

- Install/update/uninstall tested on Ubuntu and Arch.
- Debian validation either completed or clearly excluded.
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
