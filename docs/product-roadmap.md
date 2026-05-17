# Product Roadmap

This roadmap starts after the published `v0.3.0` alpha release.

The product direction is to build WatchdogVPN in layers: safe command engine
first, polished TUI experience second, broader operations third, then hardening
and stable release work.

## Current State

Published releases:

```text
v0.1.0-alpha  -> public technical alpha
v0.1.1        -> support readiness and distro validation
v0.2.0        -> persistent configuration and TUI settings/update visibility
v0.3.0        -> professional read-only product CLI
```

## Planned Release Line

```text
v0.3.1  -> safe runtime-update engine
v0.4.0  -> final product Update Center UX
v0.5.0  -> operational CLI expansion
v0.6.0  -> runtime-applied persistent configuration
v0.7.0  -> security hardening and stronger tests
v0.8.0  -> TUI modularity and polish
v0.9.0  -> release candidate
v1.0.0  -> first stable baseline
v1.1.0  -> internationalization and advanced UX
```

## v0.3.1: Safe Runtime Update Engine

Goal: add a real update action without making it dangerous.

Primary command:

```sh
watchdogvpn runtime-update
```

Required behavior:

- Show the plan before doing anything.
- Require explicit confirmation.
- Refuse to run when the working tree is dirty.
- Refuse to run when the source branch is ahead, diverged, missing upstream or
  ambiguous.
- Require branch `main` unless a documented override is introduced later.
- Run `git fetch origin --tags`.
- Run only `git pull --ff-only origin main`.
- Run `./update.sh --skip-doctor`.
- Run `hash -r`.
- Run `./doctor.sh`.
- Stop at the first failure.
- Report the last successful step and the failed step.
- Never hide `sudo`; let the terminal prompt normally.
- Do not close or relaunch the TUI yet.

Implementation blocks:

1. Document the contract.
2. Add preflight logic and tests.
3. Add confirmed execution path.
4. Add docs and release notes.
5. Validate on an installed workstation before tagging.

Non-goals:

- Automatic TUI relaunch.
- Graphical progress UI.
- VPN connect/disconnect/rotate product commands.

## v0.4.0: Product Update Center

Goal: make the TUI Update Center feel like a product, not a maintainer console.

Main user flow:

1. User opens `Update`.
2. TUI shows current version and simple status.
3. User selects `Comprobar actualizacion` or `Actualizar`.
4. TUI shows progress text/bar while checking.
5. If current:
   - show `Estas en la ultima version`.
6. If update exists:
   - show target version;
   - ask `Actualizar ahora?`;
   - offer `Si` / `No`.
7. If `No`, return to Update.
8. If `Si`, run the safe runtime-update engine.
9. Show progress:
   - preparing;
   - fetching;
   - updating source;
   - updating runtime;
   - verifying.
10. On success, close and relaunch the TUI if that is safe in the terminal
    context.
11. On failure, show a simple error and offer technical details.

Main screen:

- Current version.
- Update status.
- Primary action.
- Technical details entry.

Technical details screen:

- branch;
- commit;
- upstream;
- origin;
- ahead/behind;
- local dirty/clean state;
- last known tag;
- command output;
- failure step.

Non-goals:

- Showing Git commands on the main user-facing screen.
- Asking users to type confirmation words in all caps.
- Updating when the source checkout is unsafe.

## v0.5.0: Operational CLI Expansion

Goal: decide which runtime operations belong in `watchdogvpn`.

Candidate commands:

```sh
watchdogvpn status
watchdogvpn doctor
watchdogvpn tui
watchdogvpn report
watchdogvpn logs
watchdogvpn update-check
watchdogvpn update-plan
watchdogvpn runtime-update
watchdogvpn config get
watchdogvpn config set
watchdogvpn config reset
watchdogvpn version
```

Commands to evaluate carefully:

```sh
watchdogvpn connect <location>
watchdogvpn disconnect
watchdogvpn rotate
```

Those commands change real VPN state and should require confirmation, clear
error handling and rollback strategy where possible.

## v0.6.0: Runtime-Applied Persistent Configuration

Goal: make persisted configuration control runtime behavior safely.

Planned work:

- Apply timer settings from `/etc/watchdogvpn/config.toml`.
- Apply supported DNS profile settings from config.
- Keep TUI preferences fully persistent.
- Backup active config before migration or runtime apply.
- Validate after applying settings.
- Roll back when a supported apply step fails.
- Keep unsupported or dangerous keys read-only until tested.

## v0.7.0: Hardening And Tests

Goal: reduce security and maintenance risk before stable release.

Planned work:

- Reduce risky `shell=True` paths in the TUI.
- Centralize command execution.
- Improve install/update/uninstall contract tests.
- Expand CI beyond syntax and lightweight unit checks.
- Strengthen log/report sanitization tests.
- Review permissions for installed files and directories.
- Validate paths with spaces and unusual home directories.

## v0.8.0: TUI Modularity And Polish

Goal: make the TUI easier to maintain and more product-like.

Planned work:

- Split large TUI sections into modules.
- Separate rendering, actions, state and command execution.
- Improve loading and error states.
- Polish Settings.
- Polish Update Center.
- Keep technical details separate from user-facing flows.

## v0.9.0: Release Candidate

Goal: freeze features and prepare the first stable release.

Required work:

- Validate install/update/uninstall on supported distros.
- Review open issues.
- Review security docs.
- Review release notes.
- Confirm known limitations.
- Decide final `v1.0.0` scope.

## v1.0.0: First Stable Baseline

Goal: first stable WatchdogVPN release.

Required:

- Reliable install/update/uninstall.
- Persistent configuration.
- Professional CLI.
- Usable TUI.
- Multi-distro validation for supported targets.
- Clear docs and support process.

Non-goals:

- Full internationalization.
- WireGuard/private backend support.
- Fedora support unless validated before then.

## v1.1.0: International Product Expansion

Goal: apply the larger international roadmap after the stable baseline.

Tracked separately in [Roadmap v1.1.0](roadmap-v1.1.0.md).

Expected themes:

- TUI internationalization.
- Translated documentation.
- Visual personalization.
- Community translation process.
- GitHub/community polish.
