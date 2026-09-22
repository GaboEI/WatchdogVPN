# WatchdogVPN v0.2.0 Release Notes

Status: alpha feature release.

`v0.2.0` moves WatchdogVPN from a packaged alpha into a configurable product
baseline. The release focuses on persistent configuration, a safer product CLI,
TUI Settings and a product-facing Update Center.

This is still not a stable 1.0 release.

## Highlights

- Add persistent configuration under `/etc/watchdogvpn/config.toml`.
- Add a default configuration example in
  `examples/watchdogvpn-config.toml.example`.
- Preserve WatchdogVPN configuration during install, update and uninstall.
- Add safe config migration for missing keys without overwriting user values.
- Add `watchdogvpn config get` for read-only config inspection.
- Add `watchdogvpn config set` for safe language, TUI and reporting
  keys.
- Add confirmed `watchdogvpn config reset` for safe config sections.
- Add `docs/configuration.md` and `docs/cli.md`.
- Add TUI Settings for safe persistent preferences.
- Apply persisted TUI color and theme preferences when the interface starts.
- Add confirmed TUI Settings reset without touching DNS, timers, reporting,
  VPN state, logs or bypass configuration.
- Add a TUI Update Center with product-facing status, source sync state,
  confirmed remote metadata check and contextual runtime update guidance.
- Separate Update Center technical details from the main product-facing view.
  and TUI Update Center.

## Persistent Configuration

WatchdogVPN now has a central persistent configuration file:

```text
/etc/watchdogvpn/config.toml
```

The installer creates the default config on fresh install. The updater preserves
existing user configuration and adds missing keys safely during migration.

The uninstaller preserves `/etc/watchdogvpn/` by default. Users must explicitly
request config removal with:

```sh
./uninstall.sh --purge-config
```

## Product CLI

The `watchdogvpn` command now includes config inspection and safe config
modification commands:

```sh
watchdogvpn config get language.current
watchdogvpn config set language.current es
watchdogvpn config set tui.theme high_contrast
watchdogvpn config reset tui
watchdogvpn config reset language
```

Config writes reject unsupported keys and values before modifying the active
configuration.

## TUI Settings

The TUI now includes a Settings section for safe persistent preferences:

- language preference
- visual theme
- color on/off
- unicode on/off
- confirmed reset for language and TUI preferences

The current release persists the language preference, but full TUI
internationalization is still future work.

## TUI Update Center

The TUI now includes an Update Center that is intentionally conservative.

It can show:

- installed WatchdogVPN version
- source checkout status
- sync state
- local changes state
- runtime update readiness
- last known release tag

It can also run a confirmed remote metadata refresh:

```sh
git fetch origin --tags
```

It does not automatically run `git pull`, `git push`, `update.sh` or privileged
commands. Runtime update remains a manual action in this release.

Advanced Git and maintainer details are separated into `Detalles tecnicos` so
the main Update Center screen stays product-facing.

## Upgrade Notes

Existing users can update with:

```sh
cd ~/WatchdogVPN
git fetch origin --tags
git pull --ff-only origin main
bash tests/unit.sh
bash tests/syntax.sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
git diff --check
sudo -v
./update.sh --skip-doctor
hash -r
watchdogvpn version
./doctor.sh
VPN
```

After updating, open:

```text
VPN -> Settings
VPN -> Update
```

## Supported and Targeted Platforms

| Distribution | Status |
| --- | --- |
| Ubuntu 24.04 | Supported (stable) |
| Arch Linux | Supported (rolling) |
| Debian 13.6 | Supported (stable) |
| CachyOS | Supported (rolling) |
| Fedora | Future target |

## Known Limitations

- This is still an alpha release, not a stable 1.0 release.
- TUI language selection is persisted, but full internationalization is not
  implemented yet.
- The Update Center does not perform automatic runtime updates.
- Timer and DNS preferences are documented in the configuration model, but
  runtime application remains read-only for now.
- TUI command helpers use explicit argv wrappers instead of subprocess shell mode.
- External installer downloads for the initial provider CLI and optional DNS
  component are not yet cryptographically pinned.
- The first backend is provider-CLI based. WireGuard/private backend support is
  not implemented yet.
- Fedora support remains a future target.

## Local Checks

```sh
bash tests/unit.sh
bash tests/syntax.sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
git diff --check
```

## Non-Goals For This Release

- Stable 1.0 support promise.
- Full TUI internationalization.
- Automatic update execution from the TUI.
- Full professional CLI coverage.
- WireGuard/private backend support.
- Fedora support.
