# Validation

This repository separates lightweight validation from system-level validation.

## Local Syntax Checks

These checks do not modify the system:

```sh
python3 -m compileall -q tui tests/unit/test_tui_modules.py
bash tests/syntax.sh
bash tests/unit.sh
./doctor.sh
```

## Public Clone Smoke Test

Last recorded public clone smoke test: 2026-05-15.

Commands:

```sh
git clone https://github.com/GaboEI/WatchdogVPN.git /tmp/watchdogvpn-public-test
cd /tmp/watchdogvpn-public-test
python3 -m compileall -q tui tests/unit/test_tui_modules.py
bash tests/syntax.sh
bash tests/unit.sh
./install.sh --dry-run --yes --skip-doctor
./doctor.sh
```

Recorded result:

- HTTPS clone succeeded from the public repository.
- Python compile check passed.
- Syntax checks passed.
- Unit behavior checks passed.
- Installer dry-run passed without modifying the system.
- `doctor.sh` executed, but returned expected environment failures in a
  non-systemd/non-NetworkManager test context. A full doctor pass still requires
  a real supported Linux host.

## Real Distribution Validation

Current manually reported validation status:

| Distribution | Status | Notes |
| --- | --- | --- |
| Ubuntu 24.04 | Passed | Real workstation validation. |
| Arch Linux | Passed | Real non-virtualized machine validation. |
| Debian | Passed | Real install flow including DNS tooling. |
| CachyOS | Passed with observation | Real install flow including DNS tooling; VPN recovered after reboot. |

The CachyOS result confirms that the Arch adapter works for a real install flow
with advanced DNS. The installer gives reboot guidance if the tunnel remains
degraded after setup.

## Persistent Configuration Update Validation

Last recorded persistent configuration update validation: 2026-05-16.

Host type:

- Arch Linux real workstation.
- Existing WatchdogVPN runtime already installed.
- Existing VPN services active.

Commands:

```sh
cd ~/WatchdogVPN
git status --short --branch
sudo -v
./update.sh --skip-doctor
hash -r
command -v watchdogvpn
watchdogvpn version
watchdogvpn config get language.current
watchdogvpn config get tui.theme
watchdogvpn config get reporting.sanitize_ipv4
./doctor.sh
vpnctl status
vpnctl connect US
```

Recorded result:

- Repository was clean and synchronized with `origin/main`.
- `update.sh --skip-doctor` completed successfully.
- Installed CLI resolved to `/usr/local/bin/watchdogvpn`.
- Installed CLI reported `WatchdogVPN v0.1.1`.
- Persistent config reads returned:
  - `language.current`: `en`
  - `tui.theme`: `default`
  - `reporting.sanitize_ipv4`: `true`
- `doctor.sh` reported `OK=68 WARN=0 FAIL=0`.
- `vpnctl status` reported real VPN state `UP`.
- `vpnctl connect US` completed and kept real VPN state `UP`.
- Provider CLI text is not treated as authoritative; tunnel, route and public
  IP truth checks are the operational source of truth.

## TUI Settings Runtime Validation

Last recorded TUI Settings runtime validation: 2026-05-16.

Host type:

- Arch Linux real workstation.
- Existing WatchdogVPN runtime already installed.
- Persistent config present at `/etc/watchdogvpn/config.toml`.

Commands:

```sh
sudo -v
./update.sh --skip-doctor
watchdogvpn config get language.current
watchdogvpn config get tui.theme
watchdogvpn config get tui.color
watchdogvpn config get tui.unicode
VPN
./doctor.sh
```

Recorded result:

- `update.sh --skip-doctor` completed successfully.
- Existing `/etc/watchdogvpn/config.toml.example` was preserved.
- Existing `/etc/watchdogvpn/config.toml` was preserved.
- TUI Settings reset restored:
  - `language.current`: `en`
  - `tui.theme`: `default`
  - `tui.color`: `true`
  - `tui.unicode`: `true`
- `VPN` opened after update.
- `doctor.sh` reported `OK=68 WARN=0 FAIL=0`.
- Settings reset did not touch DNS, timers, reporting, VPN state, logs or
  bypass configuration.

## TUI Update Center Runtime Validation

Last recorded TUI Update Center runtime validation: 2026-05-17.

Host type:

- Arch Linux real workstation.
- Existing WatchdogVPN runtime already installed.
- Source checkout present at `~/WatchdogVPN`.

Commands:

```sh
cd ~/WatchdogVPN
git status --short --branch
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
VPN
```

TUI paths checked:

- `Update -> Ver estado`
- `Update -> Comprobar remoto`
- `Update -> Actualizar runtime`
- `Update -> Detalles tecnicos`

Recorded result:

- Repository was clean and synchronized with `origin/main`.
- Unit behavior checks passed.
- Syntax checks passed.
- Python compile check passed.
- `git diff --check` passed.
- Installed runtime update completed successfully.
- Installed `watchdogvpn` resolved after `hash -r`.
- `watchdogvpn version` reported the installed product version.
- `VPN` opened after update.
- Update Center presented product-facing status separately from maintainer
  technical details.
- Update Center detected the source checkout from the installed TUI context
  instead of treating `~/.local` as the repository.
- Update Center did not run `pull`, `push`, `update.sh` or privileged commands
  from the product status screen.

## Runtime Update Engine Installed Validation

Last recorded runtime update engine installed validation: 2026-05-18.

Host type:

- Ubuntu 24.04 real workstation.
- Existing WatchdogVPN runtime already installed.
- Source checkout present at `~/WatchdogVPN`.

Commands:

```sh
cd ~/WatchdogVPN
git status --short --branch
./bin/watchdogvpn runtime-update --preflight
/usr/local/bin/watchdogvpn runtime-update --preflight
./update.sh --dry-run --yes --skip-doctor
sudo -v
./update.sh --yes --skip-doctor
hash -r
cmp -s ./bin/watchdogvpn /usr/local/bin/watchdogvpn; echo cmp_exit=$?
/usr/local/bin/watchdogvpn runtime-update --preflight
./doctor.sh
```

Recorded result:

- Repository was clean and synchronized with `origin/main`.
- Checkout `./bin/watchdogvpn runtime-update --preflight` passed.
- Before the first real update, installed `/usr/local/bin/watchdogvpn` was
  still the older preflight-only runtime update implementation.
- `./update.sh --dry-run --yes --skip-doctor` passed and showed the expected
  replacement plan, including `/usr/local/bin/watchdogvpn` backup and install.
- Real `./update.sh --yes --skip-doctor` completed successfully after `sudo`
  authentication in a real terminal.
- Product-managed runtime files were backed up under `/var/backups/watchdogvpn/`.
- User TUI launcher and installed TUI module directory were backed up before
  replacement.
- Existing `/etc/watchdogvpn/config.toml.example` and
  `/etc/watchdogvpn/config.toml` were preserved.
- `systemd-analyze verify` emitted an unrelated legacy `/var/run/anydesk.pid`
  warning for `anydesk.service`; WatchdogVPN systemd verification continued.
- Final release update after the `v0.3.1` version bump completed successfully.
- Installed `/usr/local/bin/watchdogvpn version` reported `WatchdogVPN v0.3.1`.
- `cmp_exit=0` confirmed installed `/usr/local/bin/watchdogvpn` matched
  `./bin/watchdogvpn`.
- Installed `/usr/local/bin/watchdogvpn runtime-update --preflight` passed and
  showed the confirmed-execution preflight text for commit `36618ae`.
- `doctor.sh` reported `OK=68 WARN=0 FAIL=0`.
- Installed service state after update:
  - `watchdogvpn.service`: active and enabled
  - `vpn-domain-bypass.timer`: active and enabled
  - `myvpn-logrotate.timer`: active and enabled
- Network truth state was `UP`.

## Unit Behavior Checks

`tests/unit.sh` runs behavior checks with mocked system commands and temporary
state. These tests do not require a real VPN tunnel, do not write to `/etc`,
`/run`, `/var` or systemd, and do not restart services.

Current coverage:

- `vpn_truth_check` state contract:
  - `UP` when `tun0`, route and public IP are healthy
  - `DEGRADED` when the tunnel exists but route or public IP is unhealthy
  - `DOWN` when the tunnel is absent
  - `--shell`, `--quiet` and `--json` output behavior
- daemon/runtime behavior:
  - standby state is explicit
  - connect, disconnect, status and rotate go through daemon IPC
  - runtime state is persisted in the shared WatchdogVPN state directory
- TUI module behavior:
  - extracted action command builders, command helpers, state collectors,
    render helpers, constants, formatters, parsers and validators keep stable
    behavior
  - installed layout with `VPN` plus `watchdogvpn/` remains importable
  - non-interactive launcher execution exits cleanly before terminal setup

## System-Level Checks

These checks require a Linux system with systemd and, in some cases, sudo:

```sh
systemd-analyze verify systemd/*.service systemd/*.timer
sudo logrotate -d etc/logrotate.d/myvpn
```

## Runtime Checks After Installation

```sh
vpn_truth_check
watchdogvpn report
watchdog status --json
VPN
```

## Acceptance Criteria

A clean install is considered valid when:

- `doctor.sh` reports no blocking failures.
- The TUI opens with `VPN`.
- Dashboard shows VPN, backend, tunnel, route and DNS state.
- `vpn_truth_check` returns parseable state.
- `watchdog status --json` returns daemon state.
- `watchdogvpn.service` is enabled and active.
- logrotate config validates.
- uninstall can remove product files without deleting user-owned provider
  software, profiles, private keys or account state.
