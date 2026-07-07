# Demo and Validation Examples

This page shows the current WatchdogVPN terminal interface and representative
command output from a healthy installation.

The screenshots are captured from the real TUI, not a web mockup.

## TUI Screenshots

### Dashboard

![WatchdogVPN dashboard](assets/tui-dashboard.png)

The dashboard is the first operational view. It shows the real VPN state,
tunnel state, backend, route, public IP, DNS profile and active exclusions.

### Recovery Actions

![WatchdogVPN recovery actions](assets/tui-actions.png)

The actions view exposes manual recovery operations for cases where the user
wants to intervene immediately.

### DNS Profiles

![WatchdogVPN DNS tools](assets/tui-dns.png)

DNS changes are handled as explicit actions with backup, local validation and
rollback support.

### Domain Exclusions

![WatchdogVPN domain exclusions](assets/tui-exclusions.png)

Exclusions are user-owned domain rules for services that should leave through
the normal network route instead of the VPN route.

### Logs

![WatchdogVPN logs](assets/tui-logs.png)

The logs view is read-only and is intended for quick diagnostics without making
the user open individual log files manually.

## Example: Doctor

`doctor.sh` is read-only. It checks the host, repository runtime and current
installation before install/update work is performed.

```text
$ ./doctor.sh
WatchdogVPN - Doctor
Read-only preflight. No system changes will be made.

== Distro ==
[INFO] distro: Ubuntu 24.04.4 LTS (ubuntu)
[OK] distro supported
[OK] distro adapter: distros/ubuntu.sh
[INFO] package manager: apt

== System ==
[OK] init: systemd
[OK] command: bash
[OK] command: python3
[OK] command: curl
[OK] command: ip
[OK] command: systemctl
[OK] command: sudo
[OK] command: logrotate
[OK] NetworkManager active

== WatchdogVPN daemon ==
[OK] service user: watchdogvpn
[OK] daemon unit: active
[OK] daemon socket: /run/watchdogvpn/control.sock

== Network And DNS ==
[OK] truth state: UP
[OK] HTTPS connectivity

== Result ==
OK=45 WARN=0 FAIL=0
Result: OK
```

## Example: Real VPN Status

`vpnctl status` reports the truth layer result rather than blindly trusting the
provider CLI text.

```text
$ vpnctl status
VPN STATUS: UP (REAL)

tun0: UP
route: TUN
public ip: 185.174.159.38

provider status: not authoritative
```

Provider status is intentionally treated as non-authoritative. The tunnel, route
and public IP checks are the operational source of truth.

## Example: DNS

DNS v2 ships with the Phase 10 system: `watchdog dns status|test|apply|reset`,
with `auto`, `off`, `custom` and `advanced` modes, FakeIP, ECS, static IP
mapping and diversion rules. The old guided third-party DNS integration is
removed. See `docs/dns-cli.md` and `docs/phase-10-design.md` for details.

## Example: Timers

```text
$ systemctl list-timers --all vpn-domain-bypass.timer myvpn-logrotate.timer --no-pager
NEXT                         LEFT    LAST                         PASSED  UNIT                    ACTIVATES
20:10:02 MSK                 7min    20:00:01 MSK                 2min    vpn-domain-bypass.timer vpn-domain-bypass.service
21:00:00 MSK                 57min   20:00:00 MSK                 2min    myvpn-logrotate.timer   myvpn-logrotate.service
```

The daemon owns connection lifecycle; these timers cover supporting housekeeping
tasks outside the daemon process.

## Install, Update and Uninstall

```sh
git clone https://github.com/GaboEI/WatchdogVPN.git
cd WatchdogVPN
./doctor.sh
./install.sh
VPN
```

```sh
cd WatchdogVPN
git pull
./update.sh
```

```sh
cd WatchdogVPN
./uninstall.sh
```

For full removal of WatchdogVPN-managed files, logs and state:

```sh
./uninstall.sh --purge-config --purge-logs --purge-state
```

User-owned provider software, profiles, private keys and account state are not
removed by WatchdogVPN uninstall.

## Example: Installer UX

The installer shows a product-level plan before it writes files:

```text
WatchdogVPN installation plan
-----------------------------
Target distro:         Ubuntu 24.04.4 LTS (ubuntu)
Runtime commands:      /usr/local/bin
Privileged scripts:    /usr/local/sbin
Systemd units:         enabled
Advanced DNS:          no
Backups:               /var/backups/watchdogvpn
Dry run:               yes
```

The update and uninstall flows follow the same pattern: contract first, plan
second, execution details third, and a short final checklist.
