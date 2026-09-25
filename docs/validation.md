# Compatibility and Checks

This page describes how the product reports support and how the system can be
checked locally.

## Health Check

The read-only product health check reports the current system state without
modifying it:

```sh
./doctor.sh
```

## Distribution Compatibility

WatchdogVPN support is defined per release. The table below lists every
distribution and release the product knows about, its release model and its
current support classification.

<!-- BEGIN GENERATED: compat-support-table -->
| Distribution | Release | Model | Support | Certification | Freshness | Protocols |
| --- | --- | --- | --- | --- | --- | --- |
| AlmaLinux | AlmaLinux 9 | stable | certified | 2026-09-02 | — | All 12 in-scope protocols |
| Arch Linux | Arch Linux | rolling | certified | 2026-08-15 | current (365 days) | All 12 in-scope protocols |
| CachyOS | CachyOS | rolling | certified | 2026-08-16 | current (365 days) | All 12 in-scope protocols |
| CentOS Stream | CentOS Stream | rolling | certified | 2026-09-20 | current (365 days) | All 12 in-scope protocols |
| Debian | Debian 13.6 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Fedora | Fedora 44 | stable | certified | 2026-08-19 | — | All 12 in-scope protocols |
| Kali GNU/Linux | Kali GNU/Linux | rolling | certified | 2026-09-14 | current (365 days) | All 12 in-scope protocols |
| Linux Mint | Linux Mint 22.3 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Manjaro | Manjaro | rolling | certified | 2026-09-18 | current (365 days) | All 12 in-scope protocols |
| Pop!_OS | Pop!_OS 24.04 | stable | certified | 2026-09-16 | — | All 12 in-scope protocols |
| Red Hat Enterprise Linux | Red Hat Enterprise Linux 9 | stable | family_inferred | — | — | — |
| Rocky Linux | Rocky Linux 9 | stable | certified | 2026-08-20 | — | All 12 in-scope protocols |
| Ubuntu | Ubuntu 24.04.4 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Ubuntu | Ubuntu 26.04 | stable | experimental | — | — | — |
| openSUSE Leap | openSUSE Leap 15.6 | stable | certified | 2026-09-08 | — | All 12 in-scope protocols |
| openSUSE Tumbleweed | openSUSE Tumbleweed | rolling | certified | 2026-09-10 | current (365 days) | All 12 in-scope protocols |

<!-- END GENERATED: compat-support-table -->

`certified` means the exact release is fully supported across installation, the
in-scope protocols and the full lifecycle. Compatibility is release-specific:
it is never inherited from a distribution family, and one release is never
certified through another.

`family_inferred` and `experimental` releases are compatible by package family
but are not certified on their own. In particular, **Red Hat Enterprise Linux is
not certified**; it has its own release model and is never certified through
CentOS Stream. Other Debian/Ubuntu derivatives beyond Linux Mint and Pop!_OS are
likewise not individually certified.

Rolling distributions (Arch Linux, CachyOS, Manjaro, Kali, CentOS Stream and
openSUSE Tumbleweed) are certified against a specific release and carry an
expiry window; the table reports their current freshness state.

<!-- BEGIN GENERATED: compat-protocol-list -->
The following protocol families are in scope for certified releases:

- AmneziaWG
- HTTP proxy
- Hysteria2
- OpenVPN
- OpenVPN + Cloak/OverCloud
- Shadowsocks
- SOCKS
- Trojan
- TUIC
- VLESS
- VMess
- WireGuard

This list applies to certified releases only. A `family_inferred` or
`experimental` release does not imply full protocol coverage, and every
certified release is supported exactly as its own row states.

<!-- END GENERATED: compat-protocol-list -->

## Configuration Guarantees

The product enforces the following configuration behavior:

- Update preserves an existing `/etc/watchdogvpn/config.toml` and its values.
- TUI Settings reset restores `language.current`, `tui.theme`, `tui.color` and
  `tui.unicode` to their defaults.
- Settings reset does not touch DNS, timers, reporting, VPN state, logs or
  bypass configuration.
- The Update Center shows product-facing status separately from maintainer
  technical details and does not run `pull`, `push`, `update.sh` or privileged
  commands from the status screen.
- Runtime update replaces the product-managed runtime and preserves user
  configuration, logs and shared runtime state.
- Provider CLI text is not treated as authoritative; tunnel, route and public
  IP truth checks are the operational source of truth.

## Runtime Truth Model

`vpn_truth_check` reports a single state from the observable layers:

- The reachable v2 daemon takes precedence over the legacy custom-vps backend,
  so an active `wdvpn-tun0` runtime is never checked against a stale static
  `tun0` setting.
- Managed TUN mode is `UP` only when lifecycle state, the observed runtime
  interface, managed routing artifacts, kill-switch consistency and normal
  public egress agree.
- Managed proxy mode is `UP` only when lifecycle state, owned proxy listener
  evidence, kill-switch consistency and a public-IP request through the local
  proxy agree.
- `DEGRADED` means a managed runtime exists but one or more observable layers
  disagree.
- `DOWN` means no usable managed runtime is active.
- custom-vps keeps the historical `tun0`/route/public-IP contract only as a
  compatibility fallback when daemon lifecycle truth is unavailable.

## Kill-Switch Model

- sing-box capture traffic is not trusted from a mark alone.
- nftables admits the capture mark in the output chain only when an atomic
  companion postrouting chain also rejects that mark from every final interface
  except the configured managed TUN.
- External DNS rejects precede the capture-mark allow, and the separate
  outbound mark still requires the daemon UID.
- Ruleset inspection treats a missing output allow or postrouting guard as
  inconsistent.
- The iptables fallback rejects unscoped sing-box mark allows.

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

## Valid Installation Criteria

A clean install is valid when:

- `doctor.sh` reports no blocking failures.
- The TUI opens with `VPN`.
- Dashboard shows VPN, backend, tunnel, route and DNS state.
- `vpn_truth_check` returns parseable state.
- `watchdog status --json` returns daemon state.
- `watchdogvpn.service` is enabled and active.
- logrotate config validates.
- uninstall can remove product files without deleting user-owned provider
  software, profiles, private keys or account state.
