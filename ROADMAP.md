# WatchdogVPN Roadmap

WatchdogVPN is moving toward a stable `v2.0.0` Linux CLI + TUI release.

This public roadmap summarizes direction. The maintainer tracks detailed
sequencing separately.

## Product Direction

WatchdogVPN v2.0.0 is a local network control plane for resilient VPN/proxy
routing on Linux. It is not a one-button VPN launcher; it manages privileged
network behavior from a CLI-first architecture. It focuses on:

- real-state truth instead of trusting provider status text;
- daemon-backed connection lifecycle;
- profile/provider management;
- protocol driver support through sing-box, AmneziaWG and OpenVPN paths;
- controlled rotation and recovery;
- kill switch behavior;
- DNS v2 safety;
- routing rules and future app policy;
- routing/capture separation across Rule/Global, Proxy/TUN/LAN and route
  actions;
- network-context automation and unified diagnostics before the CLI surface
  freezes;
- non-destructive install/update/uninstall behavior;
- a complete CLI surface before TUI polish.

## Completed v2 Foundations

| Area | Status |
| --- | --- |
| Profile/provider/parser foundation | Implemented |
| Driver foundation | Implemented for sing-box, AmneziaWG and OpenVPN/OpenVPN+Cloak paths |
| Watchdog runtime generalization | Implemented |
| Rotation and recovery | Implemented |
| Kill switch | Implemented with DNS leak ordering |
| Guided third-party DNS removal | Completed |
| DNS v2 | Implemented in the live runtime paths |
| Routing rules / connection modes | Implemented |
| Legacy provider/runtime cleanup | Completed |
| Full CLI and operator surface | Implemented |
| Multi-distro certification | Certified on 14 Linux distributions; compatible-by-family distributions are documented but never claimed as certified |
| Roadmap reconciliation | Completed |

## Active v2 Work Ahead

The v2 foundation is implemented, including the full operator CLI, and
WatchdogVPN is certified across 14 Linux distributions. The remaining work
before a frozen `v2.0.0` is:

| Order | Track | Purpose |
| --- | --- | --- |
| 1 | Public documentation realignment | Make public docs reflect the certified distribution support exactly |
| 2 | Premium installation and maintenance experience | Calm, security-first install/update/doctor/uninstall terminal UX with no silent behavior change |
| 3 | TUI premium experience | Rewire/polish the TUI over the stable v2 behavior |
| 4 | Internationalization | Translate after CLI/TUI user-facing surfaces stabilize |
| 5 | Documentation and final cleanup | Final public docs, security notes and cleanup |
| 6 | v2.0.0 release | Tag and release |

## Protocol Positioning

WatchdogVPN distinguishes between resilient and compatibility profile families.

| Category | Protocol Families |
| --- | --- |
| Resilient / anti-DPI oriented | VLESS+Reality, Trojan TLS/uTLS, Hysteria2, AmneziaWG, OpenVPN+Cloak/OverCloud |
| Compatibility | plain WireGuard, VMess, standard Shadowsocks, SOCKS, HTTP, normal OpenVPN |
| Conditional | TUIC and Shadowsocks only when configured appropriately for restrictive networks |

This roadmap must not imply that a compatibility protocol is
censorship-resistant by default.

## v2.0.0 Boundaries

- Linux only.
- CLI + TUI only.
- No mobile app in v2.0.0.
- No desktop GUI rewrite in v2.0.0.
- No silent changes to user-owned provider software, profiles, private keys or
  account state.
- No final CLI/TUI model that collapses Rule/Global, Proxy/TUN/LAN and
  Direct/Current/Block/Group into one confusing mode.
- No final CLI freeze before network-context automation, unified diagnostics
  and redacted support export are complete.
- No TUI work until the CLI surface is complete.

## Website Timing

The public website has its own plan outside this repository. Planning and
visual exploration can happen at any time, but full download/install pages
should wait until release-candidate behavior is stable and real CLI/TUI media
exists.

## Future Direction

After v2.0.0 is stable, future work may include:

- broader GUI product work;
- additional platforms;
- richer provider collaboration workflows;
- packaging formats beyond the shell installer;
- expanded public website/docs ecosystem.
