# WatchdogVPN Roadmap

WatchdogVPN is moving toward a stable `v2.0.0` Linux CLI + TUI release.

This public roadmap summarizes direction. The maintainer tracks detailed
phase-by-phase execution in a local master plan, with each phase validated and
audited before the next one starts.

## Product Direction

WatchdogVPN v2.0.0 is a local network control plane for resilient VPN/proxy
routing on Linux. It is not a one-button VPN launcher; it manages and validates
privileged network behavior from a CLI-first architecture. It focuses on:

- real-state validation instead of trusting provider status text;
- daemon-backed connection lifecycle;
- profile/provider management;
- protocol driver support through sing-box, AmneziaWG and OpenVPN paths;
- controlled rotation and recovery;
- kill switch behavior;
- DNS v2 safety;
- routing rules and future app policy;
- routing/capture separation across Rule/Global, Proxy/TUN/LAN and route
  actions;
- network-context automation and unified diagnostics before the final CLI
  freezes;
- non-destructive install/update/uninstall behavior;
- CLI-backed real-world validation before final TUI polish.

## Completed v2 Foundations

| Area | Status |
| --- | --- |
| Profile/provider/parser foundation | Implemented and audited |
| Driver foundation | Implemented for sing-box, AmneziaWG and OpenVPN/OpenVPN+Cloak paths |
| Watchdog runtime generalization | Implemented |
| Rotation and recovery | Implemented and audited |
| Kill switch | Implemented and validated with DNS leak ordering |
| Guided third-party DNS removal | Completed |
| DNS v2 | Implemented, wired into live runtime paths and audited |
| Routing rules / connection modes | Implemented and audited |
| Legacy provider/runtime cleanup | Completed |
| Full CLI and field validation | Implemented and audited (Phases 22-23) |
| Multi-distro certification | Field-certified on 8 Linux distributions (Phases 23.5-23.6); family-inferred distros documented, not claimed as certified |
| Roadmap reconciliation | Completed after v2 scope expansion |

## Active v2 Work Ahead

Phases 12 through 23 are implemented and audited, including the full operator
CLI (Phase 22) and CLI-backed field validation (Phase 23). Phases 23.5 and 23.6
then field-certified WatchdogVPN across eight Linux distributions. The remaining
work before a frozen `v2.0.0` is:

| Order | Phase | Purpose |
| --- | --- | --- |
| 23.7 | GitHub-facing documentation realignment | Make public docs reflect exactly the distro support certified in Phases 23.5-23.6 |
| 23.8 | Premium installation and maintenance experience | Calm, security-first install/update/doctor/uninstall terminal UX with no silent behavior change |
| 24 | TUI premium experience | Rewire/polish the TUI over proven v2 behavior |
| 25 | i18n | Translate after CLI/TUI user-facing surfaces stabilize |
| 26 | Documentation and final cleanup | Final public docs, security notes and cleanup |
| 27 | v2.0.0 release | Final validation, tag and release |

## Protocol Positioning

WatchdogVPN distinguishes between resilient and compatibility profile families.

| Category | Protocol Families |
| --- | --- |
| Resilient / anti-DPI oriented | VLESS+Reality, Trojan TLS/uTLS, Hysteria2, AmneziaWG, OpenVPN+Cloak/OverCloud |
| Compatibility | plain WireGuard, VMess, standard Shadowsocks, SOCKS, HTTP, normal OpenVPN |
| Conditional | TUIC and Shadowsocks only when configured and validated for restrictive networks |

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
- No high-risk network exposure work directly on `main`; LAN proxy/gateway was
  built on a dedicated branch and merged only after VM-only validation. Future
  comparable work must follow the same branch-and-audit pattern.
- No final CLI freeze before network-context automation, unified diagnostics
  and redacted support export are designed and audited.
- No final TUI work until the CLI-backed behavior is complete and field-tested.

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
