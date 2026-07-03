# WatchdogVPN Roadmap

WatchdogVPN is moving toward a stable `v2.0.0` Linux CLI + TUI release.

This public roadmap summarizes direction. The maintainer tracks detailed
phase-by-phase execution in a local master plan, with each phase validated and
audited before the next one starts.

## Product Direction

WatchdogVPN v2.0.0 is a resilience layer for VPN/proxy operation on Linux. It
focuses on:

- real-state validation instead of trusting provider status text;
- daemon-backed connection lifecycle;
- profile/provider management;
- protocol driver support through sing-box, AmneziaWG and OpenVPN paths;
- controlled rotation and recovery;
- kill switch behavior;
- DNS v2 safety;
- routing rules and future app policy;
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
| Roadmap reconciliation | Completed after v2 scope expansion |

## Active v2 Work Ahead

These items are planned phases, not all current user-facing features:

| Order | Phase | Purpose |
| --- | --- | --- |
| 12 | Linux split tunneling and app policy | Route selected Linux processes through VPN, direct, auto-selected group or block |
| 13 | Policy diagnostics and rule UX | Explain why traffic matches a rule and what action applies |
| 14 | Node groups and auto-selection | Named groups with health-aware selection |
| 15 | DNS/network-service hardening | Refine DNS diagnostics, time checks and LAN-service decisions |
| 16 | Privacy-preserving observability | Aggregate visibility without silent sensitive history |
| 17 | Backup, restore and safe sync | Versioned backup/restore, rollback and remote-sync threat review |
| 18 | Installer v2 migration | Runtime dependency installation and non-destructive update validation |
| 19 | Full CLI | Complete operator surface after capabilities settle |
| 20 | CLI-backed field validation | Real-machine validation before final TUI work |
| 21 | TUI premium experience | Rewire/polish the TUI over proven v2 behavior |
| 22 | i18n | Translate after CLI/TUI user-facing surfaces stabilize |
| 23 | Documentation and final cleanup | Final public docs, security notes and cleanup |
| 24 | v2.0.0 release | Final validation, tag and release |

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
