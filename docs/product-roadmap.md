# Product Roadmap

This document explains the product direction behind the public
[ROADMAP](../ROADMAP.md). It is written for readers who want more context than
the short roadmap table, but less detail than the maintainer's local master
plan.

## Product Thesis

WatchdogVPN is not a generic VPN launcher. It is an operational resilience
layer for Linux users who need connectivity to be observable, recoverable and
auditable under unreliable or censored network conditions.

The product is built around four principles:

1. **Truth over text output** — provider status is not enough; the machine's
   route, tunnel, DNS and public-IP state matter.
2. **Recovery with user intent** — automation must not fight a user-requested
   stop.
3. **Explicit policy** — traffic routing, DNS behavior and recovery decisions
   must be inspectable.
4. **Non-destructive operations** — install, update, restore and uninstall must
   preserve user-owned state unless the user clearly approves removal.

## v2.0.0 Goal

The v2.0.0 line is the Linux CLI + TUI stability line. Its goal is to turn the
prototype/runtime history into a maintainable product foundation:

- daemon-backed runtime;
- multi-protocol profile drivers;
- provider/subscription imports;
- DNS v2;
- kill switch;
- rotation and recovery;
- routing rules;
- split tunneling and app policy;
- complete CLI;
- validated TUI;
- safe backup/restore;
- release-quality docs.

## Capability Tracks

### Runtime and Drivers

The runtime must support multiple protocol families without tying the product
to one provider. Current work centers on sing-box, AmneziaWG, OpenVPN and
OpenVPN+Cloak-style paths.

### DNS and Routing

DNS and routing are first-class product areas. The goal is not just to set DNS,
but to ensure DNS behavior follows route policy and does not leak through
unsafe paths when the kill switch is active.

### Policy and Split Tunneling

The next major product capability is Linux app/process policy: selected
processes should be able to go through VPN, go direct, use an auto-selected
node group or be blocked. This must be validated with real traffic, not only
generated config.

### Observability

WatchdogVPN needs enough visibility to help users diagnose failures, but not so
much that it silently creates a sensitive browsing log. The default posture must
favor privacy.

### CLI and TUI

The CLI is the validation and operator surface. The final TUI comes later, once
the behavior it renders is proven through CLI-backed real-world use.

### Website and Public Docs

The public website will become a commercial front door plus a manual/docs
surface. It should not publish unsupported install/download claims before the
release candidate is stable.

## Release Discipline

Every major phase should close with:

- focused tests;
- real-machine validation when system behavior is involved;
- QA audit;
- fixed HIGH/MEDIUM findings before advancement;
- updated docs where public behavior changed.

## What Is Out Of Scope For v2.0.0

- Mobile apps.
- Desktop GUI rewrite.
- Provider endorsement/certification.
- Claims that compatibility protocols are censorship-resistant by default.
- Silent removal of user-owned provider/account/profile data.

## Future Direction After v2.0.0

After the Linux v2 line is stable, future work can consider broader GUI and
multiplatform expansion. That future work should inherit the v2 core rather
than bypass it.
