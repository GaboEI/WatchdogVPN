# Product Roadmap

This document explains the product direction behind the public
[ROADMAP](../ROADMAP.md). It is written for readers who want more context than
the short roadmap table, but less detail than the maintainer's local master
plan.

## Product Thesis

WatchdogVPN is not a generic VPN launcher. It is a local network control plane
for Linux users who need VPN/proxy routing, DNS policy, split tunneling,
kill-switch behavior, profile recovery and diagnostics to be observable,
recoverable and auditable under unreliable or censored network conditions.

The product is built around four principles:

1. **Truth over text output** — provider status is not enough; the machine's
   route, capture path, tunnel, DNS and public-IP state matter.
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

### Routing Mode and Capture Architecture

Before the final CLI is frozen, WatchdogVPN must align three product concepts
that are easy to confuse:

- routing policy: Rule or Global;
- capture or entry: local proxy, system proxy, TUN, LAN proxy, gateway/router;
- route action: Direct, Current/Profile, Block, Group/Auto and future chains.

Rule mode means split-tunnel rules and exceptions are honored. Global mode
means all captured traffic uses the selected protected path. Proxy, TUN and LAN
are entry mechanisms, not replacements for Rule/Global. Direct remains a
first-class route action, not a feature to remove.

This track also owns rule-set runtime safety before those rules can affect live
traffic: downloader/cache behavior, trust policy, bootstrap detours, stale-cache
handling and honest diagnostics for failed or partial policy data.

### LAN Sharing and Gateway Mode

WatchdogVPN should support network-operator workflows where the host can
intentionally share a protected path with LAN devices before the final CLI is
frozen. This includes LAN proxy sharing and, as a separate higher-risk
capability, full gateway/router mode. This is valuable for people who manage
networks, servers and multi-device labs, but it changes the trust boundary and
must be built with exceptional care: a dedicated branch, VM-only network
validation, explicit bind controls, firewall UX, kill-switch coverage for
LAN-originated traffic, DNS leak checks and teardown validation before merge.

### Network Context Automation and Unified Diagnostics

Before the final CLI surface is frozen, WatchdogVPN should add network-aware
automation and a single structured diagnostics layer. This includes optional
trusted/untrusted network policy, interface/default-route changes,
captive-portal/offline state, provider update metadata, quota/expiry display
when supplied by provider data, and a redacted support export.

Automatic behavior must be explainable, disableable and reversible.
Diagnostics should help an operator answer "what is active, why, and where
would this traffic go?" without silently recording browsing history, private
keys, subscription secrets or raw local-network identifiers.

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
- LAN proxy sharing or gateway/router mode in the current mainline runtime
  before the dedicated branch/phase validates the security model.

## Future Direction After v2.0.0

After the Linux v2 line is stable, future work can consider broader GUI and
multiplatform expansion. That future work should inherit the v2 core rather
than bypass it.
