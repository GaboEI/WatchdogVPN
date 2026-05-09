# Project History

WatchdogVPN did not start as a polished product repository. It began as a local
Linux automation prototype around a real VPN workstation, then was migrated into
this product-oriented repository once the installer, updater, uninstaller and
multi-distro direction became concrete.

The earlier local prototype history is preserved locally, but it is not imported
directly into `main` because it contains machine-specific network snapshots,
domain exclusions, routing state and operational notes from a personal system.
Publishing that raw history would add privacy risk and distract from the product
repository.

This document preserves the engineering timeline without exposing those local
machine details.

## Timeline Summary

| Period | Focus |
| --- | --- |
| 2026-04-25 to 2026-04-27 | Routing investigation, first TUI state capture, truth-layer hardening |
| 2026-04-28 to 2026-04-30 | Product planning, DNS diagnostics, rollback, AdGuard Home direction |
| 2026-05-01 to 2026-05-02 | TUI polish, mouse navigation, sudo keepalive, log traceability, auth watchdog |
| 2026-05-07 | Decision to migrate from local prototype into a product repository |
| 2026-05-07 to 2026-05-09 | WatchdogVPN repository, installer/update/uninstall, CI, security docs, demo |

## Local Prototype Phase

The local prototype repository contains 56 commits. It covered the transition
from machine-specific VPN scripts into a structured resilience layer.

Representative milestones:

```text
2026-04-25  Baseline before routing investigation
2026-04-25  Update dispatcher and restore watchdog to 2 minutes
2026-04-26  Add TUI and Conky user-layer state
2026-04-27  Unify VPN truth layer and harden TUI
2026-04-27  Harden bypass actions in TUI
2026-04-27  Show newest VPN logs first in TUI
2026-04-28  Add VPN productization plan
2026-04-28  Add formal vpn truth check modes
2026-04-28  Document desktop launcher plan
2026-04-28  Document future private VPN backend
2026-04-28  Document optional AdGuard Home integration
2026-04-29  Document audit and harden VPN stack
2026-04-29  Stabilize DNS and domain bypass refresh
2026-04-29  Add VPN stress test tool
2026-04-29  Add rotate rollback after stress test
2026-04-30  Add read-only DNS diagnostics tool
2026-04-30  Add manual DNS profile apply and rollback
2026-04-30  Add safe DNS panel to TUI
2026-04-30  Make DNS panel apply real profiles
2026-04-30  Add AdGuard DoQ and OpenDNS DNS profiles
2026-04-30  Improve TUI safety and long-action feedback
2026-05-01  Refine TUI navigation hierarchy
2026-05-01  Polish TUI section copy and status labels
2026-05-01  Improve TUI mouse navigation
2026-05-01  Add TUI sudo startup keepalive
2026-05-02  Confirm TUI exit and limit mouse actions
2026-05-02  Add VPN log rotation housekeeping
2026-05-02  Standardize VPN log trace format
2026-05-02  Add TUI traceability summary
2026-05-02  Document safe update path
2026-05-02  Refine installer decisions and defaults
2026-05-02  Add AdGuard VPN auth watchdog
2026-05-02  Expand TUI dashboard visible area
2026-05-02  Make VPN notifications traceable
2026-05-07  Make TUI dashboard refresh nonblocking
2026-05-07  Approve multi-distro product repository
```

## Product Repository Phase

This repository starts at the point where the project became a product candidate
instead of a machine snapshot. The goal of the product repository is to keep
runtime files, docs, installation contracts, CI and user-facing assets in a
clean structure.

Representative milestones:

```text
2026-05-07  Create VPN Control Center product repository
2026-05-07  Rename product to WatchdogVPN
2026-05-07  Expand read-only doctor preflight
2026-05-08  Implement core installer flow
2026-05-08  Implement safe update flow
2026-05-08  Implement careful uninstall flow
2026-05-08  Implement AdGuard Home advanced DNS setup
2026-05-08  Harden installer product flow
2026-05-08  Guide clean install through AdGuard VPN CLI setup
2026-05-08  Add DNS rescue for uninstall flow
2026-05-08  Polish timer controls notifications and desktop shortcut
2026-05-08  Refine product messaging and TUI labels
2026-05-09  Prepare alpha portfolio status
2026-05-09  Add baseline GitHub Actions CI
2026-05-09  Document security model and risks
2026-05-09  Add VPN rotation frequency audit
2026-05-09  Relax VPN rotation timer activation
2026-05-09  Add TUI screenshots and demo documentation
2026-05-09  Improve README project overview
```

## Why the Raw Local History Is Not Published in `main`

The local prototype captured a real workstation while the system was being
debugged. That was useful engineering context, but it is not appropriate as a
public product history because it can include:

- local routing snapshots;
- domain exclusion lists from the author's machine;
- diagnostic files with public and private network details;
- long operational notes tied to one workstation;
- obsolete helper scripts and experiments that are not part of the product.

The product repository is intentionally curated. It keeps the useful outcome of
that work while separating personal machine state from reusable software.

## Engineering Takeaway

The important story is not that every prototype commit appears in `main`. The
important story is that the project moved through identifiable engineering
stages:

1. Real failure investigation.
2. Truth-layer validation.
3. TUI and operational feedback.
4. DNS and routing safety.
5. Watchdog and auth recovery.
6. Install/update/uninstall contracts.
7. Multi-distro product packaging.
8. CI, documentation, security review and demo assets.

That path is what shaped WatchdogVPN into the current alpha candidate.
