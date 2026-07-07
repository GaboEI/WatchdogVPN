# Phase 18 Task 18.5 - Mixed-Install Preflight And Migration Plan

Date: 2026-07-07
Scope: install/update read-only preflight classification and non-destructive
migration planning.

## Objective

Before `install.sh` or `update.sh` mutates the machine, classify the current
installation state and print the exact runtime files, systemd units, wrappers
and state paths that will be replaced, preserved, removed or reported. Mixed or
unsupported states must fail closed unless the repair path is explicitly
documented and preserves user data.

## Implementation

New `lib/install_preflight.sh` provides a shared read-only preflight used by
both `install.sh` and `update.sh`.

Classification:

- `fresh install`: no current core install and no legacy artifacts.
- `clean update`: all current core install paths are present.
- `legacy migration`: known WatchdogVPN-owned legacy artifacts or legacy user
  state are present, with a documented repair path.
- `mixed-inconsistent`: only part of the current core install is present.
- `unsupported`: product paths have an unsafe filesystem shape, such as a
  file destination occupied by a directory or a state directory path occupied
  by a regular file, or the installed product config names a backend other
  than the currently implemented backend.

The current core set is:

- `/usr/local/bin/watchdog`
- `/usr/local/bin/watchdogvpn`
- `/usr/local/bin/watchdogvpn-daemon`
- `/usr/local/lib/watchdogvpn`
- `/etc/systemd/system/watchdogvpn.service`

The preflight prints:

- runtime files and wrappers to replace/install;
- systemd units to replace/install;
- state/config/log paths preserved by default;
- known legacy WatchdogVPN-owned product artifacts to remove or report;
- legacy user data preserved unless the user explicitly purges data.

## Non-Destructive Repair Contract

Known-dead legacy product artifacts are safe to remove because they are
WatchdogVPN-owned files and units that are no longer shipped in any supported
configuration. They are already removed by shared install/update/uninstall
cleanup helpers.

Legacy user data is not deleted by this preflight. The existing shared-state
migration copies legacy `$HOME/.config/watchdogvpn` data into
`/var/lib/watchdogvpn` with no overwrite and keeps the source. Legacy
`/etc/adguardvpn.env`, `/var/lib/vpn-rotate/` and
`~/.conky/WatchdogVPN/` remain preserved unless an explicit purge flag and the
existing destructive `DELETE` confirmation are used.

Partial current installs are not repaired automatically. A partial core install
can hide version skew or unknown ownership, so the preflight reports
`mixed-inconsistent` and refuses before replacing or deleting anything.

Unsupported filesystem shapes are not repaired automatically. If a product file
target is a directory, or a product directory target is a file, the preflight
reports `unsupported` and refuses.

Unsupported backend configuration is also not preserved silently. The backend
helper only implements `custom-vps`; if an existing `/etc/watchdogvpn/config.toml`
names any other backend, the preflight reports `unsupported` and refuses before
the installer can preserve a runtime configuration the installed backend helper
would reject.

## Tests

New `tests/unit/test_mixed_install_preflight.sh` covers all five
classifications against an isolated temporary filesystem root:

- fresh install passes and prints absent runtime/state paths;
- clean update passes and prints replaced wrappers/preserved state;
- legacy migration passes and prints the documented repair contract;
- mixed-inconsistent blocks with a partial-install reason;
- unsupported blocks with the unsafe path shape.
- unsupported backend configuration blocks before install/update can preserve
  it.

The test is registered in `tests/unit.sh`.

## Deferred To Later Tasks

- Task 18.6 still owes the real VM smoke test proving a non-destructive
  update preserves backend/state, profiles/providers/rules/DNS/app policy/node
  groups and converges daemon/CLI state from scratch.
- Task 18.7 still owns the broader doctor integration: PATH conflicts, legacy
  wrapper detection, full unit/capability reporting and recovery hints.
- Task 18.8 still owns the final installer audit closure.
