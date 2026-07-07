# Phase 18 Task 18.1 - Legacy Contamination Inventory

Date: 2026-07-07
Scope: audit/documentation only. No installer, updater, uninstaller or `lib/*.sh`
code was changed for this task, per the Phase 18 task text: "Document the
inventory and define the exact detection contract before changing installer
behavior."

## Objective

Audit `install.sh`, `update.sh`, `uninstall.sh`, `doctor.sh`, `lib/*.sh` and the
shipped `systemd/` units for legacy contamination risk, and define the exact
detection contract that later Phase 18 tasks (18.2, 18.5, 18.7) must implement.

## Audited Surface

- `install.sh`, `update.sh`, `uninstall.sh`, `doctor.sh`
- `lib/common.sh`, `lib/distro.sh`, `lib/packages.sh`, `lib/install_files.sh`,
  `lib/config.sh`, `lib/systemd.sh`, `lib/runtime.sh`, `lib/desktop.sh`,
  `lib/singbox.sh`
- `systemd/*.service`, `systemd/*.timer`
- `docs/install-contracts.md`, `docs/qa-audit-2026-07-03-phase-2-6-legacy-removal.md`
- Git history around the product rename (`2b8b0ff`) and the AdGuard/Conky
  removal (`c19394f`, `59f4260`)
- The installed state of this development workstation, read-only, as a live
  case study (not a substitute for the Task 18.6 VM smoke test)

## Method

Two sources were used together: the repository's own history of removed
features (which is the most concrete record of what "legacy" means for this
specific product), and a read-only inspection of a real installed machine.
The second part matters because this workstation independently accumulated
exactly the kind of drift Phase 18 is meant to catch, without anyone
deliberately constructing a test case for it.

## Inventory By Threat-Model Category

### 1. Old binaries/wrappers in common PATH locations

Current shipped commands (`lib/runtime.sh::install_runtime_files`):
`no_vpn`, `vpn_dns_rescue`, `vpn_backend`, `vpn_manual_state`, `vpn_notify`,
`vpn_truth_check`, `vpnctl`, `watchdog` (generated wrapper), `watchdogvpn`,
`watchdogvpn-daemon` (generated wrapper) in `/usr/local/bin`;
`vpn_domain_bypass_apply.sh` in `/usr/local/sbin`; `VPN` in `~/.local/bin`.

Historical commands that existed in this product and were later deleted from
the repository (commit `c19394f`, "remove AdGuard from the v1 runtime layer
entirely"): `/usr/local/bin/vpn_auth_check`, `/usr/local/sbin/vpn_rotate.sh`,
`/usr/local/sbin/vpn_set`, `/usr/local/sbin/vpn_watchdog.sh`. These are real
prior product entrypoints, not third-party tools.

Live evidence from this workstation (read-only `ls /usr/local/bin`):

```
/usr/local/bin/fixvpn
/usr/local/bin/vpn_dnsctl
/usr/local/bin/vpn_monitor
```

None of these three names ever appear in this repository's `bin/` directory.
They predate the current product repository (the project history document
records a "loose local scripts" phase before the 2026-05-07 productization).
Neither `doctor.sh` nor `uninstall.sh` knows about them, so they are silently
invisible to both diagnostics and removal today.

**Detection contract required:** maintain a fixed list of historical
WatchdogVPN-owned command names per install root (`/usr/local/bin`,
`/usr/local/sbin`, `~/.local/bin`) distinct from the current shipped list.
Report any historical name found as legacy contamination (`WARN`), separately
from any name that isn't in either list (unknown/foreign script - report but
never touch). Never delete a path that isn't on the explicit
WatchdogVPN-owned historical list.

### 2. Stale or duplicate systemd units/timers

Current shipped units (`systemd/` + `lib/systemd.sh::SYSTEMD_UNITS`, both
match): `watchdogvpn.service`, `vpn-domain-bypass.service`,
`vpn-domain-bypass.timer`, `myvpn-logrotate.service`,
`myvpn-logrotate.timer`.

Historical units deleted from the repository in `c19394f`:
`adguardvpn.service`, `vpn-watchdog.service`, `vpn-watchdog.timer`,
`vpn-rotate.service`, `vpn-rotate.timer`, `vpn-rotate-firstboot.timer`,
`vpn-rotate-onboot.service`.

**Regression found (not fixed in this task - see "Regression Finding"
below):** commit `c19394f` added `remove_legacy_adguard_units()` to
`uninstall.sh` specifically to clean these seven units off a machine that
installed before the AdGuard removal. Commit `59f4260` ("finish legacy
provider and Conky removal") deleted that function outright, along with its
call site, with no replacement. Today's `uninstall.sh` performs zero cleanup
of these seven unit names.

`doctor.sh` has a section literally titled "Legacy Systemd Units" (line 349),
but it only inspects `vpn-domain-bypass.timer` and `myvpn-logrotate.timer` -
both are current, still-shipped units, not legacy ones. The section name is a
leftover misnomer from before those two units were the officially enabled
set; it currently does not detect any of the seven actually-legacy unit names
above. This is a documentation/naming defect for Task 18.7 to fix, not a
functional regression by itself.

**Detection contract required:** enumerate the seven historical unit names
above; for each, check `/etc/systemd/system/<unit>` existence plus
`systemctl is-enabled`/`is-active` state; report any hit as legacy
contamination. Do not disable or remove automatically outside of an explicit
migration plan (Task 18.5) or explicit user confirmation.

### 3. Stale ExecStart paths

All five currently shipped units point at installed wrapper paths
(`/usr/local/bin/watchdogvpn-daemon`, `/usr/sbin/logrotate` +
`/etc/logrotate.d/myvpn`, `/usr/local/sbin/vpn_domain_bypass_apply.sh`), never
at the source checkout directly. So there is no "current unit points at a
deleted checkout" risk today. The real risk is entirely on the historical
units from category 2: if any of those seven unit files still exist on a real
machine, their `ExecStart=` targets (`/usr/local/sbin/vpn_rotate.sh`,
`vpn_watchdog.sh`, `vpn_set`, `/usr/local/bin/vpn_auth_check`) were removed by
`c19394f`/`59f4260`'s file-removal changes, so a stale enabled timer could
still try to execute a path that install/update no longer ships. This is the
same population as category 2 and shares its detection contract.

### 4. Source checkout vs. installed runtime version skew

There is no version marker anywhere in the repository beyond the
hand-edited `VERSION="v0.3.1"` string in `bin/watchdogvpn`. No git commit
hash or install timestamp is recorded into the installed tree at install/update
time. `watchdogvpn version` / `watchdog version` only prints that static
string; it cannot detect that the installed copy is behind the source
checkout.

**Live evidence from this workstation**, obtained by diffing the installed
`/usr/local/bin/watchdogvpn` against the current checkout's `bin/watchdogvpn`
(both report `VERSION="v0.3.1"`):

- the installed copy is missing the IPv6 redaction `sed` rules added to
  `sanitize_stream()` during the Phase 16 Task 16.1 privacy fix;
- the installed copy is missing the entire `metrics_report_summary()` function
  (Phase 16 observability reporting).

Diffing the installed Python package tree `/usr/local/lib/watchdogvpn`
(installed 2026-07-04) against the source checkout confirms the same drift at
a larger scale: `config/backup_manager.py` (the whole Phase 17 backup/restore
feature, closed 2026-07-07) does not exist in the installed tree at all. A
`watchdog backup` or `watchdog uninstall` invocation through the installed
`/usr/local/bin/watchdog` wrapper on this machine would run against a runtime
that predates those commands, while `watchdog version` would report no
discrepancy whatsoever.

This is the clearest evidence in this inventory that "installed
`watchdog`/`watchdogvpn`/daemon unit and doctor resolve to the same v2 runtime
version/source" (a Phase 18 acceptance criterion) is not true right now on a
real, currently-in-use installation.

**Detection contract required:** at install/update time, stamp an
installed-state marker (source git commit hash + install timestamp) into the
installed package tree or `/etc/watchdogvpn/`. `doctor.sh` and a
`watchdog version --check`-style command must compare that marker against
`git rev-parse HEAD` of the current source checkout when run from within a
checkout, and clearly report skew rather than only printing a static product
version string.

### 5. Old config/state/log locations

Historical paths deleted from `uninstall.sh`'s purge/keep handling in
`59f4260`, with no replacement reporting or purge path left behind:
`/etc/adguardvpn.env`, `/var/lib/vpn-rotate/`, `~/.conky/WatchdogVPN/` (the
`--purge-conky` flag and its `[KEEP]`/removal branches were deleted along with
the Conky feature itself). If any of these still exist on a machine that
predates `59f4260`, they are neither reported by `doctor.sh` nor covered by
any `uninstall.sh` flag today.

Currently preserved/managed paths remain correctly documented and handled:
`/etc/vpn-domain-bypass.conf`, `/etc/watchdogvpn/`, `/var/log/myvpn/`,
`/var/lib/watchdogvpn/`.

One legacy migration path already exists and works as a good precedent for
Task 18.5: `lib/runtime.sh::migrate_watchdogvpn_shared_state()` migrates
`~/.config/watchdogvpn` into `/var/lib/watchdogvpn` exactly once, guarded by a
`.migrated` marker, with permission repair afterward. This is the kind of
explicit, idempotent, marker-guarded migration the mixed-install migration
plan (Task 18.5) should generalize to the historical paths above.

**Detection contract required:** enumerate the three historical paths above;
report existence as legacy contamination; do not delete without an explicit
purge flag and confirmation, mirroring the existing `--purge-config`/
`--purge-logs`/`--purge-state` + `--confirm-delete DELETE` pattern already in
`uninstall.sh`.

### 6. PATH precedence conflicts

`install.sh`/`update.sh` install root commands to `/usr/local/bin` and the
user launcher to `~/.local/bin/VPN`, and `ensure_user_local_bin_path()`
appends `~/.local/bin` to the shell rc file if it is missing from `PATH`.

One PATH-shadow class is already detected and handled today:
`lib/runtime.sh::install_runtime_files` explicitly removes
`~/.local/bin/watchdogvpn` (a legacy TUI package path that used to shadow the
CLI command of the same name), and `doctor.sh` (line 255-257) separately warns
if that legacy directory still exists. This is a real, working precedent for
the general check below.

No current check exists for the general case: any other earlier-in-`PATH`
location providing a same-named command (`watchdog`, `watchdogvpn`,
`watchdogvpn-daemon`, `vpnctl`, `VPN`) that would shadow the one just
installed - for example a manually placed script in `~/.local/bin` ahead of
`/usr/local/bin`, or a distro package installing to `/usr/bin`.

**Detection contract required:** for each shipped command name, resolve every
`PATH` hit (`type -a <name>` or equivalent), and report any hit other than the
expected installed path as a PATH precedence conflict, in the same style as
the existing `~/.local/bin/watchdogvpn` check.

## Regression Finding

### INV-18.1-001 - Legacy AdGuard-era systemd/file cleanup was removed without replacement

- **Evidence:** `git show 59f4260 -- uninstall.sh` shows
  `remove_legacy_adguard_units()` (added in `c19394f` to disable and remove
  `adguardvpn.service`, `vpn-watchdog.service`/`.timer`,
  `vpn-rotate.service`/`.timer`, `vpn-rotate-firstboot.timer`,
  `vpn-rotate-onboot.service`) deleted outright, along with its call site in
  the uninstall flow, its `/etc/adguardvpn.env` and `/var/lib/vpn-rotate/`
  purge branches, and the `--purge-conky` cleanup of
  `~/.conky/WatchdogVPN`.
- **Impact:** a workstation that installed WatchdogVPN before the Phase 2.6
  AdGuard removal, and later runs the current `update.sh` or `uninstall.sh`,
  gets zero cleanup of any of the above. A stale, still-enabled legacy timer
  could continue to trigger a unit whose `ExecStart` target was deleted by the
  same removal, or - if the target path was since reused for something else -
  execute something unexpected.
- **Why it is not fixed in this task:** Task 18.1's own scope, as written in
  the master plan, is "document the inventory and define the exact detection
  contract before changing installer behavior." Fixing this requires editing
  `uninstall.sh` (and likely `update.sh`), which is explicitly out of scope
  here.
- **Recommendation:** restore equivalent cleanup coverage in the next task
  that touches installer code (Task 18.2 "installer entrypoint audit" or Task
  18.5 "mixed-install preflight and migration plan"), generalized as a
  data-driven historical-artifact list rather than an AdGuard-specific
  function, so future removals don't repeat the same regression. This should
  be the first concrete fix proposed when the next Phase 18 task starts.

## Live Case Study Evidence (this development workstation)

Recorded here for traceability; this is a real personal workstation, not a
clean test VM, so it corroborates the threat model but does not replace the
Task 18.6 VM smoke test from an actually-provisioned legacy-contaminated
image.

```
$ ls /usr/local/bin | grep -Ei 'vpn|watchdog'
fixvpn
no_vpn
vpn_backend
vpn_dns_rescue
vpn_dnsctl
vpn_manual_state
vpn_monitor
vpn_notify
vpn_truth_check
vpnctl
watchdog
watchdogvpn
watchdogvpn-daemon

$ systemctl list-unit-files | grep -Ei 'vpn|watchdog|myvpn'
AmneziaVPN.service        enabled   enabled
myvpn-logrotate.service   static    -
novpn-route.service       disabled  enabled
openvpn-client@.service   disabled  enabled
openvpn-server@.service   disabled  enabled
openvpn.service           enabled   enabled
openvpn@.service          disabled  enabled
vpn-domain-bypass.service disabled  enabled
watchdogvpn.service       disabled  enabled
myvpn-logrotate.timer     enabled   enabled
vpn-domain-bypass.timer   enabled   enabled
```

`AmneziaVPN.service`, `novpn-route.service`, and the `openvpn*` units are
unrelated third-party VPN software already correctly out of scope for
WatchdogVPN's uninstall contract ("must not remove user-owned provider
software"). None of the seven historical WatchdogVPN-owned unit names from
category 2 happen to be present on this particular machine, so this evidence
does not reproduce INV-18.1-001 directly - the version-skew evidence in
category 4 (`bin/watchdogvpn` diff, missing `config/backup_manager.py`) is
this workstation's concrete contribution to the inventory instead.

## Detection Contract Summary

For the next tasks to implement, a legacy-contamination/version-skew report
must, at minimum:

1. Enumerate historical WatchdogVPN command names (per category 1) separately
   from the current shipped list, per install root.
2. Enumerate historical WatchdogVPN systemd unit names (per category 2) and
   check existence/enabled/active state.
3. Treat category 3 (stale `ExecStart`) as covered by the category 2 check -
   no separate mechanism needed given current unit design.
4. Compare an installed source marker (commit hash + timestamp) against the
   running source checkout's `HEAD`, and report skew explicitly, including
   for the Python package tree, not just the shell wrappers.
5. Enumerate historical config/state/log paths (per category 5) and report
   existence without deleting unless an explicit purge flag + confirmation is
   given.
6. Resolve every shipped command name across `PATH` and report any hit other
   than the intended installed path, generalizing the existing
   `~/.local/bin/watchdogvpn` shadow check.

None of this is implemented as code in this task. This section is the
detection contract that Task 18.2/18.5/18.7 must implement against.

## Deferred To Later Tasks

- **Task 18.2** (installer entrypoint audit): restore legacy unit/file cleanup
  (INV-18.1-001); confirm no v1-only entrypoint remains in the primary path.
- **Task 18.3** (dependency installation): `lib/singbox.sh` already downloads
  the official sing-box release archive without checksum/signature pinning
  (its own `print_singbox_external_notice()` says so); this is exactly what
  Task 18.3's acceptance criteria call for.
- **Task 18.4** (shared-state permissions): re-audit after this inventory;
  `repair_watchdogvpn_shared_state_permissions()` already exists and is a
  reasonable base.
- **Task 18.5** (mixed-install preflight and migration plan): implement the
  detection contract above; generalize
  `migrate_watchdogvpn_shared_state()`'s marker-guarded pattern to the
  historical paths in category 5.
- **Task 18.6** (non-destructive update smoke): must include a real VM
  snapshot with the AdGuard-era units/files installed, to prove
  INV-18.1-001's fix actually cleans them up.
- **Task 18.7** (doctor integration): implement the version-skew check from
  category 4; rename or fix `doctor.sh`'s "Legacy Systemd Units" section,
  which currently checks two current units under a misleading legacy label.
- **Task 18.8** (installer audit closure): confirm INV-18.1-001 and all
  detection-contract items above are closed before Phase 18 audit closes.

## Acceptance

Task 18.1 closes when:

- [x] every threat-model category (18.1's six bullets) has at least one
  concrete, evidence-based inventory entry grounded in real repository history
  or a real machine, not a hypothetical;
- [x] the exact detection contract is written down for later tasks to
  implement against;
- [x] no installer/updater/uninstaller/`lib/*.sh` behavior was changed;
- [x] the real regression found (INV-18.1-001) is documented with
  reproduction evidence and an explicit reason it is deferred rather than
  silently fixed or silently ignored.
