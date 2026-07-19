# Installation Contracts

This document defines how the product scripts should behave.

## Principles

- One repository supports Ubuntu, Debian and Arch Linux.
- Fedora/Red Hat-family package and `dnf` foundations exist, but support
  remains future scope until SELinux/firewalld and installed certification
  close.
- Runtime behavior should be shared across distros.
- Distro differences belong in `distros/` and installer helpers.
- The installer should not ask internal technical questions.
- Existing user configuration must not be overwritten without backup.
- The installer configures WatchdogVPN's own runtime and does not depend on a
  third-party commercial VPN CLI.

## User-Facing Questions

`install.sh` may ask:

- Configure the Custom VPS backend metadata when needed.
- Download and install the official sing-box binary now? (only if not already
  detected; required for most Custom VPS protocols)
- Download and install the official Cloak client (`ck-client`) now? (only if
  not already detected; defaults to yes and declining aborts publication,
  since it is required for the supported OpenVPN+Cloak protocol)

`install.sh` should not ask:

- initial rotation interval
- initial watchdog interval
- whether log housekeeping is enabled
- whether base domain bypass support is prepared
- internal install paths
- Custom VPS passwords, private keys, tokens or certificate pins

Those are product defaults and can be adjusted later from the TUI.

A non-interactive or blank Custom VPS setup retains the example default
`custom_vps.enabled = false`. Only a syntactically valid local `*.service`
selection enables that compatibility backend; the installer never publishes
it as enabled with missing control metadata. The final `vpnctl status`
recommendation remains usable and reports daemon-first truth when the optional
service is absent, while connect/restart operations still validate and fail
closed.

## doctor.sh

Role: read-only preflight and diagnostics.

It must not install, remove or modify files.
It must not change system time or NTP settings; wrong time is reported as a
protocol-connectivity risk with actionable guidance.
Its capture-mode diagnostic uses a lock-free read of the atomically published
state snapshot; a missing state file returns defaults without creating the
legacy config directory, lock files or restore journals.

It should check:

- Linux with systemd
- supported distro
- NetworkManager
- sudo
- bash
- python3
- curl
- iproute2
- awk/sed/coreutils
- logrotate
- WatchdogVPN daemon user, unit, IPC socket and installed runtime
- system time/NTP sync state and severe clock skew risk
- basic DNS
- previous installation state
- sing-box, AmneziaWG tooling, Cloak client and the Python `cryptography`
  module (protocol/feature runtime dependencies; see "Dependency Contract"
  below)
- installed-vs-source-checkout version skew (see "Dependency Contract"
  below)

Result levels:

- `OK`: does not block
- `WARN`: installation can continue, but the user should know
- `FAIL`: installation should stop

## Dependency Contract

Protocol/feature runtime dependencies (Phase 18 Task 18.3):

- **Distribution runtime set**: every real `install.sh` and `update.sh` run
  reconciles the complete adapter-owned package set even when the current
  machine already happens to expose all commonly checked commands. The set
  includes OpenVPN, NetworkManager, Polkit, nftables plus the legacy iptables
  cleanup tools, `iproute2`, `ping`, process recovery tools, notifications and
  the installer/user-management base utilities. The explicit adapters also
  own `ss`, `sysctl`, `modinfo`, CA trust and the standard text/file tools used
  by installation and recovery. `git` is provisioned so a checkout-based
  install/update can publish and later compare its exact source commit instead
  of silently recording `unknown`. After the package manager returns, WatchdogVPN
  re-checks every mandatory executable and aborts if any remain unavailable.
  `nft` is a hard security dependency: a successful installation may not rely
  on a firewall backend inherited from a developer or certification image.

- **sing-box**: required by most Custom VPS protocols. `install.sh` downloads
  the official release archive for the pinned version if not already
  detected, verifies it against a maintainer-computed SHA-256 (SagerNet does
  not publish release checksums), and refuses to install on mismatch. This is
  provisioned for every installation, not gated by the legacy `custom_vps`
  backend toggle, because supported profiles can be imported later.
- **Cloak client (`ck-client`)**: only needed for OpenVPN+Cloak profiles.
  `install.sh` offers to download and checksum-verify it the same way as
  sing-box and defaults to yes. A declined, unsupported or unverifiable Cloak
  dependency aborts install/update instead of publishing a runtime where a
  supported resilient protocol is known not to work. `--dry-run` reports the
  exact download/install plan without prompting. It is likewise provisioned
  on every installation rather than waiting for a profile to fail.
- **AmneziaWG tooling (`amneziawg-tools`/`awg`, plus `amneziawg-dkms` or
  `amneziawg-go`)**:
  never installed unattended by WatchdogVPN itself - the official install
  path adds a third-party APT repository (Ubuntu/Debian) or builds an AUR
  package (Arch), which WatchdogVPN treats as the user's own trust decision
  to make knowingly, not something to do silently on their behalf. A blank
  install or routine update does not show an AmneziaWG prompt. Instead, after
  an AmneziaWG profile is imported with `watchdog profile add`,
  `watchdog setup --profile-file`, or a provider update, the
  CLI checks the runtime and, if it is missing, prints prevalidated,
  distro-specific commands where available plus the official source links.
  The commands live in the selected `distros/` adapter, so adding a future
  distribution does not require a second detector or a CLI change.
  `doctor.sh` only reports read-only detection state (`WARN` if missing).
  A valid runtime has
  AmneziaWG-specific `awg` tooling plus either the `amneziawg` kernel module or
  the `amneziawg-go` userspace fallback used directly by the native driver.
  Standard
  WireGuard tooling (`wg-quick`/`wg`, `wireguard` kernel module) is not a
  substitute for AmneziaWG-specific profiles; plain WireGuard remains its own
  compatibility protocol.
- **Python `cryptography` module**: needed for encrypted backups
  (`watchdog backup --encrypt-backup`, Phase 17). `install.sh` and
  `update.sh` install the distro package (`python3-cryptography` on
  Ubuntu/Debian, `python-cryptography` on Arch) if missing and then re-check
  the import. Installation fails closed if the module remains unavailable;
  shipping a known-disabled security feature is not a certified install.

All automated binary downloads must use an explicit official source URL, a
checksum/signature strategy where the upstream project provides one (or a
maintainer-computed checksum pinned to the exact version otherwise), and a
clear failure message that aborts before installing anything on mismatch.

`install.sh` and `update.sh` run identical dependency checks. A returning
user who runs `update.sh` instead of reinstalling from scratch must not get a
weaker experience than a fresh install.

### Certification dependency-provenance gate

This is a permanent gate for every distro task and survives chat/session
changes. Immediately before closure, answer with evidence: did the installed
candidate work because WatchdogVPN provisioned every mandatory dependency, or
because a developer/test image already contained extra components? Record the
pre-install command/package baseline and the post-install provenance. A green
that depends on an unexplained pre-existing component is invalid and the task
remains open until that dependency is installed by both `install.sh` and
`update.sh`, validated by `doctor.sh`, regression-tested for every supported
adapter, and revalidated installed. The only protocol-runtime exception is
AmneziaWG, whose third-party trust decision remains explicit guided setup with
distro-owned commands and post-setup detection. Bootstrap requirements that
must exist before any installer can execute (a supported systemd Linux,
`bash`, package manager, network access and usable root/sudo authority) are
preconditions, not hidden runtime dependencies.

### Kernel portability contract

Distribution support is capability-based, not pinned to the exact kernel
release used by one VM. WatchdogVPN does not require a particular kernel
version, but the running kernel must provide `/dev/net/tun`, nftables hooks,
policy routing and the systemd security/capability behavior exercised by the
installed daemon. Install, update and `doctor.sh` fail when the TUN device is
absent; installed
certification must additionally prove real TUN creation, nftables application,
routing, cleanup and egress rather than infer them from the distro name.

For Arch-family AmneziaWG setup, the guided command derives the active kernel
package base from `/usr/lib/modules/$(uname -r)/pkgbase` and installs the
matching `<pkgbase>-headers`; it must not assume `linux-headers`. This covers
packaged default, LTS and alternate kernel families when their matching header
package exists. `amneziawg-go` remains the userspace fallback when a compatible
native module cannot be built or loaded.

A broad Arch-family compatibility statement requires installed evidence on
the current distribution-default kernel plus a representative alternate/LTS
kernel. Evidence on one kernel certifies only that observed kernel. Arbitrary
custom kernels that remove required Linux capabilities are not silently
claimed as supported, and a hardened/alternate kernel failure is a field
finding until attributed and formally scoped.

**Installed/source version marker:** `install.sh`/`update.sh` record the
installed source commit and timestamp (`lib/version_marker.sh`) every time
the Python runtime package tree is (re)installed. `doctor.sh` compares that
marker against `git rev-parse HEAD` of the checkout it is run from and warns if
they differ. The marker certifies files on disk, not already-imported Python
modules in a long-running daemon. Therefore `update.sh` also snapshots whether
`watchdogvpn.service` was active before replacement, restarts that active
service after installation, and requires a different nonzero systemd `MainPID`
before the IPC smoke test. A hibernating daemon remains stopped. Together these
checks answer both "does the installed tree match this checkout?" and "is the
daemon actually executing the refreshed tree?" instead of trusting only the
hand-edited `VERSION` string in `bin/watchdogvpn`.

On a first install, adding the invoking user to the `watchdogvpn` group updates
NSS but cannot alter the supplementary groups of the installer process that is
already running. The final read-only IPC smoke test therefore drops back to the
invoking user's UID/GID with `setpriv --init-groups` and verifies `watchdog
status --json` using the freshly loaded group vector and that user's real
`HOME`, `USER` and `LOGNAME`; sudo's root identity environment is not allowed to
leak into the unprivileged probe. Permission errors remain hard failures; an
active systemd unit and an existing socket are not accepted as proof when the
CLI cannot complete the IPC request. The CLI's own socket preflight uses
`stat(2)` semantics so an inaccessible socket directory is reported as a
permission problem, never as a falsely absent daemon.

## Domain Bypass Network Contract

Full rationale and incident background in `docs/security.md`'s "Domain
Bypass Network Safety". Summary of the contract:

- `vpn-domain-bypass.timer` is only auto-enabled by `install.sh`/`update.sh`
  when `/etc/vpn-domain-bypass.conf` has real configured domains. A fresh
  install with the default empty config never enables it.
- `install.sh`/`update.sh` never touch the timer at all if it is already
  active, since even an idempotent `systemctl enable --now` resets its
  schedule and forces an unplanned re-application of routing rules.
- If the user manually disabled the timer after a routing conflict,
  `install.sh`/`update.sh` will not silently re-enable it later just because
  domains are still configured (`/etc/watchdogvpn/.domain-bypass-disabled`
  marker, written by `vpn_domain_bypass_rescue`, cleared automatically once
  the user re-enables the timer themselves).
- `uninstall.sh` always runs `vpn_domain_bypass_rescue` (regardless of purge
  flags) before removing product files, since disabling the timer alone does
  not undo ip rules it already applied.
- `vpn_domain_bypass_rescue auto` is the official manual recovery command if
  another VPN/proxy client on the same machine cannot set its own routes.

## install.sh

Role: install a new system or complete a partial installation.

Expected flow:

1. Run read-only doctor and mixed-install preflight checks.
2. Explain that the product installs the WatchdogVPN runtime and can configure
   the custom-vps service-control path.
3. Detect distro and load its adapter.
4. Validate dependencies.
5. Ask product-level options.
6. Show an installation plan with target paths, options and backup location.
7. Back up files that would be replaced.
8. Validate scripts and TUI.
9. Install runtime files.
10. Validate systemd and logrotate.
11. Enable services and timers.
12. Run final checks.
13. Tell the user to open `VPN`.

## update.sh

Role: update an existing installation without reinstalling from zero.

It must preserve:

- `/etc/vpn-domain-bypass.conf`
- `/var/lib/watchdogvpn/`
- logs

It should replace only product-managed runtime files after validation and backup.
It should show a preservation contract and update plan before replacing files.

Before dependency checks or replacement, `install.sh` and `update.sh` run the
shared mixed-install preflight from `lib/install_preflight.sh`. It classifies
the machine as `fresh install`, `clean update`, `legacy migration`,
`mixed-inconsistent` or `unsupported`; prints the exact runtime files,
systemd units, wrappers and state paths that will be replaced, preserved,
removed or reported; and refuses mixed/unsupported states before mutation.
Known-dead WatchdogVPN-owned legacy artifacts are the only automatic repair
path, and user data is preserved by default. Existing product config that names
an unsupported backend is also blocked rather than preserved silently.

It runs the same dependency checks as `install.sh` (sing-box, Cloak and
Python `cryptography`) and, on every run, sweeps
orphaned pre-Phase-2.6 (AdGuard-era) systemd units and scripts if a
legacy-contaminated machine still has them - not only on a full uninstall.
It also records the installed-vs-source version marker used by
`doctor.sh`'s version-skew check (see "Dependency Contract" above). If the
daemon was active when the update began, it must be restarted after the new
files and units are installed; the updater rejects an unchanged, missing or
zero `MainPID` before running the final IPC smoke test. If the daemon was
inactive, the normal hibernate-aware enable path decides whether it should be
started, so an explicit panic/sleep state is never undone by an update.

## uninstall.sh

Role: remove WatchdogVPN without deleting user-owned VPN/proxy software or
account state.

It should remove:

- product scripts
- TUI
- product systemd units
- product NetworkManager dispatcher
- product logrotate config
- the exclusive ephemeral runtime directory `/run/watchdogvpn/`; an empty
  `/run/amneziawg/` created for the daemon is also removed, while a non-empty
  or symlinked shared AmneziaWG path is preserved
- a desktop launcher file left by a pre-removal install, if present (the
  desktop launcher feature itself was removed; `install.sh`/`update.sh` no
  longer offer or refresh it, but `uninstall.sh` still cleans up a leftover
  one)
- orphaned pre-Phase-2.6 (AdGuard-era) systemd units and scripts, if a
  legacy-contaminated machine still has them (see
  `docs/phase-18-task-18-1-legacy-contamination-inventory.md`)

It must ask before deleting:

- `/etc/vpn-domain-bypass.conf`
- `/var/log/myvpn/`
- `/var/lib/watchdogvpn/`
- `/etc/adguardvpn.env`, `/var/lib/vpn-rotate/`, `~/.conky/WatchdogVPN/`
  (legacy, gated by the same `--purge-config`/`--purge-state` flags as their
  current equivalents)

Data deletion requires the literal confirmation `DELETE`. The Python
`watchdog uninstall --delete-all-data` flow also exports a pre-delete backup
outside WatchdogVPN-owned paths before passing purge flags to `uninstall.sh`.
That full purge removes the fixed internal recovery root
`/var/backups/watchdogvpn` and suppresses new internal backups during removal;
only the user's explicit outside export survives. An overrideable custom
`BACKUP_ROOT` is never used as a recursive deletion target.

The migration source `~/.config/watchdogvpn/` remains preserved during
install, update and ordinary uninstall. The same confirmed full purge removes
that legacy source for the invoking user and the fixed historical root copy at
`/root/.config/watchdogvpn/`; when the script itself was invoked via sudo, the
invoking user's NSS home is handled as well. It does not enumerate or delete
other users' homes. The explicit CLI export is created from the already
migrated shared state before these duplicate sources are removed.
Root-managed paths are existence-checked through the shared privileged helper;
an inaccessible parent such as `/root` must not be interpreted as an absent
child and silently skip backup or removal. Dry runs use only non-interactive
cached sudo for this additional read-only check.

It must not remove:

- user-owned provider software, profiles, private keys or account state
- unrelated user files

It should show a removal plan before disabling units or removing files.
