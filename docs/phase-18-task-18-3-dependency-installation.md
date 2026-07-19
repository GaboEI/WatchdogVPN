# Phase 18 Task 18.3 - Dependency Installation

Date: 2026-07-07
Scope: install/check the four Custom VPS protocol/feature runtime
dependencies named in the master plan, with an explicit source and
checksum/signature strategy for every automated binary download.

## Objective

Install or clearly check: sing-box, AmneziaWG tooling
(`amneziawg-tools`/`awg` plus `amneziawg-dkms` or `amneziawg-go`), the Cloak client
(`ck-client`), and Python runtime dependencies. All binary downloads must use
an explicit source, a checksum/signature strategy where available, and clear
failure messages.

## Starting Gaps Found

- `lib/singbox.sh` already downloaded the official sing-box release archive,
  but with no checksum verification at all (flagged in Task 18.1).
- Nothing installed or checked AmneziaWG tooling or the Cloak client
  (`ck-client`); `drivers/amneziawg_driver.py` and
  `drivers/openvpn_cloak_driver.py` already look for these binaries at
  runtime and fail loudly with `FileNotFoundError` if missing, but nothing in
  `install.sh`/`update.sh`/`doctor.sh` ever surfaced that before a user hit it
  at connect time.
- The Python `cryptography` module (needed for Phase 17 encrypted backups)
  is only present on this development machine as a pre-existing OS package
  (`python3-cryptography`); it is not in any distro package list, so a fresh
  install would silently ship `watchdog backup --encrypt-backup` non-functional
  with no install-time signal. `config/backup_manager.py` already guards the
  import and gives a clear runtime error, so this was a missing-dependency gap
  rather than a crash bug.

## What Was Implemented

### sing-box: added checksum pinning

SagerNet does not publish a checksums/signature file for sing-box releases.
The exact pinned-version release archives
(`sing-box-1.13.14-linux-amd64-glibc.tar.gz`,
`sing-box-1.13.14-linux-arm64.tar.gz`) were downloaded directly from the
official GitHub release over HTTPS and hashed with `sha256sum` to produce
`SINGBOX_SHA256_LINUX_AMD64`/`SINGBOX_SHA256_LINUX_ARM64` in `lib/singbox.sh`.
`install_official_singbox()` now verifies the download against the matching
hash via a new shared `verify_sha256()` helper (`lib/common.sh`) before
extracting/installing, and aborts with a clear mismatch message (expected vs.
actual hash) without installing anything on failure.

### New `lib/cloak.sh`: optional Cloak client install

Mirrors the sing-box pattern: pinned version (`2.12.0`), official GitHub
release source, and maintainer-computed SHA-256 for both Linux architectures
(cbeuw/Cloak does not publish checksums either). Differs from sing-box in
one deliberate way: Cloak is only used for OpenVPN+Cloak profiles, not most
protocols, so:

- the install prompt defaults to **no**, unlike sing-box's default **yes**;
- declining does not abort the installer (sing-box is effectively required
  for Custom VPS; Cloak is not);
- under `--dry-run` it is skipped without prompting at all (prints a
  `[DRY-RUN] skip optional ...` line), so existing dry-run-based tests did
  not need new stdin input.

### New `lib/amneziawg.sh`: guided manual setup, never auto-executed

AmneziaWG has no official Ubuntu/Debian/Arch repository package, and its
kernel module must be built against the running kernel. The official install
path means adding a third-party APT repository (Ubuntu/Debian) or building an
AUR package (Arch) - both are the user's own system-trust decision to make,
not something WatchdogVPN should do silently on their behalf. The original
version of this task stopped at plain detection + links to the upstream
READMEs.

**Addendum (2026-07-07, same day):** the maintainer reviewed that and pushed
back - the product goal is that a non-technical user should never have to go
research or write their own install commands, even if they do have to type
*something* into a terminal. Pure links were not good enough UX. The fix,
implemented the same day as this task's initial closure, is a guided setup
wizard rather than either extreme (silent automation vs. a bare link):

- `amneziawg_setup_commands_ubuntu/debian/arch()` return the exact, official,
  copy-pasteable command sequence for the detected distro (sourced from the
  upstream `amneziawg-linux-kernel-module` README for Ubuntu/Debian, and the
  real AUR packages `amneziawg-dkms`/`amneziawg-tools` for Arch, both
  verified to exist before being hardcoded here).
- `guide_amneziawg_setup()` (replacing the old `check_amneziawg_dependency()`
  call site in `install.sh`, though `check_amneziawg_dependency()` itself is
  kept for `doctor.sh`'s read-only reporting): if not detected, asks the user
  (default no) whether to walk through setup now; if yes, prints the
  commands, waits for the user to run them in their own terminal
  (`read -r -p`), then re-checks and reports success or exactly what is still
  missing (userspace tools vs. kernel module vs. both, including a reboot
  hint), repeating up to 3 attempts before telling the user to fix the
  remaining issue and re-check later with `./doctor.sh`.
- WatchdogVPN's own code never runs `add-apt-repository`, `apt-get install`,
  `git clone` or `makepkg` here - those strings only ever appear inside a
  `cat <<'EOF' ... EOF` block that gets printed for the user to read and run
  themselves. This is what keeps the "no unreviewed third-party trust
  decision made on the user's behalf" property intact while still meeting
  the "no research and no guessing your own commands" product requirement.
- Skips without prompting under `--dry-run`, matching the Cloak pattern, so
  no existing dry-run test needed new stdin input.

This fulfills the task's "install **or clearly check**" wording via a middle
path: WatchdogVPN does the research and the validation; the user keeps
control of the one step (adding third-party trust to their own package
manager) that shouldn't happen without them seeing it happen.

### Python `cryptography`: distro package + best-effort install

Added `DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE` to all three distro adapters
(`python3-cryptography` for Ubuntu/Debian, `python-cryptography` for Arch -
verified to exist in Arch's `extra` repo before use). Added
`python_cryptography_available()` and `validate_python_runtime_dependencies()`
to `lib/packages.sh`: checks `python3 -c 'import cryptography'`, and if
missing, attempts `install_package_set` with the distro package, then
re-checks and warns (never fails) if still unavailable. Deliberately **not**
added to `DISTRO_BASE_PACKAGES`, since that array only gets installed as a
side effect of some other required *command* being missing - it would not
reliably trigger on a machine where `python3` itself is already present but
the module is not.

### Wiring

- `install.sh`: sources the two new libs; added
  `validate_protocol_runtime_dependencies()` (calls
  `validate_python_runtime_dependencies` + `guide_amneziawg_setup`), run in
  the "Prerequisites" section right after `validate_required_commands`;
  added `install_official_cloak` right after `install_official_singbox` in
  the Custom VPS branch.
- `update.sh`: added a "Runtime dependencies" section calling
  `validate_python_runtime_dependencies`, `install_official_singbox`,
  `install_official_cloak` and `guide_amneziawg_setup` - full parity with
  `install.sh`. **Addendum (2026-07-07, same day):** the initial version of
  this task only wired the Python cryptography backfill into `update.sh` and
  deliberately left sing-box/Cloak/AmneziaWG out, reasoning that "an
  interactive prompt during a routine update would be surprising." The
  maintainer rejected that as giving a returning user a worse experience
  than a fresh install just because they used `update.sh` instead of
  reinstalling - which is the common case for real usage, not the exception.
  All four checks now run identically in both scripts; each one already
  short-circuits to a silent `[KEEP]`/`[OK]` line when the dependency is
  already present (the overwhelming majority of real updates), so there is
  no new friction for users who already have everything installed.
- `doctor.sh`: sources the same libs and adds a "Protocol Runtime
  Dependencies" section using only the pure detection functions
  (`singbox_available`, `cloak_available`, `amneziawg_userspace_available`,
  `python_cryptography_available`) - never the installer functions, keeping
  `doctor.sh`'s "must not install, remove or modify files" contract intact.
  sing-box/AmneziaWG missing report as `WARN` (they affect most protocols);
  Cloak missing reports as `info` (niche, opt-in feature).

### Docs

`docs/install-contracts.md` gained a "Dependency Contract" section and three
new entries in the "`install.sh` may ask" list (sing-box, Cloak, and the
AmneziaWG guided-setup prompts).

## Deliberately Not Done

- WatchdogVPN's own code never executes `add-apt-repository`, `apt-get
  install amneziawg`, `git clone`/`makepkg`, or any package-manager mutation
  for AmneziaWG - the guided wizard only prints these commands for the user
  to run themselves, and re-checks afterward. This boundary is enforced by
  the test suite (see below), not just by convention.
- `cryptography` was not added to `DISTRO_BASE_PACKAGES` (see rationale
  above).
- PATH-conflict detection and the broader doctor-integration scope (systemd
  unit status, capability reporting, legacy-wrapper detection) remain Task
  18.7's job, unrelated to this task's dependency-installation scope.
  Installed/source version-skew detection itself was **not** left for Task
  18.7 - it shipped the same day, see
  `docs/phase-18-task-18-2-installer-entrypoint-audit.md`'s addendum.

## Tests

New `tests/unit/test_protocol_dependencies.sh` (registered in
`tests/unit.sh`), covering:

- both pinned checksum constants exist and are well-formed 64-character hex
  SHA-256 values, for both sing-box and Cloak;
- the shared `verify_sha256()` helper actually accepts a matching hash and
  rejects a mismatched one (executed against a real temp file, not just
  asserted as a string);
- the sing-box notice no longer claims checksums are unpinned;
- Cloak's install function skips prompting under `--dry-run`;
- the AmneziaWG lib defines the guided setup wizard and per-distro command
  generators, and contains no `run_step sudo apt`, `run_step sudo pacman`,
  `run_step git clone` or `run_step makepkg` (i.e., the setup commands can
  only ever be printed, never executed, by WatchdogVPN's own code);
- the guided wizard, exercised end to end with stubbed detection functions
  (not mocked assertions): prints copy-pasteable commands, honors a "skip"
  answer without looping forever, and skips without prompting under
  `--dry-run`;
- all three distro adapters define `DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE` with
  the correct package name;
- `install.sh` calls the new validators in the right order relative to the
  existing required-commands/sing-box checks;
- `update.sh` calls the Python dependency backfill **and** (addendum)
  `install_official_singbox`, `install_official_cloak` and
  `guide_amneziawg_setup`, and sources all three of `lib/singbox.sh`,
  `lib/cloak.sh` and `lib/amneziawg.sh` - full parity with `install.sh`, not
  a weaker subset;
- `doctor.sh` reports all four dependencies' state but never calls an
  installer function.

Manually exercised the guided wizard's three outcomes (user skips; user runs
the commands but detection still fails after 3 attempts; user runs the
commands and detection succeeds) with stubbed `amneziawg_userspace_available`/
`amneziawg_kernel_module_available` functions, since this development machine
already has AmneziaWG-compatible tooling installed and could not otherwise
exercise the "still missing" branches.

## Validation

- `bash tests/unit/test_protocol_dependencies.sh` passed.
- `bash tests/unit/test_install_backend_selection.sh` passed unchanged - the
  new dependency checks do not consume any stdin, so the existing
  fixed-answer-sequence dry-run test needed no changes.
- `bash tests/unit.sh` passed (17 shell test files, including the new one).

## Phase 23.5 superscriptive correction — reproducible dependency provenance (2026-07-19)

This section supersedes the earlier optional/best-effort conclusions for
Cloak and Python `cryptography`, and closes a broader contract gap discovered
during installed Arch/CachyOS certification. The historical text above is
retained as an audit trail; it is no longer the current product contract where
it conflicts with this section.

### Field finding and root cause

The certification machines could exercise the complete runtime only after
components already present in the image or installed during diagnosis filled
gaps in WatchdogVPN's declared package set. In particular, `nft`, `ping` and
`pgrep` were used by mandatory kill-switch, AmneziaWG handshake and process
recovery paths, yet their owning packages were not guaranteed by every
installer/updater adapter. A final green on such a machine therefore proved
the assembled developer environment, not a reproducible user installation.
The follow-up inventory expanded this beyond those three symptoms to the
security/runtime commands and owning packages used for SSH-path inspection,
policy routing, module detection, firewall fallback/cleanup, NetworkManager,
user creation and transactional file installation.

### Superseding universal contract

- Every real `install.sh` and `update.sh` run reconciles the adapter's complete
  runtime package set, even when a subset of commands is already visible.
- After package installation, every mandatory executable is rechecked and the
  operation fails closed if any remains unavailable. This includes the atomic
  nftables backend, legacy iptables cleanup tooling, OpenVPN, `ping`, process
  recovery, NetworkManager, Polkit, notifications and supporting utilities.
- Python `cryptography` is required shipped functionality, not a best-effort
  enhancement. Its distro package is installed, the import is rechecked, and
  install/update fails if it is still unavailable.
- Cloak is mandatory for the supported resilient OpenVPN+Cloak protocol. A
  declined, unsupported or unverifiable `ck-client` installation aborts the
  install/update instead of publishing a knowingly partial runtime. sing-box
  and Cloak are provisioned on every installation independently of the legacy
  `custom_vps` backend toggle; a later profile import must already have them.
- `doctor.sh` reports missing `nft`, Cloak or `cryptography` as failures; it
  remains read-only.
- AmneziaWG remains the sole protocol-runtime exception: its third-party
  repository/AUR trust step is guided and explicitly user-executed, with
  WatchdogVPN rechecking the resulting runtime. That exception does not extend
  to any other dependency.
- Ubuntu, Debian and Arch adapters carry the complete contract. A Fedora/Red
  Hat-family `dnf`/package adapter is laid down for Phase 23.6, but its presence
  is not a support claim; SELinux, firewalld, lifecycle and installed
  certification remain required before those systems can be accepted.

The bootstrap boundary is deliberately narrow: a supported systemd-based
Linux with Bash, its package manager, network access and usable root/sudo
authority must exist before the installer can provision anything. Installer
startup reads `/proc/1/comm` without depending on `ps`, so a missing `procps`
package cannot prevent the package reconciliation that repairs it.

### Permanent certification closing gate

Every distro certification must record a pre-install command/package inventory
and answer, with installed evidence: did the result work because WatchdogVPN's
installer/updater provisioned all required components, or because the test
environment already contained external components? An unexplained pre-existing
dependency invalidates the green. Closure requires a clean or deliberately
dependency-depleted VM, installer provisioning proof, updater repair proof,
`doctor.sh` with no dependency failures, regression suites, and installed
runtime revalidation. This gate applies to every future distro and survives
task, chat and maintainer handoffs.
- `bash tests/syntax.sh` passed.
- `python3 -m unittest discover -s tests -p 'test_*.py'` passed: 1026 tests
  (unaffected - this task only touched shell scripts and docs).
- `git diff --check` passed.
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`
  passed.
- Manually ran `./doctor.sh` and a real `install.sh --dry-run --yes
  --skip-doctor` on this development machine: the new "Protocol Runtime
  Dependencies" section correctly reported already-installed sing-box,
  Cloak client and `cryptography`, and AmneziaWG-compatible tooling, using
  real machine state (not mocked).
- Addendum: manually ran a real `update.sh --dry-run --yes --skip-doctor` end
  to end and confirmed the "Runtime dependencies" section now reports the
  same four checks as `install.sh` (`[OK] python cryptography module
  available`, `[KEEP] sing-box detected: ...`, `[KEEP] Cloak client detected:
  ...`, plus the Phase 18 AmneziaWG-compatible tooling line), not just the
  cryptography backfill. That Phase 18 wording is superseded by the Phase 23
  field-validation addendum below.
- Phase 23 field-validation addendum: real AmneziaWG `vpn://` exports require
  AmneziaWG-specific `awg` tooling plus either the `amneziawg` kernel module
  or the official `amneziawg-go` userspace fallback. The daemon uses `ip` and
  `awg` directly instead of sudo-driven quick scripts. Plain WireGuard
  `wg-quick`/`wg` is no longer treated as a valid AmneziaWG runtime fallback;
  standard WireGuard remains a separate compatibility protocol.
- Checksums were computed by downloading the exact pinned-version release
  assets directly from the official GitHub releases over HTTPS and hashing
  them locally, then re-verified byte-for-byte against the values written
  into the scripts before commit.
- No VM was used to test the "dependency actually missing" branches end to
  end (this development machine already has all four dependencies
  installed); the isolated function-level checks above substitute for that
  where feasible, but end-to-end proof on a clean machine remains part of
  Task 18.6's VM smoke test scope.

## Acceptance

Task 18.3 closes when:

- [x] sing-box, AmneziaWG tooling, Cloak client and Python runtime
  dependencies are each installed or clearly checked;
- [x] every automated binary download (sing-box, Cloak) uses an explicit
  official source and a checksum strategy, with a clear abort-before-install
  failure message on mismatch;
- [x] the one dependency where fully unattended install would be
  irresponsible (AmneziaWG) gets a guided, user-executed setup wizard instead
  - exact commands, validated re-checks, no research required from the user
  - without WatchdogVPN itself ever adding a third-party trust root or
  building anything on the user's behalf;
- [x] `doctor.sh` reports all four dependencies without violating its
  read-only contract;
- [x] full local validation (shell + Python test suites, syntax, compileall,
  whitespace) passes;
- [x] a clean-machine VM proof of the "missing dependency" install paths
  remains explicitly owed to Task 18.6, not claimed as done here.

## Phase 23.5 addendum — import-scoped AmneziaWG guidance (2026-07-17)

The generic guided wizard described above was removed from `install.sh` and
`update.sh`. It gave every user a long AmneziaWG prompt even when no
AmneziaWG profile had been imported, which was both misleading and noisy.

The product now checks this optional runtime only after an AmneziaWG profile
is imported through `watchdog profile add`, setup, or a subscription provider
refresh. If `awg` plus either the kernel module or `amneziawg-go` is absent,
the import still succeeds and the CLI returns a redacted dependency object
and human-readable steps. The commands are printed, never executed by
WatchdogVPN; unsupported or unverified distributions receive official source
links instead of guessed package-manager commands. `doctor.sh` keeps the
same read-only availability check.

## Final superscriptive status — dependency and kernel provenance (2026-07-19)

The 2026-07-19 superscriptive correction above is the current authority over
all earlier validation and acceptance text in this file. In particular, the
clean-machine missing-dependency proof is a mandatory certification gate, not
work that can be waived or indefinitely delegated to an older task; Cloak and
Python `cryptography` are fail-closed requirements; and AmneziaWG is the sole
guided, user-executed protocol-runtime trust exception.

Kernel provenance is part of the same rule. Arch AmneziaWG guidance derives
the active kernel package base from `/usr/lib/modules/$(uname -r)/pkgbase` and
requests matching headers instead of hardcoding `linux-headers`, with
`amneziawg-go` as the userspace fallback. `doctor.sh` fails when
`/dev/net/tun` is unavailable, as do install/update dependency validation. A
broad Arch-family compatibility statement
requires installed TUN, nftables, routing, cleanup and real-egress evidence on
the distribution-default kernel plus a representative packaged alternate/LTS
kernel; a single VM kernel is never silently generalized to the distribution.
