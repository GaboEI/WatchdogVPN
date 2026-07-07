# Phase 18 Task 18.3 - Dependency Installation

Date: 2026-07-07
Scope: install/check the four Custom VPS protocol/feature runtime
dependencies named in the master plan, with an explicit source and
checksum/signature strategy for every automated binary download.

## Objective

Install or clearly check: sing-box, AmneziaWG tooling
(`amneziawg-dkms`/`amneziawg-tools`/`awg-quick`), the Cloak client
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
  ...`, `[OK] AmneziaWG (or compatible WireGuard) tooling detected`), not
  just the cryptography backfill.
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
