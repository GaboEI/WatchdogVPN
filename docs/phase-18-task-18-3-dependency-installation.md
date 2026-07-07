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

### New `lib/amneziawg.sh`: detection and guidance only, no auto-install

AmneziaWG has no official Ubuntu/Debian/Arch repository package, and its
kernel module must be built against the running kernel. Automating its
install would mean either adding a third-party APT/AUR trust root or
building from source unattended - both are a bigger trust decision than a
plain release-binary download, so this task deliberately does **not**
automate it. `check_amneziawg_dependency()` only detects
`awg-quick`/`amneziawg-quick` (or `wg-quick` as a compatible fallback,
matching `drivers/amneziawg_driver.py`'s own tolerance) plus the kernel
module, and prints the verified upstream source links
(`amnezia-vpn/amneziawg-tools`, `amnezia-vpn/amneziawg-linux-kernel-module`)
if not found. This fulfills the task's "install **or clearly check**"
wording via the "clearly check" branch, for the one dependency where
automated install would be irresponsible to run unattended.

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
  `validate_python_runtime_dependencies` + `check_amneziawg_dependency`),
  run in the "Prerequisites" section right after `validate_required_commands`;
  added `install_official_cloak` right after `install_official_singbox` in
  the Custom VPS branch.
- `update.sh`: added a "Runtime dependencies" section calling
  `validate_python_runtime_dependencies` as a non-interactive backfill for
  machines that installed before this task. Deliberately did not wire
  sing-box/Cloak/AmneziaWG into `update.sh` - re-prompting for an optional
  binary install on every update would violate `docs/install-contracts.md`'s
  "installer should not ask internal technical questions" spirit for a
  routine update; a user who wants Cloak installed after the fact can rerun
  `install.sh` or install manually.
- `doctor.sh`: sources the same libs and adds a "Protocol Runtime
  Dependencies" section using only the pure detection functions
  (`singbox_available`, `cloak_available`, `amneziawg_userspace_available`,
  `python_cryptography_available`) - never the installer functions, keeping
  `doctor.sh`'s "must not install, remove or modify files" contract intact.
  sing-box/AmneziaWG missing report as `WARN` (they affect most protocols);
  Cloak missing reports as `info` (niche, opt-in feature).

### Docs

`docs/install-contracts.md` gained a "Dependency Contract" section and two
new entries in the "`install.sh` may ask" list (sing-box and Cloak install
prompts).

## Deliberately Not Done

- No third-party APT repository or PPA was added for AmneziaWG.
- No source build was attempted for AmneziaWG.
- `cryptography` was not added to `DISTRO_BASE_PACKAGES` (see rationale
  above).
- `update.sh` does not offer to install sing-box/Cloak/AmneziaWG.
- Version-skew detection, PATH-conflict detection and the broader
  installed/source marker mechanism remain Task 18.7's job, unrelated to this
  task's dependency-installation scope.

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
- the AmneziaWG lib defines both detection functions and contains no
  `sudo apt`, `add-apt-repository` or `curl` (i.e., cannot silently start
  installing or downloading anything);
- all three distro adapters define `DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE` with
  the correct package name;
- `install.sh` calls the new validators in the right order relative to the
  existing required-commands/sing-box checks;
- `update.sh` calls the Python dependency backfill;
- `doctor.sh` reports all four dependencies' state but never calls an
  installer function.

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
- [x] the one dependency where automated install would be irresponsible
  (AmneziaWG) is honestly limited to detection + accurate guidance, not
  silently skipped or falsely claimed as automated;
- [x] `doctor.sh` reports all four dependencies without violating its
  read-only contract;
- [x] full local validation (shell + Python test suites, syntax, compileall,
  whitespace) passes;
- [x] a clean-machine VM proof of the "missing dependency" install paths
  remains explicitly owed to Task 18.6, not claimed as done here.
