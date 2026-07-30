# Phase 23.7.5.8 — L1 Coverage Audit & Closure Report

**Status:** L1 coverage implementation complete; pending final auditor approval.  
**Branch:** `phase-23-7-5-compatibility-contract`  
**Implementation commit:** `fc9f1ced310b922f1ab424ed55bb5ebf33490e12`  
**Base commit:** `e62daadecbfd6ddad5027eed4a7108cbc883e1d4` (Task 23.7.5.7 approved)

---

## 1. Exact objective of Task 23.7.5.8

Audit the L1 test coverage of Phase 23.7.5 tasks **23.7.5.1 through 23.7.5.7**, close any *mandatory* L1 gaps that can be closed without real mutation or expansion of scope, document honest non-blocking debt, and produce an auditable record that the phase’s contract code is covered by fast, deterministic, locally-runnable tests.

This task does **not** add new product features, change the manifest, change detection/provisioning semantics, or perform L2/L3/VM certification. It is a controlled coverage closure gate before the phase can proceed to 23.7.5.9.

---

## 2. Operational definition of “L1 coverage complete”

For 23.7.5.8, L1 coverage is complete when:

1. Every closed task in 23.7.5.1–23.7.5.7 has at least one representative L1 test still passing in the repo.
2. Every behavioral contract explicitly added by Task 23.7.5.7 (shell↔engine contract, fallback semantics, exit-code contract, doctor/installer message wiring) has dedicated L1 coverage.
3. Task 23.7.5.6a has explicit L1 coverage for the cross-operation lock between `prepare()` and `uninstall()`.
4. All L1 tests run without network, without package installation, without mutating the host, and without touching VPN/DNS/firewall/interfaces.
5. No test is added solely to inflate counts; every new test maps to a real requirement or a real gap discovered during the audit.
6. Shell tests added in this task use real copies, never symlinks, when building isolated doctor trees.

---

## 3. Exact scope

- Review existing L1 tests for 23.7.5.1–23.7.5.7.
- Add L1 tests that close mandatory gaps found during the audit:
  - exit-code contract of `tools/compat_distro_classify.py`;
  - multi-family pure-Bash fallback without support classification;
  - engine-failure degradation modes (invalid JSON, non-zero exit, timeout);
  - `lib/common.sh` state-message helpers for `DISTRO_*` flags;
  - `doctor.sh` read-only reaction to `DISTRO_FUTURE`/`DISTRO_UNSUPPORTED`/`DISTRO_UNDETERMINED`;
  - `prepare()` vs `uninstall()` lock contention in the transactional provisioner.
- Stabilize `tools/compat_distro_classify.py` so that usage errors return exit code `1` and detection/manifest errors return exit code `2`.
- Write this report and update `docs/phase-23-7-5-compatibility-contract.md` with the closure of 23.7.5.8.

---

## 4. Explicit out-of-scope

- No changes to `compat/compatibility.json`, `compat/compatibility.schema.json`, `compat/detection.py`, `compat/dependency_resolution.py`, `compat/support_model.py`, `lib/packages.sh`, or `distros/*.sh`.
- No reopening of 23.7.5.1–23.7.5.7.
- No L2/L3/VM validation inside 23.7.5.8.
- No changes to runtime/network/VPN/DNS/firewall/interfaces or public CLI.
- No start of 23.7.5.9 or later tasks.
- No modification of the transactional provisioner’s domain logic beyond the added L1 test.

---

## 5. Inventory of audited surfaces / phases

| Task | Surface audited | Primary L1 test file(s) |
|------|----------------|--------------------------|
| 23.7.5.1 Design & contract | Frozen design recorded in repo doc; no executable surface to test | `docs/phase-23-7-5-compatibility-contract.md` |
| 23.7.5.2 Support model | Pure domain model, 5 support states, precedence, host/protocol orthogonality | `tests/test_compat_support_model.py` |
| 23.7.5.3 Manifest | Reader/validator, schema, structural/semantic rejection | `tests/test_compat_manifest.py`, `tools/compat_read.py` |
| 23.7.5.4 Detection & capabilities | `compat/detection.py`, `tools/compat_probe.py`, os-release parsing, probes | `tests/test_compat_detection.py` |
| 23.7.5.5 Dependency resolution | `compat/dependency_resolution.py`, `tools/compat_resolve.py`, L2 parser contract | `tests/test_compat_dependency_resolution.py`, `tests/test_compat_dependency_l2_real.py`, `tests/test_compat_dependency_matrix.py` |
| 23.7.5.6a Transactional provisioning | `compat/provisioning/*`, plan/journal/lock/rollback/uninstall | `tests/test_compat_transactional_provisioning.py`, `tests/test_compat_amneziawg_provisioning.py` |
| 23.7.5.6b AmneziaWG source-build provisioning | Source-build executor, dynamic digest, sanitized env, VM reboot harness | `tests/test_compat_amneziawg_provisioning.py`, `tests/vm/phase23_7_5_6b_amneziawg_validation.py` |
| 23.7.5.7 System migration | `tools/compat_distro_classify.py`, `lib/distro.sh`, fallback, shell↔engine contract | `tests/test_compat_system_migration.py`, `tests/unit/test_distro_detection.sh`, `tests/unit/test_shell_distro_state.sh`, `tests/unit/test_doctor_distro_state.sh` |

---

## 6. Coverage matrix

### 6.1 Task 23.7.5.2 — Support model

| Requirement / behavior | Existing test | Gap closed in 23.7.5.8 | Status |
|------------------------|---------------|------------------------|--------|
| 5 support states with deterministic precedence | `test_classifier_output_always_satisfies_invariants`, `test_exhaustive_precedence_contradictions_raise` | — | covered |
| Host/protocol orthogonality | `test_absent_protocol_does_not_affect_host_or_other_protocols`, `test_orthogonal_classifications` | — | covered |
| Freshness/expiry domain rules | `FreshnessTests` (6 cases) | — | covered |
| No real distro/release hardcoded in model | `test_model_source_has_no_real_distro_or_release` | — | covered |

### 6.2 Task 23.7.5.3 — Manifest

| Requirement / behavior | Existing test | Gap closed in 23.7.5.8 | Status |
|------------------------|---------------|------------------------|--------|
| Bootstrap reader parses as Python 3.6 stdlib-only | `test_bootstrap_reader_parses_as_python_36` | — | covered |
| Structural/semantic rejection | `ManifestInvalidCasesTests` (17 cases) | — | covered |
| Valid product manifest round-trips | `ManifestValidCasesTests` (7 cases) | — | covered |
| CLI validate/get/list/facts deterministic JSON | `test_cli_validate_get_list_facts_are_deterministic_json` | — | covered |

### 6.3 Task 23.7.5.4 — Detection & capabilities

| Requirement / behavior | Existing test | Gap closed in 23.7.5.8 | Status |
|------------------------|---------------|------------------------|--------|
| os-release parser safety | `OsReleaseParserTests` (6 cases) | — | covered |
| Safe command runner | `SafeCommandRunnerTests` (8 cases) | — | covered |
| Distribution resolution & classification | `DistributionResolutionTests` (6 cases) | — | covered |
| Capability probes & host readiness | `CapabilityProbeTests` (13 cases) | — | covered |
| Diagnostic probes (SELinux/AppArmor/firewalld) | `DiagnosticProbeTests` (5 cases) | — | covered |
| Internal tool security & determinism | `ToolAndSecurityTests` (5 cases) | — | covered |

### 6.4 Task 23.7.5.5 — Dependency resolution

| Requirement / behavior | Existing test | Gap closed in 23.7.5.8 | Status |
|------------------------|---------------|------------------------|--------|
| Resolver pure logic | `DependencyResolverTests` (21 cases) | — | covered |
| Artifact/pin contract exports | `PackageArtifactContractExportTests` | — | covered |
| L2 pull/manager/package parser taxonomy | `L2ParserTests` (47 cases) | — | covered |
| Productive matrix resolves without internal errors | `FocusedDependencyMatrixContractTests` | — | covered |
| Real container queries gated by env var | `test_real_container_package_queries` (skipped without `WATCHDOGVPN_REAL_L2=1`) | — | covered, opt-in |

### 6.5 Task 23.7.5.6a — Transactional provisioning

| Requirement / behavior | Existing test | Gap closed in 23.7.5.8 | Status |
|------------------------|---------------|------------------------|--------|
| Plan digest, journal durability, transitions, rollback, uninstall | `TransactionalProvisioningTests` (items 1–35) | — | covered |
| Lock contention between two `prepare()` calls | `test_06_lock_contention_between_two_processes` | — | covered |
| **Lock contention between `prepare()` and `uninstall()`** | — | `test_06b_lock_contention_between_prepare_and_uninstall` | **closed in 23.7.5.8** |

### 6.6 Task 23.7.5.6b — AmneziaWG source-build provisioning

| Requirement / behavior | Existing test | Gap closed in 23.7.5.8 | Status |
|------------------------|---------------|------------------------|--------|
| Dynamic output digests, authority, idempotency | `AmneziaWGProvisioningTests` | — | covered |
| Sanitized build environment | `test_build_subprocesses_receive_sanitized_env_not_parent_env` | — | covered |
| Recovery rollback state-machine fix | `test_recovery_apply_failure_rolls_back_without_invalid_transition` | — | covered |
| VM reboot recovery harness | `tests/vm/phase23_7_5_6b_amneziawg_validation.py` | — | covered at harness level |

### 6.7 Task 23.7.5.7 — System migration

| Requirement / behavior | Existing test | Gap closed in 23.7.5.8 | Status |
|------------------------|---------------|------------------------|--------|
| Shell matches engine for all fixtures | `test_shell_matches_engine_for_all_fixtures` | — | covered |
| Future flag iff experimental | `test_future_iff_experimental` | — | covered |
| Fallback never claims support (single case) | `test_fallback_never_claims_support` | parametrized for all fixtures | hardened |
| **Exit-code contract of `compat_distro_classify.py`** | — | `test_classify_exit_code_on_invalid_manifest`, `test_classify_exit_code_on_usage_error`, `test_classify_exit_code_on_missing_os_release` | **closed in 23.7.5.8** |
| **Multi-family pure-Bash fallback** | — | added to `tests/unit/test_distro_detection.sh` (arch, redhat, suse) | **closed in 23.7.5.8** |
| **Engine failure degradation (invalid JSON, non-zero exit, timeout)** | — | added to `tests/unit/test_distro_detection.sh` | **closed in 23.7.5.8** |
| **`lib/common.sh` state-message helpers** | — | `tests/unit/test_shell_distro_state.sh` | **closed in 23.7.5.8** |
| **`doctor.sh` read-only reaction to DISTRO_* flags** | — | `tests/unit/test_doctor_distro_state.sh` | **closed in 23.7.5.8** |

---

## 7. Criterion for mandatory vs optional vs future debt

- **Mandatory for approval:** a behavior that is part of the approved contract of 23.7.5.1–23.7.5.7 and that can be tested deterministically without real network/mutation. Missing coverage here blocks closure.
- **Optional improvement:** additional parametrization, faster fixtures, or broader negative cases that do not change the contract and are not required for approval.
- **Future / non-blocking debt:** coverage that requires L2/L3/VM work (real package queries, real reboot campaigns, real distro certification) or that belongs to a later task (e.g., 23.7.5.9 integration tests).

All gaps closed in 23.7.5.8 are mandatory. No optional improvements were mixed in. No L2/L3/VM work was performed inside this task.

---

## 8. Files touched (if implementation is approved)

- `tests/test_compat_system_migration.py` — added exit-code tests; parametrized fallback test.
- `tests/test_compat_transactional_provisioning.py` — added `test_06b_lock_contention_between_prepare_and_uninstall`.
- `tests/unit/test_distro_detection.sh` — added multi-family fallback and engine-failure modes.
- `tests/unit/test_shell_distro_state.sh` — new test for `lib/common.sh` helpers.
- `tests/unit/test_doctor_distro_state.sh` — new test for `doctor.sh` distro-state wiring.
- `tools/compat_distro_classify.py` — normalized `SystemExit` from argparse to `EXIT_USAGE=1`.
- `docs/phase-23-7-5-8-l1-coverage-report.md` — this report.
- `docs/phase-23-7-5-compatibility-contract.md` — closure section for 23.7.5.8.

---

## 9. Files NOT touched

- `compat/compatibility.json`
- `compat/compatibility.schema.json`
- `compat/detection.py`
- `compat/dependency_resolution.py`
- `compat/support_model.py`
- `compat/provisioning/*` (domain logic unchanged)
- `lib/packages.sh`
- `distros/*.sh`
- `lib/distro.sh`
- `lib/common.sh` (only tested, not modified)
- `install.sh`, `update.sh`, `doctor.sh` (only tested, not modified)
- Public CLI / daemon / routing / DNS / kill-switch code.

---

## 10. Validation strategy

1. **Focused Python unit tests:** run the compat test subset and confirm the expected count.
2. **Shell unit tests:** run each new/modified `.sh` test.
3. **Syntax/diff checks:** `bash tests/syntax.sh` and `git diff --check`.
4. **Manifest validation:** `python3 tools/compat_read.py validate`.
5. **Host smoke:** `python3 tools/compat_distro_classify.py classify` on the local Arch host.
6. **Fallback simulation:** run `detect_distro` with an empty `PATH` (no `python3`) and verify `DISTRO_UNDETERMINED=1`.
7. **Full discovery:** `python3 -m unittest discover -s tests` to catch regressions outside the compat subset.

---

## 11. Exact evidence delivered for audit

- This report (`docs/phase-23-7-5-8-l1-coverage-report.md`).
- Updated contract document (`docs/phase-23-7-5-compatibility-contract.md`).
- `git diff --stat` limited to the files in scope.
- Console output of:
  - `bash tests/unit/test_distro_detection.sh`
  - `bash tests/unit/test_shell_distro_state.sh`
  - `bash tests/unit/test_doctor_distro_state.sh`
  - `python3 -m unittest tests.test_compat_system_migration`
  - `python3 -m unittest tests.test_compat_transactional_provisioning`
  - `python3 -m unittest discover -s tests -p 'test_compat_*.py'`
  - `python3 -m unittest discover -s tests`
  - `bash tests/syntax.sh`
  - `python3 tools/compat_read.py validate`
  - `python3 tools/compat_distro_classify.py classify`
  - fallback simulation with empty `PATH`
  - `git diff --check`
- Final `git status --short`, branch, HEAD, and ahead/behind count.
- Explicit confirmation that `main` remains untouched.

---

## 12. Mandatory stop points for consultation

Stop and ask before proceeding if any of the following appear:

1. A mandatory gap requires touching files listed in section 9.
2. A test fails that points to a real regression in 23.7.5.1–23.7.5.7.
3. Any task beyond 23.7.5.8 seems necessary to close the L1 coverage gap.
4. The scope needs to expand to L2/L3/VM validation.
5. A new product feature or public CLI change is requested.

---

## 13. Execution results

All validation commands were executed on the local Arch host against the implementation commit `fc9f1ced310b922f1ab424ed55bb5ebf33490e12`.

| Command | Result |
|---------|--------|
| `bash tests/unit/test_distro_detection.sh` | `distro detection checks passed` |
| `bash tests/unit/test_shell_distro_state.sh` | `shell distro state checks passed` |
| `bash tests/unit/test_doctor_distro_state.sh` | `doctor distro state checks passed` |
| `python3 -m unittest tests.test_compat_system_migration` | 6 tests OK |
| `python3 -m unittest tests.test_compat_transactional_provisioning` | 266 tests OK |
| `python3 -m unittest discover -s tests -p 'test_compat_*.py'` | 489 tests OK, 1 skip |
| `python3 -m unittest discover -s tests` | 2268 tests OK, 1 skip |
| `bash tests/syntax.sh` | `syntax checks passed` |
| `python3 tools/compat_read.py validate` | `{"ok":true,"schema_version":"1.0.0"}` |
| `python3 tools/compat_distro_classify.py classify` | `support_classification: certified` for Arch Linux |
| Fallback simulation with empty `PATH` | `DISTRO_ID=arch SUPPORTED=0 FUTURE=0 UNSUPPORTED=0 UNDETERMINED=1` |
| `git diff --check` | clean |

The single skipped test is the opt-in real-container L2 query test (`WATCHDOGVPN_REAL_L2=1` not set), which is documented non-blocking debt.

---

## 14. Closure criteria

Task 23.7.5.8 is closed when:

1. All validation commands in section 10 pass.
2. The diff is limited to the files in section 8.
3. This report and the contract document are committed.
4. The branch is synchronized with `origin/phase-23-7-5-compatibility-contract`.
5. `main` remains at `8b15d470e8abca62a5bb3b72873be6bfecbaf56f`.
6. No work on 23.7.5.9 or later has started.

---

## 15. Documented non-blocking debt / future gaps

- L2 real-container package queries remain opt-in via `WATCHDOGVPN_REAL_L2=1`; they are out of scope for L1.
- VM reboot-recovery evidence for 23.7.5.6b was captured by the dedicated VM harness, not repeated here.
- Public CLI integration tests for the new compatibility contract belong to a later task (23.7.5.9+).
- Real-distro certification gaps (AlmaLinux, RHEL, CentOS Stream, openSUSE Tumbleweed remain family-inferred) are not L1 test gaps; they are certification debt tracked outside this task.
