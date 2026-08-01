# Phase 23.7.5.9 — `pruebas_por_versiones` (Plan)

**Status:** PLAN APPROVED — conditional. Implementation authorized after the 5
auditor corrections below were reflected in this document.

**Branch:** `phase-23-7-5-compatibility-contract`\
**Base commit:** `764b44a`\

**Main untouched:** `8b15d47`

---

## Objective

Build the L2 per-version test layer: a CI container matrix that runs real,
disposable-container dependency resolution against every supported
family/release, a scheduled repository-availability job, and explicit
negative-test coverage. The goal is to catch version-family breaks
automatically (e.g. the AmneziaWG PPA 404 on Ubuntu 26.04) before they reach
users or public support claims.

---

## 1. Exact scope

### Files touched

| File | Reason |
|------|----------|
| `tests/test_compat_dependency_l2_real.py` | Extend the existing real L2 harness to cover the full per-family/release matrix and negative container-only cases. |
| `tests/test_compat_dependency_l2_negative.py` | New: deterministic negative tests using `StaticAvailabilityProvider` (no containers). |
| `tests/test_compat_dependency_matrix.py` | Adjust if matrix expectations change after L2 data is incorporated. |
| `.github/workflows/compat-l2-matrix.yml` | New: CI container matrix for real L2 dependency resolution. |
| `.github/workflows/repo-availability-cron.yml` | New: scheduled read-only availability check of external repos/artifacts. |
| `tools/compat_l2_reporter.py` | New: JSON/markdown reporter for L2 matrix and cron results. |
| `docs/phase-23-7-5-9-plan.md` | This document. |
| `docs/phase-23-7-5-compatibility-contract.md` | Close-out section for Task 23.7.5.9 and record the CI file split. |
| `compat/compatibility.json` | Update `validation_metadata.per_release_ci` only by human-reviewed PR/artifact, never by an automated commit. |

### Files NOT touched

- `compat/compatibility.schema.json` — schema stays unchanged; only data is updated.
- `compat/support_model.py`, `compat/detection.py`, `compat/dependency_resolution.py` — pure logic is closed; only tests/reporters are added.
- `compat/provisioning/*` — transactional provisioning is out of scope.
- `lib/distro.sh`, `lib/common.sh`, `install.sh`, `update.sh`, `doctor.sh` — no semantic changes.
- Public CLI, daemon, routing, DNS, firewall, TUN, interfaces.

---

## 2. CI container matrix

### Why two workflows instead of the single `ci.yml` listed in the design

The frozen design §14 lists a single `.github/workflows/ci.yml` containing
both the matrix and the scheduled job. This plan splits them into two
workflows for two practical reasons:

1. **Isolation of the heavy matrix.** The L2 matrix pulls many container
   images and runs package-manager metadata refreshes. It can take 10–20
   minutes. Keeping it separate prevents a slow, network-dependent job from
   blocking the fast L1/unit/syntax gate that every commit must pass.
2. **Different trigger cadence.** The matrix runs on PRs/pushes to the phase
   branch and on manual dispatch; the cron job runs daily. A single file
   would mix these concerns and make failure attribution harder.

The contract is preserved: the two workflows together implement the single
"CI container matrix + scheduled repo-availability job" requirement from §9.
This deviation is documented here and will be recorded in
`docs/phase-23-7-5-compatibility-contract.md` at closure.

### Container targets

All targets run on GitHub-hosted runners using only ephemeral containers.
No self-hosted runner, no SSH to any VM, and no access to Gabo's personal
infrastructure.

| Target | Image | Note |
|--------|-------|------|
| `ubuntu_24_04` | `ubuntu:24.04` | Mandatory. |
| `ubuntu_26_04` | `ubuntu:26.04` | Optional: only `image_not_found` is an acceptable excuse; any other failure fails the gate. |
| `debian_13` | `debian:13` | Mandatory. |
| `fedora_44` | `fedora:44` | Mandatory. |
| `rocky_9` | `rockylinux:9` | Mandatory. |
| `opensuse_leap_15_6` | `opensuse/leap:15.6` | Mandatory. |
| `arch` | `archlinux:latest` | Mandatory. |
| `cachyos` | Only if a trustworthy official Docker image exists. | If not, documented as fixture-only. No SSH VM fallback. |
| `kali` | Fixture-only unless a stable official image exists. | Documented if not run. |

The container does not need to come with every package pre-installed. The L2
harness installs/updates the package manager index inside the container and
queries the required packages, just as the current `tests/test_compat_dependency_l2_real.py` already does for `python3` and `openvpn`.

### What the matrix validates

For each target, for each `dependency_requirement` in the manifest:

1. Pull the image.
2. Create/start the container.
3. Read `/etc/os-release` and verify identity.
4. Verify the package manager exists.
5. Refresh metadata (inside the container only).
6. Query every package declared in the selected candidate.
7. Clean up the container.
8. Produce `overall_status` per target.

A target is **green** only if `overall_status == "available"`, `cleanup.status` is in `("cleaned", "not_needed")`, and `residual_possible == false`. The only exception is `ubuntu_26_04` with a demonstrated `image_not_found` result.

### Output

- Artifact: `compat-l2-matrix.json`.
- Summary: `compat-l2-matrix.md`.
- Both are uploaded to the workflow run.

---

## 3. Scheduled repository-availability job

### Trigger

- Daily at 06:00 UTC (`schedule: cron: '0 6 * * *'`).
- Manual (`workflow_dispatch`).

### What it does

Read-only checks:

1. Container image availability for all matrix images (HEAD only).
2. External repository availability:
   - AmneziaWG PPA Launchpad endpoint.
   - EPEL 9 repository URL.
3. Artifact availability:
   - sing-box release assets (HEAD only).
   - Cloak `ck-client` release assets (HEAD only).
4. Source-build provenance:
   - AmneziaWG tools and transport commit hashes exist on GitHub.

### Reporting

- If everything is available: workflow succeeds, artifact `repo-availability-report.json` is uploaded.
- If something is unavailable: workflow fails, artifact is uploaded, and the failure is left for human review.
- **No automatic issue creation, no automatic commits, no automatic PRs.**

---

## 4. Negative tests

New file `tests/test_compat_dependency_l2_negative.py` covers every negative
case required by design §9 using the injected `StaticAvailabilityProvider`.

| Negative test | Coverage |
|---------------|----------|
| missing repository | `repository_supports_exact_target` returns `unavailable`; chain exhausts to `no_safe_route`. |
| non-existent series | `amneziawg_ubuntu_ppa_exact` on `ubuntu_26_04` and `amneziawg_debian_legacy_focal_ppa` on `debian_13` rejected with `target_release_not_explicitly_compatible`. |
| invalid hash/signature | Manifest validation rejects SHA-256 placeholders (`0*64`, `1*64`). |
| incomplete download | `artifact_exists` returns `malformed_response` with wrong size. |
| failed build | Source-build candidate with `implementation_status != "implemented"` resolves to `recipe_not_implemented`. |
| failed postcondition | Resolver detects postcondition mismatch. |
| failed rollback | Already covered in transactional provisioner L1 (`test_compat_transactional_provisioning.py`); re-used, not duplicated here. |
| interruption between steps | Re-used from 6a L1 journal recovery tests. |
| concurrency (lock) | Re-used from `test_06b_lock_contention_between_prepare_and_uninstall`. |
| offline system | `provider_error`/`timeout` for all availability calls; chain blocks with `availability_unknown`. |
| invalid manifest | `tools/compat_read.py validate` rejects corrupt/oversized/typed-wrong manifests. |
| unknown release | Distro facts resolve to no distribution → `unsupported`. |
| EOL release | `eol_or_withdrawn: true` in manifest → `unsupported`. |
| unsupported architecture | `aarch64`/`x86_64` outside `supported_values` → `out_of_contract`/`no_safe_route`. |
| partial install | Aggregate package status with one `unavailable` → `unavailable`. |
| idempotent reinstall | Re-running resolver on same fixture yields same selected method. |
| uninstall preserving pre-existing components | No mutation in L2; covered by 6a transactional provisioner tests. |

---

## 5. Writing to `compat/compatibility.json`

`validation_metadata.per_release_ci` is part of the single source of truth.
It is **never** updated by an automated workflow commit.

Two allowed paths:

1. **Artifact-only** (preferred for this task): the CI matrix produces
   `compat-l2-matrix.json` and the cron produces
   `repo-availability-report.json`. A human reviews the artifact and updates
   `validation_metadata.per_release_ci` in a normal commit, with the same
   TDD/audit/closure process as any other change.
2. **Human-reviewed PR** (if the workflow is later enhanced): the workflow
   could generate a PR branch, but the merge must be explicitly approved by a
   human maintainer.

This plan uses path (1) for Task 23.7.5.9.

---

## 6. Handling missing container runtime in CI

- The workflow requires Docker or Podman.
- A pre-check step runs `docker info` / `podman info`.
- If neither is available:
  - The job fails with a clear message: `"Container runtime unavailable — L2 matrix cannot run. This is a CI infrastructure failure, not a product test pass."`
  - The artifact contains the same message.
  - The workflow is marked as `failure`, never as `success` or silent skip.

Locally, `tests/test_compat_dependency_l2_real.py` keeps the existing
`WATCHDOGVPN_REAL_L2=1` gate: without it, the test is skipped and counted as
`1 skip`, not a green.

---

## 7. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Flaky network / Docker Hub rate limits | Retry with backoff; use Podman fallback; cache images where possible. |
| Image exists but is not representative | Verify `/etc/os-release` identity before accepting results. |
| Container leaks | `finally` always removes the container; GitHub runners are ephemeral. |
| False support claim from green matrix | Matrix only proves package/repo availability, not full L3/L4/L5 certification. Public claims remain governed by `validation_metadata.per_release_ci` and field certs. |
| Ubuntu 26.04 suddenly exists | If it becomes available, it must pass like any other target; the optional-image exception is removed in a follow-up. |

---

## 8. Closure criteria

Task 23.7.5.9 is closed when:

1. L2 matrix runs in CI for all mandatory targets and produces green `overall_status`.
2. Negative tests pass locally and in CI.
3. Cron availability job runs and produces structured artifact.
4. `validation_metadata.per_release_ci` is updated by a human-reviewed commit (not auto-commit).
5. `docs/phase-23-7-5-compatibility-contract.md` records the split of `ci.yml` into two workflows.
6. `python3 -m unittest discover -s tests` passes.
7. `bash tests/syntax.sh` passes.
8. `python3 tools/compat_read.py validate` passes.
9. `git diff --check` is clean.
10. No `shell=True`, no dangerous eval/exec, and no secret leakage in new code.
11. `main` remains at `8b15d47`; all changes are on the phase branch.

---

## 9. Deviation summary from frozen design

| Design §14 listing | This plan | Justification |
|--------------------|-----------|---------------|
| Single `.github/workflows/ci.yml` | `.github/workflows/compat-l2-matrix.yml` + `.github/workflows/repo-availability-cron.yml` | Isolates the heavy, network-dependent L2 matrix from the fast L1 gate and matches the different trigger cadence. |
| CI writes to repo | No auto-write; human-reviewed artifact update | `validation_metadata.per_release_ci` is part of the single source of truth and must not be modified by an unattended workflow. |
| CachyOS/Kali in matrix | Docker-only if trustworthy image exists; otherwise fixture-only | No self-hosted runner or SSH access to personal infrastructure. |

These deviations are documented here and will be reflected in the closure update of `docs/phase-23-7-5-compatibility-contract.md`.
