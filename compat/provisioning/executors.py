"""Trusted executor registry and the lab-only canary executor (Phase 23.7.5.6a).

Executors are resolved exclusively through code-registered entries in
``TrustedExecutorRegistry`` -- never through a manifest-driven dynamic import,
string evaluation, in-process code execution, or a spawned interactive shell
wrapper. The manifest can declare identity/method/package/artifact/hash/
provenance/postcondition data; it can never select or shape what code
actually runs.

``CanaryExecutor`` is a lab-only executor confined to an injected sandbox
root. It exercises the full plan/apply/verify/undo/postcondition cycle without
ever touching real packages, repositories, network, DNS, firewall, services or
protocols. It must never be registered for normal end-user use -- only test
and VM-harness code registers it.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from typing import Callable, Mapping, Sequence

from compat.provisioning.errors import ExecutorNotRegisteredError, PathPolicyError, ProvisioningError
from compat.provisioning.journal import StepRecord
from compat.provisioning.model import (
    ExecutionResult,
    OwnershipCandidate,
    ProvisioningPlan,
    ProvisioningStep,
    RollbackResult,
    VerificationResult,
)
from compat.provisioning.paths import (
    AllowedRootHandle,
    create_file_exclusive_relative,
    read_bytes_relative,
    remove_file_if_owned_relative,
    stat_identity_relative,
    validate_identifier,
    validate_target_path,
)


@dataclass(frozen=True)
class ExecutionContext:
    allowed_roots: tuple[Path, ...]
    now: Callable[[], str]
    forbidden_roots: tuple[Path, ...] = ()
    network_available: Callable[[], bool] | None = None
    # Captured under the provisioner lock, immediately before apply/rollback/
    # uninstall (point 2, fifth correction round) -- empty for callers that
    # never mutate (plan/dry-run). Every executor operation that touches the
    # filesystem resolves through the handle matching its target's allowed
    # root, never through a freshly re-resolved ``Path``.
    allowed_root_handles: tuple[AllowedRootHandle, ...] = ()


def handle_for_allowed_root(context: ExecutionContext, validated: Path) -> AllowedRootHandle:
    for handle in context.allowed_root_handles:
        if validated == handle.path:
            return handle
        try:
            validated.relative_to(handle.path)
            return handle
        except ValueError:
            continue
    raise PathPolicyError("no allowed-root handle bound for %s; the caller must open one under the lock before use" % validated)


class Executor(abc.ABC):
    executor_id: str
    executor_version: str
    supported_method_kind: str

    @abc.abstractmethod
    def plan_steps(self, *, capability_id: str, dependency_id: str, context: ExecutionContext) -> tuple[ProvisioningStep, ...]: ...

    @abc.abstractmethod
    def apply_step(self, step: StepRecord, context: ExecutionContext) -> ExecutionResult: ...

    @abc.abstractmethod
    def verify_step(self, step: StepRecord, execution: ExecutionResult, context: ExecutionContext) -> VerificationResult: ...

    @abc.abstractmethod
    def undo_step(self, step: StepRecord, execution: ExecutionResult, context: ExecutionContext) -> RollbackResult: ...

    @abc.abstractmethod
    def verify_postcondition(self, plan: ProvisioningPlan, context: ExecutionContext) -> VerificationResult: ...

    @abc.abstractmethod
    def inspect_step(self, step: StepRecord, context: ExecutionContext) -> Mapping[str, object]:
        """Read-only inspection of a step's real-world state, used by recovery
        to decide whether resuming is safe. Never mutates anything."""

    @abc.abstractmethod
    def postcondition_description(self) -> str: ...

    @abc.abstractmethod
    def reconstruct_undo_record(self, step: StepRecord) -> Mapping[str, object]:
        """Deterministically rebuild the undo_record apply_step would have
        produced, purely from the step's own intent/target (no I/O). Used by
        recovery when a crash landed the real action but not the journal
        write recording undo_record."""

    @abc.abstractmethod
    def expected_ownership_for_step(self, plan: ProvisioningPlan, step: ProvisioningStep) -> OwnershipCandidate:
        """Canonical, deterministic expected ownership metadata for a
        resource this step's plan creates -- derived ONLY from ``plan``,
        ``step.intent``, ``plan.selected_asset`` and this executor's own
        registered code; NEVER from a live filesystem inspection (that
        would legitimately vary mid-recovery, which is exactly why it must
        never gate authority -- see ``_detect_ownership_drift`` for the
        live-state check instead). The engine (``validate_ownership_authority``,
        ``_finalize_provenance``) uses this as the single source of truth
        for what a persisted ``OwnershipRecord`` must match; it never
        hardcodes executor-specific assumptions (e.g. "artifact_type is
        always file", "source is always None") itself."""

    def declares_network_required(self) -> bool:
        return False

    def step_is_replay_safe(self, step: StepRecord) -> bool:
        """Whether re-attempting apply for this step, if it never completed,
        is safe (idempotent creation semantics). Recovery still confirms the
        observed state before resuming; this only says the *kind* of step is
        eligible for that check at all."""
        return True


class TrustedExecutorRegistry:
    """Code-only executor registry. No dynamic import, no manifest-driven
    module/class names, no eval/exec/shell."""

    def __init__(self) -> None:
        self._executors: dict[tuple[str, str], Executor] = {}

    def register(self, *, method_kind: str, method_id: str, executor: Executor) -> None:
        key = (method_kind, method_id)
        if key in self._executors:
            raise ProvisioningError("an executor is already registered for %r" % (key,))
        self._executors[key] = executor

    def resolve(self, *, method_kind: str, method_id: str, expected_executor_version: str) -> Executor:
        executor = self._executors.get((method_kind, method_id))
        if executor is None or executor.executor_version != expected_executor_version:
            raise ExecutorNotRegisteredError(
                "no trusted executor registered for method_kind=%r method_id=%r executor_version=%r"
                % (method_kind, method_id, expected_executor_version)
            )
        return executor


CANARY_METHOD_KIND = "canary_lab"
CANARY_EXECUTOR_ID = "canary_lab_executor"
CANARY_EXECUTOR_VERSION = "1"


class CanaryExecutor(Executor):
    """Lab-only executor. Writes two small synthetic files under the injected
    sandbox root and nothing else -- no package manager, no network, no real
    system paths. Used to demonstrate the transactional infrastructure in L1
    and VM tests before any production executor exists (23.7.5.6b+)."""

    executor_id = CANARY_EXECUTOR_ID
    executor_version = CANARY_EXECUTOR_VERSION
    supported_method_kind = CANARY_METHOD_KIND

    def __init__(self, *, requires_network: bool = False) -> None:
        self._requires_network = requires_network

    def declares_network_required(self) -> bool:
        return self._requires_network

    def plan_steps(self, *, capability_id: str, dependency_id: str, context: ExecutionContext) -> tuple[ProvisioningStep, ...]:
        validate_identifier(capability_id, field="capability_id")
        validate_identifier(dependency_id, field="dependency_id")
        sandbox = context.allowed_roots[0]
        marker_path = sandbox / ("%s.marker" % capability_id)
        companion_path = sandbox / ("%s.companion" % capability_id)
        marker_content = _marker_content(capability_id)
        companion_content = _companion_content(capability_id, marker_content)
        # expected_mode/uid/gid are the deterministic invariants this
        # executor always creates its own files under -- part of the plan
        # itself (and therefore of plan_digest), never metadata the engine
        # invents or adopts after the fact from whatever it happens to find
        # on disk at commit time.
        expected_ownership = {"expected_mode": 0o600, "expected_uid": os.getuid(), "expected_gid": os.getgid()}
        return (
            ProvisioningStep(
                sequence=0,
                step_id="create_marker",
                action_type="create_file",
                intent={
                    "content_sha256": hashlib.sha256(marker_content).hexdigest(),
                    "content": marker_content.decode("ascii"),
                    **expected_ownership,
                },
                target=str(marker_path),
            ),
            ProvisioningStep(
                sequence=1,
                step_id="create_companion",
                action_type="create_file",
                intent={
                    "content_sha256": hashlib.sha256(companion_content).hexdigest(),
                    "content": companion_content.decode("ascii"),
                    **expected_ownership,
                },
                target=str(companion_path),
            ),
        )

    def apply_step(self, step: StepRecord, context: ExecutionContext) -> ExecutionResult:
        try:
            validated = validate_target_path(
                Path(step.target), allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots
            )
            handle = handle_for_allowed_root(context, validated)
        except PathPolicyError as exc:
            return ExecutionResult(status="apply_failed", error_kind="path_policy_violation", error=str(exc))
        content = step.intent["content"].encode("ascii")
        try:
            create_file_exclusive_relative(handle, validated, content, mode=0o600)
        except FileExistsError as exc:
            return ExecutionResult(status="apply_failed", error_kind="target_already_exists", error=str(exc))
        except PathPolicyError as exc:
            return ExecutionResult(status="apply_failed", error_kind="path_policy_violation", error=str(exc))
        except OSError as exc:
            return ExecutionResult(status="apply_failed", error_kind="os_error", error=str(exc))
        return ExecutionResult(
            status="applied",
            observed={"path": str(validated), "sha256": hashlib.sha256(content).hexdigest()},
            undo_record={"path": str(validated), "expected_content": step.intent["content"], "expected_sha256": step.intent["content_sha256"]},
        )

    def verify_step(self, step: StepRecord, execution: ExecutionResult, context: ExecutionContext) -> VerificationResult:
        path = Path(execution.observed.get("path", step.target))
        try:
            validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
        except PathPolicyError as exc:
            return VerificationResult(status="verification_failed", error_kind="path_policy_violation", error=str(exc))
        try:
            identity = stat_identity_relative(handle, validated)
        except FileNotFoundError as exc:
            return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
        except (OSError, PathPolicyError) as exc:
            return VerificationResult(status="verification_failed", error_kind="inspection_error", error=str(exc))
        if identity["is_symlink"]:
            return VerificationResult(status="verification_failed", error_kind="unexpected_symlink", error="target is a symlink")
        if not identity["is_regular"]:
            return VerificationResult(status="verification_failed", error_kind="not_regular_file", error="target is not a regular file")
        expected_mode = step.intent.get("expected_mode", 0o600)
        if identity["mode"] != expected_mode:
            return VerificationResult(status="verification_failed", error_kind="unexpected_mode", error="mode is %o, expected %o" % (identity["mode"], expected_mode))
        expected_uid = step.intent.get("expected_uid")
        if expected_uid is not None and identity["uid"] != expected_uid:
            return VerificationResult(status="verification_failed", error_kind="unexpected_uid", error="uid is %d, expected %d" % (identity["uid"], expected_uid))
        expected_gid = step.intent.get("expected_gid")
        if expected_gid is not None and identity["gid"] != expected_gid:
            return VerificationResult(status="verification_failed", error_kind="unexpected_gid", error="gid is %d, expected %d" % (identity["gid"], expected_gid))
        if identity["nlink"] != 1:
            return VerificationResult(status="verification_failed", error_kind="unexpected_nlink", error="st_nlink is %d, expected 1" % identity["nlink"])
        try:
            actual = read_bytes_relative(handle, validated)
        except FileNotFoundError as exc:
            return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
        except (OSError, PathPolicyError) as exc:
            return VerificationResult(status="verification_failed", error_kind="inspection_error", error=str(exc))
        expected_sha256 = step.intent["content_sha256"]
        actual_sha256 = hashlib.sha256(actual).hexdigest()
        if actual_sha256 != expected_sha256:
            return VerificationResult(status="verification_failed", error_kind="content_mismatch", error="sha256 mismatch")
        return VerificationResult(
            status="verified",
            evidence={
                "path": str(validated), "sha256": actual_sha256, "mode": oct(identity["mode"]),
                "uid": identity["uid"], "gid": identity["gid"], "nlink": identity["nlink"],
            },
        )

    def undo_step(self, step: StepRecord, execution: ExecutionResult, context: ExecutionContext) -> RollbackResult:
        undo_record = execution.undo_record or {}
        path = Path(undo_record.get("path", step.target))
        try:
            validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
        except PathPolicyError as exc:
            return RollbackResult(status="undo_failed", residual=True, error_kind="path_policy_violation", error=str(exc))
        expected_sha256 = undo_record.get("expected_sha256")
        try:
            removed = remove_file_if_owned_relative(handle, validated, expected_sha256=expected_sha256)
        except PathPolicyError as exc:
            return RollbackResult(status="undo_failed", residual=True, error_kind="ownership_mismatch", error=str(exc))
        except OSError as exc:
            return RollbackResult(status="undo_failed", residual=True, error_kind="os_error", error=str(exc))
        return RollbackResult(status="undone", residual=False, evidence={"path": str(validated), "removed": removed})

    def reconstruct_undo_record(self, step: StepRecord) -> Mapping[str, object]:
        return {"path": step.target, "expected_content": step.intent["content"], "expected_sha256": step.intent["content_sha256"]}

    def expected_ownership_for_step(self, plan: ProvisioningPlan, step: ProvisioningStep) -> OwnershipCandidate:
        content_sha256 = step.intent.get("content_sha256")
        return OwnershipCandidate(
            artifact_type="file",
            resource_identity=step.target,
            pre_existing=False,
            method_id=plan.selected_method_id,
            source=step.intent.get("source"),
            version=step.intent.get("version"),
            integrity=content_sha256,
            uid=step.intent.get("expected_uid"),
            gid=step.intent.get("expected_gid"),
            mode=step.intent.get("expected_mode"),
            nlink=1,
            post_install_fingerprint=content_sha256,
        )

    def verify_postcondition(self, plan: ProvisioningPlan, context: ExecutionContext) -> VerificationResult:
        for step in plan.steps:
            path = Path(step.target)
            try:
                validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
                handle = handle_for_allowed_root(context, validated)
            except PathPolicyError as exc:
                return VerificationResult(status="verification_failed", error_kind="path_policy_violation", error=str(exc))
            try:
                identity = stat_identity_relative(handle, validated)
            except FileNotFoundError as exc:
                return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
            except (OSError, PathPolicyError) as exc:
                return VerificationResult(status="verification_failed", error_kind="inspection_error", error=str(exc))
            if identity["is_symlink"] or not identity["is_regular"]:
                return VerificationResult(status="verification_failed", error_kind="unexpected_file_type", error=str(validated))
            expected_mode = step.intent.get("expected_mode", 0o600)
            if identity["mode"] != expected_mode:
                return VerificationResult(status="verification_failed", error_kind="unexpected_mode", error="mode is %o, expected %o at %s" % (identity["mode"], expected_mode, validated))
            expected_uid = step.intent.get("expected_uid")
            if expected_uid is not None and identity["uid"] != expected_uid:
                return VerificationResult(status="verification_failed", error_kind="unexpected_uid", error="uid is %d, expected %d at %s" % (identity["uid"], expected_uid, validated))
            expected_gid = step.intent.get("expected_gid")
            if expected_gid is not None and identity["gid"] != expected_gid:
                return VerificationResult(status="verification_failed", error_kind="unexpected_gid", error="gid is %d, expected %d at %s" % (identity["gid"], expected_gid, validated))
            if identity["nlink"] != 1:
                return VerificationResult(status="verification_failed", error_kind="unexpected_nlink", error="st_nlink is %d, expected 1" % identity["nlink"])
            expected_sha256 = step.intent.get("content_sha256")
            try:
                actual_sha256 = hashlib.sha256(read_bytes_relative(handle, validated)).hexdigest()
            except FileNotFoundError as exc:
                return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
            except (OSError, PathPolicyError) as exc:
                return VerificationResult(status="verification_failed", error_kind="inspection_error", error=str(exc))
            if expected_sha256 is not None and actual_sha256 != expected_sha256:
                return VerificationResult(status="verification_failed", error_kind="content_mismatch", error="sha256 mismatch at %s" % validated)
        return VerificationResult(status="verified", evidence={"steps": len(plan.steps)})

    def postcondition_description(self) -> str:
        return "canary marker and companion files present with expected content, permissions and no symlinks"

    def inspect_step(self, step: StepRecord, context: ExecutionContext) -> Mapping[str, object]:
        """Read-only inspection used by resume/recovery decisions. A genuine
        absence (``FileNotFoundError``) is reported as ``exists: False``; any
        other ``OSError`` (permission denied, stale handle, I/O error, ...)
        is reported as an explicit ``inspect_error`` with ``exists: None`` --
        callers must never treat that as confirmed absence, which would let
        recovery retry-from-scratch over a resource it simply couldn't see."""
        path = Path(step.target)
        try:
            validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
        except PathPolicyError as exc:
            return {"exists": None, "is_symlink": None, "content_matches": None, "path_policy_error": str(exc)}
        try:
            identity = stat_identity_relative(handle, validated)
        except FileNotFoundError:
            return {"exists": False, "is_symlink": False, "content_matches": None}
        except (OSError, PathPolicyError) as exc:
            return {"exists": None, "is_symlink": None, "content_matches": None, "inspect_error": str(exc)}
        if identity["is_symlink"]:
            return {"exists": True, "is_symlink": True, "content_matches": None}
        expected_sha256 = step.intent.get("content_sha256")
        try:
            actual_sha256 = hashlib.sha256(read_bytes_relative(handle, validated)).hexdigest()
        except FileNotFoundError:
            return {"exists": False, "is_symlink": False, "content_matches": None}
        except (OSError, PathPolicyError) as exc:
            return {"exists": True, "is_symlink": False, "content_matches": None, "inspect_error": str(exc)}
        return {"exists": True, "is_symlink": False, "content_matches": actual_sha256 == expected_sha256}


def _marker_content(capability_id: str) -> bytes:
    return ("watchdogvpn-canary-marker:%s" % capability_id).encode("ascii")


def _companion_content(capability_id: str, marker_content: bytes) -> bytes:
    return ("watchdogvpn-canary-companion:%s:%s" % (capability_id, hashlib.sha256(marker_content).hexdigest())).encode("ascii")
