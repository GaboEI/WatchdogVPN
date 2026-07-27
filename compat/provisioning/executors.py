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
from pathlib import Path
import stat
from typing import Callable, Mapping, Sequence

from compat.provisioning.errors import ExecutorNotRegisteredError, PathPolicyError, ProvisioningError
from compat.provisioning.journal import StepRecord
from compat.provisioning.model import ExecutionResult, ProvisioningPlan, ProvisioningStep, RollbackResult, VerificationResult
from compat.provisioning.paths import (
    create_file_exclusive,
    remove_file_if_owned,
    stat_identity,
    validate_identifier,
    validate_target_path,
)


@dataclass(frozen=True)
class ExecutionContext:
    allowed_roots: tuple[Path, ...]
    now: Callable[[], str]
    forbidden_roots: tuple[Path, ...] = ()
    network_available: Callable[[], bool] | None = None


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
        return (
            ProvisioningStep(
                sequence=0,
                step_id="create_marker",
                action_type="create_file",
                intent={"content_sha256": hashlib.sha256(marker_content).hexdigest(), "content": marker_content.decode("ascii")},
                target=str(marker_path),
            ),
            ProvisioningStep(
                sequence=1,
                step_id="create_companion",
                action_type="create_file",
                intent={"content_sha256": hashlib.sha256(companion_content).hexdigest(), "content": companion_content.decode("ascii")},
                target=str(companion_path),
            ),
        )

    def apply_step(self, step: StepRecord, context: ExecutionContext) -> ExecutionResult:
        try:
            validated = validate_target_path(
                Path(step.target), allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots
            )
        except PathPolicyError as exc:
            return ExecutionResult(status="apply_failed", error_kind="path_policy_violation", error=str(exc))
        content = step.intent["content"].encode("ascii")
        try:
            create_file_exclusive(validated, content, mode=0o600)
        except FileExistsError as exc:
            return ExecutionResult(status="apply_failed", error_kind="target_already_exists", error=str(exc))
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
        except PathPolicyError as exc:
            return VerificationResult(status="verification_failed", error_kind="path_policy_violation", error=str(exc))
        try:
            identity = stat_identity(validated)
        except FileNotFoundError as exc:
            return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
        except OSError as exc:
            return VerificationResult(status="verification_failed", error_kind="inspection_error", error=str(exc))
        if identity["is_symlink"]:
            return VerificationResult(status="verification_failed", error_kind="unexpected_symlink", error="target is a symlink")
        if not identity["is_regular"]:
            return VerificationResult(status="verification_failed", error_kind="not_regular_file", error="target is not a regular file")
        if identity["mode"] != 0o600:
            return VerificationResult(status="verification_failed", error_kind="unexpected_mode", error="mode is %o, expected 0600" % identity["mode"])
        if identity["nlink"] != 1:
            return VerificationResult(status="verification_failed", error_kind="unexpected_nlink", error="st_nlink is %d, expected 1" % identity["nlink"])
        try:
            actual = validated.read_bytes()
        except FileNotFoundError as exc:
            return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
        except OSError as exc:
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
        except PathPolicyError as exc:
            return RollbackResult(status="undo_failed", residual=True, error_kind="path_policy_violation", error=str(exc))
        expected_sha256 = undo_record.get("expected_sha256")
        try:
            removed = remove_file_if_owned(validated, expected_sha256=expected_sha256)
        except PathPolicyError as exc:
            return RollbackResult(status="undo_failed", residual=True, error_kind="ownership_mismatch", error=str(exc))
        except OSError as exc:
            return RollbackResult(status="undo_failed", residual=True, error_kind="os_error", error=str(exc))
        return RollbackResult(status="undone", residual=False, evidence={"path": str(validated), "removed": removed})

    def reconstruct_undo_record(self, step: StepRecord) -> Mapping[str, object]:
        return {"path": step.target, "expected_content": step.intent["content"], "expected_sha256": step.intent["content_sha256"]}

    def verify_postcondition(self, plan: ProvisioningPlan, context: ExecutionContext) -> VerificationResult:
        for step in plan.steps:
            path = Path(step.target)
            try:
                validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            except PathPolicyError as exc:
                return VerificationResult(status="verification_failed", error_kind="path_policy_violation", error=str(exc))
            try:
                identity = stat_identity(validated)
            except FileNotFoundError as exc:
                return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
            except OSError as exc:
                return VerificationResult(status="verification_failed", error_kind="inspection_error", error=str(exc))
            if identity["is_symlink"] or not identity["is_regular"]:
                return VerificationResult(status="verification_failed", error_kind="unexpected_file_type", error=str(validated))
            if identity["nlink"] != 1:
                return VerificationResult(status="verification_failed", error_kind="unexpected_nlink", error="st_nlink is %d, expected 1" % identity["nlink"])
            expected_sha256 = step.intent.get("content_sha256")
            try:
                actual_sha256 = hashlib.sha256(validated.read_bytes()).hexdigest()
            except FileNotFoundError as exc:
                return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
            except OSError as exc:
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
        except PathPolicyError as exc:
            return {"exists": None, "is_symlink": None, "content_matches": None, "path_policy_error": str(exc)}
        try:
            lstat_result = validated.lstat()
        except FileNotFoundError:
            return {"exists": False, "is_symlink": False, "content_matches": None}
        except OSError as exc:
            return {"exists": None, "is_symlink": None, "content_matches": None, "inspect_error": str(exc)}
        if stat.S_ISLNK(lstat_result.st_mode):
            return {"exists": True, "is_symlink": True, "content_matches": None}
        expected_sha256 = step.intent.get("content_sha256")
        try:
            actual_sha256 = hashlib.sha256(validated.read_bytes()).hexdigest()
        except FileNotFoundError:
            return {"exists": False, "is_symlink": False, "content_matches": None}
        except OSError as exc:
            return {"exists": True, "is_symlink": False, "content_matches": None, "inspect_error": str(exc)}
        return {"exists": True, "is_symlink": False, "content_matches": actual_sha256 == expected_sha256}


def _marker_content(capability_id: str) -> bytes:
    return ("watchdogvpn-canary-marker:%s" % capability_id).encode("ascii")


def _companion_content(capability_id: str, marker_content: bytes) -> bytes:
    return ("watchdogvpn-canary-companion:%s:%s" % (capability_id, hashlib.sha256(marker_content).hexdigest())).encode("ascii")
