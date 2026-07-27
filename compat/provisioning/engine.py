"""Transactional provisioning coordinator (Phase 23.7.5.6a).

Consumes an already-resolved, execution-ready ``ResolutionDecision`` from
``compat.dependency_resolution`` and a code-registered ``Executor`` to run a
plan/dry-run/apply/verify/rollback/recover/uninstall lifecycle with a durable
journal, a single machine-wide lock, deterministic idempotency and
ownership/provenance tracking. Never installs a real package, adds a real
repository or migrates any legacy consumer -- see
``docs/phase-23-7-5-compatibility-contract.md`` for the exact 23.7.5.6a scope.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import stat as stat_module
import uuid
from typing import Sequence

from compat.dependency_resolution import ResolutionDecision

from compat.provisioning import lock as lock_mod
from compat.provisioning import journal as journal_mod
from compat.provisioning.digest import compute_plan_digest, compute_uninstall_plan_digest
from compat.provisioning.errors import (
    ExecutionNotReadyError,
    ExecutorNotRegisteredError,
    IdentifierError,
    JournalError,
    PathPolicyError,
    ProvisioningError,
)
from compat.provisioning.executors import ExecutionContext, Executor, TrustedExecutorRegistry
from compat.provisioning.journal import StepRecord, TransactionJournal
from compat.provisioning.model import (
    ExecutionResult,
    OwnershipCandidate,
    OwnershipRecord,
    ProvisioningPlan,
    ProvisioningStep,
    RecoveryAction,
    RecoveryDecision,
    RollbackResult,
    StepState,
    TransactionState,
    UninstallPlan,
    VerificationResult,
)
from compat.provisioning.paths import remove_file_if_owned, stat_identity, validate_target_path

NEEDS_RECOVERY_ATTENTION = frozenset(
    {
        TransactionState.APPLYING,
        TransactionState.VERIFYING,
        TransactionState.ROLLING_BACK,
        TransactionState.RECOVERY_REQUIRED,
        TransactionState.RECOVERING,
        TransactionState.UNINSTALLING,
        TransactionState.ROLLBACK_FAILED,
        TransactionState.UNINSTALL_FAILED,
    }
)

UNDOABLE_STEP_STATES = frozenset(
    {StepState.APPLIED, StepState.VERIFYING, StepState.VERIFIED, StepState.VERIFY_FAILED}
)


class PrepareStatus(Enum):
    DRY_RUN = "dry_run"
    ALREADY_PRESENT = "already_present"
    ALREADY_PROVISIONED = "already_provisioned"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    OWNERSHIP_INVALID = "ownership_invalid"
    COMMITTED = "committed"
    PREPARATION_FAILED = "preparation_failed"
    ROLLBACK_FAILED = "rollback_failed"
    RECIPE_NOT_IMPLEMENTED = "recipe_not_implemented"
    OUT_OF_CONTRACT = "out_of_contract"
    OFFLINE = "offline"
    PENDING_RECOVERY = "pending_recovery_required"
    UNINSTALLED = "uninstalled"
    UNINSTALL_FAILED = "uninstall_failed"


@dataclass(frozen=True)
class PrepareOutcome:
    status: PrepareStatus
    plan: ProvisioningPlan | None
    transaction_id: str | None
    reason: str
    residuals: tuple[str, ...] = ()
    error_kind: str | None = None


@dataclass(frozen=True)
class ProvisioningEnvironment:
    state_root: Path
    registry: TrustedExecutorRegistry
    expected_executor_version: str
    context: ExecutionContext
    lock_timeout: float = lock_mod.DEFAULT_TIMEOUT_SECONDS


class IdempotencyOutcome(Enum):
    NOT_PRESENT = "not_present"
    ALREADY_PRESENT = "already_present"
    ALREADY_PROVISIONED = "already_provisioned"
    OWNERSHIP_CONFLICT = "ownership_conflict"


@dataclass(frozen=True)
class IdempotencyCheck:
    outcome: IdempotencyOutcome
    evidence: Sequence[dict]


# --------------------------------------------------------------------------
# Plan construction (also used, unchanged, for dry-run: it never mutates)
# --------------------------------------------------------------------------


def build_plan(
    decision: ResolutionDecision,
    *,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
) -> tuple[ProvisioningPlan, Executor]:
    if decision.resolution_status != "method_selected" or not decision.execution_ready:
        raise ExecutionNotReadyError(
            "decision is not execution-ready (resolution_status=%r execution_ready=%r)"
            % (decision.resolution_status, decision.execution_ready)
        )
    if not decision.selected_method_id or not decision.selected_method_kind:
        raise ExecutionNotReadyError("decision has no selected method to execute")
    executor = registry.resolve(
        method_kind=decision.selected_method_kind,
        method_id=decision.selected_method_id,
        expected_executor_version=expected_executor_version,
    )
    if executor.supported_method_kind != decision.selected_method_kind:
        raise ExecutorNotRegisteredError(
            "registered executor kind %r does not match decision method_kind %r"
            % (executor.supported_method_kind, decision.selected_method_kind)
        )
    resolved_target = decision.resolved_release or decision.resolved_distribution
    if resolved_target is None or decision.machine_architecture is None:
        raise ExecutionNotReadyError("decision is missing a concrete resolved target or architecture")

    steps = executor.plan_steps(capability_id=decision.capability_id, dependency_id=decision.dependency_id, context=context)
    selected_asset = dataclasses.asdict(decision.selected_asset) if decision.selected_asset is not None else None
    plan = ProvisioningPlan(
        capability_id=decision.capability_id,
        dependency_id=decision.dependency_id,
        resolved_target=resolved_target,
        architecture=decision.machine_architecture,
        support_classification=decision.support_classification,
        selected_method_id=decision.selected_method_id,
        selected_method_kind=decision.selected_method_kind,
        postcondition=executor.postcondition_description(),
        executor_id=executor.executor_id,
        executor_version=executor.executor_version,
        steps=steps,
        selected_asset=selected_asset,
    )
    return plan, executor


def describe_plan(plan: ProvisioningPlan) -> dict:
    return {
        "capability_id": plan.capability_id,
        "dependency_id": plan.dependency_id,
        "resolved_target": plan.resolved_target,
        "architecture": plan.architecture,
        "support_classification": plan.support_classification,
        "selected_method_id": plan.selected_method_id,
        "selected_method_kind": plan.selected_method_kind,
        "executor": {"id": plan.executor_id, "version": plan.executor_version},
        "postcondition": plan.postcondition,
        "plan_digest": compute_plan_digest(plan),
        "steps": [
            {"sequence": s.sequence, "step_id": s.step_id, "action_type": s.action_type, "target": s.target, "intent": dict(s.intent)}
            for s in plan.steps
        ],
        "planned_verification": (
            "each step verifies existence, exact content hash, permissions and absence of a symlink; "
            "the transaction also verifies its overall postcondition before committing"
        ),
        "planned_rollback": "on any failure, steps already applied are undone in reverse order using only their recorded undo_record",
    }


def dry_run(
    decision: ResolutionDecision,
    *,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
) -> dict:
    plan, _executor = build_plan(decision, registry=registry, expected_executor_version=expected_executor_version, context=context)
    return describe_plan(plan)


# --------------------------------------------------------------------------
# Ownership authority: no ownership record grants uninstall/idempotency
# authority unless it is traceable, in full, to one committed "prepare"
# transaction's own provenance (points 2 and 8-alternative).
# --------------------------------------------------------------------------


def _load_committed_source_journal(state_root: Path, transaction_id: str, *, capability_id: str) -> TransactionJournal | None:
    try:
        journal = journal_mod.read_journal(state_root, transaction_id)
    except (JournalError, IdentifierError):
        return None
    if journal.state != TransactionState.COMMITTED or journal.operation != "prepare" or journal.capability_id != capability_id:
        return None
    if not isinstance(journal.provenance, dict):
        return None
    return journal


def validate_ownership_authority(state_root: Path, capability_id: str, records: Sequence[OwnershipRecord]) -> bool:
    """Full-set-exact validation binding every product-owned record to one
    committed "prepare" transaction's own provenance. Never trusts a record
    in isolation -- an orphaned, partial or divergent record, or one bound to
    a non-committed/mismatched journal, invalidates the entire set."""
    owned = [record for record in records if record.product_owned]
    if not owned:
        return True

    transaction_ids = {record.created_by_transaction for record in owned}
    if len(transaction_ids) != 1 or None in transaction_ids:
        return False
    transaction_id = next(iter(transaction_ids))

    journal = _load_committed_source_journal(state_root, transaction_id, capability_id=capability_id)
    if journal is None:
        return False

    provenance_records = journal.provenance.get("ownership_records")
    if not isinstance(provenance_records, list):
        return False
    provenance_by_identity = {}
    for item in provenance_records:
        if not isinstance(item, dict) or "resource_identity" not in item:
            return False
        provenance_by_identity[item["resource_identity"]] = item

    if set(provenance_by_identity) != {record.candidate.resource_identity for record in owned}:
        return False

    for record in owned:
        expected = provenance_by_identity.get(record.candidate.resource_identity)
        if expected is None:
            return False
        if expected.get("integrity") != record.candidate.integrity:
            return False
        if expected.get("artifact_type") != record.candidate.artifact_type:
            return False
        if expected.get("executor_id") != record.executor_id or expected.get("executor_version") != record.executor_version:
            return False
        if expected.get("method_id") != record.candidate.method_id:
            return False
        if record.executor_id != journal.executor.get("id") or record.executor_version != journal.executor.get("version"):
            return False
        if record.candidate.method_id != journal.selected_method.get("id"):
            return False

    return True


# --------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------


def check_idempotency(
    plan: ProvisioningPlan,
    executor: Executor,
    context: ExecutionContext,
    *,
    existing_ownership: Sequence[OwnershipRecord],
    state_root: Path,
) -> IdempotencyCheck:
    inspections = []
    for step in plan.steps:
        record = StepRecord(sequence=step.sequence, step_id=step.step_id, action_type=step.action_type, state=StepState.PLANNED, intent=step.intent, target=step.target)
        observed = executor.inspect_step(record, context)
        inspections.append({"step_id": step.step_id, **dict(observed)})

    if any(item.get("path_policy_error") for item in inspections):
        return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)

    any_exist = any(item.get("exists") for item in inspections)
    if not any_exist:
        return IdempotencyCheck(IdempotencyOutcome.NOT_PRESENT, inspections)

    any_symlink = any(item.get("is_symlink") for item in inspections)
    any_mismatch = any(item.get("exists") and item.get("content_matches") is False for item in inspections)
    all_match = all(item.get("exists") and item.get("content_matches") is True for item in inspections)

    if any_symlink or any_mismatch or not all_match:
        return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)

    # Exact match only: same source (committed) transaction, same executor
    # id/version, same method, same number of resources, same paths, same
    # hashes, same uid/gid/mode, and a fully re-verified postcondition. A
    # partial match is a conflict, never a silent "close enough".
    owned_by_this_plan = [
        record
        for record in existing_ownership
        if record.product_owned
        and record.executor_id == executor.executor_id
        and record.executor_version == executor.executor_version
        and record.candidate.method_id == plan.selected_method_id
    ]
    if not owned_by_this_plan:
        return IdempotencyCheck(IdempotencyOutcome.ALREADY_PRESENT, inspections)
    if len(owned_by_this_plan) != len(plan.steps):
        return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)

    if not validate_ownership_authority(state_root, plan.capability_id, owned_by_this_plan):
        return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)

    expected_targets = {step.target for step in plan.steps}
    owned_targets = {record.candidate.resource_identity for record in owned_by_this_plan}
    if expected_targets != owned_targets:
        return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)

    intent_by_target = {step.target: step.intent for step in plan.steps}
    for record in owned_by_this_plan:
        expected_sha256 = intent_by_target.get(record.candidate.resource_identity, {}).get("content_sha256")
        if record.candidate.integrity != expected_sha256:
            return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)
        try:
            identity = stat_identity(Path(record.candidate.resource_identity))
        except OSError:
            return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)
        if record.candidate.uid is not None and record.candidate.uid != identity["uid"]:
            return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)
        if record.candidate.gid is not None and record.candidate.gid != identity["gid"]:
            return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)
        if record.candidate.mode is not None and record.candidate.mode != identity["mode"]:
            return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)

    postcondition = _safe_postcondition(executor, plan, context)
    if postcondition.status != "verified":
        return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)

    return IdempotencyCheck(IdempotencyOutcome.ALREADY_PROVISIONED, inspections)


# --------------------------------------------------------------------------
# Safe executor call wrappers -- a misbehaving executor can never crash the
# coordinator or corrupt the journal; every failure becomes error_kind
# "executor_error" instead of an unhandled exception.
# --------------------------------------------------------------------------


def _safe_inspect(executor: Executor, record: StepRecord, context: ExecutionContext) -> dict:
    try:
        return dict(executor.inspect_step(record, context))
    except Exception as exc:  # noqa: BLE001 - defensive boundary around untrusted executor code
        return {"exists": None, "is_symlink": None, "content_matches": None, "inspect_error": str(exc)}


def _safe_apply(executor: Executor, record: StepRecord, context: ExecutionContext) -> ExecutionResult:
    try:
        return executor.apply_step(record, context)
    except Exception as exc:  # noqa: BLE001
        return ExecutionResult(status="apply_failed", error_kind="executor_error", error=str(exc))


def _safe_verify(executor: Executor, record: StepRecord, result: ExecutionResult, context: ExecutionContext) -> VerificationResult:
    try:
        return executor.verify_step(record, result, context)
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(status="verification_failed", error_kind="executor_error", error=str(exc))


def _safe_undo(executor: Executor, record: StepRecord, execution: ExecutionResult, context: ExecutionContext) -> RollbackResult:
    try:
        return executor.undo_step(record, execution, context)
    except Exception as exc:  # noqa: BLE001
        return RollbackResult(status="undo_failed", residual=True, error_kind="executor_error", error=str(exc))


def _safe_postcondition(executor: Executor, plan: ProvisioningPlan, context: ExecutionContext) -> VerificationResult:
    try:
        return executor.verify_postcondition(plan, context)
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(status="verification_failed", error_kind="executor_error", error=str(exc))


# --------------------------------------------------------------------------
# Apply loop (also used, resume-aware, by recovery)
# --------------------------------------------------------------------------


def _run_apply_loop(state_root: Path, journal: TransactionJournal, plan: ProvisioningPlan, executor: Executor, context: ExecutionContext, signaled) -> tuple[TransactionJournal, bool]:
    now = context.now
    for step in plan.steps:
        record = journal.step(step.sequence)

        if record.state == StepState.VERIFIED:
            continue

        if signaled.value and record.state == StepState.PLANNED:
            record = record.with_state(StepState.APPLYING, started_at=now())
            record = record.with_state(StepState.APPLY_FAILED, completed_at=now(), error_kind="interrupted", error="interrupted before this step began")
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            return journal, False
        if signaled.value:
            return journal, False

        if record.state == StepState.PLANNED:
            before_state = _safe_inspect(executor, record, context)
            record = record.with_state(StepState.APPLYING, started_at=now(), before_state=before_state)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)  # write-ahead: durable before the irreversible action
            result = _safe_apply(executor, record, context)
        elif record.state == StepState.APPLYING:
            observed = _safe_inspect(executor, record, context)
            if observed.get("path_policy_error"):
                raise ProvisioningError("step %s failed path policy during resume inspection: %s" % (record.step_id, observed["path_policy_error"]))
            if observed.get("is_symlink"):
                raise ProvisioningError("step %s is ambiguous for resume: unexpected symlink" % record.step_id)
            if observed.get("exists") and observed.get("content_matches") is True:
                result = ExecutionResult(status="applied", undo_record=executor.reconstruct_undo_record(record))
            elif not observed.get("exists"):
                if not executor.step_is_replay_safe(record):
                    raise ProvisioningError("step %s is not declared replay-safe; cannot resume automatically" % record.step_id)
                result = _safe_apply(executor, record, context)
            else:
                raise ProvisioningError("step %s content diverged from what was recorded; ambiguous for resume" % record.step_id)
        elif record.state in (StepState.APPLIED, StepState.VERIFYING):
            # Crashed after the action succeeded (APPLIED durably recorded)
            # but before, or exactly during, the VERIFYING transition write.
            # Either way the action itself already completed; only
            # verification needs to be (re)done.
            result = ExecutionResult(status="applied", undo_record=record.undo_record or executor.reconstruct_undo_record(record))
        else:
            raise ProvisioningError("step %s is in an unexpected state for apply resume: %s" % (record.step_id, record.state.value))

        if result.status != "applied":
            record = record.with_state(StepState.APPLY_FAILED, completed_at=now(), error_kind=result.error_kind, error=result.error)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            return journal, False

        if record.state == StepState.APPLYING:
            record = record.with_state(StepState.APPLIED, completed_at=now(), undo_record=result.undo_record)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)  # durable after the action, with undo_record
            if signaled.value:
                return journal, False
            record = record.with_state(StepState.VERIFYING)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
        elif record.state == StepState.APPLIED:
            record = record.with_state(StepState.VERIFYING)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
        # else record.state == StepState.VERIFYING already: proceed straight to verify.

        verification = _safe_verify(executor, record, result, context)
        if verification.status != "verified":
            record = record.with_state(
                StepState.VERIFY_FAILED, completed_at=now(), verification=verification.evidence,
                error_kind=verification.error_kind, error=verification.error,
            )
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            return journal, False

        record = record.with_state(StepState.VERIFIED, completed_at=now(), verification=verification.evidence)
        journal = journal.with_step(record)
        journal_mod.write_journal(state_root, journal)  # durable after verify

    return journal, True


def _run_rollback(state_root: Path, journal: TransactionJournal, executor: Executor, context: ExecutionContext) -> tuple[TransactionJournal, bool, list[str]]:
    now = context.now
    residuals: list[str] = []
    for step_record in sorted(journal.steps, key=lambda item: item.sequence, reverse=True):
        current = journal.step(step_record.sequence)
        if current.state not in UNDOABLE_STEP_STATES:
            continue
        record = current.with_state(StepState.UNDOING)
        journal = journal.with_step(record)
        journal_mod.write_journal(state_root, journal)

        execution = ExecutionResult(status="applied", undo_record=record.undo_record or {})
        result = _safe_undo(executor, record, execution, context)

        if result.status == "undone":
            record = record.with_state(StepState.UNDONE, completed_at=now())
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
        else:
            record = record.with_state(StepState.UNDO_FAILED, completed_at=now(), error_kind=result.error_kind, error=result.error)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            residuals.append(record.step_id)
    return journal, not residuals, residuals


def _finalize_provenance(state_root: Path, journal: TransactionJournal, plan: ProvisioningPlan, executor: Executor, now_value: str) -> dict:
    records = []
    for step in journal.steps:
        undo_record = step.undo_record or {}
        resource_identity = undo_record.get("path", step.target or "")
        try:
            identity = stat_identity(Path(resource_identity))
        except OSError:
            identity = {"uid": None, "gid": None, "mode": None}
        candidate = OwnershipCandidate(
            artifact_type="file",
            resource_identity=resource_identity,
            pre_existing=False,
            method_id=plan.selected_method_id,
            integrity=undo_record.get("expected_sha256"),
            uid=identity.get("uid"),
            gid=identity.get("gid"),
            mode=identity.get("mode"),
            post_install_fingerprint=undo_record.get("expected_sha256"),
        )
        records.append(
            OwnershipRecord(
                capability_id=plan.capability_id,
                candidate=candidate,
                product_owned=True,
                created_by_transaction=journal.transaction_id,
                executor_id=plan.executor_id,
                executor_version=plan.executor_version,
                recorded_at=now_value,
            )
        )
    journal_mod.write_ownership_records(state_root, plan.capability_id, records)
    return {
        "transaction_id": journal.transaction_id,
        "committed_at": now_value,
        "ownership_records": [
            {
                "resource_identity": r.candidate.resource_identity,
                "artifact_type": r.candidate.artifact_type,
                "integrity": r.candidate.integrity,
                "uid": r.candidate.uid,
                "gid": r.candidate.gid,
                "mode": r.candidate.mode,
                "executor_id": r.executor_id,
                "executor_version": r.executor_version,
                "method_id": r.candidate.method_id,
            }
            for r in records
        ],
    }


# --------------------------------------------------------------------------
# prepare()
# --------------------------------------------------------------------------


def _new_transaction_id() -> str:
    return uuid.uuid4().hex


def _initial_journal(plan: ProvisioningPlan, *, transaction_id: str, now_value: str) -> TransactionJournal:
    return TransactionJournal(
        schema_version=journal_mod.SCHEMA_VERSION,
        transaction_id=transaction_id,
        operation="prepare",
        state=TransactionState.PLANNED,
        created_at=now_value,
        updated_at=now_value,
        plan_digest=compute_plan_digest(plan),
        capability_id=plan.capability_id,
        dependency_id=plan.dependency_id,
        target=plan.resolved_target,
        architecture=plan.architecture,
        support_classification=plan.support_classification,
        selected_method={"id": plan.selected_method_id, "kind": plan.selected_method_kind},
        executor={"id": plan.executor_id, "version": plan.executor_version},
        steps=tuple(
            StepRecord(sequence=s.sequence, step_id=s.step_id, action_type=s.action_type, state=StepState.PLANNED, intent=s.intent, target=s.target)
            for s in plan.steps
        ),
        selected_asset=plan.selected_asset,
    )


def prepare(decision: ResolutionDecision, env: ProvisioningEnvironment, *, apply: bool) -> PrepareOutcome:
    try:
        plan, executor = build_plan(decision, registry=env.registry, expected_executor_version=env.expected_executor_version, context=env.context)
    except ExecutorNotRegisteredError as exc:
        return PrepareOutcome(PrepareStatus.RECIPE_NOT_IMPLEMENTED, None, None, str(exc), error_kind="recipe_not_implemented")
    except ExecutionNotReadyError as exc:
        return PrepareOutcome(PrepareStatus.OUT_OF_CONTRACT, None, None, str(exc), error_kind="execution_not_ready")

    if not apply:
        return PrepareOutcome(PrepareStatus.DRY_RUN, plan, None, "dry-run: plan constructed, nothing mutated")

    if executor.declares_network_required() and not _network_available(env.context):
        return PrepareOutcome(PrepareStatus.OFFLINE, plan, None, "capability requires network and none is available", error_kind="offline")

    transaction_id = _new_transaction_id()
    with lock_mod.acquire_provisioner_lock(journal_mod.lock_path(env.state_root), transaction_id=transaction_id, timeout=env.lock_timeout):
        recovery_reports = _recover_pending_locked(env.state_root, env.registry, env.expected_executor_version, env.context)
        blocking = [item for item in recovery_reports if item.action == RecoveryAction.REQUIRE_MANUAL]
        if blocking:
            return PrepareOutcome(
                PrepareStatus.PENDING_RECOVERY, plan, None,
                "cannot start a new transaction while others require manual recovery: %s" % [item.transaction_id for item in blocking],
                error_kind="recovery_required",
            )

        existing_ownership = journal_mod.read_ownership_records(env.state_root, plan.capability_id)
        idempotency = check_idempotency(plan, executor, env.context, existing_ownership=existing_ownership, state_root=env.state_root)
        if idempotency.outcome == IdempotencyOutcome.ALREADY_PRESENT:
            return PrepareOutcome(PrepareStatus.ALREADY_PRESENT, plan, None, "capability already present before WatchdogVPN; no write performed, no uninstall right granted")
        if idempotency.outcome == IdempotencyOutcome.ALREADY_PROVISIONED:
            return PrepareOutcome(PrepareStatus.ALREADY_PROVISIONED, plan, None, "identity/version/hash/executor/postcondition already match; no duplication")
        if idempotency.outcome == IdempotencyOutcome.OWNERSHIP_CONFLICT:
            return PrepareOutcome(
                PrepareStatus.OWNERSHIP_CONFLICT, plan, None,
                "an existing but divergent component was found: %r" % (idempotency.evidence,),
                error_kind="ownership_conflict",
            )

        now = env.context.now
        journal = _initial_journal(plan, transaction_id=transaction_id, now_value=now())
        journal_mod.write_journal(env.state_root, journal)
        journal = journal.with_state(TransactionState.AUTHORIZED, now=now())
        journal_mod.write_journal(env.state_root, journal)
        journal = journal.with_state(TransactionState.APPLYING, now=now())
        journal_mod.write_journal(env.state_root, journal)

        journal, apply_ok = _apply_and_verify(env.state_root, journal, plan, executor, env.context)
        return _finish_prepare(env.state_root, journal, plan, executor, env.context, apply_ok, transaction_id)


def _apply_and_verify(state_root: Path, journal: TransactionJournal, plan: ProvisioningPlan, executor: Executor, context: ExecutionContext) -> tuple[TransactionJournal, bool]:
    with _interruption_guard() as signaled:
        journal, apply_ok = _run_apply_loop(state_root, journal, plan, executor, context, signaled)
    if not apply_ok:
        return journal, False

    now = context.now
    if journal.state != TransactionState.VERIFYING:
        journal = journal.with_state(TransactionState.VERIFYING, now=now())
        journal_mod.write_journal(state_root, journal)
    postcondition = _safe_postcondition(executor, plan, context)
    if postcondition.status != "verified":
        journal = journal.with_state(
            TransactionState.ROLLING_BACK, now=now(),
            failure={"reason": "postcondition_verification_failed", "error_kind": postcondition.error_kind, "error": postcondition.error, **dict(postcondition.evidence)},
        )
        journal_mod.write_journal(state_root, journal)
        return journal, False
    return journal, True


def _finish_prepare(state_root: Path, journal: TransactionJournal, plan: ProvisioningPlan, executor: Executor, context: ExecutionContext, apply_ok: bool, transaction_id: str) -> PrepareOutcome:
    now = context.now
    if apply_ok:
        provenance = _finalize_provenance(state_root, journal, plan, executor, now())
        journal = journal.with_state(TransactionState.COMMITTED, now=now(), provenance=provenance)
        journal_mod.write_journal(state_root, journal)
        return PrepareOutcome(PrepareStatus.COMMITTED, plan, transaction_id, "provisioned and verified")

    if journal.state != TransactionState.ROLLING_BACK:
        journal = journal.with_state(TransactionState.ROLLING_BACK, now=now())
        journal_mod.write_journal(state_root, journal)

    journal, rollback_ok, residuals = _run_rollback(state_root, journal, executor, context)
    if rollback_ok:
        journal = journal.with_state(TransactionState.ROLLED_BACK, now=now())
        journal_mod.write_journal(state_root, journal)
        journal = journal.with_state(TransactionState.PREPARATION_FAILED, now=now())
        journal_mod.write_journal(state_root, journal)
        return PrepareOutcome(PrepareStatus.PREPARATION_FAILED, plan, transaction_id, "provisioning failed; rollback completed cleanly", residuals=())

    journal = journal.with_state(TransactionState.ROLLBACK_FAILED, now=now(), failure={**(journal.failure or {}), "residuals": residuals})
    journal_mod.write_journal(state_root, journal)
    return PrepareOutcome(PrepareStatus.ROLLBACK_FAILED, plan, transaction_id, "rollback did not complete cleanly", residuals=tuple(residuals), error_kind="rollback_failed")


def _network_available(context: ExecutionContext) -> bool:
    if context.network_available is None:
        return True
    return bool(context.network_available())


# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------


class _SignalFlag:
    def __init__(self) -> None:
        self.value = False
        self.signal_name: str | None = None


def _interruption_guard():
    import signal

    flag = _SignalFlag()

    def handler(signum, _frame):
        flag.value = True
        flag.signal_name = signal.Signals(signum).name

    from contextlib import contextmanager

    @contextmanager
    def _guard():
        previous = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, handler)
        try:
            yield flag
        finally:
            for sig, old_handler in previous.items():
                signal.signal(sig, old_handler)

    return _guard()


# --------------------------------------------------------------------------
# Recovery
# --------------------------------------------------------------------------


class _Verdict(Enum):
    RESUME_APPLY = "resume_apply"
    RESUME_ROLLBACK = "resume_rollback"
    AMBIGUOUS = "ambiguous"


def recover_pending(
    state_root: Path,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
    *,
    lock_timeout: float = lock_mod.DEFAULT_TIMEOUT_SECONDS,
) -> list[RecoveryDecision]:
    """Public recovery entry point. Acquires the single machine-wide
    provisioner lock itself for the whole recovery pass and releases it in a
    ``finally`` -- recovery must never run concurrently with another
    recovery pass, nor with a ``prepare()``/``uninstall()`` in progress.
    ``prepare()``/``uninstall()`` call the internal ``_recover_pending_locked``
    directly since they already hold this same lock."""
    transaction_id = "recovery-%s" % _new_transaction_id()
    with lock_mod.acquire_provisioner_lock(journal_mod.lock_path(state_root), transaction_id=transaction_id, timeout=lock_timeout):
        return _recover_pending_locked(state_root, registry, expected_executor_version, context)


def _recover_pending_locked(
    state_root: Path,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
) -> list[RecoveryDecision]:
    """Internal recovery pass. Callers MUST already hold the provisioner
    lock -- this function never acquires it itself."""
    decisions: list[RecoveryDecision] = []
    for transaction_id in journal_mod.list_transaction_ids(state_root):
        try:
            journal = journal_mod.read_journal(state_root, transaction_id)
        except Exception as exc:  # noqa: BLE001 - corrupt/unknown-schema journal is itself the finding
            decisions.append(RecoveryDecision(transaction_id, RecoveryAction.REQUIRE_MANUAL, "journal is unreadable/invalid: %s" % exc))
            continue
        if journal.state not in NEEDS_RECOVERY_ATTENTION:
            continue
        decisions.append(_recover_one(state_root, journal, registry, expected_executor_version, context))
    return decisions


def _recover_one(
    state_root: Path,
    journal: TransactionJournal,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
) -> RecoveryDecision:
    now = context.now

    if journal.state in (TransactionState.ROLLBACK_FAILED, TransactionState.UNINSTALL_FAILED):
        if journal.state == TransactionState.ROLLBACK_FAILED:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "a previous rollback attempt already failed; manual review required"})
        else:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "a previous uninstall attempt already failed; manual review required"})
        journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, journal.recovery["reason"])

    if journal.operation == "uninstall":
        # Uninstall journals carry a synthetic selected_method ("uninstall")
        # that is never registered in the trusted executor registry -- an
        # uninstall's own recovery never dispatches through an Executor at
        # all (see _run_uninstall_loop), so it must never attempt to
        # resolve one.
        return _recover_uninstall(state_root, journal, context)

    try:
        executor = registry.resolve(
            method_kind=journal.selected_method["kind"],
            method_id=journal.selected_method["id"],
            expected_executor_version=journal.executor.get("version", expected_executor_version),
        )
    except ExecutorNotRegisteredError as exc:
        if journal.state != TransactionState.RECOVERY_REQUIRED:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": str(exc)})
            journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, str(exc))

    try:
        steps = executor.plan_steps(capability_id=journal.capability_id, dependency_id=journal.dependency_id, context=context)
        plan = ProvisioningPlan(
            capability_id=journal.capability_id,
            dependency_id=journal.dependency_id,
            resolved_target=journal.target,
            architecture=journal.architecture,
            support_classification=journal.support_classification,
            selected_method_id=journal.selected_method["id"],
            selected_method_kind=journal.selected_method["kind"],
            postcondition=executor.postcondition_description(),
            executor_id=journal.executor["id"],
            executor_version=journal.executor["version"],
            steps=steps,
            selected_asset=journal.selected_asset,
        )
    except (ValueError, KeyError) as exc:
        if journal.state != TransactionState.RECOVERY_REQUIRED:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "cannot rebuild plan for recovery: %s" % exc})
            journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "cannot rebuild plan for recovery: %s" % exc)

    if compute_plan_digest(plan) != journal.plan_digest:
        if journal.state != TransactionState.RECOVERY_REQUIRED:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "plan_digest_mismatch"})
            journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "plan_digest no longer matches the journal")

    verdict, reason = _inspect_recovery_boundary(journal, executor, context)
    if verdict == _Verdict.AMBIGUOUS:
        if journal.state != TransactionState.RECOVERY_REQUIRED:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": reason})
            journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, reason)

    if journal.state == TransactionState.RECOVERY_REQUIRED:
        journal = journal.with_state(TransactionState.RECOVERING, now=now())
        journal_mod.write_journal(state_root, journal)

    if verdict == _Verdict.RESUME_APPLY:
        if journal.state == TransactionState.RECOVERING:
            journal = journal.with_state(TransactionState.APPLYING, now=now())
            journal_mod.write_journal(state_root, journal)
        journal, apply_ok = _apply_and_verify(state_root, journal, plan, executor, context)
        if apply_ok:
            provenance = _finalize_provenance(state_root, journal, plan, executor, now())
            journal = journal.with_state(TransactionState.COMMITTED, now=now(), provenance=provenance)
            journal_mod.write_journal(state_root, journal)
            return RecoveryDecision(journal.transaction_id, RecoveryAction.RESUME, "resumed and committed")
        # _apply_and_verify already drove the journal into ROLLING_BACK on failure.
        journal, rollback_ok, residuals = _run_rollback(state_root, journal, executor, context)
        return _finalize_recovery_rollback(state_root, journal, rollback_ok, residuals)

    # RESUME_ROLLBACK
    if journal.state == TransactionState.RECOVERING:
        journal = journal.with_state(TransactionState.ROLLING_BACK, now=now())
        journal_mod.write_journal(state_root, journal)
    journal, rollback_ok, residuals = _run_rollback(state_root, journal, executor, context)
    return _finalize_recovery_rollback(state_root, journal, rollback_ok, residuals)


def _finalize_recovery_rollback(state_root: Path, journal: TransactionJournal, rollback_ok: bool, residuals: list[str]) -> RecoveryDecision:
    now = journal.updated_at
    if rollback_ok:
        journal = journal.with_state(TransactionState.ROLLED_BACK, now=now)
        journal_mod.write_journal(state_root, journal)
        journal = journal.with_state(TransactionState.PREPARATION_FAILED, now=now)
        journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.ROLLBACK, "resumed rollback completed cleanly")
    journal = journal.with_state(TransactionState.ROLLBACK_FAILED, now=now, failure={**(journal.failure or {}), "residuals": residuals})
    journal_mod.write_journal(state_root, journal)
    return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "rollback did not complete cleanly during recovery; residuals: %s" % residuals)


def _inspect_recovery_boundary(journal: TransactionJournal, executor: Executor, context: ExecutionContext) -> tuple[_Verdict, str]:
    if journal.state == TransactionState.ROLLING_BACK:
        for step in journal.steps:
            if step.state == StepState.UNDOING:
                observed = _safe_inspect(executor, step, context)
                if observed.get("path_policy_error"):
                    return _Verdict.AMBIGUOUS, "step %s failed path policy during rollback recovery: %s" % (step.step_id, observed["path_policy_error"])
                if observed.get("is_symlink"):
                    return _Verdict.AMBIGUOUS, "step %s shows an unexpected symlink during rollback recovery" % step.step_id
                if observed.get("exists") and observed.get("content_matches") is False:
                    return _Verdict.AMBIGUOUS, "step %s content diverged from its recorded undo_record" % step.step_id
        return _Verdict.RESUME_ROLLBACK, "resuming rollback already in progress"

    if journal.state in (TransactionState.APPLYING, TransactionState.RECOVERY_REQUIRED, TransactionState.RECOVERING):
        for step in journal.steps:
            if step.state in (StepState.APPLY_FAILED, StepState.VERIFY_FAILED):
                return _Verdict.RESUME_ROLLBACK, "step %s already failed; resuming by completing rollback" % step.step_id
            if step.state == StepState.UNDOING:
                return _Verdict.RESUME_ROLLBACK, "step %s was mid-undo; resuming rollback" % step.step_id
            if step.state == StepState.APPLYING:
                observed = _safe_inspect(executor, step, context)
                if observed.get("path_policy_error"):
                    return _Verdict.AMBIGUOUS, "step %s failed path policy during recovery inspection: %s" % (step.step_id, observed["path_policy_error"])
                if observed.get("is_symlink"):
                    return _Verdict.AMBIGUOUS, "step %s shows an unexpected symlink" % step.step_id
                if not observed.get("exists"):
                    if not executor.step_is_replay_safe(step):
                        return _Verdict.AMBIGUOUS, "step %s did not complete and is not declared replay-safe" % step.step_id
                    return _Verdict.RESUME_APPLY, "step %s did not complete; safe to retry from scratch" % step.step_id
                if observed.get("content_matches") is True:
                    return _Verdict.RESUME_APPLY, "step %s already completed before the interruption; resuming forward" % step.step_id
                return _Verdict.AMBIGUOUS, "step %s exists but its content does not match what was expected" % step.step_id
            if step.state == StepState.VERIFYING:
                return _Verdict.RESUME_APPLY, "step %s applied; only verification needs to be redone" % step.step_id
        return _Verdict.RESUME_APPLY, "no step in progress; resuming forward"

    if journal.state == TransactionState.VERIFYING:
        return _Verdict.RESUME_APPLY, "resuming transaction-level postcondition verification"

    if journal.state == TransactionState.UNINSTALLING:
        for step in journal.steps:
            if step.state == StepState.APPLYING:
                observed = _safe_inspect(executor, step, context)
                if observed.get("path_policy_error"):
                    return _Verdict.AMBIGUOUS, "step %s failed path policy during uninstall recovery: %s" % (step.step_id, observed["path_policy_error"])
                if observed.get("is_symlink"):
                    return _Verdict.AMBIGUOUS, "step %s shows an unexpected symlink during uninstall recovery" % step.step_id
        return _Verdict.RESUME_ROLLBACK, "resuming uninstall in progress"

    return _Verdict.AMBIGUOUS, "unrecognized transaction state for recovery: %s" % journal.state.value


def _recover_uninstall(state_root: Path, journal: TransactionJournal, context: ExecutionContext) -> RecoveryDecision:
    now = context.now
    for step in journal.steps:
        if step.state == StepState.VERIFY_FAILED or step.state == StepState.APPLY_FAILED:
            if journal.state != TransactionState.RECOVERY_REQUIRED:
                journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "an uninstall step already failed; manual review required"})
                journal_mod.write_journal(state_root, journal)
            return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "an uninstall step already failed")
    if journal.state == TransactionState.RECOVERY_REQUIRED:
        journal = journal.with_state(TransactionState.RECOVERING, now=now())
        journal_mod.write_journal(state_root, journal)
        journal = journal.with_state(TransactionState.UNINSTALLING, now=now())
        journal_mod.write_journal(state_root, journal)
    journal, ok, residuals = _run_uninstall_loop(state_root, journal, context)
    if ok:
        journal = journal.with_state(TransactionState.UNINSTALLED, now=now())
        journal_mod.write_journal(state_root, journal)
        journal_mod.delete_ownership_records(state_root, journal.capability_id)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.RESUME, "resumed uninstall and completed")
    journal = journal.with_state(TransactionState.UNINSTALL_FAILED, now=now(), failure={"residuals": residuals})
    journal_mod.write_journal(state_root, journal)
    return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "uninstall did not complete for all resources during recovery")


# --------------------------------------------------------------------------
# Uninstall
# --------------------------------------------------------------------------


def _build_uninstall_plan(capability_id: str, owned: Sequence[OwnershipRecord]) -> UninstallPlan:
    steps = tuple(
        ProvisioningStep(
            sequence=index,
            step_id="uninstall_%d" % index,
            action_type="remove_file",
            intent={"resource_identity": record.candidate.resource_identity, "expected_sha256": record.candidate.integrity},
            target=record.candidate.resource_identity,
        )
        for index, record in enumerate(reversed(list(owned)))
    )
    return UninstallPlan(
        capability_id=capability_id,
        transaction_id=_new_transaction_id(),
        target_transaction_id=owned[0].created_by_transaction or "",
        ownership_records=tuple(owned),
        steps=steps,
    )


def _uninstall_source_matches(state_root: Path, journal: TransactionJournal) -> bool:
    """Re-derives the uninstall plan from the CURRENT ownership file (still
    intact until the uninstall fully completes) and confirms both that it is
    still traceable to a committed source transaction, and that its digest
    still matches what this journal recorded when it was created -- a
    divergence in either direction means recovery, never a blind unlink."""
    owned = [record for record in journal_mod.read_ownership_records(state_root, journal.capability_id) if record.product_owned]
    if not owned:
        return False
    if not validate_ownership_authority(state_root, journal.capability_id, owned):
        return False
    try:
        candidate_plan = _build_uninstall_plan(journal.capability_id, owned)
    except ValueError:
        return False
    return compute_uninstall_plan_digest(candidate_plan) == journal.plan_digest


def _initial_uninstall_journal(plan: UninstallPlan, *, now_value: str) -> TransactionJournal:
    return TransactionJournal(
        schema_version=journal_mod.SCHEMA_VERSION,
        transaction_id=plan.transaction_id,
        operation="uninstall",
        state=TransactionState.UNINSTALL_PLANNED,
        created_at=now_value,
        updated_at=now_value,
        plan_digest=compute_uninstall_plan_digest(plan),
        capability_id=plan.capability_id,
        dependency_id="unspecified",
        target=plan.target_transaction_id or "n/a",
        architecture="n/a",
        support_classification="n/a",
        selected_method={"id": "uninstall", "kind": "uninstall"},
        executor={"id": "uninstall", "version": "1"},
        steps=tuple(
            StepRecord(sequence=s.sequence, step_id=s.step_id, action_type=s.action_type, state=StepState.PLANNED, intent=s.intent, target=s.target)
            for s in plan.steps
        ),
    )


def _mark_uninstall_step_failed(record: StepRecord, error_kind: str, error: str, *, now_value: str) -> StepRecord:
    if record.state == StepState.PLANNED:
        record = record.with_state(StepState.APPLYING, started_at=now_value)
    return record.with_state(StepState.APPLY_FAILED, completed_at=now_value, error_kind=error_kind, error=error)


def _run_uninstall_loop(state_root: Path, journal: TransactionJournal, context: ExecutionContext) -> tuple[TransactionJournal, bool, list[str]]:
    """Explicit boundary-by-boundary uninstall state machine:

    PLANNED       -> write-ahead APPLYING, then attempt the unlink.
    APPLYING      -> (resume) inspect real state first: absent means the
                     unlink most likely already landed (or nothing was ever
                     there) -- go straight to APPLIED, never re-unlink;
                     present-and-matching means retry the unlink; a symlink
                     or hash divergence is a failure, never a silent delete.
    APPLIED       -> never re-executes the unlink: APPLIED -> VERIFYING only.
    VERIFYING     -> verifies ONLY absence; never re-attempts removal.
    """
    now = context.now
    if not _uninstall_source_matches(state_root, journal):
        return journal, False, ["plan_digest_mismatch"]

    residuals: list[str] = []
    ok = True
    for step in journal.steps:
        record = journal.step(step.sequence)
        if record.state == StepState.VERIFIED:
            continue

        path = Path(record.intent["resource_identity"])
        try:
            validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
        except PathPolicyError as exc:
            record = _mark_uninstall_step_failed(record, "path_policy_violation", str(exc), now_value=now())
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            residuals.append(record.step_id)
            ok = False
            continue

        expected_sha256 = record.intent.get("expected_sha256")

        if record.state == StepState.PLANNED:
            record = record.with_state(StepState.APPLYING, started_at=now())
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)  # write-ahead before the irreversible unlink

        if record.state == StepState.APPLYING:
            try:
                lstat_result = os.lstat(validated)
            except OSError:
                exists = False
                is_symlink = False
            else:
                exists = True
                is_symlink = stat_module.S_ISLNK(lstat_result.st_mode)

            if not exists:
                # Already gone: either a prior crashed attempt already
                # completed the unlink, or there was never anything here.
                # Either way, never attempt to unlink an absent path again.
                record = record.with_state(StepState.APPLIED, completed_at=now())
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
            elif is_symlink:
                record = _mark_uninstall_step_failed(record, "unexpected_symlink", "target is a symlink during uninstall recovery", now_value=now())
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                residuals.append(record.step_id)
                ok = False
                continue
            else:
                try:
                    remove_file_if_owned(validated, expected_sha256=expected_sha256)
                except Exception as exc:  # noqa: BLE001 - ownership drift or OS error must not raise out of the loop
                    record = _mark_uninstall_step_failed(record, "ownership_drift", str(exc), now_value=now())
                    journal = journal.with_step(record)
                    journal_mod.write_journal(state_root, journal)
                    residuals.append(record.step_id)
                    ok = False
                    continue
                record = record.with_state(StepState.APPLIED, completed_at=now())
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)

        if record.state == StepState.APPLIED:
            record = record.with_state(StepState.VERIFYING)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)

        # VERIFYING: verify ONLY absence -- never re-attempt removal here.
        if validated.is_symlink() or validated.exists():
            record = record.with_state(StepState.VERIFY_FAILED, completed_at=now(), error_kind="residual", error="path still exists after removal")
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            residuals.append(record.step_id)
            ok = False
            continue

        record = record.with_state(StepState.VERIFIED, completed_at=now(), verification={"removed": True})
        journal = journal.with_step(record)
        journal_mod.write_journal(state_root, journal)
    return journal, ok, residuals


def uninstall(capability_id: str, env: ProvisioningEnvironment, *, apply: bool) -> PrepareOutcome:
    owned = [record for record in journal_mod.read_ownership_records(env.state_root, capability_id) if record.product_owned]
    if not owned:
        return PrepareOutcome(
            PrepareStatus.OUT_OF_CONTRACT, None, None,
            "no product-owned resources recorded for capability %s; nothing to uninstall" % capability_id,
            error_kind="nothing_to_uninstall",
        )
    if not validate_ownership_authority(env.state_root, capability_id, owned):
        return PrepareOutcome(
            PrepareStatus.OWNERSHIP_INVALID, None, None,
            "ownership records for capability %s do not correspond, in full, to any committed transaction; refusing to uninstall" % capability_id,
            error_kind="ownership_invalid",
        )

    if not apply:
        return PrepareOutcome(PrepareStatus.DRY_RUN, None, None, "uninstall dry-run: %d resource(s) would be removed" % len(owned))

    transaction_id = _new_transaction_id()
    with lock_mod.acquire_provisioner_lock(journal_mod.lock_path(env.state_root), transaction_id=transaction_id, timeout=env.lock_timeout):
        recovery_reports = _recover_pending_locked(env.state_root, env.registry, env.expected_executor_version, env.context)
        blocking = [item for item in recovery_reports if item.action == RecoveryAction.REQUIRE_MANUAL]
        if blocking:
            return PrepareOutcome(
                PrepareStatus.PENDING_RECOVERY, None, None,
                "cannot uninstall while others require manual recovery: %s" % [item.transaction_id for item in blocking],
                error_kind="recovery_required",
            )

        owned = [record for record in journal_mod.read_ownership_records(env.state_root, capability_id) if record.product_owned]
        if not owned:
            return PrepareOutcome(PrepareStatus.OUT_OF_CONTRACT, None, None, "nothing to uninstall", error_kind="nothing_to_uninstall")
        if not validate_ownership_authority(env.state_root, capability_id, owned):
            return PrepareOutcome(
                PrepareStatus.OWNERSHIP_INVALID, None, None,
                "ownership records for capability %s do not correspond, in full, to any committed transaction; refusing to uninstall" % capability_id,
                error_kind="ownership_invalid",
            )

        plan = _build_uninstall_plan(capability_id, owned)
        now = env.context.now
        journal = _initial_uninstall_journal(plan, now_value=now())
        journal_mod.write_journal(env.state_root, journal)
        journal = journal.with_state(TransactionState.UNINSTALLING, now=now())
        journal_mod.write_journal(env.state_root, journal)

        journal, ok, residuals = _run_uninstall_loop(env.state_root, journal, env.context)

        if ok:
            journal = journal.with_state(TransactionState.UNINSTALLED, now=now())
            journal_mod.write_journal(env.state_root, journal)
            journal_mod.delete_ownership_records(env.state_root, capability_id)
            return PrepareOutcome(PrepareStatus.UNINSTALLED, None, transaction_id, "uninstalled %d resource(s)" % len(owned))

        journal = journal.with_state(TransactionState.UNINSTALL_FAILED, now=now(), failure={"residuals": residuals})
        journal_mod.write_journal(env.state_root, journal)
        return PrepareOutcome(
            PrepareStatus.UNINSTALL_FAILED, None, transaction_id,
            "uninstall did not complete for all resources", residuals=tuple(residuals), error_kind="uninstall_failed",
        )
