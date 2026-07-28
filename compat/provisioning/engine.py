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
from typing import Mapping, Sequence

from compat.dependency_resolution import ResolutionDecision

from compat.provisioning import lock as lock_mod
from compat.provisioning import journal as journal_mod
from compat.provisioning.digest import compute_plan_digest, compute_uninstall_plan_digest
from compat.provisioning.errors import (
    DurabilityError,
    ExecutionNotReadyError,
    ExecutorNotRegisteredError,
    IdentifierError,
    JournalError,
    PathPolicyError,
    ProvisioningError,
    StateRootIdentityError,
)
from compat.provisioning.executors import ExecutionContext, Executor, TrustedExecutorRegistry, handle_for_allowed_root
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
from compat.provisioning.paths import (
    AllowedRootHandle,
    confirm_absent_descriptor_safe,
    open_allowed_root,
    remove_file_if_owned_relative,
    stat_identity_relative,
    validate_target_path,
)
from compat.provisioning.storage import StateRootHandle

NEEDS_RECOVERY_ATTENTION = frozenset(
    {
        TransactionState.APPLYING,
        TransactionState.VERIFYING,
        TransactionState.ROLLING_BACK,
        TransactionState.RECOVERY_REQUIRED,
        TransactionState.RECOVERING,
        TransactionState.UNINSTALLING,
        TransactionState.REVOKING_OWNERSHIP,
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
    RECOVERY_REQUIRED = "recovery_required"
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
    # Dedicated, stable root the global provisioner lock lives under (point
    # 1, fifth correction round) -- e.g. ``/run/lock/watchdogvpn/
    # provisioning`` in production. Deliberately required, never defaulted:
    # a silent default pointing at the wrong place would defeat the whole
    # point of a lock root that is never inside any single installation's
    # own renamable state_root tree.
    global_lock_root: Path
    lock_timeout: float = lock_mod.DEFAULT_TIMEOUT_SECONDS


def _open_locked_context(context: ExecutionContext) -> ExecutionContext:
    """Captures one ``AllowedRootHandle`` per configured allowed root (point
    2, fifth correction round), under the provisioner lock, immediately
    before this critical section's first apply/rollback/uninstall/recovery
    use -- returning a new ``ExecutionContext`` executors and the
    coordinator both use for the rest of the critical section instead of
    ``env.context`` directly. An allowed root that can no longer be opened
    (renamed away, replaced by a symlink, wrong type -- an ancestor swap)
    raises ``PathPolicyError``; any handles already opened for an earlier
    root are closed before it propagates, so callers never leak fds on this
    path."""
    opened: list[AllowedRootHandle] = []
    try:
        for root in context.allowed_roots:
            opened.append(open_allowed_root(root))
    except Exception:
        for handle in opened:
            handle.close()
        raise
    return dataclasses.replace(context, allowed_root_handles=tuple(opened))


def _close_locked_context(context: ExecutionContext) -> None:
    for handle in context.allowed_root_handles:
        handle.close()


def _eager_cache_intermediates_for_targets(context: ExecutionContext, targets) -> None:
    """Pre-opens and caches every intermediate directory descriptor between
    each allowed root and each resource path in ``targets`` (point 2, sixth
    correction round), immediately after the plan/ownership set is known
    and the lock is held -- before ANY other operation (idempotency check,
    inspection, removal, ...) touches these paths. This mirrors the eager
    open of state_root's own transactions/ownership/history subdirectories
    (point 1, fifth correction round): without it, the FIRST access to a
    nested resource could itself land on a substitute intermediate
    directory an attacker swapped in during the narrow window between the
    lock being acquired and that first access, with no earlier-cached
    identity to detect the divergence against. A target that fails
    structural validation here is silently skipped -- it is properly
    rejected later at its real use site with a clear, specific error."""
    for target in targets:
        if not target:
            continue
        try:
            validated = validate_target_path(Path(target), allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
            relative = validated.relative_to(handle.path)
            if relative.parts[:-1]:
                handle.intermediate_fd(relative.parts[:-1])
        except PathPolicyError:
            continue


def _verify_allowed_roots_identity(context: ExecutionContext) -> None:
    """Re-confirms every captured ``AllowedRootHandle`` still refers to the
    same physical directory at its canonical, configured path (point 2,
    fifth correction round) -- called immediately before finalizing
    ownership/provenance and immediately before revoking ownership, so a
    sandbox/allowed-root swap that happened mid-transaction is detected
    before ever reporting COMMITTED or UNINSTALLED. Raises
    ``PathPolicyError`` on mismatch; callers rely on the same outer
    ``except (StateRootIdentityError, PathPolicyError)`` handler that
    ``prepare()``/``uninstall()``/``recover_pending()`` already install."""
    for handle in context.allowed_root_handles:
        handle.verify_identity()


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


class _UninstallScanResult(Enum):
    """Point 4, sixth correction round: a plain boolean cannot represent
    "cannot tell" -- only "yes" or "no". An individual journal that cannot
    be read/validated during the scan might be EXACTLY the relevant
    completed-uninstall journal for this capability; its irrelevance can
    never be demonstrated without reading it, so it must never be silently
    treated as "not found" (which would wrongly grant authority)."""

    NONE_FOUND = "none_found"
    COMPLETED_FOUND = "completed_found"
    UNKNOWN = "unknown"


def _capability_has_completed_uninstall(
    state_root: Path, capability_id: str, target_transaction_id: str, *, exclude_transaction_id: str | None = None
) -> _UninstallScanResult:
    """Scans for an uninstall journal, for this exact source transaction,
    that has already progressed past resource removal
    (``REVOKING_OWNERSHIP`` or ``UNINSTALLED``). A live ownership record
    still citing that transaction at this point is stale bookkeeping left
    behind by a crash between the resources being removed and ownership
    being revoked -- it must never be trusted as authority again, even if
    its recorded hash still happens to match a path someone else has since
    recreated.

    ``exclude_transaction_id`` skips one specific uninstall journal (its own
    ``transaction_id``, never the source ``target_transaction_id``) from the
    scan -- used when this check is called from THAT very uninstall
    journal's own in-progress revocation boundary (``_revocation_boundary_is_safe``),
    where it would otherwise always find itself already sitting at
    ``REVOKING_OWNERSHIP`` and wrongly self-invalidate its own authority.

    Fails closed (point 6, fifth correction round; point 4, sixth): if the
    transactions directory itself cannot even be enumerated, OR if any
    INDIVIDUAL journal encountered during the scan cannot be read/validated,
    this returns ``UNKNOWN`` -- never silently skipped/continued past as
    irrelevant -- since a corrupted-in-place journal might be exactly the
    completed uninstall this check exists to find. The caller must deny
    authority for anything other than ``NONE_FOUND``."""
    try:
        transaction_ids = journal_mod.list_transaction_ids(state_root)
    except (JournalError, IdentifierError):
        return _UninstallScanResult.UNKNOWN
    for transaction_id in transaction_ids:
        if transaction_id == exclude_transaction_id:
            continue
        try:
            candidate = journal_mod.read_journal(state_root, transaction_id)
        except (JournalError, IdentifierError):
            return _UninstallScanResult.UNKNOWN
        if candidate.operation != "uninstall" or candidate.capability_id != capability_id:
            continue
        if candidate.target != target_transaction_id:
            continue
        if candidate.state in (TransactionState.REVOKING_OWNERSHIP, TransactionState.UNINSTALLED):
            return _UninstallScanResult.COMPLETED_FOUND
    return _UninstallScanResult.NONE_FOUND


def validate_ownership_authority(
    state_root: Path,
    capability_id: str,
    records: Sequence[OwnershipRecord],
    *,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
    exclude_uninstall_transaction_id: str | None = None,
) -> bool:
    """Full-set-exact validation binding every product-owned record to one
    committed "prepare" transaction's own PLAN -- never to
    ``journal.provenance``, a second JSON blob that lives inside the very
    same mutable journal file as the ownership metadata itself. Comparing
    ownership against provenance alone cannot detect an attacker (or
    corruption) that edits both consistently: point straight at a foreign
    resource, adjust ``provenance`` to match, and the old check would pass.

    Instead, the source transaction's plan is independently RECONSTRUCTED
    here from the trusted executor's own code (``executor.plan_steps``),
    exactly like ``_recover_one`` already does for recovery, and its digest
    is reverified against the journal's own ``plan_digest`` -- never read
    back from the journal's persisted step targets/intents, which is itself
    tamperable. ``journal.steps`` is additionally required to be
    STRUCTURALLY IDENTICAL to that reconstructed plan (see
    ``_journal_steps_match_plan_exactly``): ``plan_digest`` alone does not
    protect a step being entirely removed, duplicated or altered in
    ``journal.steps``, since a step's own persisted state (VERIFIED, its
    undo_record) is not part of ``plan_digest`` at all. Each ownership
    record must then match exactly one ``VERIFIED`` step of that plan (a
    set-exact, both-directions check), and every field is compared against
    ``executor.expected_ownership_for_step`` -- a canonical, deterministic
    expectation the TRUSTED EXECUTOR itself derives from the plan, never an
    engine-hardcoded assumption like "artifact_type is always file" or
    "source is always None" (those belong to the executor, not the
    coordinator -- a different executor may legitimately produce different
    values). Because that expectation is plan-derived (never a live
    filesystem read), it is safe to compare unconditionally even mid-
    recovery, when a resume in progress may legitimately have already
    altered the real resource -- live-state drift remains
    ``_detect_ownership_drift``'s job, run later and only once, right
    before the actual unlink. Never trusts a record in isolation -- an
    orphaned, partial or divergent record, one bound to a non-committed/
    structurally-altered journal, or one left behind by an uninstall that
    already removed its resources (stale bookkeeping pending revocation),
    invalidates the entire set."""
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

    if _capability_has_completed_uninstall(
        state_root, capability_id, transaction_id, exclude_transaction_id=exclude_uninstall_transaction_id
    ) != _UninstallScanResult.NONE_FOUND:
        return False

    try:
        executor = registry.resolve(
            method_kind=journal.selected_method["kind"],
            method_id=journal.selected_method["id"],
            expected_executor_version=journal.executor.get("version", expected_executor_version),
        )
    except (ExecutorNotRegisteredError, KeyError):
        return False

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
    except (ValueError, KeyError):
        return False

    if compute_plan_digest(plan) != journal.plan_digest:
        return False

    if not _journal_steps_match_plan_exactly(journal, plan):
        return False

    if any(step.state != StepState.VERIFIED for step in journal.steps):
        return False
    for step in journal.steps:
        if step.verification is None or not step.undo_record:
            return False

    expected_by_identity = {step.target: step for step in plan.steps if step.target}

    if set(expected_by_identity) != {record.candidate.resource_identity for record in owned}:
        return False

    for record in owned:
        candidate = record.candidate
        plan_step = expected_by_identity.get(candidate.resource_identity)
        if plan_step is None:
            return False
        expected = executor.expected_ownership_for_step(plan, plan_step)
        if record.capability_id != journal.capability_id:
            return False
        if candidate.artifact_type != expected.artifact_type:
            return False
        if candidate.resource_identity != expected.resource_identity:
            return False
        if candidate.pre_existing != expected.pre_existing:
            return False
        if candidate.method_id != expected.method_id:
            return False
        if candidate.source != expected.source:
            return False
        if candidate.version != expected.version:
            return False
        # Point 7, fifth correction round: EXACT equality against every
        # field, even when ``expected`` is ``None`` -- a prior conditional
        # guard here (``if expected.X is not None and ...``) meant that
        # whenever the executor's own canonical expectation legitimately
        # left a field unset, an attacker could set the PERSISTED
        # candidate's own value for that same field to anything at all
        # without ever being caught. ``candidate.X == expected.X`` alone,
        # with no conditional, is the only comparison that also catches a
        # None-in-the-plan field being tampered into a concrete value.
        if candidate.integrity != expected.integrity:
            return False
        if candidate.uid != expected.uid:
            return False
        if candidate.gid != expected.gid:
            return False
        if candidate.mode != expected.mode:
            return False
        if candidate.nlink != expected.nlink:
            return False
        if candidate.post_install_fingerprint != expected.post_install_fingerprint:
            return False
        if record.executor_id != journal.executor.get("id") or record.executor_version != journal.executor.get("version"):
            return False
        if record.created_by_transaction != journal.transaction_id:
            return False

    return True


def _journal_steps_match_plan_exactly(journal: TransactionJournal, plan: ProvisioningPlan) -> bool:
    """Point 3: a COMMITTED source journal's own steps must be structurally
    IDENTICAL to the independently reconstructed plan's steps -- same
    cardinality, unique sequences, same set of sequences, and for each
    sequence an exact match of step_id/action_type/target/intent.
    ``plan_digest`` alone does not protect against ``journal.steps`` being
    tampered (a step removed, duplicated, or its own recorded step_id/
    action_type/target/intent altered): none of a step's own per-step
    fields participate in ``plan_digest``, only the ORIGINAL plan's steps
    did, once, at journal-creation time."""
    if len(journal.steps) != len(plan.steps):
        return False
    journal_sequences = [step.sequence for step in journal.steps]
    if len(set(journal_sequences)) != len(journal_sequences):
        return False
    plan_by_sequence = {step.sequence: step for step in plan.steps}
    if set(journal_sequences) != set(plan_by_sequence):
        return False
    for journal_step in journal.steps:
        plan_step = plan_by_sequence[journal_step.sequence]
        if journal_step.step_id != plan_step.step_id:
            return False
        if journal_step.action_type != plan_step.action_type:
            return False
        if journal_step.target != plan_step.target:
            return False
        if dict(journal_step.intent) != dict(plan_step.intent):
            return False
    return True


def _steps_consistent_with_transaction_state(journal: TransactionJournal) -> bool:
    """Point 4, fifth correction round: a defensive sanity cross-check
    between a "prepare" journal's top-level state and its steps' own
    recorded states -- catches a tampered/corrupted combination that could
    never arise from this engine's own state machine (e.g. a step already
    ``UNDONE``/``UNDOING``/``UNDO_FAILED`` while the transaction itself is
    still moving forward, which would mean rollback started before apply
    even reached a point where anything could be undone)."""
    if journal.operation != "prepare":
        return True
    step_states = {step.state for step in journal.steps}
    if journal.state in (TransactionState.APPLYING, TransactionState.VERIFYING):
        if step_states & {StepState.UNDOING, StepState.UNDONE, StepState.UNDO_FAILED}:
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
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
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

    if not validate_ownership_authority(
        state_root, plan.capability_id, owned_by_this_plan,
        registry=registry, expected_executor_version=expected_executor_version, context=context,
    ):
        return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)

    # Idempotency is tied to the FULL plan, not just ownership/resource
    # metadata: the source transaction must be the exact same plan in every
    # respect -- capability/dependency id, resolved target, architecture,
    # support classification, selected method, executor and selected asset
    # (all encoded in plan_digest) -- never just "close enough" on the
    # resources it happened to leave behind.
    source_transaction_id = owned_by_this_plan[0].created_by_transaction
    try:
        source_journal = journal_mod.read_journal(state_root, source_transaction_id)
    except (JournalError, IdentifierError):
        return IdempotencyCheck(IdempotencyOutcome.OWNERSHIP_CONFLICT, inspections)
    if source_journal.plan_digest != compute_plan_digest(plan):
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
            validated = validate_target_path(
                Path(record.candidate.resource_identity), allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots
            )
            handle = handle_for_allowed_root(context, validated)
            identity = stat_identity_relative(handle, validated)
        except (OSError, PathPolicyError):
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
    except DurabilityError as exc:
        # The action's own effect may genuinely have happened (e.g. the file
        # was written and fsynced); only its containing directory's fsync
        # failed, so its survival across a crash is unconfirmed. This must
        # never be folded into a generic apply_failed -- see _run_apply_loop.
        return ExecutionResult(status="apply_failed", error_kind="durability_unknown", error=str(exc))
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
    except DurabilityError as exc:
        return RollbackResult(status="undo_failed", residual=True, error_kind="durability_unknown", error=str(exc))
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


def _authoritative_undo_record(executor: Executor, record: StepRecord) -> Mapping[str, object]:
    """Point 4, fifth correction round: ALWAYS reconstructs the undo_record
    fresh from the executor's own deterministic logic (plan-derived, never
    I/O) -- the PERSISTED ``record.undo_record`` is compared only as
    evidence of what a prior apply attempt recorded; it is NEVER used to
    drive the actual undo operation. A journal an attacker (or corruption)
    could otherwise alter a persisted undo_record's ``path``/
    ``expected_sha256`` to point rollback at an unrelated foreign resource
    -- reconstructing fresh and requiring exact agreement closes that.
    A divergence between the two means the journal's own bookkeeping no
    longer matches what this executor would deterministically produce for
    this exact step, which must always be treated as unsafe to resume
    automatically."""
    reconstructed = executor.reconstruct_undo_record(record)
    persisted = record.undo_record
    if persisted is not None and dict(persisted) != dict(reconstructed):
        raise ProvisioningError(
            "step %s persisted undo_record diverges from what this executor would deterministically reconstruct; refusing to trust it"
            % record.step_id
        )
    return reconstructed


def _run_apply_loop(state_root: Path, journal: TransactionJournal, plan: ProvisioningPlan, executor: Executor, context: ExecutionContext, signaled) -> tuple[TransactionJournal, bool, bool]:
    """Returns ``(journal, apply_ok, durability_unknown)``. ``durability_unknown``
    means an action's own effect may genuinely have happened but its
    containing directory's fsync failed, so its survival across a crash is
    unconfirmed -- this is never folded into a plain ``apply_ok=False``
    (which would drive an automatic rollback that could itself hit the same
    unconfirmed-durability problem, or silently report a clean failure while
    the file is actually still there). The step is deliberately left exactly
    where its write-ahead journal entry already durably placed it (``APPLYING``),
    so the existing APPLYING-resume recovery machinery -- which already
    knows how to inspect the real target and decide RESUME_APPLY vs ambiguous
    -- handles it correctly on the next recovery pass, with zero new logic."""
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
            return journal, False, False
        if signaled.value:
            return journal, False, False

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
            if observed.get("inspect_error"):
                raise ProvisioningError("step %s could not be inspected during resume: %s" % (record.step_id, observed["inspect_error"]))
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
            # verification needs to be (re)done. The undo_record used from
            # here on is always freshly reconstructed and cross-checked
            # against the persisted one (point 4, fifth correction round;
            # see _authoritative_undo_record) -- never the persisted value
            # trusted outright.
            try:
                undo_record = _authoritative_undo_record(executor, record)
            except ProvisioningError as exc:
                journal = journal.with_state(
                    TransactionState.RECOVERY_REQUIRED, now=now(),
                    recovery={"reason": "undo_record_diverged", "step_id": record.step_id, "error": str(exc)},
                )
                journal_mod.write_journal(state_root, journal)
                return journal, False, True
            result = ExecutionResult(status="applied", undo_record=undo_record)
        else:
            raise ProvisioningError("step %s is in an unexpected state for apply resume: %s" % (record.step_id, record.state.value))

        if result.status != "applied":
            if result.error_kind == "durability_unknown":
                # Do NOT transition to APPLY_FAILED: that would (a) falsely
                # claim the action never happened, when its own effect may
                # well be sitting on disk right now, and (b) make this step
                # ineligible for undo (APPLY_FAILED is not in
                # UNDOABLE_STEP_STATES), leaking it if it really is there.
                # The step's write-ahead APPLYING entry is already durable;
                # leave it exactly there and require recovery instead of
                # guessing which way to resolve it.
                journal = journal.with_state(
                    TransactionState.RECOVERY_REQUIRED, now=now(),
                    recovery={"reason": "durability_unknown", "step_id": record.step_id, "error": result.error},
                )
                journal_mod.write_journal(state_root, journal)
                return journal, False, True
            record = record.with_state(StepState.APPLY_FAILED, completed_at=now(), error_kind=result.error_kind, error=result.error)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            return journal, False, False

        if record.state == StepState.APPLYING:
            record = record.with_state(StepState.APPLIED, completed_at=now(), undo_record=result.undo_record)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)  # durable after the action, with undo_record
            if signaled.value:
                return journal, False, False
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
            return journal, False, False

        record = record.with_state(StepState.VERIFIED, completed_at=now(), verification=verification.evidence)
        journal = journal.with_step(record)
        journal_mod.write_journal(state_root, journal)  # durable after verify

    return journal, True, False


def _run_rollback(state_root: Path, journal: TransactionJournal, executor: Executor, context: ExecutionContext) -> tuple[TransactionJournal, bool, list[str]]:
    """Undoes every undoable step in reverse order. ``UNDOING`` is an
    explicit resume boundary, not a state this loop can silently skip: a step
    already left in ``UNDOING`` by a prior crash (``UNDOING`` is deliberately
    NOT a member of ``UNDOABLE_STEP_STATES``, so a naive membership check
    would pass straight over it) is inspected before anything else -- absent
    means the undo already happened and only the ``UNDONE`` write never
    landed; present-and-matching means retry; a symlink, a content divergence
    or an inspection error can never be silently retried and instead becomes
    a durable ``UNDO_FAILED`` (residual), so the loop can never report
    ``rollback_ok=True`` while a step is left stuck in ``UNDOING``."""
    now = context.now
    residuals: list[str] = []
    for step_record in sorted(journal.steps, key=lambda item: item.sequence, reverse=True):
        current = journal.step(step_record.sequence)

        if current.state == StepState.UNDOING:
            observed = _safe_inspect(executor, current, context)
            if observed.get("path_policy_error"):
                record = current.with_state(StepState.UNDO_FAILED, completed_at=now(), error_kind="path_policy_violation", error=observed["path_policy_error"])
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                residuals.append(record.step_id)
                continue
            if observed.get("inspect_error"):
                record = current.with_state(StepState.UNDO_FAILED, completed_at=now(), error_kind="inspection_error", error=observed["inspect_error"])
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                residuals.append(record.step_id)
                continue
            if not observed.get("exists"):
                # The undo already happened; only the durable UNDONE
                # transition write never landed.
                record = current.with_state(StepState.UNDONE, completed_at=now())
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                continue
            if observed.get("is_symlink"):
                record = current.with_state(StepState.UNDO_FAILED, completed_at=now(), error_kind="unexpected_symlink", error="target is a symlink during rollback recovery")
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                residuals.append(record.step_id)
                continue
            if observed.get("content_matches") is False:
                record = current.with_state(StepState.UNDO_FAILED, completed_at=now(), error_kind="content_diverged", error="target content diverged from its recorded undo_record")
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                residuals.append(record.step_id)
                continue
            # Exists and matches exactly what was recorded: the undo never
            # actually ran (or ran and failed silently before this crash);
            # safe to retry from this exact UNDOING state. The undo_record
            # driving the actual undo is always freshly reconstructed and
            # cross-checked against the persisted one (point 4, fifth
            # correction round) -- never the persisted value trusted
            # outright, since a tampered undo_record could otherwise point
            # rollback at an unrelated foreign resource.
            try:
                undo_record = _authoritative_undo_record(executor, current)
            except ProvisioningError as exc:
                record = current.with_state(StepState.UNDO_FAILED, completed_at=now(), error_kind="undo_record_diverged", error=str(exc))
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                residuals.append(record.step_id)
                continue
            execution = ExecutionResult(status="applied", undo_record=undo_record)
            result = _safe_undo(executor, current, execution, context)
            if result.status == "undone":
                record = current.with_state(StepState.UNDONE, completed_at=now())
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
            else:
                record = current.with_state(StepState.UNDO_FAILED, completed_at=now(), error_kind=result.error_kind, error=result.error)
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                residuals.append(record.step_id)
            continue

        if current.state not in UNDOABLE_STEP_STATES:
            continue
        record = current.with_state(StepState.UNDOING)
        journal = journal.with_step(record)
        journal_mod.write_journal(state_root, journal)

        try:
            undo_record = _authoritative_undo_record(executor, record)
        except ProvisioningError as exc:
            record = record.with_state(StepState.UNDO_FAILED, completed_at=now(), error_kind="undo_record_diverged", error=str(exc))
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            residuals.append(record.step_id)
            continue
        execution = ExecutionResult(status="applied", undo_record=undo_record)
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


def _finalize_provenance(state_root: Path, journal: TransactionJournal, plan: ProvisioningPlan, executor: Executor, context: ExecutionContext, now_value: str) -> dict:
    """Builds the durable ownership records a COMMITTED transaction publishes.
    Re-validates each resource's path and re-inspects its real identity right
    before commit -- a stat failure here is never silently turned into
    ``None`` metadata (which would grant uninstall/idempotency authority over
    a resource whose ownership was never actually confirmed); it raises
    ``ProvisioningError`` instead, so the caller can drive the transaction to
    ``RECOVERY_REQUIRED`` rather than a false ``COMMITTED``.

    The metadata found is never simply adopted as the new expectation, and
    the engine itself never hardcodes an executor's own semantics (point 6):
    expected artifact_type/pre_existing/method_id/source/version/mode/uid/
    gid/nlink/post_install_fingerprint all come from
    ``executor.expected_ownership_for_step`` -- a canonical, deterministic
    value derived from the plan (part of ``plan_digest``, hence
    tamper-evident) -- and the live re-stat is checked AGAINST that
    expectation, closing the window between the executor's own
    ``verify_postcondition`` and commit."""
    plan_steps_by_sequence = {step.sequence: step for step in plan.steps}
    records = []
    for step in journal.steps:
        undo_record = step.undo_record or {}
        resource_identity = undo_record.get("path", step.target or "")
        plan_step = plan_steps_by_sequence.get(step.sequence)
        if plan_step is None:
            raise ProvisioningError("cannot finalize ownership for %s: no matching plan step for sequence %d" % (resource_identity, step.sequence))
        expected = executor.expected_ownership_for_step(plan, plan_step)
        try:
            validated = validate_target_path(Path(resource_identity), allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
            identity = stat_identity_relative(handle, validated)
        except (PathPolicyError, OSError) as exc:
            raise ProvisioningError("cannot finalize ownership for %s: %s" % (resource_identity, exc)) from exc
        if identity["is_symlink"] or not identity["is_regular"]:
            raise ProvisioningError("cannot finalize ownership for %s: not a regular, non-symlink file" % resource_identity)
        if expected.nlink is not None and identity["nlink"] != expected.nlink:
            raise ProvisioningError(
                "cannot finalize ownership for %s: st_nlink is %d, expected %d" % (resource_identity, identity["nlink"], expected.nlink)
            )
        if expected.mode is not None and identity["mode"] != expected.mode:
            raise ProvisioningError(
                "cannot finalize ownership for %s: mode is %o, expected %o" % (resource_identity, identity["mode"], expected.mode)
            )
        if expected.uid is not None and identity["uid"] != expected.uid:
            raise ProvisioningError(
                "cannot finalize ownership for %s: uid is %d, expected %d" % (resource_identity, identity["uid"], expected.uid)
            )
        if expected.gid is not None and identity["gid"] != expected.gid:
            raise ProvisioningError(
                "cannot finalize ownership for %s: gid is %d, expected %d" % (resource_identity, identity["gid"], expected.gid)
            )
        candidate = OwnershipCandidate(
            artifact_type=expected.artifact_type,
            resource_identity=str(validated),
            pre_existing=expected.pre_existing,
            method_id=expected.method_id,
            source=expected.source,
            version=expected.version,
            integrity=expected.integrity,
            # Point 7, fifth correction round: when the executor's own
            # expectation for a field is None (it declares no opinion),
            # the persisted candidate must ALSO record None for it --
            # never silently upgrade "no opinion" into a concrete
            # live-stat value. Otherwise a later EXACT (not
            # None-conditional) comparison in validate_ownership_authority
            # could never agree with the executor's own None expectation,
            # rejecting even a perfectly legitimate, untampered record.
            uid=identity["uid"] if expected.uid is not None else None,
            gid=identity["gid"] if expected.gid is not None else None,
            mode=identity["mode"] if expected.mode is not None else None,
            nlink=identity["nlink"] if expected.nlink is not None else None,
            post_install_fingerprint=expected.post_install_fingerprint,
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
    try:
        with lock_mod.acquire_provisioner_lock(
            env.state_root, global_lock_root=env.global_lock_root, transaction_id=transaction_id, timeout=env.lock_timeout
        ) as handle:
            locked_context = _open_locked_context(env.context)
            try:
                _eager_cache_intermediates_for_targets(locked_context, [step.target for step in plan.steps])
                recovery_reports = _recover_pending_locked(handle, env.registry, env.expected_executor_version, locked_context)
                blocking = [item for item in recovery_reports if item.action == RecoveryAction.REQUIRE_MANUAL]
                if blocking:
                    return PrepareOutcome(
                        PrepareStatus.PENDING_RECOVERY, plan, None,
                        "cannot start a new transaction while others require manual recovery: %s" % [item.transaction_id for item in blocking],
                        error_kind="recovery_required",
                    )

                existing_ownership = journal_mod.read_ownership_records(handle, plan.capability_id)
                idempotency = check_idempotency(
                    plan, executor, locked_context, existing_ownership=existing_ownership, state_root=handle,
                    registry=env.registry, expected_executor_version=env.expected_executor_version,
                )
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
                journal_mod.write_journal(handle, journal)
                journal = journal.with_state(TransactionState.AUTHORIZED, now=now())
                journal_mod.write_journal(handle, journal)
                journal = journal.with_state(TransactionState.APPLYING, now=now())
                journal_mod.write_journal(handle, journal)

                journal, apply_ok, durability_unknown = _apply_and_verify(handle, journal, plan, executor, locked_context)
                return _finish_prepare(handle, journal, plan, executor, locked_context, apply_ok, durability_unknown, transaction_id)
            finally:
                _close_locked_context(locked_context)
    except (StateRootIdentityError, PathPolicyError) as exc:
        return PrepareOutcome(
            PrepareStatus.RECOVERY_REQUIRED, plan, transaction_id,
            "state root identity changed during the transaction; refusing to report a clean outcome: %s" % exc,
            error_kind="state_root_identity_mismatch",
        )


def _apply_and_verify(state_root: Path, journal: TransactionJournal, plan: ProvisioningPlan, executor: Executor, context: ExecutionContext) -> tuple[TransactionJournal, bool, bool]:
    """Returns ``(journal, apply_ok, durability_unknown)`` -- see
    ``_run_apply_loop`` for what ``durability_unknown`` means and why it is
    never folded into ``apply_ok=False``."""
    with _interruption_guard() as signaled:
        journal, apply_ok, durability_unknown = _run_apply_loop(state_root, journal, plan, executor, context, signaled)
    if durability_unknown:
        return journal, False, True
    if not apply_ok:
        return journal, False, False

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
        return journal, False, False
    return journal, True, False


def _finish_prepare(
    state_root: Path, journal: TransactionJournal, plan: ProvisioningPlan, executor: Executor, context: ExecutionContext,
    apply_ok: bool, durability_unknown: bool, transaction_id: str,
) -> PrepareOutcome:
    now = context.now
    if durability_unknown:
        step_id = (journal.recovery or {}).get("step_id")
        return PrepareOutcome(
            PrepareStatus.RECOVERY_REQUIRED, plan, transaction_id,
            "an action's effect may have occurred but its directory durability could not be confirmed; recovery required",
            residuals=(step_id,) if step_id else ("unknown",), error_kind="durability_unknown",
        )
    if apply_ok:
        _verify_allowed_roots_identity(context)
        try:
            provenance = _finalize_provenance(state_root, journal, plan, executor, context, now())
        except ProvisioningError as exc:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "cannot finalize provenance: %s" % exc})
            journal_mod.write_journal(state_root, journal)
            return PrepareOutcome(
                PrepareStatus.RECOVERY_REQUIRED, plan, transaction_id,
                "postcondition verified but ownership could not be finalized; recovery required",
                residuals=("provenance",), error_kind="provenance_finalization_failed",
            )
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
    global_lock_root: Path,
    lock_timeout: float = lock_mod.DEFAULT_TIMEOUT_SECONDS,
) -> list[RecoveryDecision]:
    """Public recovery entry point. Acquires the single machine-wide
    provisioner lock itself for the whole recovery pass and releases it in a
    ``finally`` -- recovery must never run concurrently with another
    recovery pass, nor with a ``prepare()``/``uninstall()`` in progress.
    ``prepare()``/``uninstall()`` call the internal ``_recover_pending_locked``
    directly since they already hold this same lock."""
    transaction_id = "recovery-%s" % _new_transaction_id()
    try:
        with lock_mod.acquire_provisioner_lock(
            state_root, global_lock_root=global_lock_root, transaction_id=transaction_id, timeout=lock_timeout
        ) as handle:
            locked_context = _open_locked_context(context)
            try:
                return _recover_pending_locked(handle, registry, expected_executor_version, locked_context)
            finally:
                _close_locked_context(locked_context)
    except (StateRootIdentityError, PathPolicyError) as exc:
        return [RecoveryDecision(transaction_id, RecoveryAction.REQUIRE_MANUAL, "state root identity changed during recovery: %s" % exc)]


def _recover_pending_locked(
    state_root: Path,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
) -> list[RecoveryDecision]:
    """Internal recovery pass. Callers MUST already hold the provisioner
    lock -- this function never acquires it itself."""
    decisions: list[RecoveryDecision] = []
    try:
        transaction_ids = journal_mod.list_transaction_ids(state_root)
    except Exception as exc:  # noqa: BLE001 - cannot even enumerate pending transactions; itself the finding
        return [RecoveryDecision("<state-scan>", RecoveryAction.REQUIRE_MANUAL, "cannot enumerate pending transactions: %s" % exc)]
    for transaction_id in transaction_ids:
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
        return _recover_uninstall(
            state_root, journal, context, registry=registry, expected_executor_version=expected_executor_version
        )

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

    _eager_cache_intermediates_for_targets(context, [step.target for step in plan.steps])

    if compute_plan_digest(plan) != journal.plan_digest:
        if journal.state != TransactionState.RECOVERY_REQUIRED:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "plan_digest_mismatch"})
            journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "plan_digest no longer matches the journal")

    # Point 4, fifth correction round: plan_digest alone was computed once,
    # at journal-creation time, from the ORIGINAL plan -- it never covers a
    # step's own subsequently-persisted (and potentially tampered) state.
    # Every "prepare" journal read back from disk for recovery must be
    # structurally IDENTICAL, step for step, to the plan independently
    # reconstructed here from the trusted executor's own code, exactly like
    # ``validate_ownership_authority`` already requires for a COMMITTED
    # source journal.
    if not _journal_steps_match_plan_exactly(journal, plan):
        if journal.state != TransactionState.RECOVERY_REQUIRED:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "journal_steps_do_not_match_plan"})
            journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "journal steps no longer match the reconstructed plan")

    if not _steps_consistent_with_transaction_state(journal):
        if journal.state != TransactionState.RECOVERY_REQUIRED:
            journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "steps_inconsistent_with_transaction_state"})
            journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "step states are inconsistent with the transaction's own top-level state")

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
        journal, apply_ok, durability_unknown = _apply_and_verify(state_root, journal, plan, executor, context)
        if apply_ok:
            _verify_allowed_roots_identity(context)
            try:
                provenance = _finalize_provenance(state_root, journal, plan, executor, context, now())
            except ProvisioningError as exc:
                journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "cannot finalize provenance: %s" % exc})
                journal_mod.write_journal(state_root, journal)
                return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "postcondition verified but ownership could not be finalized during recovery")
            journal = journal.with_state(TransactionState.COMMITTED, now=now(), provenance=provenance)
            journal_mod.write_journal(state_root, journal)
            return RecoveryDecision(journal.transaction_id, RecoveryAction.RESUME, "resumed and committed")
        if durability_unknown:
            # _apply_and_verify already drove the journal back into
            # RECOVERY_REQUIRED; a second unconfirmed-durability hit during
            # recovery itself must not trigger an automatic rollback attempt
            # (which could hit the exact same problem) -- surface for manual
            # review and let a later, separate recovery pass retry.
            return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "durability could not be confirmed during recovery; manual review required")
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
        # _run_rollback itself now handles a step resumed from UNDOING
        # safely (inspect real state, retry-if-matches, or a durable
        # UNDO_FAILED for anything ambiguous) -- no separate pre-check is
        # needed or more capable than that real handler.
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
                if observed.get("inspect_error"):
                    return _Verdict.AMBIGUOUS, "step %s could not be inspected during recovery: %s" % (step.step_id, observed["inspect_error"])
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

    # UNINSTALLING/REVOKING_OWNERSHIP are never reached here: _recover_one
    # dispatches every "uninstall" operation journal straight to
    # _recover_uninstall, which has its own dedicated boundary handling.

    return _Verdict.AMBIGUOUS, "unrecognized transaction state for recovery: %s" % journal.state.value


def _recover_uninstall(
    state_root: Path,
    journal: TransactionJournal,
    context: ExecutionContext,
    *,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
) -> RecoveryDecision:
    """Resumes an uninstall at whichever boundary it was interrupted at:
    still removing resources (``UNINSTALLING``), or all resources already
    confirmed removed and only ownership revocation remained
    (``REVOKING_OWNERSHIP``). When resuming from ``RECOVERY_REQUIRED`` (a
    prior failed attempt), the correct boundary is determined from the
    steps' own recorded state -- never from a collapsed prior top-level
    state -- since a failure during revocation looks identical, at the
    top level, to one during the unlink loop. Reaching ``REVOKING_OWNERSHIP``
    (whether just transitioned into or resumed directly at) never by itself
    authorizes a revoke: see ``_revocation_boundary_is_safe``, which
    independently reconfirms the snapshot/digest/step-states/live-absence
    before ever calling ``_revoke_ownership_and_verify``."""
    now = context.now
    _eager_cache_intermediates_for_targets(context, [r.candidate.resource_identity for r in journal.owned_snapshot])
    for step in journal.steps:
        if step.state == StepState.VERIFY_FAILED or step.state == StepState.APPLY_FAILED:
            if journal.state != TransactionState.RECOVERY_REQUIRED:
                journal = journal.with_state(TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "an uninstall step already failed; manual review required"})
                journal_mod.write_journal(state_root, journal)
            return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "an uninstall step already failed")

    if journal.state == TransactionState.RECOVERY_REQUIRED:
        journal = journal.with_state(TransactionState.RECOVERING, now=now())
        journal_mod.write_journal(state_root, journal)
        if all(step.state == StepState.VERIFIED for step in journal.steps):
            journal = journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=now())
        else:
            journal = journal.with_state(TransactionState.UNINSTALLING, now=now())
        journal_mod.write_journal(state_root, journal)

    if journal.state == TransactionState.UNINSTALLING:
        journal, ok, residuals = _run_uninstall_loop(
            state_root, journal, context, registry=registry, expected_executor_version=expected_executor_version
        )
        if not ok:
            journal = journal.with_state(TransactionState.UNINSTALL_FAILED, now=now(), failure={"residuals": residuals})
            journal_mod.write_journal(state_root, journal)
            return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "uninstall did not complete for all resources during recovery")
        journal = journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=now())
        journal_mod.write_journal(state_root, journal)

    # journal.state == TransactionState.REVOKING_OWNERSHIP here -- but this
    # is never trusted as sufficient on its own, nor is journal.steps' own
    # recorded state in isolation: independently reconfirm from the
    # snapshot's own digest, the source transaction's authority, every
    # step's real VERIFIED state, and a live recheck that none of the
    # snapshotted resources are still present before ever revoking.
    safe, unsafe_reason = _revocation_boundary_is_safe(
        state_root, journal, registry=registry, expected_executor_version=expected_executor_version, context=context
    )
    if not safe:
        journal = journal.with_state(
            TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "unsafe to revoke ownership: %s" % unsafe_reason}
        )
        journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "unsafe to revoke ownership: %s" % unsafe_reason)

    _verify_allowed_roots_identity(context)
    revoked, revoke_error = _revoke_ownership_and_verify(state_root, journal.capability_id)
    if revoked:
        journal = journal.with_state(TransactionState.UNINSTALLED, now=now())
        journal_mod.write_journal(state_root, journal)
        return RecoveryDecision(journal.transaction_id, RecoveryAction.RESUME, "resumed uninstall and completed")
    journal = journal.with_state(TransactionState.UNINSTALL_FAILED, now=now(), failure={"reason": "ownership_revocation_failed", "error": revoke_error})
    journal_mod.write_journal(state_root, journal)
    return RecoveryDecision(journal.transaction_id, RecoveryAction.REQUIRE_MANUAL, "ownership revocation did not complete during recovery")


# --------------------------------------------------------------------------
# Uninstall
# --------------------------------------------------------------------------


def _build_uninstall_plan(capability_id: str, owned: Sequence[OwnershipRecord], *, transaction_id: str) -> UninstallPlan:
    """``transaction_id`` is always caller-supplied, never minted internally:
    ``uninstall()`` passes the SAME id it uses for the provisioner-lock
    metadata, so the ``PrepareOutcome.transaction_id`` it returns is always
    exactly the uninstall journal's own id -- never a second, independently
    generated identifier the caller would have no way to correlate back to
    the actual journal on disk."""
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
        transaction_id=transaction_id,
        target_transaction_id=owned[0].created_by_transaction or "",
        ownership_records=tuple(owned),
        steps=steps,
    )


def _uninstall_source_matches(
    state_root: Path,
    journal: TransactionJournal,
    *,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
) -> bool:
    """Re-derives the uninstall plan from the journal's OWN immutable
    ``owned_snapshot`` -- never the live ownership file, which recovery must
    not depend on exclusively (it may already be gone by the time recovery
    runs, e.g. after ownership has been revoked but before the transaction
    reached UNINSTALLED) -- and confirms both that the snapshot is still
    traceable to a committed source transaction, and that recomputing the
    digest from that exact snapshot still matches what this journal recorded
    when it was created. A divergence in either direction means recovery,
    never a blind unlink."""
    owned = [record for record in journal.owned_snapshot if record.product_owned]
    if not owned:
        return False
    if not validate_ownership_authority(
        state_root, journal.capability_id, owned,
        registry=registry, expected_executor_version=expected_executor_version, context=context,
    ):
        return False
    try:
        candidate_plan = _build_uninstall_plan(journal.capability_id, owned, transaction_id=journal.transaction_id)
    except ValueError:
        return False
    if compute_uninstall_plan_digest(candidate_plan) != journal.plan_digest:
        return False
    return _uninstall_journal_steps_match_plan_exactly(journal, candidate_plan)


def _uninstall_journal_steps_match_plan_exactly(journal: TransactionJournal, plan: UninstallPlan) -> bool:
    """Point 4, fifth correction round: an uninstall journal's own
    ``journal.steps`` must be structurally IDENTICAL to the plan
    reconstructed from ``owned_snapshot`` -- same cardinality, unique
    sequences, and for each sequence an exact match of
    step_id/action_type/target/intent. Unlike the "prepare" side,
    ``compute_uninstall_plan_digest`` is computed purely from
    ``ownership_records``/``target_transaction_id``/``capability_id`` (see
    ``canonical_uninstall_plan_mapping``): it never actually covers
    ``journal.steps`` at all, since ``_build_uninstall_plan`` always
    derives ``plan.steps`` fresh, one per ownership record, in a fixed
    order -- so an attacker (or corruption) could add, remove, duplicate or
    alter a step in ``journal.steps`` without EVER moving ``plan_digest``.
    This is the check that closes that gap: it also transitively enforces
    "an ownership record exists for every step and no step lacks one" and
    "no additional steps", since ``_build_uninstall_plan`` builds exactly
    one step per ownership record by construction."""
    if len(journal.steps) != len(plan.steps):
        return False
    journal_sequences = [step.sequence for step in journal.steps]
    if len(set(journal_sequences)) != len(journal_sequences):
        return False
    plan_by_sequence = {step.sequence: step for step in plan.steps}
    if set(journal_sequences) != set(plan_by_sequence):
        return False
    for journal_step in journal.steps:
        plan_step = plan_by_sequence[journal_step.sequence]
        if journal_step.step_id != plan_step.step_id:
            return False
        if journal_step.action_type != plan_step.action_type:
            return False
        if journal_step.target != plan_step.target:
            return False
        if dict(journal_step.intent) != dict(plan_step.intent):
            return False
    return True


def _revocation_boundary_is_safe(
    state_root: Path,
    journal: TransactionJournal,
    *,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
    context: ExecutionContext,
) -> tuple[bool, str | None]:
    """Independently re-confirms, from first principles, that it is safe to
    revoke ownership -- never trusting the top-level transaction state
    (``REVOKING_OWNERSHIP``) alone, and never trusting ``journal.steps``'
    own recorded state in isolation either. Recomputes the uninstall plan
    digest fresh from the journal's immutable ``owned_snapshot``, reverifies
    the snapshot against the source ("prepare") transaction, requires every
    step to be exactly ``VERIFIED``, and independently re-confirms on disk
    that none of the snapshotted resources are still present. Any
    impossible combination -- a step not ``VERIFIED``, a digest mismatch, an
    invalid snapshot, a resource still present, or an inspection error --
    means the caller must treat this as ``RECOVERY_REQUIRED`` and never
    revoke ownership."""
    owned = [record for record in journal.owned_snapshot if record.product_owned]
    if not owned:
        return False, "empty ownership snapshot"
    if not validate_ownership_authority(
        state_root, journal.capability_id, owned,
        registry=registry, expected_executor_version=expected_executor_version, context=context,
        exclude_uninstall_transaction_id=journal.transaction_id,
    ):
        return False, "ownership snapshot no longer traces to a valid committed transaction"
    try:
        candidate_plan = _build_uninstall_plan(journal.capability_id, owned, transaction_id=journal.transaction_id)
    except ValueError as exc:
        return False, "cannot rebuild uninstall plan from snapshot: %s" % exc
    if compute_uninstall_plan_digest(candidate_plan) != journal.plan_digest:
        return False, "uninstall plan digest no longer matches the journal's own snapshot"
    if not _uninstall_journal_steps_match_plan_exactly(journal, candidate_plan):
        return False, "uninstall journal steps no longer match the plan reconstructed from the ownership snapshot"
    if any(step.state != StepState.VERIFIED for step in journal.steps):
        return False, "not every uninstall step is VERIFIED"
    for record in owned:
        # Descriptor-safe: reconstructs and validates the path through the
        # same allowlist/forbidden-roots policy, then confirms absence
        # relative to an ALREADY-CAPTURED AllowedRootHandle (point 5, fifth
        # correction round) -- never an isolated os.lstat() on the bare
        # persisted path string, and never a fresh path-based re-open of
        # the allowed root either, both of which are vulnerable to a TOCTOU
        # ancestor-swap between validation and the check itself.
        absent, reason = confirm_absent_descriptor_safe(
            record.candidate.resource_identity, allowed_root_handles=context.allowed_root_handles, forbidden_roots=context.forbidden_roots
        )
        if not absent:
            return False, reason
    return True, None


def _revoke_ownership_and_verify(state_root: Path, capability_id: str) -> tuple[bool, str | None]:
    """Durably revoke (tombstone) the live ownership file and verify the
    revocation actually landed -- idempotent, so recovery can safely call
    this again after a crash whether the delete itself already happened or
    not. Never raises: EVERY controlled failure -- a plain ``OSError`` from
    the unlink itself, or a ``DurabilityError`` from the parent-directory
    fsync that follows it (the unlink may have genuinely succeeded, but its
    survival across a crash is then unconfirmed) -- is reported as
    ``(False, reason)``, never an unhandled exception. This is what lets the
    caller drive the transaction to a recoverable failure state instead of
    crashing mid-uninstall, and guarantees the transaction can never reach
    ``UNINSTALLED`` while revocation durability is unconfirmed."""
    try:
        journal_mod.delete_ownership_records(state_root, capability_id)
    except DurabilityError as exc:
        return False, "ownership revocation durability could not be confirmed: %s" % exc
    except OSError as exc:
        return False, "failed to revoke ownership: %s" % exc
    name = "%s.json" % capability_id
    try:
        if isinstance(state_root, StateRootHandle):
            os.lstat(name, dir_fd=state_root.subdir_fd(journal_mod.OWNERSHIP_DIR))
        else:
            os.lstat(journal_mod.ownership_path(state_root, capability_id))
    except FileNotFoundError:
        return True, None
    except OSError as exc:
        return False, "cannot verify ownership revocation: %s" % exc
    return False, "ownership file still present after revocation attempt"


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
        owned_snapshot=plan.ownership_records,
    )


def _mark_uninstall_step_failed(record: StepRecord, error_kind: str, error: str, *, now_value: str) -> StepRecord:
    if record.state == StepState.PLANNED:
        record = record.with_state(StepState.APPLYING, started_at=now_value)
    return record.with_state(StepState.APPLY_FAILED, completed_at=now_value, error_kind=error_kind, error=error)


def _detect_ownership_drift(record: OwnershipRecord, validated_path: Path, handle: AllowedRootHandle) -> str | None:
    """Compares a resource's CURRENT uid/gid/mode/hard-link-count/canonical
    path against what its ``OwnershipRecord`` captured at commit time (the
    content hash itself is separately re-verified by
    ``remove_file_if_owned_relative`` immediately before the unlink).
    Returns a human-readable description of the first drift found, or
    ``None`` if nothing has drifted -- callers must refuse to remove the
    resource (no unlink) on ANY drift, since it may no longer be the exact
    resource this transaction created (a `chmod`, a `chown`, an added hard
    link, or a path re-pointed via an intermediate change all count).
    Resolved via ``handle`` (point 2, fifth correction round), never a
    fresh path-based lookup."""
    candidate = record.candidate
    if str(validated_path) != candidate.resource_identity:
        return "path drifted: expected %s, resolved to %s" % (candidate.resource_identity, validated_path)
    try:
        identity = stat_identity_relative(handle, validated_path)
    except (OSError, PathPolicyError) as exc:
        return "cannot inspect current identity: %s" % exc
    expected_nlink = candidate.nlink if candidate.nlink is not None else 1
    if identity["nlink"] != expected_nlink:
        return "hard link count drifted to %d (expected %d)" % (identity["nlink"], expected_nlink)
    if candidate.uid is not None and identity["uid"] != candidate.uid:
        return "owner uid drifted: expected %d, found %d" % (candidate.uid, identity["uid"])
    if candidate.gid is not None and identity["gid"] != candidate.gid:
        return "owner gid drifted: expected %d, found %d" % (candidate.gid, identity["gid"])
    if candidate.mode is not None and identity["mode"] != candidate.mode:
        return "mode drifted: expected %o, found %o" % (candidate.mode, identity["mode"])
    return None


def _run_uninstall_loop(
    state_root: Path,
    journal: TransactionJournal,
    context: ExecutionContext,
    *,
    registry: TrustedExecutorRegistry,
    expected_executor_version: str,
) -> tuple[TransactionJournal, bool, list[str]]:
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
    if not _uninstall_source_matches(
        state_root, journal, registry=registry, expected_executor_version=expected_executor_version, context=context
    ):
        return journal, False, ["plan_digest_mismatch"]

    # Point 2, fifth correction round: reconfirm every allowed root's
    # identity before the first unlink of this run -- an allowed root
    # (e.g. the sandbox) renamed/replaced right before uninstall begins
    # must never be silently unlinked-from-under via the still-valid,
    # fd-immune handle while reporting success; it must instead fail
    # closed (PathPolicyError, converted by the caller into
    # RECOVERY_REQUIRED), leaving every resource still sitting untouched
    # in the renamed-aside original directory as an inspectable residual.
    _verify_allowed_roots_identity(context)

    residuals: list[str] = []
    ok = True
    for step in journal.steps:
        record = journal.step(step.sequence)
        if record.state == StepState.VERIFIED:
            continue

        path = Path(record.intent["resource_identity"])
        try:
            validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
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
                identity = stat_identity_relative(handle, validated)
            except FileNotFoundError:
                exists = False
                is_symlink = False
            except (OSError, PathPolicyError) as exc:
                # A permission/I-O/stale-handle error is NOT the same as the
                # path being absent -- treating it as absence here could
                # make recovery believe a resource was already removed when
                # it simply could not be inspected, and skip straight to
                # APPLIED without ever actually removing it.
                record = _mark_uninstall_step_failed(record, "inspection_error", str(exc), now_value=now())
                journal = journal.with_step(record)
                journal_mod.write_journal(state_root, journal)
                residuals.append(record.step_id)
                ok = False
                continue
            else:
                exists = True
                is_symlink = identity["is_symlink"]

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
                owned_record = next(
                    (r for r in journal.owned_snapshot if r.candidate.resource_identity == record.intent["resource_identity"]), None
                )
                if owned_record is not None:
                    drift = _detect_ownership_drift(owned_record, validated, handle)
                    if drift is not None:
                        record = _mark_uninstall_step_failed(record, "ownership_drift", drift, now_value=now())
                        journal = journal.with_step(record)
                        journal_mod.write_journal(state_root, journal)
                        residuals.append(record.step_id)
                        ok = False
                        continue
                try:
                    remove_file_if_owned_relative(handle, validated, expected_sha256=expected_sha256)
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
        # Resolved via ``handle``, never a fresh path-based lookup: only a
        # genuine FileNotFoundError may ever result in VERIFIED here.
        try:
            stat_identity_relative(handle, validated)
        except FileNotFoundError:
            record = record.with_state(StepState.VERIFIED, completed_at=now(), verification={"removed": True})
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            continue
        except (OSError, PathPolicyError) as exc:
            record = record.with_state(StepState.VERIFY_FAILED, completed_at=now(), error_kind="inspection_error", error=str(exc))
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            residuals.append(record.step_id)
            ok = False
            continue

        record = record.with_state(StepState.VERIFY_FAILED, completed_at=now(), error_kind="residual", error="path still exists after removal")
        journal = journal.with_step(record)
        journal_mod.write_journal(state_root, journal)
        residuals.append(record.step_id)
        ok = False
    return journal, ok, residuals


def uninstall(capability_id: str, env: ProvisioningEnvironment, *, apply: bool) -> PrepareOutcome:
    owned = [record for record in journal_mod.read_ownership_records(env.state_root, capability_id) if record.product_owned]
    if not owned:
        return PrepareOutcome(
            PrepareStatus.OUT_OF_CONTRACT, None, None,
            "no product-owned resources recorded for capability %s; nothing to uninstall" % capability_id,
            error_kind="nothing_to_uninstall",
        )
    if not validate_ownership_authority(
        env.state_root, capability_id, owned,
        registry=env.registry, expected_executor_version=env.expected_executor_version, context=env.context,
    ):
        return PrepareOutcome(
            PrepareStatus.OWNERSHIP_INVALID, None, None,
            "ownership records for capability %s do not correspond, in full, to any committed transaction; refusing to uninstall" % capability_id,
            error_kind="ownership_invalid",
        )

    if not apply:
        return PrepareOutcome(PrepareStatus.DRY_RUN, None, None, "uninstall dry-run: %d resource(s) would be removed" % len(owned))

    transaction_id = _new_transaction_id()
    try:
        with lock_mod.acquire_provisioner_lock(
            env.state_root, global_lock_root=env.global_lock_root, transaction_id=transaction_id, timeout=env.lock_timeout
        ) as handle:
            locked_context = _open_locked_context(env.context)
            try:
                recovery_reports = _recover_pending_locked(handle, env.registry, env.expected_executor_version, locked_context)
                blocking = [item for item in recovery_reports if item.action == RecoveryAction.REQUIRE_MANUAL]
                if blocking:
                    return PrepareOutcome(
                        PrepareStatus.PENDING_RECOVERY, None, None,
                        "cannot uninstall while others require manual recovery: %s" % [item.transaction_id for item in blocking],
                        error_kind="recovery_required",
                    )

                owned = [record for record in journal_mod.read_ownership_records(handle, capability_id) if record.product_owned]
                if not owned:
                    return PrepareOutcome(PrepareStatus.OUT_OF_CONTRACT, None, None, "nothing to uninstall", error_kind="nothing_to_uninstall")
                _eager_cache_intermediates_for_targets(locked_context, [r.candidate.resource_identity for r in owned])
                if not validate_ownership_authority(
                    handle, capability_id, owned,
                    registry=env.registry, expected_executor_version=env.expected_executor_version, context=locked_context,
                ):
                    return PrepareOutcome(
                        PrepareStatus.OWNERSHIP_INVALID, None, None,
                        "ownership records for capability %s do not correspond, in full, to any committed transaction; refusing to uninstall" % capability_id,
                        error_kind="ownership_invalid",
                    )

                plan = _build_uninstall_plan(capability_id, owned, transaction_id=transaction_id)
                now = env.context.now
                journal = _initial_uninstall_journal(plan, now_value=now())
                journal_mod.write_journal(handle, journal)
                journal = journal.with_state(TransactionState.UNINSTALLING, now=now())
                journal_mod.write_journal(handle, journal)

                journal, ok, residuals = _run_uninstall_loop(
                    handle, journal, locked_context, registry=env.registry, expected_executor_version=env.expected_executor_version
                )

                if not ok:
                    journal = journal.with_state(TransactionState.UNINSTALL_FAILED, now=now(), failure={"residuals": residuals})
                    journal_mod.write_journal(handle, journal)
                    return PrepareOutcome(
                        PrepareStatus.UNINSTALL_FAILED, None, transaction_id,
                        "uninstall did not complete for all resources", residuals=tuple(residuals), error_kind="uninstall_failed",
                    )

                # All resources are confirmed removed. Ownership must be durably
                # revoked and that revocation verified BEFORE the transaction may
                # ever be declared UNINSTALLED -- a crash between "resources gone"
                # and "ownership revoked" must never leave silent uninstall
                # authority behind (see _capability_has_completed_uninstall, which
                # recognizes and rejects exactly that stale window on recovery).
                journal = journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=now())
                journal_mod.write_journal(handle, journal)

                safe, unsafe_reason = _revocation_boundary_is_safe(
                    handle, journal,
                    registry=env.registry, expected_executor_version=env.expected_executor_version, context=locked_context,
                )
                if not safe:
                    journal = journal.with_state(
                        TransactionState.RECOVERY_REQUIRED, now=now(), recovery={"reason": "unsafe to revoke ownership: %s" % unsafe_reason}
                    )
                    journal_mod.write_journal(handle, journal)
                    return PrepareOutcome(
                        PrepareStatus.RECOVERY_REQUIRED, None, transaction_id,
                        "unsafe to revoke ownership: %s" % unsafe_reason, error_kind="recovery_required",
                    )

                _verify_allowed_roots_identity(locked_context)
                revoked, revoke_error = _revoke_ownership_and_verify(handle, capability_id)
                if revoked:
                    journal = journal.with_state(TransactionState.UNINSTALLED, now=now())
                    journal_mod.write_journal(handle, journal)
                    return PrepareOutcome(PrepareStatus.UNINSTALLED, None, transaction_id, "uninstalled %d resource(s)" % len(owned))

                journal = journal.with_state(TransactionState.UNINSTALL_FAILED, now=now(), failure={"reason": "ownership_revocation_failed", "error": revoke_error})
                journal_mod.write_journal(handle, journal)
                return PrepareOutcome(
                    PrepareStatus.UNINSTALL_FAILED, None, transaction_id,
                    "resources removed but ownership revocation did not complete", residuals=("ownership",), error_kind="ownership_revocation_failed",
                )
            finally:
                _close_locked_context(locked_context)
    except (StateRootIdentityError, PathPolicyError) as exc:
        return PrepareOutcome(
            PrepareStatus.RECOVERY_REQUIRED, None, transaction_id,
            "state root identity changed during the transaction; refusing to report a clean outcome: %s" % exc,
            error_kind="state_root_identity_mismatch",
        )
