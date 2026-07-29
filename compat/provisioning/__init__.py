"""Transactional provisioning infrastructure (Phase 23.7.5.6a).

Pure domain model, durable journal, dedicated lock, path protection, a
trusted (code-only) executor registry with a lab-only canary executor, and
the coordinating engine (plan/dry-run/apply/verify/rollback/recover/
uninstall). No production executor is registered here; see
``docs/phase-23-7-5-compatibility-contract.md`` for the exact 23.7.5.6a scope
and ``compat.provisioning.executors.CanaryExecutor`` for the lab-only
demonstration executor.
"""

from __future__ import annotations

from compat.provisioning.digest import compute_plan_digest, compute_uninstall_plan_digest
from compat.provisioning.engine import (
    IdempotencyCheck,
    IdempotencyOutcome,
    PrepareOutcome,
    PrepareStatus,
    ProvisioningEnvironment,
    build_plan,
    check_idempotency,
    describe_plan,
    dry_run,
    prepare,
    recover_pending,
    uninstall,
    validate_ownership_authority,
)
from compat.provisioning.errors import (
    DurabilityError,
    ExecutionNotReadyError,
    ExecutorNotRegisteredError,
    IdentifierError,
    InvalidTransitionError,
    JournalError,
    OwnershipError,
    PathPolicyError,
    ProvisionerLockHeldError,
    ProvisioningError,
    RecoveryRequiredError,
)
from compat.provisioning.executors import (
    CANARY_EXECUTOR_ID,
    CANARY_EXECUTOR_VERSION,
    CANARY_METHOD_KIND,
    CanaryExecutor,
    ExecutionContext,
    Executor,
    TrustedExecutorRegistry,
)
from compat.provisioning.journal import StepRecord, TransactionJournal
from compat.provisioning.lock import acquire_provisioner_lock
from compat.provisioning.model import (
    ExecutionResult,
    IntermediateIdentity,
    OwnershipCandidate,
    OwnershipRecord,
    PathAuthority,
    PathComponentIdentity,
    ProvenanceRecord,
    ProvisioningPlan,
    ProvisioningStep,
    RecoveryAction,
    RecoveryDecision,
    RollbackResult,
    StepState,
    TransactionState,
    UninstallPlan,
    VerificationResult,
    transition_step,
    transition_transaction,
)
from compat.provisioning.paths import validate_identifier, validate_target_path

__all__ = [
    "CANARY_EXECUTOR_ID",
    "CANARY_EXECUTOR_VERSION",
    "CANARY_METHOD_KIND",
    "CanaryExecutor",
    "DurabilityError",
    "ExecutionContext",
    "ExecutionNotReadyError",
    "ExecutionResult",
    "Executor",
    "ExecutorNotRegisteredError",
    "IdempotencyCheck",
    "IdempotencyOutcome",
    "IdentifierError",
    "IntermediateIdentity",
    "InvalidTransitionError",
    "JournalError",
    "OwnershipCandidate",
    "OwnershipError",
    "OwnershipRecord",
    "PathAuthority",
    "PathComponentIdentity",
    "PathPolicyError",
    "PrepareOutcome",
    "PrepareStatus",
    "ProvenanceRecord",
    "ProvisionerLockHeldError",
    "ProvisioningEnvironment",
    "ProvisioningError",
    "ProvisioningPlan",
    "ProvisioningStep",
    "RecoveryAction",
    "RecoveryDecision",
    "RecoveryRequiredError",
    "RollbackResult",
    "StepRecord",
    "StepState",
    "TransactionJournal",
    "TransactionState",
    "TrustedExecutorRegistry",
    "UninstallPlan",
    "VerificationResult",
    "acquire_provisioner_lock",
    "build_plan",
    "check_idempotency",
    "compute_plan_digest",
    "compute_uninstall_plan_digest",
    "describe_plan",
    "dry_run",
    "prepare",
    "recover_pending",
    "transition_step",
    "transition_transaction",
    "uninstall",
    "validate_identifier",
    "validate_ownership_authority",
    "validate_target_path",
]
