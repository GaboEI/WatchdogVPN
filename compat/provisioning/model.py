"""Transactional provisioning domain model (Phase 23.7.5.6a).

Pure, immutable/validated types plus explicit state machines for the
provisioning transaction and its individual steps. No I/O, no subprocess, no
network. Journal persistence lives in ``journal.py``; execution lives in
``executors.py``/``engine.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Sequence

from compat.provisioning.errors import InvalidTransitionError


class TransactionState(Enum):
    PLANNED = "planned"
    AUTHORIZED = "authorized"
    APPLYING = "applying"
    VERIFYING = "verifying"
    PREPARE_TERMINAL_PREPARED = "prepare_terminal_prepared"
    COMMITTED = "committed"
    PREPARATION_FAILED = "preparation_failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    RECOVERY_REQUIRED = "recovery_required"
    RECOVERING = "recovering"
    UNINSTALL_PLANNED = "uninstall_planned"
    UNINSTALLING = "uninstalling"
    REVOKING_OWNERSHIP = "revoking_ownership"
    UNINSTALL_TERMINAL_PREPARED = "uninstall_terminal_prepared"
    UNINSTALLED = "uninstalled"
    UNINSTALL_FAILED = "uninstall_failed"


class StepState(Enum):
    PLANNED = "planned"
    APPLYING = "applying"
    APPLIED = "applied"
    APPLY_FAILED = "apply_failed"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    VERIFY_FAILED = "verify_failed"
    UNDOING = "undoing"
    UNDONE = "undone"
    UNDO_FAILED = "undo_failed"


# First match is the current state; the set is every state it may legally
# transition to. Terminal states map to an empty set. Any transition not
# present here is rejected by transition_transaction() with no journal
# mutation, so an impossible jump (e.g. planned -> committed, committed ->
# applying, rolled_back -> verifying, uninstalled -> applying) is a
# controlled InvalidTransitionError, never a silent state change.
TRANSACTION_TRANSITIONS: Mapping[TransactionState, frozenset[TransactionState]] = {
    TransactionState.PLANNED: frozenset({TransactionState.AUTHORIZED}),
    TransactionState.AUTHORIZED: frozenset({TransactionState.APPLYING}),
    TransactionState.APPLYING: frozenset(
        {TransactionState.VERIFYING, TransactionState.ROLLING_BACK, TransactionState.RECOVERY_REQUIRED}
    ),
    TransactionState.VERIFYING: frozenset(
        {
            TransactionState.PREPARE_TERMINAL_PREPARED,
            TransactionState.COMMITTED,
            TransactionState.ROLLING_BACK,
            TransactionState.RECOVERY_REQUIRED,
        }
    ),
    TransactionState.PREPARE_TERMINAL_PREPARED: frozenset({TransactionState.COMMITTED, TransactionState.RECOVERY_REQUIRED}),
    TransactionState.COMMITTED: frozenset({TransactionState.UNINSTALL_PLANNED}),
    TransactionState.PREPARATION_FAILED: frozenset(),
    TransactionState.ROLLING_BACK: frozenset({TransactionState.ROLLED_BACK, TransactionState.ROLLBACK_FAILED}),
    TransactionState.ROLLED_BACK: frozenset({TransactionState.PREPARATION_FAILED}),
    TransactionState.ROLLBACK_FAILED: frozenset({TransactionState.RECOVERY_REQUIRED}),
    TransactionState.RECOVERY_REQUIRED: frozenset({TransactionState.RECOVERING}),
    TransactionState.RECOVERING: frozenset(
        {
            TransactionState.APPLYING,
            TransactionState.VERIFYING,
            TransactionState.ROLLING_BACK,
            TransactionState.RECOVERY_REQUIRED,
            TransactionState.UNINSTALLING,
            TransactionState.REVOKING_OWNERSHIP,
            TransactionState.UNINSTALL_TERMINAL_PREPARED,
        }
    ),
    TransactionState.UNINSTALL_PLANNED: frozenset({TransactionState.UNINSTALLING}),
    TransactionState.UNINSTALLING: frozenset(
        {TransactionState.REVOKING_OWNERSHIP, TransactionState.UNINSTALL_FAILED, TransactionState.RECOVERY_REQUIRED}
    ),
    TransactionState.REVOKING_OWNERSHIP: frozenset(
        {
            TransactionState.UNINSTALL_TERMINAL_PREPARED,
            TransactionState.UNINSTALLED,
            TransactionState.UNINSTALL_FAILED,
            TransactionState.RECOVERY_REQUIRED,
        }
    ),
    TransactionState.UNINSTALL_TERMINAL_PREPARED: frozenset({TransactionState.UNINSTALLED, TransactionState.RECOVERY_REQUIRED}),
    TransactionState.UNINSTALLED: frozenset(),
    TransactionState.UNINSTALL_FAILED: frozenset({TransactionState.RECOVERY_REQUIRED}),
}

STEP_TRANSITIONS: Mapping[StepState, frozenset[StepState]] = {
    StepState.PLANNED: frozenset({StepState.APPLYING}),
    StepState.APPLYING: frozenset({StepState.APPLIED, StepState.APPLY_FAILED}),
    StepState.APPLIED: frozenset({StepState.VERIFYING}),
    StepState.APPLY_FAILED: frozenset({StepState.UNDOING}),
    StepState.VERIFYING: frozenset({StepState.VERIFIED, StepState.VERIFY_FAILED}),
    StepState.VERIFIED: frozenset({StepState.UNDOING}),
    StepState.VERIFY_FAILED: frozenset({StepState.UNDOING}),
    StepState.UNDOING: frozenset({StepState.UNDONE, StepState.UNDO_FAILED}),
    StepState.UNDONE: frozenset(),
    StepState.UNDO_FAILED: frozenset(),
}


def transition_transaction(current: TransactionState, next_state: TransactionState) -> TransactionState:
    allowed = TRANSACTION_TRANSITIONS.get(current)
    if allowed is None or next_state not in allowed:
        raise InvalidTransitionError(
            "invalid transaction transition: %s -> %s" % (current.value, next_state.value)
        )
    return next_state


def transition_step(current: StepState, next_state: StepState) -> StepState:
    allowed = STEP_TRANSITIONS.get(current)
    if allowed is None or next_state not in allowed:
        raise InvalidTransitionError("invalid step transition: %s -> %s" % (current.value, next_state.value))
    return next_state


@dataclass(frozen=True)
class ProvisioningStep:
    """One planned, structured unit of work. Never a shell command."""

    sequence: int
    step_id: str
    action_type: str
    intent: Mapping[str, object]
    target: str | None = None


@dataclass(frozen=True)
class ProvisioningPlan:
    """A deterministic plan bound to one resolver decision and one executor."""

    capability_id: str
    dependency_id: str
    resolved_target: str
    architecture: str
    support_classification: str
    selected_method_id: str
    selected_method_kind: str
    postcondition: str
    executor_id: str
    executor_version: str
    steps: tuple[ProvisioningStep, ...]
    selected_asset: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError("a provisioning plan must declare at least one step")
        sequences = [step.sequence for step in self.steps]
        if sequences != sorted(sequences) or len(set(sequences)) != len(sequences):
            raise ValueError("provisioning plan steps must have strictly increasing unique sequences")


@dataclass(frozen=True)
class ExecutionResult:
    status: str  # "applied" | "apply_failed"
    observed: Mapping[str, object] = field(default_factory=dict)
    undo_record: Mapping[str, object] | None = None
    error_kind: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    status: str  # "verified" | "verification_failed"
    evidence: Mapping[str, object] = field(default_factory=dict)
    error_kind: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class RollbackResult:
    status: str  # "undone" | "undo_failed"
    residual: bool
    evidence: Mapping[str, object] = field(default_factory=dict)
    error_kind: str | None = None
    error: str | None = None


class RecoveryAction(Enum):
    RESUME = "resume"
    ROLLBACK = "rollback"
    REQUIRE_MANUAL = "require_manual"


@dataclass(frozen=True)
class RecoveryDecision:
    transaction_id: str
    action: RecoveryAction
    reason: str
    boundary_step_sequence: int | None = None


@dataclass(frozen=True)
class IntermediateIdentity:
    relative_name: str
    dev: int
    ino: int
    uid: int
    mode: int


@dataclass(frozen=True)
class PathComponentIdentity:
    index: int
    relative_name: str
    dev: int
    ino: int
    uid: int
    mode: int


@dataclass(frozen=True)
class PathAuthority:
    root_path: str
    target_relative_path: str
    component_count: int
    components: tuple[PathComponentIdentity, ...]


@dataclass(frozen=True)
class PathAuthorityV2Component:
    index: int
    name: str
    role: str
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int
    nlink: int
    integrity: str | None = None


@dataclass(frozen=True)
class PathAuthorityV2:
    schema: str
    transaction_id: str
    plan_digest: str
    resource_id: str
    configured_root: str
    root_path: str
    target_relative_path: str
    component_count: int
    components: tuple[PathAuthorityV2Component, ...]
    chain_digest: str
    authority_digest: str


class CustodyState(Enum):
    MOVE_PENDING = "move_pending"
    MOVED = "moved"
    DELETED = "deleted"


@dataclass(frozen=True)
class CustodyRecord:
    resource_id: str
    state: CustodyState
    original_path: str
    original_parent: str
    original_name: str
    original_dev: int
    original_ino: int
    original_uid: int
    original_gid: int
    original_mode: int
    original_nlink: int
    authorized_hash: str | None
    custody_dir: str
    custody_dir_dev: int
    custody_dir_ino: int
    custody_dir_uid: int
    custody_dir_gid: int
    custody_dir_mode: int
    custody_name: str
    moved_dev: int | None = None
    moved_ino: int | None = None
    moved_uid: int | None = None
    moved_gid: int | None = None
    moved_mode: int | None = None
    moved_nlink: int | None = None
    moved_hash: str | None = None


@dataclass(frozen=True)
class OwnershipCandidate:
    artifact_type: str
    resource_identity: str
    pre_existing: bool
    method_id: str | None = None
    source: str | None = None
    version: str | None = None
    integrity: str | None = None
    uid: int | None = None
    gid: int | None = None
    mode: int | None = None
    nlink: int | None = None
    post_install_fingerprint: str | None = None
    intermediate_identities: tuple[IntermediateIdentity, ...] = ()
    path_authority: PathAuthority | None = None
    path_authority_v2: PathAuthorityV2 | None = None


@dataclass(frozen=True)
class OwnershipRecord:
    capability_id: str
    candidate: OwnershipCandidate
    product_owned: bool
    created_by_transaction: str | None
    executor_id: str
    executor_version: str
    recorded_at: str


@dataclass(frozen=True)
class ProvenanceRecord:
    transaction_id: str
    committed_at: str
    ownership_records: tuple[OwnershipRecord, ...]


@dataclass(frozen=True)
class UninstallPlan:
    capability_id: str
    transaction_id: str
    target_transaction_id: str
    ownership_records: tuple[OwnershipRecord, ...]
    steps: tuple[ProvisioningStep, ...]

    def __post_init__(self) -> None:
        if not self.ownership_records:
            raise ValueError("an uninstall plan requires at least one owned resource")
        if any(not record.product_owned for record in self.ownership_records):
            raise ValueError("uninstall plan may only include product-owned ownership records")
