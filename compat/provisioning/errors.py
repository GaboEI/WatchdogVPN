"""Controlled error types for transactional provisioning (Phase 23.7.5.6a)."""

from __future__ import annotations


class ProvisioningError(RuntimeError):
    """Base class for every controlled provisioning error."""


class InvalidTransitionError(ProvisioningError):
    """Raised when a transaction/step state transition is not allowed."""


class ExecutorNotRegisteredError(ProvisioningError):
    """Raised when no trusted executor is registered for a selected method."""


class ExecutionNotReadyError(ProvisioningError):
    """Raised when a ResolutionDecision is not eligible for execution."""


class PathPolicyError(ProvisioningError):
    """Raised when a target path violates the path-protection contract."""


class IdentifierError(ProvisioningError):
    """Raised when a transaction_id/capability_id/dependency_id (or any other
    identifier used to build a persistent path) fails the identifier grammar."""


class DurabilityError(ProvisioningError):
    """Raised when an action's own effect succeeded but its containing
    directory could not be durably fsynced. Callers must never declare the
    action verified/committed/undone/uninstalled when this is raised."""


class ProvisionerLockHeldError(ProvisioningError):
    """Raised when the global provisioner lock is held by another process."""

    def __init__(self, message: str, *, holder_pid: int | None = None, holder_transaction_id: str | None = None):
        super().__init__(message)
        self.holder_pid = holder_pid
        self.holder_transaction_id = holder_transaction_id


class JournalError(ProvisioningError):
    """Raised for corrupt, unknown-schema, digest-mismatched or out-of-policy journals."""


class RecoveryRequiredError(ProvisioningError):
    """Raised when a pending transaction cannot be safely resumed or rolled back automatically."""


class OwnershipError(ProvisioningError):
    """Raised for ownership conflicts or drift."""
