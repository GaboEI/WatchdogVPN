"""Pure, deterministic compatibility support-model domain (Phase 23.7.5.2).

This module is the pure semantic core of the compatibility contract frozen in
``docs/phase-23-7-5-compatibility-contract.md``. It is:

- **OS-independent**: it never reads ``/etc/os-release``, runs a shell command,
  touches the network, requires privileges, or mutates anything.
- **Deterministic**: given the same abstract inputs it always returns the same
  state; the evaluation instant is *injected*, never read from the clock.
- **Policy-parametrized**: it hardcodes no distribution or release. Every input
  is an abstract fact supplied by the caller. The real manifest data is wired in
  a later task, per the frozen phase order (manifest → detection → evaluation).

It defines three orthogonal classifications and their frozen states, the stable
and rolling policies, evidence freshness, and the domain invariants that keep the
three models from contaminating each other. Detection, the manifest, ``doctor``,
the CLI and the provisioner consume this model later; none of that integration
lives here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Sequence


class DomainError(ValueError):
    """Raised when compatibility-model inputs are internally contradictory.

    A contradictory or impossible input combination must never be resolved into a
    silently-chosen state; it is an explicit error.
    """


# --------------------------------------------------------------------------- #
# Frozen public states. The string values are the stable public representation
# consumed later by the manifest, CLI, doctor, JSON, tests and documentation.
# Never expose the language ``.name``/``repr`` as an accidental public form.
# --------------------------------------------------------------------------- #

class SupportClassification(Enum):
    CERTIFIED = "certified"
    SUPPORTED = "supported"
    FAMILY_INFERRED = "family_inferred"
    EXPERIMENTAL = "experimental"
    UNSUPPORTED = "unsupported"


class HostReadiness(Enum):
    READY = "ready"
    NEEDS_PREPARATION = "needs_preparation"
    PREPARATION_FAILED = "preparation_failed"
    INCOMPATIBLE = "incompatible"


class ProtocolReadiness(Enum):
    OPERABLE = "operable"
    PROVISIONABLE = "provisionable"
    ABSENT = "absent"
    UNSUPPORTED_HERE = "unsupported_here"


class ReleaseModel(Enum):
    STABLE = "stable"
    ROLLING = "rolling"


class FreshnessState(Enum):
    CURRENT = "current"
    EXPIRED = "expired"
    ABSENT = "absent"


class CoreCapabilityStatus(Enum):
    """Status of a single *core host* capability (protocol runtimes are separate)."""
    PRESENT = "present"
    PROVISIONABLE = "provisionable"          # absent but a provisioning method exists
    PREPARATION_FAILED = "preparation_failed"  # provisioning was attempted and exhausted
    IMPOSSIBLE = "impossible"                # structurally cannot exist on this host


class ProtocolRuntimeStatus(Enum):
    """Status of a single runtime a protocol requires (a protocol may need several)."""
    PRESENT = "present"
    PROVISIONABLE = "provisionable"
    ABSENT = "absent"                        # absent and not provisionable right now
    IMPOSSIBLE = "impossible"                # structurally cannot run on this host


_STATE_ENUMS = (
    SupportClassification,
    HostReadiness,
    ProtocolReadiness,
    ReleaseModel,
    FreshnessState,
    CoreCapabilityStatus,
    ProtocolRuntimeStatus,
)


def to_value(state: Enum) -> str:
    """Return the stable public string for a domain state."""
    if not isinstance(state, _STATE_ENUMS):
        raise DomainError(f"not a compatibility-model state: {state!r}")
    return state.value


def parse(enum_cls: type[Enum], value: str) -> Enum:
    """Parse a stable string back into its state; an unknown value is a DomainError."""
    if enum_cls not in _STATE_ENUMS:
        raise DomainError(f"not a compatibility-model state type: {enum_cls!r}")
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise DomainError(f"unknown {enum_cls.__name__} value: {value!r}") from exc


# --------------------------------------------------------------------------- #
# support_classification inputs: POLICY / EVIDENCE facts only.
# There is deliberately no machine probe here (no TUN, installed binary,
# NetworkManager, firewall backend, OpenVPN/sing-box/Cloak/AmneziaWG presence,
# ...): a concrete host never promotes or demotes a release's public class.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class StableReleaseFacts:
    """Policy/evidence facts about one discrete stable release."""
    has_adapter: bool
    meets_technical_floor: bool
    admitted: bool
    expressly_excluded: bool
    future_or_unevaluated: bool
    eol_or_withdrawn: bool
    vendor_maintained: bool
    ci_green: bool
    is_derivative_without_own_evidence: bool
    has_valid_field_certification: bool


@dataclass(frozen=True)
class RollingFacts:
    """Policy/evidence facts about a rolling distribution (no numeric minimum)."""
    has_adapter: bool
    meets_technical_floor: bool
    expressly_excluded: bool
    eol_or_withdrawn: bool
    is_derivative_without_own_evidence: bool
    has_valid_field_certification: bool
    last_validated: datetime | None  # None → no validation evidence


# --------------------------------------------------------------------------- #
# Evidence freshness (rolling). The clock is injected via ``now`` so the logic
# is deterministic and testable; the expiry policy is data (a timedelta).
# --------------------------------------------------------------------------- #

def evaluate_freshness(
    last_validated: datetime | None,
    expiry: timedelta,
    now: datetime,
) -> FreshnessState:
    if not isinstance(expiry, timedelta):
        raise DomainError("expiry must be a timedelta supplied as policy data")
    if not isinstance(now, datetime):
        raise DomainError("the evaluation instant 'now' must be injected as a datetime")
    if last_validated is None:
        return FreshnessState.ABSENT
    if now < last_validated:
        raise DomainError("evaluation instant precedes last_validated (validated in the future)")
    return FreshnessState.EXPIRED if (now - last_validated) > expiry else FreshnessState.CURRENT


# --------------------------------------------------------------------------- #
# Input-contradiction guards (impossible combinations → DomainError).
# --------------------------------------------------------------------------- #

def _validate_common_evidence(f: StableReleaseFacts | RollingFacts) -> None:
    if f.has_valid_field_certification and not f.has_adapter:
        raise DomainError("a certified release must have an adapter")
    if f.has_valid_field_certification and not f.meets_technical_floor:
        raise DomainError("a release below the technical floor cannot be certified")
    if f.has_valid_field_certification and f.is_derivative_without_own_evidence:
        raise DomainError(
            "a derivative without its own evidence cannot hold a valid field certification"
        )


def _validate_stable(f: StableReleaseFacts) -> None:
    _validate_common_evidence(f)
    if f.admitted and f.expressly_excluded:
        raise DomainError("a release cannot be both admitted and expressly excluded")
    if f.admitted and f.future_or_unevaluated:
        raise DomainError("a release cannot be both admitted and future/not-yet-evaluated")
    if f.admitted and f.eol_or_withdrawn:
        raise DomainError("a release cannot be both admitted and EOL/withdrawn")
    if f.expressly_excluded and f.future_or_unevaluated:
        raise DomainError("a release cannot be both expressly excluded and future/not-yet-evaluated")
    if f.future_or_unevaluated and f.eol_or_withdrawn:
        raise DomainError("a release cannot be both future/not-yet-evaluated and EOL/withdrawn")


# --------------------------------------------------------------------------- #
# support_classification — deterministic, non-overlapping precedence.
# Disqualifiers (→ unsupported) are checked first, then strongest evidence.
# --------------------------------------------------------------------------- #

def classify_support_stable(f: StableReleaseFacts) -> SupportClassification:
    _validate_stable(f)
    # Disqualifiers (any → unsupported), in the frozen order:
    if not f.has_adapter:
        return SupportClassification.UNSUPPORTED
    if not f.meets_technical_floor:
        return SupportClassification.UNSUPPORTED
    if f.eol_or_withdrawn:
        return SupportClassification.UNSUPPORTED
    if f.expressly_excluded:
        return SupportClassification.UNSUPPORTED
    # In contract. Strongest evidence first:
    if f.has_valid_field_certification:
        return SupportClassification.CERTIFIED
    if f.is_derivative_without_own_evidence:
        return SupportClassification.FAMILY_INFERRED
    if f.future_or_unevaluated:
        return SupportClassification.EXPERIMENTAL
    if f.admitted and f.vendor_maintained and f.ci_green:
        return SupportClassification.SUPPORTED
    # Recognized and in contract, but not certified/inferred/future/supported
    # (e.g. admitted but CI not green): the honest state is experimental.
    return SupportClassification.EXPERIMENTAL


def classify_support_rolling(
    f: RollingFacts,
    *,
    expiry: timedelta,
    now: datetime,
) -> SupportClassification:
    _validate_common_evidence(f)
    if not f.has_adapter:
        return SupportClassification.UNSUPPORTED
    if not f.meets_technical_floor:
        return SupportClassification.UNSUPPORTED
    if f.eol_or_withdrawn:
        return SupportClassification.UNSUPPORTED
    if f.expressly_excluded:
        return SupportClassification.UNSUPPORTED
    if f.has_valid_field_certification:
        return SupportClassification.CERTIFIED
    if f.is_derivative_without_own_evidence:
        return SupportClassification.FAMILY_INFERRED
    freshness = evaluate_freshness(f.last_validated, expiry, now)
    if freshness is FreshnessState.CURRENT:
        return SupportClassification.SUPPORTED
    # expired or absent evidence → experimental
    return SupportClassification.EXPERIMENTAL


def classify_support(
    facts: StableReleaseFacts | RollingFacts,
    *,
    expiry: timedelta | None = None,
    now: datetime | None = None,
) -> SupportClassification:
    """Dispatch to the stable or rolling classifier by input type."""
    if isinstance(facts, StableReleaseFacts):
        return classify_support_stable(facts)
    if isinstance(facts, RollingFacts):
        if expiry is None or now is None:
            raise DomainError("rolling classification requires an injected 'expiry' and 'now'")
        return classify_support_rolling(facts, expiry=expiry, now=now)
    raise DomainError(f"unknown support facts type: {type(facts)!r}")


# --------------------------------------------------------------------------- #
# host_readiness — computed ONLY from core host capability statuses.
# Protocol runtimes are never passed here, so a missing protocol runtime can
# never make the whole host needs_preparation / incompatible.
# --------------------------------------------------------------------------- #

def classify_host_readiness(
    required_core_statuses: Sequence[CoreCapabilityStatus],
) -> HostReadiness:
    statuses = tuple(required_core_statuses)
    for s in statuses:
        if not isinstance(s, CoreCapabilityStatus):
            raise DomainError(f"not a CoreCapabilityStatus: {s!r}")
    if any(s is CoreCapabilityStatus.IMPOSSIBLE for s in statuses):
        return HostReadiness.INCOMPATIBLE
    if any(s is CoreCapabilityStatus.PREPARATION_FAILED for s in statuses):
        return HostReadiness.PREPARATION_FAILED
    if any(s is CoreCapabilityStatus.PROVISIONABLE for s in statuses):
        return HostReadiness.NEEDS_PREPARATION
    return HostReadiness.READY


# --------------------------------------------------------------------------- #
# protocol_readiness — per protocol, independent of every other protocol.
# --------------------------------------------------------------------------- #

def classify_protocol_readiness(
    required_runtime_statuses: Sequence[ProtocolRuntimeStatus],
) -> ProtocolReadiness:
    statuses = tuple(required_runtime_statuses)
    if not statuses:
        raise DomainError("a protocol must declare at least one required runtime")
    for s in statuses:
        if not isinstance(s, ProtocolRuntimeStatus):
            raise DomainError(f"not a ProtocolRuntimeStatus: {s!r}")
    if any(s is ProtocolRuntimeStatus.IMPOSSIBLE for s in statuses):
        return ProtocolReadiness.UNSUPPORTED_HERE
    if any(s is ProtocolRuntimeStatus.ABSENT for s in statuses):
        return ProtocolReadiness.ABSENT
    if any(s is ProtocolRuntimeStatus.PROVISIONABLE for s in statuses):
        return ProtocolReadiness.PROVISIONABLE
    return ProtocolReadiness.OPERABLE


# --------------------------------------------------------------------------- #
# Domain invariants. The classifiers already honor these by construction; these
# checkers re-assert them for a (facts, result) pair so tests can prove any
# hand-built contradiction is rejected rather than silently accepted.
# --------------------------------------------------------------------------- #

def check_stable_invariants(f: StableReleaseFacts, result: SupportClassification) -> None:
    # 1. certified requires physical evidence.
    if result is SupportClassification.CERTIFIED and not f.has_valid_field_certification:
        raise DomainError("certified requires a valid field certification")
    # 2. supported (stable) requires an admitted release.
    if result is SupportClassification.SUPPORTED and not f.admitted:
        raise DomainError("stable 'supported' requires an admitted release")
    # 3. family_inferred cannot carry a valid individual certification.
    if result is SupportClassification.FAMILY_INFERRED and f.has_valid_field_certification:
        raise DomainError("family_inferred cannot hold a valid individual certification")
    # 4. experimental cannot represent an expressly-excluded release.
    if result is SupportClassification.EXPERIMENTAL and f.expressly_excluded:
        raise DomainError("experimental cannot represent an expressly-excluded release")
    # A no-adapter or below-floor release can only be unsupported.
    if (not f.has_adapter or not f.meets_technical_floor) and result is not SupportClassification.UNSUPPORTED:
        raise DomainError("a release without an adapter or below the floor must be unsupported")


def check_rolling_invariants(
    f: RollingFacts,
    result: SupportClassification,
    *,
    freshness: FreshnessState,
) -> None:
    if result is SupportClassification.CERTIFIED and not f.has_valid_field_certification:
        raise DomainError("certified requires a valid field certification")
    if result is SupportClassification.FAMILY_INFERRED and f.has_valid_field_certification:
        raise DomainError("family_inferred cannot hold a valid individual certification")
    if result is SupportClassification.EXPERIMENTAL and f.expressly_excluded:
        raise DomainError("experimental cannot represent an expressly-excluded release")
    # 2. supported (rolling) requires current validation evidence.
    if result is SupportClassification.SUPPORTED and freshness is not FreshnessState.CURRENT:
        raise DomainError("rolling 'supported' requires current validation evidence")
