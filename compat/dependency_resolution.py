"""Pure dependency-method resolver for Phase 23.7.5.5.

The resolver selects and explains dependency methods from the validated
compatibility manifest. It never installs packages, downloads artifacts, adds
repositories, builds sources, runs package managers or mutates the host.
Availability is supplied by an injected provider so L1 tests remain
deterministic and offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence

from compat.detection import CapabilityResult, DistroFacts


class DependencyResolutionError(ValueError):
    """Raised for controlled resolver input/manifest errors."""


class AvailabilityStatus(Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    MALFORMED_RESPONSE = "malformed_response"


class ResolutionStatus(Enum):
    ALREADY_PRESENT = "already_present"
    METHOD_SELECTED = "method_selected"
    RECIPE_NOT_IMPLEMENTED = "recipe_not_implemented"
    AVAILABILITY_UNKNOWN = "availability_unknown"
    OUT_OF_CONTRACT = "out_of_contract"
    NO_SAFE_ROUTE = "no_safe_route"
    AMBIGUOUS = "ambiguous"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class AvailabilityObservation:
    status: str
    evidence: str = ""
    reason: str = ""
    error_kind: str | None = None


@dataclass(frozen=True)
class DependencyRequirement:
    dependency_id: str
    capability_id: str
    description: str
    method_chain: tuple["MethodCandidate", ...]


@dataclass(frozen=True)
class MethodCandidate:
    method_id: str
    priority: int
    kind: str
    method_ref: str
    target_identity: str
    target_scope: Mapping
    architectures: tuple[str, ...]
    implementation_status: str
    postcondition: str
    data: Mapping


@dataclass(frozen=True)
class CandidateRejection:
    method_id: str
    method_kind: str
    reason: str
    evidence: str = ""
    error_kind: str | None = None


@dataclass(frozen=True)
class ResolutionDecision:
    capability_id: str
    dependency_id: str
    resolved_distribution: str | None
    resolved_release: str | None
    technical_family: str | None
    release_model: str | None
    support_classification: str
    machine_architecture: str | None
    observed_capability_status: str | None
    candidate_chain: tuple[str, ...]
    selected_method_id: str | None
    selected_method_kind: str | None
    resolution_status: str
    execution_ready: bool
    rejected_candidates: tuple[CandidateRejection, ...]
    evidence: tuple[str, ...]
    reason: str
    error_kind: str | None = None


@dataclass(frozen=True)
class ResolutionReport:
    resolved_distribution: str | None
    resolved_release: str | None
    technical_family: str | None
    release_model: str | None
    support_classification: str
    machine_architecture: str | None
    decisions: tuple[ResolutionDecision, ...]


class AvailabilityProvider:
    """Injected availability boundary. The base implementation is unknown-only."""

    def package_exists(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no package evidence")

    def repository_supports_exact_target(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no repository evidence")

    def artifact_exists(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no artifact evidence")

    def artifact_integrity_metadata_available(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no integrity evidence")

    def source_revision_available(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no source revision evidence")


class StaticAvailabilityProvider(AvailabilityProvider):
    """Deterministic provider for tests and internal fixture CLI runs."""

    def __init__(self, observations: Mapping[tuple[str, str], AvailabilityObservation | str] | None = None):
        self._observations = dict(observations or {})

    @classmethod
    def all_available(cls) -> "StaticAvailabilityProvider":
        return cls({})

    def _lookup(self, operation: str, candidate: MethodCandidate) -> AvailabilityObservation:
        key = (operation, candidate.method_id)
        value = self._observations.get(key)
        if value is None:
            return AvailabilityObservation(AvailabilityStatus.AVAILABLE.value, evidence="static fixture availability")
        if isinstance(value, AvailabilityObservation):
            return value
        return AvailabilityObservation(value, evidence="static fixture availability")

    def package_exists(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return self._lookup("package_exists", candidate)

    def repository_supports_exact_target(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return self._lookup("repository_supports_exact_target", candidate)

    def artifact_exists(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return self._lookup("artifact_exists", candidate)

    def artifact_integrity_metadata_available(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return self._lookup("artifact_integrity_metadata_available", candidate)

    def source_revision_available(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return self._lookup("source_revision_available", candidate)


def load_requirement(manifest: Mapping, dependency_id: str) -> DependencyRequirement:
    requirements = manifest.get("dependency_requirements", {})
    if dependency_id not in requirements:
        raise DependencyResolutionError("unknown dependency: %s" % dependency_id)
    raw = requirements[dependency_id]
    chain = []
    for candidate in raw["method_chain"]:
        chain.append(
            MethodCandidate(
                method_id=candidate["id"],
                priority=candidate["priority"],
                kind=candidate["kind"],
                method_ref=candidate["method_ref"],
                target_identity=candidate["target_identity"],
                target_scope=candidate["target_scope"],
                architectures=tuple(candidate["architectures"]),
                implementation_status=candidate["implementation_status"],
                postcondition=candidate["postcondition"],
                data=candidate,
            )
        )
    priorities = [candidate.priority for candidate in chain]
    if len(set(priorities)) != len(priorities):
        raise DependencyResolutionError("dependency %s has duplicate priorities" % dependency_id)
    return DependencyRequirement(
        dependency_id=dependency_id,
        capability_id=raw["capability_id"],
        description=raw["description"],
        method_chain=tuple(sorted(chain, key=lambda item: item.priority)),
    )


def resolve_dependency(
    manifest: Mapping,
    distro_facts: DistroFacts,
    support_classification: str,
    capability_results: Sequence[CapabilityResult],
    dependency_id: str,
    *,
    availability: AvailabilityProvider | None = None,
) -> ResolutionDecision:
    provider = availability or AvailabilityProvider()
    requirement = load_requirement(manifest, dependency_id)
    observed = _capability_status(capability_results, requirement.capability_id)
    chain_ids = tuple(candidate.method_id for candidate in requirement.method_chain)
    common = _decision_common(distro_facts, support_classification, requirement, observed, chain_ids)
    if support_classification == "unsupported" or distro_facts.resolved_distribution is None:
        return ResolutionDecision(
            **common,
            selected_method_id=None,
            selected_method_kind=None,
            resolution_status=ResolutionStatus.OUT_OF_CONTRACT.value,
            execution_ready=False,
            rejected_candidates=(),
            evidence=(),
            reason="target distribution is outside the compatibility contract",
            error_kind="out_of_contract",
        )
    if observed == "present":
        return ResolutionDecision(
            **common,
            selected_method_id=None,
            selected_method_kind=None,
            resolution_status=ResolutionStatus.ALREADY_PRESENT.value,
            execution_ready=True,
            rejected_candidates=(),
            evidence=("observed capability already present",),
            reason="dependency already satisfied on this host",
        )

    rejections: list[CandidateRejection] = []
    availability_unknown = False
    for candidate in requirement.method_chain:
        target_id, rejection = _candidate_target(manifest, distro_facts, candidate)
        if rejection is not None:
            rejections.append(rejection)
            continue
        assert target_id is not None
        availability_result = _check_candidate_availability(provider, candidate, target_id)
        if availability_result.status != AvailabilityStatus.AVAILABLE.value:
            if availability_result.status in (
                AvailabilityStatus.UNKNOWN.value,
                AvailabilityStatus.TIMEOUT.value,
                AvailabilityStatus.PERMISSION_DENIED.value,
                AvailabilityStatus.MALFORMED_RESPONSE.value,
            ):
                availability_unknown = True
            rejections.append(
                CandidateRejection(
                    candidate.method_id,
                    candidate.kind,
                    availability_result.reason or _availability_rejection_reason(availability_result.status),
                    availability_result.evidence or availability_result.reason,
                    availability_result.error_kind or availability_result.status,
                )
            )
            continue
        if not _candidate_has_complete_security_metadata(candidate):
            rejections.append(
                CandidateRejection(
                    candidate.method_id,
                    candidate.kind,
                    "pin_metadata_incomplete",
                    "method lacks complete pin or integrity metadata",
                    "pin_metadata_incomplete",
                )
            )
            continue
        execution_ready = candidate.implementation_status == "implemented"
        return ResolutionDecision(
            **common,
            selected_method_id=candidate.method_id,
            selected_method_kind=candidate.kind,
            resolution_status=(
                ResolutionStatus.METHOD_SELECTED.value
                if execution_ready
                else ResolutionStatus.RECIPE_NOT_IMPLEMENTED.value
            ),
            execution_ready=execution_ready,
            rejected_candidates=tuple(rejections),
            evidence=tuple(candidate.data.get("evidence", ())) + (availability_result.evidence,),
            reason=(
                "method selected but execution belongs to a later transactional provisioning task"
                if not execution_ready
                else "method selected by strict exact-target chain"
            ),
        )

    return ResolutionDecision(
        **common,
        selected_method_id=None,
        selected_method_kind=None,
        resolution_status=(
            ResolutionStatus.AVAILABILITY_UNKNOWN.value
            if availability_unknown
            else ResolutionStatus.NO_SAFE_ROUTE.value
        ),
        execution_ready=False,
        rejected_candidates=tuple(rejections),
        evidence=(),
        reason="no candidate in the declared chain qualified for this exact target",
        error_kind="availability_unknown" if availability_unknown else "no_safe_route",
    )


def resolve_all(
    manifest: Mapping,
    distro_facts: DistroFacts,
    support_classification: str,
    capability_results: Sequence[CapabilityResult],
    *,
    availability: AvailabilityProvider | None = None,
) -> ResolutionReport:
    decisions = []
    for dependency_id in sorted(manifest.get("dependency_requirements", {})):
        decisions.append(
            resolve_dependency(
                manifest,
                distro_facts,
                support_classification,
                capability_results,
                dependency_id,
                availability=availability,
            )
        )
    return ResolutionReport(
        resolved_distribution=distro_facts.resolved_distribution,
        resolved_release=distro_facts.resolved_release,
        technical_family=distro_facts.technical_family,
        release_model=distro_facts.release_model,
        support_classification=support_classification,
        machine_architecture=distro_facts.machine_architecture,
        decisions=tuple(decisions),
    )


def explain_resolution(decision: ResolutionDecision) -> Mapping:
    return {
        "dependency_id": decision.dependency_id,
        "selected_method_id": decision.selected_method_id,
        "resolution_status": decision.resolution_status,
        "reason": decision.reason,
        "rejected_candidates": [
            {
                "method_id": item.method_id,
                "method_kind": item.method_kind,
                "reason": item.reason,
                "evidence": item.evidence,
                "error_kind": item.error_kind,
            }
            for item in decision.rejected_candidates
        ],
    }


def _decision_common(
    facts: DistroFacts,
    support_classification: str,
    requirement: DependencyRequirement,
    observed: str | None,
    chain_ids: tuple[str, ...],
) -> dict:
    return {
        "capability_id": requirement.capability_id,
        "dependency_id": requirement.dependency_id,
        "resolved_distribution": facts.resolved_distribution,
        "resolved_release": facts.resolved_release,
        "technical_family": facts.technical_family,
        "release_model": facts.release_model,
        "support_classification": support_classification,
        "machine_architecture": facts.machine_architecture,
        "observed_capability_status": observed,
        "candidate_chain": chain_ids,
    }


def _capability_status(results: Sequence[CapabilityResult], capability_id: str) -> str | None:
    for result in results:
        if result.capability_id == capability_id:
            return result.domain_status
    return None


def _candidate_target(
    manifest: Mapping,
    facts: DistroFacts,
    candidate: MethodCandidate,
) -> tuple[str | None, CandidateRejection | None]:
    if facts.technical_family not in candidate.target_scope["technical_families"]:
        return None, CandidateRejection(candidate.method_id, candidate.kind, "technical_family_not_applicable")
    if facts.machine_architecture not in candidate.architectures:
        return None, CandidateRejection(candidate.method_id, candidate.kind, "architecture_not_supported")
    if facts.release_model == "rolling":
        distro_id = facts.resolved_distribution
        if distro_id not in candidate.target_scope.get("rolling_distributions", ()):
            return None, CandidateRejection(candidate.method_id, candidate.kind, "rolling_distribution_not_explicitly_targeted")
        return distro_id, None
    if facts.release_model != "stable":
        return None, CandidateRejection(candidate.method_id, candidate.kind, "release_model_unknown")
    release_id = facts.resolved_release
    if release_id is None:
        return None, CandidateRejection(candidate.method_id, candidate.kind, "release_unknown")
    if release_id not in candidate.target_scope.get("stable_releases", ()):
        return None, CandidateRejection(candidate.method_id, candidate.kind, "stable_release_not_explicitly_targeted")
    if candidate.target_identity == "mapped_base_release":
        if not facts.mapped_base_release:
            return None, CandidateRejection(candidate.method_id, candidate.kind, "mapped_base_release_absent")
        return facts.mapped_base_release, None
    if candidate.target_identity == "rolling_distribution":
        return None, CandidateRejection(candidate.method_id, candidate.kind, "stable_target_cannot_use_rolling_identity")
    return release_id, None


def _check_candidate_availability(
    provider: AvailabilityProvider,
    candidate: MethodCandidate,
    target_id: str,
) -> AvailabilityObservation:
    if candidate.kind == "official_package_exact":
        return _all_packages_exist(provider, candidate, target_id)
    if candidate.kind == "external_repo_exact":
        if target_id not in candidate.data.get("compatible_releases", ()):
            return AvailabilityObservation(
                AvailabilityStatus.UNAVAILABLE.value,
                evidence="compatible_releases=%s target=%s" % (candidate.data.get("compatible_releases", []), target_id),
                reason="target_release_not_explicitly_compatible",
                error_kind="target_release_not_explicitly_compatible",
            )
        repo = provider.repository_supports_exact_target(candidate, target_id)
        if repo.status != AvailabilityStatus.AVAILABLE.value:
            return repo
        return _all_packages_exist(provider, candidate, target_id)
    if candidate.kind == "official_artifact_pinned":
        artifact = provider.artifact_exists(candidate, target_id)
        if artifact.status != AvailabilityStatus.AVAILABLE.value:
            return artifact
        return provider.artifact_integrity_metadata_available(candidate, target_id)
    if candidate.kind == "pinned_source_build":
        return provider.source_revision_available(candidate, target_id)
    return AvailabilityObservation(AvailabilityStatus.MALFORMED_RESPONSE.value, reason="unknown method kind")


def _all_packages_exist(
    provider: AvailabilityProvider,
    candidate: MethodCandidate,
    target_id: str,
) -> AvailabilityObservation:
    for package_name in candidate.data.get("package_names", ()):
        result = provider.package_exists(candidate, target_id)
        if result.status != AvailabilityStatus.AVAILABLE.value:
            return AvailabilityObservation(
                result.status,
                evidence=result.evidence,
                reason=result.reason or "package unavailable: %s" % package_name,
                error_kind=result.error_kind,
            )
    return AvailabilityObservation(AvailabilityStatus.AVAILABLE.value, evidence="all declared packages available")


def _availability_rejection_reason(status: str) -> str:
    if status == AvailabilityStatus.UNAVAILABLE.value:
        return "candidate_unavailable"
    if status == AvailabilityStatus.UNKNOWN.value:
        return "availability_unknown"
    return status


def _candidate_has_complete_security_metadata(candidate: MethodCandidate) -> bool:
    if candidate.kind == "official_artifact_pinned":
        integrity = candidate.data.get("integrity", {})
        if not integrity or "type" not in integrity:
            return False
        return all(bool(integrity.get(arch)) for arch in candidate.architectures)
    if candidate.kind == "pinned_source_build":
        revision = candidate.data.get("revision")
        return bool(revision and revision != "unresolved")
    return True
