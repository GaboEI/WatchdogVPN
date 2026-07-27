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
from compat.support_model import CoreCapabilityStatus, ProtocolRuntimeStatus, SupportClassification


class DependencyResolutionError(ValueError):
    """Raised for controlled resolver input/manifest errors."""


class AvailabilityStatus(Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    MALFORMED_RESPONSE = "malformed_response"
    PROVIDER_ERROR = "provider_error"


class ResolutionStatus(Enum):
    ALREADY_PRESENT = "already_present"
    METHOD_SELECTED = "method_selected"
    RECIPE_NOT_IMPLEMENTED = "recipe_not_implemented"
    AVAILABILITY_UNKNOWN = "availability_unknown"
    OUT_OF_CONTRACT = "out_of_contract"
    NO_SAFE_ROUTE = "no_safe_route"
    AMBIGUOUS = "ambiguous"
    CAPABILITY_OBSERVATION_MISSING = "capability_observation_missing"
    PREPARATION_FAILED = "preparation_failed"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class AvailabilityObservation:
    status: str
    evidence: str = ""
    reason: str = ""
    error_kind: str | None = None


@dataclass(frozen=True)
class SelectedArtifact:
    architecture: str
    asset_name: str
    archive_or_binary_kind: str
    official_download_base: str
    sha256: str
    expected_executable: str


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
    provider_type: str
    provider_authoritative: bool
    availability_observations: tuple[Mapping, ...]
    all_availability_observations: tuple[Mapping, ...]
    selected_asset: SelectedArtifact | None = None
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
    provider_type: str
    provider_authoritative: bool


class AvailabilityProvider:
    """Injected availability boundary. The base implementation is unknown-only."""

    provider_type = "unknown_only"
    authoritative = False

    def package_exists(self, candidate: MethodCandidate, exact_target: str, package_name: str) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no package evidence")

    def repository_supports_exact_target(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no repository evidence")

    def artifact_exists(self, candidate: MethodCandidate, target_id: str, selected_asset: SelectedArtifact) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no artifact evidence")

    def artifact_integrity_metadata_available(self, candidate: MethodCandidate, target_id: str, selected_asset: SelectedArtifact) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no integrity evidence")

    def source_revision_available(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return AvailabilityObservation(AvailabilityStatus.UNKNOWN.value, reason="availability provider has no source revision evidence")


class StaticAvailabilityProvider(AvailabilityProvider):
    """Deterministic provider for tests and internal fixture CLI runs."""

    provider_type = "static_fixture"

    def __init__(
        self,
        observations: Mapping[tuple[str, str, str | None, str | None], AvailabilityObservation | str] | None = None,
        *,
        default_status: str = AvailabilityStatus.UNKNOWN.value,
        authoritative: bool = False,
    ):
        self._observations = dict(observations or {})
        self._default_status = default_status
        self.authoritative = authoritative

    @classmethod
    def all_available(cls) -> "StaticAvailabilityProvider":
        return cls({}, default_status=AvailabilityStatus.AVAILABLE.value, authoritative=False)

    def _lookup(
        self,
        operation: str,
        candidate: MethodCandidate,
        target_id: str,
        package_name: str | None = None,
    ) -> AvailabilityObservation:
        key = (operation, candidate.method_id, target_id, package_name)
        value = self._observations.get(key)
        if value is None:
            return AvailabilityObservation(self._default_status, evidence="static fixture availability")
        if isinstance(value, AvailabilityObservation):
            return value
        return AvailabilityObservation(value, evidence="static fixture availability")

    def package_exists(self, candidate: MethodCandidate, exact_target: str, package_name: str) -> AvailabilityObservation:
        return self._lookup("package_exists", candidate, exact_target, package_name)

    def repository_supports_exact_target(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return self._lookup("repository_supports_exact_target", candidate, target_id)

    def artifact_exists(self, candidate: MethodCandidate, target_id: str, selected_asset: SelectedArtifact) -> AvailabilityObservation:
        return self._lookup("artifact_exists", candidate, target_id, selected_asset.asset_name)

    def artifact_integrity_metadata_available(self, candidate: MethodCandidate, target_id: str, selected_asset: SelectedArtifact) -> AvailabilityObservation:
        return self._lookup("artifact_integrity_metadata_available", candidate, target_id, selected_asset.asset_name)

    def source_revision_available(self, candidate: MethodCandidate, target_id: str) -> AvailabilityObservation:
        return self._lookup("source_revision_available", candidate, target_id)


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
    _validate_support_classification(support_classification)
    observed = _capability_status(manifest, capability_results, requirement.capability_id)
    chain_ids = tuple(candidate.method_id for candidate in requirement.method_chain)
    common = _decision_common(distro_facts, support_classification, requirement, observed, chain_ids)
    common["provider_type"] = getattr(provider, "provider_type", provider.__class__.__name__)
    common["provider_authoritative"] = bool(getattr(provider, "authoritative", False))
    if support_classification == "unsupported" or distro_facts.resolved_distribution is None:
        return ResolutionDecision(
            **common,
            selected_method_id=None,
            selected_method_kind=None,
            resolution_status=ResolutionStatus.OUT_OF_CONTRACT.value,
            execution_ready=False,
            rejected_candidates=(),
            evidence=(),
            availability_observations=(),
            all_availability_observations=(),
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
            availability_observations=(),
            all_availability_observations=(),
            reason="dependency already satisfied on this host",
        )
    if observed is None:
        return ResolutionDecision(
            **common,
            selected_method_id=None,
            selected_method_kind=None,
            resolution_status=ResolutionStatus.CAPABILITY_OBSERVATION_MISSING.value,
            execution_ready=False,
            rejected_candidates=(),
            evidence=(),
            availability_observations=(),
            all_availability_observations=(),
            reason="capability observation is missing for required dependency",
            error_kind="capability_observation_missing",
        )
    if observed == "impossible":
        return ResolutionDecision(
            **common,
            selected_method_id=None,
            selected_method_kind=None,
            resolution_status=ResolutionStatus.NO_SAFE_ROUTE.value,
            execution_ready=False,
            rejected_candidates=(),
            evidence=(),
            availability_observations=(),
            all_availability_observations=(),
            reason="observed capability state is explicitly impossible here",
            error_kind="capability_impossible",
        )
    if observed == "preparation_failed":
        return ResolutionDecision(
            **common,
            selected_method_id=None,
            selected_method_kind=None,
            resolution_status=ResolutionStatus.PREPARATION_FAILED.value,
            execution_ready=False,
            rejected_candidates=(),
            evidence=(),
            availability_observations=(),
            all_availability_observations=(),
            reason="capability preparation has already failed before dependency resolution",
            error_kind="preparation_failed",
        )

    rejections: list[CandidateRejection] = []
    all_observations: list[Mapping] = []
    for index, candidate in enumerate(requirement.method_chain):
        target_id, rejection = _candidate_target(manifest, distro_facts, candidate)
        if rejection is not None:
            rejections.append(rejection)
            continue
        assert target_id is not None
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
        availability_result, observations, selected_asset = _check_candidate_availability(provider, candidate, target_id, distro_facts)
        all_observations.extend(observations)
        if availability_result.status != AvailabilityStatus.AVAILABLE.value:
            rejection = (
                CandidateRejection(
                    candidate.method_id,
                    candidate.kind,
                    availability_result.reason or _availability_rejection_reason(availability_result.status),
                    availability_result.evidence or availability_result.reason,
                    availability_result.error_kind or availability_result.status,
                )
            )
            rejections.append(rejection)
            if _availability_blocks_chain(availability_result.status):
                for lower in requirement.method_chain[index + 1 :]:
                    rejections.append(
                        CandidateRejection(
                            lower.method_id,
                            lower.kind,
                            "not_evaluated_due_to_higher_priority_unknown",
                            "blocked by %s on %s" % (availability_result.status, candidate.method_id),
                            "not_evaluated_due_to_higher_priority_unknown",
                        )
                    )
                return ResolutionDecision(
                    **common,
                    selected_method_id=None,
                    selected_method_kind=None,
                    resolution_status=ResolutionStatus.AVAILABILITY_UNKNOWN.value,
                    execution_ready=False,
                    rejected_candidates=tuple(rejections),
                    evidence=(availability_result.evidence,) if availability_result.evidence else (),
                    availability_observations=tuple(observations),
                    all_availability_observations=tuple(all_observations),
                    selected_asset=selected_asset,
                    reason="higher-priority candidate availability is indeterminate",
                    error_kind=availability_result.error_kind or availability_result.status,
                )
            continue
        execution_ready = False
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
            availability_observations=tuple(observations),
            all_availability_observations=tuple(all_observations),
            selected_asset=selected_asset,
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
        resolution_status=ResolutionStatus.NO_SAFE_ROUTE.value,
        execution_ready=False,
        rejected_candidates=tuple(rejections),
        evidence=(),
        availability_observations=(),
        all_availability_observations=tuple(all_observations),
        reason="no candidate in the declared chain qualified for this exact target",
        error_kind="no_safe_route",
    )


def resolve_all(
    manifest: Mapping,
    distro_facts: DistroFacts,
    support_classification: str,
    capability_results: Sequence[CapabilityResult],
    *,
    availability: AvailabilityProvider | None = None,
) -> ResolutionReport:
    provider = availability or AvailabilityProvider()
    decisions = []
    for dependency_id in sorted(manifest.get("dependency_requirements", {})):
        decisions.append(
            resolve_dependency(
                manifest,
                distro_facts,
                support_classification,
                capability_results,
                dependency_id,
                availability=provider,
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
        provider_type=getattr(provider, "provider_type", provider.__class__.__name__),
        provider_authoritative=bool(getattr(provider, "authoritative", False)),
    )


def explain_resolution(decision: ResolutionDecision) -> Mapping:
    return {
        "dependency_id": decision.dependency_id,
        "selected_method_id": decision.selected_method_id,
        "selected_method_kind": decision.selected_method_kind,
        "selected_asset": decision.selected_asset,
        "resolution_status": decision.resolution_status,
        "reason": decision.reason,
        "provider_type": decision.provider_type,
        "provider_authoritative": decision.provider_authoritative,
        "availability_observations": decision.availability_observations,
        "all_availability_observations": decision.all_availability_observations,
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
        "provider_type": "unknown_only",
        "provider_authoritative": False,
    }


def _validate_support_classification(value: str) -> None:
    try:
        SupportClassification(value)
    except ValueError as exc:
        raise DependencyResolutionError("invalid support_classification: %s" % value) from exc


def _capability_status(manifest: Mapping, results: Sequence[CapabilityResult], capability_id: str) -> str | None:
    core_caps = set(manifest["capabilities"]["core_host_capabilities"])
    protocol_caps = set(manifest["capabilities"]["protocol_capabilities"])
    all_caps = core_caps | protocol_caps
    if capability_id not in all_caps:
        raise DependencyResolutionError("dependency references unknown capability: %s" % capability_id)
    matches = []
    for result in results:
        if not isinstance(result, CapabilityResult):
            raise DependencyResolutionError("capability result must be CapabilityResult")
        if result.capability_id not in all_caps:
            raise DependencyResolutionError("capability result references unknown capability: %s" % result.capability_id)
        if result.capability_id == capability_id:
            matches.append(result)
    if not matches:
        return None
    if len(matches) > 1:
        raise DependencyResolutionError("duplicate capability result for %s" % capability_id)
    status = matches[0].domain_status
    valid = (
        {item.value for item in CoreCapabilityStatus}
        if capability_id in core_caps
        else {item.value for item in ProtocolRuntimeStatus}
    )
    if status not in valid:
        raise DependencyResolutionError("invalid domain_status for %s: %s" % (capability_id, status))
    return status


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
        if candidate.target_identity != "rolling_distribution":
            return None, CandidateRejection(candidate.method_id, candidate.kind, "rolling_target_requires_rolling_identity")
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
    if candidate.target_identity != "resolved_release":
        return None, CandidateRejection(candidate.method_id, candidate.kind, "unknown_target_identity")
    return release_id, None


def _check_candidate_availability(
    provider: AvailabilityProvider,
    candidate: MethodCandidate,
    target_id: str,
    facts: DistroFacts,
) -> tuple[AvailabilityObservation, list[Mapping], SelectedArtifact | None]:
    if candidate.kind == "official_package_exact":
        result, observations = _all_packages_exist(provider, candidate, target_id)
        return result, observations, None
    if candidate.kind == "external_repo_exact":
        if not _external_repo_target_is_compatible(candidate, target_id):
            result = AvailabilityObservation(
                AvailabilityStatus.UNAVAILABLE.value,
                evidence="compatible_targets=%s target=%s repository_series=%s"
                % (candidate.data.get("compatible_targets", []), target_id, candidate.data.get("repository", {}).get("series")),
                reason="target_release_not_explicitly_compatible",
                error_kind="target_release_not_explicitly_compatible",
            )
            return result, [_observation_record("repository_supports_exact_target", candidate, target_id, None, result, provider)], None
        repo = _provider_call(provider, provider.repository_supports_exact_target, candidate, target_id)
        observations = [_observation_record("repository_supports_exact_target", candidate, target_id, None, repo, provider)]
        if repo.status != AvailabilityStatus.AVAILABLE.value:
            return repo, observations, None
        repository_package = candidate.data.get("repository_package")
        if repository_package:
            bootstrap = _provider_call(provider, provider.package_exists, candidate, target_id, repository_package)
            observations.append(_observation_record("repository_package_available", candidate, target_id, repository_package, bootstrap, provider))
            if bootstrap.status != AvailabilityStatus.AVAILABLE.value:
                return bootstrap, observations, None
        packages, package_observations = _all_packages_exist(provider, candidate, target_id)
        return packages, observations + package_observations, None
    if candidate.kind == "official_artifact_pinned":
        selected_asset = _select_artifact_for_architecture(candidate, facts.machine_architecture)
        artifact = _provider_call(provider, provider.artifact_exists, candidate, target_id, selected_asset=selected_asset)
        observations = [_observation_record("artifact_exists", candidate, target_id, None, artifact, provider, selected_asset)]
        if artifact.status != AvailabilityStatus.AVAILABLE.value:
            return artifact, observations, selected_asset
        integrity = _provider_call(provider, provider.artifact_integrity_metadata_available, candidate, target_id, selected_asset=selected_asset)
        observations.append(_observation_record("artifact_integrity_metadata_available", candidate, target_id, None, integrity, provider, selected_asset))
        return integrity, observations, selected_asset
    if candidate.kind == "pinned_source_build":
        source = _provider_call(provider, provider.source_revision_available, candidate, target_id)
        return source, [_observation_record("source_revision_available", candidate, target_id, None, source, provider)], None
    result = AvailabilityObservation(AvailabilityStatus.MALFORMED_RESPONSE.value, reason="unknown method kind")
    return result, [_observation_record("unknown", candidate, target_id, None, result, provider)], None


def _external_repo_target_is_compatible(candidate: MethodCandidate, target_id: str) -> bool:
    repo_series = candidate.data.get("repository", {}).get("series")
    for entry in candidate.data.get("compatible_targets", ()):
        if entry.get("target_id") == target_id and entry.get("series") == repo_series:
            return True
    return False


def _select_artifact_for_architecture(candidate: MethodCandidate, architecture: str | None) -> SelectedArtifact:
    matches = [
        asset
        for asset in candidate.data.get("assets", ())
        if asset.get("architecture") == architecture
    ]
    if len(matches) != 1:
        raise DependencyResolutionError(
            "artifact candidate %s has %d assets for architecture %s"
            % (candidate.method_id, len(matches), architecture)
        )
    asset = matches[0]
    return SelectedArtifact(
        architecture=asset["architecture"],
        asset_name=asset["asset_name"],
        archive_or_binary_kind=asset["archive_or_binary_kind"],
        official_download_base=asset["official_download_base"],
        sha256=asset["sha256"],
        expected_executable=asset["expected_executable"],
    )


def _all_packages_exist(
    provider: AvailabilityProvider,
    candidate: MethodCandidate,
    target_id: str,
) -> tuple[AvailabilityObservation, list[Mapping]]:
    observations = []
    for package_name in candidate.data.get("package_names", ()):
        result = _provider_call(provider, provider.package_exists, candidate, target_id, package_name)
        observations.append(_observation_record("package_exists", candidate, target_id, package_name, result, provider))
        if result.status != AvailabilityStatus.AVAILABLE.value:
            return AvailabilityObservation(
                result.status,
                evidence=result.evidence,
                reason=result.reason or "package unavailable: %s" % package_name,
                error_kind=result.error_kind,
            ), observations
    return AvailabilityObservation(AvailabilityStatus.AVAILABLE.value, evidence="all declared packages available"), observations


def _provider_call(
    provider: AvailabilityProvider,
    func,
    candidate: MethodCandidate,
    target_id: str,
    package_name: str | None = None,
    selected_asset: SelectedArtifact | None = None,
) -> AvailabilityObservation:
    try:
        if selected_asset is not None:
            result = func(candidate, target_id, selected_asset)
        elif package_name is None:
            result = func(candidate, target_id)
        else:
            result = func(candidate, target_id, package_name)
    except Exception as exc:
        return AvailabilityObservation(
            AvailabilityStatus.PROVIDER_ERROR.value,
            reason="availability provider raised an exception",
            error_kind="provider_error",
            evidence=str(exc),
        )
    if not isinstance(result, AvailabilityObservation):
        return AvailabilityObservation(
            AvailabilityStatus.PROVIDER_ERROR.value,
            reason="availability provider returned invalid observation",
            error_kind="provider_error",
        )
    if result.status not in {item.value for item in AvailabilityStatus}:
        return AvailabilityObservation(
            AvailabilityStatus.PROVIDER_ERROR.value,
            reason="availability provider returned invalid status",
            error_kind="provider_error",
            evidence=str(result.status),
        )
    for field in ("evidence", "reason"):
        if type(getattr(result, field)) is not str:
            return AvailabilityObservation(
                AvailabilityStatus.PROVIDER_ERROR.value,
                reason="availability provider returned invalid %s" % field,
                error_kind="provider_error",
            )
    if result.error_kind is not None and type(result.error_kind) is not str:
        return AvailabilityObservation(
            AvailabilityStatus.PROVIDER_ERROR.value,
            reason="availability provider returned invalid error_kind",
            error_kind="provider_error",
        )
    if bool(getattr(provider, "authoritative", False)) and result.status == AvailabilityStatus.AVAILABLE.value and not result.evidence:
        return AvailabilityObservation(
            AvailabilityStatus.PROVIDER_ERROR.value,
            reason="authoritative provider returned available without evidence",
            error_kind="provider_error",
        )
    if selected_asset is not None:
        mismatch = _provider_asset_mismatch(result, selected_asset)
        if mismatch is not None:
            return AvailabilityObservation(
                AvailabilityStatus.PROVIDER_ERROR.value,
                reason=mismatch,
                error_kind="provider_error",
                evidence=result.evidence,
            )
    return result


def _provider_asset_mismatch(result: AvailabilityObservation, selected_asset: SelectedArtifact) -> str | None:
    if result.status != AvailabilityStatus.AVAILABLE.value:
        return None
    evidence = result.evidence or ""
    if "architecture=" in evidence and ("architecture=%s" % selected_asset.architecture) not in evidence:
        return "provider responded for a different artifact architecture"
    if "asset_name=" in evidence and ("asset_name=%s" % selected_asset.asset_name) not in evidence:
        return "provider responded for a different artifact asset"
    return None


def _observation_record(
    operation: str,
    candidate: MethodCandidate,
    target_id: str,
    package_name: str | None,
    result: AvailabilityObservation,
    provider: AvailabilityProvider,
    selected_asset: SelectedArtifact | None = None,
) -> Mapping:
    record = {
        "candidate_priority": candidate.priority,
        "operation": operation,
        "method_id": candidate.method_id,
        "target": target_id,
        "status": result.status,
        "evidence": result.evidence,
        "reason": result.reason,
        "error_kind": result.error_kind,
        "provider_type": getattr(provider, "provider_type", provider.__class__.__name__),
        "provider_authoritative": bool(getattr(provider, "authoritative", False)),
    }
    if package_name is not None:
        record["package_name"] = package_name
    if selected_asset is not None:
        record["asset"] = {
            "architecture": selected_asset.architecture,
            "asset_name": selected_asset.asset_name,
            "archive_or_binary_kind": selected_asset.archive_or_binary_kind,
            "official_download_base": selected_asset.official_download_base,
            "sha256": selected_asset.sha256,
            "expected_executable": selected_asset.expected_executable,
        }
    if candidate.kind == "external_repo_exact":
        record["repository"] = candidate.data.get("repository", {})
    return record


def _availability_blocks_chain(status: str) -> bool:
    return status in {
        AvailabilityStatus.UNKNOWN.value,
        AvailabilityStatus.TIMEOUT.value,
        AvailabilityStatus.PERMISSION_DENIED.value,
        AvailabilityStatus.MALFORMED_RESPONSE.value,
        AvailabilityStatus.PROVIDER_ERROR.value,
    }


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
        if integrity.get("type") == "sha256":
            return all(_is_sha256(integrity.get(arch)) for arch in candidate.architectures)
        if integrity.get("type") == "signature":
            required = ("signature", "key_fingerprint", "key_provenance", "verification_policy")
            return all(type(integrity.get(field)) is str and integrity.get(field) for field in required)
        return False
    if candidate.kind == "pinned_source_build":
        components = candidate.data.get("components", ())
        if components:
            return all(
                component.get("revision_type") == "commit" and _is_git_commit(component.get("revision"))
                for component in components
            )
        revision = candidate.data.get("revision")
        if candidate.data.get("revision_type") != "commit" or not _is_git_commit(revision):
            return False
        return True
    return True


def _is_sha256(value) -> bool:
    return type(value) is str and len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _is_git_commit(value) -> bool:
    return type(value) is str and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)
