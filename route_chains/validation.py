from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from config.persistence import PersistentValidationError
from route_chains.models import ChainHopType, RouteChainDocument, chain_target


@dataclass(frozen=True, slots=True)
class ChainValidationFinding:
    code: str
    chain_id: str
    message: str
    hop_index: int | None = None
    target_type: str | None = None
    target: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "chain_id": self.chain_id,
            "message": self.message,
            "hop_index": self.hop_index,
            "target_type": self.target_type,
            "target": self.target,
        }


def validate_chain_references(
    document: RouteChainDocument,
    *,
    profile_ids: set[str] | frozenset[str],
    group_names: set[str] | frozenset[str],
) -> tuple[ChainValidationFinding, ...]:
    findings: list[ChainValidationFinding] = []
    for chain in document.chains:
        for index, hop in enumerate(chain.hops, start=1):
            if hop.type is ChainHopType.PROFILE and hop.target not in profile_ids:
                findings.append(
                    ChainValidationFinding(
                        code="missing_profile",
                        chain_id=chain.id,
                        hop_index=index,
                        target_type=hop.type.value,
                        target=hop.target,
                        message=f"chain {chain.id!r} hop {index} references missing profile",
                    )
                )
            elif hop.type is ChainHopType.GROUP and hop.target not in group_names:
                findings.append(
                    ChainValidationFinding(
                        code="missing_group",
                        chain_id=chain.id,
                        hop_index=index,
                        target_type=hop.type.value,
                        target=hop.target,
                        message=f"chain {chain.id!r} hop {index} references missing group",
                    )
                )
    return tuple(findings)


def validate_chain_action_reference(
    action: str,
    document: RouteChainDocument,
) -> ChainValidationFinding | None:
    target = chain_target(action)
    if target is None:
        return None
    chains_by_id = {chain.id: chain for chain in document.chains}
    chain = chains_by_id.get(target)
    if chain is None:
        return ChainValidationFinding(
            code="missing_chain",
            chain_id=target,
            target_type="chain",
            target=target,
            message=f"chain route action references missing chain {target!r}",
        )
    if not chain.enabled:
        return ChainValidationFinding(
            code="disabled_chain",
            chain_id=target,
            target_type="chain",
            target=target,
            message=f"chain route action references disabled chain {target!r}",
        )
    return None


def validate_chain_runtime_dependencies(
    document: RouteChainDocument,
    *,
    profile_route_actions: Mapping[str, str] | None = None,
    group_selected_profile_ids: Mapping[str, str] | None = None,
) -> tuple[ChainValidationFinding, ...]:
    """Detect model-level cycles that can be known before runtime mapping.

    The route-chain model rejects nested chain hops, so direct chain-to-chain
    cycles are unrepresentable. This helper covers the remaining pre-runtime
    cycle shape from the contract: a profile selected by a chain hop would
    require the same chain route action.
    """
    profile_route_actions = profile_route_actions or {}
    group_selected_profile_ids = group_selected_profile_ids or {}
    findings: list[ChainValidationFinding] = []
    for chain in document.chains:
        expected_action = f"chain:{chain.id}"
        for index, hop in enumerate(chain.hops, start=1):
            if hop.type is ChainHopType.PROFILE:
                if profile_route_actions.get(hop.target) == expected_action:
                    findings.append(
                        ChainValidationFinding(
                            code="self_cycle_profile_route_action",
                            chain_id=chain.id,
                            hop_index=index,
                            target_type=hop.type.value,
                            target=hop.target,
                            message=(
                                f"chain {chain.id!r} hop {index} selects a profile "
                                "that requires the same chain"
                            ),
                        )
                    )
            elif hop.type is ChainHopType.GROUP:
                selected_profile = group_selected_profile_ids.get(hop.target)
                if (
                    selected_profile is not None
                    and profile_route_actions.get(selected_profile) == expected_action
                ):
                    findings.append(
                        ChainValidationFinding(
                            code="self_cycle_group_selected_profile",
                            chain_id=chain.id,
                            hop_index=index,
                            target_type=hop.type.value,
                            target=hop.target,
                            message=(
                                f"chain {chain.id!r} hop {index} selects a group "
                                "whose selected profile requires the same chain"
                            ),
                        )
                    )
    return tuple(findings)


def raise_for_findings(findings: tuple[ChainValidationFinding, ...]) -> None:
    if findings:
        messages = "; ".join(finding.message for finding in findings)
        raise PersistentValidationError(messages)
