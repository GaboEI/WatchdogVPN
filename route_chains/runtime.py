from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from dns.models import DNSChannelName, DNSMode, DNSPolicy
from models.profile import Profile, ProtocolType
from node_groups.models import NodeGroupSelectionMode
from node_groups.resolver import resolve_candidates
from node_groups.scoring import select_best
from node_groups.store import NodeGroupStore
from route_chains.models import ChainHopType, RouteChainDocument, chain_target
from route_chains.store import RouteChainStore


SINGBOX_CHAIN_PROTOCOLS = frozenset(
    {
        ProtocolType.VLESS,
        ProtocolType.VMESS,
        ProtocolType.TROJAN,
        ProtocolType.HYSTERIA2,
        ProtocolType.TUIC,
        ProtocolType.SHADOWSOCKS,
        ProtocolType.WIREGUARD,
        ProtocolType.SOCKS,
        ProtocolType.HTTP,
    }
)


class ChainRuntimeStatus(str, Enum):
    RESOLVED = "resolved"
    BLOCKED = "blocked"


class ChainHopRuntimeStatus(str, Enum):
    RESOLVED = "resolved"
    MISSING = "missing"
    DISABLED = "disabled"
    UNHEALTHY = "unhealthy"
    UNSUPPORTED = "unsupported"
    UNRESOLVED = "unresolved"


class ChainDNSPathStatus(str, Enum):
    CHAIN_OWNED = "chain-owned"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ChainRuntimeHopPlan:
    index: int
    hop_type: str
    target: str
    status: ChainHopRuntimeStatus
    outbound_tag: str | None = None
    resolved_profile_id: str | None = None
    resolved_profile: Profile | None = None
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "hop_type": self.hop_type,
            "target": self.target,
            "status": self.status.value,
            "outbound_tag": self.outbound_tag,
            "resolved_profile_id": self.resolved_profile_id,
            "failure_reason": self.failure_reason,
        }


@dataclass(frozen=True, slots=True)
class ChainRuntimePlan:
    route_action: str
    chain_id: str
    status: ChainRuntimeStatus
    dns_path_status: ChainDNSPathStatus
    failure_policy: str = "fail_closed"
    health_policy: str = "all_required"
    route_outbound_tag: str | None = None
    hops: tuple[ChainRuntimeHopPlan, ...] = field(default_factory=tuple)
    failure_reason: str | None = None

    @property
    def resolved(self) -> bool:
        return self.status is ChainRuntimeStatus.RESOLVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_action": self.route_action,
            "chain_id": self.chain_id,
            "status": self.status.value,
            "dns_path_status": self.dns_path_status.value,
            "failure_policy": self.failure_policy,
            "health_policy": self.health_policy,
            "route_outbound_tag": self.route_outbound_tag,
            "hops": [hop.to_dict() for hop in self.hops],
            "failure_reason": self.failure_reason,
        }


class ChainRuntimeResolver:
    def __init__(
        self,
        *,
        chain_store: RouteChainStore | None = None,
        profile_store: ProfileStore | None = None,
        node_group_store: NodeGroupStore | None = None,
        provider_store: ProviderStore | None = None,
        supported_protocols: frozenset[ProtocolType] = SINGBOX_CHAIN_PROTOCOLS,
    ) -> None:
        self.chain_store = chain_store or RouteChainStore()
        self.profile_store = profile_store or ProfileStore()
        self.node_group_store = node_group_store or NodeGroupStore()
        self.provider_store = provider_store or ProviderStore()
        self.supported_protocols = supported_protocols

    def resolve_action(
        self,
        action: str,
        *,
        dns_policy: DNSPolicy | None,
        config: dict[str, Any],
    ) -> ChainRuntimePlan | None:
        chain_id = chain_target(action)
        if chain_id is None:
            return None
        document = self.chain_store.load()
        return self.resolve_chain_action(
            action,
            document=document,
            dns_policy=dns_policy,
            config=config,
        )

    def resolve_chain_action(
        self,
        action: str,
        *,
        document: RouteChainDocument,
        dns_policy: DNSPolicy | None,
        config: dict[str, Any],
    ) -> ChainRuntimePlan:
        chain_id = chain_target(action)
        if chain_id is None:
            raise ValueError(f"not a chain route action: {action!r}")
        chain = next((item for item in document.chains if item.id == chain_id), None)
        if chain is None:
            return _blocked(action, chain_id, "missing_chain", ChainDNSPathStatus.UNKNOWN)
        if not chain.enabled:
            return _blocked(action, chain_id, "disabled_chain", ChainDNSPathStatus.UNKNOWN)

        hop_plans: list[ChainRuntimeHopPlan] = []
        for index, hop in enumerate(chain.hops, start=1):
            if hop.type is ChainHopType.PROFILE:
                hop_plan = self._profile_hop_plan(chain_id, index, hop.target, config)
            else:
                hop_plan = self._group_hop_plan(chain_id, index, hop.target, config)
            hop_plans.append(hop_plan)
            if hop_plan.status is not ChainHopRuntimeStatus.RESOLVED:
                return _blocked(
                    action,
                    chain_id,
                    hop_plan.failure_reason or hop_plan.status.value,
                    ChainDNSPathStatus.UNKNOWN,
                    tuple(hop_plans),
                )

        dns_status = chain_dns_path_status(dns_policy)
        if dns_status is not ChainDNSPathStatus.CHAIN_OWNED:
            return _blocked(
                action,
                chain_id,
                "dns_path_unavailable",
                dns_status,
                tuple(hop_plans),
            )

        return ChainRuntimePlan(
            route_action=action,
            chain_id=chain_id,
            status=ChainRuntimeStatus.RESOLVED,
            dns_path_status=dns_status,
            route_outbound_tag=hop_plans[-1].outbound_tag,
            hops=tuple(hop_plans),
        )

    def _profile_hop_plan(
        self,
        chain_id: str,
        index: int,
        profile_id: str,
        config: dict[str, Any],
    ) -> ChainRuntimeHopPlan:
        profile = self.profile_store.get(profile_id)
        if profile is None:
            return _hop(index, "profile", profile_id, ChainHopRuntimeStatus.MISSING, "missing_profile")
        eligible = resolve_profile_health(profile, self.provider_store, config)
        if not eligible:
            reason = "disabled_profile" if not profile.enabled else "unhealthy_profile"
            status = (
                ChainHopRuntimeStatus.DISABLED
                if not profile.enabled
                else ChainHopRuntimeStatus.UNHEALTHY
            )
            return _hop(index, "profile", profile_id, status, reason)
        if profile.protocol not in self.supported_protocols:
            return _hop(
                index,
                "profile",
                profile_id,
                ChainHopRuntimeStatus.UNSUPPORTED,
                "unsupported_profile_protocol",
            )
        return _hop(
            index,
            "profile",
            profile_id,
            ChainHopRuntimeStatus.RESOLVED,
            None,
            outbound_tag=chain_hop_outbound_tag(chain_id, index),
            resolved_profile_id=profile.id,
            resolved_profile=profile,
        )

    def _group_hop_plan(
        self,
        chain_id: str,
        index: int,
        group_name: str,
        config: dict[str, Any],
    ) -> ChainRuntimeHopPlan:
        group = self.node_group_store.get(group_name)
        if group is None:
            return _hop(index, "group", group_name, ChainHopRuntimeStatus.MISSING, "missing_group")
        if not group.enabled:
            return _hop(index, "group", group_name, ChainHopRuntimeStatus.DISABLED, "disabled_group")
        candidates = resolve_candidates(
            group,
            self.profile_store,
            self.provider_store,
            config,
        )
        if not candidates:
            return _hop(
                index,
                "group",
                group_name,
                ChainHopRuntimeStatus.UNRESOLVED,
                "empty_group_resolution",
            )
        if group.selection_mode is NodeGroupSelectionMode.MANUAL:
            profile = next(
                (candidate for candidate in candidates if candidate.id == group.manual_profile_id),
                None,
            )
        else:
            profile, _ = select_best(group, candidates, config)
        if profile is None:
            return _hop(
                index,
                "group",
                group_name,
                ChainHopRuntimeStatus.UNRESOLVED,
                "empty_group_resolution",
            )
        if profile.protocol not in self.supported_protocols:
            return _hop(
                index,
                "group",
                group_name,
                ChainHopRuntimeStatus.UNSUPPORTED,
                "unsupported_profile_protocol",
                resolved_profile_id=profile.id,
            )
        return _hop(
            index,
            "group",
            group_name,
            ChainHopRuntimeStatus.RESOLVED,
            None,
            outbound_tag=chain_hop_outbound_tag(chain_id, index),
            resolved_profile_id=profile.id,
            resolved_profile=profile,
        )


def chain_hop_outbound_tag(chain_id: str, index: int) -> str:
    return f"watchdogvpn-chain-{chain_id}-hop-{index}"


def chain_dns_path_status(dns_policy: DNSPolicy | None) -> ChainDNSPathStatus:
    if dns_policy is None or dns_policy.mode is DNSMode.OFF:
        return ChainDNSPathStatus.UNAVAILABLE
    proxy_channel = dns_policy.channels.get(DNSChannelName.PROXY)
    if proxy_channel is None:
        return ChainDNSPathStatus.UNAVAILABLE
    if not any(resolver.enabled for resolver in proxy_channel.resolvers):
        return ChainDNSPathStatus.UNAVAILABLE
    return ChainDNSPathStatus.CHAIN_OWNED


def resolve_profile_health(
    profile: Profile,
    provider_store: ProviderStore,
    config: dict[str, Any],
) -> bool:
    from rotation.pool_builder import filter_eligible_profiles

    return profile in filter_eligible_profiles([profile], provider_store, config)


def _blocked(
    action: str,
    chain_id: str,
    reason: str,
    dns_status: ChainDNSPathStatus,
    hops: tuple[ChainRuntimeHopPlan, ...] = (),
) -> ChainRuntimePlan:
    return ChainRuntimePlan(
        route_action=action,
        chain_id=chain_id,
        status=ChainRuntimeStatus.BLOCKED,
        dns_path_status=dns_status,
        hops=hops,
        failure_reason=reason,
    )


def _hop(
    index: int,
    hop_type: str,
    target: str,
    status: ChainHopRuntimeStatus,
    reason: str | None,
    *,
    outbound_tag: str | None = None,
    resolved_profile_id: str | None = None,
    resolved_profile: Profile | None = None,
) -> ChainRuntimeHopPlan:
    return ChainRuntimeHopPlan(
        index=index,
        hop_type=hop_type,
        target=target,
        status=status,
        outbound_tag=outbound_tag,
        resolved_profile_id=resolved_profile_id,
        resolved_profile=resolved_profile,
        failure_reason=reason,
    )
