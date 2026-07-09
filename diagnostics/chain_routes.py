from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from app_policy.models import AppPolicy
from dns.models import DNSPolicy
from route_chains.models import RouteChainDocument, chain_target
from route_chains.runtime import ChainRuntimePlan, ChainRuntimeResolver
from rules.models import RuleGroup


class ChainDiagnosticStatus(str, Enum):
    RESOLVED = "resolved"
    PREDICTED = "predicted"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ChainRouteDiagnostic:
    route_action: str
    chain_id: str
    matched: bool
    configured_state: str
    runtime_plan_state: str
    live_observed_state: str
    validation_state: str
    status: ChainDiagnosticStatus
    confidence: ChainDiagnosticStatus
    route_action_status: str
    dns_path_status: str
    final_outbound_status: str
    hop_order: tuple[dict[str, Any], ...]
    failure_reason: str | None
    support_export_safe: bool = True
    installed_vm_validated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_action": self.route_action,
            "chain_id": self.chain_id,
            "matched": self.matched,
            "configured_state": self.configured_state,
            "runtime_plan_state": self.runtime_plan_state,
            "live_observed_state": self.live_observed_state,
            "validation_state": self.validation_state,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "route_action_status": self.route_action_status,
            "dns_path_status": self.dns_path_status,
            "final_outbound_status": self.final_outbound_status,
            "hop_order": [dict(item) for item in self.hop_order],
            "failure_reason": self.failure_reason,
            "support_export_safe": self.support_export_safe,
            "installed_vm_validated": self.installed_vm_validated,
        }

    def to_human_lines(self) -> list[str]:
        lines = [
            f"chain {self.chain_id}: {self.status.value} ({self.route_action_status})",
            f"  confidence: {self.confidence.value}",
            f"  dns path: {self.dns_path_status}",
            f"  final outbound: {self.final_outbound_status}",
            f"  live observation: {self.live_observed_state}; vm validation: not-claimed",
        ]
        if self.failure_reason:
            lines.append(f"  failure: {self.failure_reason}")
        for hop in self.hop_order:
            detail = hop.get("unavailable_reason") or hop.get("resolved_status")
            lines.append(
                "  hop {index}: {hop_type} {status} ({detail})".format(
                    index=hop["index"],
                    hop_type=hop["hop_type"],
                    status=hop["availability"],
                    detail=detail or "no-detail",
                )
            )
        return lines


def diagnose_chain_route_action(
    route_action: str | None,
    *,
    chain_document: RouteChainDocument,
    dns_policy: DNSPolicy,
    resolver: ChainRuntimeResolver,
    config: dict[str, Any] | None = None,
    matched: bool = True,
    runtime_plan: ChainRuntimePlan | None = None,
    redact: bool = True,
) -> ChainRouteDiagnostic | None:
    if route_action is None:
        return None
    chain_id = chain_target(route_action)
    if chain_id is None:
        return None
    chain = next((item for item in chain_document.chains if item.id == chain_id), None)
    configured_state = "missing"
    if chain is not None:
        configured_state = "enabled" if chain.enabled else "disabled"
    if runtime_plan is None:
        runtime_plan = resolver.resolve_chain_action(
            route_action,
            document=chain_document,
            dns_policy=dns_policy,
            config=config or {},
        )
    status = _diagnostic_status(configured_state, runtime_plan)
    return ChainRouteDiagnostic(
        route_action=route_action,
        chain_id=chain_id,
        matched=matched,
        configured_state=configured_state,
        runtime_plan_state=runtime_plan.status.value,
        live_observed_state="not-observed",
        validation_state="unsupported-not-vm-validated",
        status=status,
        confidence=_confidence(status),
        route_action_status=_route_action_status(status),
        dns_path_status=runtime_plan.dns_path_status.value,
        final_outbound_status=(
            "available" if runtime_plan.resolved and runtime_plan.route_outbound_tag else "blocked"
        ),
        hop_order=_hop_order(runtime_plan, redact=redact),
        failure_reason=runtime_plan.failure_reason,
    )


def diagnose_configured_chains(
    *,
    rule_groups: Iterable[RuleGroup],
    app_policy: AppPolicy | None,
    routing_state: dict[str, Any],
    chain_document: RouteChainDocument,
    dns_policy: DNSPolicy,
    resolver: ChainRuntimeResolver,
    config: dict[str, Any] | None = None,
    matched_route_action: str | None = None,
    redact: bool = True,
) -> dict[str, Any]:
    actions = _configured_chain_actions(rule_groups, app_policy, routing_state)
    diagnostics = [
        diagnose_chain_route_action(
            action,
            chain_document=chain_document,
            dns_policy=dns_policy,
            resolver=resolver,
            config=config,
            matched=action == matched_route_action,
            redact=redact,
        )
        for action in sorted(actions)
    ]
    items = [item for item in diagnostics if item is not None]
    status = "not-configured"
    if items:
        if any(item.status is ChainDiagnosticStatus.RESOLVED for item in items):
            status = "resolved"
        elif any(item.status is ChainDiagnosticStatus.PARTIAL for item in items):
            status = "partial"
        elif any(item.status is ChainDiagnosticStatus.UNAVAILABLE for item in items):
            status = "unavailable"
        else:
            status = "unknown"
    return {
        "status": status,
        "configured_chain_action_count": len(actions),
        "matched_chain_id": _matched_chain_id(items),
        "items": [item.to_dict() for item in items],
        "human": [line for item in items for line in item.to_human_lines()],
        "support_export_safe": True,
        "installed_vm_validated": False,
    }


def _configured_chain_actions(
    rule_groups: Iterable[RuleGroup],
    app_policy: AppPolicy | None,
    routing_state: dict[str, Any],
) -> set[str]:
    actions: set[str] = set()
    default_action = str(routing_state.get("default_route_action", ""))
    if chain_target(default_action) is not None:
        actions.add(default_action)
    for group in rule_groups:
        if not group.enabled:
            continue
        for rule in group.rules:
            if rule.enabled and chain_target(rule.action) is not None:
                actions.add(rule.action)
    if app_policy is not None and app_policy.enabled:
        for rule in app_policy.rules:
            if rule.enabled and chain_target(rule.action) is not None:
                actions.add(str(rule.action))
        default_app_action = str(app_policy.default_action)
        if chain_target(default_app_action) is not None:
            actions.add(default_app_action)
    return actions


def _diagnostic_status(
    configured_state: str,
    plan: ChainRuntimePlan,
) -> ChainDiagnosticStatus:
    if configured_state == "missing":
        return ChainDiagnosticStatus.UNKNOWN
    if plan.resolved:
        return ChainDiagnosticStatus.RESOLVED
    if plan.hops:
        return ChainDiagnosticStatus.PARTIAL
    if configured_state == "disabled":
        return ChainDiagnosticStatus.UNAVAILABLE
    return ChainDiagnosticStatus.UNAVAILABLE


def _route_action_status(status: ChainDiagnosticStatus) -> str:
    if status is ChainDiagnosticStatus.RESOLVED:
        return "applies"
    if status is ChainDiagnosticStatus.PARTIAL:
        return "fail-closed-partial"
    if status is ChainDiagnosticStatus.PREDICTED:
        return "predicted"
    if status is ChainDiagnosticStatus.UNAVAILABLE:
        return "fail-closed-unavailable"
    return "fail-closed-unknown"


def _confidence(status: ChainDiagnosticStatus) -> ChainDiagnosticStatus:
    if status is ChainDiagnosticStatus.RESOLVED:
        return ChainDiagnosticStatus.PREDICTED
    return status


def _hop_order(
    plan: ChainRuntimePlan,
    *,
    redact: bool,
) -> tuple[dict[str, Any], ...]:
    items: list[dict[str, Any]] = []
    for hop in plan.hops:
        items.append(
            {
                "index": hop.index,
                "hop_type": hop.hop_type,
                "target": _safe_target(hop.hop_type, hop.target, redact=redact),
                "availability": "available" if hop.status.value == "resolved" else "unavailable",
                "resolved_status": hop.status.value,
                "unavailable_reason": hop.failure_reason,
                "outbound_tag_status": "present" if hop.outbound_tag else "blocked",
            }
        )
    return tuple(items)


def _safe_target(hop_type: str, target: str, *, redact: bool) -> str:
    if not redact:
        return target
    return f"<redacted-{hop_type}-target>" if target else f"<missing-{hop_type}-target>"


def _matched_chain_id(items: list[ChainRouteDiagnostic]) -> str | None:
    for item in items:
        if item.matched:
            return item.chain_id
    return None
