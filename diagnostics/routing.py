from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app_policy.models import AppPolicy, AppPolicyAction
from config.state_manager import parse_capture_modes
from diagnostics.chain_routes import ChainRouteDiagnostic
from rules.explanation import RuleExplanation, RuleExplanationConfidence, RuleExplainer
from rules.models import RuleGroup
from rules.rule_engine import TrafficInfo
from rules.ruleset_trust import RuleSetTrustRegistry


DEFAULT_ROUTING_STATE = {
    "routing_state_version": "1",
    "routing_policy": "rule",
    "capture_modes": "local_proxy,tun",
    "default_route_action": "current",
    "active_mode": "rules",
}


@dataclass(frozen=True, slots=True)
class RouteDiagnostic:
    traffic: TrafficInfo
    routing_state: dict[str, Any]
    confidence: RuleExplanationConfidence
    route_action: str | None
    route_action_status: str
    route_source: dict[str, Any] | None
    rule_evaluation: str
    no_rule_match: bool | None
    rule_explanation: RuleExplanation | None
    chain_diagnostic: ChainRouteDiagnostic | None = None

    def to_dict(self) -> dict[str, Any]:
        rule_data = self.rule_explanation.to_dict() if self.rule_explanation else {}
        return {
            "diagnostic_scope": "configured-policy-only",
            "runtime_observation": False,
            "input_traffic": rule_data.get(
                "input_traffic",
                {
                    "domain": self.traffic.domain,
                    "ip": self.traffic.ip,
                    "port": self.traffic.port,
                    "protocol": self.traffic.protocol,
                    "network": self.traffic.network,
                    "process_name": self.traffic.process_name,
                    "process_path": self.traffic.process_path,
                },
            ),
            "matched": rule_data.get("matched", self.route_source),
            "priority_path": rule_data.get("priority_path", []),
            "skipped_conditions": rule_data.get("skipped_conditions", []),
            "unevaluated_rule_sets": rule_data.get("unevaluated_rule_sets", []),
            "traffic": {
                "domain": self.traffic.domain,
                "ip": self.traffic.ip,
                "port": self.traffic.port,
                "protocol": self.traffic.protocol,
                "network": self.traffic.network,
                "process_name": self.traffic.process_name,
                "process_path": self.traffic.process_path,
            },
            "routing": {
                "routing_state_version": self.routing_state["routing_state_version"],
                "routing_policy": self.routing_state["routing_policy"],
                "capture_modes": list(parse_capture_modes(self.routing_state["capture_modes"])),
                "default_route_action": self.routing_state["default_route_action"],
                "active_mode": self.routing_state.get("active_mode"),
                "active_mode_role": "compatibility-display-only",
            },
            "confidence": self.confidence.value,
            "route_action": self.route_action,
            "route_action_status": self.route_action_status,
            "route_source": self.route_source,
            "rule_evaluation": self.rule_evaluation,
            "no_rule_match": self.no_rule_match,
            "rule_explanation": (
                self.rule_explanation.to_dict() if self.rule_explanation else None
            ),
            "chain": (
                self.chain_diagnostic.to_dict()
                if self.chain_diagnostic is not None
                else None
            ),
        }


def diagnose_route(
    *,
    traffic: TrafficInfo,
    rule_groups: list[RuleGroup],
    routing_state: dict[str, Any] | None = None,
    trust_registry: RuleSetTrustRegistry | None = None,
    app_policy: AppPolicy | None = None,
    chain_diagnostic: ChainRouteDiagnostic | None = None,
) -> RouteDiagnostic:
    state = _routing_state(routing_state)
    policy = state["routing_policy"]
    default_action = state["default_route_action"]

    if policy == "global":
        return RouteDiagnostic(
            traffic=traffic,
            routing_state=state,
            confidence=RuleExplanationConfidence.DEFINITIVE,
            route_action=default_action,
            route_action_status="applies",
            route_source={
                "source": "routing-policy",
                "routing_policy": "global",
                "action": default_action,
                "group_name": None,
                "rule_id": None,
            },
            rule_evaluation="ignored-by-global-policy",
            no_rule_match=None,
            rule_explanation=None,
            chain_diagnostic=chain_diagnostic,
        )

    explanation = RuleExplainer(
        final_policy=_rule_explainer_final_policy(default_action),
        trust_registry=trust_registry,
    ).explain(traffic, rule_groups)
    route_action = _normalized_matched_action(explanation, default_action)
    route_source = explanation.matched.to_dict() if explanation.matched else None
    no_rule_match = bool(route_source and route_source.get("source") == "final")

    if no_rule_match and route_source is not None:
        route_source = {
            **route_source,
            "action": default_action,
            "default_route_action": default_action,
        }

    confidence = explanation.confidence
    if app_policy is not None and app_policy.enabled:
        app_action = matching_app_policy_action(app_policy, traffic)
        if app_action is not None:
            route_action = app_action
            route_source = {
                "source": "app-policy",
                "action": app_action,
                "group_name": None,
                "rule_id": None,
            }
            no_rule_match = None
        if (
            app_policy_has_unevaluated_matchers(app_policy)
            and confidence != RuleExplanationConfidence.RUNTIME_REQUIRED
        ):
            confidence = RuleExplanationConfidence.PARTIAL

    return RouteDiagnostic(
        traffic=traffic,
        routing_state=state,
        confidence=confidence,
        route_action=route_action,
        route_action_status=_route_action_status(confidence),
        route_source=route_source,
        rule_evaluation="evaluated",
        no_rule_match=no_rule_match,
        rule_explanation=explanation,
        chain_diagnostic=chain_diagnostic,
    )


def matching_app_policy_action(policy: AppPolicy, traffic: TrafficInfo) -> str | None:
    for rule in policy.rules:
        if not rule.enabled:
            continue
        if app_policy_rule_matches(rule.match, traffic):
            return app_policy_action_value(rule.action)
    if policy.mode.value == "whitelist":
        return app_policy_action_value(policy.default_action)
    default_action = app_policy_action_value(policy.default_action)
    if default_action != AppPolicyAction.CURRENT.value:
        return default_action
    return None


def app_policy_rule_matches(
    match: dict[str, list[str] | list[int]],
    traffic: TrafficInfo,
) -> bool:
    for key, values in match.items():
        if key == "process_name" and traffic.process_name not in values:
            return False
        if key == "process_path" and traffic.process_path not in values:
            return False
        if key == "process_path_regex":
            return False
        if key in {"user", "user_id"}:
            return False
    return True


def app_policy_has_unevaluated_matchers(policy: AppPolicy) -> bool:
    for rule in policy.rules:
        if not rule.enabled:
            continue
        if set(rule.match) & {"process_path_regex", "user", "user_id"}:
            return True
    return False


def app_policy_action_value(action: AppPolicyAction | str) -> str:
    return action.value if isinstance(action, AppPolicyAction) else str(action)


def _routing_state(state: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(DEFAULT_ROUTING_STATE)
    if state:
        for key in DEFAULT_ROUTING_STATE:
            if key in state:
                merged[key] = state[key]
    parse_capture_modes(str(merged["capture_modes"]))
    return merged


def _rule_explainer_final_policy(default_action: str) -> str:
    if default_action == "current":
        return "current_profile"
    return default_action


def _normalized_matched_action(
    explanation: RuleExplanation,
    default_action: str,
) -> str | None:
    if explanation.matched is None:
        return None
    if explanation.matched.source == "final":
        return default_action
    return explanation.matched.action


def _route_action_status(confidence: RuleExplanationConfidence) -> str:
    if confidence == RuleExplanationConfidence.DEFINITIVE:
        return "applies"
    if confidence in {
        RuleExplanationConfidence.PARTIAL,
        RuleExplanationConfidence.RUNTIME_REQUIRED,
    }:
        return "candidate"
    return "unknown"
