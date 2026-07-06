from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app_policy.models import AppPolicy, AppPolicyAction
from dns.models import DNSChannelName, DNSMode, DNSPolicy, DNSRuleAction
from node_groups.models import group_target
from rules.explanation import RuleExplanation, RuleExplanationConfidence, RuleExplainer
from rules.rule_engine import TrafficInfo
from rules.models import RuleGroup


DNS_ROUTE_BY_ACTION = {
    "direct": "direct",
    "block": "blocked",
    "current": "proxy",
    "current_profile": "proxy",
    "auto_select": "proxy",
}


@dataclass(frozen=True, slots=True)
class RouteDNSDiagnostic:
    traffic: TrafficInfo
    confidence: RuleExplanationConfidence
    route_action: str | None
    route_source: dict[str, str | None] | None
    dns_channel: str | None
    dns_path: str
    dns_reason: str
    rule_explanation: RuleExplanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "traffic": {
                "domain": self.traffic.domain,
                "ip": self.traffic.ip,
                "port": self.traffic.port,
                "protocol": self.traffic.protocol,
                "network": self.traffic.network,
                "process_name": self.traffic.process_name,
                "process_path": self.traffic.process_path,
            },
            "confidence": self.confidence.value,
            "route": {
                "action": self.route_action,
                "source": self.route_source,
            },
            "dns": {
                "channel": self.dns_channel,
                "path": self.dns_path,
                "reason": self.dns_reason,
            },
            "rule_explanation": self.rule_explanation.to_dict(),
        }


def diagnose_route_dns(
    *,
    traffic: TrafficInfo,
    rule_groups: list[RuleGroup],
    dns_policy: DNSPolicy,
    app_policy: AppPolicy | None = None,
    final_policy: str = "current_profile",
) -> RouteDNSDiagnostic:
    explanation = RuleExplainer(final_policy=final_policy).explain(
        traffic,
        rule_groups,
    )
    route_action = explanation.matched.action if explanation.matched else None
    route_source = explanation.matched.to_dict() if explanation.matched else None
    if app_policy is not None and app_policy.enabled:
        app_action = _matching_app_policy_action(app_policy, traffic)
        if app_action is not None:
            route_action = app_action
            route_source = {
                "source": "app-policy",
                "action": app_action,
                "group_name": None,
                "rule_id": None,
            }

    confidence = explanation.confidence
    if (
        app_policy is not None
        and app_policy.enabled
        and _app_policy_has_unevaluated_matchers(app_policy)
        and confidence != RuleExplanationConfidence.RUNTIME_REQUIRED
    ):
        confidence = RuleExplanationConfidence.PARTIAL
    if (
        _dns_policy_has_unevaluated_rules(dns_policy)
        and confidence != RuleExplanationConfidence.RUNTIME_REQUIRED
    ):
        confidence = RuleExplanationConfidence.PARTIAL
    if traffic.domain is None:
        return RouteDNSDiagnostic(
            traffic=traffic,
            confidence=RuleExplanationConfidence.UNKNOWN,
            route_action=route_action,
            route_source=route_source,
            dns_channel=None,
            dns_path="unknown",
            dns_reason="dns diagnostics require a domain input",
            rule_explanation=explanation,
        )

    if confidence == RuleExplanationConfidence.RUNTIME_REQUIRED:
        return RouteDNSDiagnostic(
            traffic=traffic,
            confidence=confidence,
            route_action=route_action,
            route_source=route_source,
            dns_channel=None,
            dns_path="unknown",
            dns_reason="routing depends on runtime-evaluated rule sets",
            rule_explanation=explanation,
        )

    dns_channel, dns_reason = _dns_channel_for_traffic(
        traffic=traffic,
        route_action=route_action,
        dns_policy=dns_policy,
        app_policy=app_policy,
    )
    dns_path = _dns_path(dns_policy, dns_channel)
    if dns_channel is not None and dns_path == "unavailable":
        dns_reason = f"{dns_reason}; selected channel has no configured resolver"
    return RouteDNSDiagnostic(
        traffic=traffic,
        confidence=confidence,
        route_action=route_action,
        route_source=route_source,
        dns_channel=dns_channel.value if dns_channel else None,
        dns_path=dns_path,
        dns_reason=dns_reason,
        rule_explanation=explanation,
    )


def _matching_app_policy_action(policy: AppPolicy, traffic: TrafficInfo) -> str | None:
    for rule in policy.rules:
        if not rule.enabled:
            continue
        if _app_policy_rule_matches(rule.match, traffic):
            return _app_policy_action_value(rule.action)
    if policy.mode.value == "whitelist":
        return _app_policy_action_value(policy.default_action)
    default_action = _app_policy_action_value(policy.default_action)
    if default_action != AppPolicyAction.CURRENT.value:
        return default_action
    return None


def _app_policy_rule_matches(
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


def _app_policy_has_unevaluated_matchers(policy: AppPolicy) -> bool:
    for rule in policy.rules:
        if not rule.enabled:
            continue
        if set(rule.match) & {"process_path_regex", "user", "user_id"}:
            return True
    return False


def _app_policy_action_value(action: AppPolicyAction | str) -> str:
    return action.value if isinstance(action, AppPolicyAction) else str(action)


def _dns_channel_for_traffic(
    *,
    traffic: TrafficInfo,
    route_action: str | None,
    dns_policy: DNSPolicy,
    app_policy: AppPolicy | None,
) -> tuple[DNSChannelName | None, str]:
    if dns_policy.mode == DNSMode.OFF:
        return None, "dns policy is off"

    app_dns = _app_policy_dns_channel(app_policy, traffic)
    if app_dns is not None:
        return app_dns

    rule_channel = _dns_diversion_channel(dns_policy, traffic.domain)
    if rule_channel is not None:
        return rule_channel

    if route_action and group_target(route_action) is not None:
        return DNSChannelName.PROXY, "group action follows the current selected profile"
    channel_name = DNS_ROUTE_BY_ACTION.get(str(route_action or "current_profile"))
    if channel_name == "direct":
        return DNSChannelName.DIRECT, "route action uses direct DNS"
    if channel_name == "blocked":
        return None, "route action blocks traffic; DNS would be rejected"
    return DNSChannelName.PROXY, "route action follows the current profile/proxy path"


def _app_policy_dns_channel(
    policy: AppPolicy | None,
    traffic: TrafficInfo,
) -> tuple[DNSChannelName | None, str] | None:
    if policy is None or not policy.enabled:
        return None
    action = _matching_app_policy_action(policy, traffic)
    if action is None:
        return None
    if action == "direct":
        return DNSChannelName.DIRECT, "matched app policy direct action"
    if action == "block":
        return None, "matched app policy block action; DNS would be rejected"
    return DNSChannelName.PROXY, "matched app policy current/group action"


def _dns_diversion_channel(
    policy: DNSPolicy,
    domain: str | None,
) -> tuple[DNSChannelName | None, str] | None:
    if domain is None or not policy.rules_enabled:
        return None
    for _, rule in sorted(enumerate(policy.rules), key=lambda item: (item[1].priority, item[0])):
        if not rule.enabled:
            continue
        if not _dns_rule_matches(rule.pattern, domain):
            continue
        if rule.action == DNSRuleAction.REJECT:
            return None, f"dns diversion rule {rule.id} rejects the domain"
        if rule.channel is None:
            return None
        return rule.channel, f"dns diversion rule {rule.id} selects {rule.channel.value}"
    return None


def _dns_rule_matches(pattern: str, domain: str) -> bool:
    kind, _, value = pattern.partition(":")
    value = value.strip().lower().rstrip(".")
    domain = domain.strip().lower().rstrip(".")
    if kind == "domain":
        return domain == value
    if kind == "suffix":
        return domain == value or domain.endswith("." + value.lstrip("."))
    if kind == "keyword":
        return value in domain
    return False


def _dns_policy_has_unevaluated_rules(policy: DNSPolicy) -> bool:
    if not policy.rules_enabled:
        return False
    for rule in policy.rules:
        if not rule.enabled:
            continue
        kind, _, _ = rule.pattern.partition(":")
        if kind not in {"domain", "suffix", "keyword"}:
            return True
    return False


def _dns_path(policy: DNSPolicy, channel: DNSChannelName | None) -> str:
    if channel is None:
        return "blocked"
    if not _channel_has_enabled_resolver(policy, channel):
        return "unavailable"
    if channel == DNSChannelName.DIRECT:
        return "direct"
    if channel == DNSChannelName.PROXY:
        if policy.proxy_resolution_channel == "fakeip":
            return "tunnel-or-fakeip"
        return "tunnel"
    if channel == DNSChannelName.FINAL:
        return "final"
    if channel in {
        DNSChannelName.BOOTSTRAP,
        DNSChannelName.DNS_SERVER,
        DNSChannelName.PROXY_SERVER,
    }:
        return "bootstrap"
    return "unknown"


def _channel_has_enabled_resolver(policy: DNSPolicy, channel: DNSChannelName) -> bool:
    dns_channel = policy.channels.get(channel)
    if dns_channel is None:
        return False
    return any(resolver.enabled for resolver in dns_channel.resolvers)
