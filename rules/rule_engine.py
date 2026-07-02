from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from rules.models import ALLOWED_RULE_CONDITIONS, SIMPLE_RULE_ACTIONS, Rule, RuleGroup


# Priority order for the "rules" connection mode. Each tier name matches a
# default rule group from rules/models.py (Task 11.1), except "imported":
# RuleStore.import_group() creates timestamped groups named "imported-<ts>",
# so the "imported" tier gathers every group named "imported" or prefixed
# "imported-", not just a single literal group.
PRIORITY_TIER_ORDER = ("block", "custom", "app", "imported", "recommended")

# ruleset_remote/ruleset_builtin reference external rule-set data (geosite,
# geoip, or a remote .srs/.json URL) that this in-process engine does not
# load or expand. Rules imported via rules/rule_parser.py never produce
# these keys (import already expands them into concrete domain/ip_cidr
# conditions) — only a hand-written custom rule could contain them. Native
# sing-box config generation (Task 11.5) is expected to pass these through
# to sing-box's own rule_set matching instead. Until then, a rule that
# relies on one of these conditions never matches under evaluate().
UNEVALUABLE_CONDITIONS = {"ruleset_remote", "ruleset_builtin"}


@dataclass(slots=True)
class TrafficInfo:
    domain: str | None = None
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    network: str | None = None
    process_name: str | None = None
    process_path: str | None = None

    def __post_init__(self) -> None:
        if self.domain is not None:
            normalized = str(self.domain).strip().lower().rstrip(".")
            self.domain = normalized or None


@dataclass(slots=True, frozen=True)
class RuleMatch:
    action: str
    group_name: str | None
    rule_id: str | None


def _match_domain(value: str, domain: str) -> bool:
    return domain == value.strip().lower().rstrip(".")


def _match_domain_suffix(value: str, domain: str) -> bool:
    suffix = value.strip().lower().rstrip(".")
    if suffix.startswith("."):
        suffix = suffix[1:]
    return bool(suffix) and (domain == suffix or domain.endswith("." + suffix))


def _match_domain_keyword(value: str, domain: str) -> bool:
    return value.strip().lower() in domain


def _match_domain_regex(value: str, domain: str) -> bool:
    try:
        return re.search(value, domain) is not None
    except re.error:
        return False


def _match_ip_cidr(value: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False


def _match_port(value: str, port: int) -> bool:
    try:
        return int(value) == port
    except ValueError:
        return False


def _match_port_range(value: str, port: int) -> bool:
    left, sep, right = value.partition(":")
    if not sep:
        return _match_port(value, port)
    try:
        lower = int(left) if left else 0
        upper = int(right) if right else 65535
    except ValueError:
        return False
    return lower <= port <= upper


def _match_exact_ci(value: str, candidate: str) -> bool:
    return value.strip().lower() == candidate.strip().lower()


def _match_exact(value: str, candidate: str) -> bool:
    return value.strip() == candidate


# Every evaluable key in ALLOWED_RULE_CONDITIONS must have exactly one entry
# here. There is no fallback branch on purpose: a condition key missing from
# this dict fails loudly in _condition_matches instead of silently matching
# with the wrong comparison (see Task 11.3 validation notes for the bug this
# replaced — ip_cidr previously fell through to a string-equality check).
_MATCHERS = {
    "domain": (lambda traffic: traffic.domain, _match_domain),
    "domain_suffix": (lambda traffic: traffic.domain, _match_domain_suffix),
    "domain_keyword": (lambda traffic: traffic.domain, _match_domain_keyword),
    "domain_regex": (lambda traffic: traffic.domain, _match_domain_regex),
    "ip_cidr": (lambda traffic: traffic.ip, _match_ip_cidr),
    "port": (lambda traffic: traffic.port, _match_port),
    "port_range": (lambda traffic: traffic.port, _match_port_range),
    "protocol": (lambda traffic: traffic.protocol, _match_exact_ci),
    "network": (lambda traffic: traffic.network, _match_exact_ci),
    "process_name": (lambda traffic: traffic.process_name, _match_exact),
    "process_path": (lambda traffic: traffic.process_path, _match_exact),
}


_unregistered = ALLOWED_RULE_CONDITIONS - set(_MATCHERS) - UNEVALUABLE_CONDITIONS
if _unregistered:
    raise AssertionError(
        f"rule conditions missing a matcher or unevaluable marker: {sorted(_unregistered)}"
    )
del _unregistered


def _condition_matches(condition_key: str, values: list[str], traffic: TrafficInfo) -> bool:
    if condition_key in UNEVALUABLE_CONDITIONS:
        return False
    if condition_key not in _MATCHERS:
        raise ValueError(f"no matcher registered for rule condition: {condition_key!r}")
    field_getter, matcher = _MATCHERS[condition_key]
    field_value = field_getter(traffic)
    if field_value is None:
        return False
    return any(matcher(value, field_value) for value in values)


def rule_matches(rule: Rule, traffic: TrafficInfo) -> bool:
    if not rule.conditions:
        return False
    return all(
        _condition_matches(condition_key, values, traffic)
        for condition_key, values in rule.conditions.items()
    )


def group_by_tier(groups: list[RuleGroup]) -> dict[str, list[RuleGroup]]:
    tiers: dict[str, list[RuleGroup]] = {name: [] for name in PRIORITY_TIER_ORDER}
    for group in groups:
        if group.name == "imported" or group.name.startswith("imported-"):
            tiers["imported"].append(group)
        elif group.name in tiers:
            tiers[group.name].append(group)
    tiers["imported"].sort(key=lambda group: (group.priority, group.name))
    return tiers


@dataclass
class RuleEngine:
    final_policy: str = "current_profile"

    def __post_init__(self) -> None:
        if self.final_policy not in SIMPLE_RULE_ACTIONS:
            raise ValueError(f"unsupported final_policy: {self.final_policy!r}")

    def evaluate(self, traffic: TrafficInfo, groups: list[RuleGroup]) -> RuleMatch:
        tiers = group_by_tier(groups)
        for tier in PRIORITY_TIER_ORDER:
            for group in tiers[tier]:
                if not group.enabled:
                    continue
                for rule in group.rules:
                    if not rule.enabled:
                        continue
                    if rule_matches(rule, traffic):
                        return RuleMatch(
                            action=rule.action, group_name=group.name, rule_id=rule.id
                        )
        return RuleMatch(action=self.final_policy, group_name=None, rule_id=None)
