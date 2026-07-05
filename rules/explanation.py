from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rules.models import SIMPLE_RULE_ACTIONS, Rule, RuleGroup
from rules.rule_engine import (
    PRIORITY_TIER_ORDER,
    TrafficInfo,
    UNEVALUABLE_CONDITIONS,
    _MATCHERS,
    group_by_tier,
)


class RuleExplanationConfidence(str, Enum):
    DEFINITIVE = "definitive"
    PARTIAL = "partial"
    RUNTIME_REQUIRED = "runtime-required"
    UNKNOWN = "unknown"


class RuleExplanationPathResult(str, Enum):
    MATCHED = "matched"
    NO_MATCH = "no-match"
    SKIPPED = "skipped"
    RUNTIME_REQUIRED = "runtime-required"


class RuleExplanationSkipReason(str, Enum):
    DISABLED_GROUP = "disabled-group"
    DISABLED_RULE = "disabled-rule"
    MISSING_INPUT = "missing-input"
    UNEVALUATED_RULE_SET = "unevaluated-rule-set"


@dataclass(slots=True, frozen=True)
class RuleExplanationMatch:
    action: str
    group_name: str | None = None
    rule_id: str | None = None
    source: str = "rule"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "action": self.action,
            "group_name": self.group_name,
            "rule_id": self.rule_id,
        }


@dataclass(slots=True, frozen=True)
class RuleExplanationSkippedCondition:
    condition: str
    values: list[str]
    reason: RuleExplanationSkipReason
    group_name: str | None = None
    rule_id: str | None = None
    tier: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "group_name": self.group_name,
            "rule_id": self.rule_id,
            "condition": self.condition,
            "values": list(self.values),
            "reason": self.reason.value,
        }


@dataclass(slots=True, frozen=True)
class RuleExplanationUnevaluatedRuleSet:
    kind: str
    values: list[str]
    group_name: str
    rule_id: str
    tier: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "group_name": self.group_name,
            "rule_id": self.rule_id,
            "kind": self.kind,
            "values": list(self.values),
        }


@dataclass(slots=True, frozen=True)
class RuleExplanationPathEntry:
    tier: str
    group_name: str
    rule_id: str | None
    result: RuleExplanationPathResult
    action: str | None = None
    reason: RuleExplanationSkipReason | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "group_name": self.group_name,
            "rule_id": self.rule_id,
            "result": self.result.value,
            "action": self.action,
            "reason": self.reason.value if self.reason else None,
        }


@dataclass(slots=True, frozen=True)
class RuleExplanation:
    input_traffic: TrafficInfo
    confidence: RuleExplanationConfidence
    matched: RuleExplanationMatch | None
    priority_path: list[RuleExplanationPathEntry] = field(default_factory=list)
    skipped_conditions: list[RuleExplanationSkippedCondition] = field(default_factory=list)
    unevaluated_rule_sets: list[RuleExplanationUnevaluatedRuleSet] = field(
        default_factory=list
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_traffic": _traffic_to_dict(self.input_traffic),
            "matched": self.matched.to_dict() if self.matched else None,
            "priority_path": [entry.to_dict() for entry in self.priority_path],
            "skipped_conditions": [
                condition.to_dict() for condition in self.skipped_conditions
            ],
            "unevaluated_rule_sets": [
                ruleset.to_dict() for ruleset in self.unevaluated_rule_sets
            ],
            "confidence": self.confidence.value,
        }


def _traffic_to_dict(traffic: TrafficInfo) -> dict[str, Any]:
    return {
        "domain": traffic.domain,
        "ip": traffic.ip,
        "port": traffic.port,
        "protocol": traffic.protocol,
        "network": traffic.network,
        "process_name": traffic.process_name,
        "process_path": traffic.process_path,
    }


def _traffic_has_input(traffic: TrafficInfo) -> bool:
    return any(value is not None for value in _traffic_to_dict(traffic).values())


def _condition_matches(condition_key: str, values: list[str], traffic: TrafficInfo) -> bool:
    field_getter, matcher = _MATCHERS[condition_key]
    field_value = field_getter(traffic)
    if field_value is None:
        return False
    return any(matcher(value, field_value) for value in values)


def _missing_input(condition_key: str, traffic: TrafficInfo) -> bool:
    if condition_key not in _MATCHERS:
        return False
    field_getter, _ = _MATCHERS[condition_key]
    return field_getter(traffic) is None


def _ruleset_kind(condition_key: str) -> str:
    if condition_key == "ruleset_remote":
        return "remote"
    if condition_key == "ruleset_builtin":
        return "built-in"
    return condition_key


def _confidence(
    *,
    traffic: TrafficInfo,
    runtime_required: bool,
    partial: bool,
) -> RuleExplanationConfidence:
    if runtime_required:
        return RuleExplanationConfidence.RUNTIME_REQUIRED
    if not _traffic_has_input(traffic):
        return RuleExplanationConfidence.UNKNOWN
    if partial:
        return RuleExplanationConfidence.PARTIAL
    return RuleExplanationConfidence.DEFINITIVE


def _explain_rule_conditions(
    *,
    rule: Rule,
    traffic: TrafficInfo,
    tier: str,
    group_name: str,
) -> tuple[
    bool,
    bool,
    bool,
    list[RuleExplanationSkippedCondition],
    list[RuleExplanationUnevaluatedRuleSet],
]:
    skipped: list[RuleExplanationSkippedCondition] = []
    unevaluated: list[RuleExplanationUnevaluatedRuleSet] = []
    has_runtime_required = False
    has_missing_input = False
    has_local_mismatch = False

    for condition_key, values in rule.conditions.items():
        if condition_key in UNEVALUABLE_CONDITIONS:
            has_runtime_required = True
            skipped.append(
                RuleExplanationSkippedCondition(
                    tier=tier,
                    group_name=group_name,
                    rule_id=rule.id,
                    condition=condition_key,
                    values=list(values),
                    reason=RuleExplanationSkipReason.UNEVALUATED_RULE_SET,
                )
            )
            unevaluated.append(
                RuleExplanationUnevaluatedRuleSet(
                    tier=tier,
                    group_name=group_name,
                    rule_id=rule.id,
                    kind=_ruleset_kind(condition_key),
                    values=list(values),
                )
            )
            continue

        if _missing_input(condition_key, traffic):
            has_missing_input = True
            skipped.append(
                RuleExplanationSkippedCondition(
                    tier=tier,
                    group_name=group_name,
                    rule_id=rule.id,
                    condition=condition_key,
                    values=list(values),
                    reason=RuleExplanationSkipReason.MISSING_INPUT,
                )
            )
            continue

        if not _condition_matches(condition_key, values, traffic):
            has_local_mismatch = True

    if has_local_mismatch:
        return False, False, False, [], []

    matched = not has_runtime_required and not has_missing_input
    return matched, has_runtime_required, has_missing_input, skipped, unevaluated


@dataclass
class RuleExplainer:
    final_policy: str = "current_profile"

    def __post_init__(self) -> None:
        if self.final_policy not in SIMPLE_RULE_ACTIONS:
            raise ValueError(f"unsupported final_policy: {self.final_policy!r}")

    def explain(self, traffic: TrafficInfo, groups: list[RuleGroup]) -> RuleExplanation:
        tiers = group_by_tier(groups)
        path: list[RuleExplanationPathEntry] = []
        skipped: list[RuleExplanationSkippedCondition] = []
        unevaluated: list[RuleExplanationUnevaluatedRuleSet] = []
        runtime_required = False
        partial = False
        matched: RuleExplanationMatch | None = None

        for tier in PRIORITY_TIER_ORDER:
            for group in tiers[tier]:
                if not group.enabled:
                    path.append(
                        RuleExplanationPathEntry(
                            tier=tier,
                            group_name=group.name,
                            rule_id=None,
                            result=RuleExplanationPathResult.SKIPPED,
                            reason=RuleExplanationSkipReason.DISABLED_GROUP,
                        )
                    )
                    continue
                for rule in group.rules:
                    if not rule.enabled:
                        path.append(
                            RuleExplanationPathEntry(
                                tier=tier,
                                group_name=group.name,
                                rule_id=rule.id,
                                result=RuleExplanationPathResult.SKIPPED,
                                reason=RuleExplanationSkipReason.DISABLED_RULE,
                            )
                        )
                        continue

                    (
                        rule_matched,
                        rule_runtime_required,
                        rule_missing_input,
                        rule_skipped,
                        rule_unevaluated,
                    ) = _explain_rule_conditions(
                        rule=rule,
                        traffic=traffic,
                        tier=tier,
                        group_name=group.name,
                    )
                    skipped.extend(rule_skipped)
                    unevaluated.extend(rule_unevaluated)
                    runtime_required = runtime_required or rule_runtime_required
                    partial = partial or rule_missing_input

                    if rule_runtime_required:
                        path.append(
                            RuleExplanationPathEntry(
                                tier=tier,
                                group_name=group.name,
                                rule_id=rule.id,
                                result=RuleExplanationPathResult.RUNTIME_REQUIRED,
                                action=rule.action,
                                reason=RuleExplanationSkipReason.UNEVALUATED_RULE_SET,
                            )
                        )
                        continue
                    if rule_missing_input:
                        path.append(
                            RuleExplanationPathEntry(
                                tier=tier,
                                group_name=group.name,
                                rule_id=rule.id,
                                result=RuleExplanationPathResult.SKIPPED,
                                action=rule.action,
                                reason=RuleExplanationSkipReason.MISSING_INPUT,
                            )
                        )
                        continue
                    if rule_matched:
                        matched = RuleExplanationMatch(
                            action=rule.action,
                            group_name=group.name,
                            rule_id=rule.id,
                        )
                        path.append(
                            RuleExplanationPathEntry(
                                tier=tier,
                                group_name=group.name,
                                rule_id=rule.id,
                                result=RuleExplanationPathResult.MATCHED,
                                action=rule.action,
                            )
                        )
                        return RuleExplanation(
                            input_traffic=traffic,
                            matched=matched,
                            priority_path=path,
                            skipped_conditions=skipped,
                            unevaluated_rule_sets=unevaluated,
                            confidence=_confidence(
                                traffic=traffic,
                                runtime_required=runtime_required,
                                partial=partial,
                            ),
                        )

                    path.append(
                        RuleExplanationPathEntry(
                            tier=tier,
                            group_name=group.name,
                            rule_id=rule.id,
                            result=RuleExplanationPathResult.NO_MATCH,
                            action=rule.action,
                        )
                    )

        matched = RuleExplanationMatch(action=self.final_policy, source="final")
        return RuleExplanation(
            input_traffic=traffic,
            matched=matched,
            priority_path=path,
            skipped_conditions=skipped,
            unevaluated_rule_sets=unevaluated,
            confidence=_confidence(
                traffic=traffic,
                runtime_required=runtime_required,
                partial=partial,
            ),
        )
