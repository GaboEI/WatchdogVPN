from __future__ import annotations

from typing import Any, Callable

from rules.models import Rule, RuleGroup
from rules.rule_engine import PRIORITY_TIER_ORDER, UNEVALUABLE_CONDITIONS, group_by_tier


# All evaluable Rule condition keys (everything except UNEVALUABLE_CONDITIONS)
# map 1:1 onto sing-box's native route.rules field names — same key, same
# list-of-strings shape — verified against the real sing-box 1.13.14 binary
# with `sing-box check`. No key translation is needed below.


def _rule_to_singbox_rule(
    rule: Rule, resolve_outbound: Callable[[str], str]
) -> dict[str, Any] | None:
    if not rule.enabled:
        return None
    # ruleset_remote/ruleset_builtin need sing-box route.rule_set declarations
    # (remote/local rule-set objects with their own fetch/cache lifecycle) that
    # no task has built yet — see Task 11.3's UNEVALUABLE_CONDITIONS note. A
    # rule that depends on one of these is skipped here too, for the same
    # reason RuleEngine.evaluate() never matches it locally: skipping keeps
    # the generated sing-box config and the local Python evaluator in
    # agreement instead of silently disagreeing on the same rule.
    if set(rule.conditions) & UNEVALUABLE_CONDITIONS:
        return None
    singbox_rule: dict[str, Any] = {
        key: list(values) for key, values in rule.conditions.items()
    }
    if rule.action == "block":
        singbox_rule["action"] = "reject"
    else:
        singbox_rule["outbound"] = resolve_outbound(rule.action)
    return singbox_rule


def _final_rule(final_policy: str, resolve_outbound: Callable[[str], str]) -> dict[str, Any]:
    if final_policy == "block":
        return {"action": "reject"}
    return {"outbound": resolve_outbound(final_policy)}


def build_singbox_route_rules(
    groups: list[RuleGroup],
    *,
    current_outbound_tag: str,
    final_policy: str = "current_profile",
) -> list[dict[str, Any]]:
    """Translate rule groups into sing-box route.rules, in priority order.

    "direct" always resolves to the "direct" outbound tag. "current_profile",
    "auto_select", and "group:<id>" all resolve to current_outbound_tag:
    SingBoxDriver only ever configures one active outbound at a time (the
    connecting profile), so auto_select/group:<id> have no multi-outbound
    selector to route to yet — this is documented, deferred debt for a
    future multi-outbound rotation task, not a bug in this generator.
    A rule matching "block" (or final_policy == "block") becomes a native
    sing-box `"action": "reject"` rule instead of an outbound reference.
    """

    def resolve_outbound(action: str) -> str:
        if action == "direct":
            return "direct"
        return current_outbound_tag

    rules: list[dict[str, Any]] = []
    tiers = group_by_tier(groups)
    for tier in PRIORITY_TIER_ORDER:
        for group in tiers[tier]:
            if not group.enabled:
                continue
            for rule in group.rules:
                singbox_rule = _rule_to_singbox_rule(rule, resolve_outbound)
                if singbox_rule is not None:
                    rules.append(singbox_rule)
    rules.append(_final_rule(final_policy, resolve_outbound))
    return rules
