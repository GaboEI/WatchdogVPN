from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from config.persistence import reject_unknown_keys, strict_bool, strict_int


RULE_FIELDS = {"id", "action", "conditions", "enabled"}
RULE_GROUP_FIELDS = {"name", "enabled", "rules", "priority"}

ALLOWED_RULE_CONDITIONS = {
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "port",
    "port_range",
    "protocol",
    "network",
    "ruleset_remote",
    "ruleset_builtin",
    "process_name",
    "process_path",
}

SIMPLE_RULE_ACTIONS = {"direct", "current_profile", "auto_select", "block"}

GROUP_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_GROUP_ACTION_RE = re.compile(r"^group:(?P<group_id>.+)$")

DEFAULT_RULE_GROUPS = (
    "recommended",
    "direct",
    "proxy",
    "block",
    "custom",
    "app",
    "imported",
)


def _validate_rule_action(action: Any) -> str:
    action = str(action).strip()
    if action in SIMPLE_RULE_ACTIONS:
        return action
    match = _GROUP_ACTION_RE.match(action)
    if match and match.group("group_id").strip():
        return action
    raise ValueError(f"unsupported rule action: {action!r}")


def _validate_rule_conditions(conditions: Any) -> dict[str, list[str]]:
    if not isinstance(conditions, dict):
        raise ValueError("rule conditions must be an object")
    validated: dict[str, list[str]] = {}
    for key, value in conditions.items():
        if key not in ALLOWED_RULE_CONDITIONS:
            raise ValueError(f"unsupported rule condition type: {key!r}")
        if not isinstance(value, list) or not value:
            raise ValueError(f"rule condition {key!r} must be a non-empty list")
        entries = [str(item).strip() for item in value]
        if any(not item for item in entries):
            raise ValueError(f"rule condition {key!r} must not contain empty values")
        validated[key] = entries
    if not validated:
        raise ValueError("rule must define at least one condition")
    return validated


def validate_group_name(name: Any) -> str:
    name = str(name).strip()
    if not GROUP_NAME_RE.match(name):
        raise ValueError(
            "rule group name must be a lowercase slug (letters, digits, '-', '_', max 64 chars)"
        )
    return name


@dataclass(slots=True)
class Rule:
    id: str
    action: str
    conditions: dict[str, list[str]] = field(default_factory=dict)
    enabled: bool = True

    def __post_init__(self) -> None:
        self.id = str(self.id).strip()
        if not self.id:
            raise ValueError("rule id must not be empty")
        self.action = _validate_rule_action(self.action)
        self.conditions = _validate_rule_conditions(self.conditions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "conditions": {key: list(value) for key, value in self.conditions.items()},
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        reject_unknown_keys(data, RULE_FIELDS, "rule")
        return cls(
            id=str(data["id"]),
            action=str(data["action"]),
            conditions=data.get("conditions", {}),
            enabled=strict_bool(data.get("enabled", True), "rule.enabled"),
        )


@dataclass(slots=True)
class RuleGroup:
    name: str
    enabled: bool = True
    rules: list[Rule] = field(default_factory=list)
    priority: int = 100

    def __post_init__(self) -> None:
        self.name = validate_group_name(self.name)
        self.priority = int(self.priority)
        self.rules = [
            rule if isinstance(rule, Rule) else Rule.from_dict(rule) for rule in self.rules
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "rules": [rule.to_dict() for rule in self.rules],
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleGroup":
        reject_unknown_keys(data, RULE_GROUP_FIELDS, "rule group")
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError("rule group rules must be a list")
        return cls(
            name=str(data["name"]),
            enabled=strict_bool(data.get("enabled", True), "rule_group.enabled"),
            rules=[Rule.from_dict(item) for item in rules],
            priority=strict_int(data.get("priority", 100), "rule_group.priority"),
        )
