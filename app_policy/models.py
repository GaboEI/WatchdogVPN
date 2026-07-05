from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from config.persistence import (
    PersistentValidationError,
    reject_unknown_keys,
    strict_bool,
    strict_int,
)
from node_groups.models import group_target


APP_POLICY_SCHEMA_VERSION = 1
APP_POLICY_FIELDS = {
    "schema_version",
    "enabled",
    "mode",
    "default_action",
    "rules",
}
APP_POLICY_RULE_FIELDS = {
    "id",
    "action",
    "match",
    "enabled",
}
APP_POLICY_MATCH_FIELDS = {
    "process_name",
    "process_path",
    "process_path_regex",
    "user",
    "user_id",
}
UNAVAILABLE_ACTIONS = {"auto"}


class AppPolicyMode(str, Enum):
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"


class AppPolicyAction(str, Enum):
    CURRENT = "current"
    DIRECT = "direct"
    BLOCK = "block"


class MatchConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _validate_action(value: Any, field_name: str) -> AppPolicyAction | str:
    if isinstance(value, AppPolicyAction):
        return value
    action = str(value).strip()
    if action in UNAVAILABLE_ACTIONS:
        raise PersistentValidationError(
            f"{field_name} action {action!r} is scheduled for later multi-outbound support"
        )
    # group:<name> is additive: existing persisted "current"/"direct"/"block"
    # rules are unaffected (none of them ever matched group_target()), and
    # this is now backed by a real NodeGroup selector (Task 14.6) instead of
    # being rejected as unbuilt. Kept as a raw string, not an AppPolicyAction
    # member - there is no enum value for an arbitrary group name, matching
    # how rules.models.Rule.action already stores group:<name> as a string.
    if group_target(action) is not None:
        return action
    try:
        return AppPolicyAction(action)
    except ValueError as exc:
        supported = ", ".join(item.value for item in AppPolicyAction)
        raise PersistentValidationError(
            f"{field_name} must be one of: {supported}, or 'group:<name>'"
        ) from exc


def _action_value(action: AppPolicyAction | str) -> str:
    """Serialize either an AppPolicyAction member or a raw group:<name>
    string to its persisted form - action is no longer always an enum
    member now that group:<name> is accepted, so `.value` is not always
    valid on it."""
    return action.value if isinstance(action, AppPolicyAction) else action


def _string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise PersistentValidationError(f"{field_name} must be a non-empty list")
    entries: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise PersistentValidationError(f"{field_name} entries must be strings")
        normalized = item.strip()
        if not normalized:
            raise PersistentValidationError(f"{field_name} must not contain empty values")
        entries.append(normalized)
    return entries


def _user_id_list(value: Any, field_name: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise PersistentValidationError(f"{field_name} must be a non-empty list")
    entries: list[int] = []
    for item in value:
        number = strict_int(item, f"{field_name} entry")
        if number < 0:
            raise PersistentValidationError(f"{field_name} entries must not be negative")
        entries.append(number)
    return entries


def _validate_match(match: Any) -> dict[str, list[str] | list[int]]:
    if not isinstance(match, dict):
        raise PersistentValidationError("app policy rule match must be an object")
    reject_unknown_keys(match, APP_POLICY_MATCH_FIELDS, "app policy rule match")
    validated: dict[str, list[str] | list[int]] = {}
    for key, value in match.items():
        field_name = f"app_policy.rule.match.{key}"
        if key == "user_id":
            validated[key] = _user_id_list(value, field_name)
        else:
            validated[key] = _string_list(value, field_name)
    if not validated:
        raise PersistentValidationError("app policy rule must define at least one matcher")
    return validated


def _confidence(match: dict[str, list[str] | list[int]]) -> MatchConfidence:
    if "user_id" in match or "process_path" in match:
        return MatchConfidence.HIGH
    if "process_path_regex" in match or "user" in match:
        return MatchConfidence.MEDIUM
    return MatchConfidence.LOW


@dataclass(slots=True)
class AppPolicyRule:
    id: str
    action: AppPolicyAction | str
    match: dict[str, list[str] | list[int]]
    enabled: bool = True

    def __post_init__(self) -> None:
        self.id = str(self.id).strip()
        if not self.id:
            raise PersistentValidationError("app policy rule id must not be empty")
        self.action = _validate_action(self.action, "app_policy.rule.action")
        self.match = _validate_match(self.match)
        self.enabled = strict_bool(self.enabled, "app_policy.rule.enabled")

    @property
    def match_confidence(self) -> MatchConfidence:
        return _confidence(self.match)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": _action_value(self.action),
            "match": {key: list(value) for key, value in self.match.items()},
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppPolicyRule":
        if not isinstance(data, dict):
            raise PersistentValidationError("app policy rule must be an object")
        reject_unknown_keys(data, APP_POLICY_RULE_FIELDS, "app policy rule")
        for field_name in ("id", "action", "match"):
            if field_name not in data:
                raise PersistentValidationError(
                    f"app policy rule missing required field: {field_name}"
                )
        return cls(
            id=str(data["id"]),
            action=str(data["action"]),
            match=data.get("match", {}),
            enabled=strict_bool(data.get("enabled", True), "app_policy.rule.enabled"),
        )


@dataclass(slots=True)
class AppPolicy:
    enabled: bool = False
    mode: AppPolicyMode | str = AppPolicyMode.BLACKLIST
    default_action: AppPolicyAction | str = AppPolicyAction.CURRENT
    rules: list[AppPolicyRule] = field(default_factory=list)
    schema_version: int = APP_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.schema_version = strict_int(self.schema_version, "app_policy.schema_version")
        if self.schema_version != APP_POLICY_SCHEMA_VERSION:
            raise PersistentValidationError(
                f"unsupported app policy schema_version: {self.schema_version}"
            )
        self.enabled = strict_bool(self.enabled, "app_policy.enabled")
        try:
            self.mode = AppPolicyMode(self.mode)
        except ValueError as exc:
            raise PersistentValidationError(
                "app_policy.mode must be one of: whitelist, blacklist"
            ) from exc
        self.default_action = _validate_action(
            self.default_action,
            "app_policy.default_action",
        )
        self.rules = [
            rule if isinstance(rule, AppPolicyRule) else AppPolicyRule.from_dict(rule)
            for rule in self.rules
        ]

    @classmethod
    def disabled_due_to_error(cls, reason: str) -> "AppPolicy":
        _ = reason
        return cls(
            enabled=False,
            mode=AppPolicyMode.BLACKLIST,
            default_action=AppPolicyAction.BLOCK,
            rules=[],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "enabled": self.enabled,
            "mode": self.mode.value,
            "default_action": _action_value(self.default_action),
            "rules": [rule.to_dict() for rule in self.rules],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppPolicy":
        if not isinstance(data, dict):
            raise PersistentValidationError("app policy must be an object")
        reject_unknown_keys(data, APP_POLICY_FIELDS, "app policy")
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise PersistentValidationError("app_policy.rules must be a list")
        return cls(
            schema_version=data.get("schema_version", APP_POLICY_SCHEMA_VERSION),
            enabled=strict_bool(data.get("enabled", False), "app_policy.enabled"),
            mode=str(data.get("mode", AppPolicyMode.BLACKLIST.value)),
            default_action=str(data.get("default_action", AppPolicyAction.CURRENT.value)),
            rules=[AppPolicyRule.from_dict(item) for item in rules],
        )
