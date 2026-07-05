from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from config.persistence import PersistentValidationError, reject_unknown_keys, strict_bool


NODE_GROUP_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

_GROUP_ACTION_RE = re.compile(r"^group:(?P<group_name>.+)$")


def group_target(action: Any) -> str | None:
    """Parse a `group:<name>` action string, returning `<name>`, or None if
    `action` does not target a node group.

    This is the single canonical parser for the `group:<name>` syntax.
    `rules/models.py` and `app_policy/models.py` both import this instead
    of each keeping their own regex, and `core/watchdog.py`'s runtime
    resolution uses it too - there must be exactly one definition of "how
    to read a group target" in the codebase. `<name>` is not validated
    against NODE_GROUP_NAME_RE here (matching the historical, already-
    persisted behavior of the original rules/models.py regex this
    replaces) - whether a referenced name resolves to a real NodeGroup is
    a runtime concern (core.watchdog.WatchdogRuntime._effective_node_group),
    not a syntax concern.
    """
    match = _GROUP_ACTION_RE.match(str(action).strip())
    return match.group("group_name").strip() if match else None


NODE_GROUP_FIELDS = {
    "name",
    "enabled",
    "member_profile_ids",
    "member_provider_ids",
    "exclude_profile_ids",
    "resilience_policy",
    "selection_mode",
    "manual_profile_id",
}


class NodeGroupResiliencePolicy(str, Enum):
    """How strictly this group's candidate resolution treats the
    resilient/compatibility protocol split (models.profile.ResilienceCategory).

    RESILIENT_ONLY  - hard filter: compatibility profiles are never eligible
                       candidates, healthy or not. If no resilient candidate
                       is healthy, the group resolves to an empty candidate
                       set (fail-closed), never silently falls back to a
                       compatibility profile - see node_groups.resolver.
    PREFERRED       - both categories are eligible; resilient candidates are
                       ranked higher by Task 14.4's scoring. Compatibility is
                       usable as a fallback when no resilient candidate is
                       healthy. This is the default, matching the existing
                       Phase 8 "Rotation category note" baseline.
    COMPATIBILITY_ALLOWED - both categories are eligible with no preference
                       weighting at all; an explicit opt-out of the
                       resilient/compatibility distinction for this group.

    PREFERRED and COMPATIBILITY_ALLOWED are indistinguishable at the
    candidate-resolution layer (node_groups.resolver) - the difference
    between them is ranking (Task 14.4), not filtering. Only RESILIENT_ONLY
    changes which profiles are eligible at all.
    """

    RESILIENT_ONLY = "resilient_only"
    PREFERRED = "preferred"
    COMPATIBILITY_ALLOWED = "compatibility_allowed"


class NodeGroupSelectionMode(str, Enum):
    """Which profile a group currently resolves to.

    MANUAL - manual_profile_id is a hard pin. If that profile becomes
             unhealthy or leaves the group, the group resolves as
             unavailable - it does NOT silently fall back to auto-select.
             Matches the project's existing rule (Task 7.4): "Failures are
             recovered. Decisions are respected." Auto-select never
             overrides an explicit manual choice.
    AUTO   - Task 14.4's scoring picks among resolve_candidates()'s output.
             No scoring algorithm exists yet in Task 14.3; this is the
             default placeholder mode.
    """

    MANUAL = "manual"
    AUTO = "auto"


def _validate_name(name: Any) -> str:
    normalized = str(name).strip()
    if not NODE_GROUP_NAME_RE.match(normalized):
        raise PersistentValidationError(
            "node_group.name must be a lowercase slug (letters, digits, "
            "'-', '_', max 64 chars)"
        )
    return normalized


def _validate_id_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise PersistentValidationError(f"{field_name} must be a list")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PersistentValidationError(f"{field_name} entries must be non-empty strings")
        candidate = item.strip()
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized


@dataclass(slots=True)
class NodeGroup:
    """A named, persistent rotation scope (Phase 14 Task 14.3).

    Identity is `name` alone (no separate id), matching RuleGroup rather
    than Profile/Provider: the CLI always addresses a group by name
    (`node-group create <name>`, `select <group>`, `add-profile <group>`),
    and - unlike Profile.id - nothing stores a NodeGroup by a separate,
    stable identifier.

    Deliberate consequence: `name` is immutable in v2.0 - there is no
    rename operation, by design. Rule/app-policy actions reference a group
    via `group:<name>` (rules/models.py's _GROUP_ACTION_RE, documented in
    ADR 0002). Renaming would either leave those references dangling or
    require cascading through every rule/app-policy that mentions the old
    name - out of scope for this task. To rename a group in v2.0, remove it
    and create a new one (same as RuleGroup, which also has no rename).
    Revisit only as a deliberate future feature, not an oversight.
    """

    name: str
    enabled: bool = True
    member_profile_ids: list[str] = field(default_factory=list)
    member_provider_ids: list[str] = field(default_factory=list)
    exclude_profile_ids: list[str] = field(default_factory=list)
    resilience_policy: NodeGroupResiliencePolicy = NodeGroupResiliencePolicy.PREFERRED
    selection_mode: NodeGroupSelectionMode = NodeGroupSelectionMode.AUTO
    manual_profile_id: str | None = None

    def __post_init__(self) -> None:
        self.name = _validate_name(self.name)
        self.enabled = strict_bool(self.enabled, "node_group.enabled")
        self.member_profile_ids = _validate_id_list(
            self.member_profile_ids, "node_group.member_profile_ids"
        )
        self.member_provider_ids = _validate_id_list(
            self.member_provider_ids, "node_group.member_provider_ids"
        )
        self.exclude_profile_ids = _validate_id_list(
            self.exclude_profile_ids, "node_group.exclude_profile_ids"
        )

        try:
            self.resilience_policy = NodeGroupResiliencePolicy(self.resilience_policy)
        except ValueError as exc:
            supported = ", ".join(item.value for item in NodeGroupResiliencePolicy)
            raise PersistentValidationError(
                f"node_group.resilience_policy must be one of: {supported}"
            ) from exc

        try:
            self.selection_mode = NodeGroupSelectionMode(self.selection_mode)
        except ValueError as exc:
            supported = ", ".join(item.value for item in NodeGroupSelectionMode)
            raise PersistentValidationError(
                f"node_group.selection_mode must be one of: {supported}"
            ) from exc

        # Make the invalid pairing unrepresentable: manual requires a pinned
        # profile, auto forbids one (no stale pin sitting around unused).
        if self.selection_mode is NodeGroupSelectionMode.MANUAL:
            if not isinstance(self.manual_profile_id, str) or not self.manual_profile_id.strip():
                raise PersistentValidationError(
                    "node_group.manual_profile_id is required when "
                    "selection_mode is 'manual'"
                )
            self.manual_profile_id = self.manual_profile_id.strip()
        else:
            if self.manual_profile_id is not None:
                raise PersistentValidationError(
                    "node_group.manual_profile_id must not be set when "
                    "selection_mode is 'auto'"
                )

        # Direct contradiction only: a profile id explicitly listed as both
        # a member and excluded is a user input error, rejected here.
        # A profile reachable only via member_provider_ids that also
        # appears in exclude_profile_ids is a legitimate "this provider
        # except these nodes" pattern - resolved by exclusion precedence at
        # runtime (node_groups.resolver), not rejected here.
        overlap = set(self.member_profile_ids) & set(self.exclude_profile_ids)
        if overlap:
            names = ", ".join(sorted(overlap))
            raise PersistentValidationError(
                "node_group.member_profile_ids and node_group.exclude_profile_ids "
                f"must not overlap directly: {names}"
            )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["resilience_policy"] = self.resilience_policy.value
        data["selection_mode"] = self.selection_mode.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NodeGroup":
        if not isinstance(data, dict):
            raise PersistentValidationError("node_group must be an object")
        reject_unknown_keys(data, NODE_GROUP_FIELDS, "node_group")
        return cls(
            name=str(data["name"]),
            enabled=strict_bool(data.get("enabled", True), "node_group.enabled"),
            member_profile_ids=data.get("member_profile_ids", []),
            member_provider_ids=data.get("member_provider_ids", []),
            exclude_profile_ids=data.get("exclude_profile_ids", []),
            resilience_policy=str(
                data.get("resilience_policy", NodeGroupResiliencePolicy.PREFERRED.value)
            ),
            selection_mode=str(
                data.get("selection_mode", NodeGroupSelectionMode.AUTO.value)
            ),
            manual_profile_id=data.get("manual_profile_id"),
        )
