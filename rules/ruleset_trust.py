from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from config.persistence import reject_unknown_keys, strict_bool, strict_int


RULE_SET_TRUST_FIELDS = {
    "id",
    "kind",
    "source",
    "critical",
    "expected_sha256",
    "update_interval_seconds",
    "max_stale_seconds",
    "failure_behavior",
}
RULE_SET_STATUS_FIELDS = {
    "id",
    "state",
    "loaded_sha256",
    "last_loaded_at",
    "last_checked_at",
    "cache_path",
    "error",
}

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class RuleSetKind(str, Enum):
    REMOTE = "remote"
    BUILT_IN = "built-in"


class RuleSetFailureBehavior(str, Enum):
    FAIL_CLOSED = "fail-closed"
    WARN_AND_SKIP = "warn-and-skip"


class RuleSetLoadState(str, Enum):
    NOT_EVALUATED = "not-evaluated"
    LOADED = "loaded"
    STALE = "stale"
    FAILED = "failed"


def _validate_sha256(value: Any) -> str | None:
    if value is None:
        return None
    checksum = str(value).strip().lower()
    if not _SHA256_RE.match(checksum):
        raise ValueError("expected_sha256 must be a 64-character SHA-256 hex digest")
    return checksum


def _positive_int(value: Any, field_name: str) -> int:
    number = strict_int(value, field_name)
    if number <= 0:
        raise ValueError(f"{field_name} must be greater than zero")
    return number


@dataclass(slots=True)
class RuleSetTrustPolicy:
    id: str
    kind: RuleSetKind | str
    source: str
    critical: bool = True
    expected_sha256: str | None = None
    update_interval_seconds: int = 86400
    max_stale_seconds: int = 604800
    failure_behavior: RuleSetFailureBehavior | str | None = None

    def __post_init__(self) -> None:
        self.id = str(self.id).strip()
        if not self.id:
            raise ValueError("rule-set trust policy id must not be empty")
        try:
            self.kind = RuleSetKind(self.kind)
        except ValueError as exc:
            raise ValueError("rule-set kind must be one of: remote, built-in") from exc
        self.source = str(self.source).strip()
        if not self.source:
            raise ValueError("rule-set source must not be empty")
        self.critical = strict_bool(self.critical, "rule_set_trust.critical")
        self.expected_sha256 = _validate_sha256(self.expected_sha256)
        self.update_interval_seconds = _positive_int(
            self.update_interval_seconds,
            "rule_set_trust.update_interval_seconds",
        )
        self.max_stale_seconds = _positive_int(
            self.max_stale_seconds,
            "rule_set_trust.max_stale_seconds",
        )
        if self.max_stale_seconds < self.update_interval_seconds:
            raise ValueError("max_stale_seconds must be >= update_interval_seconds")
        if self.failure_behavior is None:
            self.failure_behavior = (
                RuleSetFailureBehavior.FAIL_CLOSED
                if self.critical
                else RuleSetFailureBehavior.WARN_AND_SKIP
            )
        else:
            self.failure_behavior = RuleSetFailureBehavior(self.failure_behavior)
        if self.kind == RuleSetKind.REMOTE and self.expected_sha256 is None:
            raise ValueError("remote rule-set trust policy requires expected_sha256")
        # rules/ruleset_lifecycle.py's default_fetch_rule_set() already
        # refuses non-https sources at refresh time - reject it here too so a
        # remote policy can never be persisted in a state that is guaranteed
        # to fail every future refresh.
        if self.kind == RuleSetKind.REMOTE and urlparse(self.source).scheme != "https":
            raise ValueError("remote rule-set source must use https")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "source": self.source,
            "critical": self.critical,
            "expected_sha256": self.expected_sha256,
            "update_interval_seconds": self.update_interval_seconds,
            "max_stale_seconds": self.max_stale_seconds,
            "failure_behavior": self.failure_behavior.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleSetTrustPolicy":
        reject_unknown_keys(data, RULE_SET_TRUST_FIELDS, "rule-set trust policy")
        return cls(
            id=str(data["id"]),
            kind=str(data["kind"]),
            source=str(data["source"]),
            critical=strict_bool(data.get("critical", True), "rule_set_trust.critical"),
            expected_sha256=data.get("expected_sha256"),
            update_interval_seconds=strict_int(
                data.get("update_interval_seconds", 86400),
                "rule_set_trust.update_interval_seconds",
            ),
            max_stale_seconds=strict_int(
                data.get("max_stale_seconds", 604800),
                "rule_set_trust.max_stale_seconds",
            ),
            failure_behavior=data.get("failure_behavior"),
        )


@dataclass(slots=True)
class RuleSetStatus:
    id: str
    state: RuleSetLoadState | str = RuleSetLoadState.NOT_EVALUATED
    loaded_sha256: str | None = None
    last_loaded_at: str | None = None
    last_checked_at: str | None = None
    cache_path: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        self.id = str(self.id).strip()
        if not self.id:
            raise ValueError("rule-set status id must not be empty")
        self.state = RuleSetLoadState(self.state)
        self.loaded_sha256 = _validate_sha256(self.loaded_sha256)
        if self.cache_path is not None:
            self.cache_path = str(self.cache_path).strip() or None
        if self.state in {RuleSetLoadState.FAILED, RuleSetLoadState.STALE} and not self.error:
            raise ValueError(f"rule-set status {self.state.value} requires an error")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state.value,
            "loaded_sha256": self.loaded_sha256,
            "last_loaded_at": self.last_loaded_at,
            "last_checked_at": self.last_checked_at,
            "cache_path": self.cache_path,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleSetStatus":
        reject_unknown_keys(data, RULE_SET_STATUS_FIELDS, "rule-set status")
        return cls(
            id=str(data["id"]),
            state=str(data.get("state", RuleSetLoadState.NOT_EVALUATED.value)),
            loaded_sha256=data.get("loaded_sha256"),
            last_loaded_at=data.get("last_loaded_at"),
            last_checked_at=data.get("last_checked_at"),
            cache_path=data.get("cache_path"),
            error=data.get("error"),
        )


@dataclass(slots=True)
class RuleSetTrustRegistry:
    policies: dict[str, RuleSetTrustPolicy] = field(default_factory=dict)
    statuses: dict[str, RuleSetStatus] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.policies = {
            key: policy if isinstance(policy, RuleSetTrustPolicy) else RuleSetTrustPolicy.from_dict(policy)
            for key, policy in self.policies.items()
        }
        self.statuses = {
            key: status if isinstance(status, RuleSetStatus) else RuleSetStatus.from_dict(status)
            for key, status in self.statuses.items()
        }
        for key, policy in self.policies.items():
            if key != policy.id:
                raise ValueError("rule-set trust policy key must match policy id")
        for key, status in self.statuses.items():
            if key != status.id:
                raise ValueError("rule-set status key must match status id")

    def policy_for(self, rule_set_id: str) -> RuleSetTrustPolicy | None:
        return self.policies.get(rule_set_id)

    def status_for(self, rule_set_id: str) -> RuleSetStatus:
        return self.statuses.get(rule_set_id) or RuleSetStatus(id=rule_set_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policies": {
                key: policy.to_dict() for key, policy in sorted(self.policies.items())
            },
            "statuses": {
                key: status.to_dict() for key, status in sorted(self.statuses.items())
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleSetTrustRegistry":
        policies = data.get("policies", {})
        statuses = data.get("statuses", {})
        if not isinstance(policies, dict):
            raise ValueError("rule-set trust registry policies must be an object")
        if not isinstance(statuses, dict):
            raise ValueError("rule-set trust registry statuses must be an object")
        return cls(
            policies={
                str(key): RuleSetTrustPolicy.from_dict(value)
                for key, value in policies.items()
            },
            statuses={
                str(key): RuleSetStatus.from_dict(value)
                for key, value in statuses.items()
            },
        )
