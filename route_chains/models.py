from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from config.persistence import PersistentValidationError, reject_unknown_keys, strict_bool, strict_int


ROUTE_CHAIN_SCHEMA_VERSION = 1
CHAIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_CHAIN_ACTION_RE = re.compile(r"^chain:(?P<chain_id>.+)$")

ROUTE_CHAIN_DOCUMENT_FIELDS = {"schema_version", "chains"}
ROUTE_CHAIN_FIELDS = {
    "id",
    "enabled",
    "description",
    "hops",
    "dns_strategy",
    "failure_policy",
    "health_policy",
    "created_at",
    "updated_at",
}
CHAIN_HOP_FIELDS = {
    "type",
    "target",
    "required",
    "selection_policy",
}


class ChainHopType(str, Enum):
    PROFILE = "profile"
    GROUP = "group"


class ChainDNSStrategy(str, Enum):
    CHAIN = "chain"


class ChainFailurePolicy(str, Enum):
    FAIL_CLOSED = "fail_closed"


class ChainHealthPolicy(str, Enum):
    ALL_REQUIRED = "all_required"


def chain_target(action: Any) -> str | None:
    """Parse chain:<id> without enabling it as a route action.

    Route/app-policy validators still reject chain actions until runtime mapping
    lands. This parser exists so every future integration point uses one syntax
    definition instead of independent regular expressions.
    """
    match = _CHAIN_ACTION_RE.match(str(action).strip())
    if not match:
        return None
    return validate_chain_id(match.group("chain_id").strip(), "chain action")


def validate_chain_id(value: Any, field_name: str = "route_chain.id") -> str:
    if not isinstance(value, str):
        raise PersistentValidationError(f"{field_name} must be a string")
    normalized = value.strip()
    if not CHAIN_ID_RE.match(normalized):
        raise PersistentValidationError(
            f"{field_name} must be a lowercase slug (letters, digits, '-', '_', max 64 chars)"
        )
    return normalized


def _required_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise PersistentValidationError(f"{field_name} must be a string")
    normalized = value.strip()
    if not normalized:
        raise PersistentValidationError(f"{field_name} must not be empty")
    return normalized


def _optional_string(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PersistentValidationError(f"{field_name} must be a string")
    normalized = value.strip()
    return normalized or None


@dataclass(slots=True)
class ChainHop:
    type: ChainHopType | str
    target: str
    required: bool = True
    selection_policy: str | None = None

    def __post_init__(self) -> None:
        try:
            self.type = ChainHopType(self.type)
        except ValueError as exc:
            supported = ", ".join(item.value for item in ChainHopType)
            raise PersistentValidationError(
                f"route_chain.hop.type must be one of: {supported}"
            ) from exc
        self.target = _required_string(self.target, "route_chain.hop.target")
        if self.type is ChainHopType.GROUP:
            self.target = validate_chain_id(self.target, "route_chain.hop.target")
            if self.selection_policy not in (None, "group_policy"):
                raise PersistentValidationError(
                    "route_chain.hop.selection_policy must be 'group_policy' when set"
                )
        elif self.selection_policy is not None:
            raise PersistentValidationError(
                "route_chain.hop.selection_policy is only supported for group hops"
            )
        self.required = strict_bool(self.required, "route_chain.hop.required")
        if not self.required:
            raise PersistentValidationError(
                "route_chain.hop.required must be true until explicit alternate-hop failover exists"
            )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "type": self.type.value,
            "target": self.target,
            "required": self.required,
        }
        if self.selection_policy is not None:
            data["selection_policy"] = self.selection_policy
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChainHop":
        if not isinstance(data, dict):
            raise PersistentValidationError("route_chain.hop must be an object")
        reject_unknown_keys(data, CHAIN_HOP_FIELDS, "route_chain.hop")
        for field_name in ("type", "target"):
            if field_name not in data:
                raise PersistentValidationError(
                    f"route_chain.hop missing required field: {field_name}"
                )
        return cls(
            type=str(data["type"]),
            target=data["target"],
            required=strict_bool(data.get("required", True), "route_chain.hop.required"),
            selection_policy=_optional_string(
                data.get("selection_policy"),
                "route_chain.hop.selection_policy",
            ),
        )


@dataclass(slots=True)
class RouteChain:
    id: str
    hops: list[ChainHop | dict[str, Any]]
    enabled: bool = False
    description: str | None = None
    dns_strategy: ChainDNSStrategy | str = ChainDNSStrategy.CHAIN
    failure_policy: ChainFailurePolicy | str = ChainFailurePolicy.FAIL_CLOSED
    health_policy: ChainHealthPolicy | str = ChainHealthPolicy.ALL_REQUIRED
    created_at: str | None = None
    updated_at: str | None = None

    def __post_init__(self) -> None:
        self.id = validate_chain_id(self.id)
        self.enabled = strict_bool(self.enabled, "route_chain.enabled")
        self.description = _optional_string(self.description, "route_chain.description")
        try:
            self.dns_strategy = ChainDNSStrategy(self.dns_strategy)
        except ValueError as exc:
            raise PersistentValidationError("route_chain.dns_strategy must be: chain") from exc
        try:
            self.failure_policy = ChainFailurePolicy(self.failure_policy)
        except ValueError as exc:
            raise PersistentValidationError(
                "route_chain.failure_policy must be: fail_closed"
            ) from exc
        try:
            self.health_policy = ChainHealthPolicy(self.health_policy)
        except ValueError as exc:
            raise PersistentValidationError(
                "route_chain.health_policy must be: all_required"
            ) from exc
        if not isinstance(self.hops, list) or not self.hops:
            raise PersistentValidationError("route_chain.hops must be a non-empty list")
        self.hops = [
            hop if isinstance(hop, ChainHop) else ChainHop.from_dict(hop)
            for hop in self.hops
        ]
        self.created_at = _optional_string(self.created_at, "route_chain.created_at")
        self.updated_at = _optional_string(self.updated_at, "route_chain.updated_at")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "enabled": self.enabled,
            "hops": [hop.to_dict() for hop in self.hops],
            "dns_strategy": self.dns_strategy.value,
            "failure_policy": self.failure_policy.value,
            "health_policy": self.health_policy.value,
        }
        if self.description is not None:
            data["description"] = self.description
        if self.created_at is not None:
            data["created_at"] = self.created_at
        if self.updated_at is not None:
            data["updated_at"] = self.updated_at
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RouteChain":
        if not isinstance(data, dict):
            raise PersistentValidationError("route_chain must be an object")
        reject_unknown_keys(data, ROUTE_CHAIN_FIELDS, "route_chain")
        for field_name in ("id", "hops"):
            if field_name not in data:
                raise PersistentValidationError(
                    f"route_chain missing required field: {field_name}"
                )
        return cls(
            id=data["id"],
            enabled=strict_bool(data.get("enabled", False), "route_chain.enabled"),
            description=data.get("description"),
            hops=data.get("hops", []),
            dns_strategy=str(data.get("dns_strategy", ChainDNSStrategy.CHAIN.value)),
            failure_policy=str(
                data.get("failure_policy", ChainFailurePolicy.FAIL_CLOSED.value)
            ),
            health_policy=str(
                data.get("health_policy", ChainHealthPolicy.ALL_REQUIRED.value)
            ),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


@dataclass(slots=True)
class RouteChainDocument:
    chains: list[RouteChain | dict[str, Any]] = field(default_factory=list)
    schema_version: int = ROUTE_CHAIN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.schema_version = strict_int(self.schema_version, "route_chains.schema_version")
        if self.schema_version != ROUTE_CHAIN_SCHEMA_VERSION:
            raise PersistentValidationError(
                f"unsupported route_chains schema_version: {self.schema_version}"
            )
        if not isinstance(self.chains, list):
            raise PersistentValidationError("route_chains.chains must be a list")
        self.chains = [
            chain if isinstance(chain, RouteChain) else RouteChain.from_dict(chain)
            for chain in self.chains
        ]
        ids = [chain.id for chain in self.chains]
        if len(ids) != len(set(ids)):
            raise PersistentValidationError("route_chains.chains must not contain duplicate ids")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "chains": [chain.to_dict() for chain in self.chains],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RouteChainDocument":
        if not isinstance(data, dict):
            raise PersistentValidationError("route_chains document must be an object")
        reject_unknown_keys(data, ROUTE_CHAIN_DOCUMENT_FIELDS, "route_chains document")
        return cls(
            schema_version=data.get("schema_version", ROUTE_CHAIN_SCHEMA_VERSION),
            chains=data.get("chains", []),
        )


def redact_chain_document(document: RouteChainDocument) -> dict[str, Any]:
    return {
        "schema_version": document.schema_version,
        "chain_count": len(document.chains),
        "chains": [
            {
                "id": chain.id,
                "enabled": chain.enabled,
                "hop_count": len(chain.hops),
                "hop_types": [hop.type.value for hop in chain.hops],
                "dns_strategy": chain.dns_strategy.value,
                "failure_policy": chain.failure_policy.value,
                "health_policy": chain.health_policy.value,
                "description": "<redacted>" if chain.description else None,
                "created_at_present": chain.created_at is not None,
                "updated_at_present": chain.updated_at is not None,
            }
            for chain in document.chains
        ],
    }
