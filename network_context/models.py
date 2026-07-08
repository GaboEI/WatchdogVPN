from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from config.persistence import (
    PersistentValidationError,
    reject_unknown_keys,
    strict_bool,
    strict_int,
)


NETWORK_CONTEXT_POLICY_SCHEMA_VERSION = 1

NETWORK_CONTEXT_POLICY_FIELDS = {
    "schema_version",
    "enabled",
    "profiles",
    "triggers",
    "redaction",
}
NETWORK_PROFILE_FIELDS = {
    "id",
    "label",
    "trust",
    "enabled",
    "matches",
}
NETWORK_MATCH_FIELDS = {
    "kind",
    "value",
    "explicit_consent",
    "consent_note",
}
ACTION_INTENT_FIELDS = {
    "enabled",
    "action",
    "explanation",
    "disable_hint",
    "reversible",
    "reversal",
}
REDACTION_FIELDS = {
    "support_export",
    "include_profile_labels",
    "include_match_values",
}
TRIGGER_FIELDS = {
    "trusted_network",
    "untrusted_network",
    "interface_changed",
    "captive_portal",
    "offline",
}
FORBIDDEN_POLICY_FIELDS = {
    "raw_ssid",
    "raw_bssid",
    "raw_interface_name",
    "gateway_identifier",
    "gateway_link_layer_identifier",
    "public_exit_ip",
    "public_exit_ip_history",
    "captive_portal_history",
    "network_transition_history",
    "per_network_automation_history",
    "automation_history",
    "dns_query_history",
    "destination_history",
}
PROFILE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$")


class NetworkTrust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class NetworkMatchKind(str, Enum):
    PROFILE_TAG = "profile_tag"
    SSID_SHA256 = "ssid_sha256"
    BSSID_SHA256 = "bssid_sha256"
    INTERFACE_NAME_SHA256 = "interface_name_sha256"
    INTERFACE_TYPE = "interface_type"
    GATEWAY_IDENTIFIER_SHA256 = "gateway_identifier_sha256"
    RAW_SSID = "raw_ssid"
    RAW_BSSID = "raw_bssid"
    RAW_INTERFACE_NAME = "raw_interface_name"
    RAW_GATEWAY_IDENTIFIER = "raw_gateway_identifier"


class NetworkPolicyAction(str, Enum):
    MANUAL = "manual"
    WARN_ONLY = "warn_only"
    KEEP_CURRENT = "keep_current"
    CONNECT = "connect"
    DISCONNECT = "disconnect"


class NetworkContextTrigger(str, Enum):
    TRUSTED_NETWORK = "trusted_network"
    UNTRUSTED_NETWORK = "untrusted_network"
    INTERFACE_CHANGED = "interface_changed"
    CAPTIVE_PORTAL = "captive_portal"
    OFFLINE = "offline"


RAW_MATCH_KINDS = {
    NetworkMatchKind.RAW_SSID,
    NetworkMatchKind.RAW_BSSID,
    NetworkMatchKind.RAW_INTERFACE_NAME,
    NetworkMatchKind.RAW_GATEWAY_IDENTIFIER,
}
HASHED_MATCH_KINDS = {
    NetworkMatchKind.SSID_SHA256,
    NetworkMatchKind.BSSID_SHA256,
    NetworkMatchKind.INTERFACE_NAME_SHA256,
    NetworkMatchKind.GATEWAY_IDENTIFIER_SHA256,
}
AUTOMATIC_ACTIONS = {
    NetworkPolicyAction.CONNECT,
    NetworkPolicyAction.DISCONNECT,
}


def _string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise PersistentValidationError(f"{field_name} must be a string")
    normalized = value.strip()
    if not normalized:
        raise PersistentValidationError(f"{field_name} must not be empty")
    return normalized


def _optional_string(value: Any, field_name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise PersistentValidationError(f"{field_name} must be a string")
    return value.strip()


def _validate_no_forbidden_fields(data: dict[str, Any], object_name: str) -> None:
    forbidden = sorted(set(data) & FORBIDDEN_POLICY_FIELDS)
    if forbidden:
        names = ", ".join(forbidden)
        raise PersistentValidationError(
            f"{object_name} contains sensitive fields that are not persisted by default: {names}"
        )


def _validate_hex_sha256(value: str, field_name: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdefABCDEF" for char in value):
        raise PersistentValidationError(f"{field_name} must be a SHA-256 hex digest")


@dataclass(slots=True)
class ActionIntent:
    action: NetworkPolicyAction | str = NetworkPolicyAction.MANUAL
    enabled: bool = False
    explanation: str = "Manual mode; no automatic network action is taken."
    disable_hint: str = "Leave this intent disabled or set action to manual."
    reversible: bool = True
    reversal: str = "No runtime state is changed."

    def __post_init__(self) -> None:
        try:
            self.action = NetworkPolicyAction(self.action)
        except ValueError as exc:
            supported = ", ".join(item.value for item in NetworkPolicyAction)
            raise PersistentValidationError(
                f"network_context.action must be one of: {supported}"
            ) from exc
        self.enabled = strict_bool(self.enabled, "network_context.action.enabled")
        self.explanation = _string(
            self.explanation,
            "network_context.action.explanation",
        )
        self.disable_hint = _string(
            self.disable_hint,
            "network_context.action.disable_hint",
        )
        self.reversible = strict_bool(
            self.reversible,
            "network_context.action.reversible",
        )
        self.reversal = _string(self.reversal, "network_context.action.reversal")
        if self.enabled and self.action == NetworkPolicyAction.MANUAL:
            raise PersistentValidationError(
                "enabled network context intents must not use manual action"
            )
        if self.action in AUTOMATIC_ACTIONS and not self.reversible:
            raise PersistentValidationError(
                "network context connect/disconnect intents must be reversible"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "action": self.action.value,
            "explanation": self.explanation,
            "disable_hint": self.disable_hint,
            "reversible": self.reversible,
            "reversal": self.reversal,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionIntent":
        if not isinstance(data, dict):
            raise PersistentValidationError("network context action intent must be an object")
        reject_unknown_keys(data, ACTION_INTENT_FIELDS, "network context action intent")
        return cls(
            enabled=strict_bool(
                data.get("enabled", False),
                "network_context.action.enabled",
            ),
            action=str(data.get("action", NetworkPolicyAction.MANUAL.value)),
            explanation=str(
                data.get(
                    "explanation",
                    "Manual mode; no automatic network action is taken.",
                )
            ),
            disable_hint=str(
                data.get(
                    "disable_hint",
                    "Leave this intent disabled or set action to manual.",
                )
            ),
            reversible=strict_bool(
                data.get("reversible", True),
                "network_context.action.reversible",
            ),
            reversal=str(data.get("reversal", "No runtime state is changed.")),
        )


@dataclass(slots=True)
class NetworkMatch:
    kind: NetworkMatchKind | str
    value: str
    explicit_consent: bool = False
    consent_note: str = ""

    def __post_init__(self) -> None:
        try:
            self.kind = NetworkMatchKind(self.kind)
        except ValueError as exc:
            supported = ", ".join(item.value for item in NetworkMatchKind)
            raise PersistentValidationError(
                f"network_context.match.kind must be one of: {supported}"
            ) from exc
        self.value = _string(self.value, "network_context.match.value")
        self.explicit_consent = strict_bool(
            self.explicit_consent,
            "network_context.match.explicit_consent",
        )
        self.consent_note = _optional_string(
            self.consent_note,
            "network_context.match.consent_note",
        )
        if self.kind in HASHED_MATCH_KINDS:
            _validate_hex_sha256(self.value, "network_context.match.value")
        if self.kind in RAW_MATCH_KINDS:
            if not self.explicit_consent:
                raise PersistentValidationError(
                    f"{self.kind.value} requires explicit consent before persistence"
                )
            if not self.consent_note:
                raise PersistentValidationError(
                    f"{self.kind.value} requires a consent_note before persistence"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "explicit_consent": self.explicit_consent,
            "consent_note": self.consent_note,
        }

    def to_redacted_dict(self) -> dict[str, Any]:
        marker = "<redacted-sensitive-value>" if self.kind in RAW_MATCH_KINDS else "<redacted-match-value>"
        return {
            "kind": self.kind.value,
            "value": marker,
            "explicit_consent": self.explicit_consent,
            "consent_note": "<redacted-consent-note>" if self.consent_note else "",
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkMatch":
        if not isinstance(data, dict):
            raise PersistentValidationError("network context match must be an object")
        reject_unknown_keys(data, NETWORK_MATCH_FIELDS, "network context match")
        for field_name in ("kind", "value"):
            if field_name not in data:
                raise PersistentValidationError(
                    f"network context match missing required field: {field_name}"
                )
        return cls(
            kind=str(data["kind"]),
            value=str(data["value"]),
            explicit_consent=strict_bool(
                data.get("explicit_consent", False),
                "network_context.match.explicit_consent",
            ),
            consent_note=str(data.get("consent_note", "")),
        )


@dataclass(slots=True)
class NetworkProfile:
    id: str
    label: str
    trust: NetworkTrust | str = NetworkTrust.UNKNOWN
    enabled: bool = True
    matches: list[NetworkMatch] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.id = _string(self.id, "network_context.profile.id")
        if not PROFILE_ID_RE.match(self.id):
            raise PersistentValidationError(
                "network_context.profile.id must be 1-64 safe identifier characters"
            )
        self.label = _string(self.label, "network_context.profile.label")
        try:
            self.trust = NetworkTrust(self.trust)
        except ValueError as exc:
            raise PersistentValidationError(
                "network_context.profile.trust must be one of: trusted, untrusted, unknown"
            ) from exc
        self.enabled = strict_bool(self.enabled, "network_context.profile.enabled")
        self.matches = [
            item if isinstance(item, NetworkMatch) else NetworkMatch.from_dict(item)
            for item in self.matches
        ]
        if not self.matches:
            raise PersistentValidationError("network context profile must define matches")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "trust": self.trust.value,
            "enabled": self.enabled,
            "matches": [item.to_dict() for item in self.matches],
        }

    def to_redacted_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": "<redacted-profile-label>",
            "trust": self.trust.value,
            "enabled": self.enabled,
            "matches": [item.to_redacted_dict() for item in self.matches],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkProfile":
        if not isinstance(data, dict):
            raise PersistentValidationError("network context profile must be an object")
        _validate_no_forbidden_fields(data, "network context profile")
        reject_unknown_keys(data, NETWORK_PROFILE_FIELDS, "network context profile")
        for field_name in ("id", "label", "matches"):
            if field_name not in data:
                raise PersistentValidationError(
                    f"network context profile missing required field: {field_name}"
                )
        matches = data.get("matches", [])
        if not isinstance(matches, list):
            raise PersistentValidationError("network_context.profile.matches must be a list")
        return cls(
            id=str(data["id"]),
            label=str(data["label"]),
            trust=str(data.get("trust", NetworkTrust.UNKNOWN.value)),
            enabled=strict_bool(
                data.get("enabled", True),
                "network_context.profile.enabled",
            ),
            matches=[NetworkMatch.from_dict(item) for item in matches],
        )


@dataclass(slots=True)
class NetworkContextPolicy:
    enabled: bool = False
    profiles: list[NetworkProfile] = field(default_factory=list)
    triggers: dict[NetworkContextTrigger, ActionIntent] = field(default_factory=dict)
    redaction: dict[str, bool] = field(
        default_factory=lambda: {
            "support_export": True,
            "include_profile_labels": False,
            "include_match_values": False,
        }
    )
    schema_version: int = NETWORK_CONTEXT_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.schema_version = strict_int(
            self.schema_version,
            "network_context.schema_version",
        )
        if self.schema_version != NETWORK_CONTEXT_POLICY_SCHEMA_VERSION:
            raise PersistentValidationError(
                f"unsupported network context schema_version: {self.schema_version}"
            )
        self.enabled = strict_bool(self.enabled, "network_context.enabled")
        self.profiles = [
            item if isinstance(item, NetworkProfile) else NetworkProfile.from_dict(item)
            for item in self.profiles
        ]
        profile_ids = [profile.id for profile in self.profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise PersistentValidationError("network context profile ids must be unique")
        self.triggers = _normalize_triggers(self.triggers)
        self.redaction = _normalize_redaction(self.redaction)

    @classmethod
    def disabled_due_to_error(cls, reason: str) -> "NetworkContextPolicy":
        _ = reason
        return cls(enabled=False, profiles=[], triggers={}, redaction={})

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "enabled": self.enabled,
            "profiles": [profile.to_dict() for profile in self.profiles],
            "triggers": {
                trigger.value: self.triggers[trigger].to_dict()
                for trigger in NetworkContextTrigger
            },
            "redaction": dict(self.redaction),
        }

    def to_redacted_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "enabled": self.enabled,
            "profiles": [profile.to_redacted_dict() for profile in self.profiles],
            "triggers": {
                trigger.value: self.triggers[trigger].to_dict()
                for trigger in NetworkContextTrigger
            },
            "redaction": dict(self.redaction),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkContextPolicy":
        if not isinstance(data, dict):
            raise PersistentValidationError("network context policy must be an object")
        _validate_no_forbidden_fields(data, "network context policy")
        reject_unknown_keys(data, NETWORK_CONTEXT_POLICY_FIELDS, "network context policy")
        profiles = data.get("profiles", [])
        if not isinstance(profiles, list):
            raise PersistentValidationError("network_context.profiles must be a list")
        triggers = data.get("triggers", {})
        if not isinstance(triggers, dict):
            raise PersistentValidationError("network_context.triggers must be an object")
        redaction = data.get("redaction", {})
        if not isinstance(redaction, dict):
            raise PersistentValidationError("network_context.redaction must be an object")
        return cls(
            schema_version=data.get(
                "schema_version",
                NETWORK_CONTEXT_POLICY_SCHEMA_VERSION,
            ),
            enabled=strict_bool(data.get("enabled", False), "network_context.enabled"),
            profiles=[NetworkProfile.from_dict(item) for item in profiles],
            triggers=triggers,
            redaction={
                str(key): strict_bool(value, f"network_context.redaction.{key}")
                for key, value in redaction.items()
            },
        )


def _normalize_triggers(
    triggers: dict[NetworkContextTrigger | str, ActionIntent | dict[str, Any]],
) -> dict[NetworkContextTrigger, ActionIntent]:
    if not isinstance(triggers, dict):
        raise PersistentValidationError("network_context.triggers must be an object")
    normalized: dict[NetworkContextTrigger, ActionIntent] = {}
    for key, value in triggers.items():
        try:
            trigger = key if isinstance(key, NetworkContextTrigger) else NetworkContextTrigger(key)
        except ValueError as exc:
            supported = ", ".join(item.value for item in NetworkContextTrigger)
            raise PersistentValidationError(
                f"network_context.triggers keys must be one of: {supported}"
            ) from exc
        normalized[trigger] = (
            value if isinstance(value, ActionIntent) else ActionIntent.from_dict(value)
        )
    for trigger in NetworkContextTrigger:
        normalized.setdefault(trigger, ActionIntent())
    return normalized


def _normalize_redaction(redaction: dict[str, bool]) -> dict[str, bool]:
    if not isinstance(redaction, dict):
        raise PersistentValidationError("network_context.redaction must be an object")
    reject_unknown_keys(redaction, REDACTION_FIELDS, "network context redaction")
    defaults = {
        "support_export": True,
        "include_profile_labels": False,
        "include_match_values": False,
    }
    defaults.update(
        {
            str(key): strict_bool(value, f"network_context.redaction.{key}")
            for key, value in redaction.items()
        }
    )
    if not defaults["support_export"]:
        raise PersistentValidationError(
            "network_context.redaction.support_export must stay enabled by default"
        )
    return defaults
