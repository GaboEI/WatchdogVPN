from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from config.persistence import reject_unknown_keys, strict_bool, strict_float


class ProtocolType(str, Enum):
    VLESS = "vless"
    VMESS = "vmess"
    TROJAN = "trojan"
    HYSTERIA2 = "hysteria2"
    TUIC = "tuic"
    SHADOWSOCKS = "shadowsocks"
    WIREGUARD = "wireguard"
    AMNEZIAWG = "amneziawg"
    SOCKS = "socks"
    HTTP = "http"
    OPENVPN = "openvpn"
    OPENVPN_CLOAK = "openvpn_cloak"


class ProfileSource(str, Enum):
    MANUAL = "manual"
    SUBSCRIPTION = "subscription"


class ResilienceCategory(str, Enum):
    """Anti-DPI/censorship-resistance category, per the master plan's
    "Profile Categories" doctrine (Phase 2/4.6/5.5) - never encoded in code
    until now. Documentation-only classifications must not silently drift
    from what the driver/parser layers actually validated:
    - RESILIENT: directly serves anti-censorship/anti-DPI resilience.
    - COMPATIBILITY: broad interoperability, no anti-censorship claim.
    """

    RESILIENT = "resilient"
    COMPATIBILITY = "compatibility"


PROTOCOL_RESILIENCE_CATEGORY: dict[ProtocolType, ResilienceCategory] = {
    ProtocolType.VLESS: ResilienceCategory.RESILIENT,
    ProtocolType.TROJAN: ResilienceCategory.RESILIENT,
    ProtocolType.HYSTERIA2: ResilienceCategory.RESILIENT,
    ProtocolType.AMNEZIAWG: ResilienceCategory.RESILIENT,
    ProtocolType.OPENVPN_CLOAK: ResilienceCategory.RESILIENT,
    ProtocolType.VMESS: ResilienceCategory.COMPATIBILITY,
    ProtocolType.TUIC: ResilienceCategory.COMPATIBILITY,
    ProtocolType.SHADOWSOCKS: ResilienceCategory.COMPATIBILITY,
    ProtocolType.WIREGUARD: ResilienceCategory.COMPATIBILITY,
    ProtocolType.SOCKS: ResilienceCategory.COMPATIBILITY,
    ProtocolType.HTTP: ResilienceCategory.COMPATIBILITY,
    ProtocolType.OPENVPN: ResilienceCategory.COMPATIBILITY,
}


def profile_resilience_category(profile: "Profile") -> ResilienceCategory:
    """Direct mapping access, not .get(protocol, default): a missing entry
    must raise KeyError, not silently degrade to COMPATIBILITY. Completeness
    is enforced separately by a test iterating every ProtocolType - a masked
    default here would defeat that fail-loud guarantee."""
    return PROTOCOL_RESILIENCE_CATEGORY[profile.protocol]


PROFILE_FINGERPRINT_SECRET_KEYS = {
    "auth",
    "auth_str",
    "auth_str_type",
    "obfs_password",
    "password",
    "private_key",
    "psk",
    "secret",
    "token",
    "uuid",
}
PROFILE_FINGERPRINT_RAW_KEYS = {
    "raw_config",
}
PROFILE_FINGERPRINT_DISPLAY_KEYS = {
    "fragment",
    "name",
    "tag",
}


def profile_fingerprint(profile: "Profile") -> str:
    """Return a stable, secret-safe identity fingerprint for duplicate checks.

    The fingerprint is intentionally not persisted and never shown to users. It
    uses protocol plus normalized runtime config, excludes display-only labels,
    and hashes secret/raw material before hashing the whole canonical payload.
    """
    payload = {
        "protocol": profile.protocol.value,
        "config": _fingerprint_value(profile.config),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _fingerprint_value(value: Any, *, key: str | None = None) -> Any:
    if key in PROFILE_FINGERPRINT_DISPLAY_KEYS:
        return None
    if key in PROFILE_FINGERPRINT_SECRET_KEYS or key in PROFILE_FINGERPRINT_RAW_KEYS:
        return {"sha256": _secret_digest(value)}
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for item_key, item_value in value.items():
            normalized_key = str(item_key).strip().lower()
            if normalized_key in PROFILE_FINGERPRINT_DISPLAY_KEYS:
                continue
            normalized_value = _fingerprint_value(item_value, key=normalized_key)
            if normalized_value is not None:
                result[normalized_key] = normalized_value
        return result
    if isinstance(value, list):
        return [_fingerprint_value(item) for item in value]
    if isinstance(value, tuple):
        return [_fingerprint_value(item) for item in value]
    if isinstance(value, str):
        return value.strip()
    return value


def _secret_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


PROFILE_FIELDS = {
    "id",
    "name",
    "protocol",
    "config",
    "source",
    "provider_id",
    "in_rotation_pool",
    "enabled",
    "created_at",
    "last_used",
    "last_health_check",
    "health_status",
    "latency_ms",
    "last_latency_check",
}


def _dt_to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _dt_from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


@dataclass(slots=True)
class Profile:
    id: str
    name: str
    protocol: ProtocolType
    config: dict[str, Any]
    source: ProfileSource
    provider_id: str | None = None
    in_rotation_pool: bool = False
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: datetime | None = None
    last_health_check: datetime | None = None
    health_status: str = "unknown"
    latency_ms: float | None = None
    last_latency_check: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["protocol"] = self.protocol.value
        data["source"] = self.source.value
        data["created_at"] = _dt_to_iso(self.created_at)
        data["last_used"] = _dt_to_iso(self.last_used)
        data["last_health_check"] = _dt_to_iso(self.last_health_check)
        data["last_latency_check"] = _dt_to_iso(self.last_latency_check)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Profile":
        reject_unknown_keys(data, PROFILE_FIELDS, "profile")
        config = data.get("config", {})
        if not isinstance(config, dict):
            raise ValueError("profile config must be an object")
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            protocol=ProtocolType(data["protocol"]),
            config=dict(config),
            source=ProfileSource(data["source"]),
            provider_id=data.get("provider_id"),
            in_rotation_pool=strict_bool(data.get("in_rotation_pool", False), "profile.in_rotation_pool"),
            enabled=strict_bool(data.get("enabled", True), "profile.enabled"),
            created_at=_dt_from_iso(data.get("created_at")) or datetime.utcnow(),
            last_used=_dt_from_iso(data.get("last_used")),
            last_health_check=_dt_from_iso(data.get("last_health_check")),
            health_status=str(data.get("health_status", "unknown")),
            latency_ms=(
                strict_float(data["latency_ms"], "profile.latency_ms")
                if data.get("latency_ms") is not None
                else None
            ),
            last_latency_check=_dt_from_iso(data.get("last_latency_check")),
        )
