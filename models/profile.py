from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


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
    ADGUARD = "adguard"


class ProfileSource(str, Enum):
    MANUAL = "manual"
    SUBSCRIPTION = "subscription"


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

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["protocol"] = self.protocol.value
        data["source"] = self.source.value
        data["created_at"] = _dt_to_iso(self.created_at)
        data["last_used"] = _dt_to_iso(self.last_used)
        data["last_health_check"] = _dt_to_iso(self.last_health_check)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Profile":
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            protocol=ProtocolType(data["protocol"]),
            config=dict(data.get("config", {})),
            source=ProfileSource(data["source"]),
            provider_id=data.get("provider_id"),
            in_rotation_pool=bool(data.get("in_rotation_pool", False)),
            enabled=bool(data.get("enabled", True)),
            created_at=_dt_from_iso(data.get("created_at")) or datetime.utcnow(),
            last_used=_dt_from_iso(data.get("last_used")),
            last_health_check=_dt_from_iso(data.get("last_health_check")),
            health_status=str(data.get("health_status", "unknown")),
        )
