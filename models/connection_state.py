from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


ALLOWED_STATUSES = {
    "connected",
    "reconnecting",
    "all_failed",
    "normal_network_temp",
    "kill_switch_active",
    "waiting_retry",
    "recovered",
    "standby",
}


def _dt_to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _dt_from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


@dataclass(slots=True)
class ConnectionState:
    active_profile_id: str = ""
    connected_at: datetime | None = None
    mode: str = "standby"
    tun_active: bool = False
    proxy_active: bool = False
    kill_switch_active: bool = False
    status: str = "standby"

    def __post_init__(self) -> None:
        if self.status not in ALLOWED_STATUSES:
            raise ValueError(f"invalid status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["connected_at"] = _dt_to_iso(self.connected_at)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConnectionState":
        return cls(
            active_profile_id=str(data.get("active_profile_id", "")),
            connected_at=_dt_from_iso(data.get("connected_at")),
            mode=str(data.get("mode", "standby")),
            tun_active=bool(data.get("tun_active", False)),
            proxy_active=bool(data.get("proxy_active", False)),
            kill_switch_active=bool(data.get("kill_switch_active", False)),
            status=str(data.get("status", "standby")),
        )

