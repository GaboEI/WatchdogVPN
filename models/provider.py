from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


def _dt_to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _dt_from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


@dataclass(slots=True)
class Provider:
    id: str
    name: str
    url: str
    last_updated: datetime | None = None
    profiles: list[str] = field(default_factory=list)
    rotation_enabled: bool = False
    auto_update: bool = True
    update_interval_hours: int = 24

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["last_updated"] = _dt_to_iso(self.last_updated)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Provider":
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            url=str(data["url"]),
            last_updated=_dt_from_iso(data.get("last_updated")),
            profiles=list(data.get("profiles", [])),
            rotation_enabled=bool(data.get("rotation_enabled", False)),
            auto_update=bool(data.get("auto_update", True)),
            update_interval_hours=int(data.get("update_interval_hours", 24)),
        )

