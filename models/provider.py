from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from config.persistence import reject_unknown_keys, strict_bool, strict_int


PROVIDER_FIELDS = {
    "id",
    "name",
    "url",
    "last_updated",
    "profiles",
    "rotation_enabled",
    "auto_update",
    "update_interval_hours",
    "metadata",
}


def normalized_provider_url(url: str) -> str:
    return str(url or "").strip()


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
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["last_updated"] = _dt_to_iso(self.last_updated)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Provider":
        reject_unknown_keys(data, PROVIDER_FIELDS, "provider")
        profiles = data.get("profiles", [])
        metadata = data.get("metadata", {})
        if not isinstance(profiles, list):
            raise ValueError("provider profiles must be a list")
        if not isinstance(metadata, dict):
            raise ValueError("provider metadata must be an object")
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            url=str(data["url"]),
            last_updated=_dt_from_iso(data.get("last_updated")),
            profiles=[str(profile_id) for profile_id in profiles],
            rotation_enabled=strict_bool(
                data.get("rotation_enabled", False),
                "provider.rotation_enabled",
            ),
            auto_update=strict_bool(data.get("auto_update", True), "provider.auto_update"),
            update_interval_hours=strict_int(
                data.get("update_interval_hours", 24),
                "provider.update_interval_hours",
            ),
            metadata=dict(metadata),
        )
