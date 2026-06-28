from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

from models.profile import Profile


def _profiles_path() -> Path:
    base = Path(os.environ.get("WATCHDOGVPN_CONFIG_DIR", Path.home() / ".config" / "watchdogvpn"))
    return Path(os.environ.get("WATCHDOGVPN_PROFILES_FILE", base / "profiles.json"))


class ProfileStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _profiles_path()

    def _load_raw(self) -> list[dict]:
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save_raw(self, items: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(items, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def add(self, profile: Profile) -> None:
        items = self._load_raw()
        items = [item for item in items if item.get("id") != profile.id]
        items.append(profile.to_dict())
        self._save_raw(items)

    def get(self, profile_id: str) -> Profile | None:
        for item in self._load_raw():
            if item.get("id") == profile_id:
                return Profile.from_dict(item)
        return None

    def list(self) -> list[Profile]:
        return [Profile.from_dict(item) for item in self._load_raw()]

    def update(self, profile: Profile) -> None:
        self.add(profile)

    def remove(self, profile_id: str) -> None:
        items = [item for item in self._load_raw() if item.get("id") != profile_id]
        self._save_raw(items)

    def get_rotation_pool(self) -> list[Profile]:
        return [p for p in self.list() if p.enabled and p.in_rotation_pool]

