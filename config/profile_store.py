from __future__ import annotations

import os
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import dump_json, file_lock, load_json, require_list
from models.profile import Profile


def _profiles_path() -> Path:
    base = resolve_config_dir()
    return Path(os.environ.get("WATCHDOGVPN_PROFILES_FILE", base / "profiles.json"))


class ProfileStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _profiles_path()

    def _load_raw(self) -> list[dict]:
        items = require_list(load_json(self.path, []), self.path)
        return [dict(item) for item in items]

    def _save_raw(self, items: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        dump_json(self.path, items)

    def add(self, profile: Profile) -> None:
        with file_lock(self.path):
            items = self._load_raw()
            items = [item for item in items if item.get("id") != profile.id]
            items.append(profile.to_dict())
            self._save_raw(items)

    def get(self, profile_id: str) -> Profile | None:
        with file_lock(self.path):
            for item in self._load_raw():
                if item.get("id") == profile_id:
                    return Profile.from_dict(item)
        return None

    def list(self) -> list[Profile]:
        with file_lock(self.path):
            return [Profile.from_dict(item) for item in self._load_raw()]

    def update(self, profile: Profile) -> None:
        self.add(profile)

    def remove(self, profile_id: str) -> None:
        with file_lock(self.path):
            items = [item for item in self._load_raw() if item.get("id") != profile_id]
            self._save_raw(items)

    def get_rotation_pool(self) -> list[Profile]:
        return [p for p in self.list() if p.enabled and p.in_rotation_pool]
