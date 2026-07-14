from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
from typing import TypeVar

from config.paths import resolve_config_dir
from config.persistence import dump_json, file_lock, load_json, require_list
from models.profile import Profile
from parsers.openvpn_safety import validate_openvpn_profile


T = TypeVar("T")


def _profiles_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_PROFILES_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "profiles.json"


class ProfileStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _profiles_path()

    def _load_raw(self) -> list[dict]:
        items = require_list(load_json(self.path, []), self.path)
        return [dict(item) for item in items]

    def _save_raw(self, items: list[dict]) -> None:
        dump_json(self.path, items)

    def add(self, profile: Profile) -> None:
        validate_openvpn_profile(profile)
        with file_lock(self.path):
            items = self._load_raw()
            items = [item for item in items if item.get("id") != profile.id]
            items.append(profile.to_dict())
            self._save_raw(items)

    def update_atomically(
        self,
        transform: Callable[[list[Profile]], tuple[list[Profile], T]],
    ) -> T:
        """Apply one profile-store mutation while holding the store lock.

        The callback receives the complete current snapshot and must return the
        complete replacement snapshot plus its caller-specific result. The
        replacement is validated before one atomic publication, so callers can
        build all-or-nothing multi-profile transactions without observing or
        creating a partial profile store.
        """
        with file_lock(self.path):
            current = [Profile.from_dict(item) for item in self._load_raw()]
            replacement, result = transform(current)
            for profile in replacement:
                validate_openvpn_profile(profile)
            self._save_raw([profile.to_dict() for profile in replacement])
            return result

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
