from __future__ import annotations

import os
from pathlib import Path

from config.persistence import dump_json, file_lock, load_json, require_list
from models.provider import Provider


def _providers_path() -> Path:
    base = Path(os.environ.get("WATCHDOGVPN_CONFIG_DIR", Path.home() / ".config" / "watchdogvpn"))
    return Path(os.environ.get("WATCHDOGVPN_PROVIDERS_FILE", base / "providers.json"))


class ProviderLimitError(ValueError):
    pass


class ProviderStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _providers_path()

    def _load_raw(self) -> list[dict]:
        items = require_list(load_json(self.path, []), self.path)
        return [dict(item) for item in items]

    def _save_raw(self, items: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        dump_json(self.path, items)

    def add(self, provider: Provider) -> None:
        with file_lock(self.path):
            items = self._load_raw()
            if provider.id not in {item.get("id") for item in items} and len(items) >= 2:
                raise ProviderLimitError("maximum 2 external providers allowed")
            items = [item for item in items if item.get("id") != provider.id]
            items.append(provider.to_dict())
            self._save_raw(items)

    def get(self, provider_id: str) -> Provider | None:
        with file_lock(self.path):
            for item in self._load_raw():
                if item.get("id") == provider_id:
                    return Provider.from_dict(item)
        return None

    def list(self) -> list[Provider]:
        with file_lock(self.path):
            return [Provider.from_dict(item) for item in self._load_raw()]

    def update(self, provider: Provider) -> None:
        self.add(provider)

    def remove(self, provider_id: str) -> None:
        with file_lock(self.path):
            items = [item for item in self._load_raw() if item.get("id") != provider_id]
            self._save_raw(items)
