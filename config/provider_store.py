from __future__ import annotations

import json
import os
from pathlib import Path

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
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save_raw(self, items: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(items, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def add(self, provider: Provider) -> None:
        items = self._load_raw()
        if provider.id not in {item.get("id") for item in items} and len(items) >= 2:
            raise ProviderLimitError("maximum 2 external providers allowed")
        items = [item for item in items if item.get("id") != provider.id]
        items.append(provider.to_dict())
        self._save_raw(items)

    def get(self, provider_id: str) -> Provider | None:
        for item in self._load_raw():
            if item.get("id") == provider_id:
                return Provider.from_dict(item)
        return None

    def list(self) -> list[Provider]:
        return [Provider.from_dict(item) for item in self._load_raw()]

    def update(self, provider: Provider) -> None:
        self.add(provider)

    def remove(self, provider_id: str) -> None:
        items = [item for item in self._load_raw() if item.get("id") != provider_id]
        self._save_raw(items)

