from __future__ import annotations

import os
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import dump_json, file_lock, load_json, require_mapping
from route_chains.models import RouteChain, RouteChainDocument


def _route_chains_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_ROUTE_CHAINS_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "chains.json"


class RouteChainStoreError(RuntimeError):
    pass


class RouteChainStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _route_chains_path()

    def load(self) -> RouteChainDocument:
        with file_lock(self.path):
            data = require_mapping(load_json(self.path, RouteChainDocument().to_dict()), self.path)
            return RouteChainDocument.from_dict(data)

    def save(self, document: RouteChainDocument) -> None:
        validated = RouteChainDocument.from_dict(document.to_dict())
        with file_lock(self.path):
            dump_json(self.path, validated.to_dict())

    def list(self) -> list[RouteChain]:
        return list(self.load().chains)

    def get(self, chain_id: str) -> RouteChain | None:
        for chain in self.list():
            if chain.id == chain_id:
                return chain
        return None

    def add(self, chain: RouteChain) -> None:
        validated = RouteChain.from_dict(chain.to_dict())
        with file_lock(self.path):
            document = RouteChainDocument.from_dict(
                require_mapping(load_json(self.path, RouteChainDocument().to_dict()), self.path)
            )
            chains = [item for item in document.chains if item.id != validated.id]
            chains.append(validated)
            dump_json(self.path, RouteChainDocument(chains=chains).to_dict())

    def remove(self, chain_id: str) -> None:
        with file_lock(self.path):
            document = RouteChainDocument.from_dict(
                require_mapping(load_json(self.path, RouteChainDocument().to_dict()), self.path)
            )
            chains = [item for item in document.chains if item.id != chain_id]
            dump_json(self.path, RouteChainDocument(chains=chains).to_dict())
