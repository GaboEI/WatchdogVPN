from __future__ import annotations

import os
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import dump_json, file_lock, load_json, require_mapping
from rules.ruleset_trust import RuleSetStatus, RuleSetTrustRegistry


def _ruleset_trust_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_RULESET_TRUST_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "ruleset-trust.json"


class RuleSetTrustStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _ruleset_trust_path()

    def load(self) -> RuleSetTrustRegistry:
        with file_lock(self.path):
            data = require_mapping(load_json(self.path, {}), self.path)
            if not data:
                return RuleSetTrustRegistry()
            return RuleSetTrustRegistry.from_dict(data)

    def save(self, registry: RuleSetTrustRegistry) -> None:
        with file_lock(self.path):
            dump_json(self.path, registry.to_dict())

    def update_statuses(self, statuses: list[RuleSetStatus]) -> RuleSetTrustRegistry:
        with file_lock(self.path):
            data = require_mapping(load_json(self.path, {}), self.path)
            registry = RuleSetTrustRegistry.from_dict(data) if data else RuleSetTrustRegistry()
            for status in statuses:
                registry.statuses[status.id] = status
            dump_json(self.path, registry.to_dict())
            return registry
