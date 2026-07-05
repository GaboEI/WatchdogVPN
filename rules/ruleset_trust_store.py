from __future__ import annotations

import os
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import file_lock, load_json, require_mapping
from rules.ruleset_trust import RuleSetTrustRegistry


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
