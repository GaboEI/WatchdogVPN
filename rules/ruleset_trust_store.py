from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import dump_json, file_lock, load_json, require_mapping
from rules.ruleset_trust import RuleSetStatus, RuleSetTrustPolicy, RuleSetTrustRegistry


def _ruleset_trust_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_RULESET_TRUST_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "ruleset-trust.json"


class RuleSetTrustStoreError(RuntimeError):
    pass


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

    def add(self, policy: RuleSetTrustPolicy) -> Path | None:
        with file_lock(self.path):
            backup_path = self._backup_existing_unlocked()
            data = require_mapping(load_json(self.path, {}), self.path)
            registry = RuleSetTrustRegistry.from_dict(data) if data else RuleSetTrustRegistry()
            registry.policies[policy.id] = policy
            dump_json(self.path, registry.to_dict())
            return backup_path

    def remove(self, policy_id: str) -> Path | None:
        with file_lock(self.path):
            data = require_mapping(load_json(self.path, {}), self.path)
            registry = RuleSetTrustRegistry.from_dict(data) if data else RuleSetTrustRegistry()
            if policy_id not in registry.policies:
                raise RuleSetTrustStoreError(f"rule-set trust policy not found: {policy_id}")
            backup_path = self._backup_existing_unlocked()
            del registry.policies[policy_id]
            dump_json(self.path, registry.to_dict())
            return backup_path

    def _backup_dir(self) -> Path:
        return self.path.parent / "ruleset-trust-backups"

    def _backup_path_unlocked(self) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        base = self._backup_dir() / f"ruleset-trust-{timestamp}.json"
        if not base.exists():
            return base
        suffix = 2
        while True:
            candidate = self._backup_dir() / f"ruleset-trust-{timestamp}-{suffix}.json"
            if not candidate.exists():
                return candidate
            suffix += 1

    def _backup_existing_unlocked(self) -> Path | None:
        if not self.path.exists():
            return None
        backup_path = self._backup_path_unlocked()
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        backup_path.write_bytes(self.path.read_bytes())
        return backup_path
