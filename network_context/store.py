from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import (
    PersistentStoreError,
    PersistentValidationError,
    dump_json,
    file_lock,
    load_json,
    require_mapping,
)

from .models import NetworkContextPolicy


def _network_context_policy_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_NETWORK_CONTEXT_POLICY_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "network-context-policy.json"


@dataclass(frozen=True, slots=True)
class NetworkContextPolicyLoadResult:
    policy: NetworkContextPolicy
    valid: bool
    error: str | None = None


class NetworkContextPolicyStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _network_context_policy_path()

    def load(self) -> NetworkContextPolicy:
        with file_lock(self.path):
            data = require_mapping(load_json(self.path, {}), self.path)
            if not data:
                return NetworkContextPolicy()
            return NetworkContextPolicy.from_dict(data)

    def load_or_disabled(self) -> NetworkContextPolicyLoadResult:
        try:
            return NetworkContextPolicyLoadResult(policy=self.load(), valid=True)
        except (PersistentStoreError, PersistentValidationError) as exc:
            return NetworkContextPolicyLoadResult(
                policy=NetworkContextPolicy.disabled_due_to_error(str(exc)),
                valid=False,
                error=str(exc),
            )

    def save(self, policy: NetworkContextPolicy) -> None:
        with file_lock(self.path):
            dump_json(self.path, policy.to_dict())
