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

from .models import AppPolicy


def _app_policy_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_APP_POLICY_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "app-policy.json"


@dataclass(frozen=True, slots=True)
class AppPolicyLoadResult:
    policy: AppPolicy
    valid: bool
    error: str | None = None


class AppPolicyStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _app_policy_path()

    def load(self) -> AppPolicy:
        with file_lock(self.path):
            data = require_mapping(load_json(self.path, {}), self.path)
            if not data:
                return AppPolicy()
            return AppPolicy.from_dict(data)

    def load_or_disabled(self) -> AppPolicyLoadResult:
        try:
            return AppPolicyLoadResult(policy=self.load(), valid=True)
        except (PersistentStoreError, PersistentValidationError) as exc:
            return AppPolicyLoadResult(
                policy=AppPolicy.disabled_due_to_error(str(exc)),
                valid=False,
                error=str(exc),
            )

    def save(self, policy: AppPolicy) -> None:
        with file_lock(self.path):
            dump_json(self.path, policy.to_dict())
