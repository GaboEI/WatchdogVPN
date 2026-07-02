from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from config.persistence import dump_json, file_lock, load_json, require_mapping
from rules.models import DEFAULT_RULE_GROUPS, Rule, RuleGroup, validate_group_name


def _rules_dir() -> Path:
    base = Path(os.environ.get("WATCHDOGVPN_CONFIG_DIR", Path.home() / ".config" / "watchdogvpn"))
    return Path(os.environ.get("WATCHDOGVPN_RULES_DIR", base / "rules"))


class RuleStoreError(RuntimeError):
    pass


class RuleStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _rules_dir()

    def _group_path(self, name: str) -> Path:
        return self.path / f"{validate_group_name(name)}.json"

    def add_group(self, group: RuleGroup) -> None:
        target = self._group_path(group.name)
        with file_lock(target):
            self.path.mkdir(parents=True, exist_ok=True)
            dump_json(target, group.to_dict())

    def get_group(self, name: str) -> RuleGroup | None:
        target = self._group_path(name)
        with file_lock(target):
            if not target.exists():
                return None
            data = require_mapping(load_json(target, {}), target)
            return RuleGroup.from_dict(data)

    def list_groups(self) -> list[RuleGroup]:
        if not self.path.exists():
            return []
        groups = []
        for file in sorted(self.path.glob("*.json")):
            data = require_mapping(load_json(file, {}), file)
            groups.append(RuleGroup.from_dict(data))
        return groups

    def update_group(self, group: RuleGroup) -> None:
        self.add_group(group)

    def remove_group(self, name: str) -> None:
        target = self._group_path(name)
        with file_lock(target):
            if target.exists():
                target.unlink()

    def enable_group(self, name: str) -> None:
        group = self._require_group(name)
        group.enabled = True
        self.update_group(group)

    def disable_group(self, name: str) -> None:
        group = self._require_group(name)
        group.enabled = False
        self.update_group(group)

    def ensure_default_groups(self) -> None:
        for name in DEFAULT_RULE_GROUPS:
            if self.get_group(name) is None:
                self.add_group(RuleGroup(name=name))

    def import_group(self, rules: list[Rule], *, prefix: str = "imported") -> RuleGroup:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        name = f"{prefix}-{timestamp}"
        suffix = 1
        while self.get_group(name) is not None:
            suffix += 1
            name = f"{prefix}-{timestamp}-{suffix}"
        group = RuleGroup(name=name, rules=list(rules))
        self.add_group(group)
        return group

    def _require_group(self, name: str) -> RuleGroup:
        group = self.get_group(name)
        if group is None:
            raise RuleStoreError(f"rule group not found: {name}")
        return group
